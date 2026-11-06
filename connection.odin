package whatsapp

import network_client "../client"
import "core:crypto"
import "core:crypto/x25519"
import "core:mem"
import "core:slice"
import "core:time"
import "core:bytes"
import grp "core:crypto/_edwards25519"
import field "core:crypto/_fiat/field_curve25519"
import "core:crypto/aes"
import "core:crypto/hkdf"
import "core:crypto/sha2"

// Noise client, framing and transport.

// Noise client handshake and lifecycle

Noise_Credentials :: struct {
	// Persisted device Noise key, distinct from the per-connection ephemeral.
	static_private_key: [32]u8,
}

Certificate_Error :: enum {
	None,
	Invalid_Certificate_Chain,
	Missing_Intermediate,
	Invalid_Intermediate_Details,
	Unexpected_Issuer_Serial,
	Rejected,
}

Certificate_Verifier :: #type proc(
	payload: []u8,
	server_static: [32]u8,
) -> Certificate_Error

Client_Config :: struct {
	max_frame_payload:  int, // Zero defaults to 1 MiB.
	handshake_timeout:  time.Duration, // Zero defaults to 10 seconds where supported.
	// Nil preserves the pinned Baileys 6.7.23 issuer-serial policy. This is
	// not an XEdDSA certificate-chain verifier; endpoint trust comes from TLS.
	verify_certificate: Certificate_Verifier,
}

Client_Phase :: enum {
	Uninitialized,
	Initialized,
	Handshake,
	Noise_Ready,
	Failed,
	Closed,
}

Client_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	Invalid_Credentials,
	Entropy_Unavailable,
	Allocation_Failed,
	Transport_Failed,
	Protobuf_Failed,
	Unexpected_Handshake_Message,
	Invalid_Server_Ephemeral,
	Invalid_Server_Static,
	Invalid_Server_Payload,
	DH_Failed,
	Noise_Failed,
	Certificate_Rejected,
	Deadline_Failed,
	Payload_Oversized,
	Destination_Undersized,
	Peer_Closed,
	WebSocket_Close_Failed,
}

Client_Error :: struct {
	kind:        Client_Error_Kind,
	transport:   Frame_Transport_Error,
	protobuf:    Protobuf_Error,
	noise:       Noise_Error,
	certificate: Certificate_Error,
	websocket:   network_client.WebSocket_Error,
	stream:      network_client.WebSocket_Stream_Error,
	allocation:  mem.Allocator_Error,
}

// Caller-owned and serialized. Successful initialization transfers shutdown
// responsibility for websocket to this client. Noise_Ready means encryption
// is established, not that this device has been paired or logged in.
Client :: struct {
	websocket:         ^network_client.WebSocket_Conn,
	config:            Client_Config,
	phase:             Client_Phase,
	frames:            Frame_Transport,
	noise:             Noise_State,
	static_private:    [32]u8,
	static_public:     [32]u8,
	ephemeral_private: [32]u8,
	ephemeral_public:  [32]u8,
	last_error:        Client_Error,
}

noise_credentials_generate :: proc(
) -> (
	credentials: Noise_Credentials,
	error: Client_Error,
) {
	when !crypto.HAS_RAND_BYTES do return {}, {kind = .Entropy_Unavailable}
	crypto.rand_bytes(credentials.static_private_key[:])
	return credentials, {}
}

client_init :: proc(
	client: ^Client,
	websocket: ^network_client.WebSocket_Conn,
	credentials: Noise_Credentials,
	config: Client_Config = {},
) -> Client_Error {
	if client == nil || client.phase != .Uninitialized {
		return {kind = .Invalid_State}
	}

	if websocket == nil || websocket.phase != .Open {
		return {kind = .Invalid_State}
	}

	settings := config
	if settings.max_frame_payload == 0 {
		settings.max_frame_payload = 1 << 20
	}

	if settings.max_frame_payload < 128 ||
	   settings.max_frame_payload > MAX_FRAME_PAYLOAD ||
	   settings.handshake_timeout < 0 {
		return {kind = .Invalid_Config}
	}

	private := credentials.static_private_key
	defer crypto.zero_explicit(&private, size_of(private))
	if crypto.is_zero_constant_time(private[:]) == 1 {
		return {kind = .Invalid_Credentials}
	}

	when !crypto.HAS_RAND_BYTES do return {kind = .Entropy_Unavailable}
	if err := frame_transport_init(
		&client.frames,
		websocket,
		settings.max_frame_payload,
	); err.kind != .None {
		return {kind = .Transport_Failed, transport = err}
	}

	client.websocket = websocket
	client.config = settings
	client.static_private = private
	x25519.scalarmult_basepoint(
		client.static_public[:],
		client.static_private[:],
	)
	crypto.rand_bytes(client.ephemeral_private[:])
	x25519.scalarmult_basepoint(
		client.ephemeral_public[:],
		client.ephemeral_private[:],
	)
	if err := noise_init(&client.noise, client.ephemeral_public);
	   err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	client.phase = .Initialized
	return {}
}

// Runs Baileys' ClientHello -> ServerHello -> ClientFinish exchange. The
// payload is an already encoded WAProto.ClientPayload; registration/login
// construction belongs to the credentials/pairing layer above this package.
client_handshake :: proc(
	client: ^Client,
	client_payload: []u8,
) -> Client_Error {
	if client == nil do return {kind = .Invalid_State}

	if client.phase == .Noise_Ready do return {}

	if client.phase == .Failed do return client.last_error

	if client.phase != .Initialized {
		return {kind = .Invalid_State}
	}

	finish_size := client_finish_wire_size(len(client_payload))
	if finish_size > client.config.max_frame_payload ||
	   finish_size > client.websocket.config.max_message_size - 3 {
		return {kind = .Payload_Oversized}
	}

	deadlines_set, deadline_error := client_handshake_deadline_start(client)
	if deadline_error.kind != .None do return deadline_error

	defer {
		if deadlines_set &&
		   !slice.contains(
				   []type_of(client.phase){.Failed, .Closed},
				   client.phase,
			   ) &&
		   client.websocket.phase == .Open {
			network_client.websocket_set_deadline(client.websocket, {})
		}

	}
	client.phase = .Handshake
	if exchange_error := client_handshake_exchange(client, client_payload, finish_size);
	   exchange_error.kind != .None do return exchange_error

	if err := noise_split(&client.noise); err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	client_secret_keys_clear(client)
	if deadlines_set {
		if err := network_client.websocket_set_deadline(client.websocket, {});
		   err.kind != .None {
			return client_fail(
				client,
				{kind = .Deadline_Failed, stream = err},
			)
		}

		deadlines_set = false
	}

	client.phase = .Noise_Ready
	return {}
}

client_handshake_deadline_start :: proc(client: ^Client) -> (bool, Client_Error) {
	deadlines_set := false
	if client.websocket.stream.set_read_deadline != nil &&
	   client.websocket.stream.set_write_deadline != nil {
		timeout := client.config.handshake_timeout
		if timeout == 0 do timeout = 10 * time.Second

		if err := network_client.websocket_set_deadline(
			client.websocket,
			time.time_add(time.now(), timeout),
		); err.kind != .None {
			return false, client_fail(
				client,
				{kind = .Deadline_Failed, stream = err},
			)
		}

		deadlines_set = true
	} else if client.config.handshake_timeout > 0 {
		return false, client_fail(
			client,
			{
				kind = .Deadline_Failed,
				stream = {kind = .Deadline_Unsupported},
			},
		)
	}

	return deadlines_set, {}
}

client_handshake_hello_send :: proc(client: ^Client) -> Client_Error {
	hello: [36]u8
	size, encode_err := handshake_client_hello_encode(
		hello[:],
		client.ephemeral_public,
	)
	if encode_err != .None {
		return client_fail(
			client,
			{kind = .Protobuf_Failed, protobuf = encode_err},
		)
	}

	if err := frame_transport_send(&client.frames, hello[:size]);
	   err.kind != .None {
		return client_fail(
			client,
			{kind = .Transport_Failed, transport = err},
		)
	}

	return {}
}

client_handshake_server_read :: proc(
	client: ^Client, server_buffer: []u8,
) -> (Handshake_Message, Client_Error) {
	received, receive_err := frame_transport_receive(
		&client.frames,
		server_buffer,
	)
	if receive_err.kind != .None {
		return {}, client_fail(
			client,
			{kind = .Transport_Failed, transport = receive_err},
		)
	}

	server, decode_err := handshake_message_decode(
		server_buffer[:received],
	)
	if decode_err != .None {
		return {}, client_fail(
			client,
			{kind = .Protobuf_Failed, protobuf = decode_err},
		)
	}

	if server.kind != .Server_Hello {
		return {}, client_fail(
			client,
			{kind = .Unexpected_Handshake_Message},
		)
	}

	if !server.has_ephemeral || len(server.ephemeral) != 32 {
		return {}, client_fail(
			client,
			{kind = .Invalid_Server_Ephemeral},
		)
	}

	if !server.has_static || len(server.static) != 48 {
		return {}, client_fail(client, {kind = .Invalid_Server_Static})
	}

	if !server.has_payload || len(server.payload) < NOISE_TAG_SIZE {
		return {}, client_fail(client, {kind = .Invalid_Server_Payload})
	}

	return server, {}
}

client_noise_mix_dh :: proc(client: ^Client, private, remote: []u8) -> Client_Error {
	shared: [32]u8
	defer crypto.zero_explicit(&shared, size_of(shared))
	x25519.scalarmult(shared[:], private, remote)
	if crypto.is_zero_constant_time(shared[:]) == 1 {
		return client_fail(client, {kind = .DH_Failed})
	}

	if err := noise_mix_key(&client.noise, shared); err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	return {}
}

client_handshake_server_static_decrypt :: proc(
	client: ^Client, server: Handshake_Message, server_static: []u8,
) -> Client_Error {
	if err := noise_mix_hash(&client.noise, server.ephemeral);
	   err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	if dh_error := client_noise_mix_dh(client, client.ephemeral_private[:], server.ephemeral);
	   dh_error.kind != .None do return dh_error
	if _, err := noise_decrypt(
		&client.noise,
		server_static,
		server.static,
	); err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	return client_noise_mix_dh(client, client.ephemeral_private[:], server_static)
}

client_handshake_certificate_verify :: proc(
	client: ^Client, server: Handshake_Message, server_static: ^[32]u8,
) -> Client_Error {
	certificate, cert_alloc_err := make(
		[]u8,
		len(server.payload) - NOISE_TAG_SIZE,
		context.allocator,
	)
	if cert_alloc_err != nil {
		return client_fail(
			client,
			{kind = .Allocation_Failed, allocation = cert_alloc_err},
		)
	}

	defer delete(certificate)
	if _, err := noise_decrypt(
		&client.noise,
		certificate,
		server.payload,
	); err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	verify := client.config.verify_certificate
	if verify == nil do verify = baileys_certificate_policy

	if err := verify(certificate, server_static^); err != .None {
		return client_fail(
			client,
			{kind = .Certificate_Rejected, certificate = err},
		)
	}

	return {}
}

client_handshake_static_send_prepare :: proc(
	client: ^Client, server: Handshake_Message, encrypted_static: []u8,
) -> Client_Error {
	if _, err := noise_encrypt(
		&client.noise,
		encrypted_static,
		client.static_public[:],
	); err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	return client_noise_mix_dh(client, client.static_private[:], server.ephemeral)
}

client_handshake_finish_send :: proc(
	client: ^Client, encrypted_static, encrypted_payload: []u8, finish_size: int,
) -> Client_Error {
	finish, finish_alloc_err := make(
		[]u8,
		finish_size,
		context.allocator,
	)
	if finish_alloc_err != nil {
		return client_fail(
			client,
			{
				kind = .Allocation_Failed,
				allocation = finish_alloc_err,
			},
		)
	}

	defer delete(finish)
	_, finish_err := handshake_client_finish_encode(
		finish,
		encrypted_static,
		encrypted_payload,
	)
	if finish_err != .None {
		return client_fail(
			client,
			{kind = .Protobuf_Failed, protobuf = finish_err},
		)
	}

	if err := frame_transport_send(&client.frames, finish);
	   err.kind != .None {
		return client_fail(
			client,
			{kind = .Transport_Failed, transport = err},
		)
	}

	return {}
}

client_handshake_payload_send :: proc(
	client: ^Client, client_payload, encrypted_static: []u8, finish_size: int,
) -> Client_Error {
	encrypted_payload, payload_alloc_err := make(
		[]u8,
		len(client_payload) + NOISE_TAG_SIZE,
		context.allocator,
	)
	if payload_alloc_err != nil {
		return client_fail(
			client,
			{
				kind = .Allocation_Failed,
				allocation = payload_alloc_err,
			},
		)
	}

	defer delete(encrypted_payload)
	if _, err := noise_encrypt(
		&client.noise,
		encrypted_payload,
		client_payload,
	); err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = err},
		)
	}

	return client_handshake_finish_send(client, encrypted_static, encrypted_payload, finish_size)
}

client_handshake_exchange :: proc(
	client: ^Client, client_payload: []u8, finish_size: int,
) -> Client_Error {
	if hello_error := client_handshake_hello_send(client); hello_error.kind != .None {
		return hello_error
	}
	server_buffer, allocation_err := make(
		[]u8,
		client.config.max_frame_payload,
		context.allocator,
	)
	if allocation_err != nil {
		return client_fail(
			client,
			{kind = .Allocation_Failed, allocation = allocation_err},
		)
	}

	defer delete(server_buffer)
	server, server_error := client_handshake_server_read(client, server_buffer)
	if server_error.kind != .None do return server_error
	server_static: [32]u8
	if static_error := client_handshake_server_static_decrypt(client, server, server_static[:]);
	   static_error.kind != .None do return static_error
	if certificate_error := client_handshake_certificate_verify(client, server, &server_static);
	   certificate_error.kind != .None do return certificate_error
	encrypted_static: [48]u8
	if static_error := client_handshake_static_send_prepare(client, server, encrypted_static[:]);
	   static_error.kind != .None do return static_error
	return client_handshake_payload_send(client, client_payload, encrypted_static[:], finish_size)
}

// Matches the pinned Baileys policy exactly: the intermediate must name root
// issuer serial zero. Signatures and validity times are not verified here.
baileys_certificate_policy :: proc(
	payload: []u8,
	server_static: [32]u8,
) -> Certificate_Error {
	chain, err := cert_chain_decode(payload)
	if err != .None do return .Invalid_Certificate_Chain

	if !chain.has_intermediate || !chain.intermediate.has_details {
		return .Missing_Intermediate
	}

	details, details_err := certificate_details_decode(
		chain.intermediate.details,
	)
	if details_err != .None {
		return .Invalid_Intermediate_Details
	}

	if !details.has_issuer_serial || details.issuer_serial != 0 {
		return .Unexpected_Issuer_Serial
	}

	return .None
}

client_close :: proc(client: ^Client) -> Client_Error {
	if client == nil || client.phase == .Uninitialized {
		return {kind = .Invalid_State}
	}

	if client.phase == .Closed do return {}

	frame_transport_clear(&client.frames)
	noise_clear(&client.noise)
	client_secret_keys_clear(client)
	client.phase = .Closed
	if err := network_client.websocket_close(client.websocket); err.kind != .None {
		return {kind = .WebSocket_Close_Failed, websocket = err}
	}

	return {}
}

client_fail :: proc(
	client: ^Client,
	err: Client_Error,
) -> Client_Error {
	client.phase = .Failed
	client.last_error = err
	frame_transport_clear(&client.frames)
	noise_clear(&client.noise)
	client_secret_keys_clear(client)
	network_client.websocket_close(client.websocket, 1008)
	return err
}

client_secret_keys_clear :: proc(client: ^Client) {
	crypto.zero_explicit(
		&client.static_private,
		size_of(client.static_private),
	)
	crypto.zero_explicit(
		&client.ephemeral_private,
		size_of(client.ephemeral_private),
	)
}

client_finish_wire_size :: proc(payload_size: int) -> int {
	if payload_size > MAX_FRAME_PAYLOAD - NOISE_TAG_SIZE {
		return MAX_FRAME_PAYLOAD + 1
	}

	encrypted_size := payload_size + NOISE_TAG_SIZE
	inner :=
		50 + 1 + client_varint_size(encrypted_size) + encrypted_size
	return 1 + client_varint_size(inner) + inner
}

client_varint_size :: proc(value: int) -> int {
	n, size := value, 1
	for n >= 128 {n >>= 7; size += 1}
	return size
}

// Encrypted client message I/O

// Sends an opaque encoded WhatsApp binary node under the established Noise
// keys. The node codec and account/session state live above this layer.
client_write :: proc(
	client: ^Client,
	payload: []u8,
) -> Client_Error {
	if client == nil do return {kind = .Invalid_State}

	if client.phase == .Failed do return client.last_error

	if client.phase != .Noise_Ready {
		return {kind = .Invalid_State}
	}

	if len(payload) >
		   client.config.max_frame_payload - NOISE_TAG_SIZE ||
	   len(payload) >
		   client.websocket.config.max_message_size -
			   FRAME_HEADER_SIZE -
			   NOISE_TAG_SIZE {
		return {kind = .Payload_Oversized}
	}

	ciphertext, allocation_err := make(
		[]u8,
		len(payload) + NOISE_TAG_SIZE,
		context.allocator,
	)
	if allocation_err != nil {
		return {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
	}

	defer delete(ciphertext)
	_, encrypt_err := noise_encrypt(
		&client.noise,
		ciphertext,
		payload,
	)
	if encrypt_err != .None {
		return client_fail(
			client,
			{kind = .Noise_Failed, noise = encrypt_err},
		)
	}

	if err := frame_transport_send(&client.frames, ciphertext);
	   err.kind != .None {
		return client_fail(
			client,
			{kind = .Transport_Failed, transport = err},
		)
	}

	return {}
}

// Returns decrypted node bytes. On Destination_Undersized, n gives the
// required plaintext size and the encrypted envelope remains queued for retry;
// no nonce is consumed until decryption is attempted with enough space.
client_read :: proc(
	client: ^Client,
	dst: []u8,
) -> (
	n: int,
	error: Client_Error,
) {
	if client == nil do return 0, {kind = .Invalid_State}

	if client.phase == .Failed {
		return 0, client.last_error
	}

	if client.phase != .Noise_Ready {
		return 0, {kind = .Invalid_State}
	}

	capacity := client.config.max_frame_payload
	if len(dst) < capacity - NOISE_TAG_SIZE {
		capacity = len(dst) + NOISE_TAG_SIZE
	}

	ciphertext, allocation_err := make(
		[]u8,
		capacity,
		context.allocator,
	)
	if allocation_err != nil {
		return 0, {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
	}

	defer delete(ciphertext)
	size, frame_error := client_encrypted_frame_receive(client, ciphertext)
	if frame_error.kind != .None do return size, frame_error

	decrypted, decrypt_err := noise_decrypt(
		&client.noise,
		dst,
		ciphertext[:size],
	)
	if decrypt_err != .None {
		// The primitive also clears on authentication failure. Keep the client
		// boundary explicit before discarding failed session keys.
		crypto.zero_explicit(
			raw_data(dst),
			min(len(dst), max(0, size - NOISE_TAG_SIZE)),
		)
		return 0, client_fail(
			client,
			{kind = .Noise_Failed, noise = decrypt_err},
		)
	}

	return decrypted, {}
}

client_encrypted_frame_receive :: proc(client: ^Client, ciphertext: []u8) -> (int, Client_Error) {
	size, receive_err := frame_transport_receive(
		&client.frames,
		ciphertext,
	)
	if receive_err.kind == .Destination_Undersized {
		return size -
		NOISE_TAG_SIZE, {kind = .Destination_Undersized}
	}

	if receive_err.kind != .None {
		kind: Client_Error_Kind = .Transport_Failed
		if receive_err.kind == .Peer_Closed {
			kind = .Peer_Closed
		}

		return 0, client_fail(
			client,
			{kind = kind, transport = receive_err},
		)
	}

	return size, {}
}

// WhatsApp envelope framing

FRAME_HEADER_SIZE :: 3
MAX_FRAME_PAYLOAD :: 0xff_ffff

Frame_Error :: enum {
	Destination_Undersized,
	Header_Incomplete,
	Invalid_Consume_Count,
	None,
	Negative_Length,
	Payload_Incomplete,
	Payload_Oversized,
	Receive_Buffer_Full,
}

frame_encode_len :: proc(
	size: int,
) -> (
	header: [3]u8,
	error: Frame_Error,
) {
	if size < 0 {
		return {}, .Negative_Length
	}

	if size > MAX_FRAME_PAYLOAD {
		return {}, .Payload_Oversized
	}

	header[0] = cast(u8)(size >> 16) & 0xff
	header[1] = cast(u8)(size >> 8) & 0xff
	header[2] = cast(u8)size & 0xff

	return header, .None
}

frame_decode_len :: proc(header: [3]u8) -> int {
	return(
		cast(int)header[0] << 16 |
		cast(int)header[1] << 8 |
		cast(int)header[2] \
	)
}

frame_encode :: proc(
	dst: []u8,
	payload: []u8,
) -> (
	written: int,
	error: Frame_Error,
) {
	header, len_err := frame_encode_len(len(payload))
	if len_err != .None do return 0, len_err

	required := FRAME_HEADER_SIZE + len(payload)
	if len(dst) < required {
		return 0, .Destination_Undersized
	}

	copy(dst[:FRAME_HEADER_SIZE], header[:])
	copy(dst[FRAME_HEADER_SIZE:required], payload)

	return required, .None
}

frame_decode :: proc(
	src: []u8,
) -> (
	payload: []u8,
	consumed: int,
	error: Frame_Error,
) {
	if len(src) < FRAME_HEADER_SIZE {
		return nil, 0, .Header_Incomplete
	}

	header := [3]u8{src[0], src[1], src[2]}
	payload_size := frame_decode_len(header)

	required := FRAME_HEADER_SIZE + payload_size
	if len(src) < required {
		return nil, 0, .Payload_Incomplete
	}

	return src[FRAME_HEADER_SIZE:required], required, .None
}

Frame_Reader :: struct {
	storage: []u8,
	used:    int,
}

frame_reader_feed :: proc(
	reader: ^Frame_Reader,
	data: []u8,
) -> Frame_Error {
	available := len(reader.storage) - reader.used

	if len(data) > available do return .Receive_Buffer_Full

	copy(reader.storage[reader.used:], data)
	reader.used += len(data)

	return .None
}

frame_reader_peek :: proc(
	reader: ^Frame_Reader,
) -> (
	payload: []u8,
	consumed: int,
	error: Frame_Error,
) {
	return frame_decode(reader.storage[:reader.used])
}

frame_reader_consume :: proc(
	reader: ^Frame_Reader,
	count: int,
) -> Frame_Error {
	if count < 0 || count > reader.used {
		return .Invalid_Consume_Count
	}

	remaining := reader.used - count

	copy(
		reader.storage[:remaining],
		reader.storage[count:reader.used],
	)

	reader.used = remaining
	return .None
}

// WhatsApp envelopes over WebSocket

FRAME_INTRO :: [4]u8{87, 65, 6, 3}
DEFAULT_TRANSPORT_MAX_PAYLOAD :: 1 << 20
MAX_EMPTY_WEBSOCKET_MESSAGES :: 128

Frame_Transport_Error_Kind :: enum {
	None,
	Invalid_State,
	Already_Initialized,
	Invalid_Connection,
	Invalid_Payload_Limit,
	Payload_Oversized,
	WebSocket_Message_Oversized,
	WebSocket_Write_Failed,
	WebSocket_Read_Failed,
	Unexpected_Message_Type,
	Destination_Undersized,
	Truncated_Envelope,
	Peer_Closed,
	No_Progress,
	Allocation_Failed,
	Frame_Codec_Failed,
}

Frame_Transport_Error :: struct {
	kind:       Frame_Transport_Error_Kind,
	websocket:  network_client.WebSocket_Error,
	frame:      Frame_Error,
	allocation: mem.Allocator_Error,
}

// Borrows an already-open WebSocket. Owns only its receive buffers; clear does
// not close the socket. Payloads are opaque: Noise and message decoding happen
// above this layer. Optional routing-info/ED introduction headers are not used.
// This state must stay at a stable address and be used serially.
Frame_Transport :: struct {
	connection:                      ^network_client.WebSocket_Conn,
	max_payload:                     int,
	allocator:                       mem.Allocator,
	initialized, intro_sent, failed: bool,
	failure:                         Frame_Transport_Error,
	// Keep one complete WS message so multiple WA envelopes can be drained
	// without requiring their combined length to fit max_payload.
	ws_message:                      [dynamic]u8,
	ws_at, ws_size:                  int,
	header:                          [FRAME_HEADER_SIZE]u8,
	header_used:                     int,
	payload:                         [dynamic]u8,
	payload_used, payload_size:      int,
	ready:                           bool,
}

frame_transport_init :: proc(
	state: ^Frame_Transport,
	conn: ^network_client.WebSocket_Conn,
	max_payload: int = DEFAULT_TRANSPORT_MAX_PAYLOAD,
) -> Frame_Transport_Error {
	if state == nil {
		return {kind = .Invalid_State, frame = .None}
	}

	if state.initialized {
		return {kind = .Already_Initialized, frame = .None}
	}

	if conn == nil ||
	   conn.phase != .Open ||
	   conn.config.max_message_size <= 0 {
		return {kind = .Invalid_Connection, frame = .None}
	}

	if max_payload < 0 || max_payload > MAX_FRAME_PAYLOAD {
		return {kind = .Invalid_Payload_Limit, frame = .None}
	}

	state^ = {
		connection  = conn,
		max_payload = max_payload,
		allocator   = context.allocator,
		initialized = true,
		ws_message  = make([dynamic]u8, context.allocator),
		payload     = make([dynamic]u8, context.allocator),
	}
	return {frame = .None}
}

// Sends one binary WS message. The WA introduction is prepended to the first
// successfully sent envelope only. The WS message limit independently bounds
// the payload plus its three-byte header and first-send four-byte introduction.
// Local size errors consume nothing and can be corrected and retried.
frame_transport_send :: proc(
	state: ^Frame_Transport,
	payload: []u8,
) -> Frame_Transport_Error {
	if err := frame_transport_validate(state); err.kind != .None {
		return err
	}

	if len(payload) > state.max_payload ||
	   len(payload) > MAX_FRAME_PAYLOAD {
		return {
			kind = .Payload_Oversized,
			frame = .Payload_Oversized,
		}
	}

	intro_size := 0
	if !state.intro_sent do intro_size = len(FRAME_INTRO)

	wire_size := intro_size + FRAME_HEADER_SIZE + len(payload)
	if wire_size > state.connection.config.max_message_size {
		return {
			kind = .WebSocket_Message_Oversized,
			websocket = {kind = .Message_Oversized},
			frame = .None,
		}
	}

	wire, allocation_err := make([]u8, wire_size, state.allocator)
	if allocation_err != nil {
		return frame_transport_fail(
			state,
			{
				kind = .Allocation_Failed,
				allocation = allocation_err,
				frame = .None,
			},
		)
	}

	defer delete(wire, state.allocator)
	if intro_size != 0 {
		for value, i in FRAME_INTRO do wire[i] = value
	}

	_, frame_err := frame_encode(wire[intro_size:], payload)
	if frame_err != .None {
		return frame_transport_fail(
			state,
			{kind = .Frame_Codec_Failed, frame = frame_err},
		)
	}

	if err := network_client.websocket_write_message(state.connection, .Binary, wire);
	   err.kind != .None {
		return frame_transport_fail(
			state,
			{
				kind = .WebSocket_Write_Failed,
				websocket = err,
				frame = .None,
			},
		)
	}

	state.intro_sent = true
	return {frame = .None}
}

// Reads one WA envelope across binary WS message boundaries. Complete envelopes
// are retained if dst is undersized: n reports the required size for retry.
// Empty WA envelopes are valid and still consume their three-byte header.
frame_transport_receive :: proc(
	state: ^Frame_Transport,
	dst: []u8,
) -> (
	n: int,
	error: Frame_Transport_Error,
) {
	if err := frame_transport_validate(state); err.kind != .None {
		return 0, err
	}

	if state.ready {
		return frame_transport_deliver(state, dst)
	}

	empty_messages := 0
	for {
		if state.ws_at == state.ws_size {
			if err := frame_transport_next_message(state);
			   err.kind != .None {
				return 0, err
			}

			if state.ws_size == 0 {
				empty_messages += 1
				if empty_messages > MAX_EMPTY_WEBSOCKET_MESSAGES {
					return 0, frame_transport_fail(
						state,
						{kind = .No_Progress, frame = .None},
					)
				}

				continue
			}

		}

		if state.header_used < FRAME_HEADER_SIZE {
			complete, header_error := frame_transport_header_receive(state)
			if header_error.kind != .None do return 0, header_error
			if !complete do continue
		}

		count := copy(
			state.payload[state.payload_used:],
			state.ws_message[state.ws_at:state.ws_size],
		)
		state.payload_used += count
		state.ws_at += count
		if state.payload_used == state.payload_size {
			state.ready = true
			return frame_transport_deliver(state, dst)
		}

	}
}

frame_transport_header_receive :: proc(state: ^Frame_Transport) -> (bool, Frame_Transport_Error) {
	count := copy(
		state.header[state.header_used:],
		state.ws_message[state.ws_at:state.ws_size],
	)
	state.header_used += count
	state.ws_at += count
	if state.header_used < FRAME_HEADER_SIZE {
		return false, {}
	}

	state.payload_size = frame_decode_len(state.header)
	if state.payload_size > state.max_payload {
		return false, frame_transport_fail(
			state,
			{
				kind = .Payload_Oversized,
				frame = .Payload_Oversized,
			},
		)
	}

	// Validate the declared size before allocating payload storage.
	if allocation_err := resize(
		&state.payload,
		state.payload_size,
	); allocation_err != nil {
		return false, frame_transport_fail(
			state,
			{
				kind = .Allocation_Failed,
				allocation = allocation_err,
				frame = .None,
			},
		)
	}

	return true, {}
}

// Clears owned buffers and permits reuse with a fresh, already-open WebSocket.
// The borrowed WebSocket is deliberately left under the caller's ownership.
frame_transport_clear :: proc(state: ^Frame_Transport) {
	if state == nil do return

	delete(state.ws_message)
	delete(state.payload)
	state^ = {}
}

frame_transport_validate :: proc(
	state: ^Frame_Transport,
) -> Frame_Transport_Error {
	if state == nil || !state.initialized {
		return {kind = .Invalid_State, frame = .None}
	}

	if state.failed do return state.failure

	if state.connection == nil {
		return {kind = .Invalid_Connection, frame = .None}
	}

	return {frame = .None}
}

frame_transport_next_message :: proc(
	state: ^Frame_Transport,
) -> Frame_Transport_Error {
	for {
		opcode, size, err := network_client.websocket_read_message(
			state.connection,
			state.ws_message[:],
		)
		if err.kind == .Destination_Undersized {
			if opcode != .Binary {
				return frame_transport_fail(
					state,
					{
						kind = .Unexpected_Message_Type,
						websocket = err,
						frame = .None,
					},
				)
			}

			if size < 0 ||
			   size > state.connection.config.max_message_size {
				return frame_transport_fail(
					state,
					{
						kind = .WebSocket_Message_Oversized,
						websocket = err,
						frame = .None,
					},
				)
			}

			if allocation_err := resize(&state.ws_message, size);
			   allocation_err != nil {
				return frame_transport_fail(
					state,
					{
						kind = .Allocation_Failed,
						allocation = allocation_err,
						frame = .None,
					},
				)
			}

			continue
		}

		if err.kind != .None {
			return frame_transport_read_fail(state, err)
		}

		if opcode != .Binary {
			return frame_transport_fail(
				state,
				{kind = .Unexpected_Message_Type, frame = .None},
			)
		}

		state.ws_at, state.ws_size = 0, size
		return {frame = .None}
	}
}

frame_transport_read_fail :: proc(
	state: ^Frame_Transport, err: network_client.WebSocket_Error,
) -> Frame_Transport_Error {
	kind: Frame_Transport_Error_Kind = .WebSocket_Read_Failed
	frame_err: Frame_Error = .None
	if state.header_used > 0 || state.payload_used > 0 {
		kind = .Truncated_Envelope
		frame_err = .Payload_Incomplete
		if state.header_used < FRAME_HEADER_SIZE {
			frame_err = .Header_Incomplete
		}

	} else if err.kind == .EOF {
		kind = .Peer_Closed
	}

	return frame_transport_fail(
		state,
		{kind = kind, websocket = err, frame = frame_err},
	)
}

frame_transport_deliver :: proc(
	state: ^Frame_Transport,
	dst: []u8,
) -> (
	int,
	Frame_Transport_Error,
) {
	if len(dst) < state.payload_size {
		return state.payload_size, {
			kind = .Destination_Undersized,
			frame = .Destination_Undersized,
		}
	}

	count := copy(dst, state.payload[:])
	state.ready = false
	state.header_used, state.payload_used, state.payload_size =
		0, 0, 0
	clear(&state.payload)
	return count, {frame = .None}
}

frame_transport_fail :: proc(
	state: ^Frame_Transport,
	err: Frame_Transport_Error,
) -> Frame_Transport_Error {
	delete(state.ws_message)
	delete(state.payload)
	state.ws_message, state.payload = nil, nil
	state.failed = true
	state.failure = err
	state.ready = false
	return err
}

// Noise and Curve25519 cryptographic primitives.

// Noise cryptographic state

NOISE_HEADER :: [4]u8{87, 65, 6, 3}
NOISE_MODE :: "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
NOISE_TAG_SIZE :: 16
MAX_NOISE_PLAINTEXT_SIZE :: MAX_FRAME_PAYLOAD - NOISE_TAG_SIZE
NOISE_COUNTER_LIMIT :: cast(u64)1 << 32

Noise_Phase :: enum {
	Uninitialized,
	Handshake,
	Transport,
	Failed,
}

Noise_Error :: enum {
	None,
	Invalid_State,
	Destination_Undersized,
	Overlapping_Buffers,
	Ciphertext_Too_Short,
	Payload_Oversized,
	Counter_Exhausted,
	Authentication_Failed,
}

// Internal, caller-owned state; keep at a stable address and do not copy or
// mutate it while live. DH and certificate authentication live above this
// symmetric layer. Counters are u64 only to represent the exhausted 2^32 state.
Noise_State :: struct {
	hash:                        [32]u8,
	chaining_key:                [32]u8,
	write_key:                   [32]u8,
	read_key:                    [32]u8,
	write_counter, read_counter: u64,
	phase:                       Noise_Phase,
	failure:                     Noise_Error,
}

// Match Baileys 6.7.23's exact initialization: no initial empty-payload hash.
// Unlike generic Noise libraries, its 32-byte protocol name includes four NULs.
// The initial ck/keys remain the protocol name while h mixes header then e.
noise_init :: proc(
	state: ^Noise_State,
	ephemeral_public: [32]u8,
) -> Noise_Error {
	if state == nil || state.phase != .Uninitialized {
		return .Invalid_State
	}

	mode := NOISE_MODE
	copy(state.hash[:], transmute([]u8)mode)
	state.chaining_key = state.hash
	state.write_key, state.read_key = state.hash, state.hash
	state.write_counter, state.read_counter = 0, 0
	state.failure = .None
	state.phase = .Handshake
	header := NOISE_HEADER
	ephemeral := ephemeral_public
	noise_mix_hash(state, header[:])
	noise_mix_hash(state, ephemeral[:])
	return .None
}

// Baileys authenticate() becomes a no-op after transport keys are installed.
noise_mix_hash :: proc(
	state: ^Noise_State,
	data: []u8,
) -> Noise_Error {
	if err := noise_state_validate(state); err != .None {
		return err
	}

	if state.phase == .Transport do return .None

	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, state.hash[:])
	sha2.update(&ctx, data)
	sha2.final(&ctx, state.hash[:])
	return .None
}

// HKDF-SHA256(IKM=DH, salt=ck, info="", length=64). Both handshake
// directions use the second half, and share a single counter until split.
noise_mix_key :: proc(
	state: ^Noise_State,
	shared: [32]u8,
) -> Noise_Error {
	if err := noise_state_validate(state); err != .None {
		return err
	}

	if state.phase != .Handshake do return .Invalid_State

	secret := shared
	defer crypto.zero_explicit(&secret, size_of(secret))
	derived: [64]u8
	defer crypto.zero_explicit(&derived, size_of(derived))
	hkdf.extract_and_expand(
		.SHA256,
		state.chaining_key[:],
		secret[:],
		nil,
		derived[:],
	)
	copy(state.chaining_key[:], derived[:32])
	copy(state.write_key[:], derived[32:])
	state.read_key = state.write_key
	state.write_counter, state.read_counter = 0, 0
	return .None
}

// Initiator split: first HKDF half writes, second reads. There is no AAD in
// transport mode, and send/receive nonces advance independently from zero.
// A second split is rejected so traffic nonces can never be reset accidentally.
noise_split :: proc(state: ^Noise_State) -> Noise_Error {
	if err := noise_state_validate(state); err != .None {
		return err
	}

	if state.phase != .Handshake do return .Invalid_State

	derived: [64]u8
	defer crypto.zero_explicit(&derived, size_of(derived))
	hkdf.extract_and_expand(
		.SHA256,
		state.chaining_key[:],
		nil,
		nil,
		derived[:],
	)
	copy(state.write_key[:], derived[:32])
	copy(state.read_key[:], derived[32:])
	crypto.zero_explicit(
		&state.chaining_key,
		size_of(state.chaining_key),
	)
	crypto.zero_explicit(&state.hash, size_of(state.hash))
	state.write_counter, state.read_counter = 0, 0
	state.phase = .Transport
	return .None
}

// Appends a 16-byte GCM tag. Invalid local buffer arguments do not advance
// counters, update h, or write dst. Source and destination must not overlap.
noise_encrypt :: proc(
	state: ^Noise_State,
	dst, plaintext: []u8,
) -> (
	written: int,
	error: Noise_Error,
) {
	if err := noise_state_validate(state); err != .None {
		return 0, err
	}

	if len(plaintext) > MAX_NOISE_PLAINTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	if len(dst) < NOISE_TAG_SIZE ||
	   len(plaintext) > len(dst) - NOISE_TAG_SIZE {
		return 0, .Destination_Undersized
	}

	written = len(plaintext) + NOISE_TAG_SIZE
	if bytes.alias(dst[:written], plaintext) {
		return 0, .Overlapping_Buffers
	}

	if state.write_counter >= NOISE_COUNTER_LIMIT {
		return 0, noise_fail(state, .Counter_Exhausted)
	}

	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, state.write_key[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	nonce := noise_nonce(state.write_counter)
	aad: []u8
	if state.phase == .Handshake do aad = state.hash[:]

	aes.seal_gcm(
		&ctx,
		dst[:len(plaintext)],
		dst[len(plaintext):written],
		nonce[:],
		aad,
		plaintext,
	)
	state.write_counter += 1
	noise_mix_hash(state, dst[:written])
	return written, .None
}

// During the handshake decryption advances the same counter as encryption.
// Authentication failure clears dst and permanently destroys this state.
noise_decrypt :: proc(
	state: ^Noise_State,
	dst, ciphertext: []u8,
) -> (
	written: int,
	error: Noise_Error,
) {
	if err := noise_state_validate(state); err != .None {
		return 0, err
	}

	if len(ciphertext) < NOISE_TAG_SIZE {
		return 0, .Ciphertext_Too_Short
	}

	if len(ciphertext) > MAX_FRAME_PAYLOAD {
		return 0, .Payload_Oversized
	}

	written = len(ciphertext) - NOISE_TAG_SIZE
	if len(dst) < written {
		return 0, .Destination_Undersized
	}

	if bytes.alias(dst[:written], ciphertext) {
		return 0, .Overlapping_Buffers
	}

	counter := state.write_counter
	if state.phase == .Transport {
		counter = state.read_counter
	}

	if counter >= NOISE_COUNTER_LIMIT {
		return 0, noise_fail(state, .Counter_Exhausted)
	}

	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, state.read_key[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	nonce := noise_nonce(counter)
	aad: []u8
	if state.phase == .Handshake do aad = state.hash[:]

	valid := aes.open_gcm(
		&ctx,
		dst[:written],
		nonce[:],
		aad,
		ciphertext[:written],
		ciphertext[written:],
	)
	if !valid {
		crypto.zero_explicit(raw_data(dst), written)
		return 0, noise_fail(state, .Authentication_Failed)
	}

	if state.phase == .Transport {
		state.read_counter += 1
	} else {
		state.write_counter += 1
	}

	noise_mix_hash(state, ciphertext)
	return written, .None
}

noise_clear :: proc(state: ^Noise_State) {
	if state != nil {
		crypto.zero_explicit(state, size_of(Noise_State))
	}

}

noise_nonce :: proc(counter: u64) -> [12]u8 {
	// Baileys generateIV uses DataView.setUint32(8, counter), big-endian.
	return {
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		cast(u8)(counter >> 24),
		cast(u8)(counter >> 16),
		cast(u8)(counter >> 8),
		cast(u8)counter,
	}
}

noise_state_validate :: proc(state: ^Noise_State) -> Noise_Error {
	if state == nil || state.phase == .Uninitialized {
		return .Invalid_State
	}

	if state.phase == .Failed do return state.failure

	return .None
}

noise_fail :: proc(
	state: ^Noise_State,
	err: Noise_Error,
) -> Noise_Error {
	noise_clear(state)
	state.phase, state.failure = .Failed, err
	return err
}

// Signal Curve25519 signatures

/*
Signal's Curve25519 signature construction follows curve25519-js 0.0.4:
https://github.com/harveyconnor/curve25519-js (lib/index.js).
The pinned libsignal wrapper is bcea72df9ec34d9d9140ab30619cf479c7c144c7.
Scalar/group arithmetic is provided by Odin's core crypto packages.

Copyright (c) 2019 Smart Guide Pty Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


Signal_Error :: enum {
	None,
	Entropy_Unavailable,
	Nonce_Generation_Failed,
	Invalid_Public_Key,
	Invalid_Signature_Length,
	Invalid_Signature_Encoding,
	Verification_Failed,
}

// Raw 32-byte Montgomery public key, without Signal's key-type prefix 0x05.
signal_curve_public :: proc(private: [32]u8) -> [32]u8 {
	secret := private
	defer crypto.zero_explicit(&secret, size_of(secret))
	public: [32]u8
	x25519.scalarmult_basepoint(public[:], secret[:])
	return public
}

// This is Signal's direct/clamped-scalar signature variant, not Ed25519 seed
// signing. Randomized nonces use curve25519-js's domain-separated 64-byte
// random-suffix construction. Its verifier also accepts deterministic legacy
// signatures. The Edwards public-key sign bit is carried in signature[63].
signal_curve_sign :: proc(
	private: [32]u8,
	message: []u8,
) -> (
	signature: [64]u8,
	error: Signal_Error,
) {
	when !crypto.HAS_RAND_BYTES do return {}, .Entropy_Unavailable
	secret := private
	defer crypto.zero_explicit(&secret, size_of(secret))
	secret[0] &= 248
	secret[31] = (secret[31] & 127) | 64
	a, nonce, challenge, s: grp.Scalar
	defer grp.sc_clear(&a)
	defer grp.sc_clear(&nonce)
	defer grp.sc_clear(&challenge)
	defer grp.sc_clear(&s)
	grp.sc_set_bytes_rfc8032(&a, secret[:])
	A, R: grp.Group_Element
	defer grp.ge_clear(&A)
	defer grp.ge_clear(&R)
	grp.ge_scalarmult_basepoint(&A, &a)
	public: [32]u8
	grp.ge_bytes(&A, public[:])
	random, digest: [64]u8
	defer crypto.zero_explicit(&random, size_of(random))
	defer crypto.zero_explicit(&digest, size_of(digest))
	domain: [32]u8
	for &value in domain do value = 0xff
	domain[0] = 0xfe
	ctx: sha2.Context_512
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	// Avoid the negligible zero-nonce case because verification rejects all
	// low-order R points. Independent randomness is sampled on each attempt.
	zero: grp.Scalar
	generated := false
	for _ in 0 ..< 8 {
		crypto.rand_bytes(random[:])
		sha2.init_512(&ctx)
		sha2.update(&ctx, domain[:])
		sha2.update(&ctx, secret[:])
		sha2.update(&ctx, message)
		sha2.update(&ctx, random[:])
		sha2.final(&ctx, digest[:])
		grp.sc_set_bytes_wide(&nonce, &digest)
		if grp.sc_equal(&nonce, &zero) != 1 {
			generated = true
			break
		}

	}
	if !generated do return {}, .Nonce_Generation_Failed

	grp.ge_scalarmult_basepoint(&R, &nonce)
	grp.ge_bytes(&R, signature[:32])
	sha2.init_512(&ctx)
	sha2.update(&ctx, signature[:32])
	sha2.update(&ctx, public[:])
	sha2.update(&ctx, message)
	sha2.final(&ctx, digest[:])
	grp.sc_set_bytes_wide(&challenge, &digest)
	grp.sc_mul(&s, &challenge, &a)
	grp.sc_add(&s, &s, &nonce)
	grp.sc_bytes(signature[32:], &s)
	signature[63] |= public[31] & 0x80
	return signature, .None
}

// Strict verification: canonical Montgomery key, canonical R/S encodings,
// and prime-order A/R. This intentionally rejects malformed/malleable encodings
// tolerated by older JS verifiers; correctly generated signatures interoperate.
signal_curve_verify :: proc(
	public: [32]u8,
	message, signature: []u8,
) -> Signal_Error {
	if len(signature) != 64 {
		return .Invalid_Signature_Length
	}

	ed_public, public_error := signal_curve_edwards_public(public, signature)
	if public_error != .None do return public_error
	A, R, neg_A, calculated: grp.Group_Element
	if !grp.ge_set_bytes(&A, ed_public[:]) ||
	   grp.ge_is_small_order(&A) ||
	   !grp.ge_in_prime_order_subgroup_vartime(&A) {
		return .Invalid_Public_Key
	}

	if !grp.ge_set_bytes(&R, signature[:32]) ||
	   grp.ge_is_small_order(&R) ||
	   !grp.ge_in_prime_order_subgroup_vartime(&R) {
		return .Invalid_Signature_Encoding
	}

	s_bytes: [32]u8
	copy(s_bytes[:], signature[32:])
	s_bytes[31] &= 127
	s, challenge: grp.Scalar
	if !grp.sc_set_bytes(&s, s_bytes[:]) {
		return .Invalid_Signature_Encoding
	}

	ctx: sha2.Context_512
	digest: [64]u8
	sha2.init_512(&ctx)
	sha2.update(&ctx, signature[:32])
	sha2.update(&ctx, ed_public[:])
	sha2.update(&ctx, message)
	sha2.final(&ctx, digest[:])
	grp.sc_set_bytes_wide(&challenge, &digest)
	grp.ge_negate(&neg_A, &A)
	grp.ge_double_scalarmult_basepoint_vartime(
		&calculated,
		&challenge,
		&neg_A,
		&s,
	)
	if grp.ge_equal(&calculated, &R) != 1 {
		return .Verification_Failed
	}

	return .None
}

signal_curve_edwards_public :: proc(
	public: [32]u8, signature: []u8,
) -> ([32]u8, Signal_Error) {
	public_copy := public
	u, one, numerator, denominator, inverse, y, zero: field.Tight_Field_Element
	field.fe_from_bytes(&u, &public_copy)
	if field.fe_equal_bytes(&u, &public_copy) != 1 {
		return {}, .Invalid_Public_Key
	}

	field.fe_one(&one)
	field.fe_carry_add(&denominator, &u, &one)
	if field.fe_equal(&denominator, &zero) == 1 {
		return {}, .Invalid_Public_Key
	}

	field.fe_carry_sub(&numerator, &u, &one)
	field.fe_carry_inv(&inverse, field.fe_relax_cast(&denominator))
	field.fe_carry_mul(
		&y,
		field.fe_relax_cast(&numerator),
		field.fe_relax_cast(&inverse),
	)
	ed_public: [32]u8
	field.fe_to_bytes(&ed_public, &y)
	ed_public[31] |= signature[63] & 0x80
	return ed_public, .None
}

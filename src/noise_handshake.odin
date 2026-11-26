package whatsapp

import "core:crypto"
import "core:crypto/x25519"
import "core:mem"
import "core:time"
import "shared:surf"

Noise_Credentials :: struct {
	// Persisted device Noise key, distinct from the per-connection ephemeral.
	static_private_key: [32]u8,
}

Client_Config :: struct {
	max_frame_payload:  int, // Zero defaults to 1 MiB.
	handshake_timeout:  time.Duration, // Zero defaults to 10 seconds where supported.
	// Nil verifies both Signal certificate signatures against the pinned root,
	// issuer linkage, static-key binding and current validity. A hook replaces it.
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
	websocket:   surf.WebSocket_Error,
	stream:      surf.WebSocket_Stream_Error,
	allocation:  mem.Allocator_Error,
}

// Caller-owned and serialized. Successful initialization transfers shutdown
// responsibility for websocket to this client. Noise_Ready means encryption
// is established, not that this device has been paired or logged in.
Client :: struct {
	websocket:         ^surf.WebSocket_Conn,
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

noise_credentials_generate :: proc() -> (credentials: Noise_Credentials, error: Client_Error) {
	when !crypto.HAS_RAND_BYTES {
		return {}, {kind = .Entropy_Unavailable}
	}

	crypto.rand_bytes(credentials.static_private_key[:])

	return credentials, {}
}

client_init :: proc(
	client: ^Client,
	websocket: ^surf.WebSocket_Conn,
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

	when !crypto.HAS_RAND_BYTES {
		return {kind = .Entropy_Unavailable}
	}

	if err := frame_transport_init(&client.frames, websocket, settings.max_frame_payload);
	   err.kind != .None {
		return {kind = .Transport_Failed, transport = err}
	}

	client.websocket = websocket
	client.config = settings
	client.static_private = private
	x25519.scalarmult_basepoint(client.static_public[:], client.static_private[:])
	crypto.rand_bytes(client.ephemeral_private[:])
	x25519.scalarmult_basepoint(client.ephemeral_public[:], client.ephemeral_private[:])
	if err := noise_init(&client.noise, client.ephemeral_public); err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	client.phase = .Initialized
	return {}
}

// Runs the ClientHello -> ServerHello -> ClientFinish exchange. The
// payload is an already encoded WAProto.ClientPayload; registration/login
// construction belongs to the credentials/pairing layer above this package.
client_handshake :: proc(client: ^Client, client_payload: []u8) -> Client_Error {
	if client == nil {
		return {kind = .Invalid_State}
	}

	if client.phase == .Noise_Ready {
		return {}
	}

	if client.phase == .Failed {
		return client.last_error
	}

	if client.phase != .Initialized {
		return {kind = .Invalid_State}
	}

	finish_size := client_finish_wire_size(len(client_payload))

	if finish_size > client.config.max_frame_payload ||
	   finish_size > client.websocket.config.max_message_size - 3 {
		return {kind = .Payload_Oversized}
	}

	deadlines_set, deadline_error := client_handshake_deadline_start(client)
	if deadline_error.kind != .None {
		return deadline_error
	}

	defer {
		if deadlines_set &&
		   (client.phase != .Failed && client.phase != .Closed) &&
		   client.websocket.phase == .Open {
			surf.websocket_set_deadline(client.websocket, {})
		}
	}

	client.phase = .Handshake
	if exchange_error := client_handshake_exchange(client, client_payload, finish_size);
	   exchange_error.kind != .None {
		return exchange_error
	}

	if err := noise_split(&client.noise); err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	client_secret_keys_clear(client)

	if deadlines_set {
		if err := surf.websocket_set_deadline(client.websocket, {}); err.kind != .None {
			return client_fail(client, {kind = .Deadline_Failed, stream = err})
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
		if timeout == 0 {
			timeout = 10 * time.Second
		}

		if err := surf.websocket_set_deadline(
			client.websocket,
			time.time_add(time.now(), timeout),
		); err.kind != .None {
			return false, client_fail(client, {kind = .Deadline_Failed, stream = err})
		}

		deadlines_set = true
	} else if client.config.handshake_timeout > 0 {
		return false, client_fail(
			client,
			{kind = .Deadline_Failed, stream = {kind = .Deadline_Unsupported}},
		)
	}

	return deadlines_set, {}
}

client_handshake_hello_send :: proc(client: ^Client) -> Client_Error {
	hello: [36]u8
	size, encode_err := handshake_client_hello_encode(hello[:], client.ephemeral_public)

	if encode_err != .None {
		return client_fail(client, {kind = .Protobuf_Failed, protobuf = encode_err})
	}

	if err := frame_transport_send(&client.frames, hello[:size]); err.kind != .None {
		return client_fail(client, {kind = .Transport_Failed, transport = err})
	}

	return {}
}

client_handshake_server_read :: proc(
	client: ^Client,
	server_buffer: []u8,
) -> (
	Handshake_Message,
	Client_Error,
) {
	received, receive_err := frame_transport_receive(&client.frames, server_buffer)

	if receive_err.kind != .None {
		return {}, client_fail(client, {kind = .Transport_Failed, transport = receive_err})
	}

	server, decode_err := handshake_message_decode(server_buffer[:received])

	if decode_err != .None {
		return {}, client_fail(client, {kind = .Protobuf_Failed, protobuf = decode_err})
	}

	if server.kind != .Server_Hello {
		return {}, client_fail(client, {kind = .Unexpected_Handshake_Message})
	}

	if !server.has_ephemeral || len(server.ephemeral) != 32 {
		return {}, client_fail(client, {kind = .Invalid_Server_Ephemeral})
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
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	return {}
}

client_handshake_server_static_decrypt :: proc(
	client: ^Client,
	server: Handshake_Message,
	server_static: []u8,
) -> Client_Error {
	if err := noise_mix_hash(&client.noise, server.ephemeral); err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	if dh_error := client_noise_mix_dh(client, client.ephemeral_private[:], server.ephemeral);
	   dh_error.kind != .None {
		return dh_error
	}

	if _, err := noise_decrypt(&client.noise, server_static, server.static); err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	return client_noise_mix_dh(client, client.ephemeral_private[:], server_static)
}

client_decrypt_and_verify_server_certificate :: proc(
	client: ^Client,
	server: Handshake_Message,
	server_static: ^[32]u8,
) -> Client_Error {
	certificate, cert_alloc_err := make(
		[]u8,
		len(server.payload) - NOISE_TAG_SIZE,
		context.allocator,
	)
	if cert_alloc_err != nil {
		return client_fail(client, {kind = .Allocation_Failed, allocation = cert_alloc_err})
	}
	defer delete(certificate)

	if _, err := noise_decrypt(&client.noise, certificate, server.payload); err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	verify := client.config.verify_certificate
	if verify == nil {
		verify = verify_whatsapp_server_certificate
	}

	if err := verify(certificate, server_static^); err != .None {
		return client_fail(client, {kind = .Certificate_Rejected, certificate = err})
	}

	return {}
}

client_handshake_static_send_prepare :: proc(
	client: ^Client,
	server: Handshake_Message,
	encrypted_static: []u8,
) -> Client_Error {
	if _, err := noise_encrypt(&client.noise, encrypted_static, client.static_public[:]);
	   err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	return client_noise_mix_dh(client, client.static_private[:], server.ephemeral)
}

client_handshake_finish_send :: proc(
	client: ^Client,
	encrypted_static, encrypted_payload: []u8,
	finish_size: int,
) -> Client_Error {
	finish, finish_alloc_err := make([]u8, finish_size, context.allocator)
	if finish_alloc_err != nil {
		return client_fail(client, {kind = .Allocation_Failed, allocation = finish_alloc_err})
	}
	defer delete(finish)

	_, finish_err := handshake_client_finish_encode(finish, encrypted_static, encrypted_payload)
	if finish_err != .None {
		return client_fail(client, {kind = .Protobuf_Failed, protobuf = finish_err})
	}

	if err := frame_transport_send(&client.frames, finish); err.kind != .None {
		return client_fail(client, {kind = .Transport_Failed, transport = err})
	}

	return {}
}

client_handshake_payload_send :: proc(
	client: ^Client,
	client_payload, encrypted_static: []u8,
	finish_size: int,
) -> Client_Error {
	encrypted_payload, payload_alloc_err := make(
		[]u8,
		len(client_payload) + NOISE_TAG_SIZE,
		context.allocator,
	)
	if payload_alloc_err != nil {
		return client_fail(client, {kind = .Allocation_Failed, allocation = payload_alloc_err})
	}
	defer delete(encrypted_payload)

	if _, err := noise_encrypt(&client.noise, encrypted_payload, client_payload); err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = err})
	}

	return client_handshake_finish_send(client, encrypted_static, encrypted_payload, finish_size)
}

client_handshake_exchange :: proc(
	client: ^Client,
	client_payload: []u8,
	finish_size: int,
) -> Client_Error {
	if hello_error := client_handshake_hello_send(client); hello_error.kind != .None {
		return hello_error
	}

	server_buffer, allocation_err := make([]u8, client.config.max_frame_payload, context.allocator)

	if allocation_err != nil {
		return client_fail(client, {kind = .Allocation_Failed, allocation = allocation_err})
	}
	defer delete(server_buffer)

	server, server_error := client_handshake_server_read(client, server_buffer)
	if server_error.kind != .None {
		return server_error
	}

	server_static: [32]u8
	if static_error := client_handshake_server_static_decrypt(client, server, server_static[:]);
	   static_error.kind != .None {
		return static_error
	}

	if certificate_error := client_decrypt_and_verify_server_certificate(
		client,
		server,
		&server_static,
	); certificate_error.kind != .None {
		return certificate_error
	}

	encrypted_static: [48]u8
	if static_error := client_handshake_static_send_prepare(client, server, encrypted_static[:]);
	   static_error.kind != .None {
		return static_error
	}

	return client_handshake_payload_send(client, client_payload, encrypted_static[:], finish_size)
}

client_close :: proc(client: ^Client) -> Client_Error {
	if client == nil || client.phase == .Uninitialized {
		return {kind = .Invalid_State}
	}

	if client.phase == .Closed {
		return {}
	}

	frame_transport_clear(&client.frames)
	noise_clear(&client.noise)
	client_secret_keys_clear(client)
	client.phase = .Closed

	if err := surf.websocket_close(client.websocket); err.kind != .None {
		return {kind = .WebSocket_Close_Failed, websocket = err}
	}

	return {}
}

client_fail :: proc(client: ^Client, err: Client_Error) -> Client_Error {
	client.phase = .Failed
	client.last_error = err
	frame_transport_clear(&client.frames)
	noise_clear(&client.noise)
	client_secret_keys_clear(client)
	surf.websocket_close(client.websocket, 1008)

	return err
}

client_secret_keys_clear :: proc(client: ^Client) {
	crypto.zero_explicit(&client.static_private, size_of(client.static_private))
	crypto.zero_explicit(&client.ephemeral_private, size_of(client.ephemeral_private))
}

client_finish_wire_size :: proc(payload_size: int) -> int {
	if payload_size > MAX_FRAME_PAYLOAD - NOISE_TAG_SIZE {
		return MAX_FRAME_PAYLOAD + 1
	}

	encrypted_size := payload_size + NOISE_TAG_SIZE
	inner := 50 + 1 + protobuf_varint_size(cast(u64)encrypted_size) + encrypted_size

	return 1 + protobuf_varint_size(cast(u64)inner) + inner
}

// Sends an opaque encoded WhatsApp binary node under the established Noise
// keys. The node codec and account/session state live above this layer.
client_write :: proc(client: ^Client, payload: []u8) -> Client_Error {
	if client == nil {
		return {kind = .Invalid_State}
	}

	if client.phase == .Failed {
		return client.last_error
	}

	if client.phase != .Noise_Ready {
		return {kind = .Invalid_State}
	}

	if len(payload) > client.config.max_frame_payload - NOISE_TAG_SIZE ||
	   len(payload) >
		   client.websocket.config.max_message_size - FRAME_HEADER_SIZE - NOISE_TAG_SIZE {
		return {kind = .Payload_Oversized}
	}

	ciphertext, allocation_err := make([]u8, len(payload) + NOISE_TAG_SIZE, context.allocator)

	if allocation_err != nil {
		return {kind = .Allocation_Failed, allocation = allocation_err}
	}
	defer delete(ciphertext)

	_, encrypt_err := noise_encrypt(&client.noise, ciphertext, payload)

	if encrypt_err != .None {
		return client_fail(client, {kind = .Noise_Failed, noise = encrypt_err})
	}

	if err := frame_transport_send(&client.frames, ciphertext); err.kind != .None {
		return client_fail(client, {kind = .Transport_Failed, transport = err})
	}

	return {}
}

// Returns decrypted node bytes. On Destination_Undersized, n gives the
// required plaintext size and the encrypted envelope remains queued for retry;
// no nonce is consumed until decryption is attempted with enough space.
client_read :: proc(client: ^Client, dst: []u8) -> (n: int, error: Client_Error) {
	if client == nil {
		return 0, {kind = .Invalid_State}
	}

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

	ciphertext, allocation_err := make([]u8, capacity, context.allocator)

	if allocation_err != nil {
		return 0, {kind = .Allocation_Failed, allocation = allocation_err}
	}
	defer delete(ciphertext)

	size, frame_error := client_encrypted_frame_receive(client, ciphertext)
	if frame_error.kind != .None {
		return size, frame_error
	}

	decrypted, decrypt_err := noise_decrypt(&client.noise, dst, ciphertext[:size])

	if decrypt_err != .None {
		// The primitive also clears on authentication failure. Keep the client
		// boundary explicit before discarding failed session keys.
		crypto.zero_explicit(raw_data(dst), min(len(dst), max(0, size - NOISE_TAG_SIZE)))
		return 0, client_fail(client, {kind = .Noise_Failed, noise = decrypt_err})
	}

	return decrypted, {}
}

client_encrypted_frame_receive :: proc(client: ^Client, ciphertext: []u8) -> (int, Client_Error) {
	size, receive_err := frame_transport_receive(&client.frames, ciphertext)

	if receive_err.kind == .Destination_Undersized {
		return size - NOISE_TAG_SIZE, {kind = .Destination_Undersized}
	}

	if receive_err.kind != .None {
		kind: Client_Error_Kind = .Transport_Failed

		if receive_err.kind == .Peer_Closed {
			kind = .Peer_Closed
		}

		return 0, client_fail(client, {kind = kind, transport = receive_err})
	}

	return size, {}
}

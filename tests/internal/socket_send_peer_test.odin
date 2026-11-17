package whatsapp

import http "../http"
import network_client "../surf"
import ws "../websocket"
import "core:bytes"
import "core:fmt"
import "core:net"
import "core:os"
import "core:slice"
import "core:sys/posix"
import "core:time"

// Synthetic WhatsApp peer for the send paths. Real WebSocket framing, Noise
// transport, IQ routing, X3DH, pairwise Signal and sender-key records run
// against in-memory keys; no account, network or provider is involved. The
// peer owns group 123@g.us with two members: us (111:1) and 222 (devices 1, 2).
Send_Peer :: struct {
	socket:                                        Socket,
	auth:                                          Auth_State,
	store:                                         State_Store,
	prekeys:                                       Prekey_Store,
	noise:                                         Noise_State,
	local:                                         [2]Signal_Recipient_Keys,
	pairwise:                                      [2]Signal_Session,
	groups:                                        [2]Signal_Group_Record,
	input:                                         [dynamic]u8,
	read_at:                                       int,
	raw:                                           [dynamic][]u8,
	last_plain:                                    [16384]u8,
	last_size:                                     int,
	last_id:                                       [128]u8,
	last_id_size:                                  int,
	media_type:                                    [32]u8,
	media_type_size:                               int,
	uploaded:                                      [dynamic]u8,
	directory, path:                               string,
	durable, failed, fail_message:                 bool,
	metadata_queries, device_queries, key_queries: int,
	upload_requests, upload_status:                int,
	pipe:                                          [2]posix.FD,
	pipe_pending:                                  bool,
}

send_peer_private :: proc(start: int) -> [32]u8 {
	value: [32]u8

	for &b, i in value {
		b = u8(start + i)
	}

	value[0] &= 248
	value[31] = value[31] & 127 | 64

	return value
}

send_peer_local :: proc(start: int, registration: u32) -> Signal_Recipient_Keys {
	return {
		identity_private = send_peer_private(start),
		registration_id = registration,
		signed_prekey_private = send_peer_private(start + 32),
		signed_prekey_id = 7,
		has_prekey = true,
		prekey_private = send_peer_private(start + 64),
		prekey_id = 9,
	}
}

send_peer_bundle :: proc(local: Signal_Recipient_Keys) -> Signal_Prekey_Bundle {
	bundle := Signal_Prekey_Bundle {
		registration_id = local.registration_id,
		identity_public = signal_curve_public(local.identity_private),
		signed_prekey_id = local.signed_prekey_id,
		signed_prekey_public = signal_curve_public(local.signed_prekey_private),
		has_prekey = local.has_prekey,
		prekey_id = local.prekey_id,
		prekey_public = signal_curve_public(local.prekey_private),
	}
	signed: [33]u8
	signed[0] = 5
	copy(signed[1:], bundle.signed_prekey_public[:])
	error: Signal_Error
	bundle.signed_prekey_signature, error = signal_curve_sign(local.identity_private, signed[:])
	assert(error == .None)

	return bundle
}

send_peer_noise_key :: proc(start: int) -> [32]u8 {
	value: [32]u8

	for &b, i in value {
		b = u8(start + i)
	}

	return value
}

send_peer_server_frame :: proc(dst: []u8, payload: []u8) -> int {
	dst[0] = 0x82
	at := 2

	if len(payload) < 126 {
		dst[1] = u8(len(payload))
	} else {
		dst[1] = 126
		dst[2] = u8(len(payload) >> 8)
		dst[3] = u8(len(payload))
		at = 4
	}

	copy(dst[at:], payload)

	return at + len(payload)
}

send_peer_read :: proc(data: rawptr, dst: []u8) -> (int, network_client.WebSocket_Stream_Error) {
	peer := cast(^Send_Peer)data

	if peer.pipe_pending {
		// Consume the readiness byte that announced the queued input.
		peer.pipe_pending = false
		byte: [1]u8
		posix.read(peer.pipe[0], raw_data(byte[:]), 1)
	}

	n := min(len(dst), len(peer.input) - peer.read_at)

	if n == 0 {
		return 0, {kind = .EOF}
	}

	copy(dst, peer.input[peer.read_at:][:n])
	peer.read_at += n

	return n, {}
}

send_peer_close :: proc(data: rawptr) -> network_client.WebSocket_Stream_Error {
	return {}
}

send_peer_deadline :: proc(data: rawptr, deadline: time.Time) -> network_client.WebSocket_Stream_Error {
	return {}
}

send_peer_enqueue :: proc(peer: ^Send_Peer, node: Binary_Node) {
	wire: [8192]u8
	n, encode_error := binary_node_encode(wire[:], node)

	if encode_error.kind != .None {
		peer.failed = true
		return
	}

	ciphertext: [8208]u8
	size, noise_error := noise_encrypt(&peer.noise, ciphertext[:], wire[:n])

	if noise_error != .None {
		peer.failed = true
		return
	}

	envelope: [8211]u8
	envelope[0] = u8(size >> 16)
	envelope[1] = u8(size >> 8)
	envelope[2] = u8(size)
	copy(envelope[3:], ciphertext[:size])
	frame: [8221]u8
	frame_size := send_peer_server_frame(frame[:], envelope[:size + 3])
	append(&peer.input, ..frame[:frame_size])
}

send_peer_device_node :: proc(id, key_index: string) -> Binary_Node {
	attrs := new([2]Binary_Node_Attribute, context.temp_allocator)
	attrs^ = {{"id", id}, {"key-index", key_index}}

	return {tag = "device", attrs = attrs[:]}
}

send_peer_user_node :: proc(jid: string, devices: []Binary_Node) -> Binary_Node {
	attrs := new([1]Binary_Node_Attribute, context.temp_allocator)
	attrs^ = {{"jid", jid}}
	list := new([1]Binary_Node, context.temp_allocator)
	list^ = {{tag = "device-list", content = devices}}
	holder := new([1]Binary_Node, context.temp_allocator)
	holder^ = {{tag = "devices", content = list[:]}}

	return {tag = "user", attrs = attrs[:], content = holder[:]}
}

send_peer_participant_node :: proc(jid: string) -> Binary_Node {
	attrs := new([1]Binary_Node_Attribute, context.temp_allocator)
	attrs^ = {{"jid", jid}}

	return {tag = "participant", attrs = attrs[:]}
}

send_peer_iq :: proc(peer: ^Send_Peer, node: Binary_Node) {
	id, _ := node_attr(node, "id")
	xmlns, _ := node_attr(node, "xmlns")
	attrs := []Binary_Node_Attribute{{"type", "result"}, {"id", id}, {"from", "s.whatsapp.net"}}

	switch xmlns {
	case "w:g2":
		peer.metadata_queries += 1
		attrs[2] = {"from", "123@g.us"}
		group_attrs := []Binary_Node_Attribute{{"id", "123"}, {"subject", "Synthetic"}, {"addressing_mode", "pn"}}
		participants := []Binary_Node{send_peer_participant_node("111@s.whatsapp.net"), send_peer_participant_node("222@s.whatsapp.net")}
		group := []Binary_Node{{tag = "group", attrs = group_attrs, content = participants}}
		send_peer_enqueue(peer, {tag = "iq", attrs = attrs, content = group})
	case "usync":
		peer.device_queries += 1
		own := []Binary_Node{send_peer_device_node("1", "1")}
		other := []Binary_Node{send_peer_device_node("1", "1"), send_peer_device_node("2", "2")}
		users := []Binary_Node{send_peer_user_node("111@s.whatsapp.net", own), send_peer_user_node("222@s.whatsapp.net", other)}
		list := []Binary_Node{{tag = "list", content = users}}
		usync := []Binary_Node{{tag = "usync", content = list}}
		send_peer_enqueue(peer, {tag = "iq", attrs = attrs, content = usync})
	case "encrypt":
		peer.key_queries += 1
		send_peer_keys(peer, node, attrs)
	case "w:m":
		host_attrs := []Binary_Node_Attribute{{"hostname", "mmg.whatsapp.net"}, {"maxContentLengthBytes", "16777216"}}
		hosts := []Binary_Node{{tag = "host", attrs = host_attrs}}
		conn_attrs := []Binary_Node_Attribute{{"auth", "synthetic-token"}, {"ttl", "30"}}
		conn := []Binary_Node{{tag = "media_conn", attrs = conn_attrs, content = hosts}}
		send_peer_enqueue(peer, {tag = "iq", attrs = attrs, content = conn})
	case:
		peer.failed = true
	}
}

send_peer_device_index :: proc(jid: string) -> int {
	if slice.contains([]string{"222:2@s.whatsapp.net", "222:2@lid"}, jid) {
		return 1
	}

	return 0
}

send_peer_keys :: proc(peer: ^Send_Peer, node: Binary_Node, attrs: []Binary_Node_Attribute) {
	key := node_child(node, "key")

	if key == nil {
		peer.failed = true
		return
	}

	user := node_child(key^, "user")

	if user == nil {
		peer.failed = true
		return
	}

	jid, _ := node_attr(user^, "jid")
	bundle := send_peer_bundle(peer.local[send_peer_device_index(jid)])
	registration := [4]u8{u8(bundle.registration_id >> 24), u8(bundle.registration_id >> 16), u8(bundle.registration_id >> 8), u8(bundle.registration_id)}
	signed_id := [3]u8{0, 0, 7}
	prekey_id := [3]u8{0, 0, 9}
	signed := []Binary_Node {
		{tag = "id", content = signed_id[:]},
		{tag = "value", content = bundle.signed_prekey_public[:]},
		{tag = "signature", content = bundle.signed_prekey_signature[:]},
	}
	one_time := []Binary_Node{{tag = "id", content = prekey_id[:]}, {tag = "value", content = bundle.prekey_public[:]}}
	fields := []Binary_Node {
		{tag = "registration", content = registration[:]},
		{tag = "identity", content = bundle.identity_public[:]},
		{tag = "skey", content = signed},
		{tag = "key", content = one_time},
	}
	user_attrs := []Binary_Node_Attribute{{"jid", jid}}
	users := []Binary_Node{{tag = "user", attrs = user_attrs, content = fields}}
	list := []Binary_Node{{tag = "list", content = users}}
	send_peer_enqueue(peer, {tag = "iq", attrs = attrs, content = list})
}

send_peer_unpad :: proc(data: []u8) -> []u8 {
	if len(data) == 0 {
		return nil
	}

	n := int(data[len(data) - 1])

	if n < 1 || n > 16 || n > len(data) {
		return nil
	}

	for c in data[len(data) - n:] {
		if int(c) != n {
			return nil
		}
	}

	return data[:len(data) - n]
}

// Decrypts what the socket sent exactly as the group members would: each
// participant's pairwise envelope carries the sender-key distribution that
// then opens the group payload.
send_peer_message :: proc(peer: ^Send_Peer, node: Binary_Node, raw: []u8) {
	captured := make([]u8, len(raw))
	copy(captured, raw)
	append(&peer.raw, captured)
	id, _ := node_attr(node, "id")
	peer.last_id_size = copy(peer.last_id[:], transmute([]u8)id)
	// The outbound record must already be durable when the wire is written.
	loaded: State_Store
	defer state_store_clear(&loaded)

	if state_store_load(&loaded, peer.socket.config.state_path, peer.store.identity).kind != .None {
		peer.failed = true
		return
	}

	stored, found := state_store_get(&loaded, .Outbound_Message, id)
	_, group_found := state_store_get(&loaded, .Sender_Key, "123@g.us|111:1@s.whatsapp.net")
	_, content_found := state_store_get(&loaded, .Outbound_Content, id)
	peer.durable = found && group_found && content_found && bytes.equal(stored, raw) && loaded.revision == loaded.durable_revision

	if !peer.durable {
		peer.failed = true
		return
	}

	participants := node_child(node, "participants")

	if participants == nil {
		peer.failed = true
		return
	}

	recipients, _ := participants.content.([]Binary_Node)
	trusted := signal_curve_public(peer.auth.credentials.identity_private)

	for recipient in recipients {
		jid, _ := node_attr(recipient, "jid")
		index := send_peer_device_index(jid)
		child := node_child(recipient, "enc")

		if child == nil {
			peer.failed = true
			return
		}

		media_type, _ := node_attr(child^, "mediatype")
		peer.media_type_size = copy(peer.media_type[:], transmute([]u8)media_type)
		wire, _ := child.content.([]u8)
		kind, _ := node_attr(child^, "type")
		buffer: [2048]u8
		count: int

		if kind == "pkmsg" {
			n, _, decrypt_error := signal_session_decrypt_prekey(&peer.pairwise[index], buffer[:], wire, peer.local[index], trusted)

			if decrypt_error.kind != .None {
				peer.failed = true
				return
			}

			count = n
		} else {
			n, decrypt_error := signal_session_decrypt(&peer.pairwise[index], buffer[:], wire, trusted)

			if decrypt_error.kind != .None {
				peer.failed = true
				return
			}

			count = n
		}

		distribution, decode_error := text_message_decode(send_peer_unpad(buffer[:count]))

		if decode_error != .None || !distribution.has_sender_key_distribution || distribution.sender_key_distribution.group_id != "123@g.us" {
			peer.failed = true
			return
		}

		if signal_group_distribution_process(&peer.groups[index], distribution.sender_key_distribution.distribution) != .None {
			peer.failed = true
			return
		}

		group_enc := node_child(node, "enc")

		if group_enc == nil {
			peer.failed = true
			return
		}

		group_wire, _ := group_enc.content.([]u8)
		plaintext: [16384]u8
		n, group_error := signal_group_decrypt(plaintext[:], &peer.groups[index], group_wire)

		if group_error != .None {
			peer.failed = true
			return
		}

		clean := send_peer_unpad(plaintext[:n])

		if clean == nil {
			peer.failed = true
			return
		}

		peer.last_size = copy(peer.last_plain[:], clean)
	}
}

send_peer_write :: proc(data: rawptr, wire: []u8) -> (int, network_client.WebSocket_Stream_Error) {
	peer := cast(^Send_Peer)data
	header, at, frame_error := ws.frame_header_decode(wire, true)

	if header.opcode == .Close {
		return len(wire), {}
	}

	if frame_error != .None || header.opcode != .Binary || !header.fin || header.payload_length != u64(len(wire) - at) {
		peer.failed = true
		return 0, {kind = .TCP_Failed}
	}

	payload := make([]u8, len(wire) - at)
	defer delete(payload)
	copy(payload, wire[at:])
	ws.mask_payload(payload, header.masking_key)
	envelope := payload

	if len(payload) >= 4 && bytes.equal(payload[:4], []u8{'W', 'A', 6, 3}) {
		envelope = payload[4:]
	}

	if len(envelope) < 3 {
		peer.failed = true
		return 0, {kind = .TCP_Failed}
	}

	size := int(envelope[0]) << 16 | int(envelope[1]) << 8 | int(envelope[2])

	if size != len(envelope) - 3 {
		peer.failed = true
		return 0, {kind = .TCP_Failed}
	}

	plaintext := make([]u8, size)
	defer delete(plaintext)
	n, noise_error := noise_decrypt(&peer.noise, plaintext, envelope[3:])

	if noise_error != .None {
		peer.failed = true
		return 0, {kind = .TCP_Failed}
	}

	document, decode_error := binary_node_decode(plaintext[:n])

	if decode_error.kind != .None {
		peer.failed = true
		return 0, {kind = .TCP_Failed}
	}

	defer binary_document_destroy(&document)

	if document.root.tag == "iq" {
		send_peer_iq(peer, document.root)
	} else if document.root.tag == "message" {
		send_peer_message(peer, document.root, plaintext[:n])

		if peer.fail_message {
			return 0, {kind = .TCP_Failed}
		}
	}

	return len(wire), {}
}

// Stands in for the CDN: records the uploaded ciphertext and returns the
// upload descriptor. context.user_ptr carries the peer.
send_peer_http :: proc(
	request: http.Request,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	peer := cast(^Send_Peer)context.user_ptr

	if request.method != .POST || config.max_redirects != 0 {
		peer.failed = true
		return {}, {kind = .Invalid_Config}
	}

	peer.upload_requests += 1

	if peer.upload_status != 0 {
		return {status = peer.upload_status}, {}
	}

	clear(&peer.uploaded)
	append(&peer.uploaded, ..request.body)
	body := `{"url":"https://mmg.whatsapp.net/synthetic.enc","direct_path":"/synthetic.enc"}`

	return {status = 200, body = transmute([]u8)body}, {}
}

send_peer_new :: proc() -> ^Send_Peer {
	peer := new(Send_Peer)
	directory, directory_error := os.make_directory_temp("", "whatsapp-send-peer-*", context.allocator)
	assert(directory_error == nil)
	peer.directory = directory
	peer.path = fmt.aprintf("%s/state", directory)
	credentials, credentials_error := device_credentials_generate()
	assert(credentials_error == .None)
	peer.auth.credentials = credentials
	peer.auth.credentials.identity_private = send_peer_private(1)
	peer.auth.credentials.registration_id = 100
	me := "111:1@s.whatsapp.net"
	peer.auth.account.jid_size = copy(peer.auth.account.jid[:], transmute([]u8)me)
	peer.auth.account.valid = true
	peer.auth.account.details_size = 1
	peer.auth.account.details[0] = 1
	identity := signal_curve_public(peer.auth.credentials.identity_private)
	assert(state_store_init(&peer.store, identity).kind == .None)
	peer.local[0] = send_peer_local(64, 200)
	peer.local[1] = send_peer_local(144, 201)
	peer.socket = {
		phase = .Online,
		auth = &peer.auth,
		store = &peer.store,
		prekeys = &peer.prekeys,
		config = {state_path = peer.path, query_timeout = time.Second, http_execute = send_peer_http},
	}
	peer.socket.websocket = {
		phase = .Open,
		allocator = context.allocator,
		config = {host = "synthetic.invalid", max_message_size = 8192},
		stream = {
			data = peer,
			read = send_peer_read,
			write = send_peer_write,
			close = send_peer_close,
			abort = send_peer_close,
			set_read_deadline = send_peer_deadline,
			set_write_deadline = send_peer_deadline,
		},
	}
	// Readiness hook only: bytes are delivered by the in-memory stream.
	peer.socket.websocket.tls_client.application.inbound_size = 1
	assert(client_init(&peer.socket.client, &peer.socket.websocket, {static_private_key = peer.auth.credentials.noise_private}, {max_frame_payload = 8192}).kind == .None)
	noise_clear(&peer.socket.client.noise)
	peer.socket.client.noise = {
		phase     = .Transport,
		write_key = send_peer_noise_key(1),
		read_key  = send_peer_noise_key(33),
	}
	peer.socket.client.phase = .Noise_Ready
	peer.socket.client.frames.intro_sent = true
	peer.socket.session = {
		client = &peer.socket.client,
		auth = &peer.auth,
		phase = .Login_Accepted,
		config = {keepalive_interval = time.Minute},
		last_received = time.now(),
		next_ping = time.time_add(time.now(), time.Minute),
	}
	peer.noise = {
		phase     = .Transport,
		read_key  = send_peer_noise_key(1),
		write_key = send_peer_noise_key(33),
	}

	return peer
}

send_peer_destroy :: proc(peer: ^Send_Peer) {
	socket_close(&peer.socket)
	state_store_clear(&peer.store)
	device_credentials_clear(&peer.auth.credentials)

	for &session in peer.pairwise {
		signal_session_clear(&session)
	}

	for &group in peer.groups {
		signal_group_record_clear(&group)
	}

	for wire in peer.raw {
		delete(wire)
	}

	if peer.pipe != {} {
		posix.close(peer.pipe[0])
		posix.close(peer.pipe[1])
	}

	delete(peer.input)
	delete(peer.raw)
	delete(peer.uploaded)
	os.remove_all(peer.directory)
	delete(peer.path)
	delete(peer.directory)
	free(peer)
}

// Replaces the in-memory readiness hook with an idle local pipe so the
// WebSocket poll genuinely waits; queued server frames are announced by
// writing one byte to the pipe.
send_peer_use_pipe :: proc(peer: ^Send_Peer) {
	assert(posix.pipe(&peer.pipe) == .OK)
	peer.socket.websocket.tls_client.application.inbound_size = 0
	peer.socket.websocket.tls_client.tcp.socket = cast(net.TCP_Socket)peer.pipe[0]
}

send_peer_announce :: proc(peer: ^Send_Peer) {
	peer.pipe_pending = true
	byte := [1]u8{1}
	posix.write(peer.pipe[1], raw_data(byte[:]), 1)
}

package whatsapp_test

import wire_frames "../../fixtures/message_transport"
import "core:bytes"
import "core:fmt"
import "core:os"
import "core:slice"
import "core:sys/posix"
import "core:time"
import "shared:surf"
import ws "shared:async/websocket"
import wa "shared:whatsapp"

// Synthetic WhatsApp peer for the send paths. Real WebSocket framing, Noise
// transport, IQ routing, X3DH, pairwise Signal and sender-key records run
// against in-memory keys; no account, network or provider is involved. The
// peer owns group 123@g.us with two members: us (111:1) and 222 (devices 1, 2).
Send_Peer :: struct {
	lookup_reply: proc(peer: ^Send_Peer, id: string),
	history_reply: proc(peer: ^Send_Peer, id: string),
	contact_replies: []wa.Binary_Node,
	contact_versions: []string,
	contact_requests: int,
	socket:                                        wa.Socket,
	auth:                                          wa.Auth_State,
	store:                                         wa.State_Store,
	prekeys:                                       wa.Prekey_Store,
	noise:                                         wa.Noise_State,
	local:                                         [2]wa.Signal_Recipient_Keys,
	pairwise:                                      [2]wa.Signal_Session,
	groups:                                        [2]wa.Signal_Group_Record,
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
	terminal_read_error:                           surf.WebSocket_Error_Kind,
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

send_peer_local :: proc(start: int, registration: u32) -> wa.Signal_Recipient_Keys {
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

send_peer_bundle :: proc(local: wa.Signal_Recipient_Keys) -> wa.Signal_Prekey_Bundle {
	bundle := wa.Signal_Prekey_Bundle {
		registration_id = local.registration_id,
		identity_public = wa.signal_curve_public(local.identity_private),
		signed_prekey_id = local.signed_prekey_id,
		signed_prekey_public = wa.signal_curve_public(local.signed_prekey_private),
		has_prekey = local.has_prekey,
		prekey_id = local.prekey_id,
		prekey_public = wa.signal_curve_public(local.prekey_private),
	}

	signed: [33]u8
	signed[0] = 5
	copy(signed[1:], bundle.signed_prekey_public[:])
	error: wa.Signal_Error
	bundle.signed_prekey_signature, error = wa.signal_curve_sign(local.identity_private, signed[:])
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

send_peer_read :: proc(data: rawptr, dst: []u8) -> (int, surf.WebSocket_Error) {
	peer := cast(^Send_Peer)data

	if peer.pipe_pending {
		// Consume the readiness byte that announced the queued input.
		peer.pipe_pending = false
		byte: [1]u8
		posix.read(peer.pipe[0], raw_data(byte[:]), 1)
	}

	n := min(len(dst), len(peer.input) - peer.read_at)

	if n == 0 {
		return 0, {kind = .Peer_Closed if peer.terminal_read_error == .None else peer.terminal_read_error}
	}

	copy(dst, peer.input[peer.read_at:][:n])
	peer.read_at += n

	return n, {}
}

send_peer_close :: proc(data: rawptr, _: u16) -> surf.WebSocket_Error {
	return {}
}

send_peer_enqueue :: proc(peer: ^Send_Peer, node: wa.Binary_Node) {
	wire: [8192]u8
	n, encode_error := wa.binary_node_encode(wire[:], node)

	if encode_error.kind != .None {
		peer.failed = true
		return
	}

	ciphertext: [8208]u8
	size, noise_error := wa.noise_encrypt(&peer.noise, ciphertext[:], wire[:n])

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

send_peer_device_node :: proc(id, key_index: string) -> wa.Binary_Node {
	attrs := new([2]wa.Binary_Node_Attribute, context.temp_allocator)
	attrs^ = {{"id", id}, {"key-index", key_index}}

	return {tag = "device", attrs = attrs[:]}
}

send_peer_user_node :: proc(jid: string, devices: []wa.Binary_Node) -> wa.Binary_Node {
	attrs := new([1]wa.Binary_Node_Attribute, context.temp_allocator)
	attrs^ = {{"jid", jid}}

	list := new([1]wa.Binary_Node, context.temp_allocator)
	list^ = {{tag = "device-list", content = devices}}

	holder := new([1]wa.Binary_Node, context.temp_allocator)
	holder^ = {{tag = "devices", content = list[:]}}

	return {tag = "user", attrs = attrs[:], content = holder[:]}
}

send_peer_participant_node :: proc(jid: string) -> wa.Binary_Node {
	attrs := new([1]wa.Binary_Node_Attribute, context.temp_allocator)
	attrs^ = {{"jid", jid}}

	return {tag = "participant", attrs = attrs[:]}
}

send_peer_iq :: proc(peer: ^Send_Peer, node: wa.Binary_Node) {
	id, _ := wa.node_attr(node, "id")
	xmlns, _ := wa.node_attr(node, "xmlns")
	attrs := []wa.Binary_Node_Attribute{{"type", "result"}, {"id", id}, {"from", "s.whatsapp.net"}}

	switch xmlns {
	case "w:sync:app:state":
		attrs[2] = {"from", "@s.whatsapp.net"}

		if to, _ := wa.node_attr(node, "to"); to != "@s.whatsapp.net" { peer.failed = true; return }

		sync, _ := wa.device_unique_child(node, "sync")
		collection, _ := wa.device_unique_child(sync, "collection")
		snapshot, _ := wa.node_attr(collection, "return_snapshot")
		version, _ := wa.node_attr(collection, "version")
		name, _ := wa.node_attr(collection, "name")
		if peer.contact_requests >= len(peer.contact_replies) || name != "critical_unblock_low" ||
		   version != peer.contact_versions[peer.contact_requests] || (snapshot == "true") != (version == "") {
			peer.failed = true
			return
		}

		reply := peer.contact_replies[peer.contact_requests]
		peer.contact_requests += 1
		send_peer_enqueue(peer, {tag = "iq", attrs = attrs, content = []wa.Binary_Node{{tag = "sync", content = []wa.Binary_Node{reply}}}})


	case "w:g2":
		peer.metadata_queries += 1
		attrs[2] = {"from", "123@g.us"}

		group_attrs := []wa.Binary_Node_Attribute{{"id", "123"}, {"subject", "Synthetic"}, {"addressing_mode", "pn"}}

		participants := []wa.Binary_Node{send_peer_participant_node("111@s.whatsapp.net"), send_peer_participant_node("222@s.whatsapp.net")}

		group := []wa.Binary_Node{{tag = "group", attrs = group_attrs, content = participants}}

		send_peer_enqueue(peer, {tag = "iq", attrs = attrs, content = group})


	case "usync":
		peer.device_queries += 1
		own := []wa.Binary_Node{send_peer_device_node("1", "1")}

		other := []wa.Binary_Node{send_peer_device_node("1", "1"), send_peer_device_node("2", "2")}

		users := []wa.Binary_Node{send_peer_user_node("111@s.whatsapp.net", own), send_peer_user_node("222@s.whatsapp.net", other)}

		list := []wa.Binary_Node{{tag = "list", content = users}}

		usync := []wa.Binary_Node{{tag = "usync", content = list}}

		send_peer_enqueue(peer, {tag = "iq", attrs = attrs, content = usync})


	case "encrypt":
		peer.key_queries += 1
		send_peer_keys(peer, node, attrs)
	case "w:m":
		host_attrs := []wa.Binary_Node_Attribute{{"hostname", "mmg.whatsapp.net"}, {"maxContentLengthBytes", "16777216"}}

		hosts := []wa.Binary_Node{{tag = "host", attrs = host_attrs}}

		conn_attrs := []wa.Binary_Node_Attribute{{"auth", "synthetic-token"}, {"ttl", "30"}}

		conn := []wa.Binary_Node{{tag = "media_conn", attrs = conn_attrs, content = hosts}}

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

send_peer_keys :: proc(peer: ^Send_Peer, node: wa.Binary_Node, attrs: []wa.Binary_Node_Attribute) {
	key := wa.node_child(node, "key")

	if key == nil {
		peer.failed = true
		return
	}

	user := wa.node_child(key^, "user")

	if user == nil {
		peer.failed = true
		return
	}

	jid, _ := wa.node_attr(user^, "jid")
	bundle := send_peer_bundle(peer.local[send_peer_device_index(jid)])
	registration := [4]u8{u8(bundle.registration_id >> 24), u8(bundle.registration_id >> 16), u8(bundle.registration_id >> 8), u8(bundle.registration_id)}

	signed_id := [3]u8{0, 0, 7}

	prekey_id := [3]u8{0, 0, 9}

	signed := []wa.Binary_Node {
		{tag = "id", content = signed_id[:]},
		{tag = "value", content = bundle.signed_prekey_public[:]},
		{tag = "signature", content = bundle.signed_prekey_signature[:]},
	}

	one_time := []wa.Binary_Node{{tag = "id", content = prekey_id[:]}, {tag = "value", content = bundle.prekey_public[:]}}

	fields := []wa.Binary_Node {
		{tag = "registration", content = registration[:]},
		{tag = "identity", content = bundle.identity_public[:]},
		{tag = "skey", content = signed},
		{tag = "key", content = one_time},
	}

	user_attrs := []wa.Binary_Node_Attribute{{"jid", jid}}

	users := []wa.Binary_Node{{tag = "user", attrs = user_attrs, content = fields}}

	list := []wa.Binary_Node{{tag = "list", content = users}}

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
send_peer_message :: proc(peer: ^Send_Peer, node: wa.Binary_Node, raw: []u8) {
	captured := make([]u8, len(raw))
	copy(captured, raw)
	append(&peer.raw, captured)
	id, _ := wa.node_attr(node, "id")
	peer.last_id_size = copy(peer.last_id[:], transmute([]u8)id)
	// The outbound record must already be durable when the wire is written.
	loaded: wa.State_Store
	defer wa.state_store_clear(&loaded)

	if wa.state_store_load(&loaded, peer.socket.config.state_path, peer.store.identity).kind != .None {
		peer.failed = true
		return
	}

	stored, found := wa.state_store_get(&loaded, .Outbound_Message, id)
	if category, _ := wa.node_attr(node, "category"); category == "peer" {
		to, _ := wa.node_attr(node, "to")
		priority, _ := wa.node_attr(node, "push_priority")
		enc, e := wa.device_unique_child(node, "enc")
		cipher, ok := enc.content.([]u8)
		peer.durable = found && bytes.equal(stored, raw)
		expected_priority := "high_force" if peer.lookup_reply != nil || peer.history_reply != nil else "high"
		_, sensitive := wa.node_attr(node, "privacy_sensitive")
		if !ok || e.kind != .None || !peer.durable || to != "111@s.whatsapp.net" ||
		   priority != expected_priority || sensitive != (peer.history_reply != nil) {
			peer.failed = true
			return
		}

		plaintext: [512]u8
		n, _, err := wa.signal_session_decrypt_prekey(&peer.pairwise[0], plaintext[:], cipher, peer.local[0], peer.store.identity)
		if err.kind != .None { peer.failed = true; return }

		peer.last_size = copy(peer.last_plain[:], send_peer_unpad(plaintext[:n]))
		if peer.history_reply != nil {peer.history_reply(peer, id)}

		if peer.lookup_reply != nil {peer.lookup_reply(peer, id)}

		return
	}

	_, group_found := wa.state_store_get(&loaded, .Sender_Key, "123@g.us|111:1@s.whatsapp.net")
	_, content_found := wa.state_store_get(&loaded, .Outbound_Content, id)
	peer.durable = found && group_found && content_found && bytes.equal(stored, raw) && loaded.revision == loaded.durable_revision

	if !peer.durable {
		peer.failed = true
		return
	}

	participants := wa.node_child(node, "participants")

	if participants == nil {
		peer.failed = true
		return
	}

	recipients, _ := participants.content.([]wa.Binary_Node)
	trusted := wa.signal_curve_public(peer.auth.credentials.identity_private)

	for recipient in recipients {
		jid, _ := wa.node_attr(recipient, "jid")
		index := send_peer_device_index(jid)
		child := wa.node_child(recipient, "enc")

		if child == nil {
			peer.failed = true
			return
		}

		media_type, _ := wa.node_attr(child^, "mediatype")
		peer.media_type_size = copy(peer.media_type[:], transmute([]u8)media_type)
		wire, _ := child.content.([]u8)
		kind, _ := wa.node_attr(child^, "type")
		buffer: [2048]u8
		count: int

		if kind == "pkmsg" {
			n, _, decrypt_error := wa.signal_session_decrypt_prekey(&peer.pairwise[index], buffer[:], wire, peer.local[index], trusted)

			if decrypt_error.kind != .None {
				peer.failed = true
				return
			}

			count = n
		} else {
			n, decrypt_error := wa.signal_session_decrypt(&peer.pairwise[index], buffer[:], wire, trusted)

			if decrypt_error.kind != .None {
				peer.failed = true
				return
			}

			count = n
		}

		distribution, decode_error := wa.text_message_decode(send_peer_unpad(buffer[:count]))

		if decode_error != .None || !distribution.has_sender_key_distribution || distribution.sender_key_distribution.group_id != "123@g.us" {
			peer.failed = true
			return
		}

		if wa.signal_group_distribution_process(&peer.groups[index], distribution.sender_key_distribution.distribution) != .None {
			peer.failed = true
			return
		}

		group_enc := wa.node_child(node, "enc")

		if group_enc == nil {
			peer.failed = true
			return
		}

		group_wire, _ := group_enc.content.([]u8)
		plaintext: [16384]u8
		n, group_error := wa.signal_group_decrypt(plaintext[:], &peer.groups[index], group_wire)

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

send_peer_write :: proc(data: rawptr, wire: []u8) -> (int, surf.WebSocket_Error) {
	peer := cast(^Send_Peer)data
	header, at, frame_error := ws.frame_header_decode(wire, true)

	if header.opcode == .Close {
		return len(wire), {}
	}

	if frame_error != .None || header.opcode != .Binary || !header.fin || header.payload_length != u64(len(wire) - at) {
		peer.failed = true
		return 0, {kind = .IO_Failed}
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
		return 0, {kind = .IO_Failed}
	}

	size := int(envelope[0]) << 16 | int(envelope[1]) << 8 | int(envelope[2])

	if size != len(envelope) - 3 {
		peer.failed = true
		return 0, {kind = .IO_Failed}
	}

	plaintext := make([]u8, size)
	defer delete(plaintext)

	n, noise_error := wa.noise_decrypt(&peer.noise, plaintext, envelope[3:])

	if noise_error != .None {
		peer.failed = true
		return 0, {kind = .IO_Failed}
	}

	document, decode_error := wa.binary_node_decode(plaintext[:n])

	if decode_error.kind != .None {
		peer.failed = true
		return 0, {kind = .IO_Failed}
	}
	defer wa.binary_document_destroy(&document)

	if document.root.tag == "iq" {
		send_peer_iq(peer, document.root)
	} else if document.root.tag == "message" {
		send_peer_message(peer, document.root, plaintext[:n])

		if peer.fail_message {
			return 0, {kind = .IO_Failed}
		}
	}

	return len(wire), {}
}

// Stands in for the CDN: records the uploaded ciphertext and returns the
// upload descriptor. context.user_ptr carries the peer.
send_peer_http :: proc(
	request: surf.Request,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
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
	credentials, credentials_error := wa.device_credentials_generate()
	assert(credentials_error == .None)
	peer.auth.credentials = credentials
	peer.auth.credentials.identity_private = send_peer_private(1)
	peer.auth.credentials.registration_id = 100
	me := "111:1@s.whatsapp.net"
	peer.auth.account.jid_size = copy(peer.auth.account.jid[:], transmute([]u8)me)
	peer.auth.account.valid = true
	peer.auth.account.details_size = 1
	peer.auth.account.details[0] = 1
	identity := wa.signal_curve_public(peer.auth.credentials.identity_private)
	assert(wa.state_store_init(&peer.store, identity).kind == .None)
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
		max_message_size = 8192,
		data = peer,
		read = wire_frames.reader(send_peer_read),
		write = wire_frames.writer(send_peer_write),
		close = send_peer_close,
	}

	assert(wa.client_init(&peer.socket.client, &peer.socket.websocket, {static_private_key = peer.auth.credentials.noise_private}, {max_frame_payload = 8192}).kind == .None)
	wa.noise_clear(&peer.socket.client.noise)
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
	wa.socket_close(&peer.socket)
	wa.state_store_clear(&peer.store)
	wa.device_credentials_clear(&peer.auth.credentials)

	for &session in peer.pairwise {
		wa.signal_session_clear(&session)
	}

	for &group in peer.groups {
		wa.signal_group_record_clear(&group)
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
	peer.socket.websocket.poll = send_peer_pipe_poll
}

send_peer_announce :: proc(peer: ^Send_Peer) {
	peer.pipe_pending = true
	byte := [1]u8{1}

	posix.write(peer.pipe[1], raw_data(byte[:]), 1)
}

send_peer_pipe_poll :: proc(data: rawptr, timeout: time.Duration, wakeup: ^os.File) -> (bool, surf.WebSocket_Error) {
	peer := cast(^Send_Peer)data
	return wa.message_poll_fd(peer.pipe[0], timeout, wakeup)
}

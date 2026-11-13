package main

import wa "../.."
import surf "../../../surf"
import ws "../../../websocket"
import "core:bytes"
import "core:fmt"
import "core:os"
import "core:net"

SOCKET_ID :: "encrypted-socket-recovery-1"
SOCKET_GROUP :: "123@g.us"
SOCKET_A :: "111:1@s.whatsapp.net"
SOCKET_B :: "222:1@s.whatsapp.net"
SOCKET_TEXT :: "synthetic Socket encrypted recovery"
SOCKET_ACK_JOURNAL :: "socket-application-ack"

// The production prepared-send path receives synthetic already-discovered
// metadata. All encryption, session/sender-key staging, commit, transport output
// and positive-ACK processing below are the actual public Socket implementation.
Socket_Recovery :: struct {
	socket:                            wa.Socket,
	auth:                              wa.Auth_State,
	f:                                 ^Fixture,
	directory, stage, prekey_path:     string,
	input, output:                     [8192]u8,
	input_size, input_at, output_size: int,
	replay:                            bool,
	tcp: net.TCP_Connection,
	native_stream: surf.WebSocket_Stream,
	tcp_enabled: bool,
}

socket_body :: proc() -> []u8 {
	buffer: [256]u8
	size, error := wa.text_message_encode(buffer[:], {kind = .Conversation, text = SOCKET_TEXT})
	assert(error == .None)
	body := make([]u8, size); copy(body, buffer[:size]); return body
}

socket_recovery_close :: proc(peer: ^Socket_Recovery) {
	wa.socket_close(&peer.socket); wa.device_credentials_clear(&peer.auth.credentials)
	delete(peer.prekey_path); free(peer)
}

socket_recovery_read :: proc(data: rawptr, dst: []u8) -> (int, surf.WebSocket_Stream_Error) {
	peer := cast(^Socket_Recovery)data
	if peer.tcp_enabled {
		count, error := peer.native_stream.read(peer.native_stream.data, dst)
		peer.input_at += count
		return count, error
	}
	count := min(len(dst), peer.input_size - peer.input_at, 3)
	if count == 0 {
		return 0, {kind = .EOF}
	}
	copy(dst[:count], peer.input[peer.input_at:][:count]); peer.input_at += count
	return count, {}
}

socket_recovery_stream_close :: proc(_: rawptr) -> surf.WebSocket_Stream_Error {return {}}

socket_owned_write :: proc(directory, name: string, data: []u8) {
	path := fmt.aprintf("%s/%s", directory, name); defer delete(path)
	file, opened := os.open(path, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
	assert(opened == nil)
	count, written := os.write(file, data)
	assert(written == nil && count == len(data))
	assert(os.flush(file) == nil && os.close(file) == nil)
	parent, parent_error := os.open(directory); assert(parent_error == nil)
	assert(os.flush(parent) == nil && os.close(parent) == nil)
}

// Bind the handoff to the exact committed ratchet, sender key, membership,
// immutable content and separate prekey file. ACK may remove only pending wire.
socket_state_witness :: proc(peer: ^Socket_Recovery) -> [160]u8 {
	address, addressed := wa.socket_signal_address(&peer.socket, SOCKET_B)
	assert(addressed.kind == .None)
	defer delete(address)
	canonical, canonical_error := wa.socket_signal_address(&peer.socket, SOCKET_A)
	assert(canonical_error.kind == .None)
	defer delete(canonical)
	key_name := fmt.aprintf("%s|%s", SOCKET_GROUP, canonical); defer delete(key_name)
	session, have_session := wa.state_store_get(&peer.f.store, .Session, address)
	group, have_group := wa.state_store_get(&peer.f.store, .Sender_Key, key_name)
	members, have_members := wa.state_store_get(&peer.f.store, .Sender_Key_Membership, key_name)
	content, have_content := wa.state_store_get(&peer.f.store, .Outbound_Content, SOCKET_ID)
	assert(have_session && have_group && have_members && have_content)
	assert(string(members) == SOCKET_B)
	prekeys, io_error := os.read_entire_file(peer.prekey_path, context.allocator)
	assert(io_error == nil)
	defer delete(prekeys)
	result: [160]u8
	for value, index in ([]([]u8){session, group, members, content, prekeys}) {
		digest := wa.state_hash(value); copy(result[index * 32:][:32], digest[:])
	}
	return result
}

socket_recovery_write :: proc(data: rawptr, src: []u8) -> (int, surf.WebSocket_Stream_Error) {
	peer := cast(^Socket_Recovery)data
	if !peer.replay && peer.output_size == 0 && peer.stage == "socket-after-commit-before-write" {
		boundary(peer.stage)
	}
	count := len(src)
	if peer.tcp_enabled {
		written, error := peer.native_stream.write(peer.native_stream.data, src)
		if error.kind != .None {return written, error}
		count = written
	}
	assert(peer.output_size + count <= len(peer.output))
	peer.output_size += copy(peer.output[peer.output_size:], src[:count])
	header, offset, error := ws.frame_header_decode(peer.output[:peer.output_size], true)
	if error == .None && offset + int(header.payload_length) == peer.output_size {
		// This durable fixture file is the owned transport peer's handoff witness,
		// not a server delivery claim. It cannot change the sender's StateStore.
		if !peer.tcp_enabled {
			name := "replay.bin" if peer.replay else "transport.bin"
			socket_owned_write(peer.directory, name, peer.output[:peer.output_size])
			if !peer.replay {
				witness := socket_state_witness(peer)
				socket_owned_write(peer.directory, "transport-state.bin", witness[:])
			}
		}
		if !peer.replay && peer.stage == "socket-after-wire-before-return" {
			boundary(peer.stage)
		}
	}
	return count, {}
}

socket_recovery_attach :: proc(
	f: ^Fixture,
	directory, stage: string,
	replay := false,
) -> ^Socket_Recovery {
	peer := new(Socket_Recovery)
	peer.f, peer.directory, peer.stage, peer.replay = f, directory, stage, replay
	peer.prekey_path = fmt.aprintf("%s/prekeys.bin", directory)
	local := fixture_local(96, 200); bundle := fixture_bundle(local)
	peer.auth.credentials = {
		noise_private              = fixture_private(10),
		pairing_ephemeral_private  = fixture_private(20),
		identity_private           = local.identity_private,
		signed_prekey_private      = local.signed_prekey_private,
		signed_prekey_public       = bundle.signed_prekey_public,
		signed_prekey_signature    = bundle.signed_prekey_signature,
		signed_prekey_id           = local.signed_prekey_id,
		registration_id            = local.registration_id,
		next_prekey_id             = 10,
		first_unuploaded_prekey_id = 10,
	}
	peer.auth.credentials.adv_secret[0] = 1
	assert(wa.device_credentials_validate(&peer.auth.credentials) == .None)
	peer.auth.account.jid_size = copy(peer.auth.account.jid[:], SOCKET_A)
	peer.socket = {
		phase = .Online,
		auth = &peer.auth,
		prekeys = &f.prekeys,
		store = &f.store,
		config = {state_path = f.path, prekey_path = peer.prekey_path},
	}
	peer.socket.websocket = {
		phase = .Open,
		allocator = context.allocator,
		config = {host = "synthetic.invalid", max_message_size = 8192},
		stream = {
			data = peer,
			read = socket_recovery_read,
			write = socket_recovery_write,
			close = socket_recovery_stream_close,
		},
	}
	if socket_tcp_port != 0 {socket_tcp_connect(peer)}
	peer.socket.client = {
		phase = .Noise_Ready,
		websocket = &peer.socket.websocket,
		config = {max_frame_payload = 8192},
		noise = {phase = .Transport},
	}
	assert(
		wa.frame_transport_init(&peer.socket.client.frames, &peer.socket.websocket, 8192).kind ==
		.None,
	)
	peer.socket.client.frames.intro_sent = true
	peer.socket.session = {
		phase  = .Login_Accepted,
		client = &peer.socket.client,
		auth   = &peer.auth,
	}
	return peer
}

socket_recovery_prepare :: proc(f: ^Fixture, peer: ^Socket_Recovery) {
	fixture_established(f)
	// Drop the older standalone fixture's record conventions. This fixture uses
	// production numeric consumed-key markers and canonical session addresses.
	assert(wa.state_store_delete(&f.store, .Consumed_Prekey, "device-b/9").kind == .None)
	assert(wa.state_store_delete(&f.store, .Outbound_Message, INITIAL_ID).kind == .None)
	assert(wa.state_store_delete(&f.store, .Inbox_Message, INITIAL_ID).kind == .None)
	assert(wa.state_store_delete(&f.store, .Outbound_Content, INTENT_ID).kind == .None)
	for name in ([]string{"device-a", "device-b"}) {
		assert(wa.state_store_delete(&f.store, .Session, name).kind == .None)
		assert(wa.state_store_delete(&f.store, .Identity, name).kind == .None)
	}
	assert(wa.state_store_set(&f.store, .Consumed_Prekey, "9", []u8{1}).kind == .None)
	assert(wa.prekey_store_save(peer.prekey_path, &f.prekeys).kind == .None)
	prekeys_set(f)
	receiver := session_bytes(&f.pair.a); defer delete(receiver)
	assert(
		wa.state_store_set(&f.store, .Captured_Message, "socket-peer-session", receiver).kind ==
		.None,
	)
	address, addressed := wa.socket_signal_address(&peer.socket, SOCKET_B)
	assert(addressed.kind == .None)
	defer delete(address)
	session_set(&f.store, address, &f.pair.b)
	identity := wa.signal_curve_public(fixture_private(0))
	assert(wa.state_store_set(&f.store, .Identity, address, identity[:]).kind == .None)
	body := socket_body(); defer delete(body)
	// Stable caller intent exists before any production encryption or output.
	assert(wa.state_store_set(&f.store, .Captured_Message, SOCKET_ID, body).kind == .None)
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
}

socket_recovery_send :: proc(peer: ^Socket_Recovery) {
	body := socket_body(); defer delete(body)
	canonical, addressed := wa.socket_signal_address(&peer.socket, SOCKET_A)
	assert(addressed.kind == .None)
	defer delete(canonical)
	id, error := wa.socket_group_send_prepared(
		&peer.socket,
		SOCKET_GROUP,
		"pn",
		"",
		SOCKET_ID,
		"",
		canonical,
		body,
		[]string{SOCKET_B},
	)
	defer delete(id)
	assert(error.kind == .None && id == SOCKET_ID && peer.socket.sequence == 0)
	assert(peer.socket.client.noise.write_counter == 1 && peer.output_size > 0)
}

socket_recovery_ack_frame :: proc(destination: []u8) -> int {
	encoded, ciphertext, envelope: [2048]u8
	size, binary_error := wa.binary_node_encode(
		encoded[:],
		{tag = "ack", attrs = {{"class", "message"}, {"id", SOCKET_ID}}},
	)
	assert(binary_error.kind == .None)
	server := wa.Noise_State {
		phase = .Transport,
	}; defer wa.noise_clear(&server)
	encrypted_size, encrypted := wa.noise_encrypt(&server, ciphertext[:], encoded[:size])
	assert(encrypted == .None)
	envelope_size, framed := wa.frame_encode(envelope[:], ciphertext[:encrypted_size])
	assert(framed == .None)
	frame_size, websocket_error := ws.frame_encode(
		destination,
		true,
		.Binary,
		envelope[:envelope_size],
		{},
		masked = false,
	)
	assert(websocket_error == .None); return frame_size
}

socket_recovery_ack :: proc(peer: ^Socket_Recovery) {
	if !peer.tcp_enabled {peer.input_size = socket_recovery_ack_frame(peer.input[:])}
	event, error := wa.socket_read(&peer.socket)
	assert(error.kind == .None && event.kind == .None && peer.socket.phase == .Online)
	assert(peer.socket.client.noise.read_counter == 1)
	if peer.tcp_enabled {assert(peer.input_at > 0)}
	else {assert(peer.input_at == peer.input_size)}
	_, pending := wa.state_store_get(&peer.f.store, .Outbound_Message, SOCKET_ID); assert(!pending)
}

socket_stage_run :: proc(directory, stage: string) {
	f := fixture_open(directory, true); defer fixture_close(f)
	peer := socket_recovery_attach(f, directory, stage); defer socket_recovery_close(peer)
	socket_recovery_prepare(f, peer)
	if stage == "socket-before-send" {
		boundary(stage)
	}
	socket_recovery_send(peer)
	if stage == "socket-after-send-before-ack" {
		boundary(stage)
	}
	socket_recovery_ack(peer)
	if stage == "socket-after-positive-ack" {
		boundary(stage)
	}
	assert(
		wa.state_store_set(&f.store, .Captured_Message, SOCKET_ACK_JOURNAL, transmute([]u8)string(SOCKET_ID)).kind ==
		.None,
	)
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
	if stage == "socket-after-ack-journal" {
		boundary(stage)
	}
	assert(stage == "control")
}

socket_transport_inner :: proc(packet: []u8) -> []u8 {
	header, offset, decoded := ws.frame_header_decode(packet, true)
	assert(decoded == .None && offset + int(header.payload_length) == len(packet))
	payload := packet[offset:]; ws.mask_payload(payload, header.masking_key)
	encrypted, consumed, framed := wa.frame_decode(payload)
	assert(framed == .None && consumed == len(payload))
	transport := wa.Noise_State {
		phase = .Transport,
	}; defer wa.noise_clear(&transport)
	plain: [8192]u8
	count, decrypted := wa.noise_decrypt(&transport, plain[:], encrypted)
	assert(decrypted == .None)
	result := make([]u8, count); copy(result, plain[:count]); return result
}

// The owned synthetic peer decrypts both the pairwise distribution and group payload using
// the actual receiver session. No constant ciphertext or synthetic ratchet strings.
socket_peer_decrypt :: proc(f: ^Fixture, inner: []u8) {
	document, decoded := wa.binary_node_decode(inner); assert(decoded.kind == .None)
	defer wa.binary_document_destroy(&document)
	id, id_found := wa.pairing_node_attr(document.root, "id")
	destination, destination_found := wa.pairing_node_attr(document.root, "to")
	assert(
		document.root.tag == "message" &&
		id_found &&
		id == SOCKET_ID &&
		destination_found &&
		destination == SOCKET_GROUP,
	)
	participants, have_participants := wa.pairing_node_child(document.root, "participants")
	assert(have_participants)
	devices, valid_devices := participants.content.([]wa.Binary_Node)
	assert(valid_devices && len(devices) == 1)
	device, have_device := wa.pairing_node_attr(devices[0], "jid")
	assert(have_device && device == SOCKET_B)
	enc, have_enc := wa.pairing_node_child(devices[0], "enc"); assert(have_enc)
	kind, have_kind := wa.pairing_node_attr(enc^, "type"); assert(have_kind && kind == "msg")
	distribution_wire, valid_distribution := enc.content.([]u8); assert(valid_distribution)
	plaintext: [2048]u8
	count, error := wa.signal_session_decrypt(
		&f.pair.a,
		plaintext[:],
		distribution_wire,
		wa.signal_curve_public(fixture_private(96)),
	)
	assert(error.kind == .None)
	unpadded, unpadding := wa.socket_message_unpad(plaintext[:count])
	assert(unpadding.kind == .None)
	message, parsed := wa.text_message_decode(unpadded)
	assert(
		parsed == .None &&
		message.has_sender_key_distribution &&
		message.sender_key_distribution.group_id == SOCKET_GROUP,
	)
	record := new(wa.Signal_Group_Record)
	defer {wa.signal_group_record_clear(record); free(record)}
	assert(
		wa.signal_group_distribution_process(
			record,
			message.sender_key_distribution.distribution,
		) ==
		.None,
	)
	group_enc, have_group := wa.pairing_node_child(document.root, "enc"); assert(have_group)
	group_wire, valid_group := group_enc.content.([]u8); assert(valid_group)
	group_plaintext: [2048]u8
	group_count, group_error := wa.signal_group_decrypt(group_plaintext[:], record, group_wire)
	assert(group_error == .None && record.states[0].next_iteration == 1)
	body, unpad_error := wa.socket_message_unpad(group_plaintext[:group_count])
	assert(unpad_error.kind == .None)
	text, text_error := wa.text_message_decode(body)
	assert(text_error == .None && text.text == SOCKET_TEXT)
	_, replay := wa.signal_group_decrypt(group_plaintext[:], record, group_wire)
	assert(replay == .Replay && record.states[0].next_iteration == 1)
}

socket_verify_run :: proc(directory, stage: string) {
	f := fixture_open(directory, false); defer fixture_close(f)
	before, io_error := os.read_entire_file(f.path, context.allocator); assert(io_error == nil)
	defer delete(before)
	peer := socket_recovery_attach(f, directory, stage, true); defer socket_recovery_close(peer)
	address, addressed := wa.socket_signal_address(&peer.socket, SOCKET_B)
	assert(addressed.kind == .None)
	defer delete(address)
	// Load the production sender session and the separate synthetic peer snapshot.
	session_get(&f.store, address, &f.pair.b)
	receiver, receiver_found := wa.state_store_get(
		&f.store,
		.Captured_Message,
		"socket-peer-session",
	)
	assert(receiver_found && wa.signal_session_decode(&f.pair.a, receiver).kind == .None)
	assert(
		wa.prekey_store_load(peer.prekey_path, &f.prekeys, &peer.auth.credentials).kind == .None,
	)
	marker, marker_found := wa.state_store_get(&f.store, .Consumed_Prekey, "9")
	assert(
		marker_found && bytes.equal(marker, []u8{1}) && wa.prekey_store_get(&f.prekeys, 9) == nil,
	)
	prekey_before, prekey_io := os.read_entire_file(peer.prekey_path, context.allocator)
	assert(prekey_io == nil)
	defer delete(prekey_before)
	encoded_prekeys, prekeys_found := wa.state_store_get(&f.store, .Captured_Message, "prekeys-b")
	assert(prekeys_found && bytes.equal(prekey_before, encoded_prekeys))
	pending, pending_found := wa.state_store_get(&f.store, .Outbound_Message, SOCKET_ID)
	_, retained := wa.state_store_get(&f.store, .Outbound_Content, SOCKET_ID)
	intent, intent_found := wa.state_store_get(&f.store, .Captured_Message, SOCKET_ID)
	body := socket_body(); defer delete(body)
	assert(intent_found && bytes.equal(intent, body))
	_, journal := wa.state_store_get(&f.store, .Captured_Message, SOCKET_ACK_JOURNAL)
	before_send := stage == "socket-before-send"
	acked :=
		stage == "socket-after-positive-ack" ||
		stage == "socket-after-ack-journal" ||
		stage == "control"
	assert(pending_found == (!before_send && !acked) && retained == !before_send)
	assert(journal == (stage == "socket-after-ack-journal" || stage == "control"))
	assert(f.pair.b.send_counter == (0 if before_send else 1))
	canonical, canonical_error := wa.socket_signal_address(&peer.socket, SOCKET_A)
	assert(canonical_error.kind == .None)
	defer delete(canonical)
	key_name := fmt.aprintf("%s|%s", SOCKET_GROUP, canonical); defer delete(key_name)
	snapshot, group_found := wa.state_store_get(&f.store, .Sender_Key, key_name)
	assert(group_found != before_send)
	if group_found {
		record := new(wa.Signal_Group_Record)
		defer {wa.signal_group_record_clear(record); free(record)}
		assert(
			wa.signal_group_record_decode(record, snapshot) == .None &&
			record.count == 1 &&
			record.states[0].next_iteration == 1,
		)
	}
	path := fmt.aprintf("%s/transport.bin", directory); defer delete(path)
	escaped := !before_send && stage != "socket-after-commit-before-write"
	assert(os.exists(path) == escaped)
	if escaped {
		witness_path := fmt.aprintf("%s/transport-state.bin", directory)
		defer delete(witness_path)
		witness, witness_io := os.read_entire_file(witness_path, context.allocator)
		assert(witness_io == nil)
		defer delete(witness)
		expected := socket_state_witness(peer)
		assert(bytes.equal(witness, expected[:]))
		packet, read_error := os.read_entire_file(path, context.allocator)
		assert(read_error == nil); defer delete(packet)
		inner := socket_transport_inner(packet); defer delete(inner)
		if pending_found {
			assert(bytes.equal(inner, pending))
		}
		socket_peer_decrypt(f, inner)
	} else if pending_found {
		socket_peer_decrypt(f, pending)
	}
	if pending_found {
		// Public ordinary send must take its exact pending replay path; it may not
		// rediscover devices, encrypt again, or advance a persisted session/key.
		revision := f.store.revision
		id, error := wa.socket_send_group(&peer.socket, SOCKET_GROUP, body, message_id = SOCKET_ID)
		defer delete(id)
		assert(error.kind == .None && id == SOCKET_ID && peer.socket.sequence == 0)
		assert(f.store.revision == revision && peer.socket.client.noise.write_counter == 1)
		if peer.tcp_enabled {socket_tcp_wait_replay(peer)}
		replay_path := fmt.aprintf("%s/replay.bin", directory); defer delete(replay_path)
		packet, read_error := os.read_entire_file(replay_path, context.allocator)
		assert(read_error == nil); defer delete(packet)
		replay_inner := socket_transport_inner(packet); defer delete(replay_inner)
		assert(bytes.equal(replay_inner, pending))
	}
	// After ACK but before caller journal: retain stable intent as unknown and do
	// not call send again. Absence of pending wire is not durable ACK knowledge.
	if acked && !journal {
		assert(peer.output_size == 0)
	}
	after, after_error := os.read_entire_file(f.path, context.allocator)
	assert(after_error == nil); defer delete(after)
	assert(bytes.equal(before, after))
	prekey_after, prekey_after_io := os.read_entire_file(peer.prekey_path, context.allocator)
	assert(prekey_after_io == nil)
	defer delete(prekey_after)
	assert(bytes.equal(prekey_before, prekey_after))
	fmt.printf(
		"ENCRYPTED_SOCKET_REOPEN_PASS stage=%s pending=%t application_ack_known=%t recipient_delivery=false\n",
		stage,
		pending_found,
		journal,
	)
}

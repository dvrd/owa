package whatsapp_test

import "core:bytes"
import "core:crypto"
import "core:fmt"
import "core:testing"
import test_fixtures "../fixtures/client"
import "shared:surf"
import wa "shared:whatsapp"

@(test)
mandatory_control_ack_malformed_envelopes_do_not_send_or_commit :: proc(t: ^testing.T) {
	for tag in ([]string{"receipt", "call"}) {
		for attrs in ([]([]wa.Binary_Node_Attribute) {
				{{"from", "222@s.whatsapp.net"}},
				{{"id", "synthetic-routing-id"}},
				{{"id", ""}, {"from", "222@s.whatsapp.net"}},
				{{"id", "synthetic-routing-id"}, {"from", ""}},
			}) {
			f := test_fixtures.negative_ack_fixture()
			defer test_fixtures.negative_ack_destroy(f)
			wire: test_fixtures.Send_Id_Wire
			test_fixtures.send_id_wire_connect(&f.socket, &wire)
			defer wa.socket_close(&f.socket)
			before := test_fixtures.negative_ack_disk(f)
			defer delete(before)
			revision, durable := f.store.revision, f.store.durable_revision
			event, error := wa.socket_process_node(&f.socket, test_fixtures.ack_routing_node(tag, "", attrs))
			testing.expect_value(t, error.kind, .Protocol_Error)
			testing.expect_value(t, event.kind, .None)
			testing.expect_value(t, wire.used, 0)
			testing.expect_value(t, f.socket.client.noise.write_counter, u64(0))
			test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
		}
	}
}

@(test)
mandatory_control_ack_write_failure_is_terminal_without_chat_commit :: proc(t: ^testing.T) {
	for tag in ([]string{"receipt", "call"}) {
		f := test_fixtures.negative_ack_fixture()
		defer test_fixtures.negative_ack_destroy(f)
		wire: test_fixtures.Send_Id_Wire
		test_fixtures.send_id_wire_connect(&f.socket, &wire)
		defer wa.socket_close(&f.socket)
		f.socket.websocket.stream.write = status_ack_failed_write
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		event, error := wa.socket_process_node(
			&f.socket,
			test_fixtures.ack_routing_node(tag, "", {{"id", "synthetic-routing-id"}, {"from", "222@s.whatsapp.net"}}),
		)
		testing.expect_value(t, error.kind, .Session_Failed)
		testing.expect_value(t, error.session.kind, .Client_Failed)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, f.socket.phase, .Failed)
		testing.expect_value(t, wire.used, 0)
		test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
	}
}

// Synthetic keys and a real established Signal exchange. Adapted from the
// owned encrypted_recovery fixture; no account material or fabricated sessions.
inbound_alias_private :: proc(start: int) -> [32]u8 {
	value: [32]u8

	for &b, i in value {
		b = u8(start + i)
	}

	value[0] &= 248
	value[31] = value[31] & 127 | 64

	return value
}

inbound_alias_local :: proc(start: int, registration: u32) -> wa.Signal_Recipient_Keys {
	return {
		identity_private = inbound_alias_private(start),
		registration_id = registration,
		signed_prekey_private = inbound_alias_private(start + 32),
		signed_prekey_id = 7,
		has_prekey = true,
		prekey_private = inbound_alias_private(start + 64),
		prekey_id = 9,
	}
}

inbound_alias_fixture :: proc(existing_lid: bool, first: []u8 = nil, second: []u8 = nil, next_wire: ^[]u8 = nil) -> (^test_fixtures.Negative_Ack_Fixture, []u8) {
	f := test_fixtures.negative_ack_fixture()
	a, b := inbound_alias_local(0, 100), inbound_alias_local(96, 200)
	public_a, public_b := wa.signal_curve_public(a.identity_private), wa.signal_curve_public(b.identity_private)
	bundle := wa.Signal_Prekey_Bundle {
		registration_id      = b.registration_id,
		identity_public      = public_b,
		signed_prekey_id     = b.signed_prekey_id,
		signed_prekey_public = wa.signal_curve_public(b.signed_prekey_private),
		has_prekey           = true,
		prekey_id            = b.prekey_id,
		prekey_public        = wa.signal_curve_public(b.prekey_private),
	}

	signed: [33]u8
	signed[0] = 5
	copy(signed[1:], bundle.signed_prekey_public[:])
	bundle.signed_prekey_signature, _ = wa.signal_curve_sign(b.identity_private, signed[:])
	sender, receiver: wa.Signal_Session
	defer {
		wa.signal_session_clear(&sender)
		wa.signal_session_clear(&receiver)
	}

	assert(
		wa.signal_session_init_initiator(&sender, a.identity_private, a.registration_id, bundle, public_b).kind == .None,
	)
	wire, plaintext: [4096]u8
	kind, size, error := wa.signal_session_encrypt(&sender, wire[:], []u8{1}, public_b)
	assert(error.kind == .None && kind == .Prekey)
	_, consumed, prekey_error := wa.signal_session_decrypt_prekey(&receiver, plaintext[:], wire[:size], b, public_a)
	assert(prekey_error.kind == .None && consumed == 9)
	kind, size, error = wa.signal_session_encrypt(&receiver, wire[:], []u8{1}, public_a)
	assert(error.kind == .None && kind == .Whisper)
	_, error = wa.signal_session_decrypt(&sender, plaintext[:], wire[:size], public_b)
	assert(error.kind == .None && !sender.pending_prekey)
	length := copy(plaintext[:], first)
	if first == nil {
		message_error: wa.Message_Error
		length, message_error = wa.text_message_encode(plaintext[:], {kind = .Conversation, text = "synthetic inbound alias"})
		assert(message_error == .None)
	}
	plaintext[length] = 1
	kind, size, error = wa.signal_session_encrypt(&sender, wire[:], plaintext[:length + 1], public_b)
	assert(error.kind == .None && kind == .Whisper)
	encrypted := make([]u8, size)
	copy(encrypted, wire[:size])
	if next_wire != nil {
		length = copy(plaintext[:], second)
		plaintext[length] = 1
		kind, size, error = wa.signal_session_encrypt(&sender, wire[:], plaintext[:length+1], public_b)
		assert(error.kind == .None && kind == .Whisper)
		next_wire^ = bytes.clone(wire[:size])
	}
	count, encoded := wa.signal_session_encode(nil, &receiver)
	assert(encoded.kind == .Destination_Undersized)
	data := make([]u8, count)
	defer {
		crypto.zero_explicit(raw_data(data), len(data))
		delete(data)
	}

	_, encoded = wa.signal_session_encode(data, &receiver)
	assert(encoded.kind == .None)
	address := existing_lid ? "999:1@lid" : "111:1@s.whatsapp.net"
	assert(wa.state_store_set(&f.store, .Session, address, data).kind == .None)
	assert(wa.state_store_set(&f.store, .Identity, address, public_a[:]).kind == .None)
	f.auth.credentials.identity_private = b.identity_private
	f.auth.credentials.registration_id = b.registration_id
	f.auth.account.jid_size = copy(f.auth.account.jid[:], "222:1@s.whatsapp.net")
	assert(wa.state_store_save(&f.store, f.path).kind == .None)

	return f, encrypted
}

inbound_alias_node :: proc(encrypted: []u8, lid_primary, group: bool) -> wa.Binary_Node {
	primary := lid_primary ? "999:1@lid" : "111:1@s.whatsapp.net"
	attrs := make([dynamic]wa.Binary_Node_Attribute)
	append(&attrs, {"id", "owa427-inbound"}, {"type", "text"})

	if group {
		append(&attrs, {"from", "123@g.us"}, {"participant", primary})
	} else {
		append(&attrs, {"from", primary})
	}

	field := group ? (lid_primary ? "participant_pn" : "participant_lid") : (lid_primary ? "sender_pn" : "sender_lid")
	append(&attrs, {field, lid_primary ? "111@s.whatsapp.net" : "999@lid"})
	children := make([]wa.Binary_Node, 1)
	children[0] = {
		tag     = "enc",
		attrs   = make([]wa.Binary_Node_Attribute, 1),
		content = encrypted,
	}

	children[0].attrs[0] = {"type", "msg"}

	return {tag = "message", attrs = attrs[:], content = children}
}

inbound_alias_node_destroy :: proc(node: wa.Binary_Node) {
	delete(node.attrs)
	children := node.content.([]wa.Binary_Node)

	for child in children {
		delete(child.attrs)
	}

	delete(children)
}

inbound_alias_process :: proc(f: ^test_fixtures.Negative_Ack_Fixture, node: wa.Binary_Node) -> (wa.Socket_Event, wa.Socket_Error) {
	history: bool

	return wa.socket_process_message(&f.socket, node, &history)
}

@(test)
inbound_alias_established_session_is_discovered_before_decrypt_and_dedup :: proc(t: ^testing.T) {
	for lid_primary in ([]bool{true, false}) {
		for group in ([]bool{false, true}) {
			f, encrypted := inbound_alias_fixture(!lid_primary)
			defer test_fixtures.negative_ack_destroy(f); defer delete(encrypted)
			node := inbound_alias_node(encrypted, lid_primary, group)
			defer inbound_alias_node_destroy(node)
			event, error := inbound_alias_process(f, node)
			testing.expect_value(t, error.kind, .None)
			testing.expect_value(t, event.kind, .Message)

			if event.message == nil {
				continue
			}

			defer wa.socket_message_destroy(event.message)
			alias, have := wa.state_store_get(&f.store, .LID_Mapping, "lid:999@lid")
			testing.expect(t, have && string(alias) == "111@s.whatsapp.net")
			key := group ? "123@g.us|111:1@s.whatsapp.net|owa427-inbound" : "|111:1@s.whatsapp.net|owa427-inbound"
			_, inbox := wa.state_store_get(&f.store, .Inbox_Message, key)
			testing.expect(t, inbox)
			testing.expect_value(t, wa.socket_message_complete(&f.socket, event.message).kind, .None)
			// Reopen durable store, then replay through the OTHER primary address.
			restored: wa.State_Store
			assert(wa.state_store_load(&restored, f.path, f.store.identity).kind == .None)
			wa.state_store_clear(&f.store)
			f.store = restored
			before := test_fixtures.negative_ack_disk(f)
			defer delete(before)
			revision, durable := f.store.revision, f.store.durable_revision
			other := inbound_alias_node(encrypted, !lid_primary, group)
			defer inbound_alias_node_destroy(other)
			duplicate, duplicate_error := inbound_alias_process(f, other)
			testing.expect_value(t, duplicate_error.kind, .None)
			testing.expect_value(t, duplicate.kind, .None)
			test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
		}
	}
}

@(test)
inbound_alias_failed_decrypt_or_save_never_commits_hints :: proc(t: ^testing.T) {
	for fail_save in ([]bool{false, true}) {
		f, encrypted := inbound_alias_fixture(false)
		defer test_fixtures.negative_ack_destroy(f)
		defer delete(encrypted)
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		bad_path: string
		defer delete(bad_path)

		if fail_save {
			bad_path = fmt.aprintf("%s/missing/state", f.directory)
			f.socket.config.state_path = bad_path
		} else {
			encrypted[len(encrypted) - 1] ~= 1
		}

		node := inbound_alias_node(encrypted, true, false)
		defer inbound_alias_node_destroy(node)
		event, error := inbound_alias_process(f, node)
		testing.expect(t, error.kind != .None)
		testing.expect_value(t, event.kind, .None)
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
	}
}

inbound_alias_extra_attr :: proc(node: ^wa.Binary_Node, attr: wa.Binary_Node_Attribute) {
	attrs := make([]wa.Binary_Node_Attribute, len(node.attrs) + 1)
	copy(attrs, node.attrs)
	attrs[len(node.attrs)] = attr
	delete(node.attrs)
	node.attrs = attrs
}

@(test)
inbound_alias_refuses_conflicting_invalid_and_ambiguous_sender_hints :: proc(t: ^testing.T) {
	for added in ([]wa.Binary_Node_Attribute {
			{"addressing_mode", "pn"},
			{"addressing_mode", "unknown"},
			{"sender_pn", "333@s.whatsapp.net"},
			{"sender_lid", "999@lid"},
			{"sender_pn", "111@s.whatsapp.net"},
			{"sender_pn", "111:2@s.whatsapp.net"},
			{"sender_pn", "111@lid"},
			{"sender_pn", "invalid"},
			{"sender_pn", ""},
		}) {
		f, encrypted := inbound_alias_fixture(false)
		defer test_fixtures.negative_ack_destroy(f)
		defer delete(encrypted)
		node := inbound_alias_node(encrypted, true, false)
		defer inbound_alias_node_destroy(node)
		// sender_pn is already present. To exercise both conflicts and bad values,
		// change that field when the added key repeats it; duplicate is separate.
		if added.key == "sender_pn" && added.value != "333@s.whatsapp.net" && added.value != "111@s.whatsapp.net" {
			node.attrs[len(node.attrs) - 1] = added
		} else {
			inbound_alias_extra_attr(&node, added)
		}
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		event, error := inbound_alias_process(f, node)
		testing.expect(t, error.kind != .None)
		testing.expect_value(t, event.kind, .None)
		if event.message != nil {
			wa.socket_message_destroy(event.message)
		}
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
	}
}

@(test)
inbound_alias_refuses_existing_mapping_or_identity_pin_conflicts :: proc(t: ^testing.T) {
	for mapping_conflict in ([]bool{false, true}) {
		f, encrypted := inbound_alias_fixture(false)
		defer test_fixtures.negative_ack_destroy(f)
		defer delete(encrypted)

		if mapping_conflict {
			assert(wa.socket_lid_mapping_stage(&f.store, "111@s.whatsapp.net", "888@lid").kind == .None)
		} else {
			identity := wa.signal_curve_public(inbound_alias_private(32))
			assert(wa.state_store_set(&f.store, .Identity, "999:1@lid", identity[:]).kind == .None)
		}

		assert(wa.state_store_save(&f.store, f.path).kind == .None)
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		node := inbound_alias_node(encrypted, true, true)
		defer inbound_alias_node_destroy(node)
		event, error := inbound_alias_process(f, node)
		testing.expect_value(t, error.kind, .Identity_Changed)
		testing.expect_value(t, event.kind, .None)
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
	}
}

@(test)
inbound_alias_preserves_no_hint_and_accepts_same_device_and_canonical_domains :: proc(t: ^testing.T) {
	for variant in 0 ..< 4 {
		f, encrypted := inbound_alias_fixture(false)
		defer test_fixtures.negative_ack_destroy(f)
		defer delete(encrypted)
		node := inbound_alias_node(encrypted, variant != 0, false)
		defer inbound_alias_node_destroy(node)

		if variant == 0 {
			node.attrs = node.attrs[:len(node.attrs) - 1]
		}

		if variant == 1 {
			node.attrs[len(node.attrs) - 1].value = "111:1@s.whatsapp.net"
		}

		if variant == 2 {
			node.attrs[len(node.attrs) - 1].value = "111@c.us"
		}

		if variant == 3 {
			inbound_alias_extra_attr(&node, {"addressing_mode", "lid"})
			inbound_alias_extra_attr(&node, {"participant_pn", "111:1@c.us"})
		}

		event, error := inbound_alias_process(f, node)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .Message)

		if event.message != nil {
			wa.socket_message_destroy(event.message)
		}

		_, mapped := wa.state_store_get(&f.store, .LID_Mapping, "lid:999@lid")
		testing.expect_value(t, mapped, variant != 0)
	}
}

@(test)
inbound_alias_unsupported_encryption_preflight_precedes_hint_processing :: proc(t: ^testing.T) {
	f, encrypted := inbound_alias_fixture(false)
	defer test_fixtures.negative_ack_destroy(f)
	defer delete(encrypted)
	node := inbound_alias_node(encrypted, true, true)
	defer inbound_alias_node_destroy(node)
	node.content.([]wa.Binary_Node)[0].attrs[0].value = "msmsg"
	inbound_alias_extra_attr(&node, {"addressing_mode", "invalid"})
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	event, error := inbound_alias_process(f, node)
	testing.expect_value(t, error.kind, .Unsupported_Message_Encryption)
	testing.expect_value(t, event.kind, .None)
	test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
}

@(test)
inbound_alias_skipped_self_echo_and_unencrypted_control_cannot_install_hints :: proc(t: ^testing.T) {
	for own_group in ([]bool{false, true}) {
		f, encrypted := inbound_alias_fixture(false)
		defer test_fixtures.negative_ack_destroy(f)
		defer delete(encrypted)
		node := inbound_alias_node(encrypted, !own_group, own_group)
		defer inbound_alias_node_destroy(node)

		if own_group {
			f.auth.account.jid_size = copy(f.auth.account.jid[:], "111:1@s.whatsapp.net")
		} else {
			node.content.([]wa.Binary_Node)[0].tag = "unavailable"
		}

		event, error := inbound_alias_process(f, node)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .None)
		_, have := wa.state_store_get(&f.store, .LID_Mapping, "lid:999@lid")
		testing.expect(t, !have)
	}
}

@(test)
inbound_alias_inbox_key_preserves_uninitialized_state_rejection :: proc(t: ^testing.T) {
	store: wa.State_Store
	socket := wa.Socket {
		store = &store,
	}

	key, error := wa.socket_inbox_key(&socket, "", "111@s.whatsapp.net", "inbox-guard")
	defer delete(key)
	testing.expect_value(t, error.kind, .Invalid_State)
	testing.expect_value(t, key, "")
}

@(test)
inbound_alias_inbox_key_preserves_nil_socket_and_store_rejection :: proc(t: ^testing.T) {
	for socket in ([](^wa.Socket){nil, new(wa.Socket)}) {
		defer if socket != nil {
			free(socket)
		}

		key, error := wa.socket_inbox_key(socket, "", "111@s.whatsapp.net", "inbox-guard")
		defer delete(key)
		testing.expect_value(t, error.kind, .Invalid_State)
		testing.expect_value(t, key, "")
	}

	key, error := wa.socket_inbox_key_store(nil, "", "111@s.whatsapp.net", "inbox-guard")
	defer delete(key)
	testing.expect_value(t, error.kind, .Invalid_State)
	testing.expect_value(t, key, "")
}

@(test)
inbound_alias_own_device_classification_requires_successful_decrypt_and_staged_mapping :: proc(t: ^testing.T) {
	for group in ([]bool{false, true}) {
		for corrupt in ([]bool{false, true}) {
			f, encrypted := inbound_alias_fixture(false)
			defer test_fixtures.negative_ack_destroy(f)
			defer delete(encrypted)
			f.auth.account.jid_size = copy(f.auth.account.jid[:], "111:2@s.whatsapp.net")
			node := inbound_alias_node(encrypted, true, group)
			defer inbound_alias_node_destroy(node)
			before := test_fixtures.negative_ack_disk(f)
			defer delete(before)
			revision, durable := f.store.revision, f.store.durable_revision

			if corrupt {
				encrypted[len(encrypted) - 1] ~= 1
			}

			event, error := inbound_alias_process(f, node)

			if corrupt {
				testing.expect(t, error.kind != .None)
				testing.expect_value(t, event.kind, .None)
				test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
				continue
			}

			testing.expect_value(t, error.kind, .None)
			testing.expect_value(t, event.kind, .Message)

			if event.message == nil {
				continue
			}

			testing.expect(t, event.message.from_me)
			wa.socket_message_destroy(event.message)
			restored: wa.State_Store
			assert(wa.state_store_load(&restored, f.path, f.store.identity).kind == .None)
			wa.state_store_clear(&f.store)
			f.store = restored
			count := 0

			for record in f.store.records {
				if record.kind != .Inbox_Message {
					continue
				}

				recovered, restore_error := wa.socket_inbox_record_restore(&f.socket, record)
				testing.expect_value(t, restore_error.kind, .None)

				if recovered != nil {
					count += 1
					testing.expect(t, recovered.from_me)
					wa.socket_message_destroy(recovered)
				}
			}

			testing.expect_value(t, count, 1)
		}
	}
}

@(test)
inbound_alias_self_classification_refuses_invalid_owner_state :: proc(t: ^testing.T) {
	testing.expect(t, !wa.socket_sender_is_self(nil, "111@s.whatsapp.net"))
	socket: wa.Socket
	testing.expect(t, !wa.socket_sender_is_self(&socket, "111@s.whatsapp.net"))
	store: wa.State_Store
	auth: wa.Auth_State
	testing.expect(t, !wa.socket_sender_is_self_store(nil, &auth, "111@s.whatsapp.net"))
	testing.expect(t, !wa.socket_sender_is_self_store(&store, &auth, "111@s.whatsapp.net"))
	testing.expect(t, !wa.socket_sender_is_self_store(&store, nil, "111@s.whatsapp.net"))
}

// These maps qualify the existing bounded ACK policy, not a server acceptance
// contract. The independent implementations disagree on normal type/local from;
// see docs/message-ack-contract-20261113.md before changing that policy.
Message_Ack_Vector :: struct {
	attrs, expected: []wa.Binary_Node_Attribute,
	unavailable:     bool,
	error_code:      u32,
	local:           string,
}

message_ack_expect :: proc(t: ^testing.T, wire: ^test_fixtures.Send_Id_Wire, expected: []wa.Binary_Node_Attribute) {
	testing.expect(t, wire.used > 0)

	if wire.used == 0 {
		return
	}

	plain: [2048]u8
	encoded := test_fixtures.send_id_wire_plain(wire, plain[:])
	doc, error := wa.binary_node_decode(transmute([]u8)encoded)
	assert(error.kind == .None)
	defer wa.binary_document_destroy(&doc)
	testing.expect_value(t, doc.root.tag, "ack")
	testing.expect_value(t, len(doc.root.attrs), len(expected))

	for attr in expected {
		value, found := wa.node_attr(doc.root, attr.key)
		testing.expect(t, found && value == attr.value)
	}
}

message_ack_vector :: proc(t: ^testing.T, vector: Message_Ack_Vector) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	copy(f.auth.account.jid[:], vector.local)
	f.auth.account.jid_size = len(vector.local)
	wire: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&f.socket, &wire)
	defer wa.socket_close(&f.socket)
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	children := [1]wa.Binary_Node{{tag = "unavailable"}}
	node := wa.Binary_Node {
		tag   = "message",
		attrs = vector.attrs,
	}

	if vector.unavailable {
		node.content = children[:]
	}

	buffer: [2048]u8
	count, encoded := wa.binary_node_encode(buffer[:], node)
	assert(encoded.kind == .None)
	doc, decoded := wa.binary_node_decode(buffer[:count])
	assert(decoded.kind == .None)
	error := wa.socket_acknowledge(&f.socket, doc.root, vector.error_code)
	wa.binary_document_destroy(&doc)

	for &value in buffer {
		value = 0xa5
	}

	testing.expect_value(t, error.kind, .None)
	message_ack_expect(t, &wire, vector.expected)
	testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
	test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
}

@(test)
message_ack_normal_policy_uses_exact_encrypted_maps_after_document_release :: proc(t: ^testing.T) {
	for local in ([]string{"", "111:1@s.whatsapp.net"}) {
		for optional in ([]([]wa.Binary_Node_Attribute){{}, {{"type", "text"}}, {{"type", ""}}}) {
			attrs := [3]wa.Binary_Node_Attribute{{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}, {}}
			count := 2

			if len(optional) > 0 {
				attrs[2] = optional[0]
				count = 3
			}

			message_ack_vector(
				t,
				{
					attrs = attrs[:count],
					local = local,
					expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"}, {"class", "message"}},
				},
			)
		}
	}
}

@(test)
message_ack_optional_participant_and_recipient_preserve_presence :: proc(t: ^testing.T) {
	for participant in ([]string{"333:4@s.whatsapp.net", ""}) {
		for recipient in ([]string{"444@s.whatsapp.net", ""}) {
			message_ack_vector(
				t,
				{
					attrs = {
						{"id", "synthetic-ack-id"},
						{"from", "222@s.whatsapp.net"},
						{"type", "media"},
						{"participant", participant},
						{"recipient", recipient},
					},
					expected = {
						{"id", "synthetic-ack-id"},
						{"to", "222@s.whatsapp.net"},
						{"class", "message"},
						{"participant", participant},
						{"recipient", recipient},
					},
				},
			)
		}
	}
}

@(test)
message_ack_unavailable_and_error_maps_remain_separate_legacy_policies :: proc(t: ^testing.T) {
	for kind in ([]string{"text", ""}) {
		message_ack_vector(
			t,
			{
				attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}, {"type", kind}},
				unavailable = true,
				local = "111:1@s.whatsapp.net",
				expected = {
					{"id", "synthetic-ack-id"},
					{"to", "222@s.whatsapp.net"},
					{"class", "message"},
					{"type", kind},
					{"from", "111:1@s.whatsapp.net"},
				},
			},
		)
		message_ack_vector(
			t,
			{
				attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}, {"type", kind}},
				error_code = 487,
				local = "111:1@s.whatsapp.net",
				expected = {
					{"id", "synthetic-ack-id"},
					{"to", "222@s.whatsapp.net"},
					{"class", "message"},
					{"type", kind},
					{"error", "487"},
				},
			},
		)
	}

	// No local identity is an artificial private-helper state, not paired support.
	message_ack_vector(
		t,
		{
			attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}},
			unavailable = true,
			expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"}, {"class", "message"}, {"from", ""}},
		},
	)
	message_ack_vector(
		t,
		{
			attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}},
			error_code = 487,
			expected = {
				{"id", "synthetic-ack-id"},
				{"to", "222@s.whatsapp.net"},
				{"class", "message"},
				{"error", "487"},
			},
		},
	)
}

@(test)
message_ack_missing_or_empty_mandatory_attrs_do_not_write :: proc(t: ^testing.T) {
	for attrs in ([]([]wa.Binary_Node_Attribute) {
			{{"from", "222@s.whatsapp.net"}},
			{{"id", "synthetic-ack-id"}},
			{{"id", ""}, {"from", "222@s.whatsapp.net"}},
			{{"id", "synthetic-ack-id"}, {"from", ""}},
		}) {
		f := test_fixtures.negative_ack_fixture()
		defer test_fixtures.negative_ack_destroy(f)
		wire: test_fixtures.Send_Id_Wire
		test_fixtures.send_id_wire_connect(&f.socket, &wire)
		defer wa.socket_close(&f.socket)
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		error := wa.socket_acknowledge(&f.socket, {tag = "message", attrs = attrs})
		testing.expect_value(t, error.kind, .Protocol_Error)
		testing.expect_value(t, wire.used, 0)
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(0))
		test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
	}
}

@(test)
message_ack_write_failure_does_not_mutate_or_replay_intent :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	wire: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&f.socket, &wire)
	defer wa.socket_close(&f.socket)
	f.socket.websocket.stream.write = status_ack_failed_write
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	error := wa.socket_acknowledge(
		&f.socket,
		{tag = "message", attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}}},
	)
	testing.expect_value(t, error.kind, .Session_Failed)
	testing.expect_value(t, f.socket.phase, .Failed)
	testing.expect_value(t, wire.used, 0)
	test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
	after := test_fixtures.negative_ack_disk(f)
	defer delete(after)
	testing.expect(t, bytes.equal(before, after))
}

@(test)
negative_ack_error_presence_rejects_tracked_intent_without_any_mutation :: proc(t: ^testing.T) {
	// Error presence, not successful numeric parsing, determines rejection.
	for value in ([]string{"479", "463", "", "not-a-number", "0", "-1"}) {
		f := test_fixtures.negative_ack_fixture()
		defer test_fixtures.negative_ack_destroy(f)
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		event, error := wa.socket_process_node(
			&f.socket,
			{tag = "ack", attrs = {{"class", "message"}, {"id", "owned-id"}, {"error", value}}},
		)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, error.kind, .Message_Rejected)
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
		wire, pending := wa.state_store_get(&f.store, .Outbound_Message, "owned-id")
		testing.expect(t, pending && bytes.equal(wire, transmute([]u8)string("synthetic wire")))
		_, retained := wa.state_store_get(&f.store, .Outbound_Content, "owned-id")
		testing.expect(t, retained)
	}
}

@(test)
negative_ack_retained_or_pending_intent_alone_is_tracked :: proc(t: ^testing.T) {
	for removed in ([]wa.State_Record_Kind{.Outbound_Message, .Outbound_Content}) {
		f := test_fixtures.negative_ack_fixture()
		defer test_fixtures.negative_ack_destroy(f)
		assert(wa.state_store_delete(&f.store, removed, "owned-id").kind == .None)
		assert(wa.state_store_save(&f.store, f.path).kind == .None)
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		_, error := wa.socket_process_node(
			&f.socket,
			{tag = "ack", attrs = {{"class", "message"}, {"id", "owned-id"}, {"error", "479"}}},
		)
		testing.expect_value(t, error.kind, .Message_Rejected)
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
	}
}

@(test)
negative_ack_unknown_missing_id_or_other_class_does_not_abort_session :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision

	for attributes in ([]([]wa.Binary_Node_Attribute) {
			{{"class", "message"}, {"id", "unknown-id"}, {"error", "479"}},
			{{"class", "message"}, {"id", ""}, {"error", ""}},
			{{"class", "message"}, {"error", "malformed"}},
			{{"class", "receipt"}, {"id", "owned-id"}, {"error", "479"}},
			{{"id", "owned-id"}, {"error", "479"}},
		}) {
		event, error := wa.socket_process_node(&f.socket, {tag = "ack", attrs = attributes})
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, error.kind, .None)
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
	}
}

@(test)
negative_ack_positive_control_commits_pending_removal_and_retains_content :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	revision := f.store.revision
	_, error := wa.socket_process_node(&f.socket, {tag = "ack", attrs = {{"class", "message"}, {"id", "owned-id"}}})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, f.socket.phase, .Online)
	testing.expect_value(t, f.store.revision, revision + 1)
	testing.expect_value(t, f.store.durable_revision, f.store.revision)
	_, pending := wa.state_store_get(&f.store, .Outbound_Message, "owned-id")
	_, retained := wa.state_store_get(&f.store, .Outbound_Content, "owned-id")
	testing.expect(t, !pending && retained)
	restored: wa.State_Store
	defer wa.state_store_clear(&restored)
	testing.expect_value(t, wa.state_store_load(&restored, f.path, f.store.identity).kind, .None)
	_, durable_pending := wa.state_store_get(&restored, .Outbound_Message, "owned-id")
	_, durable_content := wa.state_store_get(&restored, .Outbound_Content, "owned-id")
	testing.expect(t, !durable_pending && durable_content)
	testing.expect_value(t, restored.revision, revision + 1)
}

@(test)
trust_identity_pins_new_key_and_drops_sessions_and_sender_keys_of_that_device :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	original := identity_api_pin(1)
	replacement := identity_api_pin(40)
	device := "555:1@s.whatsapp.net"
	testing.expect_value(t, wa.state_store_set(&fixture.store, .Identity, device, original[:]).kind, wa.State_Error_Kind.None)
	doomed := [?]struct {
		kind: wa.State_Record_Kind,
		name: string,
	} {
		{.Session, "555:1@s.whatsapp.net"},
		{.Session, "555:1@s.whatsapp.net#prior-base"},
		{.Sender_Key, "123@g.us|555:1@s.whatsapp.net"},
		{.Sender_Key_Membership, "123@g.us|555:1@s.whatsapp.net"},
	}
	survivors := [?]struct {
		kind: wa.State_Record_Kind,
		name: string,
	}{{.Session, "999:1@s.whatsapp.net"}, {.Sender_Key, "123@g.us|999:1@s.whatsapp.net"}, {.Session, "555:2@s.whatsapp.net"}}
	for record in doomed {
		testing.expect_value(t, wa.state_store_set(&fixture.store, record.kind, record.name, []u8{1}).kind, wa.State_Error_Kind.None)
	}

	for record in survivors {
		testing.expect_value(t, wa.state_store_set(&fixture.store, record.kind, record.name, []u8{1}).kind, wa.State_Error_Kind.None)
	}

	testing.expect_value(t, wa.socket_trust_identity(&fixture.socket, device, replacement).kind, wa.Socket_Error_Kind.None)

	pin, found := wa.state_store_get(&fixture.store, .Identity, device)
	testing.expect(t, found)
	testing.expect(t, bytes.equal(pin, replacement[:]))

	for record in doomed {
		testing.expectf(t, !identity_api_has(&fixture.store, record.kind, record.name), "%v %s survived", record.kind, record.name)
	}

	for record in survivors {
		testing.expectf(t, identity_api_has(&fixture.store, record.kind, record.name), "%v %s lost", record.kind, record.name)
	}

	testing.expect_value(t, fixture.store.revision, fixture.store.durable_revision)
}

@(test)
trust_identity_rejects_invalid_input_and_failed_save_keeps_pin_and_sessions :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	original := identity_api_pin(1)
	replacement := identity_api_pin(40)
	device := "555:1@s.whatsapp.net"
	testing.expect_value(t, wa.state_store_set(&fixture.store, .Identity, device, original[:]).kind, wa.State_Error_Kind.None)
	testing.expect_value(t, wa.state_store_set(&fixture.store, .Session, device, []u8{1}).kind, wa.State_Error_Kind.None)
	revision := fixture.store.revision

	zero: [32]u8
	testing.expect_value(t, wa.socket_trust_identity(&fixture.socket, device, zero).kind, wa.Socket_Error_Kind.Invalid_Config)
	testing.expect_value(t, wa.socket_trust_identity(&fixture.socket, "not-a-jid", replacement).kind, wa.Socket_Error_Kind.Invalid_Config)
	testing.expect_value(t, wa.socket_trust_identity(&fixture.socket, "555@g.us", replacement).kind, wa.Socket_Error_Kind.Invalid_Config)
	testing.expect_value(t, wa.socket_trust_identity(nil, device, replacement).kind, wa.Socket_Error_Kind.Invalid_Config)

	fixture.socket.config.state_path = "/nonexistent-whatsapp-library-directory/state"
	testing.expect_value(t, wa.socket_trust_identity(&fixture.socket, device, replacement).kind, wa.Socket_Error_Kind.State_Failed)

	pin, found := wa.state_store_get(&fixture.store, .Identity, device)
	testing.expect(t, found)
	testing.expect(t, bytes.equal(pin, original[:]))
	testing.expect(t, identity_api_has(&fixture.store, .Session, device))
	testing.expect_value(t, fixture.store.revision, revision)
}

// Top-level status is a transport control, distinct from message/status@broadcast.
// Capture the actual masked-WebSocket/Noise output; a viewed receipt or chat event
// must never be emitted. All addresses/content below are synthetic.
@(test)
status_ack_top_level_live_and_offline_preserves_transport_attributes :: proc(t: ^testing.T) {
	for phase in ([]wa.Socket_Phase{.Online, .Provisioning}) {
		for kind in ([]string{"media", "text"}) {
			for offline in ([]string{"true", "false"}) {
				f := test_fixtures.negative_ack_fixture()
				defer test_fixtures.negative_ack_destroy(f)
				before := test_fixtures.negative_ack_disk(f)
				defer delete(before)
				revision, durable := f.store.revision, f.store.durable_revision
				wire: test_fixtures.Send_Id_Wire
				test_fixtures.send_id_wire_connect(&f.socket, &wire)
				defer wa.frame_transport_clear(&f.socket.client.frames)
				f.socket.phase = phase
				event, error := wa.socket_process_node(
					&f.socket,
					{
						tag = "status",
						attrs = {
							{"id", "synthetic-status-id"},
							{"from", "status@broadcast"},
							{"type", kind},
							{"participant", "222@s.whatsapp.net"},
							{"recipient", "333:4@s.whatsapp.net"},
							{"offline", offline},
						},
						content = []u8{1, 2, 3},
					},
				)
				testing.expect_value(t, error.kind, .None)
				testing.expect_value(t, event.kind, .None)
				testing.expect(t, event.message == nil)
				testing.expect(t, wire.used > 0, "status must produce one transport ACK")

				if wire.used == 0 {
					continue
				}

				plain: [2048]u8
				encoded := test_fixtures.send_id_wire_plain(&wire, plain[:])
				document, binary_error := wa.binary_node_decode(transmute([]u8)encoded)
				testing.expect_value(t, binary_error.kind, .None)

				if binary_error.kind != .None {
					continue
				}

				defer wa.binary_document_destroy(&document)
				testing.expect_value(t, document.root.tag, "ack")
				testing.expect_value(t, len(document.root.attrs), 6)

				for expected in ([]wa.Binary_Node_Attribute {
						{"id", "synthetic-status-id"},
						{"to", "status@broadcast"},
						{"class", "status"},
						{"type", kind},
						{"participant", "222@s.whatsapp.net"},
						{"recipient", "333:4@s.whatsapp.net"},
					}) {
					value, found := wa.node_attr(document.root, expected.key)
					testing.expect(t, found && value == expected.value)
				}

				_, nack := wa.node_attr(document.root, "error")
				_, offline_copied := wa.node_attr(document.root, "offline")
				testing.expect(t, !nack && !offline_copied)
				testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
				testing.expect_value(t, f.store.revision, revision)
				testing.expect_value(t, f.store.durable_revision, durable)
				after := test_fixtures.negative_ack_disk(f)
				defer delete(after)
				testing.expect(t, bytes.equal(before, after), "status ACK must not mutate durable chat state")
			}
		}
	}
}

@(test)
status_ack_malformed_envelopes_fail_without_output_or_store_changes :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	wire: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&f.socket, &wire)
	defer wa.frame_transport_clear(&f.socket.client.frames)
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision

	for attrs in ([]([]wa.Binary_Node_Attribute) {
			{{"from", "status@broadcast"}},
			{{"id", "synthetic-id"}},
			{{"id", ""}, {"from", "status@broadcast"}},
			{{"id", "synthetic-id"}, {"from", ""}},
		}) {
		event, error := wa.socket_process_node(&f.socket, {tag = "status", attrs = attrs})
		testing.expect_value(t, error.kind, .Protocol_Error)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, wire.used, 0)
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
	}
}

status_ack_failed_write :: proc(_: rawptr, _: []u8) -> (int, surf.WebSocket_Stream_Error) {
	return 0, {kind = .No_Progress}
}

@(test)
status_ack_write_failure_is_propagated_without_chat_state_commit :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	wire: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&f.socket, &wire)
	defer wa.socket_close(&f.socket)
	f.socket.websocket.stream.write = status_ack_failed_write
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	event, error := wa.socket_process_node(
		&f.socket,
		{tag = "status", attrs = {{"id", "synthetic-id"}, {"from", "status@broadcast"}}},
	)
	testing.expect_value(t, error.kind, .Session_Failed)
	testing.expect_value(t, error.session.kind, .Client_Failed)
	testing.expect_value(t, event.kind, .None)
	testing.expect_value(t, f.socket.phase, .Failed)
	testing.expect_value(t, f.store.revision, revision)
	testing.expect_value(t, f.store.durable_revision, durable)
	after := test_fixtures.negative_ack_disk(f)
	defer delete(after)
	testing.expect(t, bytes.equal(before, after))
}

@(test)
status_ack_legacy_broadcast_message_remains_transport_only :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	wire: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&f.socket, &wire)
	defer wa.frame_transport_clear(&f.socket.client.frames)
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	event, error := wa.socket_process_node(
		&f.socket,
		{tag = "message", attrs = {{"id", "synthetic-legacy-id"}, {"from", "status@broadcast"}, {"type", "media"}}},
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, event.kind, .None)
	plain: [2048]u8
	encoded := test_fixtures.send_id_wire_plain(&wire, plain[:])
	document, decode := wa.binary_node_decode(transmute([]u8)encoded)
	assert(decode.kind == .None)
	defer wa.binary_document_destroy(&document)
	class, found := wa.node_attr(document.root, "class")
	testing.expect(t, document.root.tag == "ack" && found && class == "message")
	_, viewed_type := wa.node_attr(document.root, "type")
	_, nack := wa.node_attr(document.root, "error")
	testing.expect(t, !viewed_type && !nack)
	testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
	test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
}

unsupported_enc_cipher := [1]u8{1}

unsupported_enc_node :: proc(kind: string, mixed, reverse, group: bool) -> wa.Binary_Node {
	node := wa.Binary_Node {
		tag = "message",
	}

	node.attrs = make([]wa.Binary_Node_Attribute, group ? 4 : 3)

	if group {
		copy(
			node.attrs,
			[]wa.Binary_Node_Attribute {
				{"id", "unsupported-content-id"},
				{"from", "123@g.us"},
				{"participant", "222:4@s.whatsapp.net"},
				{"type", "text"},
			},
		)
	} else {
		copy(
			node.attrs,
			[]wa.Binary_Node_Attribute {
				{"id", "unsupported-content-id"},
				{"from", "222@s.whatsapp.net"},
				{"type", "text"},
			},
		)
	}

	children := make([]wa.Binary_Node, mixed ? 2 : 1)
	unknown := mixed && reverse ? 1 : 0

	for &child, i in children {
		child.tag = "enc"
		child.attrs = make([]wa.Binary_Node_Attribute, 1)
		child.attrs[0] = {"type", i == unknown ? kind : "pkmsg"}
		child.content = unsupported_enc_cipher[:]
	}

	node.content = children

	return node
}

unsupported_enc_node_destroy :: proc(node: wa.Binary_Node) {
	children := node.content.([]wa.Binary_Node)

	for child in children {
		delete(child.attrs)
	}

	delete(children)
	delete(node.attrs)
}

unsupported_enc_case :: proc(t: ^testing.T, kind: string, mixed, reverse, group: bool) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	node := unsupported_enc_node(kind, mixed, reverse, group)
	defer unsupported_enc_node_destroy(node)
	// Reopen the actual durable state before each replay. Unsupported content
	// must not become a deduplicated success after reconnect.
	for _ in 0 ..< 3 {
		restored: wa.State_Store
		assert(wa.state_store_load(&restored, f.path, f.store.identity).kind == .None)
		wa.state_store_clear(&f.store)
		f.store = restored
		f.socket.phase = .Online
		wire: test_fixtures.Send_Id_Wire
		test_fixtures.send_id_wire_connect(&f.socket, &wire)
		event, error := wa.socket_process_node(&f.socket, node)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
		testing.expect_value(t, len(f.socket.deferred_retries), 0)
		test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)

		if wire.used > 0 && f.socket.client.noise.write_counter == 1 {
			plain: [2048]u8
			encoded := test_fixtures.send_id_wire_plain(&wire, plain[:])
			doc, decoded := wa.binary_node_decode(transmute([]u8)encoded)
			assert(decoded.kind == .None)
			testing.expect_value(t, doc.root.tag, "ack")
			code, found := wa.node_attr(doc.root, "error")
			testing.expect(t, found)
			testing.expect_value(t, code, kind == "msmsg" ? "495" : "490")
			id, _ := wa.node_attr(doc.root, "id")
			testing.expect_value(t, id, "unsupported-content-id")
			wa.binary_document_destroy(&doc)
		} else {
			testing.expect(t, false, "exactly one negative ACK required")
		}

		wa.socket_close(&f.socket)
	}

	after := test_fixtures.negative_ack_disk(f)
	defer delete(after)
	testing.expect(t, bytes.equal(before, after))
}

@(test)
unsupported_encryption_never_success_marks_and_replay_is_bounded :: proc(t: ^testing.T) {
	for kind in ([]string{"msmsg", "future-cipher", ""}) {
		for group in ([]bool{false, true}) {
			unsupported_enc_case(t, kind, false, false, group)
		}
	}
}

@(test)
unsupported_encryption_rejects_mixed_children_before_any_ratchet_mutation :: proc(t: ^testing.T) {
	for kind in ([]string{"msmsg", "future-cipher"}) {
		for reverse in ([]bool{false, true}) {
			unsupported_enc_case(t, kind, true, reverse, true)
		}
	}
}

unsupported_enc_write_fail :: proc(data: rawptr, source: []u8) -> (int, surf.WebSocket_Stream_Error) {
	return 0, {kind = .No_Progress}
}

@(test)
unsupported_encryption_failed_nack_does_not_commit_or_enqueue_retry :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	wire: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&f.socket, &wire)
	defer wa.socket_close(&f.socket)
	f.socket.websocket.stream.write = unsupported_enc_write_fail
	node := unsupported_enc_node("msmsg", false, false, false)
	defer unsupported_enc_node_destroy(node)
	event, error := wa.socket_process_node(&f.socket, node)
	testing.expect(t, error.kind != .None)
	testing.expect_value(t, event.kind, .None)
	testing.expect_value(t, len(f.socket.deferred_retries), 0)
	// A write failure may fail the transport; durable content must remain exact.
	testing.expect_value(t, f.store.revision, revision)
	testing.expect_value(t, f.store.durable_revision, durable)
	after := test_fixtures.negative_ack_disk(f)
	defer delete(after)
	testing.expect(t, bytes.equal(before, after))
}

@(test)
unsupported_encryption_keeps_supported_distribution_order_and_controls_admissible :: proc(t: ^testing.T) {
	// Preflight must leave both packet orders for the existing two-pass Signal
	// decoder, and leave non-encrypted controls to their existing handler.
	supported := [3]wa.Binary_Node {
		{tag = "enc", attrs = {{"type", "skmsg"}}},
		{tag = "enc", attrs = {{"type", "pkmsg"}}},
		{tag = "enc", attrs = {{"type", "msg"}}},
	}

	testing.expect_value(t, wa.message_encryption_nack_reason({content = supported[:]}), u32(0))
	supported[0], supported[2] = supported[2], supported[0]
	testing.expect_value(t, wa.message_encryption_nack_reason({content = supported[:]}), u32(0))
	controls := [1]wa.Binary_Node{{tag = "unavailable"}}
	testing.expect_value(t, wa.message_encryption_nack_reason({content = controls[:]}), u32(0))
}

@(test)
history_redelivery_restores_receipt_after_reopening_store :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	from :: "222@s.whatsapp.net"
	id :: "history-receipt"
	name, e := wa.socket_inbox_key_store(&f.store, "", from, id)
	assert(e.kind == .None)
	defer delete(name)
	// Message.protocolMessage.historySyncNotification, with an empty notification.
	payload := []u8{0x62, 2, 0x32, 0}
	staged: wa.State_Store
	defer wa.state_store_clear(&staged)
	assert(wa.socket_store_clone(&staged, &f.store).kind == .None)
	receipt := false
	handled, committed := wa.socket_message_control_commit(&f.socket, &staged, name, "", payload, true, &receipt)
	testing.expect(t, handled && committed.kind == .None && receipt)
	identity := f.store.identity
	assert(wa.state_store_load(&f.store, f.path, identity).kind == .None)
	receipt = false
	node := wa.Binary_Node{tag = "message", attrs = []wa.Binary_Node_Attribute{{"from", from}, {"id", id}}}
	_, err := wa.socket_process_message(&f.socket, node, &receipt)
	testing.expect(t, err.kind == .None && receipt)
}

@(test)
private_voice_capture_survives_reopen :: proc(t: ^testing.T) {
	chat :: "111@s.whatsapp.net"
	alias :: "999@lid"
	ids := [2]string{"note-one", "note-two"}
	for capture in ([]bool{false, true}) {
		second: []u8
		f, first := inbound_alias_fixture(
			false,
			test_fixtures.codec_api_hex(test_fixtures.VOICE_1_PROTO),
			test_fixtures.codec_api_hex(test_fixtures.VOICE_2_PROTO),
			&second,
		)
		defer test_fixtures.negative_ack_destroy(f)
		defer delete(first)
		defer delete(second)
		for cipher, i in ([2][]u8{first, second}) {
			node := inbound_alias_node(cipher, i == 1, false)
			defer inbound_alias_node_destroy(node)
			node.attrs[0].value = ids[i]
			node.attrs[1] = {"t", "103" if i == 0 else "104"}
			event, recv := inbound_alias_process(f, node)
			assert(recv.kind == .None && event.message != nil)
			defer wa.socket_message_destroy(event.message)
			m := event.message
			testing.expect_value(
				t,
				wa.socket_complete_private_audio(&f.socket, m, "555@lid").kind,
				.Invalid_Config,
			)
			if capture {
				for _ in 0 ..< 2 {
					testing.expect_value(
						t,
						wa.socket_complete_private_audio(&f.socket, m, chat).kind,
						.None,
					)
				}
			} else {
				testing.expect_value(t, wa.socket_message_complete(&f.socket, m).kind, .None)
			}
			replay, e := inbound_alias_process(f, node)
			testing.expect(t, replay.kind == .None && e.kind == .None)
		}
		identity := f.store.identity
		wa.state_store_clear(&f.store)
		assert(wa.state_store_load(&f.store, f.path, identity).kind == .None)
		retained := 0
		for record in f.store.records {
			if record.kind == .Private_Audio {
				retained += 1
			}
			testing.expect(t, record.kind != .Inbox_Message)
		}
		testing.expect_value(t, retained, 2 if capture else 0)
		for id, i in ids {
			m, e := wa.load_private_audio(&f.store, alias, id)
			assert(e.kind == .None)
			if !capture {
				testing.expect(t, m == nil); continue
			}
			assert(m != nil)
			defer wa.socket_message_destroy(m)
			testing.expect(t, m.id == id && m.timestamp == u64(103 + i))
			state := test_fixtures.Download_State {
				encrypted = test_fixtures.codec_api_hex(
					test_fixtures.VOICE_1_CIPHER if i == 0 else test_fixtures.VOICE_2_CIPHER,
				),
			}
			context.user_ptr = &state
			f.socket.phase = .Online
			f.socket.config.http_execute = test_fixtures.download_http
			dst: [64]u8
			n, download := wa.socket_download_media(&f.socket, m, dst[:])
			testing.expect(
				t,
				download.kind == .None &&
				string(dst[:n]) ==
					("OggS synthetic voice 1" if i == 0 else "OggS synthetic voice 2"),
			)
		}
	}
}

@(test)
private_audio_capture_evicts_oldest_and_preserves_inbox_on_save_failure :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)
	chat :: "111@s.whatsapp.net"
	m := wa.Socket_Message {
		participant = chat,
		protobuf    = test_fixtures.codec_api_hex(test_fixtures.VOICE_1_PROTO),
	}
	for i in 0 ..= wa.MAX_CAPTURED_PRIVATE_AUDIO {
		id := fmt.aprintf("synthetic-%d", i)
		defer delete(id)
		m.id, m.timestamp = id, u64(100 + i)
		key, ke := wa.socket_inbox_key(&f.socket, "", chat, id)
		assert(ke.kind == .None)
		defer delete(key)
		assert(wa.socket_inbox_stage(&f.store, key, &m).kind == .None)
		if i == wa.MAX_CAPTURED_PRIVATE_AUDIO {
			f.socket.config.state_path = ""
			testing.expect(t, wa.socket_complete_private_audio(&f.socket, &m, chat).kind != .None)
			_, pending := wa.state_store_get(&f.store, .Inbox_Message, key)
			_, first := wa.state_store_get(
				&f.store,
				.Private_Audio,
				"111@s.whatsapp.net|synthetic-0",
			)
			testing.expect(t, pending && first)
			f.socket.config.state_path = f.path
		}
		assert(wa.socket_complete_private_audio(&f.socket, &m, chat).kind == .None)
	}
	retained := 0
	for record in f.store.records {
		if record.kind == .Private_Audio {
			retained += 1
		}
	}
	oldest, e := wa.load_private_audio(&f.store, chat, "synthetic-0")
	testing.expect(
		t,
		e.kind == .None && oldest == nil && retained == wa.MAX_CAPTURED_PRIVATE_AUDIO,
	)
}

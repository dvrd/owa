package whatsapp

import "core:bytes"
import "core:testing"

// These maps qualify the existing bounded ACK policy, not a server acceptance
// contract. The independent implementations disagree on normal type/local from;
// see docs/message-ack-contract-20261113.md before changing that policy.
Message_Ack_Vector :: struct {
	attrs, expected: []Binary_Node_Attribute,
	unavailable: bool,
	error_code: u32,
	local: string,
}

message_ack_expect :: proc(t: ^testing.T, wire: ^Send_Id_Wire,
	expected: []Binary_Node_Attribute) {
	testing.expect(t, wire.used > 0)
	if wire.used == 0 {return}
	plain: [2048]u8
	encoded := send_id_wire_plain(wire, plain[:])
	doc, error := binary_node_decode(transmute([]u8)encoded)
	assert(error.kind == .None); defer binary_document_destroy(&doc)
	testing.expect_value(t, doc.root.tag, "ack")
	testing.expect_value(t, len(doc.root.attrs), len(expected))
	for attr in expected {
		value, found := node_attr(doc.root, attr.key)
		testing.expect(t, found && value == attr.value)
	}
}

message_ack_vector :: proc(t: ^testing.T, vector: Message_Ack_Vector) {
	f := negative_ack_fixture(); defer negative_ack_destroy(f)
	copy(f.auth.account.jid[:], vector.local); f.auth.account.jid_size = len(vector.local)
	wire: Send_Id_Wire
	send_id_wire_connect(&f.socket, &wire); defer socket_close(&f.socket)
	before := negative_ack_disk(f); defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	children := [1]Binary_Node{{tag = "unavailable"}}
	node := Binary_Node{tag = "message", attrs = vector.attrs}
	if vector.unavailable {node.content = children[:]}
	buffer: [2048]u8
	count, encoded := binary_node_encode(buffer[:], node); assert(encoded.kind == .None)
	doc, decoded := binary_node_decode(buffer[:count]); assert(decoded.kind == .None)
	error := socket_acknowledge(&f.socket, doc.root, vector.error_code)
	binary_document_destroy(&doc)
	for &value in buffer {value = 0xa5}
	testing.expect_value(t, error.kind, .None)
	message_ack_expect(t, &wire, vector.expected)
	testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
	ack_routing_unchanged(t, f, before, revision, durable)
}

@(test)
message_ack_normal_policy_uses_exact_encrypted_maps_after_document_release :: proc(t: ^testing.T) {
	for local in ([]string{"", "111:1@s.whatsapp.net"}) {
		for optional in ([]([]Binary_Node_Attribute){
			{}, {{"type", "text"}}, {{"type", ""}},
		}) {
			attrs := [3]Binary_Node_Attribute{{"id", "synthetic-ack-id"},
				{"from", "222@s.whatsapp.net"}, {}}
			count := 2
			if len(optional) > 0 {attrs[2] = optional[0]; count = 3}
			message_ack_vector(t, {attrs = attrs[:count], local = local,
				expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"},
					{"class", "message"}}})
		}
	}
}

@(test)
message_ack_optional_participant_and_recipient_preserve_presence :: proc(t: ^testing.T) {
	for participant in ([]string{"333:4@s.whatsapp.net", ""}) {
		for recipient in ([]string{"444@s.whatsapp.net", ""}) {
			message_ack_vector(t, {
				attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"},
					{"type", "media"}, {"participant", participant}, {"recipient", recipient}},
				expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"},
					{"class", "message"}, {"participant", participant}, {"recipient", recipient}},
			})
		}
	}
}

@(test)
message_ack_unavailable_and_error_maps_remain_separate_legacy_policies :: proc(t: ^testing.T) {
	for kind in ([]string{"text", ""}) {
		message_ack_vector(t, {
			attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}, {"type", kind}},
			unavailable = true, local = "111:1@s.whatsapp.net",
			expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"},
				{"class", "message"}, {"type", kind}, {"from", "111:1@s.whatsapp.net"}},
		})
		message_ack_vector(t, {
			attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}, {"type", kind}},
			error_code = 487, local = "111:1@s.whatsapp.net",
			expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"},
				{"class", "message"}, {"type", kind}, {"error", "487"}},
		})
	}
	// No local identity is an artificial private-helper state, not paired support.
	message_ack_vector(t, {
		attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}},
		unavailable = true,
		expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"},
			{"class", "message"}, {"from", ""}},
	})
	message_ack_vector(t, {
		attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}}, error_code = 487,
		expected = {{"id", "synthetic-ack-id"}, {"to", "222@s.whatsapp.net"},
			{"class", "message"}, {"error", "487"}},
	})
}

@(test)
message_ack_missing_or_empty_mandatory_attrs_do_not_write :: proc(t: ^testing.T) {
	for attrs in ([]([]Binary_Node_Attribute){
		{{"from", "222@s.whatsapp.net"}}, {{"id", "synthetic-ack-id"}},
		{{"id", ""}, {"from", "222@s.whatsapp.net"}},
		{{"id", "synthetic-ack-id"}, {"from", ""}},
	}) {
		f := negative_ack_fixture(); defer negative_ack_destroy(f)
		wire: Send_Id_Wire
		send_id_wire_connect(&f.socket, &wire); defer socket_close(&f.socket)
		before := negative_ack_disk(f); defer delete(before)
		revision, durable := f.store.revision, f.store.durable_revision
		error := socket_acknowledge(&f.socket, {tag = "message", attrs = attrs})
		testing.expect_value(t, error.kind, .Protocol_Error)
		testing.expect_value(t, wire.used, 0)
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(0))
		ack_routing_unchanged(t, f, before, revision, durable)
	}
}

@(test)
message_ack_write_failure_does_not_mutate_or_replay_intent :: proc(t: ^testing.T) {
	f := negative_ack_fixture(); defer negative_ack_destroy(f)
	wire: Send_Id_Wire
	send_id_wire_connect(&f.socket, &wire); defer socket_close(&f.socket)
	f.socket.websocket.stream.write = status_ack_failed_write
	before := negative_ack_disk(f); defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	error := socket_acknowledge(&f.socket, {tag = "message",
		attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}}})
	testing.expect_value(t, error.kind, .Session_Failed)
	testing.expect_value(t, f.socket.phase, .Failed)
	testing.expect_value(t, wire.used, 0)
	ack_routing_unchanged(t, f, before, revision, durable)
	after := negative_ack_disk(f); defer delete(after)
	testing.expect(t, bytes.equal(before, after))
}

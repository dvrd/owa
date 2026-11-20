package whatsapp

import "core:bytes"
import "core:testing"
import surf "shared:surf"

unsupported_enc_cipher := [1]u8{1}
unsupported_enc_node :: proc(kind: string, mixed, reverse, group: bool) -> Binary_Node {
	node := Binary_Node {
		tag = "message",
	}

	node.attrs = make([]Binary_Node_Attribute, group ? 4 : 3)

	if group {
		copy(
			node.attrs,
			[]Binary_Node_Attribute {
				{"id", "unsupported-content-id"},
				{"from", "123@g.us"},
				{"participant", "222:4@s.whatsapp.net"},
				{"type", "text"},
			},
		)
	} else {
		copy(
			node.attrs,
			[]Binary_Node_Attribute {
				{"id", "unsupported-content-id"},
				{"from", "222@s.whatsapp.net"},
				{"type", "text"},
			},
		)
	}

	children := make([]Binary_Node, mixed ? 2 : 1)
	unknown := mixed && reverse ? 1 : 0

	for &child, i in children {
		child.tag = "enc"
		child.attrs = make([]Binary_Node_Attribute, 1)
		child.attrs[0] = {"type", i == unknown ? kind : "pkmsg"}
		child.content = unsupported_enc_cipher[:]
	}

	node.content = children

	return node
}
unsupported_enc_node_destroy :: proc(node: Binary_Node) {
	children := node.content.([]Binary_Node)

	for child in children {
		delete(child.attrs)
	}

	delete(children)
	delete(node.attrs)
}

unsupported_enc_case :: proc(t: ^testing.T, kind: string, mixed, reverse, group: bool) {
	f := negative_ack_fixture()
	defer negative_ack_destroy(f)
	before := negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	node := unsupported_enc_node(kind, mixed, reverse, group)
	defer unsupported_enc_node_destroy(node)
	// Reopen the actual durable state before each replay. Unsupported content
	// must not become a deduplicated success after reconnect.
	for _ in 0 ..< 3 {
		restored: State_Store
		assert(state_store_load(&restored, f.path, f.store.identity).kind == .None)
		state_store_clear(&f.store)
		f.store = restored
		f.socket.phase = .Online
		wire: Send_Id_Wire
		send_id_wire_connect(&f.socket, &wire)
		event, error := socket_process_node(&f.socket, node)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
		testing.expect_value(t, len(f.socket.deferred_retries), 0)
		negative_ack_unchanged(t, f, before, revision, durable)

		if wire.used > 0 && f.socket.client.noise.write_counter == 1 {
			plain: [2048]u8
			encoded := send_id_wire_plain(&wire, plain[:])
			doc, decoded := binary_node_decode(transmute([]u8)encoded)
			assert(decoded.kind == .None)
			testing.expect_value(t, doc.root.tag, "ack")
			code, found := node_attr(doc.root, "error")
			testing.expect(t, found)
			testing.expect_value(t, code, kind == "msmsg" ? "495" : "490")
			id, _ := node_attr(doc.root, "id")
			testing.expect_value(t, id, "unsupported-content-id")
			binary_document_destroy(&doc)
		} else {
			testing.expect(t, false, "exactly one negative ACK required")
		}

		socket_close(&f.socket)
	}

	after := negative_ack_disk(f)
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
	f := negative_ack_fixture()
	defer negative_ack_destroy(f)
	before := negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	wire: Send_Id_Wire
	send_id_wire_connect(&f.socket, &wire)
	defer socket_close(&f.socket)
	f.socket.websocket.stream.write = unsupported_enc_write_fail
	node := unsupported_enc_node("msmsg", false, false, false)
	defer unsupported_enc_node_destroy(node)
	event, error := socket_process_node(&f.socket, node)
	testing.expect(t, error.kind != .None)
	testing.expect_value(t, event.kind, .None)
	testing.expect_value(t, len(f.socket.deferred_retries), 0)
	// A write failure may fail the transport; durable content must remain exact.
	testing.expect_value(t, f.store.revision, revision)
	testing.expect_value(t, f.store.durable_revision, durable)
	after := negative_ack_disk(f)
	defer delete(after)
	testing.expect(t, bytes.equal(before, after))
}

@(test)
unsupported_encryption_keeps_supported_distribution_order_and_controls_admissible :: proc(t: ^testing.T) {
	// Preflight must leave both packet orders for the existing two-pass Signal
	// decoder, and leave non-encrypted controls to their existing handler.
	supported := [3]Binary_Node {
		{tag = "enc", attrs = {{"type", "skmsg"}}},
		{tag = "enc", attrs = {{"type", "pkmsg"}}},
		{tag = "enc", attrs = {{"type", "msg"}}},
	}

	testing.expect_value(t, message_encryption_nack_reason({content = supported[:]}), u32(0))
	supported[0], supported[2] = supported[2], supported[0]
	testing.expect_value(t, message_encryption_nack_reason({content = supported[:]}), u32(0))
	controls := [1]Binary_Node{{tag = "unavailable"}}
	testing.expect_value(t, message_encryption_nack_reason({content = controls[:]}), u32(0))
}

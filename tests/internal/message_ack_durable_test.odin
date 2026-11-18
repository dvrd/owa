package whatsapp

import surf "shared:surf"
import ws "shared:websocket"
import "core:bytes"
import "core:fmt"
import "core:testing"

Message_Ack_Durable_Writer :: struct {
	fixture:      ^Negative_Ack_Fixture,
	name:         string,
	wire:         Send_Id_Wire,
	observations: int,
	fail_ack:     bool,
}

message_ack_durable_write :: proc(data: rawptr, source: []u8) -> (int, surf.WebSocket_Stream_Error) {
	capture := cast(^Message_Ack_Durable_Writer)data
	restored: State_Store
	defer state_store_clear(&restored)
	f := capture.fixture
	assert(state_store_load(&restored, f.path, f.store.identity).kind == .None)
	_, inbox := state_store_get(&restored, .Inbox_Message, capture.name)
	_, processed := state_store_get(&restored, .Processed_Message, capture.name)
	assert(inbox && !processed && restored.revision == restored.durable_revision)
	capture.observations += 1

	if capture.fail_ack && f.socket.client.noise.write_counter == 2 {
		return 0, {kind = .No_Progress}
	}

	return send_id_wire_write(&capture.wire, source)
}

message_ack_event_stage :: proc(f: ^Negative_Ack_Fixture, node: Binary_Node) -> (Socket_Event, Socket_Error) {
	candidate: State_Store
	defer state_store_clear(&candidate)
	assert(socket_store_clone(&candidate, &f.store).kind == .None)
	name, error := socket_inbox_key(&f.socket, "", "222@s.whatsapp.net", "synthetic-ack-id")
	assert(error.kind == .None)
	defer delete(name)

	return socket_message_event_commit(
		&f.socket,
		&candidate,
		node,
		name,
		"",
		"222@s.whatsapp.net",
		"synthetic-ack-id",
		[]u8{10, 3, 'a', 'c', 'k'},
		false,
	)
}

message_ack_expect_frames :: proc(t: ^testing.T, wire: ^Send_Id_Wire, have_ack: bool) {
	peer := Noise_State {
		phase = .Transport,
	}

	defer noise_clear(&peer)
	offset, frames := 0, 0

	for _ in 0 ..< 3 {
		if offset == wire.used {
			break
		}

		header, size, error := ws.frame_header_decode(wire.data[offset:wire.used], true)
		assert(error == .None && header.payload_length <= u64(wire.used - offset - size))
		end := offset + size + int(header.payload_length)
		payload := wire.data[offset + size:end]
		ws.mask_payload(payload, header.masking_key)
		encrypted, consumed, frame_error := frame_decode(payload)
		assert(frame_error == .None && consumed == len(payload))
		plain: [2048]u8
		count, decrypted := noise_decrypt(&peer, plain[:], encrypted)
		assert(decrypted == .None)
		doc, decoded := binary_node_decode(plain[:count])
		assert(decoded.kind == .None)
		defer binary_document_destroy(&doc)
		testing.expect_value(t, doc.root.tag, frames == 0 ? "receipt" : "ack")
		kind, _ := node_attr(doc.root, "type")
		testing.expect(t, kind != "read" && kind != "viewed")

		if frames == 1 {
			testing.expect_value(t, len(doc.root.attrs), 3)

			for attr in ([]Binary_Node_Attribute {
					{"id", "synthetic-ack-id"},
					{"to", "222@s.whatsapp.net"},
					{"class", "message"},
				}) {
				value, found := node_attr(doc.root, attr.key)
				testing.expect(t, found && value == attr.value)
			}
		}

		offset = end
		frames += 1
	}

	testing.expect_value(t, offset, wire.used)
	testing.expect_value(t, frames, have_ack ? 2 : 1)
}

message_ack_reopen_and_complete :: proc(t: ^testing.T, f: ^Negative_Ack_Fixture, name: string) {
	restored: State_Store
	defer state_store_clear(&restored)
	assert(state_store_load(&restored, f.path, f.store.identity).kind == .None)
	reopened := Socket {
		phase = .Online,
		auth = &f.auth,
		store = &restored,
		prekeys = &f.prekeys,
		config = {state_path = f.path},
	}

	defer socket_close(&reopened)
	assert(socket_inbox_restore(&reopened).kind == .None)
	testing.expect_value(t, len(reopened.queue), 1)

	if len(reopened.queue) != 1 {
		return
	}

	event, error := socket_read(&reopened)
	assert(error.kind == .None && event.message != nil)
	defer socket_message_destroy(event.message)
	testing.expect_value(t, event.message.id, "synthetic-ack-id")
	before := negative_ack_disk(f)
	defer delete(before)
	bad := fmt.aprintf("%s/missing/state", f.directory)
	defer delete(bad)
	reopened.config.state_path = bad
	testing.expect_value(t, socket_message_complete(&reopened, event.message).kind, .State_Failed)
	after := negative_ack_disk(f)
	defer delete(after)
	testing.expect(t, bytes.equal(before, after))
	_, inbox := state_store_get(&restored, .Inbox_Message, name)
	_, processed := state_store_get(&restored, .Processed_Message, name)
	testing.expect(t, inbox && !processed)
	reopened.config.state_path = f.path
	testing.expect_value(t, socket_message_complete(&reopened, event.message).kind, .None)
	_, inbox = state_store_get(&restored, .Inbox_Message, name)
	_, processed = state_store_get(&restored, .Processed_Message, name)
	testing.expect(t, !inbox && processed)
	testing.expect_value(t, reopened.client.noise.write_counter, u64(0))
	state_store_clear(&restored)
	assert(state_store_load(&restored, f.path, f.store.identity).kind == .None)
	assert(socket_inbox_restore(&reopened).kind == .None)
	testing.expect_value(t, len(reopened.queue), 0)
}

@(test)
message_ack_durable_inbox_precedes_wire_and_failed_ack_remains_recoverable :: proc(t: ^testing.T) {
	for fail_ack in ([]bool{false, true}) {
		f := negative_ack_fixture()
		defer negative_ack_destroy(f)
		capture := Message_Ack_Durable_Writer {
			fixture  = f,
			fail_ack = fail_ack,
		}

		send_id_wire_connect(&f.socket, &capture.wire)
		defer socket_close(&f.socket)
		f.socket.websocket.stream.data = &capture
		f.socket.websocket.stream.write = message_ack_durable_write
		name, key_error := socket_inbox_key(&f.socket, "", "222@s.whatsapp.net", "synthetic-ack-id")
		assert(key_error.kind == .None)
		defer delete(name)
		capture.name = name
		node := Binary_Node {
			tag   = "message",
			attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}, {"type", "text"}},
		}

		event, stage_error := message_ack_event_stage(f, node)
		assert(stage_error.kind == .None && event.message != nil)
		error := socket_message_receipts_send(&f.socket, node, event, false)
		testing.expect_value(t, error.kind, fail_ack ? Socket_Error_Kind.Session_Failed : Socket_Error_Kind.None)

		if !fail_ack {
			socket_message_destroy(event.message)
		}

		testing.expect(t, capture.observations >= 2)
		message_ack_expect_frames(t, &capture.wire, !fail_ack)
		message_ack_reopen_and_complete(t, f, name)
		testing.expect_value(t, send_id_http_calls, 0)
	}
}

@(test)
message_ack_failed_inbox_commit_exposes_no_event_or_wire :: proc(t: ^testing.T) {
	f := negative_ack_fixture()
	defer negative_ack_destroy(f)
	wire: Send_Id_Wire
	send_id_wire_connect(&f.socket, &wire)
	defer socket_close(&f.socket)
	before := negative_ack_disk(f)
	defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	bad := fmt.aprintf("%s/missing/state", f.directory)
	defer delete(bad)
	f.socket.config.state_path = bad
	event, error := message_ack_event_stage(f, {})
	testing.expect_value(t, error.kind, .State_Failed)
	testing.expect(t, event.message == nil && event.kind == .None)
	testing.expect_value(t, wire.used, 0)
	testing.expect_value(t, f.socket.client.noise.write_counter, u64(0))
	ack_routing_unchanged(t, f, before, revision, durable)
}

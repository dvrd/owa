package whatsapp

import network_client "../surf"
import ws "../websocket"
import "core:bytes"
import "core:testing"

// Top-level status is a transport control, distinct from message/status@broadcast.
// Capture the actual masked-WebSocket/Noise output; a viewed receipt or chat event
// must never be emitted. All addresses/content below are synthetic.
@(test)
status_ack_top_level_live_and_offline_preserves_transport_attributes :: proc(t: ^testing.T) {
	for phase in ([]Socket_Phase{.Online, .Provisioning}) {
		for kind in ([]string{"media", "text"}) {
			for offline in ([]string{"true", "false"}) {
				f := negative_ack_fixture(); defer negative_ack_destroy(f)
				before := negative_ack_disk(f); defer delete(before)
				revision, durable := f.store.revision, f.store.durable_revision
				wire: Send_Id_Wire
				send_id_wire_connect(&f.socket, &wire)
				defer frame_transport_clear(&f.socket.client.frames)
				f.socket.phase = phase
				event, error := socket_process_node(
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
				encoded := send_id_wire_plain(&wire, plain[:])
				document, binary_error := binary_node_decode(transmute([]u8)encoded)
				testing.expect_value(t, binary_error.kind, .None)
				if binary_error.kind != .None {
					continue
				}
				defer binary_document_destroy(&document)
				testing.expect_value(t, document.root.tag, "ack")
				testing.expect_value(t, len(document.root.attrs), 6)
				for expected in ([]Binary_Node_Attribute {
						{"id", "synthetic-status-id"},
						{"to", "status@broadcast"},
						{"class", "status"},
						{"type", kind},
						{"participant", "222@s.whatsapp.net"},
						{"recipient", "333:4@s.whatsapp.net"},
					}) {
					value, found := pairing_node_attr(document.root, expected.key)
					testing.expect(t, found && value == expected.value)
				}
				_, nack := pairing_node_attr(document.root, "error")
				_, offline_copied := pairing_node_attr(document.root, "offline")
				testing.expect(t, !nack && !offline_copied)
				testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
				testing.expect_value(t, f.store.revision, revision)
				testing.expect_value(t, f.store.durable_revision, durable)
				after := negative_ack_disk(f); defer delete(after)
				testing.expect(
					t,
					bytes.equal(before, after),
					"status ACK must not mutate durable chat state",
				)
			}
		}
	}
}

Status_Ack_Stream :: struct {
	input:  Negative_Ack_Stream,
	output: Send_Id_Wire,
}
status_ack_read :: proc(data: rawptr, dst: []u8) -> (int, network_client.WebSocket_Stream_Error) {
	stream := cast(^Status_Ack_Stream)data
	return negative_ack_stream_read(&stream.input, dst)
}
status_ack_write :: proc(data: rawptr, src: []u8) -> (int, network_client.WebSocket_Stream_Error) {
	stream := cast(^Status_Ack_Stream)data
	return send_id_wire_write(&stream.output, src)
}

status_ack_encrypted_input :: proc(f: ^Negative_Ack_Fixture, stream: ^Status_Ack_Stream) {
	encoded, ciphertext, envelope: [1024]u8
	size, error := binary_node_encode(
		encoded[:],
		{
			tag = "status",
			attrs = {
				{"id", "synthetic-offline-status"},
				{"from", "status@broadcast"},
				{"type", "media"},
				{"offline", "true"},
			},
		},
	)
	assert(error.kind == .None)
	peer := Noise_State {
		phase = .Transport,
	}; defer noise_clear(&peer)
	encrypted_size, encrypted := noise_encrypt(&peer, ciphertext[:], encoded[:size])
	assert(encrypted == .None)
	envelope_size, framed := frame_encode(envelope[:], ciphertext[:encrypted_size])
	assert(framed == .None)
	frame_size, websocket_error := ws.frame_encode(
		stream.input.input[:],
		true,
		.Binary,
		envelope[:envelope_size],
		{},
		masked = false,
	)
	assert(websocket_error == .None); stream.input.size = frame_size
	send_id_wire_connect(&f.socket, &stream.output)
	f.socket.websocket.stream = {
		data  = stream,
		read  = status_ack_read,
		write = status_ack_write,
		close = negative_ack_stream_close,
	}
	f.socket.session = {
		phase  = .Login_Accepted,
		client = &f.socket.client,
		auth   = &f.auth,
	}
}

@(test)
status_ack_encrypted_socket_read_handles_provisioning_offline_batch :: proc(t: ^testing.T) {
	for phase in ([]Socket_Phase{.Online, .Provisioning}) {
		f := negative_ack_fixture(); defer negative_ack_destroy(f)
		stream: Status_Ack_Stream
		status_ack_encrypted_input(f, &stream)
		defer socket_close(&f.socket)
		f.socket.phase = phase
		before := negative_ack_disk(f); defer delete(before)
		event, error := socket_read(&f.socket)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, f.socket.phase, phase)
		testing.expect_value(t, f.socket.client.noise.read_counter, u64(1))
		testing.expect(
			t,
			stream.output.used > 0,
			"offline status must reach the ACK handler before activation",
		)
		if stream.output.used == 0 {
			continue
		}
		plain: [2048]u8
		encoded := send_id_wire_plain(&stream.output, plain[:])
		document, decode := binary_node_decode(transmute([]u8)encoded)
		assert(decode.kind == .None)
		defer binary_document_destroy(&document)
		class, class_found := pairing_node_attr(document.root, "class")
		testing.expect(t, document.root.tag == "ack" && class_found && class == "status")
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
		after := negative_ack_disk(f); defer delete(after)
		testing.expect(t, bytes.equal(before, after))
	}
}

@(test)
status_ack_malformed_envelopes_fail_without_output_or_store_changes :: proc(t: ^testing.T) {
	f := negative_ack_fixture(); defer negative_ack_destroy(f)
	wire: Send_Id_Wire
	send_id_wire_connect(&f.socket, &wire); defer frame_transport_clear(&f.socket.client.frames)
	before := negative_ack_disk(f); defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	for attrs in ([]([]Binary_Node_Attribute) {
			{{"from", "status@broadcast"}},
			{{"id", "synthetic-id"}},
			{{"id", ""}, {"from", "status@broadcast"}},
			{{"id", "synthetic-id"}, {"from", ""}},
		}) {
		event, error := socket_process_node(&f.socket, {tag = "status", attrs = attrs})
		testing.expect_value(t, error.kind, .Protocol_Error)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, wire.used, 0)
		negative_ack_unchanged(t, f, before, revision, durable)
	}
}

status_ack_failed_write :: proc(
	_: rawptr,
	_: []u8,
) -> (
	int,
	network_client.WebSocket_Stream_Error,
) {
	return 0, {kind = .No_Progress}
}

@(test)
status_ack_write_failure_is_propagated_without_chat_state_commit :: proc(t: ^testing.T) {
	f := negative_ack_fixture(); defer negative_ack_destroy(f)
	wire: Send_Id_Wire
	send_id_wire_connect(&f.socket, &wire); defer socket_close(&f.socket)
	f.socket.websocket.stream.write = status_ack_failed_write
	before := negative_ack_disk(f); defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	event, error := socket_process_node(
		&f.socket,
		{tag = "status", attrs = {{"id", "synthetic-id"}, {"from", "status@broadcast"}}},
	)
	testing.expect_value(t, error.kind, .Session_Failed)
	testing.expect_value(t, error.session.kind, .Client_Failed)
	testing.expect_value(t, event.kind, .None)
	testing.expect_value(t, f.socket.phase, .Failed)
	testing.expect_value(t, f.store.revision, revision)
	testing.expect_value(t, f.store.durable_revision, durable)
	after := negative_ack_disk(f); defer delete(after)
	testing.expect(t, bytes.equal(before, after))
}

@(test)
status_ack_legacy_broadcast_message_remains_transport_only :: proc(t: ^testing.T) {
	f := negative_ack_fixture(); defer negative_ack_destroy(f)
	wire: Send_Id_Wire
	send_id_wire_connect(&f.socket, &wire); defer frame_transport_clear(&f.socket.client.frames)
	before := negative_ack_disk(f); defer delete(before)
	revision, durable := f.store.revision, f.store.durable_revision
	event, error := socket_process_node(
		&f.socket,
		{
			tag = "message",
			attrs = {
				{"id", "synthetic-legacy-id"},
				{"from", "status@broadcast"},
				{"type", "media"},
			},
		},
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, event.kind, .None)
	plain: [2048]u8
	encoded := send_id_wire_plain(&wire, plain[:])
	document, decode := binary_node_decode(transmute([]u8)encoded); assert(decode.kind == .None)
	defer binary_document_destroy(&document)
	class, found := pairing_node_attr(document.root, "class")
	testing.expect(t, document.root.tag == "ack" && found && class == "message")
	_, viewed_type := pairing_node_attr(document.root, "type")
	_, nack := pairing_node_attr(document.root, "error")
	testing.expect(t, !viewed_type && !nack)
	testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
	negative_ack_unchanged(t, f, before, revision, durable)
}

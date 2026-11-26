package whatsapp_test

import test_fixtures "../../fixtures/client"
import "core:bytes"
import "core:fmt"
import "core:testing"
import "core:time"
import "shared:surf"
import ws "shared:websocket"
import wa "shared:whatsapp"

// These are ACKs of received stanzas, not read/view receipts, call acceptance or
// application delivery effects. All traffic below stays in synthetic fixtures.
ack_routing_input :: proc(f: ^test_fixtures.Negative_Ack_Fixture, stream: ^Status_Ack_Stream, node: wa.Binary_Node) {
	encoded, ciphertext, envelope: [2048]u8
	count, error := wa.binary_node_encode(encoded[:], node)
	assert(error.kind == .None)
	peer := wa.Noise_State {
		phase = .Transport,
	}

	defer wa.noise_clear(&peer)

	encrypted, noise_error := wa.noise_encrypt(&peer, ciphertext[:], encoded[:count])
	assert(noise_error == .None)
	framed, frame_error := wa.frame_encode(envelope[:], ciphertext[:encrypted])
	assert(frame_error == .None)
	size, websocket_error := ws.frame_encode(
		stream.input.input[:],
		true,
		.Binary,
		envelope[:framed],
		{},
		masked = false,
	)
	assert(websocket_error == .None)
	stream.input.size = size
	test_fixtures.send_id_wire_connect(&f.socket, &stream.output)
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

ack_routing_stage :: proc(socket: ^wa.Socket, stage: int) {
	assert(stage >= 0 && stage < 4)
	socket.phase = stage == 3 ? .Online : .Provisioning

	switch stage {
	case 0:
		socket.provision_stage = .Count
	case 1:
		socket.provision_stage = .Upload
	case 2:
		socket.provision_stage = .Active
	case 3:
		socket.provision_stage = .None
	}
}

ack_routing_expect_exact :: proc(t: ^testing.T, f: ^test_fixtures.Negative_Ack_Fixture, wire: ^test_fixtures.Send_Id_Wire, tag, kind: string) {
	testing.expect(t, wire.used > 0, "mandatory stanza ACK must be written")

	if wire.used == 0 {
		return
	}

	// This decoder asserts exactly one WebSocket/Noise envelope, not a prefix.
	plain: [2048]u8
	encoded := test_fixtures.send_id_wire_plain(wire, plain[:])
	document, error := wa.binary_node_decode(transmute([]u8)encoded)
	assert(error.kind == .None)
	defer wa.binary_document_destroy(&document)

	testing.expect_value(t, document.root.tag, "ack")

	for expected in ([]wa.Binary_Node_Attribute {
			{"id", "synthetic-routing-id"},
			{"to", "222@s.whatsapp.net"},
			{"class", tag},
			{"participant", "333:4@s.whatsapp.net"},
			{"recipient", "444@s.whatsapp.net"},
		}) {
		value, found := wa.node_attr(document.root, expected.key)
		testing.expect(t, found && value == expected.value)
	}

	actual, typed := wa.node_attr(document.root, "type")
	testing.expect(t, typed == (kind != "") && actual == kind)
	testing.expect_value(t, len(document.root.attrs), kind == "" ? 5 : 6)
	_, has_error := wa.node_attr(document.root, "error")
	_, has_offline := wa.node_attr(document.root, "offline")
	testing.expect(t, !has_error && !has_offline)
	testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
	testing.expect_value(t, test_fixtures.send_id_http_calls, 0)
}

ack_routing_encrypted_case :: proc(t: ^testing.T, tag, kind: string, stage: int) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)

	attrs := [7]wa.Binary_Node_Attribute {
		{"id", "synthetic-routing-id"},
		{"from", "222@s.whatsapp.net"},
		{"participant", "333:4@s.whatsapp.net"},
		{"recipient", "444@s.whatsapp.net"},
		{"offline", "true"},
		{"type", kind},
		{},
	}

	count := kind == "" ? 5 : 6
	stream: Status_Ack_Stream
	ack_routing_input(f, &stream, test_fixtures.ack_routing_node(tag, kind, attrs[:count]))
	defer wa.socket_close(&f.socket)

	ack_routing_stage(&f.socket, stage)
	phase, provision := f.socket.phase, f.socket.provision_stage
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)

	revision, durable := f.store.revision, f.store.durable_revision
	event, error := wa.socket_read(&f.socket)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, f.socket.phase, phase)
	testing.expect_value(t, f.socket.provision_stage, provision)
	testing.expect_value(t, f.socket.client.noise.read_counter, u64(1))
	testing.expect(t, event.message == nil)
	// Keep the previously visible call node available to specialized waiters.
	testing.expect_value(t, event.kind, tag == "call" ? wa.Socket_Event_Kind.Node : .None)

	if tag == "call" {
		testing.expect_value(t, event.node.tag, "call")
	}

	ack_routing_expect_exact(t, f, &stream.output, tag, kind)
	test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
}

@(test)
mandatory_receipt_ack_encrypted_provisioning_matches_online :: proc(t: ^testing.T) {
	for stage in 0 ..< 4 {
		for kind in ([]string{"", "read"}) {
			ack_routing_encrypted_case(t, "receipt", kind, stage)
		}
	}
}

@(test)
mandatory_call_ack_encrypted_preserves_call_visibility_without_answering :: proc(t: ^testing.T) {
	for stage in 0 ..< 4 {
		for kind in ([]string{"", "offer"}) {
			ack_routing_encrypted_case(t, "call", kind, stage)
		}
	}
}

ack_routing_retry_attributes := [5]wa.Binary_Node_Attribute {
	{"id", "synthetic-missing-retry"},
	{"from", "123@g.us"},
	{"type", "retry"},
	{"participant", "333:4@s.whatsapp.net"},
	{"recipient", "444@s.whatsapp.net"},
}

ack_routing_retry_children := [1]wa.Binary_Node{{tag = "retry", attrs = {{"count", "1"}}}}

ack_routing_retry_node :: proc() -> wa.Binary_Node {
	return {tag = "receipt", attrs = ack_routing_retry_attributes[:], content = ack_routing_retry_children[:]}
}

ack_routing_expect_retry_ack :: proc(t: ^testing.T, stream: ^Status_Ack_Stream) {
	testing.expect(t, stream.output.used > 0)

	if stream.output.used == 0 {
		return
	}

	plain: [2048]u8
	encoded := test_fixtures.send_id_wire_plain(&stream.output, plain[:])
	document, error := wa.binary_node_decode(transmute([]u8)encoded)
	assert(error.kind == .None)
	defer wa.binary_document_destroy(&document)

	testing.expect_value(t, document.root.tag, "ack")
	testing.expect_value(t, len(document.root.attrs), 6)

	for expected in ([]wa.Binary_Node_Attribute {
			{"id", "synthetic-missing-retry"},
			{"to", "123@g.us"},
			{"class", "receipt"},
			{"type", "retry"},
			{"participant", "333:4@s.whatsapp.net"},
			{"recipient", "444@s.whatsapp.net"},
		}) {
		value, found := wa.node_attr(document.root, expected.key)
		testing.expect(t, found && value == expected.value)
	}
}

Ack_Retry_Tick_Probe :: struct {
	reads, writes: int,
}

ack_retry_tick_read :: proc(data: rawptr, _: []u8) -> (int, surf.WebSocket_Stream_Error) {
	probe := cast(^Ack_Retry_Tick_Probe)data
	probe.reads += 1

	return 0, {kind = .EOF}
}

ack_retry_tick_write :: proc(data: rawptr, _: []u8) -> (int, surf.WebSocket_Stream_Error) {
	probe := cast(^Ack_Retry_Tick_Probe)data
	probe.writes += 1

	return 0, {kind = .No_Progress}
}

@(test)
mandatory_provisioning_retry_is_owned_until_online_and_outside_query :: proc(t: ^testing.T) {
	for initial_stage in 0 ..< 3 {
		f := test_fixtures.negative_ack_fixture()
		defer test_fixtures.negative_ack_destroy(f)

		stream: Status_Ack_Stream
		ack_routing_input(f, &stream, ack_routing_retry_node())
		defer wa.socket_close(&f.socket)

		ack_routing_stage(&f.socket, initial_stage)
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)

		revision, durable := f.store.revision, f.store.durable_revision
		event, error := wa.socket_read(&f.socket)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
		ack_routing_expect_retry_ack(t, &stream)
		testing.expect_value(t, len(f.socket.deferred_retries), 1)

		if len(f.socket.deferred_retries) != 1 {
			continue
		}

		wa.binary_document_destroy(&f.socket.session.document)
		queued := f.socket.deferred_retries[0].root
		id, found := wa.node_attr(queued, "id")
		kind, kind_found := wa.node_attr(queued, "type")
		retry, have_retry := wa.pairing_node_child(queued, "retry")
		testing.expect(t, found && id == "synthetic-missing-retry" && kind_found && kind == "retry" && have_retry)

		if have_retry {
			count, count_found := wa.node_attr(retry^, "count")
			testing.expect(t, count_found && count == "1", "queued document must own its released session bytes")
		}

		now := f.socket.session.last_received
		f.socket.session.config.keepalive_interval = time.Hour
		f.socket.session.next_ping = time.time_add(now, time.Hour)
		f.socket.last_prune = now
		probe: Ack_Retry_Tick_Probe
		f.socket.websocket.stream.data = &probe
		f.socket.websocket.stream.read = ack_retry_tick_read
		f.socket.websocket.stream.write = ack_retry_tick_write

		for stage in 0 ..< 3 {
			ack_routing_stage(&f.socket, stage)
			_, tick_error := wa.socket_tick(&f.socket, now)
			testing.expect_value(t, tick_error.kind, .None)
			testing.expect_value(t, len(f.socket.deferred_retries), 1)
			testing.expect_value(t, f.store.revision, revision)
			testing.expect_value(t, f.store.durable_revision, durable)
		}

		ack_routing_stage(&f.socket, 3)
		f.socket.query_depth = 1
		_, nested := wa.socket_tick(&f.socket, now)
		testing.expect_value(t, nested.kind, .None)
		testing.expect_value(t, len(f.socket.deferred_retries), 1)
		f.socket.query_depth = 0
		_, drained := wa.socket_tick(&f.socket, now)
		testing.expect_value(t, drained.kind, .None)
		testing.expect_value(t, len(f.socket.deferred_retries), 0)
		testing.expect_value(t, probe.reads, 0)
		testing.expect_value(t, probe.writes, 0)
		testing.expect_value(t, test_fixtures.send_id_http_calls, 0)
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
		// The referenced retained message is absent, so post-Online retry is a no-op.
		test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
	}
}

@(test)
mandatory_provisioning_retry_keeps_existing_64_bound_and_ack_order :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)

	for _ in 0 ..< 64 {
		assert(wa.socket_defer_retry(&f.socket, ack_routing_retry_node()).kind == .None)
	}

	stream: Status_Ack_Stream
	ack_routing_input(f, &stream, ack_routing_retry_node())
	defer wa.socket_close(&f.socket)

	ack_routing_stage(&f.socket, 0)
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)

	revision, durable := f.store.revision, f.store.durable_revision
	event, error := wa.socket_read(&f.socket)
	testing.expect_value(t, error.kind, .Queue_Full)
	testing.expect_value(t, event.kind, .None)
	testing.expect_value(t, len(f.socket.deferred_retries), 64)
	testing.expect_value(t, f.socket.phase, .Provisioning)
	testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
	ack_routing_expect_retry_ack(t, &stream)
	wa.binary_document_destroy(&f.socket.session.document)

	for queued in f.socket.deferred_retries {
		id, found := wa.node_attr(queued.root, "id")
		testing.expect(t, found && id == "synthetic-missing-retry")
	}

	testing.expect_value(t, test_fixtures.send_id_http_calls, 0)
	testing.expect_value(t, f.store.revision, revision)
	testing.expect_value(t, f.store.durable_revision, durable)
	after := test_fixtures.negative_ack_disk(f)
	defer delete(after)

	testing.expect(t, bytes.equal(before, after))
}

Message_Ack_Durable_Writer :: struct {
	fixture:      ^test_fixtures.Negative_Ack_Fixture,
	name:         string,
	wire:         test_fixtures.Send_Id_Wire,
	observations: int,
	fail_ack:     bool,
}

message_ack_durable_write :: proc(data: rawptr, source: []u8) -> (int, surf.WebSocket_Stream_Error) {
	capture := cast(^Message_Ack_Durable_Writer)data
	restored: wa.State_Store
	defer wa.state_store_clear(&restored)

	f := capture.fixture
	assert(wa.state_store_load(&restored, f.path, f.store.identity).kind == .None)
	_, inbox := wa.state_store_get(&restored, .Inbox_Message, capture.name)
	_, processed := wa.state_store_get(&restored, .Processed_Message, capture.name)
	assert(inbox && !processed && restored.revision == restored.durable_revision)
	capture.observations += 1

	if capture.fail_ack && f.socket.client.noise.write_counter == 2 {
		return 0, {kind = .No_Progress}
	}

	return test_fixtures.send_id_wire_write(&capture.wire, source)
}

message_ack_event_stage :: proc(f: ^test_fixtures.Negative_Ack_Fixture, node: wa.Binary_Node) -> (wa.Socket_Event, wa.Socket_Error) {
	candidate: wa.State_Store
	defer wa.state_store_clear(&candidate)

	assert(wa.socket_store_clone(&candidate, &f.store).kind == .None)
	name, error := wa.socket_inbox_key(&f.socket, "", "222@s.whatsapp.net", "synthetic-ack-id")
	assert(error.kind == .None)
	defer delete(name)

	return wa.socket_message_event_commit(
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

message_ack_expect_frames :: proc(t: ^testing.T, wire: ^test_fixtures.Send_Id_Wire, have_ack: bool) {
	peer := wa.Noise_State {
		phase = .Transport,
	}

	defer wa.noise_clear(&peer)

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
		encrypted, consumed, frame_error := wa.frame_decode(payload)
		assert(frame_error == .None && consumed == len(payload))
		plain: [2048]u8
		count, decrypted := wa.noise_decrypt(&peer, plain[:], encrypted)
		assert(decrypted == .None)
		doc, decoded := wa.binary_node_decode(plain[:count])
		assert(decoded.kind == .None)
		defer wa.binary_document_destroy(&doc)

		testing.expect_value(t, doc.root.tag, frames == 0 ? "receipt" : "ack")
		kind, _ := wa.node_attr(doc.root, "type")
		testing.expect(t, kind != "read" && kind != "viewed")

		if frames == 1 {
			testing.expect_value(t, len(doc.root.attrs), 3)

			for attr in ([]wa.Binary_Node_Attribute {
					{"id", "synthetic-ack-id"},
					{"to", "222@s.whatsapp.net"},
					{"class", "message"},
				}) {
				value, found := wa.node_attr(doc.root, attr.key)
				testing.expect(t, found && value == attr.value)
			}
		}

		offset = end
		frames += 1
	}

	testing.expect_value(t, offset, wire.used)
	testing.expect_value(t, frames, have_ack ? 2 : 1)
}

message_ack_reopen_and_complete :: proc(t: ^testing.T, f: ^test_fixtures.Negative_Ack_Fixture, name: string) {
	restored: wa.State_Store
	defer wa.state_store_clear(&restored)

	assert(wa.state_store_load(&restored, f.path, f.store.identity).kind == .None)
	reopened := wa.Socket {
		phase = .Online,
		auth = &f.auth,
		store = &restored,
		prekeys = &f.prekeys,
		config = {state_path = f.path},
	}

	defer wa.socket_close(&reopened)

	assert(wa.socket_inbox_restore(&reopened).kind == .None)
	testing.expect_value(t, len(reopened.queue), 1)

	if len(reopened.queue) != 1 {
		return
	}

	event, error := wa.socket_read(&reopened)
	assert(error.kind == .None && event.message != nil)
	defer wa.socket_message_destroy(event.message)

	testing.expect_value(t, event.message.id, "synthetic-ack-id")
	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)

	bad := fmt.aprintf("%s/missing/state", f.directory)
	defer delete(bad)

	reopened.config.state_path = bad
	testing.expect_value(t, wa.socket_message_complete(&reopened, event.message).kind, .State_Failed)
	after := test_fixtures.negative_ack_disk(f)
	defer delete(after)

	testing.expect(t, bytes.equal(before, after))
	_, inbox := wa.state_store_get(&restored, .Inbox_Message, name)
	_, processed := wa.state_store_get(&restored, .Processed_Message, name)
	testing.expect(t, inbox && !processed)
	reopened.config.state_path = f.path
	testing.expect_value(t, wa.socket_message_complete(&reopened, event.message).kind, .None)
	_, inbox = wa.state_store_get(&restored, .Inbox_Message, name)
	_, processed = wa.state_store_get(&restored, .Processed_Message, name)
	testing.expect(t, !inbox && processed)
	testing.expect_value(t, reopened.client.noise.write_counter, u64(0))
	wa.state_store_clear(&restored)
	assert(wa.state_store_load(&restored, f.path, f.store.identity).kind == .None)
	assert(wa.socket_inbox_restore(&reopened).kind == .None)
	testing.expect_value(t, len(reopened.queue), 0)
}

@(test)
message_ack_durable_inbox_precedes_wire_and_failed_ack_remains_recoverable :: proc(t: ^testing.T) {
	for fail_ack in ([]bool{false, true}) {
		f := test_fixtures.negative_ack_fixture()
		defer test_fixtures.negative_ack_destroy(f)

		capture := Message_Ack_Durable_Writer {
			fixture  = f,
			fail_ack = fail_ack,
		}

		test_fixtures.send_id_wire_connect(&f.socket, &capture.wire)
		defer wa.socket_close(&f.socket)

		f.socket.websocket.stream.data = &capture
		f.socket.websocket.stream.write = message_ack_durable_write
		name, key_error := wa.socket_inbox_key(&f.socket, "", "222@s.whatsapp.net", "synthetic-ack-id")
		assert(key_error.kind == .None)
		defer delete(name)

		capture.name = name
		node := wa.Binary_Node {
			tag   = "message",
			attrs = {{"id", "synthetic-ack-id"}, {"from", "222@s.whatsapp.net"}, {"type", "text"}},
		}

		event, stage_error := message_ack_event_stage(f, node)
		assert(stage_error.kind == .None && event.message != nil)
		error := wa.socket_message_receipts_send(&f.socket, node, event, false)
		testing.expect_value(t, error.kind, fail_ack ? wa.Socket_Error_Kind.Session_Failed : wa.Socket_Error_Kind.None)

		if !fail_ack {
			wa.socket_message_destroy(event.message)
		}

		testing.expect(t, capture.observations >= 2)
		message_ack_expect_frames(t, &capture.wire, !fail_ack)
		message_ack_reopen_and_complete(t, f, name)
		testing.expect_value(t, test_fixtures.send_id_http_calls, 0)
	}
}

@(test)
message_ack_failed_inbox_commit_exposes_no_event_or_wire :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)

	wire: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&f.socket, &wire)
	defer wa.socket_close(&f.socket)

	before := test_fixtures.negative_ack_disk(f)
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
	test_fixtures.ack_routing_unchanged(t, f, before, revision, durable)
}

Negative_Ack_Stream :: struct {
	input:                 [2048]u8,
	size, read_at, writes: int,
}

negative_ack_stream_read :: proc(data: rawptr, destination: []u8) -> (int, surf.WebSocket_Stream_Error) {
	stream := cast(^Negative_Ack_Stream)data
	n := min(len(destination), stream.size - stream.read_at, 3)

	if n == 0 {
		return 0, {kind = .EOF}
	}

	copy(destination[:n], stream.input[stream.read_at:][:n])
	stream.read_at += n

	return n, {}
}

negative_ack_stream_write :: proc(data: rawptr, source: []u8) -> (int, surf.WebSocket_Stream_Error) {
	stream := cast(^Negative_Ack_Stream)data
	stream.writes += 1

	return len(source), {}
}

negative_ack_stream_close :: proc(data: rawptr) -> surf.WebSocket_Stream_Error {
	return {}
}

negative_ack_encrypted_stream :: proc(f: ^test_fixtures.Negative_Ack_Fixture, stream: ^Negative_Ack_Stream) {
	encoded, ciphertext, envelope: [1024]u8
	node := wa.Binary_Node {
		tag   = "ack",
		attrs = {{"class", "message"}, {"id", "owned-id"}, {"error", "479"}},
	}

	plain_size, binary_error := wa.binary_node_encode(encoded[:], node)
	assert(binary_error.kind == .None)
	key: [32]u8

	for &byte, index in key {
		byte = u8(index + 1)
	}

	peer := wa.Noise_State {
		phase     = .Transport,
		write_key = key,
	}

	defer wa.noise_clear(&peer)

	encrypted_size, encrypted := wa.noise_encrypt(&peer, ciphertext[:], encoded[:plain_size])
	assert(encrypted == .None)
	envelope_size, framed := wa.frame_encode(envelope[:], ciphertext[:encrypted_size])
	assert(framed == .None)
	frame_size, websocket_error := ws.frame_encode(
		stream.input[:],
		true,
		.Binary,
		envelope[:envelope_size],
		{},
		masked = false,
	)
	assert(websocket_error == .None)
	stream.size = frame_size
	socket := &f.socket
	socket.websocket = {
		phase = .Open,
		allocator = context.allocator,
		config = {host = "synthetic.invalid", max_message_size = 4096},
		stream = {
			data = stream,
			read = negative_ack_stream_read,
			write = negative_ack_stream_write,
			close = negative_ack_stream_close,
		},
	}

	socket.client = {
		phase = .Noise_Ready,
		websocket = &socket.websocket,
		config = {max_frame_payload = 4096},
		noise = {phase = .Transport, read_key = key},
	}

	assert(wa.frame_transport_init(&socket.client.frames, &socket.websocket, 4096).kind == .None)
	socket.client.frames.intro_sent = true
	socket.session = {
		phase  = .Login_Accepted,
		client = &socket.client,
		auth   = &f.auth,
	}
}

@(test)
negative_ack_encrypted_socket_read_surfaces_rejection_before_pending_absence :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)

	stream: Negative_Ack_Stream
	negative_ack_encrypted_stream(f, &stream)
	defer wa.socket_close(&f.socket)

	before := test_fixtures.negative_ack_disk(f)
	defer delete(before)

	revision, durable := f.store.revision, f.store.durable_revision
	event, error := wa.socket_read(&f.socket)
	testing.expect_value(t, error.kind, .Message_Rejected)
	testing.expect_value(t, event.kind, .None)
	testing.expect_value(t, f.socket.client.noise.read_counter, u64(1))
	testing.expect_value(t, stream.read_at, stream.size)
	testing.expect_value(t, stream.writes, 0)
	// The tool's pending-absence success gate must remain unreachable after this error.
	_, pending := wa.state_store_get(&f.store, .Outbound_Message, "owned-id")
	_, retained := wa.state_store_get(&f.store, .Outbound_Content, "owned-id")
	testing.expect(t, pending && retained)
	test_fixtures.negative_ack_unchanged(t, f, before, revision, durable)
}

Status_Ack_Stream :: struct {
	input:  Negative_Ack_Stream,
	output: test_fixtures.Send_Id_Wire,
}

status_ack_read :: proc(data: rawptr, dst: []u8) -> (int, surf.WebSocket_Stream_Error) {
	stream := cast(^Status_Ack_Stream)data

	return negative_ack_stream_read(&stream.input, dst)
}

status_ack_write :: proc(data: rawptr, src: []u8) -> (int, surf.WebSocket_Stream_Error) {
	stream := cast(^Status_Ack_Stream)data

	return test_fixtures.send_id_wire_write(&stream.output, src)
}

status_ack_encrypted_input :: proc(f: ^test_fixtures.Negative_Ack_Fixture, stream: ^Status_Ack_Stream) {
	encoded, ciphertext, envelope: [1024]u8
	size, error := wa.binary_node_encode(
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
	peer := wa.Noise_State {
		phase = .Transport,
	}

	defer wa.noise_clear(&peer)

	encrypted_size, encrypted := wa.noise_encrypt(&peer, ciphertext[:], encoded[:size])
	assert(encrypted == .None)
	envelope_size, framed := wa.frame_encode(envelope[:], ciphertext[:encrypted_size])
	assert(framed == .None)
	frame_size, websocket_error := ws.frame_encode(
		stream.input.input[:],
		true,
		.Binary,
		envelope[:envelope_size],
		{},
		masked = false,
	)
	assert(websocket_error == .None)
	stream.input.size = frame_size
	test_fixtures.send_id_wire_connect(&f.socket, &stream.output)
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
	for phase in ([]wa.Socket_Phase{.Online, .Provisioning}) {
		f := test_fixtures.negative_ack_fixture()
		defer test_fixtures.negative_ack_destroy(f)

		stream: Status_Ack_Stream
		status_ack_encrypted_input(f, &stream)
		defer wa.socket_close(&f.socket)

		f.socket.phase = phase
		before := test_fixtures.negative_ack_disk(f)
		defer delete(before)

		event, error := wa.socket_read(&f.socket)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .None)
		testing.expect_value(t, f.socket.phase, phase)
		testing.expect_value(t, f.socket.client.noise.read_counter, u64(1))
		testing.expect(t, stream.output.used > 0, "offline status must reach the ACK handler before activation")

		if stream.output.used == 0 {
			continue
		}

		plain: [2048]u8
		encoded := test_fixtures.send_id_wire_plain(&stream.output, plain[:])
		document, decode := wa.binary_node_decode(transmute([]u8)encoded)
		assert(decode.kind == .None)
		defer wa.binary_document_destroy(&document)

		class, class_found := wa.node_attr(document.root, "class")
		testing.expect(t, document.root.tag == "ack" && class_found && class == "status")
		testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
		after := test_fixtures.negative_ack_disk(f)
		defer delete(after)

		testing.expect(t, bytes.equal(before, after))
	}
}

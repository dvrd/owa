package whatsapp

import ws "../websocket"
import "core:bytes"
import "core:testing"
import "core:time"
import surf "../surf"

// Reference: WhiskeySockets/Baileys src/Socket/messages-recv.ts handleReceipt and
// handleCall ACK in finally; src/Utils/stanza-ack.ts preserves transport attrs.
// These are ACKs of received stanzas, not read/view receipts, call acceptance or
// application delivery effects. All traffic below stays in synthetic fixtures.
ack_routing_input :: proc(f: ^Negative_Ack_Fixture, stream: ^Status_Ack_Stream,
 node: Binary_Node) {
 encoded, ciphertext, envelope: [2048]u8
 count, error := binary_node_encode(encoded[:], node)
 assert(error.kind == .None)
 peer := Noise_State{phase = .Transport}; defer noise_clear(&peer)
 encrypted, noise_error := noise_encrypt(&peer, ciphertext[:], encoded[:count])
 assert(noise_error == .None)
 framed, frame_error := frame_encode(envelope[:], ciphertext[:encrypted])
 assert(frame_error == .None)
 size, websocket_error := ws.frame_encode(stream.input.input[:], true, .Binary,
  envelope[:framed], {}, masked = false)
 assert(websocket_error == .None)
 stream.input.size = size
 send_id_wire_connect(&f.socket, &stream.output)
 f.socket.websocket.stream = {data = stream, read = status_ack_read,
  write = status_ack_write, close = negative_ack_stream_close}
 f.socket.session = {phase = .Login_Accepted, client = &f.socket.client, auth = &f.auth}
}

ack_routing_stage :: proc(socket: ^Socket, stage: int) {
 assert(stage >= 0 && stage < 4)
 socket.phase = stage == 3 ? .Online : .Provisioning
 switch stage {
 case 0: socket.provision_stage = .Count
 case 1: socket.provision_stage = .Upload
 case 2: socket.provision_stage = .Active
 case 3: socket.provision_stage = .None
 }
}

ack_routing_expect_exact :: proc(t: ^testing.T, f: ^Negative_Ack_Fixture,
 wire: ^Send_Id_Wire, tag, kind: string) {
 testing.expect(t, wire.used > 0, "mandatory stanza ACK must be written")
 if wire.used == 0 {return}
 // This decoder asserts exactly one WebSocket/Noise envelope, not a prefix.
 plain: [2048]u8
 encoded := send_id_wire_plain(wire, plain[:])
 document, error := binary_node_decode(transmute([]u8)encoded)
 assert(error.kind == .None); defer binary_document_destroy(&document)
 testing.expect_value(t, document.root.tag, "ack")
 for expected in ([]Binary_Node_Attribute{{"id", "synthetic-routing-id"},
  {"to", "222@s.whatsapp.net"}, {"class", tag},
  {"participant", "333:4@s.whatsapp.net"}, {"recipient", "444@s.whatsapp.net"}}) {
  value, found := pairing_node_attr(document.root, expected.key)
  testing.expect(t, found && value == expected.value)
 }
 actual, typed := pairing_node_attr(document.root, "type")
 testing.expect(t, typed == (kind != "") && actual == kind)
 testing.expect_value(t, len(document.root.attrs), kind == "" ? 5 : 6)
 _, has_error := pairing_node_attr(document.root, "error")
 _, has_offline := pairing_node_attr(document.root, "offline")
 testing.expect(t, !has_error && !has_offline)
 testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
 testing.expect_value(t, send_id_http_calls, 0)
}

ack_routing_call_children := [1]Binary_Node{{tag = "offer",
 attrs = {{"call-id", "synthetic-call-id"}, {"call-creator", "222@s.whatsapp.net"}}}}

ack_routing_node :: proc(tag, kind: string, attrs: []Binary_Node_Attribute) -> Binary_Node {
 node := Binary_Node{tag = tag, attrs = attrs}
 if tag == "call" {node.content = ack_routing_call_children[:]}
 return node
}

ack_routing_unchanged :: proc(t: ^testing.T, f: ^Negative_Ack_Fixture,
 before: []u8, revision, durable: u64) {
 testing.expect_value(t, f.store.revision, revision)
 testing.expect_value(t, f.store.durable_revision, durable)
 testing.expect_value(t, len(f.socket.queue), 0)
 testing.expect_value(t, len(f.socket.deferred_retries), 0)
 after := negative_ack_disk(f); defer delete(after)
 testing.expect(t, bytes.equal(before, after), "transport ACK cannot commit chat state")
}

ack_routing_encrypted_case :: proc(t: ^testing.T, tag, kind: string, stage: int) {
 f := negative_ack_fixture(); defer negative_ack_destroy(f)
 attrs := [7]Binary_Node_Attribute{{"id", "synthetic-routing-id"},
  {"from", "222@s.whatsapp.net"}, {"participant", "333:4@s.whatsapp.net"},
  {"recipient", "444@s.whatsapp.net"}, {"offline", "true"}, {"type", kind}, {}}
 count := kind == "" ? 5 : 6
 stream: Status_Ack_Stream
 ack_routing_input(f, &stream, ack_routing_node(tag, kind, attrs[:count]))
 defer socket_close(&f.socket)
 ack_routing_stage(&f.socket, stage)
 phase, provision := f.socket.phase, f.socket.provision_stage
 before := negative_ack_disk(f); defer delete(before)
 revision, durable := f.store.revision, f.store.durable_revision
 event, error := socket_read(&f.socket)
 testing.expect_value(t, error.kind, .None)
 testing.expect_value(t, f.socket.phase, phase)
 testing.expect_value(t, f.socket.provision_stage, provision)
 testing.expect_value(t, f.socket.client.noise.read_counter, u64(1))
 testing.expect(t, event.message == nil)
 // Keep the previously visible call node available to specialized waiters.
 testing.expect_value(t, event.kind, tag == "call" ? Socket_Event_Kind.Node : .None)
 if tag == "call" {testing.expect_value(t, event.node.tag, "call")}
 ack_routing_expect_exact(t, f, &stream.output, tag, kind)
 ack_routing_unchanged(t, f, before, revision, durable)
}

@(test)
mandatory_receipt_ack_encrypted_provisioning_matches_online :: proc(t: ^testing.T) {
 for stage in 0..<4 {
  for kind in ([]string{"", "read"}) {ack_routing_encrypted_case(t, "receipt", kind, stage)}
 }
}

@(test)
mandatory_call_ack_encrypted_preserves_call_visibility_without_answering :: proc(t: ^testing.T) {
 for stage in 0..<4 {
  for kind in ([]string{"", "offer"}) {ack_routing_encrypted_case(t, "call", kind, stage)}
 }
}

@(test)
mandatory_control_ack_malformed_envelopes_do_not_send_or_commit :: proc(t: ^testing.T) {
 for tag in ([]string{"receipt", "call"}) {
  for attrs in ([]([]Binary_Node_Attribute){
   {{"from", "222@s.whatsapp.net"}}, {{"id", "synthetic-routing-id"}},
   {{"id", ""}, {"from", "222@s.whatsapp.net"}},
   {{"id", "synthetic-routing-id"}, {"from", ""}},
  }) {
   f := negative_ack_fixture(); defer negative_ack_destroy(f)
   wire: Send_Id_Wire
   send_id_wire_connect(&f.socket, &wire); defer socket_close(&f.socket)
   before := negative_ack_disk(f); defer delete(before)
   revision, durable := f.store.revision, f.store.durable_revision
   event, error := socket_process_node(&f.socket, ack_routing_node(tag, "", attrs))
   testing.expect_value(t, error.kind, .Protocol_Error)
   testing.expect_value(t, event.kind, .None)
   testing.expect_value(t, wire.used, 0)
   testing.expect_value(t, f.socket.client.noise.write_counter, u64(0))
   ack_routing_unchanged(t, f, before, revision, durable)
  }
 }
}

@(test)
mandatory_control_ack_write_failure_is_terminal_without_chat_commit :: proc(t: ^testing.T) {
 for tag in ([]string{"receipt", "call"}) {
  f := negative_ack_fixture(); defer negative_ack_destroy(f)
  wire: Send_Id_Wire
  send_id_wire_connect(&f.socket, &wire); defer socket_close(&f.socket)
  f.socket.websocket.stream.write = status_ack_failed_write
  before := negative_ack_disk(f); defer delete(before)
  revision, durable := f.store.revision, f.store.durable_revision
  event, error := socket_process_node(&f.socket, ack_routing_node(tag, "",
   {{"id", "synthetic-routing-id"}, {"from", "222@s.whatsapp.net"}}))
  testing.expect_value(t, error.kind, .Session_Failed)
  testing.expect_value(t, error.session.kind, .Client_Failed)
  testing.expect_value(t, event.kind, .None)
  testing.expect_value(t, f.socket.phase, .Failed)
  testing.expect_value(t, wire.used, 0)
  ack_routing_unchanged(t, f, before, revision, durable)
 }
}

ack_routing_retry_attributes := [5]Binary_Node_Attribute{{"id", "synthetic-missing-retry"},
 {"from", "123@g.us"}, {"type", "retry"},
 {"participant", "333:4@s.whatsapp.net"}, {"recipient", "444@s.whatsapp.net"}}
ack_routing_retry_children := [1]Binary_Node{{tag = "retry", attrs = {{"count", "1"}}}}

ack_routing_retry_node :: proc() -> Binary_Node {
 return {tag = "receipt", attrs = ack_routing_retry_attributes[:], content = ack_routing_retry_children[:]}
}

ack_routing_expect_retry_ack :: proc(t: ^testing.T, stream: ^Status_Ack_Stream) {
 testing.expect(t, stream.output.used > 0)
 if stream.output.used == 0 {return}
 plain: [2048]u8
 encoded := send_id_wire_plain(&stream.output, plain[:])
 document, error := binary_node_decode(transmute([]u8)encoded); assert(error.kind == .None)
 defer binary_document_destroy(&document)
 testing.expect_value(t, document.root.tag, "ack")
 testing.expect_value(t, len(document.root.attrs), 6)
 for expected in ([]Binary_Node_Attribute{{"id", "synthetic-missing-retry"},
  {"to", "123@g.us"}, {"class", "receipt"}, {"type", "retry"},
  {"participant", "333:4@s.whatsapp.net"}, {"recipient", "444@s.whatsapp.net"}}) {
  value, found := pairing_node_attr(document.root, expected.key)
  testing.expect(t, found && value == expected.value)
 }
}

Ack_Retry_Tick_Probe :: struct {reads, writes: int}
ack_retry_tick_read :: proc(data: rawptr, _: []u8) -> (int, surf.WebSocket_Stream_Error) {
 probe := cast(^Ack_Retry_Tick_Probe)data; probe.reads += 1
 return 0, {kind = .EOF}
}
ack_retry_tick_write :: proc(data: rawptr, _: []u8) -> (int, surf.WebSocket_Stream_Error) {
 probe := cast(^Ack_Retry_Tick_Probe)data; probe.writes += 1
 return 0, {kind = .No_Progress}
}

@(test)
mandatory_provisioning_retry_is_owned_until_online_and_outside_query :: proc(t: ^testing.T) {
 for initial_stage in 0..<3 {
  f := negative_ack_fixture(); defer negative_ack_destroy(f)
  stream: Status_Ack_Stream
  ack_routing_input(f, &stream, ack_routing_retry_node())
  defer socket_close(&f.socket)
  ack_routing_stage(&f.socket, initial_stage)
  before := negative_ack_disk(f); defer delete(before)
  revision, durable := f.store.revision, f.store.durable_revision
  event, error := socket_read(&f.socket)
  testing.expect_value(t, error.kind, .None)
  testing.expect_value(t, event.kind, .None)
  testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
  ack_routing_expect_retry_ack(t, &stream)
  testing.expect_value(t, len(f.socket.deferred_retries), 1)
  if len(f.socket.deferred_retries) != 1 {continue}
  binary_document_destroy(&f.socket.session.document)
  queued := f.socket.deferred_retries[0].root
  id, found := pairing_node_attr(queued, "id")
  kind, kind_found := pairing_node_attr(queued, "type")
  retry, have_retry := pairing_node_child(queued, "retry")
  testing.expect(t, found && id == "synthetic-missing-retry" && kind_found && kind == "retry" && have_retry)
  if have_retry {
   count, count_found := pairing_node_attr(retry^, "count")
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
  for stage in 0..<3 {
   ack_routing_stage(&f.socket, stage)
   _, tick_error := socket_tick(&f.socket, now)
   testing.expect_value(t, tick_error.kind, .None)
   testing.expect_value(t, len(f.socket.deferred_retries), 1)
   testing.expect_value(t, f.store.revision, revision)
   testing.expect_value(t, f.store.durable_revision, durable)
  }
  ack_routing_stage(&f.socket, 3)
  f.socket.query_depth = 1
  _, nested := socket_tick(&f.socket, now)
  testing.expect_value(t, nested.kind, .None)
  testing.expect_value(t, len(f.socket.deferred_retries), 1)
  f.socket.query_depth = 0
  _, drained := socket_tick(&f.socket, now)
  testing.expect_value(t, drained.kind, .None)
  testing.expect_value(t, len(f.socket.deferred_retries), 0)
  testing.expect_value(t, probe.reads, 0)
  testing.expect_value(t, probe.writes, 0)
  testing.expect_value(t, send_id_http_calls, 0)
  testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
  // The referenced retained message is absent, so post-Online retry is a no-op.
  ack_routing_unchanged(t, f, before, revision, durable)
 }
}

@(test)
mandatory_provisioning_retry_keeps_existing_64_bound_and_ack_order :: proc(t: ^testing.T) {
 f := negative_ack_fixture(); defer negative_ack_destroy(f)
 for _ in 0..<64 {assert(socket_defer_retry(&f.socket, ack_routing_retry_node()).kind == .None)}
 stream: Status_Ack_Stream
 ack_routing_input(f, &stream, ack_routing_retry_node())
 defer socket_close(&f.socket)
 ack_routing_stage(&f.socket, 0)
 before := negative_ack_disk(f); defer delete(before)
 revision, durable := f.store.revision, f.store.durable_revision
 event, error := socket_read(&f.socket)
 testing.expect_value(t, error.kind, .Queue_Full)
 testing.expect_value(t, event.kind, .None)
 testing.expect_value(t, len(f.socket.deferred_retries), 64)
 testing.expect_value(t, f.socket.phase, .Provisioning)
 testing.expect_value(t, f.socket.client.noise.write_counter, u64(1))
 ack_routing_expect_retry_ack(t, &stream)
 binary_document_destroy(&f.socket.session.document)
 for queued in f.socket.deferred_retries {
  id, found := pairing_node_attr(queued.root, "id")
  testing.expect(t, found && id == "synthetic-missing-retry")
 }
 testing.expect_value(t, send_id_http_calls, 0)
 testing.expect_value(t, f.store.revision, revision)
 testing.expect_value(t, f.store.durable_revision, durable)
 after := negative_ack_disk(f); defer delete(after)
 testing.expect(t, bytes.equal(before, after))
}

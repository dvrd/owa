package whatsapp

import "core:bytes"
import network_client "../surf"
import http "../http"
import ws "../websocket"
import "core:fmt"
import "core:os"
import "core:testing"

Send_Id_Fixture :: struct {
 socket: Socket,
 auth: Auth_State,
 store: State_Store,
 directory, path: string,
}

send_id_fixture :: proc() -> ^Send_Id_Fixture {
 fixture := new(Send_Id_Fixture)
 directory, error := os.make_directory_temp("", "whatsapp-send-id-*", context.allocator)
 assert(error == nil)
 fixture.directory = directory
 fixture.path = fmt.aprintf("%s/state", directory)
 identity: [32]u8; identity[0] = 1
 assert(state_store_init(&fixture.store, identity).kind == .None)
 fixture.socket = {phase = .Online, store = &fixture.store, auth = &fixture.auth,
  config = {state_path = fixture.path}}
 assert(socket_group_outbound_commit(&fixture.socket, "123@g.us", "", "stable-id",
  transmute([]u8)string("original content"), transmute([]u8)string("original wire")).kind == .None)
 return fixture
}

send_id_fixture_destroy :: proc(fixture: ^Send_Id_Fixture) {
 state_store_clear(&fixture.store)
 assert(os.remove_all(fixture.directory) == nil)
 delete(fixture.path); delete(fixture.directory); free(fixture)
}

@(test)
send_id_conflicting_commit_preserves_pending_wire_and_durable_state :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 revision := fixture.store.revision
 error := socket_group_outbound_commit(&fixture.socket, "456@g.us", "", "stable-id",
  transmute([]u8)string("replacement content"), transmute([]u8)string("replacement wire"))
 testing.expect_value(t, error.kind, .Invalid_Config)
 wire, present := state_store_get(&fixture.store, .Outbound_Message, "stable-id")
 testing.expect(t, present && bytes.equal(wire, transmute([]u8)string("original wire")))
 testing.expect_value(t, fixture.store.revision, revision)
 restored: State_Store; defer state_store_clear(&restored)
 loaded := state_store_load(&restored, fixture.path, fixture.store.identity)
 testing.expect_value(t, loaded.kind, .None)
 durable, found := state_store_get(&restored, .Outbound_Message, "stable-id")
 testing.expect(t, found && bytes.equal(durable, transmute([]u8)string("original wire")))
}

@(test)
send_id_conflict_is_rejected_before_metadata_or_cryptographic_work :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 revision := fixture.store.revision
 id, error := socket_send_group(&fixture.socket, "456@g.us",
  transmute([]u8)string("replacement content"), message_id = "stable-id")
 defer delete(id)
 testing.expect_value(t, error.kind, .Invalid_Config)
 testing.expect_value(t, id, "")
 testing.expect_value(t, fixture.store.revision, revision)
 testing.expect_value(t, fixture.socket.sequence, u64(0))
 testing.expect_value(t, fixture.socket.phase, .Online)
}

@(test)
send_id_pending_same_intent_reuses_id_without_queries_or_new_state :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 revision := fixture.store.revision
 id, error := socket_send_group(&fixture.socket, "123@g.us",
  transmute([]u8)string("original content"), message_id = "stable-id")
 defer delete(id)
 // No initialized wire client: replay fails closed, retaining the original ID and packet.
 testing.expect_value(t, error.kind, .Session_Failed)
 testing.expect_value(t, id, "stable-id")
 testing.expect_value(t, fixture.socket.sequence, u64(0))
 testing.expect_value(t, fixture.store.revision, revision)
 wire, present := state_store_get(&fixture.store, .Outbound_Message, "stable-id")
 testing.expect(t, present && bytes.equal(wire, transmute([]u8)string("original wire")))
}


Send_Id_Wire :: struct {data: [4096]u8, used: int}

@(thread_local)
send_id_http_calls: int

send_id_http :: proc(request: http.Request, config: network_client.Config) ->
 (network_client.Response, network_client.HTTP_Error) {
 send_id_http_calls += 1
 return {}, {kind = .IO_Failed}
}

send_id_wire_connect :: proc(socket: ^Socket, wire: ^Send_Id_Wire) {
 socket.websocket = {phase = .Open, allocator = context.allocator,
  config = {host = "synthetic.invalid", max_message_size = 4096},
  stream = {data = wire, write = send_id_wire_write, read = send_id_wire_read,
   close = send_id_wire_close}}
 socket.client = {phase = .Noise_Ready, websocket = &socket.websocket,
  config = {max_frame_payload = 4096}, noise = {phase = .Transport}}
 assert(frame_transport_init(&socket.client.frames, &socket.websocket, 4096).kind == .None)
 socket.client.frames.intro_sent = true
 socket.config.http_execute = send_id_http
 send_id_http_calls = 0
}

send_id_wire_write :: proc(data: rawptr, source: []u8) ->
 (int, network_client.WebSocket_Stream_Error) {
 wire := cast(^Send_Id_Wire)data
 assert(len(source) <= len(wire.data) - wire.used)
 wire.used += copy(wire.data[wire.used:], source)
 return len(source), {}
}

send_id_wire_read :: proc(data: rawptr, destination: []u8) ->
 (int, network_client.WebSocket_Stream_Error) {return 0, {kind = .EOF}}

send_id_wire_close :: proc(data: rawptr) -> network_client.WebSocket_Stream_Error {return {}}

send_id_wire_plain :: proc(wire: ^Send_Id_Wire, destination: []u8) -> string {
 header, size, decode := ws.frame_header_decode(wire.data[:wire.used], true)
 assert(decode == .None && size + int(header.payload_length) == wire.used)
 payload := wire.data[size:wire.used]
 ws.mask_payload(payload, header.masking_key)
 encrypted, consumed, framed := frame_decode(payload)
 assert(framed == .None && consumed == len(payload))
 peer := Noise_State{phase = .Transport}
 count, decrypted := noise_decrypt(&peer, destination, encrypted)
 assert(decrypted == .None)
 return string(destination[:count])
}

@(test)
send_id_successful_pending_replay_preserves_exact_inner_packet :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 wire: Send_Id_Wire
 socket := &fixture.socket
 send_id_wire_connect(socket, &wire)
 defer frame_transport_clear(&socket.client.frames)
 revision := fixture.store.revision
 id, error := socket_send_group(socket, "123@g.us", transmute([]u8)string("original content"),
  message_id = "stable-id")
 defer delete(id)
 testing.expect_value(t, error.kind, .None)
 testing.expect_value(t, id, "stable-id")
 testing.expect_value(t, fixture.store.revision, revision)
 testing.expect_value(t, socket.sequence, u64(0))
 plain: [1024]u8
 testing.expect_value(t, send_id_wire_plain(&wire, plain[:]), "original wire")
}

@(test)
send_id_targeted_retry_bypasses_pending_replay_without_changing_intent :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 id, handled, error := socket_group_existing_send(&fixture.socket, "123@g.us", "",
  "stable-id", "222:1@s.whatsapp.net", transmute([]u8)string("original content"))
 defer delete(id)
 testing.expect(t, !handled)
 testing.expect_value(t, error.kind, .None)
 _, conflict, conflict_error := socket_group_existing_send(&fixture.socket, "123@g.us", "",
  "stable-id", "222:1@s.whatsapp.net", transmute([]u8)string("changed content"))
 testing.expect(t, conflict)
 testing.expect_value(t, conflict_error.kind, .Invalid_Config)
}


@(test)
send_id_retained_content_does_not_fabricate_acknowledgment :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 assert(state_store_delete(&fixture.store, .Outbound_Message, "stable-id").kind == .None)
 id, handled, error := socket_group_existing_send(&fixture.socket, "123@g.us", "",
  "stable-id", "", transmute([]u8)string("original content"))
 defer delete(id)
 testing.expect(t, !handled)
 testing.expect_value(t, error.kind, .None)
}


send_id_media_fixture :: proc(fixture: ^Send_Id_Fixture) {
 assert(state_store_delete(&fixture.store, .Outbound_Content, "stable-id").kind == .None)
 assert(state_store_delete(&fixture.store, .Outbound_Message, "stable-id").kind == .None)
 hash := media_hash(transmute([]u8)string("%PDF-original"))
 key: [32]u8; key[0] = 1
 message := Media_Message{kind = .Document, url = "https://mmg.whatsapp.net/a.enc",
  direct_path = "/a.enc", mime_type = "application/pdf", caption = "caption", file_name = "a.pdf",
  media_key = key[:], file_sha256 = hash[:], file_enc_sha256 = hash[:],
  file_length = 13, has_file_length = true}
 buffer: [1024]u8
 count, error := media_message_encode(buffer[:], message)
 assert(error.kind == .None)
 assert(socket_group_outbound_commit(&fixture.socket, "123@g.us", "document", "stable-id",
  buffer[:count], transmute([]u8)string("original media wire")).kind == .None)
}

@(test)
send_id_high_level_document_replay_does_not_upload_again :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 send_id_media_fixture(fixture)
 wire_capture: Send_Id_Wire
 send_id_wire_connect(&fixture.socket, &wire_capture)
 defer frame_transport_clear(&fixture.socket.client.frames)
 revision := fixture.store.revision
 id, error := socket_send_document(&fixture.socket, "123@g.us",
  transmute([]u8)string("%PDF-original"), "a.pdf", "caption", "application/pdf", "stable-id")
 defer delete(id)
 testing.expect_value(t, id, "stable-id")
 testing.expect_value(t, error.kind, .None)
 testing.expect_value(t, send_id_http_calls, 0)
 testing.expect(t, wire_capture.used > 0)
 plain: [1024]u8
 testing.expect_value(t, send_id_wire_plain(&wire_capture, plain[:]), "original media wire")
 testing.expect_value(t, fixture.store.revision, revision)
 testing.expect_value(t, fixture.socket.sequence, u64(0))
 wire, found := state_store_get(&fixture.store, .Outbound_Message, "stable-id")
 testing.expect(t, found && string(wire) == "original media wire")
}

@(test)
send_id_high_level_document_conflicts_fail_before_upload :: proc(t: ^testing.T) {
 fixture := send_id_fixture(); defer send_id_fixture_destroy(fixture)
 send_id_media_fixture(fixture)
 fixture.socket.config.http_execute = send_id_http
 send_id_http_calls = 0
 for row in ([]struct {group, content, name, caption: string}{
  {"456@g.us", "%PDF-original", "a.pdf", "caption"},
  {"123@g.us", "%PDF-changed!", "a.pdf", "caption"},
  {"123@g.us", "%PDF-original", "b.pdf", "caption"},
  {"123@g.us", "%PDF-original", "a.pdf", "changed"},
 }) {
  id, error := socket_send_document(&fixture.socket, row.group,
   transmute([]u8)row.content, row.name, row.caption, "application/pdf", "stable-id")
  delete(id)
  testing.expect_value(t, error.kind, .Invalid_Config)
  testing.expect_value(t, fixture.socket.sequence, u64(0))
  testing.expect_value(t, send_id_http_calls, 0)
  fixture.socket.phase = .Online
 }
}

package main

import wa "../.."
import surf "../../../surf"
import ws "../../../websocket"
import "core:bytes"
import "core:crypto/sha2"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sys/posix"
import "core:time"

FIXED_ID :: "recovery-campaign-fixed-id"
FIXED_GROUP :: "123@g.us"
PAYLOAD :: string("synthetic immutable recovery intent")
PACKET :: string("synthetic committed inner packet")
Intent_Status :: enum u8 {Prepared, Queued, Acknowledged}
Intent :: struct {magic: [8]u8, id: [64]u8, digest: [32]u8, status: Intent_Status}
Fixture :: struct {
 socket: wa.Socket,
 auth: wa.Auth_State,
 prekeys: wa.Prekey_Store,
 store: wa.State_Store,
 path, intent_path: string,
 identity: [32]u8,
}
Wire :: struct {data: [4096]u8, used: int}

fixture_open :: proc(directory: string, initialize: bool) -> ^Fixture {
 assert(strings.has_prefix(directory, "/tmp/wa-recovery-") ||
  strings.has_prefix(directory, "/private/tmp/wa-recovery-"))
 f := new(Fixture)
 f.path = fmt.aprintf("%s/state.bin", directory)
 f.intent_path = fmt.aprintf("%s/intent.bin", directory)
 for &byte, index in f.identity {byte = u8(index + 1)}
 if initialize {
  assert(!os.exists(f.path) && !os.exists(f.intent_path))
  assert(wa.state_store_init(&f.store, f.identity).kind == .None)
  assert(wa.state_store_set(&f.store, .Session, "synthetic-ratchet",
   transmute([]u8)string("ratchet-before")).kind == .None)
  assert(wa.state_store_save(&f.store, f.path).kind == .None)
 } else {assert(wa.state_store_load(&f.store, f.path, f.identity).kind == .None)}
 f.socket = {phase = .Online, auth = &f.auth, prekeys = &f.prekeys,
  store = &f.store, config = {state_path = f.path}}
 return f
}

fixture_close :: proc(f: ^Fixture) {
 wa.socket_close(&f.socket)
 wa.state_store_clear(&f.store)
 delete(f.path); delete(f.intent_path); free(f)
}

intent_write :: proc(f: ^Fixture, directory: string, status: Intent_Status) {
 intent := Intent{status = status}
 copy(intent.magic[:], "RECOVER1"); copy(intent.id[:], FIXED_ID)
 intent.digest = payload_digest()
 temporary := fmt.aprintf("%s.next", f.intent_path); defer delete(temporary)
 file, error := os.open(temporary, {.Write, .Create, .Excl}, os.perm_number(0o600))
 assert(error == nil)
 data := (cast([^]u8)&intent)[:size_of(intent)]
 count, written := os.write(file, data)
 assert(written == nil && count == len(data)); assert(os.flush(file) == nil)
 assert(os.close(file) == nil); assert(os.rename(temporary, f.intent_path) == nil)
 cpath := strings.clone_to_cstring(directory); defer delete(cpath)
 descriptor := posix.open(cpath, {}, {})
 assert(descriptor >= 0); defer posix.close(descriptor)
 assert(posix.fsync(descriptor) == .OK)
}

boundary :: proc(stage, requested: string) {
 if stage != requested {return}
 fmt.printf("BOUNDARY_READY %s\n", stage); _ = os.flush(os.stdout)
 for {time.sleep(time.Second)}
}

child :: proc(directory, stage: string) {
 f := fixture_open(directory, true); defer fixture_close(f)
 assert(wa.state_store_set(&f.store, .Session, "synthetic-ratchet",
  transmute([]u8)string("ratchet-after")).kind == .None)
 boundary("before-commit", stage)
 intent_write(f, directory, .Prepared)
 boundary("after-intent", stage)
 intent_write(f, directory, .Queued)
 assert(wa.socket_group_outbound_commit(&f.socket, FIXED_GROUP, "", FIXED_ID,
  transmute([]u8)PAYLOAD, transmute([]u8)PACKET).kind == .None)
 boundary("after-pending-wire", stage)
 _, ack := wa.socket_process_node(&f.socket, {tag = "ack", attrs = {
  {"class", "message"}, {"id", FIXED_ID}}})
 assert(ack.kind == .None)
 boundary("after-positive-ack", stage)
 intent_write(f, directory, .Acknowledged)
 boundary("after-ack-journal", stage)
 assert(stage == "control")
 fmt.println("CONTROL_READY")
}

wire_read :: proc(_: rawptr, _: []u8) -> (int, surf.WebSocket_Stream_Error) {
 return 0, {kind = .EOF}
}
wire_write :: proc(data: rawptr, source: []u8) -> (int, surf.WebSocket_Stream_Error) {
 wire := cast(^Wire)data
 assert(len(source) <= len(wire.data)-wire.used)
 wire.used += copy(wire.data[wire.used:], source)
 return len(source), {}
}
wire_close :: proc(_: rawptr) -> surf.WebSocket_Stream_Error {return {}}

verify_replay :: proc(f: ^Fixture) {
 wire: Wire
 socket := &f.socket
 defer socket.websocket = {}
 defer wa.socket_close(socket)
 socket.websocket = {phase = .Open, allocator = context.allocator,
  config = {host = "synthetic.invalid", max_message_size = 4096},
  stream = {data = &wire, read = wire_read, write = wire_write, close = wire_close}}
 socket.client = {phase = .Noise_Ready, websocket = &socket.websocket,
  config = {max_frame_payload = 4096}, noise = {phase = .Transport}}
 assert(wa.frame_transport_init(&socket.client.frames, &socket.websocket, 4096).kind == .None)
 socket.client.frames.intro_sent = true
 revision := f.store.revision
 id, error := wa.socket_send_group(socket, FIXED_GROUP, transmute([]u8)PAYLOAD,
  message_id = FIXED_ID)
 defer delete(id)
 assert(error.kind == .None && id == FIXED_ID && socket.sequence == 0)
 assert(f.store.revision == revision && socket.client.noise.write_counter == 1)
 header, offset, decoded := ws.frame_header_decode(wire.data[:wire.used], true)
 assert(decoded == .None && offset + int(header.payload_length) == wire.used)
 payload := wire.data[offset:wire.used]; ws.mask_payload(payload, header.masking_key)
 encrypted, consumed, framed := wa.frame_decode(payload)
 assert(framed == .None && consumed == len(payload))
 peer := wa.Noise_State{phase = .Transport}; defer wa.noise_clear(&peer)
 plain: [1024]u8
 count, decrypted := wa.noise_decrypt(&peer, plain[:], encrypted)
 assert(decrypted == .None && string(plain[:count]) == PACKET)
}

verify_intent :: proc(f: ^Fixture, stage: string) -> Intent_Status {
 if stage == "before-commit" {assert(!os.exists(f.intent_path)); return .Prepared}
 data, error := os.read_entire_file(f.intent_path, context.allocator)
 assert(error == nil); defer delete(data)
 intent: Intent
 assert(len(data) == size_of(intent))
 copy((cast([^]u8)&intent)[:size_of(intent)], data)
 expected := payload_digest()
 assert(string(intent.magic[:]) == "RECOVER1")
 assert(string(intent.id[:len(FIXED_ID)]) == FIXED_ID && intent.digest == expected)
 expected_status: Intent_Status = .Queued
 if stage == "after-intent" {expected_status = .Prepared}
 if stage == "after-ack-journal" || stage == "control" {expected_status = .Acknowledged}
 assert(intent.status == expected_status)
 return intent.status
}

verify :: proc(directory, stage: string) {
 f := fixture_open(directory, false); defer fixture_close(f)
 wrong := f.identity; wrong[0] ~= 1
 rejected: wa.State_Store; defer wa.state_store_clear(&rejected)
 assert(wa.state_store_load(&rejected, f.path, wrong).kind == .Identity_Mismatch)
 status := verify_intent(f, stage)
 before := stage == "before-commit" || stage == "after-intent"
 ratchet, found := wa.state_store_get(&f.store, .Session, "synthetic-ratchet")
 assert(found && string(ratchet) == (before ? "ratchet-before" : "ratchet-after"))
 wire, pending := wa.state_store_get(&f.store, .Outbound_Message, FIXED_ID)
 content, retained := wa.state_store_get(&f.store, .Outbound_Content, FIXED_ID)
 assert(pending == (stage == "after-pending-wire"))
 assert(retained == !before)
 if pending {assert(string(wire) == PACKET); verify_replay(f)}
 if retained {
  document, decoded := wa.binary_node_decode(content); assert(decoded.kind == .None)
  defer wa.binary_document_destroy(&document)
  payload, valid := document.root.content.([]u8)
  assert(valid && bytes.equal(payload, transmute([]u8)PAYLOAD))
 }
 if stage == "after-positive-ack" {
  assert(!pending && status == .Queued)
  fmt.println("RECOVERY_UNKNOWN recipient_delivery=false automatic_send=false")
 }
 fmt.printf("RECOVERY_VERIFIED stage=%s pending=%t retained=%t status=%v delivery=false\n",
  stage, pending, retained, status)
}

main :: proc() {
 assert(len(os.args) == 4)
 switch os.args[1] {
 case "child": child(os.args[2], os.args[3])
 case "verify": verify(os.args[2], os.args[3])
 case: assert(false)
 }
}

payload_digest :: proc() -> [32]u8 {
 state: sha2.Context_256
 digest: [32]u8
 sha2.init_256(&state); sha2.update(&state, transmute([]u8)PAYLOAD)
 sha2.final(&state, digest[:])
 return digest
}

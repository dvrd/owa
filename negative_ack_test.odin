package whatsapp

import "core:bytes"
import "core:fmt"
import "core:os"
import "core:testing"

Negative_Ack_Fixture :: struct {
 socket: Socket,
 auth: Auth_State,
 prekeys: Prekey_Store,
 store: State_Store,
 directory, path: string,
}

negative_ack_fixture :: proc() -> ^Negative_Ack_Fixture {
 f := new(Negative_Ack_Fixture)
 directory, error := os.make_directory_temp("", "whatsapp-negative-ack-*", context.allocator)
 assert(error == nil)
 f.directory = directory; f.path = fmt.aprintf("%s/state", directory)
 identity: [32]u8; identity[0] = 1
 assert(state_store_init(&f.store, identity).kind == .None)
 f.socket = {phase = .Online, auth = &f.auth, prekeys = &f.prekeys,
  store = &f.store, config = {state_path = f.path}}
 assert(socket_group_outbound_commit(&f.socket, "123@g.us", "", "owned-id",
  transmute([]u8)string("synthetic content"),
  transmute([]u8)string("synthetic wire")).kind == .None)
 return f
}

negative_ack_destroy :: proc(f: ^Negative_Ack_Fixture) {
 state_store_clear(&f.store)
 assert(os.remove_all(f.directory) == nil)
 delete(f.path); delete(f.directory); free(f)
}

negative_ack_disk :: proc(f: ^Negative_Ack_Fixture) -> []u8 {
 data, error := os.read_entire_file(f.path, context.allocator)
 assert(error == nil); return data
}

negative_ack_unchanged :: proc(t: ^testing.T, f: ^Negative_Ack_Fixture,
 before: []u8, revision, durable: u64) {
 testing.expect_value(t, f.store.revision, revision)
 testing.expect_value(t, f.store.durable_revision, durable)
 testing.expect_value(t, f.socket.phase, .Online)
 after := negative_ack_disk(f); defer delete(after)
 testing.expect(t, bytes.equal(before, after), "negative/irrelevant ACK must not rewrite disk")
 restored: State_Store; defer state_store_clear(&restored)
 testing.expect_value(t, state_store_load(&restored, f.path, f.store.identity).kind, .None)
 testing.expect_value(t, restored.revision, revision)
 for kind in ([]State_Record_Kind{.Outbound_Message, .Outbound_Content}) {
  expected, exists := state_store_get(&f.store, kind, "owned-id")
  actual, found := state_store_get(&restored, kind, "owned-id")
  testing.expect(t, exists == found && bytes.equal(expected, actual))
 }
}

@(test)
negative_ack_error_presence_rejects_tracked_intent_without_any_mutation :: proc(t: ^testing.T) {
 // Error presence, not successful numeric parsing, determines rejection.
 for value in ([]string{"479", "463", "", "not-a-number", "0", "-1"}) {
  f := negative_ack_fixture(); defer negative_ack_destroy(f)
  before := negative_ack_disk(f); defer delete(before)
  revision, durable := f.store.revision, f.store.durable_revision
  event, error := socket_process_node(&f.socket,
   {tag = "ack", attrs = {{"class", "message"}, {"id", "owned-id"}, {"error", value}}})
  testing.expect_value(t, event.kind, .None)
  testing.expect_value(t, error.kind, .Message_Rejected)
  negative_ack_unchanged(t, f, before, revision, durable)
  wire, pending := state_store_get(&f.store, .Outbound_Message, "owned-id")
  testing.expect(t, pending && bytes.equal(wire, transmute([]u8)string("synthetic wire")))
  _, retained := state_store_get(&f.store, .Outbound_Content, "owned-id")
  testing.expect(t, retained)
 }
}

@(test)
negative_ack_retained_or_pending_intent_alone_is_tracked :: proc(t: ^testing.T) {
 for removed in ([]State_Record_Kind{.Outbound_Message, .Outbound_Content}) {
  f := negative_ack_fixture(); defer negative_ack_destroy(f)
  assert(state_store_delete(&f.store, removed, "owned-id").kind == .None)
  assert(state_store_save(&f.store, f.path).kind == .None)
  before := negative_ack_disk(f); defer delete(before)
  revision, durable := f.store.revision, f.store.durable_revision
  _, error := socket_process_node(&f.socket,
   {tag = "ack", attrs = {{"class", "message"}, {"id", "owned-id"}, {"error", "479"}}})
  testing.expect_value(t, error.kind, .Message_Rejected)
  negative_ack_unchanged(t, f, before, revision, durable)
 }
}

@(test)
negative_ack_unknown_missing_id_or_other_class_does_not_abort_session :: proc(t: ^testing.T) {
 f := negative_ack_fixture(); defer negative_ack_destroy(f)
 before := negative_ack_disk(f); defer delete(before)
 revision, durable := f.store.revision, f.store.durable_revision
 for attributes in ([]([]Binary_Node_Attribute){
  {{"class", "message"}, {"id", "unknown-id"}, {"error", "479"}},
  {{"class", "message"}, {"id", ""}, {"error", ""}},
  {{"class", "message"}, {"error", "malformed"}},
  {{"class", "receipt"}, {"id", "owned-id"}, {"error", "479"}},
  {{"id", "owned-id"}, {"error", "479"}},
 }) {
  event, error := socket_process_node(&f.socket, {tag = "ack", attrs = attributes})
  testing.expect_value(t, event.kind, .None)
  testing.expect_value(t, error.kind, .None)
  negative_ack_unchanged(t, f, before, revision, durable)
 }
}

@(test)
negative_ack_positive_control_commits_pending_removal_and_retains_content :: proc(t: ^testing.T) {
 f := negative_ack_fixture(); defer negative_ack_destroy(f)
 revision := f.store.revision
 _, error := socket_process_node(&f.socket,
  {tag = "ack", attrs = {{"class", "message"}, {"id", "owned-id"}}})
 testing.expect_value(t, error.kind, .None)
 testing.expect_value(t, f.socket.phase, .Online)
 testing.expect_value(t, f.store.revision, revision + 1)
 testing.expect_value(t, f.store.durable_revision, f.store.revision)
 _, pending := state_store_get(&f.store, .Outbound_Message, "owned-id")
 _, retained := state_store_get(&f.store, .Outbound_Content, "owned-id")
 testing.expect(t, !pending && retained)
 restored: State_Store; defer state_store_clear(&restored)
 testing.expect_value(t, state_store_load(&restored, f.path, f.store.identity).kind, .None)
 _, durable_pending := state_store_get(&restored, .Outbound_Message, "owned-id")
 _, durable_content := state_store_get(&restored, .Outbound_Content, "owned-id")
 testing.expect(t, !durable_pending && durable_content)
 testing.expect_value(t, restored.revision, revision + 1)
}

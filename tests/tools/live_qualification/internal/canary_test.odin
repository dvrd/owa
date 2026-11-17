package main

import wa "../.."
import "core:bytes"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

Canary_Fixture :: struct {root, path: string, runner: ^Runner, storage: ^Storage}

canary_fixture_destroy :: proc(f: ^Canary_Fixture) {
 storage_close(f.storage); free(f.runner)
 os.remove_all(f.root); delete(f.path); delete(f.root); free(f)
 sync.mutex_unlock(&probe_test_mutex)
}

canary_fixture :: proc(t: ^testing.T) -> ^Canary_Fixture {
 sync.mutex_lock(&probe_test_mutex)
 f := new(Canary_Fixture)
 f.root = probe_test_directory(); f.path = storage_path(f.root, "auth")
 f.runner = new(Runner); f.storage = &f.runner.storage
 failure := storage_open(f.storage, f.path, .Pair_New, "synthetic canary")
 testing.expect_value(t, failure, .None)
 if failure != .None {canary_fixture_destroy(f); return nil}
 failure = storage_scope_target(f.storage, "synthetic@g.us")
 testing.expect_value(t, failure, .None)
 if failure != .None {canary_fixture_destroy(f); return nil}
 failure = canary_ledger_create(f.storage, 3600)
 testing.expect_value(t, failure, .None)
 if failure != .None {canary_fixture_destroy(f); return nil}
 return f
}

canary_reopen :: proc(t: ^testing.T, f: ^Canary_Fixture) -> bool {
 storage_close(f.storage)
 error := storage_open(f.storage, f.path, .Pair_New, "synthetic canary")
 testing.expect_value(t, error, .None)
 return error == .None
}

canary_id :: proc(s: ^Storage, index: int) -> string {
 owned, _ := strings.clone(string(s.canary.entries[index].intent.id[:32]))
 return owned
}

canary_options :: proc() -> Options {
 return {command = .Watch, send = true, allow_scoped_retries = true,
  group_subject = "synthetic canary", canary_interval_seconds = 3600}
}

canary_ack_pair :: proc(t: ^testing.T, s: ^Storage, now: i64) {
 first := int(s.canary.count)-2
 for index in first..<first+2 {
  testing.expect_value(t, canary_mark(s, index, .Queued, now), .None)
  testing.expect_value(t, canary_mark(s, index, .Acknowledged, now), .None)
 }
}

canary_file :: proc(f: ^Canary_Fixture, name: string) -> []u8 {
 path := storage_path(f.path, name); defer delete(path)
 data, _ := os.read_entire_file(path, context.allocator)
 return data
}

@(test)
canary_prepare_is_durable_same_ids_after_reopen_and_crypto_is_unchanged :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, wa.state_store_set(&s.state, .Session,
  "synthetic-ratchet", []u8{1, 7, 19, 23}).kind, .None)
 testing.expect_value(t, wa.state_store_save(&s.state, s.state_path).kind, .None)
 auth := canary_file(f, "auth.bin"); defer delete(auth)
 prekeys := canary_file(f, "prekeys.bin"); defer delete(prekeys)
 native := canary_file(f, "state.bin"); defer delete(native)
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 first := canary_id(s, 0); defer delete(first)
 second := canary_id(s, 1); defer delete(second)
 testing.expect(t, first != second && len(first) == 32 && len(second) == 32)
 testing.expect_value(t, s.canary.entries[0].intent.status, .Prepared)
 testing.expect_value(t, len(s.state.records), 1)
 if !canary_reopen(t, f) {return}
 testing.expect_value(t, string(s.canary.entries[0].intent.id[:32]), first)
 testing.expect_value(t, string(s.canary.entries[1].intent.id[:32]), second)
 for name, index in ([]string{"auth.bin", "prekeys.bin", "state.bin"}) {
  after := canary_file(f, name); defer delete(after)
  before := ([][]u8{auth, prekeys, native})[index]
  testing.expect(t, bytes.equal(before, after))
 }
}

@(test)
canary_queue_without_wire_is_unknown_and_prepared_cannot_skip_to_ack :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 testing.expect_value(t, canary_mark(s, 0, .Acknowledged, 100), .Intent_Mismatch)
 testing.expect_value(t, canary_mark(s, 0, .Queued, 101), .None)
 id := canary_id(s, 0); defer delete(id)
 if !canary_reopen(t, f) {return}
 testing.expect_value(t, string(s.canary.entries[0].intent.id[:32]), id)
 testing.expect_value(t, s.canary.entries[0].intent.status, .Queued)
 testing.expect_value(t, canary_admission(canary_options(), s).kind, .Canary_Unknown)
 testing.expect_value(t, canary_prepare_cycle(s, 4000), .Outbox_Unsafe)
 testing.expect_value(t, canary_mark(s, 0, .Prepared, 101), .Intent_Mismatch)
 testing.expect_value(t, s.canary.cycle, 1)
}

@(test)
canary_only_two_ordered_acks_advance_the_durable_schedule :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 testing.expect(t, canary_mark(s, 1, .Queued, 100) != .None)
 testing.expect_value(t, canary_mark(s, 0, .Queued, 101), .None)
 testing.expect_value(t, canary_mark(s, 0, .Acknowledged, 102), .None)
 testing.expect_value(t, s.canary.next_due, 0)
 testing.expect_value(t, canary_prepare_cycle(s, 5000), .Outbox_Unsafe)
 testing.expect_value(t, canary_mark(s, 1, .Queued, 103), .None)
 testing.expect_value(t, canary_mark(s, 1, .Acknowledged, 104), .None)
 testing.expect_value(t, s.canary.completed_at, 104)
 testing.expect_value(t, s.canary.next_due, 3704)
 if !canary_reopen(t, f) {return}
 testing.expect_value(t, canary_prepare_cycle(s, 3703), .Scope_Mismatch)
 testing.expect_value(t, canary_prepare_cycle(s, 3704), .None)
 testing.expect_value(t, s.canary.cycle, 2)
}

@(test)
canary_scope_and_fingerprint_conflicts_fail_without_ledger_replacement :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 before := canary_file(f, CANARY_FILE); defer delete(before)
 candidate := canary_clone(s); defer free(candidate)
 candidate.identity[0] ~= 1
 testing.expect_value(t, canary_commit(s, candidate), .Journal_Invalid)
 candidate^ = s.canary^
 candidate.nonce[0] ~= 1
 testing.expect_value(t, canary_commit(s, candidate), .Journal_Invalid)
 candidate^ = s.canary^
 candidate.subject[0] = 'X'
 testing.expect_value(t, canary_commit(s, candidate), .Scope_Mismatch)
 candidate^ = s.canary^
 candidate.target[0] = 'X'
 testing.expect_value(t, canary_commit(s, candidate), .Scope_Mismatch)
 unchanged := canary_file(f, CANARY_FILE); defer delete(unchanged)
 testing.expect(t, bytes.equal(before, unchanged))
 candidate^ = s.canary^
 candidate.entries[0].intent.fingerprint[0] =
  candidate.entries[0].intent.fingerprint[0] == 'a' ? 'b' : 'a'
 testing.expect_value(t, canary_commit(s, candidate), .None)
 testing.expect_value(t, canary_admission(canary_options(), s).storage, .Intent_Mismatch)
 after := canary_file(f, CANARY_FILE); defer delete(after)
 testing.expect(t, !bytes.equal(before, after))
}

canary_stage_text :: proc(t: ^testing.T, s: ^Storage, id: string) {
 payload, wire: [512]u8
 n, encoded := wa.text_message_encode(payload[:], {kind = .Conversation, text = qualification_text})
 testing.expect_value(t, encoded, .None)
 size, error := wa.binary_node_encode(wire[:],
  {tag = "message", attrs = {{"to", s.target_jid}, {"id", id}}})
 testing.expect_value(t, error.kind, .None)
 socket := wa.Socket{store = &s.state, config = {state_path = s.state_path}}
 testing.expect_value(t, wa.socket_group_outbound_commit(&socket, s.target_jid,
  "", id, payload[:n], wire[:size]).kind, .None)
}

@(test)
canary_pending_same_id_and_positive_witness_are_required_for_ack :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 testing.expect_value(t, canary_mark(s, 0, .Queued, 100), .None)
 id := canary_id(s, 0); defer delete(id)
 canary_stage_text(t, s, id)
 wire, found := wa.state_store_get(&s.state, .Outbound_Message, id)
 saved := make([]u8, len(wire)); defer delete(saved); copy(saved, wire)
 testing.expect(t, found && canary_pending_authorized(s, id, canary_options()))
 testing.expect_value(t, storage_scope_guard_offline(s, false, "synthetic canary"), .None)
 testing.expect_value(t, canary_admission(canary_options(), s).kind, .None)
 testing.expect_value(t, canary_prepare_cycle(s, 4000), .Outbox_Unsafe)
 observed := canary_observe(f.runner)
 testing.expect(t, observed[0] && !observed[1])
 testing.expect_value(t, canary_reconcile(f.runner, observed, 101).kind, .None)
 testing.expect_value(t, s.canary.entries[0].intent.status, .Queued)
 again, _ := wa.state_store_get(&s.state, .Outbound_Message, id)
 testing.expect(t, bytes.equal(saved, again))
 f.runner.socket = {phase = .Online, auth = &s.auth, prekeys = &s.prekeys,
  store = &s.state, config = {state_path = s.state_path}}
 _, ack := wa.socket_process_node(&f.runner.socket,
  {tag = "ack", attrs = {{"class", "message"}, {"id", id}}})
 testing.expect_value(t, ack.kind, .None)
 testing.expect_value(t, canary_reconcile(f.runner, {}, 102).kind, .None)
 testing.expect_value(t, s.canary.entries[0].intent.status, .Queued)
 testing.expect_value(t, canary_admission(canary_options(), s).kind, .Canary_Unknown)
 testing.expect_value(t, canary_reconcile(f.runner, observed, 103).kind, .None)
 testing.expect_value(t, s.canary.entries[0].intent.status, .Acknowledged)
 testing.expect_value(t, string(s.canary.entries[0].intent.id[:32]), id)
 testing.expect_value(t, s.canary.completed_at, 0)
}

@(test)
canary_gc_requires_both_ack_and_durable_native_content_absence :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 canary_ack_pair(t, s, 100)
 old := canary_id(s, 0); defer delete(old)
 // Synthetic retained content exercises ownership; no transport is involved.
 testing.expect_value(t, wa.state_store_set(&s.state, .Outbound_Content, old, []u8{9}).kind, .None)
 testing.expect_value(t, wa.state_store_save(&s.state, s.state_path).kind, .None)
 testing.expect_value(t, canary_prepare_cycle(s, 3700), .None)
 testing.expect_value(t, s.canary.count, 4)
 canary_ack_pair(t, s, 3700)
 testing.expect_value(t, wa.state_store_delete(&s.state, .Outbound_Content, old).kind, .None)
 candidate := canary_clone(s); defer free(candidate)
 canary_compact(s, candidate)
 testing.expect_value(t, candidate.count, 4)
 testing.expect_value(t, wa.state_store_save(&s.state, s.state_path).kind, .None)
 candidate^ = s.canary^
 canary_compact(s, candidate)
 testing.expect_value(t, candidate.count, 2)
 testing.expect_value(t, candidate.entries[0].cycle, 2)
 testing.expect_value(t, candidate.cycle, 2)
 testing.expect_value(t, canary_prepare_cycle(s, 7300), .None)
 testing.expect_value(t, s.canary.cycle, 3)
 testing.expect_value(t, s.canary.entries[int(s.canary.count)-2].cycle, 3)
}

@(test)
canary_full_retained_archive_fails_closed_without_reusing_a_cycle :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 candidate := canary_clone(s); defer free(candidate)
 candidate.count = CANARY_CAPACITY; candidate.cycle = CANARY_CAPACITY / 2
 candidate.first_completed_at = 100
 candidate.completed_at = 100; candidate.next_due = 3700
 for index in 0..<CANARY_CAPACITY {
  entry := &candidate.entries[index]
  testing.expect_value(t, canary_entry_create(s, entry, u64(index/2)+1,
   index%2 == 1, ""), .None)
  entry.intent.status = .Acknowledged
  if index%2 == 0 {
   testing.expect_value(t, wa.state_store_set(&s.state, .Outbound_Content,
    string(entry.intent.id[:32]), []u8{9}).kind, .None)
  }
 }
 testing.expect_value(t, wa.state_store_save(&s.state, s.state_path).kind, .None)
 committed := canary_commit(s, candidate)
 testing.expect_value(t, committed, .None); if committed != .None {return}
 before := canary_file(f, CANARY_FILE); defer delete(before)
 testing.expect_value(t, canary_prepare_cycle(s, 3700), .Limit)
 testing.expect_value(t, s.canary.cycle, CANARY_CAPACITY / 2)
 testing.expect_value(t, s.canary.count, CANARY_CAPACITY)
 after := canary_file(f, CANARY_FILE); defer delete(after)
 testing.expect(t, bytes.equal(before, after))
}

@(test)
canary_failed_atomic_write_keeps_prior_durable_ids_and_status :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 before := canary_file(f, CANARY_FILE); defer delete(before)
 id := canary_id(s, 0); defer delete(id)
 original := s.directory_fd
 s.directory_fd = -1
 testing.expect_value(t, canary_mark(s, 0, .Queued, 101), .IO)
 s.directory_fd = original
 testing.expect_value(t, s.canary.entries[0].intent.status, .Prepared)
 after := canary_file(f, CANARY_FILE); defer delete(after)
 testing.expect(t, bytes.equal(before, after))
 if !canary_reopen(t, f) {return}
 testing.expect_value(t, string(s.canary.entries[0].intent.id[:32]), id)
 testing.expect_value(t, s.canary.entries[0].intent.status, .Prepared)
}

// Child-only: abrupt exit bypasses cleanup, exercising durable boundaries.
@(test)
canary_checkpoint_child :: proc(_: ^testing.T) {
 stage := os.get_env("WA_CANARY_STAGE", context.allocator)
 if stage == "" {delete(stage); return}
 path := os.get_env("WA_CANARY_DIR", context.allocator)
 s := new(Storage)
 if storage_open(s, path, .Pair_New, "synthetic canary") != .None {os.exit(90)}
 if stage == "before" {os.exit(81)}
 if s.canary.count == 0 && canary_prepare_cycle(s, 100) != .None {os.exit(91)}
 if stage == "prepared" {os.exit(82)}
 if stage == "queued" {
  if canary_mark(s, 0, .Queued, 101) != .None {os.exit(92)}
  os.exit(83)
 }
 os.exit(99)
}

@(test)
canary_process_exit_at_durable_boundaries_keeps_ids_and_crypto :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 auth := canary_file(f, "auth.bin"); defer delete(auth)
 prekeys := canary_file(f, "prekeys.bin"); defer delete(prekeys)
 native := canary_file(f, "state.bin"); defer delete(native)
 id := ""; defer delete(id)
 executable, located := os.get_executable_path(context.allocator); defer delete(executable)
 testing.expect(t, located == nil); if located != nil {return}
 for stage, index in ([]string{"before", "prepared", "queued"}) {
  storage_close(s)
  stage_env := fmt.aprintf("WA_CANARY_STAGE=%s", stage); defer delete(stage_env)
  path_env := fmt.aprintf("WA_CANARY_DIR=%s", f.path); defer delete(path_env)
  process, started := os.process_start({
   command = {executable, "-tests:canary_checkpoint_child"}, env = {stage_env, path_env}})
  testing.expectf(t, started == nil, "child start error=%v executable=%q", started, executable)
  if started != nil {return}
  result, waited := os.process_wait(process)
  testing.expect(t, waited == nil)
  testing.expect_value(t, result.exit_code, 81+index)
  if !canary_reopen(t, f) {return}
  if index == 0 {testing.expect_value(t, s.canary.count, 0)}
  if index == 1 {
   testing.expect_value(t, s.canary.entries[0].intent.status, .Prepared)
   id = canary_id(s, 0)
  }
  if index == 2 {
   testing.expect_value(t, string(s.canary.entries[0].intent.id[:32]), id)
   testing.expect_value(t, s.canary.entries[0].intent.status, .Queued)
   testing.expect_value(t, canary_admission(canary_options(), s).kind, .Canary_Unknown)
  }
  for name, which in ([]string{"auth.bin", "prekeys.bin", "state.bin"}) {
   after := canary_file(f, name); defer delete(after)
   testing.expect(t, bytes.equal(([][]u8{auth, prekeys, native})[which], after))
  }
 }
}

@(test)
canary_partial_uncommitted_next_is_discarded_without_changing_durable_intent :: proc(
 t: ^testing.T,
) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 testing.expect_value(t, canary_prepare_cycle(s, 100), .None)
 id := canary_id(s, 0); defer delete(id)
 before := canary_file(f, CANARY_FILE); defer delete(before)
 testing.expect_value(t, storage_write(s, "canary.ledger.next", []u8{1, 2, 3}), .None)
 next := storage_path(f.path, "canary.ledger.next"); defer delete(next)
 testing.expect(t, os.exists(next))
 if !canary_reopen(t, f) {return}
 testing.expect(t, !os.exists(next))
 testing.expect_value(t, string(s.canary.entries[0].intent.id[:32]), id)
 testing.expect_value(t, s.canary.entries[0].intent.status, .Prepared)
 after := canary_file(f, CANARY_FILE); defer delete(after)
 testing.expect(t, bytes.equal(before, after))
}

@(test)
canary_due_revalidates_group_before_ids_and_not_due_does_not_query :: proc(t: ^testing.T) {
 f := canary_fixture(t); if f == nil {return}; defer canary_fixture_destroy(f)
 s := f.storage
 f.runner.options = canary_options()
 f.runner.deadline = time.tick_add(time.tick_now(), 120*time.Second)
 before := canary_file(f, CANARY_FILE); defer delete(before)
 native := canary_file(f, "state.bin"); defer delete(native)
 // An uninitialized native Socket cannot perform a group query or network I/O.
 testing.expect_value(t, canary_schedule(f.runner).kind, .Protocol)
 testing.expect_value(t, s.canary.count, 0)
 testing.expect_value(t, s.canary.cycle, 0)
 after := canary_file(f, CANARY_FILE); defer delete(after)
 native_after := canary_file(f, "state.bin"); defer delete(native_after)
 testing.expect(t, bytes.equal(before, after) && bytes.equal(native, native_after))
 now := canary_now()
 testing.expect_value(t, canary_prepare_cycle(s, now), .None)
 canary_ack_pair(t, s, now)
 pending := canary_file(f, CANARY_FILE); defer delete(pending)
 testing.expect_value(t, canary_schedule(f.runner).kind, .None)
 testing.expect_value(t, s.canary.count, 2)
 testing.expect_value(t, s.canary.cycle, 1)
 unchanged := canary_file(f, CANARY_FILE); defer delete(unchanged)
 testing.expect(t, bytes.equal(pending, unchanged))
}

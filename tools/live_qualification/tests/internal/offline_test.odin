package main

import wa "../.."
import "core:bytes"
import "core:os"
import "core:sync"
import "core:sys/posix"
import "core:testing"

probe_test_mutex: sync.Mutex

probe_test_directory :: proc() -> string {
 path, error := os.make_directory_temp("/tmp", "wa-qualification-offline-*", context.allocator)
 assert(error == nil)
 return path
}

probe_test_node :: proc(s: ^Storage, kind: wa.State_Record_Kind, id: string,
 node: wa.Binary_Node) {
 n, measured := wa.binary_node_encode(nil, node)
 assert(measured.kind == .Destination_Undersized)
 data := make([]u8, n); defer delete(data)
 _, encoded := wa.binary_node_encode(data, node); assert(encoded.kind == .None)
 assert(wa.state_store_set(&s.state, kind, id, data).kind == .None)
}

@(test)
probe_arguments_never_default_to_network_or_sending :: proc(t: ^testing.T) {
 empty, error := options_parse(nil)
 testing.expect_value(t, error.kind, .None)
 testing.expect_value(t, empty.command, .None)
 testing.expect(t, !empty.send)
 for input in ([][]string{{"--help"}, {"pair", "--preview"}, {"preview"}}) {
  parsed, failure := options_parse(input)
  testing.expect_value(t, failure.kind, .None); testing.expect(t, !parsed.send)
 }
 for input in ([][]string{{"pair"}, {"qualify"}, {"inspect"},
  {"pair", "--auth-dir", "/tmp/unused", "--group-subject", "offline", "--send"},
  {"qualify", "--auth-dir", "relative", "--group-subject", "offline"},
  {"qualify", "--auth-dir", "/tmp/unused", "--group-subject", "offline",
   "--timeout-seconds", "601"}}) {
  _, failure := options_parse(input); testing.expect(t, failure.kind != .None)
 }
 parsed, failure := options_parse({"qualify", "--auth-dir", "/tmp/unused",
  "--group-subject", "offline"})
 testing.expect_value(t, failure.kind, .None)
 testing.expect_value(t, parsed.command, .Qualify)
 testing.expect(t, !parsed.send)
}

@(test)
probe_storage_is_private_complete_exclusive_and_resumable :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "auth"); defer delete(path)
 s := new(Storage); defer free(s); defer storage_close(s)
 testing.expect_value(t, storage_open(s, path, .Pair_New, "offline"), .None)
 if !s.opened {return}
 testing.expect(t, s.opened && !s.auth.credentials.registered)
 info: posix.stat_t
 cpath := storage_cpath(path); defer delete(cpath)
 assert(posix.lstat(cpath, &info) == .OK)
 mask := transmute(posix.mode_t)posix._mode_t(0o7777)
 testing.expect_value(t, info.st_mode & mask, posix.mode_t{.IRUSR, .IWUSR, .IXUSR})
 for name in ([]string{"owner.lock", "generated-session.marker", "scope.journal",
  "auth.bin", "prekeys.bin", "state.bin"}) {
  file := storage_cpath(name); defer delete(file)
  assert(posix.fstatat(s.directory_fd, file, &info, {.SYMLINK_NOFOLLOW}) == .OK)
  testing.expect_value(t, info.st_mode & mask, posix.mode_t{.IRUSR, .IWUSR})
  testing.expect_value(t, info.st_nlink, 1)
 }
 other := new(Storage); defer free(other)
 testing.expect_value(t, storage_open(other, path, .Pair_New, "offline"), .Already_Open)
 lock_path := storage_path(path, "owner.lock"); defer delete(lock_path)
 script := "import os,fcntl,sys; f=os.open(sys.argv[1],os.O_RDWR)\n" +
  "try: fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n" +
  "except BlockingIOError: sys.exit(0)\n" + "sys.exit(1)"
 process, started := os.process_start({command = {"/usr/bin/python3", "-c", script, lock_path}})
 assert(started == nil)
 state, waited := os.process_wait(process)
 testing.expect(t, waited == nil && state.exit_code == 0, "second process must not own lock")
 identity := s.marker.identity
 storage_close(s)
 testing.expect_value(t, storage_open(s, path, .Pair_New, "offline"), .None)
 testing.expect(t, s.marker.identity == identity)
 storage_close(s)
 testing.expect(t, storage_open(s, path, .Qualify_Resume, "offline") != .None)
 git := storage_path(path, ".git"); defer delete(git)
 assert(os.make_directory(git, os.perm_number(0o700)) == nil)
 testing.expect_value(t, storage_open(s, path, .Pair_New, "offline"), .Directory_Unsafe)
}

@(test)
probe_storage_refuses_unmarked_git_and_incomplete_directories_without_repair :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "unmarked"); defer delete(path)
 assert(os.make_directory(path, os.perm_number(0o700)) == nil)
 sentinel := storage_path(path, "auth.bin"); defer delete(sentinel)
 assert(os.write_entire_file(sentinel, []u8{1, 2, 3}) == nil)
 s := new(Storage); defer free(s); defer storage_close(s)
 testing.expect(t, storage_open(s, path, .Pair_New, "offline") != .None)
 lock := storage_path(path, "owner.lock"); defer delete(lock)
 testing.expect(t, !os.exists(lock))
 data, read := os.read_entire_file(sentinel, context.allocator); assert(read == nil); defer delete(data)
 testing.expect(t, bytes.equal(data, []u8{1, 2, 3}))
 git := storage_path(root, ".git"); defer delete(git)
 assert(os.make_directory(git, os.perm_number(0o700)) == nil)
 fresh := storage_path(root, "forbidden"); defer delete(fresh)
 testing.expect_value(t, storage_open(s, fresh, .Pair_New, "offline"), .Directory_Unsafe)
 testing.expect(t, !os.exists(fresh))
 assert(os.remove(git) == nil)
 testing.expect_value(t, storage_open(s, fresh, .Pair_New, "offline"), .None)
 if !s.opened {return}
 storage_close(s)
 missing := storage_path(fresh, "prekeys.bin"); defer delete(missing)
 assert(os.remove(missing) == nil)
 testing.expect(t, storage_open(s, fresh, .Pair_New, "offline") != .None)
 testing.expect(t, !os.exists(missing), "incomplete stores must never regenerate identity")
}

@(test)
probe_intent_is_durable_stable_and_status_is_monotonic_before_side_effects :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "auth"); defer delete(path)
 s := new(Storage); defer free(s); defer storage_close(s)
 {failure := storage_open(s, path, .Pair_New, "offline")
 testing.expectf(t, failure == .None, "failure=%v root=%q path=%q exists=%v",
  failure, root, path, os.exists(root)); if failure != .None {return}}
 assert(storage_scope_target(s, "123@g.us") == .None)
 first, error := storage_journal_prepare(s, "text", "content-A")
 assert(error == .None); defer delete(first)
 testing.expect_value(t, len(first), 32)
 testing.expect(t, len(s.state.records) == 0, "preparation must not enqueue any message")
 status, status_error := storage_journal_status(s, "text", first)
 testing.expect(t, status_error == .None && status == .Prepared)
 testing.expect(t, storage_journal_mark(s, "text", first, .Acknowledged) != .None)
 assert(storage_journal_mark(s, "text", first, .Queued) == .None)
 testing.expect(t, storage_journal_mark(s, "text", first, .Prepared) != .None)
 assert(storage_journal_mark(s, "text", first, .Acknowledged) == .None)
 journal_before := s.journal
 _, mismatch := storage_journal_prepare(s, "text", "changed-content")
 testing.expect_value(t, mismatch, .Intent_Mismatch)
 testing.expect(t, bytes.equal(storage_bytes(&journal_before), storage_bytes(&s.journal)))
 testing.expect_value(t, storage_scope_target(s, "456@g.us"), .Scope_Mismatch)
 storage_close(s)
 {failure := storage_open(s, path, .Pair_New, "offline")
 testing.expectf(t, failure == .None, "failure=%v root=%q path=%q exists=%v",
  failure, root, path, os.exists(root)); if failure != .None {return}}
 second, repeated := storage_journal_prepare(s, "text", "content-A")
 assert(repeated == .None); defer delete(second)
 testing.expect(t, first == second && raw_data(first) != raw_data(second))
 after, after_error := storage_journal_status(s, "text", second)
 testing.expect(t, after_error == .None && after == .Acknowledged)
}

@(test)
probe_outbox_guard_rejects_other_groups_unknown_ids_and_pair_replay :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "auth"); defer delete(path)
 s := new(Storage); defer free(s); defer storage_close(s)
 {failure := storage_open(s, path, .Pair_New, "offline")
 testing.expectf(t, failure == .None, "failure=%v root=%q path=%q exists=%v",
  failure, root, path, os.exists(root)); if failure != .None {return}}
 assert(storage_scope_target(s, "123@g.us") == .None)
 id, error := storage_journal_prepare(s, "text", "content-A")
 assert(error == .None); defer delete(id)
 probe_test_node(s, .Outbound_Content, id,
  {tag = "saved", attrs = {{"to", "123@g.us"}}})
 probe_test_node(s, .Outbound_Message, id,
  {tag = "message", attrs = {{"to", "123@g.us"}, {"id", id}}})
 testing.expect_value(t, storage_scope_guard_offline(s, false, "offline"), .None)
 testing.expect_value(t, storage_scope_guard_offline(s, true, "offline"), .Outbox_Unsafe)
 testing.expect_value(t, storage_scope_guard_offline(s, false, "other"), .Scope_Mismatch)
 probe_test_node(s, .Outbound_Message, id,
  {tag = "message", attrs = {{"to", "456@g.us"}, {"id", id}}})
 testing.expect_value(t, storage_scope_guard_offline(s, false, "offline"), .Outbox_Unsafe)
 probe_test_node(s, .Outbound_Message, id,
  {tag = "message", attrs = {{"to", "123@g.us"}, {"id", "changed"}}})
 testing.expect_value(t, storage_scope_guard_offline(s, false, "offline"), .Outbox_Unsafe)
 probe_test_node(s, .Outbound_Message, id,
  {tag = "message", attrs = {{"to", "123@g.us"}, {"id", id}}})
 probe_test_node(s, .Outbound_Content, "unknown",
  {tag = "saved", attrs = {{"to", "123@g.us"}}})
 testing.expect_value(t, storage_scope_guard_offline(s, false, "offline"), .Outbox_Unsafe)
}

@(test)
probe_no_send_guard_rejects_even_owned_pending_messages_before_connection :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "auth"); defer delete(path)
 s := new(Storage); defer free(s); defer storage_close(s)
 {failure := storage_open(s, path, .Pair_New, "offline")
 testing.expect_value(t, failure, .None); if failure != .None {return}}
 assert(storage_scope_target(s, "123@g.us") == .None)
 id, error := storage_journal_prepare(s, "text", "content-A")
 assert(error == .None); defer delete(id)
 probe_test_node(s, .Outbound_Content, id,
  {tag = "saved", attrs = {{"to", "123@g.us"}}})
 probe_test_node(s, .Outbound_Message, id,
  {tag = "message", attrs = {{"to", "123@g.us"}, {"id", id}}})
 for command in ([]Command{.Inspect, .Qualify}) {
  testing.expect(t, runner_scope_guard({command = command,
   group_subject = "offline", send = false}, s).kind != .None)
 }
 testing.expect_value(t, runner_scope_guard({command = .Qualify,
  group_subject = "offline", send = true}, s).kind, .None)
}

@(test)
probe_target_selection_and_action_fingerprint_are_deterministic :: proc(t: ^testing.T) {
 groups := []wa.Socket_Group_Summary{
  {jid = "123@g.us", subject = "offline"},
  {jid = "456@g.us", subject = "different"},
 }
 selected, error := group_select(groups, "offline")
 testing.expect(t, error.kind == .None && selected == "123@g.us")
 _, missing := group_select(groups, "Offline")
 testing.expect_value(t, missing.kind, .Target_Not_Found)
 groups[1].subject = "offline"
 _, ambiguous := group_select(groups, "offline")
 testing.expect_value(t, ambiguous.kind, .Target_Ambiguous)
 fingerprint := action_fingerprint([]u8{97, 98, 99}); defer delete(fingerprint)
 testing.expect_value(t, fingerprint,
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
 bound := action_fingerprint_parts("application/pdf", []u8{97, 98, 99})
 defer delete(bound)
 testing.expect(t, fingerprint != bound)
 testing.expect(t, len(qualification_text) > 0)
 testing.expect(t, len(qualification_pdf) > 5 && qualification_pdf[:5] == "%PDF-")
}

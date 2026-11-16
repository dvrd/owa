package main

import wa "../.."
import "core:bytes"
import "core:crypto"
import "core:os"
import "core:sync"
import "core:testing"

RETARGET_TEST_FILES :: [5]string{
 "auth.bin", "prekeys.bin", "state.bin", "generated-session.marker", "scope.journal"}

retarget_test_snapshot :: proc(s: ^Storage) -> [5][]u8 {
 snapshot: [5][]u8
 for name, index in RETARGET_TEST_FILES {
  path := storage_path(s.directory, name); defer delete(path)
  content, error := os.read_entire_file(path, context.allocator)
  assert(error == nil); snapshot[index] = content
 }
 return snapshot
}

retarget_test_snapshot_clear :: proc(snapshot: ^[5][]u8) {
 for &data in snapshot {
  crypto.zero_explicit(raw_data(data), len(data)); delete(data); data = nil
 }
}

retarget_test_expect_files :: proc(t: ^testing.T, s: ^Storage,
 before: [5][]u8, journal_changes: bool) {
 after := retarget_test_snapshot(s); defer retarget_test_snapshot_clear(&after)
 for data, index in before {
  same := bytes.equal(data, after[index])
  testing.expect_value(t, same, index == 4 ? !journal_changes : true)
 }
}

@(test)
retarget_unused_scope_updates_only_journal_and_reopens_under_new_subject :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "session"); defer delete(path)
 s := new(Storage); defer free(s); defer storage_close(s)
 testing.expect_value(t, storage_open(s, path, .Pair_New, "original subject"), .None)
 if !s.opened {return}
 before := retarget_test_snapshot(s); defer retarget_test_snapshot_clear(&before)
 nonce, identity := s.marker.nonce, s.marker.identity
 testing.expect_value(t, storage_scope_retarget(s, "corrected subject"), .None)
 testing.expect_value(t, s.target_subject, "corrected subject")
 testing.expect(t, s.marker.nonce == nonce && s.marker.identity == identity)
 retarget_test_expect_files(t, s, before, true)
 storage_close(s)
 testing.expect_value(t, storage_open(s, path, .Pair_New, "original subject"), .Scope_Mismatch)
 testing.expect_value(t, storage_open(s, path, .Pair_New, "corrected subject"), .None)
 testing.expect(t, s.marker.nonce == nonce && s.marker.identity == identity)
 testing.expect_value(t, s.target_subject, "corrected subject")
}

@(test)
retarget_rejects_pending_content_prepared_intent_and_bound_target_without_writes :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 for mode in 0..<4 {
  root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
  path := storage_path(root, "session"); defer delete(path)
  s := new(Storage); defer free(s); defer storage_close(s)
  testing.expect_value(t, storage_open(s, path, .Pair_New, "original subject"), .None)
  if !s.opened {return}
  if mode < 2 {
   kind := mode == 0 ? wa.State_Record_Kind.Outbound_Message : .Outbound_Content
   assert(wa.state_store_set(&s.state, kind, "owned-test-id",
    transmute([]u8)string("synthetic retained record")).kind == .None)
   assert(wa.state_store_save(&s.state, s.state_path).kind == .None)
  } else if mode == 2 {
   candidate := s.journal
   candidate.count = 1
   entry := &candidate.intents[0]
   entry.kind_size = u32(copy(entry.kind[:], "text"))
   entry.fingerprint_size = u32(copy(entry.fingerprint[:], "synthetic fingerprint"))
   entry.id_size = u32(copy(entry.id[:], "00000000000000000000000000000000"))
   assert(storage_record_write(s, "scope.journal", &candidate) == .None)
   s.journal = candidate
  } else {assert(storage_scope_target(s, "123@g.us") == .None)}
  before := retarget_test_snapshot(s); defer retarget_test_snapshot_clear(&before)
  testing.expect(t, storage_scope_retarget(s, "corrected subject") != .None)
  testing.expect_value(t, s.target_subject, "original subject")
  retarget_test_expect_files(t, s, before, false)
  storage_close(s)
 }
}

@(test)
retarget_rejects_invalid_subjects_and_unowned_storage :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "session"); defer delete(path)
 s := new(Storage); defer free(s); defer storage_close(s)
 testing.expect_value(t, storage_open(s, path, .Pair_New, "original subject"), .None)
 if !s.opened {return}
 before := retarget_test_snapshot(s); defer retarget_test_snapshot_clear(&before)
 for subject in ([]string{"", "bad\x00subject", "bad\nsubject", "\xff"}) {
  testing.expect(t, storage_scope_retarget(s, subject) != .None)
  retarget_test_expect_files(t, s, before, false)
 }
 testing.expect_value(t, storage_scope_retarget(nil, "valid subject"), .Ownership)
 storage_close(s)
 testing.expect_value(t, storage_scope_retarget(s, "valid subject"), .Ownership)
}

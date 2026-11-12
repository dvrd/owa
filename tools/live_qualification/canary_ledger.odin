package main

import "core:sys/posix"

CANARY_MAGIC :: "ODWA-CANARY-v1"
CANARY_FILE :: "canary.ledger"
CANARY_CAPACITY :: 512
Canary_Entry :: struct {cycle: u64, intent: Storage_Intent}
Canary_Ledger :: struct {
 magic: [16]u8,
 identity, nonce: [32]u8,
 subject: [512]u8,
 target: [128]u8,
 subject_size, target_size, count: u32,
 cycle: u64,
 interval_seconds: i64,
 next_due, completed_at, first_completed_at: i64,
 entries: [CANARY_CAPACITY]Canary_Entry,
 checksum: [32]u8,
}

canary_ledger_load :: proc(s: ^Storage) -> Storage_Error {
 if error := canary_discard_temporary(s); error != .None {return error}
 path := storage_cpath(CANARY_FILE); defer delete(path)
 info: posix.stat_t
 if posix.fstatat(s.directory_fd, path, &info, {.SYMLINK_NOFOLLOW}) != .OK {
  return posix.errno() == .ENOENT ? .None : .IO
 }
 if !storage_safe_stat(info, false) {return .Directory_Unsafe}
 ledger, allocation := new(Canary_Ledger)
 if allocation != nil {return .Allocation}
 s.canary = ledger
 if error := storage_read(s, CANARY_FILE, storage_bytes(ledger)); error != .None {return error}
 return canary_ledger_validate(s)
}

canary_ledger_validate :: proc(s: ^Storage) -> Storage_Error {
 ledger := s.canary
 if ledger == nil {return .None}
 if !storage_record_valid(ledger) ||
  string(ledger.magic[:len(CANARY_MAGIC)]) != CANARY_MAGIC ||
  ledger.identity != s.marker.identity || ledger.nonce != s.marker.nonce ||
  ledger.subject_size > 512 || ledger.target_size > 128 ||
  ledger.count > CANARY_CAPACITY || ledger.count % 2 != 0 ||
  ledger.interval_seconds < 3600 || ledger.interval_seconds > 86400 ||
  ledger.completed_at < 0 || ledger.first_completed_at < 0 || ledger.next_due < 0 ||
  ledger.first_completed_at > ledger.completed_at ||
  ledger.completed_at > max(i64)-ledger.interval_seconds {
  return .Journal_Invalid
 }
 if string(ledger.subject[:ledger.subject_size]) != s.target_subject ||
  string(ledger.target[:ledger.target_size]) != s.target_jid || s.target_jid == "" {
  return .Scope_Mismatch
 }
 if ledger.count == 0 {
  valid := ledger.cycle == 0 && ledger.completed_at == 0 && ledger.next_due == 0 &&
   ledger.first_completed_at == 0
  return valid ? .None : .Journal_Invalid
 }
 previous: u64
 for index in 0..<int(ledger.count) {
  record := &ledger.entries[index]
  entry := &record.intent
  kind := index % 2 == 0 ? "text" : "pdf"
  if entry.kind_size != u32(len(kind)) || string(entry.kind[:entry.kind_size]) != kind ||
   entry.id_size != 32 || entry.fingerprint_size != 64 ||
   u8(entry.status) > u8(Journal_Status.Acknowledged) || record.cycle == 0 ||
   record.cycle > ledger.cycle {return .Journal_Invalid}
  if index % 2 == 0 {
   if record.cycle <= previous {return .Journal_Invalid}; previous = record.cycle
  } else if record.cycle != previous {return .Journal_Invalid}
  if record.cycle < ledger.cycle && entry.status != .Acknowledged {return .Journal_Invalid}
  id := string(entry.id[:entry.id_size])
  for old in 0..<index {
   if id == string(ledger.entries[old].intent.id[:32]) {return .Journal_Invalid}
  }
  for old in 0..<int(s.journal.count) {
   if id == string(s.journal.intents[old].id[:s.journal.intents[old].id_size]) {
    return .Journal_Invalid
   }
  }
 }
 first := int(ledger.count)-2
 text_status := ledger.entries[first].intent.status
 pdf_status := ledger.entries[first+1].intent.status
 if pdf_status != .Prepared && text_status != .Acknowledged {return .Journal_Invalid}
 complete := text_status == .Acknowledged && pdf_status == .Acknowledged
 if complete && (ledger.completed_at == 0 || ledger.first_completed_at == 0 ||
  ledger.next_due != ledger.completed_at+ledger.interval_seconds) {return .Journal_Invalid}
 if !complete && ledger.next_due != 0 {return .Journal_Invalid}
 if ledger.cycle > 1 && ledger.first_completed_at == 0 {return .Journal_Invalid}
 return previous == ledger.cycle ? .None : .Journal_Invalid
}

canary_find :: proc(s: ^Storage, id: string) -> (int, bool) {
 if s.canary == nil {return 0, false}
 for index in 0..<int(s.canary.count) {
  if string(s.canary.entries[index].intent.id[:32]) == id {return index, true}
 }
 return 0, false
}

canary_commit :: proc(s: ^Storage, candidate: ^Canary_Ledger) -> Storage_Error {
 if s == nil || !s.opened || storage_owner != s || s.canary == nil {return .Ownership}
 candidate.checksum = {}
 candidate.checksum = storage_digest(storage_bytes(candidate))
 old := s.canary
 s.canary = candidate
 validated := canary_ledger_validate(s)
 s.canary = old
 if validated != .None {return validated}
 if error := storage_record_write(s, CANARY_FILE, candidate); error != .None {return error}
 s.canary^ = candidate^
 return canary_ledger_validate(s)
}

canary_clone :: proc(s: ^Storage) -> ^Canary_Ledger {
 candidate, allocation := new(Canary_Ledger)
 if allocation != nil {return nil}
 if s.canary != nil {candidate^ = s.canary^}
 return candidate
}

// A .next file was never the committed sidecar. It cannot authorize a send or ACK.
// Discard only this private, bounded regular temporary under the held owner lock.
canary_discard_temporary :: proc(s: ^Storage) -> Storage_Error {
 path := storage_cpath(CANARY_FILE+".next"); defer delete(path)
 info: posix.stat_t
 if posix.fstatat(s.directory_fd, path, &info, {.SYMLINK_NOFOLLOW}) != .OK {
  return posix.errno() == .ENOENT ? .None : .IO
 }
 if !storage_safe_stat(info, false) || info.st_size < 0 ||
  info.st_size > size_of(Canary_Ledger) {return .Directory_Unsafe}
 if posix.unlinkat(s.directory_fd, path, {}) != .OK {return .IO}
 return posix.fsync(s.directory_fd) == .OK ? .None : .IO
}

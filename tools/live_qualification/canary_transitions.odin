package main

import wa "../.."
import "core:crypto"
import "core:encoding/hex"

canary_ledger_create :: proc(s: ^Storage, interval: int) -> Storage_Error {
 if s == nil || !s.opened || storage_owner != s {return .Ownership}
 if interval < 3600 || interval > 86400 || s.target_jid == "" {return .Scope_Mismatch}
 if s.canary != nil {
  return s.canary.interval_seconds == i64(interval) ? .None : .Intent_Mismatch
 }
 ledger := canary_clone(s)
 if ledger == nil {return .Allocation}
 defer free(ledger)
 copy(ledger.magic[:], CANARY_MAGIC)
 ledger.identity, ledger.nonce = s.marker.identity, s.marker.nonce
 ledger.subject_size = u32(copy(ledger.subject[:], s.target_subject))
 ledger.target_size = u32(copy(ledger.target[:], s.target_jid))
 ledger.interval_seconds = i64(interval)
 stored, allocation := new(Canary_Ledger)
 if allocation != nil {return .Allocation}
 s.canary = stored
 error := canary_commit(s, ledger)
 if error != .None {free(s.canary); s.canary = nil}
 return error
}

canary_pending :: proc(s: ^Storage) -> bool {
 for record in s.state.records {if record.kind == .Outbound_Message {return true}}
 return false
}

canary_pair_retained :: proc(s: ^Storage, pair: []Canary_Entry) -> bool {
 for index in 0..<2 {
  entry := pair[index].intent
  id := string(entry.id[:32])
  if _, exists := wa.state_store_get(&s.state, .Outbound_Content, id); exists {return true}
  if _, exists := wa.state_store_get(&s.state, .Outbound_Message, id); exists {return true}
 }
 return false
}

// Metadata-only compaction; native seven-day pruning alone owns content lifetime.
canary_compact :: proc(s: ^Storage, candidate: ^Canary_Ledger) {
 if s.state.revision != s.state.durable_revision {return}
 kept := 0
 for index := 0; index < int(candidate.count); index += 2 {
  pair := &candidate.entries[index]
  remove := pair.cycle < candidate.cycle && pair.intent.status == .Acknowledged &&
   candidate.entries[index+1].intent.status == .Acknowledged &&
   !canary_pair_retained(s, candidate.entries[index:index+2])
  if remove {continue}
  if kept != index {
   candidate.entries[kept] = candidate.entries[index]
   candidate.entries[kept+1] = candidate.entries[index+1]
  }
  kept += 2
 }
 for index in kept..<int(candidate.count) {candidate.entries[index] = {}}
 candidate.count = u32(kept)
}

canary_entry_create :: proc(s: ^Storage, entry: ^Canary_Entry, cycle: u64,
 document: bool, other_id: string) -> Storage_Error {
 kind := document ? "pdf" : "text"
 fingerprint := action_fingerprint_parts(action_metadata(document),
  transmute([]u8)(document ? qualification_pdf : qualification_text))
 if fingerprint == "" {return .Allocation}; defer delete(fingerprint)
 entry.cycle = cycle
 entry.intent.kind_size = u32(copy(entry.intent.kind[:], kind))
 entry.intent.fingerprint_size = u32(copy(entry.intent.fingerprint[:], fingerprint))
 for _ in 0..<4 {
  random: [16]u8; crypto.rand_bytes(random[:])
  encoded, error := hex.encode(random[:]); if error != nil {return .Allocation}
  id := string(encoded)
  _, known := canary_find(s, id)
  for index in 0..<int(s.journal.count) {
   known = known || id == string(s.journal.intents[index].id[:s.journal.intents[index].id_size])
  }
  if !known && id != other_id {
   copy(entry.intent.id[:32], encoded); entry.intent.id_size = 32
   delete(encoded); return .None
  }
  delete(encoded)
 }
 return .Entropy
}

canary_prepare_cycle :: proc(s: ^Storage, now: i64) -> Storage_Error {
 ledger := s.canary
 if ledger == nil || now < ledger.completed_at || now < 0 ||
  now > max(i64)-ledger.interval_seconds {return .Scope_Mismatch}
 if canary_pending(s) {return .Outbox_Unsafe}
 if ledger.count > 0 {
  for index in int(ledger.count)-2..<int(ledger.count) {
   if ledger.entries[index].intent.status != .Acknowledged {return .Outbox_Unsafe}
  }
  if now < ledger.next_due {return .Scope_Mismatch}
 }
 if ledger.cycle == max(u64) {return .Limit}
 candidate := canary_clone(s); if candidate == nil {return .Allocation}; defer free(candidate)
 canary_compact(s, candidate)
 if candidate.count > CANARY_CAPACITY-2 {return .Limit}
 candidate.cycle += 1; candidate.next_due = 0
 first := int(candidate.count)
 for offset in 0..<2 {
  other := offset == 0 ? "" : string(candidate.entries[first].intent.id[:32])
  if error := canary_entry_create(s, &candidate.entries[first+offset], candidate.cycle,
   offset == 1, other); error != .None {return error}
 }
 candidate.count += 2
 return canary_commit(s, candidate)
}

canary_mark :: proc(s: ^Storage, index: int, status: Journal_Status, now: i64) -> Storage_Error {
 if s.canary == nil || index < int(s.canary.count)-2 || index >= int(s.canary.count) {
  return .Intent_Mismatch
 }
 old := s.canary.entries[index].intent.status
 if status < old || u8(status) > u8(Journal_Status.Acknowledged) ||
  old == .Prepared && status == .Acknowledged {return .Intent_Mismatch}
 if status == old {return .None}
 if now < s.canary.completed_at || now < 0 ||
  now > max(i64)-s.canary.interval_seconds {return .Scope_Mismatch}
 candidate := canary_clone(s); if candidate == nil {return .Allocation}; defer free(candidate)
 candidate.entries[index].intent.status = status
 first := int(candidate.count)-2
 if candidate.entries[first].intent.status == .Acknowledged &&
  candidate.entries[first+1].intent.status == .Acknowledged {
  if candidate.first_completed_at == 0 {candidate.first_completed_at = now}
  candidate.completed_at = now
  candidate.next_due = now + candidate.interval_seconds
 }
 return canary_commit(s, candidate)
}

package main

import wa "../.."
import "core:time"

canary_enabled :: proc(options: Options) -> bool {
 return options.command == .Watch && options.send && options.allow_scoped_retries &&
  options.canary_interval_seconds >= 3600
}

canary_pending_authorized :: proc(s: ^Storage, id: string, options: Options) -> bool {
 if !canary_enabled(options) {return false}
 index, found := canary_find(s, id)
 return found && index >= int(s.canary.count)-2 &&
  s.canary.entries[index].intent.status == .Queued
}

canary_admission :: proc(options: Options, s: ^Storage) -> Tool_Error {
 if error := canary_ledger_validate(s); error != .None {return {kind = .Journal, storage = error}}
 if s.canary == nil {return {}}
 if canary_enabled(options) && s.canary.interval_seconds != i64(options.canary_interval_seconds) {
  return {kind = .Journal, storage = .Intent_Mismatch}
 }
 for index in 0..<int(s.canary.count) {
  entry := &s.canary.entries[index].intent
  expected := action_fingerprint_parts(action_metadata(index % 2 == 1),
   transmute([]u8)(index % 2 == 1 ? qualification_pdf : qualification_text))
  if expected == "" {return {kind = .Allocation}}
  matches := expected == string(entry.fingerprint[:entry.fingerprint_size]); delete(expected)
  if !matches {return {kind = .Journal, storage = .Intent_Mismatch}}
  id := string(entry.id[:32])
  _, pending := wa.state_store_get(&s.state, .Outbound_Message, id)
  _, retained := wa.state_store_get(&s.state, .Outbound_Content, id)
  if entry.status == .Prepared && (pending || retained) {return {kind = .Scope}}
  if entry.status != .Acknowledged && !canary_enabled(options) {return {kind = .Scope}}
  if entry.status == .Queued && !pending && !options.retry_unknown_canary {
   return {kind = .Canary_Unknown}
  }
 }
 return {}
}

canary_observe :: proc(runner: ^Runner) -> [2]bool {
 result: [2]bool
 ledger := runner.storage.canary
 if ledger == nil || ledger.count == 0 {return result}
 first := int(ledger.count)-2
 for offset in 0..<2 {
  entry := &ledger.entries[first+offset].intent
  if entry.status != .Queued {continue}
  _, result[offset] = wa.state_store_get(&runner.storage.state, .Outbound_Message,
   string(entry.id[:32]))
 }
 return result
}

// A successful native operation can consume a positive ACK while doing an IQ.
// Only a wire observed present BEFORE that operation can establish this witness.
canary_reconcile :: proc(runner: ^Runner, observed: [2]bool, now: i64) -> Tool_Error {
 ledger := runner.storage.canary
 if ledger == nil || ledger.count == 0 {return {}}
 first := int(ledger.count)-2
 for offset in 0..<2 {
  entry := &ledger.entries[first+offset].intent
  if !observed[offset] || entry.status != .Queued {continue}
  if _, pending := wa.state_store_get(&runner.storage.state, .Outbound_Message,
   string(entry.id[:32])); pending {continue}
  if error := canary_mark(&runner.storage, first+offset, .Acknowledged, now); error != .None {
   return {kind = .Journal, storage = error}
  }
  phase_print(offset == 0 ? .CANARY_TEXT_ACKED : .CANARY_PDF_ACKED)
  if offset == 1 {
   runner.canary_due_tick = time.tick_add(time.tick_now(),
    time.Duration(ledger.interval_seconds)*time.Second)
   runner.canary_due_set = true
   runner.canary_completed += 1; phase_print(.CANARY_COMPLETE)
   canary_status(runner)
  }
 }
 return {}
}

canary_has_unknown :: proc(s: ^Storage) -> bool {
 if s.canary == nil || s.canary.count < 2 {return false}
 for index in int(s.canary.count)-2..<int(s.canary.count) {
  entry := &s.canary.entries[index].intent
  if entry.status != .Queued {continue}
  if _, pending := wa.state_store_get(&s.state, .Outbound_Message,
   string(entry.id[:32])); !pending {return true}
 }
 return false
}

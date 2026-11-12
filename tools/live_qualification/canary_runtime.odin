package main

import wa "../.."
import "core:time"

canary_now :: proc() -> i64 {return time.now()._nsec / 1_000_000_000}

canary_schedule :: proc(runner: ^Runner) -> Tool_Error {
 if !canary_enabled(runner.options) {return {}}
 s := &runner.storage
 if error := canary_ledger_create(s, runner.options.canary_interval_seconds); error != .None {
  return {kind = .Journal, storage = error}
 }
 now := canary_now()
 if now < s.canary.completed_at {return {kind = .Journal, storage = .Scope_Mismatch}}
 count := int(s.canary.count)
 complete := count == 0 || (s.canary.entries[count-2].intent.status == .Acknowledged &&
  s.canary.entries[count-1].intent.status == .Acknowledged)
 if complete {
  if runner.canary_due_set && time.tick_diff(time.tick_now(), runner.canary_due_tick) > 0 {
   return {}
  }
  if runner.canary_completed >= 48 {return {kind = .Storage, storage = .Limit}}
  if now < s.canary.next_due || canary_pending(s) || remaining(runner) < 90*time.Second {
   return {}
  }
 }
 if remaining(runner) < 90*time.Second {return {}}
 observed := canary_observe(runner)
 refreshed := runner_target(runner)
 if refreshed.kind != .None {return refreshed}
 reconciled := canary_reconcile(runner, observed, canary_now())
 if reconciled.kind != .None {return reconciled}
 if complete {
  if canary_pending(s) || remaining(runner) < 60*time.Second {return {}}
  if error := canary_prepare_cycle(s, canary_now()); error != .None {
   return {kind = .Journal, storage = error}
  }
  phase_print(.CANARY_PREPARED)
 }
 for offset in 0..<2 {
  if error := canary_send(runner, offset); error.kind != .None {return error}
 }
 return {}
}

canary_send :: proc(runner: ^Runner, offset: int) -> Tool_Error {
 s := &runner.storage
 index := int(s.canary.count)-2+offset
 entry := &s.canary.entries[index].intent
 if entry.status == .Acknowledged {return {}}
 id := string(entry.id[:32])
 if entry.status == .Queued {
  if _, pending := wa.state_store_get(&s.state, .Outbound_Message, id); !pending {
   if !runner.options.retry_unknown_canary {
    phase_print(.CANARY_UNKNOWN); return {kind = .Canary_Unknown}
   }
   // Explicit recovery applies only to the already-loaded unknown item.
   runner.options.retry_unknown_canary = false
  }
 }
 if error := canary_mark(s, index, .Queued, canary_now()); error != .None {
  return {kind = .Journal, storage = error}
 }
 if error := runner_query_budget(runner); error.kind != .None {return error}
 sent: string
 error: wa.Socket_Error
 if offset == 0 {
  sent, error = wa.socket_send_text(&runner.socket, runner.target_jid, qualification_text,
   message_id = id)
 } else {
  sent, error = wa.socket_send_document(&runner.socket, runner.target_jid,
   transmute([]u8)qualification_pdf, "mesa-qualification.pdf", "Synthetic PDF transport check.",
   "application/pdf", id)
 }
 defer delete(sent)
 if error.kind != .None {return {kind = .Send, socket = error}}
 if sent != id {return {kind = .Protocol}}
 return canary_ack_wait(runner, index)
}

canary_ack_wait :: proc(runner: ^Runner, index: int) -> Tool_Error {
 s := &runner.storage
 id := string(s.canary.entries[index].intent.id[:32])
 if _, pending := wa.state_store_get(&s.state, .Outbound_Message, id); !pending {
  return {kind = .Canary_Unknown}
 }
 deadline := time.tick_add(time.tick_now(), min(remaining(runner), 15*time.Second))
 for time.tick_diff(time.tick_now(), deadline) > 0 {
  observed := canary_observe(runner)
  restart, error := runner_pump(runner)
  if error.kind != .None {return error}
  if restart {return {kind = .Protocol}}
  reconciled := canary_reconcile(runner, observed, canary_now())
  if reconciled.kind != .None {return reconciled}
  if s.canary.entries[index].intent.status == .Acknowledged {return {}}
 }
 return {kind = .Timeout}
}

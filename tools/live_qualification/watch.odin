package main

import wa "../.."
import "core:crypto"
import "core:fmt"
import "core:os"
import "core:time"

watch_retryable :: proc(error: Tool_Error) -> bool {
 if error.kind != .Connect && error.kind != .Protocol {return false}
 socket := error.socket
 if socket.kind == .Websocket_Failed {
  return socket.websocket.kind == .TLS_Failed && socket.websocket.tls.kind == .TCP_Dial_Failed
 }
 if socket.kind != .Session_Failed {return false}
 if socket.session.kind == .Connection_Lost {return true}
 if socket.session.kind != .Client_Failed {return false}
 client := socket.session.client
 if client.kind == .Peer_Closed {return true}
 if client.kind != .Transport_Failed {return false}
 frame := client.transport
 if frame.kind == .Peer_Closed {return true}
 stream := frame.websocket.stream
 return stream.kind == .EOF || stream.transport.kind == .Timeout ||
  stream.tls.transport.kind == .Timeout || stream.tls.kind == .EOF ||
  stream.tls.kind == .Unexpected_EOF
}

watch_backoff :: proc(attempt: int, jitter: u16) -> time.Duration {
 seconds := int(1) << uint(min(max(attempt, 0), 5))
 return time.Duration(min(seconds, 30))*time.Second +
  time.Duration(jitter % 501)*time.Millisecond
}

watch_wait :: proc(runner: ^Runner, attempt: int) {
 random: [2]u8
 crypto.rand_bytes(random[:])
 delay := watch_backoff(attempt, u16(random[0]) | u16(random[1])<<8)
 deadline := time.tick_add(time.tick_now(), min(delay, remaining(runner)))
 for time.tick_diff(time.tick_now(), deadline) > 0 {
  time.sleep(min(time.tick_diff(time.tick_now(), deadline), 100*time.Millisecond))
 }
}

watch_state_bounded :: proc(storage: ^Storage) -> bool {
 if len(storage.state.records) > 49152 {return false}
 total := 0
 for record in storage.state.records {
  total += len(record.name) + len(record.data)
  if total > 48 << 20 {return false}
 }
 return true
}

watch_health :: proc(start: time.Tick, reconnects: int) {
 seconds := int(time.tick_diff(start, time.tick_now()) / time.Second)
 fmt.printf("WATCH_HEALTH uptime_seconds=%d reconnects=%d\n", seconds, reconnects)
 os.flush(os.stdout)
}

watch_connected :: proc(runner: ^Runner, start: time.Tick, reconnects: int) -> Tool_Error {
 next_health := time.tick_now()
 for remaining(runner) > 0 {
  if time.tick_diff(time.tick_now(), next_health) <= 0 {
   if !watch_state_bounded(&runner.storage) {return {kind = .Storage, storage = .Limit}}
   watch_health(start, reconnects)
   next_health = time.tick_add(time.tick_now(), 60*time.Second)
  }
  if error := canary_schedule(runner); error.kind != .None {return error}
  observed := canary_observe(runner)
  restart, error := runner_pump(runner)
  if error.kind == .None {error = canary_reconcile(runner, observed, canary_now())}
  if error.kind == .Timeout && remaining(runner) <= 0 {return {}}
  if error.kind != .None {return error}
  if restart {return {kind = .Protocol}}
 }
 return {}
}

runner_watch :: proc(runner: ^Runner) -> Tool_Error {
 start := time.tick_now()
 reconnects := 0
 failures := 0
 for remaining(runner) > 0 {
  observed := canary_observe(runner)
  error := runner_online(runner)
  if error.kind == .None {error = canary_reconcile(runner, observed, canary_now())}
  if error.kind == .None {
   observed = canary_observe(runner)
   error = runner_target(runner)
   if error.kind == .None {error = canary_reconcile(runner, observed, canary_now())}
   if error.kind == .None && (canary_enabled(runner.options) || runner.storage.canary != nil) {
    canary_status(runner)
   }
  }
  if error.kind == .None {
   connected_at := time.tick_now()
   error = watch_connected(runner, start, reconnects)
   if time.tick_diff(connected_at, time.tick_now()) >= 60*time.Second {failures = 0}
  }
  if error.kind == .None && remaining(runner) <= 0 {break}
  if !watch_retryable(error) || failures + 1 >= 8 || reconnects >= 1000 {return error}
  wa.socket_close(&runner.socket)
  runner.socket = {}
  phase_print(.WATCH_RECONNECTING)
  watch_wait(runner, failures)
  failures += 1; reconnects += 1
 }
 phase_print(.WATCH_COMPLETE)
 return {}
}

watch_scope_guard :: proc(options: Options, storage: ^Storage,
 allow_pending: bool) -> Tool_Error {
 if error := canary_admission(options, storage); error.kind != .None {return error}
 if error := storage_scope_guard_offline(storage, false, options.group_subject);
  error != .None {return {kind = .Scope, storage = error}}
 for index in 0..<int(storage.journal.count) {
  if storage.journal.intents[index].status != .Acknowledged {
   return {kind = .Scope, storage = .Outbox_Unsafe}
  }
 }
 if options.allow_scoped_retries && storage.target_jid == "" {
  return {kind = .Scope, storage = .Scope_Mismatch}
 }
 for record in storage.state.records {
  permitted_canary := canary_pending_authorized(storage, record.name, options)
  if record.kind == .Outbound_Message &&
   (!options.allow_scoped_retries || (!allow_pending && !permitted_canary)) {
   return {kind = .Scope, storage = .Outbox_Unsafe}
  }
  if record.kind == .Outbound_Content && !options.allow_scoped_retries {
   return {kind = .Scope, storage = .Outbox_Unsafe}
  }
 }
 return {}
}

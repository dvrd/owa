package main

import wa "../.."
import "core:time"

remaining :: proc(runner: ^Runner) -> time.Duration {
 return time.tick_diff(time.tick_now(), runner.deadline)
}

runner_read_scoped :: proc(socket: ^wa.Socket) -> (wa.Socket_Event, wa.Socket_Error) {
 socket.read_deadline_scopes += 1
 defer socket.read_deadline_scopes -= 1
 return wa.socket_read(socket)
}

runner_poll_event :: proc(runner: ^Runner) -> (wa.Socket_Event, Tool_Error) {
 if remaining(runner) <= 0 {return {}, {kind = .Timeout}}
 ready, poll_error := wa.socket_poll(&runner.socket, 100 * time.Millisecond)
 if poll_error.kind != .None {return {}, {kind = .Protocol, socket = poll_error}}
 if !ready {return {}, {}}
 deadline := time.time_add(time.now(), min(remaining(runner), 5 * time.Second))
 if error := wa.socket_read_deadline(&runner.socket, deadline); error.kind != .None {
  return {}, {kind = .Protocol, socket = error}
 }
 event, read_error := runner_read_scoped(&runner.socket)
 if read_error.kind != .None {return {}, {kind = .Protocol, socket = read_error}}
 if error := wa.socket_read_deadline(&runner.socket, {}); error.kind != .None {
  if event.message != nil {wa.socket_message_destroy(event.message)}
  return {}, {kind = .Protocol, socket = error}
 }
 return event, {}
}

runner_event :: proc(runner: ^Runner, event: wa.Socket_Event) -> (bool, Tool_Error) {
 switch event.kind {
 case .QR:
  if runner.options.command != .Pair {return false, {kind = .Unexpected_Pairing}}
  return false, qr_write(runner, event.qr)
 case .Paired: phase_print(.PAIRED)
 case .Restart_Required: return true, {}
 case .Online: phase_print(.ONLINE)
 case .Message:
  // No business handlers run. Keep durable inbox work under this owned session.
  wa.socket_message_destroy(event.message)
 case .None, .Node:
 }
 return false, {}
}

runner_pump_inner :: proc(runner: ^Runner) -> (bool, Tool_Error) {
 if remaining(runner) <= 0 {return false, {kind = .Timeout}}
 event, tick_error := wa.socket_tick(&runner.socket, time.now())
 if tick_error.kind != .None {return false, {kind = .Protocol, socket = tick_error}}
 if restart, error := runner_event(runner, event); restart || error.kind != .None {
  return restart, error
 }
 observed, read_error := runner_poll_event(runner)
 if read_error.kind != .None {return false, read_error}
 return runner_event(runner, observed)
}

runner_online :: proc(runner: ^Runner) -> Tool_Error {
 for attempt in 0..<3 {
  if remaining(runner) <= 0 {return {kind = .Timeout}}
  if error := runner_scope_guard(runner.options, &runner.storage); error.kind != .None {
   return error
  }
  phase_print(.CONNECTING)
  connected := wa.socket_connect(&runner.socket, &runner.storage.auth,
   &runner.storage.prekeys, &runner.storage.state, runner.config)
  if connected.kind != .None {return {kind = .Connect, socket = connected}}
  for remaining(runner) > 0 {
   restart, error := runner_pump(runner)
   if error.kind != .None {return error}
   if restart {break}
   if runner.socket.phase == .Online {return {}}
  }
  wa.socket_close(&runner.socket)
  runner.socket = {}
  runner.restarts = attempt + 1
  phase_print(.RECONNECTING)
 }
 return {kind = .Timeout}
}

hold_budget :: proc(hold_seconds: int, available: time.Duration) -> time.Duration {
 if hold_seconds <= 0 || available <= 0 {return 0}
 return min(time.Duration(min(hold_seconds, 300)) * time.Second, available)
}

runner_hold :: proc(runner: ^Runner) -> Tool_Error {
 if runner.options.hold_seconds == 0 {return {}}
 budget := hold_budget(runner.options.hold_seconds, remaining(runner))
 if budget <= 0 {return {kind = .Timeout}}
 outer_deadline := runner.deadline
 runner.deadline = time.tick_add(time.tick_now(), budget)
 if runner.deadline._nsec > outer_deadline._nsec {runner.deadline = outer_deadline}
 defer runner.deadline = outer_deadline
 phase_print(.CONNECTED_HOLD)
 for remaining(runner) > 0 {
  restart, error := runner_pump(runner)
  if error.kind == .Timeout && remaining(runner) <= 0 {break}
  if read_timeout(error) && remaining(runner) <= 0 {
   error.kind = .Timeout; return error
  }
  if error.kind != .None {return error}
  // A restart invalidates this connected hold. Never silently reconnect/replay.
  if restart {return {kind = .Protocol}}
 }
 if time.tick_diff(time.tick_now(), outer_deadline) <= 0 {return {kind = .Timeout}}
 return {}
}

read_timeout :: proc(error: Tool_Error) -> bool {
 if error.kind != .Protocol || error.socket.kind != .Session_Failed ||
  error.socket.session.kind != .Client_Failed {return false}
 stream := error.socket.session.client.transport.websocket.stream
 return stream.transport.kind == .Timeout || stream.tls.transport.kind == .Timeout
}

runner_pump :: proc(runner: ^Runner) -> (bool, Tool_Error) {
 if remaining(runner) <= 0 {return false, {kind = .Timeout}}
 budget := min(remaining(runner), 5 * time.Second)
 timeout := runner.socket.config.query_timeout
 runner.socket.config.query_timeout = budget
 defer runner.socket.config.query_timeout = timeout
 deadline := time.time_add(time.now(), budget)
 if error := wa.socket_write_deadline(&runner.socket, deadline); error.kind != .None {
  wa.socket_close(&runner.socket)
  return false, {kind = .Protocol, socket = error}
 }
 restart, error := runner_pump_inner(runner)
 if error.kind != .None {
  wa.socket_close(&runner.socket)
  return restart, error
 }
 if cleared := wa.socket_write_deadline(&runner.socket, {}); cleared.kind != .None {
  wa.socket_close(&runner.socket)
  return false, {kind = .Protocol, socket = cleared}
 }
 return restart, {}
}

package main

import wa "../.."
import surf "../../../surf"
import "core:testing"
import "core:time"

Deadline_Probe :: struct {calls: int, last: time.Time}

deadline_probe_set :: proc(data: rawptr, value: time.Time) -> surf.WebSocket_Stream_Error {
 trace := cast(^Deadline_Probe)data
 trace.calls += 1; trace.last = value
 return {}
}

deadline_probe_close :: proc(_: rawptr) -> surf.WebSocket_Stream_Error {return {}}

@(test)
probe_scoped_read_preserves_outer_deadline_and_restores_scope_on_all_returns :: proc(t: ^testing.T) {
 trace: Deadline_Probe
 socket: wa.Socket
 socket.phase = .Online
 socket.websocket = {phase = .Open, allocator = context.allocator,
  stream = {data = &trace, close = deadline_probe_close, abort = deadline_probe_close,
   set_read_deadline = deadline_probe_set}}
 outer := time.time_add(time.now(), 5*time.Second)
 assert(wa.socket_read_deadline(&socket, outer).kind == .None)
 message := new(wa.Socket_Message)
 message.allocator = context.allocator
 socket.queue = make([dynamic]^wa.Socket_Message)
 append(&socket.queue, message)
 event, success := runner_read_scoped(&socket)
 testing.expect_value(t, success.kind, .None)
 testing.expect(t, event.message == message)
 testing.expect_value(t, socket.read_deadline_scopes, 0)
 testing.expect(t, trace.calls == 1 && trace.last == outer)
 wa.socket_message_destroy(event.message)
 // An uninitialized session fails inside socket_receive. Without the scoped
 // wrapper, that path would replace the caller's five-second deadline with 15s.
 _, failure := runner_read_scoped(&socket)
 testing.expect(t, failure.kind != .None)
 testing.expect_value(t, socket.read_deadline_scopes, 0)
 testing.expect(t, trace.calls == 1 && trace.last == outer)
 wa.socket_close(&socket)
}

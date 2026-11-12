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

Write_Deadline_Probe :: struct {
 deadline: time.Time,
 sets, writes, closes: int,
 write_had_deadline: bool,
}

write_probe_deadline :: proc(data: rawptr, value: time.Time) -> surf.WebSocket_Stream_Error {
 probe := cast(^Write_Deadline_Probe)data
 probe.deadline = value; probe.sets += 1
 return {}
}

write_probe_read :: proc(_: rawptr, _: []u8) -> (int, surf.WebSocket_Stream_Error) {
 return 0, {kind = .EOF}
}

write_probe_send :: proc(data: rawptr, source: []u8) ->
 (int, surf.WebSocket_Stream_Error) {
 probe := cast(^Write_Deadline_Probe)data
 probe.writes += 1
 probe.write_had_deadline = probe.deadline != (time.Time{})
 return 0, {kind = .TLS_Failed, tls = {kind = .Transport_Write_Failed,
  transport = {kind = .Timeout}}}
}

write_probe_close :: proc(data: rawptr) -> surf.WebSocket_Stream_Error {
 probe := cast(^Write_Deadline_Probe)data
 probe.closes += 1
 return {}
}

@(test)
probe_keepalive_write_is_deadline_scoped_and_failure_preserved :: proc(t: ^testing.T) {
 probe: Write_Deadline_Probe
 runner := new(Runner); defer free(runner)
 socket := &runner.socket
 socket.phase = .Online
 socket.config.query_timeout = 17*time.Second
 socket.websocket = {phase = .Open, allocator = context.allocator,
  config = {host = "synthetic.invalid", max_message_size = 4096},
  stream = {data = &probe, read = write_probe_read, write = write_probe_send,
   close = write_probe_close,
   abort = write_probe_close, set_write_deadline = write_probe_deadline}}
 socket.client = {phase = .Noise_Ready, websocket = &socket.websocket,
  config = {max_frame_payload = 4096}, noise = {phase = .Transport}}
 assert(wa.frame_transport_init(&socket.client.frames, &socket.websocket, 4096).kind == .None)
 socket.client.frames.intro_sent = true
 socket.session = {phase = .Login_Accepted, client = &socket.client,
  last_received = time.now(), config = {keepalive_interval = 30*time.Second}}
 runner.deadline = time.tick_add(time.tick_now(), 250*time.Millisecond)
 before := time.now()
 _, error := runner_pump(runner)
 testing.expect_value(t, error.kind, .Protocol)
 testing.expect_value(t, error.socket.kind, .Session_Failed)
 testing.expect_value(t, error.socket.session.client.kind, .Transport_Failed)
 testing.expect_value(t,
  error.socket.session.client.transport.websocket.stream.tls.transport.kind, .Timeout)
 testing.expect(t, probe.writes > 0 && probe.write_had_deadline)
 testing.expect(t, time.diff(before, probe.deadline) > 0 &&
  time.diff(before, probe.deadline) <= 300*time.Millisecond)
 testing.expect(t, probe.closes > 0)
 testing.expect_value(t, socket.phase, .Closed)
 testing.expect_value(t, socket.config.query_timeout, 17*time.Second)
}

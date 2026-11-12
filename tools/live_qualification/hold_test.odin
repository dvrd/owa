package main

import "core:testing"
import "core:time"

@(test)
hold_parser_requires_bounded_unique_integer :: proc(t: ^testing.T) {
 for value in ([]string{"0", "1", "300"}) {
  options, error := options_parse({"inspect", "--auth-dir", "/private/test-session",
   "--group-subject", "Synthetic Test", "--hold-seconds", value})
  testing.expect_value(t, error.kind, .None)
  testing.expect(t, options.hold_seconds >= 0 && options.hold_seconds <= 300)
 }
 for value in ([]string{"-1", "301", "not-an-integer", "999999999999999999999999999"}) {
  _, error := options_parse({"inspect", "--auth-dir", "/private/test-session",
   "--group-subject", "Synthetic Test", "--hold-seconds", value})
  testing.expect_value(t, error.kind, .Usage)
 }
 _, duplicate := options_parse({"preview", "--hold-seconds", "0", "--hold-seconds", "1"})
 testing.expect_value(t, duplicate.kind, .Usage)
 options, omitted := options_parse({"preview"})
 testing.expect_value(t, omitted.kind, .None)
 testing.expect_value(t, options.hold_seconds, 0)
}

@(test)
hold_budget_never_exceeds_request_or_available :: proc(t: ^testing.T) {
 testing.expect_value(t, hold_budget(0, time.Hour), time.Duration(0))
 testing.expect_value(t, hold_budget(60, 0), time.Duration(0))
 testing.expect_value(t, hold_budget(60, -time.Second), time.Duration(0))
 testing.expect_value(t, hold_budget(60, 250*time.Millisecond), 250*time.Millisecond)
 testing.expect_value(t, hold_budget(60, time.Hour), 60*time.Second)
 testing.expect_value(t, hold_budget(999, time.Hour), 300*time.Second)
}

@(test)
hold_disabled_and_expired_do_not_touch_uninitialized_transport :: proc(t: ^testing.T) {
 runner := new(Runner)
 defer free(runner)
 runner.options.hold_seconds = 0
 testing.expect_value(t, runner_hold(runner).kind, .None)
 runner.options.hold_seconds = 60
 runner.deadline = time.tick_add(time.tick_now(), -time.Second)
 deadline := runner.deadline
 testing.expect_value(t, runner_hold(runner).kind, .Timeout)
 testing.expect_value(t, runner.deadline, deadline)
}

@(test)
hold_timeout_classifier_preserves_non_timeout_failures :: proc(t: ^testing.T) {
 error := Tool_Error{kind = .Protocol, socket = {kind = .Session_Failed,
  session = {kind = .Client_Failed}}}
 testing.expect(t, !read_timeout(error))
 error.socket.session.client.transport.websocket.stream.tls.transport.kind = .Timeout
 testing.expect(t, read_timeout(error))
 error.socket.kind = .Message_Rejected
 testing.expect(t, !read_timeout(error))
}

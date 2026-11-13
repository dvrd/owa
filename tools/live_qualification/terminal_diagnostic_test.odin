package main

import wa "../.."
import "core:strings"
import "core:testing"
import "core:time"

@(test)
terminal_stream_failure_preserves_safe_context_after_document_destroy :: proc(t: ^testing.T) {
 runner := new(Runner); defer free(runner)
 client: wa.Client
 auth: wa.Auth_State
 session := wa.Session{phase = .Login_Accepted, client = &client, auth = &auth,
  config = {observe_node = terminal_observe, observer_data = runner}}
 node := wa.Binary_Node{tag = "stream:error", attrs = {{"id", "private-account-marker"}},
  content = []wa.Binary_Node{{tag = "conflict"}, {tag = "private-child-marker"}}}
 encoded: [2048]u8
 count, encoded_error := wa.binary_node_encode(encoded[:], node)
 testing.expect_value(t, encoded_error.kind, .None)
 if encoded_error.kind != .None {return}
 _, failure := wa.session_process(&session, encoded[:count], time.now())
 testing.expect_value(t, failure.kind, .Server_Failure)
 testing.expect_value(t, failure.server_code, u32(0))
 testing.expect_value(t, session.phase, .Failed)
 typed := terminal_failure(runner,
  {kind = .Protocol, socket = {kind = .Session_Failed, session = failure}})
 testing.expect_value(t, typed.server_node, .Stream_Error)
 testing.expect_value(t, typed.server_detail, .Conflict)
 testing.expect_value(t, typed.server_unknown_children, u8(1))
 testing.expect(t, !watch_retryable(typed), "diagnostic context must not relax terminal policy")
 output: [1024]u8
 line := terminal_failure_format(output[:], typed)
 testing.expect(t, strings.contains(line, "NODE Stream_Error DETAIL Conflict UNKNOWN_CHILDREN 1"))
 testing.expect(t, !strings.contains(line, "private-"))
}

@(test)
terminal_context_is_bounded_and_never_attaches_to_transport_errors :: proc(t: ^testing.T) {
 runner := new(Runner); defer free(runner)
 children: [64]string
 for &child in children {child = "private-unknown-value"}
 terminal_observe(runner, {tag = "failure", kind = "private-type", children = children[:]})
 testing.expect_value(t, runner.terminal.node, .Failure)
 testing.expect_value(t, runner.terminal.detail, .Other)
 testing.expect_value(t, runner.terminal.unknown_children, u8(32))
 transport := terminal_failure(runner, {kind = .Protocol,
  socket = {kind = .Session_Failed, session = {kind = .Connection_Lost}}})
 testing.expect_value(t, transport.server_node, .Unknown)
 terminal_observe(runner, {tag = "iq"})
 testing.expect_value(t, runner.terminal.node, .Unknown)
}

@(test)
terminal_ack_child_preserves_fixed_detail_without_any_routing_attributes :: proc(t: ^testing.T) {
 runner := new(Runner); defer free(runner)
 client: wa.Client
 auth: wa.Auth_State
 session := wa.Session{phase = .Login_Accepted, client = &client, auth = &auth,
  config = {observe_node = terminal_observe, observer_data = runner}}
 node := wa.Binary_Node{tag = "stream:error", content = []wa.Binary_Node{
  {tag = "ack", attrs = {{"class", "private-class"}, {"id", "private-id"},
   {"type", "private-type"}, {"participant", "private-participant"}}}}}
 encoded: [2048]u8
 count, encode_error := wa.binary_node_encode(encoded[:], node); assert(encode_error.kind == .None)
 _, error := wa.session_process(&session, encoded[:count], time.now())
 assert(error.kind == .Server_Failure)
 failure := terminal_failure(runner, {kind = .Protocol,
  socket = {kind = .Session_Failed, session = error}})
 testing.expect_value(t, failure.server_detail, .Ack)
 testing.expect_value(t, failure.server_unknown_children, u8(0))
 testing.expect(t, !watch_retryable(failure), "ACK diagnostics must not relax terminal reconnect policy")
 output: [1024]u8
 line := terminal_failure_format(output[:], failure)
 testing.expect(t, strings.contains(line, "NODE Stream_Error DETAIL Ack UNKNOWN_CHILDREN 0"))
 testing.expect(t, !strings.contains(line, "private-"))
}

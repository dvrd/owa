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
 testing.expect_value(t, failure.server_detail, .Ack_Other)
 testing.expect_value(t, failure.server_unknown_children, u8(0))
 testing.expect(t, !watch_retryable(failure), "ACK diagnostics must not relax terminal reconnect policy")
 output: [1024]u8
 line := terminal_failure_format(output[:], failure)
 testing.expect(t, strings.contains(line, "NODE Stream_Error DETAIL Ack_Other UNKNOWN_CHILDREN 0"))
 testing.expect(t, !strings.contains(line, "private-"))
}

@(test)
terminal_ack_classes_survive_document_destroy_and_never_expose_attributes :: proc(t: ^testing.T) {
 for fixture in ([]struct {raw, detail: string}{
  {"message", "Ack_Message"}, {"receipt", "Ack_Receipt"},
  {"notification", "Ack_Notification"}, {"status", "Ack_Status"},
  {"call", "Ack_Call"}, {"private-class-marker", "Ack_Other"}, {"", "Ack_Unknown"},
 }) {
  runner := new(Runner); defer free(runner)
  client: wa.Client; auth: wa.Auth_State
  session := wa.Session{phase = .Login_Accepted, client = &client, auth = &auth,
   config = {observe_node = terminal_observe, observer_data = runner}}
  node := wa.Binary_Node{tag = "stream:error", content = []wa.Binary_Node{
   {tag = "ack", attrs = {{"class", fixture.raw}, {"type", "private-type-marker"},
    {"id", "private-id-marker"}, {"participant", "private-participant-marker"}}}}}
  encoded: [2048]u8
  count, error := wa.binary_node_encode(encoded[:], node); assert(error.kind == .None)
  _, failure := wa.session_process(&session, encoded[:count], time.now())
  assert(failure.kind == .Server_Failure)
  // Failure has already destroyed the document. Poison the caller's wire too.
  for &byte in encoded {byte = 0xa5}
  typed := terminal_failure(runner, {kind = .Protocol,
   socket = {kind = .Session_Failed, session = failure}})
  output: [1024]u8
  line := terminal_failure_format(output[:], typed)
  testing.expect(t, strings.contains(line, fixture.detail))
  testing.expect(t, strings.contains(line, "UNKNOWN_CHILDREN 0"))
  testing.expect(t, !strings.contains(line, "private-"))
  testing.expect(t, !watch_retryable(typed))
 }
}

@(test)
terminal_ack_subclass_preserves_existing_type_and_mixed_child_semantics :: proc(t: ^testing.T) {
 runner := new(Runner); defer free(runner)
 terminal_observe(runner, {tag = "stream:error", kind = "ack", children = {"ack"},
  ack_class = .Receipt})
 testing.expect_value(t, runner.terminal.detail, .Ack_Receipt)
 terminal_observe(runner, {tag = "stream:error", children = {"ack", "conflict"},
  ack_class = .Status})
 testing.expect_value(t, runner.terminal.detail, .Multiple)
 testing.expect_value(t, runner.terminal.unknown_children, u8(0))
 terminal_observe(runner, {tag = "failure", children = {"ack"}, ack_class = .Status})
 testing.expect_value(t, runner.terminal.detail, .Ack)
}

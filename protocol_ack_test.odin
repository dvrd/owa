package whatsapp

import "core:testing"
import "core:time"

Protocol_Ack_Capture :: struct {
 class: Protocol_Ack_Class,
 calls, children: int,
 metadata_unchanged: bool,
}
protocol_ack_capture :: proc(data: rawptr, info: Protocol_Node_Info) {
 capture := cast(^Protocol_Ack_Capture)data
 capture.calls += 1
 capture.class = info.ack_class
 capture.children = len(info.children)
 capture.metadata_unchanged = info.tag == "stream:error" && info.kind == "private-top-type" &&
  len(info.children) == 1 && info.children[0] == "ack"
}

@(test)
protocol_ack_observer_retains_only_fixed_class_after_document_release :: proc(t: ^testing.T) {
 for fixture in ([]struct {raw: string, class: Protocol_Ack_Class}{
  {"message", .Message}, {"receipt", .Receipt}, {"notification", .Notification},
  {"status", .Status}, {"call", .Call}, {"private-unknown-class", .Other}, {"", .Unknown},
 }) {
  capture: Protocol_Ack_Capture
  client: Client; auth: Auth_State
  session := Session{phase = .Login_Accepted, client = &client, auth = &auth,
   config = {observe_node = protocol_ack_capture, observer_data = &capture}}
  wire: [2048]u8
  count, encoded := binary_node_encode(wire[:], {
   tag = "stream:error", attrs = {{"type", "private-top-type"}},
   content = []Binary_Node{{tag = "ack", attrs = {{"class", fixture.raw},
    {"type", "private-child-type"}, {"id", "private-stanza-id"}}}},
  })
  assert(encoded.kind == .None)
  _, failure := session_process(&session, wire[:count], time.now())
  testing.expect_value(t, failure.kind, .Server_Failure)
  for &byte in wire {byte = 0xa5}
  testing.expect_value(t, capture.class, fixture.class)
  testing.expect_value(t, capture.calls, 1)
  testing.expect(t, capture.metadata_unchanged)
 }
}

@(test)
protocol_ack_observer_limits_context_and_rejects_conflicting_classes :: proc(t: ^testing.T) {
 children: [33]Binary_Node
 for &child in children {child = {tag = "private-child"}}
 children[32] = {tag = "ack", attrs = {{"class", "status"}}}
 testing.expect_value(t, session_stream_ack_class({tag = "stream:error",
  content = children[:]}), .Unknown)
 children[0] = {tag = "ack", attrs = {{"class", "message"}}}
 testing.expect_value(t, session_stream_ack_class({tag = "stream:error",
  content = children[:]}), .Unknown)
 testing.expect_value(t, session_stream_ack_class({tag = "stream:error",
  content = children[:32]}), .Message)
 children[1] = {tag = "ack", attrs = {{"class", "status"}}}
 testing.expect_value(t, session_stream_ack_class({tag = "stream:error",
  content = children[:]}), .Unknown)
 testing.expect_value(t, session_stream_ack_class({tag = "failure",
  content = children[:]}), .Unknown)
 testing.expect_value(t, session_ack_class({attrs = {{"class", "status"},
  {"class", "status"}}}), .Unknown)
 attrs: [33]Binary_Node_Attribute
 attrs[0] = {"class", "status"}
 testing.expect_value(t, session_ack_class({attrs = attrs[:]}), .Unknown)
}

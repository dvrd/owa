package main

import wa "../.."
import "core:fmt"

Terminal_Node :: enum {Unknown, Failure, Stream_Error}
Terminal_Detail :: enum {
 None, Conflict, Replaced, Device_Removed, Unauthorized, Internal_Server_Error,
 Policy_Violation, Resource_Constraint, System_Shutdown, Ack, Other, Multiple,
 Ack_Message, Ack_Receipt, Ack_Notification, Ack_Status, Ack_Call, Ack_Other, Ack_Unknown,
}
Terminal_Diagnostic :: struct {node: Terminal_Node, detail: Terminal_Detail, unknown_children: u8}

terminal_detail :: proc(value: string) -> Terminal_Detail {
 switch value {
 case "": return .None
 case "conflict": return .Conflict
 case "replaced": return .Replaced
 case "device_removed", "device-removed": return .Device_Removed
 case "not-authorized", "unauthorized": return .Unauthorized
 case "internal-server-error": return .Internal_Server_Error
 case "policy-violation": return .Policy_Violation
 case "resource-constraint": return .Resource_Constraint
 case "system-shutdown": return .System_Shutdown
 case "ack": return .Ack
 case: return .Other
 }
}

terminal_ack_detail :: proc(class: wa.Protocol_Ack_Class) -> Terminal_Detail {
 switch class {
 case .Message: return .Ack_Message
 case .Receipt: return .Ack_Receipt
 case .Notification: return .Ack_Notification
 case .Status: return .Ack_Status
 case .Call: return .Ack_Call
 case .Other: return .Ack_Other
 case .Unknown: return .Ack_Unknown
 }
 return .Ack_Unknown
}

// Retain only fixed enums/counts while borrowed node strings are valid. Never
// serialize raw attributes, stanza children, account addresses or content.
terminal_observe :: proc(data: rawptr, info: wa.Protocol_Node_Info) {
 if data == nil {return}
 runner := cast(^Runner)data
 runner.terminal = {}
 switch info.tag {
 case "failure": runner.terminal.node = .Failure
 case "stream:error": runner.terminal.node = .Stream_Error
 case: return
 }
 runner.terminal.detail = terminal_detail(info.kind)
 for child in info.children[:min(len(info.children), 32)] {
  detail := terminal_detail(child)
  if detail == .Ack && runner.terminal.node == .Stream_Error {
   detail = terminal_ack_detail(info.ack_class)
  }
  if detail == .Other {
   runner.terminal.unknown_children += 1
   continue
  }
  if detail == .None {continue}
  if runner.terminal.detail == .None || runner.terminal.detail == .Other ||
   runner.terminal.detail == .Ack && child == "ack" {
   runner.terminal.detail = detail
  } else if runner.terminal.detail != detail {runner.terminal.detail = .Multiple}
 }
 if runner.terminal.detail == .None && runner.terminal.unknown_children > 0 {
  runner.terminal.detail = .Other
 }
}

terminal_failure :: proc(runner: ^Runner, failure: Tool_Error) -> Tool_Error {
 result := failure
 if failure.socket.kind == .Session_Failed && failure.socket.session.kind == .Server_Failure {
  result.server_node = runner.terminal.node
  result.server_detail = runner.terminal.detail
  result.server_unknown_children = runner.terminal.unknown_children
 }
 return result
}

terminal_failure_format :: proc(buffer: []u8, failure: Tool_Error) -> string {
 if failure.socket.kind == .Session_Failed && failure.socket.session.kind == .Server_Failure {
  return fmt.bprintf(buffer,
   "ERROR %v STORAGE %v SOCKET %v CERTIFICATE %v SESSION %v CODE %d NODE %v DETAIL %v UNKNOWN_CHILDREN %d\n",
   failure.kind, failure.storage, failure.socket.kind,
   failure.socket.session.client.certificate, failure.socket.session.kind,
   failure.socket.session.server_code, failure.server_node, failure.server_detail,
   failure.server_unknown_children)
 }
 return fmt.bprintf(buffer,
  "ERROR %v STORAGE %v SOCKET %v CERTIFICATE %v SESSION %v CODE %d\n",
  failure.kind, failure.storage, failure.socket.kind,
  failure.socket.session.client.certificate, failure.socket.session.kind,
  failure.socket.session.server_code)
}

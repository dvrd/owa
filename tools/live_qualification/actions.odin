package main

import wa "../.."
import "core:crypto/sha2"
import "core:encoding/hex"
import "core:strings"
import "core:time"

qualification_text :: "Mesa WhatsApp qualification: synthetic text transport check."
qualification_pdf := string(#load("payloads/qualification.pdf"))

runner_scope_guard :: proc(options: Options, storage: ^Storage) -> Tool_Error {
 if error := storage_scope_guard_offline(storage, options.command == .Pair,
  options.group_subject); error != .None {return {kind = .Scope, storage = error}}
 if !options.send {
  for record in storage.state.records {
   if record.kind == .Outbound_Message || record.kind == .Outbound_Content {
    return {kind = .Scope, storage = .Outbox_Unsafe}
   }
  }
 }
 return {}
}

group_select :: proc(groups: []wa.Socket_Group_Summary,
 subject: string) -> (string, Tool_Error) {
 if !subject_valid(subject) || len(groups) > 10000 {return "", {kind = .Usage}}
 found := ""
 matches := 0
 for group in groups {
  if group.subject != subject {continue}
  matches += 1
  if matches > 1 {return "", {kind = .Target_Ambiguous}}
  found = group.jid
 }
 if matches == 0 || found == "" {return "", {kind = .Target_Not_Found}}
 return found, {}
}

action_fingerprint :: proc(data: []u8) -> string {
 return action_fingerprint_parts("", data)
}

action_fingerprint_parts :: proc(metadata: string, data: []u8) -> string {
 state: sha2.Context_256
 digest: [32]u8
 sha2.init_256(&state)
 sha2.update(&state, transmute([]u8)metadata)
 sha2.update(&state, data); sha2.final(&state, digest[:])
 encoded, allocation := hex.encode(digest[:])
 if allocation != nil {return ""}
 return string(encoded)
}

runner_query_budget :: proc(runner: ^Runner) -> Tool_Error {
 if remaining(runner) <= 0 {return {kind = .Timeout}}
 runner.socket.config.query_timeout = min(remaining(runner), 10 * time.Second)
 return {}
}

runner_target :: proc(runner: ^Runner) -> Tool_Error {
 if error := runner_query_budget(runner); error.kind != .None {return error}
 groups, group_error := wa.socket_groups_participating(&runner.socket)
 if group_error.kind != .None {return {kind = .Protocol, socket = group_error}}
 defer wa.socket_group_summaries_destroy(&groups)
 selected, selection_error := group_select(groups[:], runner.options.group_subject)
 if selection_error.kind != .None {return selection_error}
 owned, allocation := strings.clone(selected)
 if allocation != nil {return {kind = .Allocation}}
 runner.target_jid = owned
 if error := runner_query_budget(runner); error.kind != .None {return error}
 group, metadata_error := wa.socket_group_metadata(&runner.socket, owned)
 if metadata_error.kind != .None {return {kind = .Protocol, socket = metadata_error}}
 defer wa.socket_group_destroy(&group)
 if group.metadata.subject != runner.options.group_subject || group.jid != owned {
  return {kind = .Scope}
 }
 if error := storage_scope_target(&runner.storage, owned); error != .None {
  return {kind = .Scope, storage = error}
 }
 phase_print(.TARGET_READY)
 return {}
}

runner_ack_wait :: proc(runner: ^Runner, kind, id: string) -> Tool_Error {
 if _, pending := wa.state_store_get(&runner.storage.state, .Outbound_Message, id); !pending {
  phase_print(.ACK_PENDING)
  return {kind = .Protocol}
 }
 phase_print(.ACK_WAIT)
 deadline := time.tick_add(time.tick_now(), min(remaining(runner), 15 * time.Second))
 for time.tick_diff(time.tick_now(), deadline) > 0 {
  restart, error := runner_pump(runner)
  if error.kind != .None {return error}
  if restart {return {kind = .Protocol}}
  if _, pending := wa.state_store_get(&runner.storage.state, .Outbound_Message, id); !pending {
   // Present in this process: only authenticated ACK processing removes this record.
   if stored := storage_journal_mark(&runner.storage, kind, id, .Acknowledged); stored != .None {
    return {kind = .Journal, storage = stored}
   }
   phase_print(.SERVER_ACKED)
   return {}
  }
 }
 phase_print(.ACK_PENDING)
 return {kind = .Timeout}
}

runner_send :: proc(runner: ^Runner, document: bool) -> Tool_Error {
 if !runner.options.send || runner.options.command != .Qualify {return {kind = .Usage}}
 kind := document ? "pdf" : "text"
 payload := document ? qualification_pdf : qualification_text
 metadata := "v1|text\n"
 if document {
  metadata = "v1|document|application/pdf|mesa-qualification.pdf|Synthetic PDF transport check.\n"
 }
 fingerprint := action_fingerprint_parts(metadata, transmute([]u8)payload)
 defer delete(fingerprint)
 if fingerprint == "" {return {kind = .Allocation}}
 id, prepare_error := storage_journal_prepare(&runner.storage, kind, fingerprint)
 if prepare_error != .None {return {kind = .Journal, storage = prepare_error}}
 defer delete(id)
 status, status_error := storage_journal_status(&runner.storage, kind, id)
 if status_error != .None {return {kind = .Journal, storage = status_error}}
 if status == .Acknowledged {phase_print(.SERVER_ACKED); return {}}
 if status == .Queued {
  if _, pending := wa.state_store_get(&runner.storage.state, .Outbound_Message, id); !pending {
   phase_print(.RESUME_UNKNOWN)
  }
 }
 if marked := storage_journal_mark(&runner.storage, kind, id, .Queued); marked != .None {
  return {kind = .Journal, storage = marked}
 }
 if error := runner_query_budget(runner); error.kind != .None {return error}
 sent: string
 send_error: wa.Socket_Error
 if document {
  sent, send_error = wa.socket_send_document(&runner.socket, runner.target_jid,
   transmute([]u8)qualification_pdf, "mesa-qualification.pdf", "Synthetic PDF transport check.",
   "application/pdf", id)
 } else {
  sent, send_error = wa.socket_send_text(&runner.socket, runner.target_jid, qualification_text,
   message_id = id)
 }
 defer delete(sent)
 if send_error.kind != .None {return {kind = .Send, socket = send_error}}
 if sent != id {return {kind = .Protocol}}
 phase_print(document ? .PDF_QUEUED : .TEXT_QUEUED)
 return runner_ack_wait(runner, kind, id)
}

runner_actions :: proc(runner: ^Runner) -> Tool_Error {
 if error := runner_target(runner); error.kind != .None {return error}
 if !runner.options.send {return {}}
 if error := runner_send(runner, false); error.kind != .None {return error}
 return runner_send(runner, true)
}

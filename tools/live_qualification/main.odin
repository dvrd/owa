package main

import wa "../.."
import "core:crypto/tls"
import "core:fmt"
import "core:log"
import "core:os"
import "core:path/filepath"
import "core:strconv"
import "core:time"
import "core:unicode/utf8"
import "core:crypto/sha2"
import "core:encoding/hex"
import "core:strings"
import "core:crypto"
import "core:encoding/json"

Command :: enum {None, Pair, Inspect, Qualify, Preview, Retarget, Watch}
Options :: struct {
 command: Command,
 auth_dir, group_subject, previous_group_subject: string,
 send, preview, allow_scoped_retries, retry_unknown_canary: bool,
 timeout_seconds, hold_seconds, canary_interval_seconds: int,
}
Tool_Error_Kind :: enum {
 None, Usage, Storage, Trust, Connect, Timeout, Protocol, QR, IO, Allocation,
 Target_Not_Found, Target_Ambiguous, Scope, Send, Journal, Unexpected_Pairing, Canary_Unknown,
}
Tool_Error :: struct {
 kind: Tool_Error_Kind, storage: Storage_Error, socket: wa.Socket_Error,
 server_node: Terminal_Node, server_detail: Terminal_Detail, server_unknown_children: u8,
}
Phase :: enum {
 STORAGE_READY, VERSION_DISCOVERY, VERSION_DISCOVERED, VERSION_PINNED,
 CONNECTED_HOLD, CONNECTING, PAIRED, RECONNECTING, ONLINE, TARGET_READY, TEXT_QUEUED,
 WATCH_RECONNECTING, WATCH_COMPLETE, PDF_QUEUED, ACK_WAIT, SERVER_ACKED, ACK_PENDING,
 RESUME_UNKNOWN, COMPLETE, PREVIEW_READY, CANARY_PREPARED, CANARY_TEXT_ACKED,
 CANARY_PDF_ACKED, CANARY_COMPLETE, CANARY_UNKNOWN,
}
Runner :: struct {
 storage: Storage,
 socket: wa.Socket,
 roots: tls.Root_Pool,
 config: wa.Socket_Config,
 options: Options,
 deadline: time.Tick,
 target_jid: string,
 restarts: int,
 canary_completed: int,
 canary_due_tick: time.Tick,
 canary_due_set: bool,
 terminal: Terminal_Diagnostic,
}

phase_print :: proc(value: Phase) {fmt.printf("PHASE %v\n", value); os.flush(os.stdout)}

options_parse :: proc(args: []string) -> (Options, Tool_Error) {
 options := Options{timeout_seconds = 300}
 if len(args) == 0 {return options, {}}
 if len(args) > 16 {return {}, {kind = .Usage}}
 switch args[0] {
 case "--help", "-h": return options, {}
 case "pair": options.command = .Pair
 case "inspect": options.command = .Inspect
 case "qualify": options.command = .Qualify
 case "preview": options.command = .Preview
 case "retarget": options.command = .Retarget
 case "watch": options.command = .Watch; options.timeout_seconds = 86400
 case: return {}, {kind = .Usage}
 }
 index := 1
 timeout_seen, hold_seen, canary_seen := false, false, false
 for index < len(args) {
  flag := args[index]; index += 1
  if flag == "--help" {return {}, {}}
  if flag == "--retry-unknown-canary" {
   if options.retry_unknown_canary {return {}, {kind = .Usage}}
   options.retry_unknown_canary = true; continue
  }
  if flag == "--allow-scoped-retries" {
   if options.allow_scoped_retries {return {}, {kind = .Usage}}
   options.allow_scoped_retries = true; continue
  }
  if flag == "--send" || flag == "--preview" {
   if flag == "--send" {
    if options.send {return {}, {kind = .Usage}}; options.send = true
   } else {
    if options.preview {return {}, {kind = .Usage}}; options.preview = true
   }
   continue
  }
  if index == len(args) {return {}, {kind = .Usage}}
  value := args[index]; index += 1
  switch flag {
  case "--auth-dir":
   if options.auth_dir != "" || !filepath.is_abs(value) {return {}, {kind = .Usage}}
   options.auth_dir = value
  case "--previous-group-subject":
   if options.previous_group_subject != "" || !subject_valid(value) {
    return {}, {kind = .Usage}
   }
   options.previous_group_subject = value
  case "--group-subject":
   if options.group_subject != "" || !subject_valid(value) {return {}, {kind = .Usage}}
   options.group_subject = value
  case "--hold-seconds":
   seconds, valid := strconv.parse_int(value)
   if hold_seen || !valid || seconds < 0 || seconds > 300 {return {}, {kind = .Usage}}
   options.hold_seconds, hold_seen = seconds, true
  case "--canary-interval-seconds":
   seconds, valid := strconv.parse_int(value)
   if canary_seen || !valid || seconds < 3600 || seconds > 86400 {return {}, {kind = .Usage}}
   options.canary_interval_seconds, canary_seen = seconds, true
  case "--timeout-seconds":
   seconds, valid := strconv.parse_int(value)
   low := options.command == .Watch ? 60 : 10
   high := options.command == .Watch ? 172800 : 600
   if timeout_seen || !valid || seconds < low || seconds > high {return {}, {kind = .Usage}}
   options.timeout_seconds, timeout_seen = seconds, true
  case: return {}, {kind = .Usage}
  }
 }
 if options.retry_unknown_canary && !canary_enabled(options) {return {}, {kind = .Usage}}
 if options.allow_scoped_retries && options.command != .Watch {return {}, {kind = .Usage}}
 if options.command == .Retarget {
  if options.auth_dir == "" || !subject_valid(options.group_subject) ||
   !subject_valid(options.previous_group_subject) || options.send || options.preview ||
   hold_seen || timeout_seen || canary_seen {return {}, {kind = .Usage}}
  return options, {}
 }
 if canary_seen && (options.command != .Watch || !options.send ||
  !options.allow_scoped_retries) {return {}, {kind = .Usage}}
 if options.command == .Watch && ((options.send && !canary_seen) || options.preview || hold_seen) {
  return {}, {kind = .Usage}
 }
 if options.previous_group_subject != "" {return {}, {kind = .Usage}}
 if options.send && options.command != .Qualify && options.command != .Watch {
  return {}, {kind = .Usage}
 }
 if options.command == .Preview || options.preview {return options, {}}
 if options.auth_dir == "" || !subject_valid(options.group_subject) {return {}, {kind = .Usage}}
 return options, {}
}

subject_valid :: proc(value: string) -> bool {
 if len(value) == 0 || len(value) > 256 || !utf8.valid_string(value) {return false}
 for byte in value {if byte < 32 || byte == 127 {return false}}
 return true
}

runner_prepare :: proc(runner: ^Runner) -> Tool_Error {
 options := runner.options
 mode := options.command == .Pair ? Storage_Mode.Pair_New : .Qualify_Resume
 if error := storage_open(&runner.storage, options.auth_dir, mode, options.group_subject);
    error != .None {return {kind = .Storage, storage = error}}
 if options.retry_unknown_canary && !canary_has_unknown(&runner.storage) {
  return {kind = .Usage}
 }
 if error := runner_scope_guard(options, &runner.storage); error.kind != .None {return error}
 phase_print(.STORAGE_READY)
 if tls.root_pool_load_system(&runner.roots).kind != .None {return {kind = .Trust}}
 runner.config = {tls = {root_cas = runner.roots.roots[:runner.roots.count]},
  payload = wa.default_payload_config(), query_timeout = 10 * time.Second,
  auth_path = runner.storage.auth_path, prekey_path = runner.storage.prekey_path,
  state_path = runner.storage.state_path,
  observe_node = terminal_observe, observer_data = runner}
 phase_print(.VERSION_DISCOVERY)
 version := wa.web_version_discover({tls = runner.config.tls,
  timeout = 5 * time.Second, max_redirects = 2})
 runner.config.payload.version = version.version
 phase_print(version.source == .Pinned ? .VERSION_PINNED : .VERSION_DISCOVERED)
 if options.command == .Watch {
  fmt.printf("WATCH_VERSION major=%d minor=%d patch=%d\n", version.version[0],
   version.version[1], version.version[2]); os.flush(os.stdout)
 }
 return {}
}

runner_close :: proc(runner: ^Runner) {
 if runner.socket.phase != .Uninitialized {wa.socket_close(&runner.socket)}
 qr_remove(runner)
 storage_close(&runner.storage)
 tls.root_pool_destroy(&runner.roots)
 delete(runner.target_jid)
}

run_command :: proc(options: Options) -> Tool_Error {
 if options.command == .Retarget {return run_retarget(options)}
 runner, allocation := new(Runner)
 if allocation != nil || runner == nil {return {kind = .Allocation}}
 defer free(runner)
 runner.options = options
 budget := time.Duration(options.timeout_seconds) * time.Second
 runner.deadline = time.tick_add(time.tick_now(), budget)
 defer runner_close(runner)
 if error := runner_prepare(runner); error.kind != .None {return error}
 if options.command == .Watch {return terminal_failure(runner, runner_watch(runner))}
 if error := runner_online(runner); error.kind != .None {return terminal_failure(runner, error)}
 if error := runner_hold(runner); error.kind != .None {return terminal_failure(runner, error)}
 if options.command != .Pair {
  if error := runner_actions(runner); error.kind != .None {return terminal_failure(runner, error)}
 }
 phase_print(.COMPLETE)
 return {}
}

main :: proc() {
 context.logger = log.nil_logger()
 options, error := options_parse(os.args[1:])
 if error.kind != .None || options.command == .None {
  fmt.println("Usage: live_qualification pair|inspect|qualify --auth-dir /private/owned-dir")
  fmt.println("       network modes require --group-subject")
  fmt.println("       --send: qualify, or watch with --canary-interval-seconds and scoped retries")
  fmt.println("       retarget requires --previous-group-subject and --group-subject; offline only")
  fmt.println("       preview or --preview performs no network or session initialization")
  if error.kind != .None {os.exit(2)}
  return
 }
 if options.command == .Preview || options.preview {phase_print(.PREVIEW_READY); return}
 failure := run_command(options)
 if failure.kind != .None {
  buffer: [1024]u8
  fmt.eprintf("%s", terminal_failure_format(buffer[:], failure))
  os.exit(1)
 }
}

run_retarget :: proc(options: Options) -> Tool_Error {
 storage, allocation := new(Storage)
 if allocation != nil || storage == nil {return {kind = .Allocation}}
 defer free(storage)
 defer storage_close(storage)
 if error := storage_open(storage, options.auth_dir, .Qualify_Resume,
  options.previous_group_subject); error != .None {return {kind = .Storage, storage = error}}
 if error := storage_scope_retarget(storage, options.group_subject); error != .None {
  return {kind = .Scope, storage = error}
 }
 phase_print(.COMPLETE)
 return {}
}

qualification_text :: "Mesa WhatsApp qualification: synthetic text transport check."
qualification_pdf := string(#load("payloads/qualification.pdf"))

runner_scope_guard :: proc(options: Options, storage: ^Storage) -> Tool_Error {
 if options.command == .Watch {
  return watch_scope_guard(options, storage, false)
 }
 if storage.canary != nil {return {kind = .Scope, storage = .Outbox_Unsafe}}
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

// Public diagnostics contain counts only, never group names or addresses.
Group_Counts :: struct {total, empty_subjects, exact_matches: int}

group_counts :: proc(groups: []wa.Socket_Group_Summary, subject: string) -> Group_Counts {
 counts := Group_Counts{total = len(groups)}
 for group in groups {
  if group.subject == "" {counts.empty_subjects += 1}
  if group.subject == subject {counts.exact_matches += 1}
 }
 return counts
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
 counts := group_counts(groups[:], runner.options.group_subject)
 fmt.printf("GROUP_COUNTS total=%d empty_subjects=%d exact_matches=%d\n",
  counts.total, counts.empty_subjects, counts.exact_matches)
 os.flush(os.stdout)
 selected, selection_error := group_select(groups[:], runner.options.group_subject)
 if selection_error.kind != .None {return selection_error}
 owned, allocation := strings.clone(selected)
 if allocation != nil {return {kind = .Allocation}}
 accepted := false
 defer {if !accepted {delete(owned)}}
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
 delete(runner.target_jid)
 runner.target_jid = owned
 accepted = true
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
 fingerprint := action_fingerprint_parts(action_metadata(document), transmute([]u8)payload)
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

action_metadata :: proc(document: bool) -> string {
 if document {
  return "v1|document|application/pdf|mesa-qualification.pdf|Synthetic PDF transport check.\n"
 }
 return "v1|text\n"
}

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
  guard: Tool_Error
  if runner.options.command == .Watch {
   guard = watch_scope_guard(runner.options, &runner.storage, true)
  } else {guard = runner_scope_guard(runner.options, &runner.storage)}
  if error := guard; error.kind != .None {
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

qr_write :: proc(runner: ^Runner, token: string) -> Tool_Error {
 code, encode_error := wa.qr_encode(token)
 if encode_error != .None {return {kind = .QR}}
 defer crypto.zero_explicit(&code, size_of(code))
 qr_modules: [wa.QR_MAX_SIZE * wa.QR_MAX_SIZE]bool
 defer crypto.zero_explicit(&qr_modules, size_of(qr_modules))
 for y in 0..<code.size {
  for x in 0..<code.size {qr_modules[y * code.size + x] = wa.qr_module(&code, x, y)}
 }
 body, json_error := json.marshal(struct {size: int, modules: []bool}{
  code.size, qr_modules[:code.size * code.size]})
 if json_error != nil {return {kind = .Allocation}}
 defer {crypto.zero_explicit(raw_data(body), len(body)); delete(body)}
 path := fmt.aprintf("%s/qr.json", runner.storage.directory); defer delete(path)
 if error := qr_private_write(path, body); error.kind != .None {return error}
 fmt.println("QR_READY qr.json"); os.flush(os.stdout)
 return {}
}

qr_private_write :: proc(path: string, data: []u8) -> Tool_Error {
 temporary := fmt.aprintf("%s.next-%d", path, time.now()._nsec); defer delete(temporary)
 file, open_error := os.open(temporary, {.Write, .Create, .Excl}, os.perm_number(0o600))
 if open_error != nil {return {kind = .IO}}
 closed, renamed := false, false
 defer {
  if !closed {os.close(file)}
  if !renamed {os.remove(temporary)}
 }
 offset := 0
 for offset < len(data) {
  count, error := os.write(file, data[offset:])
  if error != nil || count <= 0 {return {kind = .IO}}
  offset += count
 }
 if os.flush(file) != nil {return {kind = .IO}}
 close_error := os.close(file); closed = true
 if close_error != nil {return {kind = .IO}}
 if os.rename(temporary, path) != nil {return {kind = .IO}}
 renamed = true
 return {}
}

qr_remove :: proc(runner: ^Runner) {
 if runner.storage.directory == "" {return}
 path := fmt.aprintf("%s/qr.json", runner.storage.directory); defer delete(path)
 // A cleanup failure leaves an expiring rendering inside the private0600 file.
 _ = os.remove(path)
}

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

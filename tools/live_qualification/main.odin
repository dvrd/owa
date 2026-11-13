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

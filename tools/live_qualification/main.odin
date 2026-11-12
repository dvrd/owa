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

Command :: enum {None, Pair, Inspect, Qualify, Preview}
Options :: struct {
 command: Command,
 auth_dir, group_subject: string,
 send, preview: bool,
 timeout_seconds: int,
}
Tool_Error_Kind :: enum {
 None, Usage, Storage, Trust, Connect, Timeout, Protocol, QR, IO, Allocation,
 Target_Not_Found, Target_Ambiguous, Scope, Send, Journal, Unexpected_Pairing,
}
Tool_Error :: struct {kind: Tool_Error_Kind, storage: Storage_Error, socket: wa.Socket_Error}
Phase :: enum {
 STORAGE_READY, VERSION_DISCOVERY, VERSION_DISCOVERED, VERSION_PINNED,
 CONNECTING, PAIRED, RECONNECTING, ONLINE, TARGET_READY, TEXT_QUEUED,
 PDF_QUEUED, ACK_WAIT, SERVER_ACKED, ACK_PENDING, RESUME_UNKNOWN, COMPLETE, PREVIEW_READY,
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
 case: return {}, {kind = .Usage}
 }
 index := 1
 timeout_seen := false
 for index < len(args) {
  flag := args[index]; index += 1
  if flag == "--help" {return {}, {}}
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
  case "--group-subject":
   if options.group_subject != "" || !subject_valid(value) {return {}, {kind = .Usage}}
   options.group_subject = value
  case "--timeout-seconds":
   seconds, valid := strconv.parse_int(value)
   if timeout_seen || !valid || seconds < 10 || seconds > 600 {return {}, {kind = .Usage}}
   options.timeout_seconds, timeout_seen = seconds, true
  case: return {}, {kind = .Usage}
  }
 }
 if options.send && options.command != .Qualify {return {}, {kind = .Usage}}
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
 if error := runner_scope_guard(options, &runner.storage); error.kind != .None {return error}
 phase_print(.STORAGE_READY)
 if tls.root_pool_load_system(&runner.roots).kind != .None {return {kind = .Trust}}
 runner.config = {tls = {root_cas = runner.roots.roots[:runner.roots.count]},
  payload = wa.default_payload_config(), query_timeout = 10 * time.Second,
  auth_path = runner.storage.auth_path, prekey_path = runner.storage.prekey_path,
  state_path = runner.storage.state_path}
 phase_print(.VERSION_DISCOVERY)
 version := wa.web_version_discover({tls = runner.config.tls,
  timeout = 5 * time.Second, max_redirects = 2})
 runner.config.payload.version = version.version
 phase_print(version.source == .Pinned ? .VERSION_PINNED : .VERSION_DISCOVERED)
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
 runner, allocation := new(Runner)
 if allocation != nil || runner == nil {return {kind = .Allocation}}
 defer free(runner)
 runner.options = options
 budget := time.Duration(options.timeout_seconds) * time.Second
 runner.deadline = time.tick_add(time.tick_now(), budget)
 defer runner_close(runner)
 if error := runner_prepare(runner); error.kind != .None {return error}
 if error := runner_online(runner); error.kind != .None {return error}
 if options.command != .Pair {
  if error := runner_actions(runner); error.kind != .None {return error}
 }
 phase_print(.COMPLETE)
 return {}
}

main :: proc() {
 context.logger = log.nil_logger()
 options, error := options_parse(os.args[1:])
 if error.kind != .None || options.command == .None {
  fmt.println("Usage: live_qualification pair|inspect|qualify --auth-dir /private/owned-dir")
  fmt.println("       network modes require --group-subject; only qualify accepts --send")
  fmt.println("       preview or --preview performs no network or session initialization")
  if error.kind != .None {os.exit(2)}
  return
 }
 if options.command == .Preview || options.preview {phase_print(.PREVIEW_READY); return}
 failure := run_command(options)
 if failure.kind != .None {
  fmt.eprintf("ERROR %v STORAGE %v SOCKET %v CERTIFICATE %v SESSION %v CODE %d\n",
   failure.kind, failure.storage, failure.socket.kind,
   failure.socket.session.client.certificate, failure.socket.session.kind,
   failure.socket.session.server_code)
  os.exit(1)
 }
}

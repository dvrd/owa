package main

import wa "../.."
import "core:os"
import "core:sync"
import "core:testing"
import "core:time"

@(test)
watch_parser_bounds_runtime_and_requires_separate_retry_authorization :: proc(t: ^testing.T) {
 args := []string{"watch", "--auth-dir", "/private/synthetic", "--group-subject", "offline"}
 options, error := options_parse(args)
 testing.expect_value(t, error.kind, .None)
 testing.expect_value(t, options.timeout_seconds, 86400)
 testing.expect(t, !options.send && !options.allow_scoped_retries)
 for suffix in ([]([]string){
  {"--send"}, {"--preview"}, {"--hold-seconds", "0"},
  {"--timeout-seconds", "59"}, {"--timeout-seconds", "172801"},
  {"--allow-scoped-retries", "--allow-scoped-retries"},
 }) {
  all := make([dynamic]string); defer delete(all)
  append(&all, ..args); append(&all, ..suffix)
  _, rejected := options_parse(all[:]); testing.expect_value(t, rejected.kind, .Usage)
 }
 _, accepted := options_parse({"watch", "--auth-dir", "/private/synthetic",
  "--group-subject", "offline", "--timeout-seconds", "172800", "--allow-scoped-retries"})
 testing.expect_value(t, accepted.kind, .None)
 _, misplaced := options_parse({"preview", "--allow-scoped-retries"})
 testing.expect_value(t, misplaced.kind, .Usage)
}

@(test)
watch_retry_policy_excludes_auth_security_schema_and_server_rejection :: proc(t: ^testing.T) {
 for kind in ([]wa.Socket_Error_Kind{.Server_Rejected, .Message_Rejected, .Identity_Changed,
  .Binary_Failed, .State_Failed, .Protocol_Error, .Signal_Failed}) {
  testing.expect(t, !watch_retryable({kind = .Protocol, socket = {kind = kind}}))
 }
 testing.expect(t, watch_retryable({kind = .Protocol, socket = {kind = .Session_Failed,
  session = {kind = .Connection_Lost}}}))
 testing.expect(t, watch_retryable({kind = .Protocol, socket = {kind = .Session_Failed,
  session = {kind = .Client_Failed, client = {kind = .Peer_Closed}}}}))
 testing.expect(t, !watch_retryable({kind = .Protocol, socket = {kind = .Session_Failed,
  session = {kind = .Client_Failed, client = {kind = .Certificate_Rejected}}}}))
 testing.expect(t, !watch_retryable({kind = .Connect, socket = {kind = .Websocket_Failed,
  websocket = {kind = .TLS_Failed, tls = {kind = .Handshake_Failed}}}}))
 for attempt in 0..<100 {
  delay := watch_backoff(attempt, 65535)
  testing.expect(t, delay >= time.Second && delay <= 30500*time.Millisecond)
 }
}

@(test)
watch_admits_only_acknowledged_scoped_content_and_refuses_startup_pending :: proc(t: ^testing.T) {
 sync.mutex_lock(&probe_test_mutex); defer sync.mutex_unlock(&probe_test_mutex)
 root := probe_test_directory(); defer delete(root); defer os.remove_all(root)
 path := storage_path(root, "auth"); defer delete(path)
 s := new(Storage); defer free(s); defer storage_close(s)
 failure := storage_open(s, path, .Pair_New, "offline")
 testing.expect_value(t, failure, .None); if failure != .None {return}
 assert(storage_scope_target(s, "123@g.us") == .None)
 id, prepared := storage_journal_prepare(s, "text", "synthetic")
 assert(prepared == .None); defer delete(id)
 options := Options{command = .Watch, group_subject = "offline", allow_scoped_retries = true}
 testing.expect_value(t, runner_scope_guard(options, s).kind, .Scope)
 assert(storage_journal_mark(s, "text", id, .Queued) == .None)
 assert(storage_journal_mark(s, "text", id, .Acknowledged) == .None)
 probe_test_node(s, .Outbound_Content, id, {tag = "saved", attrs = {{"to", "123@g.us"}}})
 testing.expect_value(t, runner_scope_guard(options, s).kind, .None)
 options.allow_scoped_retries = false
 testing.expect_value(t, runner_scope_guard(options, s).kind, .Scope)
 options.allow_scoped_retries = true
 probe_test_node(s, .Outbound_Message, id,
  {tag = "message", attrs = {{"to", "123@g.us"}, {"id", id}}})
 testing.expect_value(t, runner_scope_guard(options, s).kind, .Scope)
 testing.expect_value(t, watch_scope_guard(options, s, true).kind, .None)
 probe_test_node(s, .Outbound_Message, id,
  {tag = "message", attrs = {{"to", "456@g.us"}, {"id", id}}})
 testing.expect_value(t, watch_scope_guard(options, s, true).kind, .Scope)
}

@(test)
watch_resource_guard_stops_before_native_store_capacity :: proc(t: ^testing.T) {
 s := new(Storage); defer free(s)
 testing.expect(t, watch_state_bounded(s))
 s.state.records = make([dynamic]wa.State_Record, 49153)
 defer delete(s.state.records)
 testing.expect(t, !watch_state_bounded(s))
}

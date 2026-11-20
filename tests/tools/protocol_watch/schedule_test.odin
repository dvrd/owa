package protocol_watch_test
import "core:fmt"
import "core:slice"
import w "../../../tools/protocol_watch"
import "core:mem"
import "core:os"
import "core:strings"
import p "core:sys/posix"
import "core:testing"
import "core:time"
valid_agent_result :: proc() -> w.Value {
	return w.object(
		{"status", w.text("NO_ACTION")},
		{"summary", w.text("No compatibility approval from hashes.")},
		{"findings", w.array()},
	)
}
schedule_options_for_test :: proc(root: string) -> w.Schedule {
	return w.Schedule {
		state_dir = w.join(root, "state"),
		manifest = w.join(w.library_root(), "tools/protocol_watch/sources.json"),
		library = w.library_root(),
		codex = "/fake/codex",
		executable = "/fake/protocol-watch",
		budget_seconds = 600,
	}
}
shell_argv :: proc(script: string) -> []string {
	values := []string{"/bin/sh", "-c", script}
	out := make([]string, len(values))
	copy(out, values)

	return out
}
@(test)
schedule_command_explicit_read_only :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	argv := w.build_review_agent_argv("/fake/codex", "/public/library", "/private/schema")
	testing.expect(
		t,
		argv[1] == "exec" &&
		argv[2] == "--sandbox" &&
		argv[3] == "read-only" &&
		argv[4] == "--ephemeral" &&
		argv[len(argv) - 1] == "-",
	)
	testing.expect(t, !slice.contains(argv, "--model") && !slice.contains(argv, "--add-dir"))
}
@(test)
schedule_plist_daily_no_install :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	args := schedule_options_for_test(root)
	data, failure := w.plist(args)
	testing.expect(
		t,
		failure == nil &&
		strings.contains(data, "<integer>9</integer>") &&
		strings.contains(data, "<key>RunAtLoad</key><false/>") &&
		strings.contains(data, "<integer>63</integer>"),
	)
	result: w.Value
	result, failure = w.write_plist(args)
	testing.expect(t, failure == nil && w.json_boolean_equals(w.get(result, "installed"), false))
	testing.expect(t, w.private_file(w.join(args.state_dir, "review-agent/daily-review.plist")) == nil)
	args.budget_seconds = 601; _, failure = w.plist(args)
	testing.expect(t, failure == w.Failure("BUDGET_INVALID"))
}
@(test)
schedule_result_schema_bounded :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	testing.expect(t, w.validate_result(valid_agent_result()) == nil)

	for mode in 0 ..< 4 {
		value := valid_agent_result()
		switch mode {case 0:
			w.put(&value, "extra", w.text("untrusted"))
		case 1:
			w.put(&value, "summary", w.text(strings.repeat("x", 2001)))
		case 2:
			entries := w.array()

			for _ in 0 ..< 11 {
				a := w.items(entries)
				append(&a, w.object())
				entries = a
			}

			w.put(&value, "findings", entries)
		case 3:
			w.put(&value, "status", w.text("COMPATIBLE"))
		}; testing.expect(t, w.validate_result(value) == w.Failure("AGENT_RESULT_INVALID"))
	}
}
@(test)
schedule_real_child_stdin_schema :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	script := w.concatenate_strings(
		"value=$(cat); test \"$value\" = 'public report' || exit 8; printf '%s\\n' '",
		w.encode(valid_agent_result()),
		"'",
	)
	result, failure := w.agent_run(shell_argv(script), transmute([]u8)string("public report"), 3)
	testing.expect(t, failure == nil && w.equal(result, valid_agent_result()))
}
@(test)
schedule_nonreading_stdin_deadline :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	start := time.tick_now()
	_, failure := w.agent_run(shell_argv("sleep 30"), transmute([]u8)strings.repeat("x", 256 * 1024), 1)
	testing.expect(t, failure == w.Failure("AGENT_DEADLINE"))
	testing.expect(t, time.tick_diff(start, time.tick_now()) < 4 * time.Second)
}
@(test)
schedule_stderr_never_returned :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	_, failure := w.agent_run(
		shell_argv("cat >/dev/null; printf private-secret-token >&2; exit 1"),
		transmute([]u8)string("public"),
		3,
	); testing.expect(t, failure == w.Failure("AGENT_EXEC_FAILED"))
}
watch_ok :: proc(args: w.Schedule) -> (w.Value, w.Failure) {
	return w.object(
			{"status", w.text("REVIEW_REQUIRED")},
			{"compatibility_approved", w.boolean(false)},
			{
				"observation",
				w.object(
					{
						"sources",
						w.array(
							w.object(
								{"name", w.text("public")},
								{"files", w.array(w.object({"path", w.text("protocol.go")}))},
							),
						),
					},
				),
			},
		),
		nil
}
watch_fail :: proc(args: w.Schedule) -> (w.Value, w.Failure) {
	return w.null(), "WATCH_EXEC_FAILED"
}
agent_ok :: proc(argv: []string, prompt: []u8, seconds: int) -> (w.Value, w.Failure) {
	assert(strings.contains(string(prompt), "PUBLIC REPORT JSON:") && !strings.contains(string(prompt), "auth_dir"))

	return valid_agent_result(), nil
}
agent_forbidden :: proc(argv: []string, prompt: []u8, seconds: int) -> (w.Value, w.Failure) {
	panic("agent must not run")
}
@(test)
schedule_watch_then_agent_never_approves_drift :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	args := schedule_options_for_test(root)
	result, failure := w.schedule_run(args, watch_ok, agent_ok)
	testing.expect(t, failure == nil)
	testing.expect_value(t, w.str(w.get(result, "status")), "REVIEW_REQUIRED")
	testing.expect(t, w.json_boolean_equals(w.get(result, "compatibility_approved"), false))
	testing.expect(t, w.private_file(w.join(args.state_dir, "review-agent/agent-review.json")) == nil)
	testing.expect(t, os.exists(w.join(args.state_dir, "review-agent/alert.json")))
}
@(test)
schedule_watcher_failure_skips_agent :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	result, failure := w.schedule_run(schedule_options_for_test(root), watch_fail, agent_forbidden)
	testing.expect(t, failure == nil && w.str(w.get(result, "status")) == "FAILED")
}
@(test)
schedule_singleton_excludes_parallel_jobs :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	args := schedule_options_for_test(root)
	fd, failure := w.locked_state(args.state_dir)
	assert(failure == nil)
	p.close(fd)
	lock, lock_failure := w.locked_state(w.join(args.state_dir, "review-agent"))
	assert(lock_failure == nil)
	defer p.close(lock)
	_, failure = w.schedule_run(args, watch_ok, agent_forbidden)
	testing.expect(t, failure == w.Failure("ALREADY_RUNNING"))
}
@(test)
schedule_sanitizes_environment :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	for entry in w.agent_environment(
		
	) {testing.expect(t, !strings.has_prefix(entry, "LINEAR_API=") && !strings.has_prefix(entry, "AWS_SECRET_ACCESS_KEY="))}
	script := w.concatenate_strings(
		"test -z \"$LINEAR_API\" && test -z \"$AWS_SECRET_ACCESS_KEY\" || exit 9; cat >/dev/null; printf '%s\\n' '",
		w.encode(valid_agent_result()),
		"'",
	); _, failure := w.agent_run(shell_argv(script), nil, 3); testing.expect(t, failure == nil)
}
@(test)
schedule_oversized_stdout_killed :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	_, failure := w.agent_run(shell_argv("cat >/dev/null; head -c 70000 /dev/zero"), nil, 3)
	testing.expect(t, failure == w.Failure("AGENT_OUTPUT_LIMIT"))
}
watcher_argv :: proc(state: string, report: w.Value, write: bool, code: int, summary: w.Value = nil) -> []string {
	without := summary

	if summary == nil {
		without = w.object()

		for key in w.keys(report) {
			if key != "observation" {
				w.put(&without, key, w.get(report, key))
			}
		}
	}

	script := ""

	if write {
		script = "printf '%s\\n' \"$2\" > \"$1/new.json\"; chmod 600 \"$1/new.json\"; mv \"$1/new.json\" \"$1/report.json\"; "
	}; script = w.concatenate_strings(script, "printf '%s\\n' \"$3\"; exit ", fmt.aprint(code))
	values := []string{"/bin/sh", "-c", script, "sh", state, w.encode(report), w.encode(without)}
	out := make([]string, len(values))
	copy(out, values)

	return out
}
@(test)
schedule_fresh_report_and_summary_match :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	args := schedule_options_for_test(root)
	fd, failure := w.locked_state(args.state_dir)
	assert(failure == nil)
	p.close(fd)
	report := w.object(
		{"status", w.text("NO_MONITORED_DRIFT")},
		{"compatibility_approved", w.boolean(false)},
		{"observation", w.object({"sources", w.array()})},
	); assert(w.atomic_json(w.join(args.state_dir, "report.json"), report) == nil)
	result: w.Value
	result, failure = w.watch_run(args, watcher_argv(args.state_dir, report, true, 0))
	testing.expect(t, failure == nil && w.equal(result, report))
	_, failure = w.watch_run(args, watcher_argv(args.state_dir, report, false, 0))
	testing.expect(t, failure == w.Failure("WATCH_REPORT_STALE"))
	summary := w.object({"status", w.text("NO_MONITORED_DRIFT")}, {"compatibility_approved", w.boolean(false)})
	w.put(&report, "compatibility_approved", w.boolean(true))
	_, failure = w.watch_run(args, watcher_argv(args.state_dir, report, true, 0, summary))
	testing.expect(t, failure == w.Failure("WATCH_REPORT_MISMATCH"))
}
@(test)
schedule_failed_watcher_preserves_report :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	args := schedule_options_for_test(root)
	fd, failure := w.locked_state(args.state_dir)
	assert(failure == nil)
	p.close(fd)
	report := w.object({"status", w.text("NO_MONITORED_DRIFT")}, {"observation", w.object()})
	path := w.join(args.state_dir, "report.json")
	assert(w.atomic_json(path, report) == nil)
	before, _ := os.read_entire_file(path, context.allocator)
	_, failure = w.watch_run(args, watcher_argv(args.state_dir, report, false, 2))
	testing.expect(t, failure == w.Failure("WATCH_EXEC_FAILED"))
	after, _ := os.read_entire_file(path, context.allocator)
	testing.expect_value(t, string(before), string(after))
}
@(test)
schedule_stalled_watcher_hard_killed :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	started := time.tick_now()
	_, failure := w.watch_capture(shell_argv("trap '' TERM; sleep 30"), 50 * time.Millisecond)
	testing.expect(t, failure == w.Failure("WATCH_DEADLINE"))
	testing.expect(t, time.tick_diff(started, time.tick_now()) < time.Second)
}
@(test)
schedule_exit_three_only_review_required :: proc(t: ^testing.T) {
	arena := setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	args := schedule_options_for_test(root)
	fd, failure := w.locked_state(args.state_dir)
	assert(failure == nil)
	p.close(fd)
	report := w.object({"status", w.text("REVIEW_REQUIRED")}, {"observation", w.object()})
	result: w.Value
	result, failure = w.watch_run(args, watcher_argv(args.state_dir, report, true, 3))
	testing.expect(t, failure == nil && w.str(w.get(result, "status")) == "REVIEW_REQUIRED")
	_, failure = w.watch_run(args, watcher_argv(args.state_dir, report, true, 0))
	testing.expect(t, failure == w.Failure("WATCH_RESULT_INVALID"))
}

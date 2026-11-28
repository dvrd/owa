package protocol_watch_test

import w "../../../tools/protocol_watcher/src"
import test_fixtures "../../fixtures/protocol_watch"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import p "core:sys/posix"
import "core:testing"
import "core:time"

@(test)
schedule_real_child_stdin_schema :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	script := w.concatenate_strings(
		"value=$(cat); test \"$value\" = 'public report' || exit 8; printf '%s\\n' '",
		w.encode(test_fixtures.valid_agent_result()),
		"'",
	)
	result, failure := w.agent_run(test_fixtures.shell_argv(script), transmute([]u8)string("public report"), 3)
	testing.expect(t, failure == nil && w.equal(result, test_fixtures.valid_agent_result()))
}

@(test)
schedule_nonreading_stdin_deadline :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	start := time.tick_now()
	_, failure := w.agent_run(test_fixtures.shell_argv("sleep 30"), transmute([]u8)strings.repeat("x", 256 * 1024), 1)
	testing.expect(t, failure == w.Failure("AGENT_DEADLINE"))
	testing.expect(t, time.tick_diff(start, time.tick_now()) < 4 * time.Second)
}

@(test)
schedule_stderr_never_returned :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	_, failure := w.agent_run(
		test_fixtures.shell_argv("cat >/dev/null; printf private-secret-token >&2; exit 1"),
		transmute([]u8)string("public"),
		3,
	); testing.expect(t, failure == w.Failure("AGENT_EXEC_FAILED"))
}

@(test)
schedule_oversized_stdout_killed :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	_, failure := w.agent_run(test_fixtures.shell_argv("cat >/dev/null; head -c 70000 /dev/zero"), nil, 3)
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
	}

	script = w.concatenate_strings(script, "printf '%s\\n' \"$3\"; exit ", fmt.aprint(code))
	values := []string{"/bin/sh", "-c", script, "sh", state, w.encode(report), w.encode(without)}

	out := make([]string, len(values))
	copy(out, values)

	return out
}

@(test)
schedule_fresh_report_and_summary_match :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)

	args := test_fixtures.schedule_options_for_test(root)
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
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)

	args := test_fixtures.schedule_options_for_test(root)
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
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	started := time.tick_now()
	_, failure := w.watch_capture(test_fixtures.shell_argv("trap '' TERM; sleep 30"), 50 * time.Millisecond)
	testing.expect(t, failure == w.Failure("WATCH_DEADLINE"))
	testing.expect(t, time.tick_diff(started, time.tick_now()) < time.Second)
}

@(test)
schedule_exit_three_only_review_required :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)

	args := test_fixtures.schedule_options_for_test(root)
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

@(test)
schedule_sanitizes_environment :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	for entry in w.agent_environment() {testing.expect(t, !strings.has_prefix(entry, "LINEAR_API=") && !strings.has_prefix(entry, "AWS_SECRET_ACCESS_KEY="))}

	script := w.concatenate_strings(
		"test -z \"$LINEAR_API\" && test -z \"$AWS_SECRET_ACCESS_KEY\" || exit 9; cat >/dev/null; printf '%s\\n' '",
		w.encode(test_fixtures.valid_agent_result()),
		"'",
	); _, failure := w.agent_run(test_fixtures.shell_argv(script), nil, 3); testing.expect(t, failure == nil)
}

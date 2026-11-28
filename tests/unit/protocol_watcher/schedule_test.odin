package protocol_watch_test

import w "../../../tools/protocol_watcher/src"
import test_fixtures "../../fixtures/protocol_watch"
import "core:mem"
import "core:os"
import "core:slice"
import "core:strings"
import p "core:sys/posix"
import "core:testing"

@(test)
schedule_command_explicit_read_only :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
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
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)

	args := test_fixtures.schedule_options_for_test(root)
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
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	testing.expect(t, w.validate_result(test_fixtures.valid_agent_result()) == nil)

	for mode in 0 ..< 4 {
		value := test_fixtures.valid_agent_result()
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
		}

		testing.expect(t, w.validate_result(value) == w.Failure("AGENT_RESULT_INVALID"))
	}
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

	return test_fixtures.valid_agent_result(), nil
}

agent_forbidden :: proc(argv: []string, prompt: []u8, seconds: int) -> (w.Value, w.Failure) {
	panic("agent must not run")
}

@(test)
schedule_watch_then_agent_never_approves_drift :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)

	args := test_fixtures.schedule_options_for_test(root)
	result, failure := w.schedule_run(args, watch_ok, agent_ok)
	testing.expect(t, failure == nil)
	testing.expect_value(t, w.str(w.get(result, "status")), "REVIEW_REQUIRED")
	testing.expect(t, w.json_boolean_equals(w.get(result, "compatibility_approved"), false))
	testing.expect(t, w.private_file(w.join(args.state_dir, "review-agent/agent-review.json")) == nil)
	testing.expect(t, os.exists(w.join(args.state_dir, "review-agent/alert.json")))
}

@(test)
schedule_watcher_failure_skips_agent :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)

	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-schedule-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)

	result, failure := w.schedule_run(test_fixtures.schedule_options_for_test(root), watch_fail, agent_forbidden)
	testing.expect(t, failure == nil && w.str(w.get(result, "status")) == "FAILED")
}

@(test)
schedule_singleton_excludes_parallel_jobs :: proc(t: ^testing.T) {
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
	lock, lock_failure := w.locked_state(w.join(args.state_dir, "review-agent"))
	assert(lock_failure == nil)
	defer p.close(lock)

	_, failure = w.schedule_run(args, watch_ok, agent_forbidden)
	testing.expect(t, failure == w.Failure("ALREADY_RUNNING"))
}

package protocol_watch_test

import w "../src"
import "core:mem"
import "core:testing"

@(test)
cli_option_pairs_preserve_values_and_reject_duplicate_flags :: proc(t: ^testing.T) {
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena)
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)

	options, err := w.parse_option_pairs([]string{"--state-dir", "state", "--report", "report.json"})
	testing.expect(t, err == nil)
	testing.expect_value(t, w.str(w.get(options, "--report")), "report.json")
	_, duplicate := w.parse_option_pairs([]string{"--report", "first", "--report", "second"})
	testing.expect_value(t, duplicate, w.Failure("ARGUMENTS_INVALID"))
}

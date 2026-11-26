package protocol_fixture

import w "../../../tools/protocol_watcher/src"
import "core:mem"

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
		manifest = w.join(w.library_root(), "tools/protocol_watcher/sources.json"),
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

ROOT :: #directory + "/../../.."

HEAD :: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

setup_arena :: proc() -> mem.Dynamic_Arena {
	a: mem.Dynamic_Arena
	mem.dynamic_arena_init(&a)

	return a
}

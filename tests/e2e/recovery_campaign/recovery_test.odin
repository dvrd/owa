package main

import child "../child_process"
import "base:runtime"
import "core:fmt"
import "core:os"
import "core:testing"

@(init)
run_recovery_child :: proc "contextless" () {
	context = runtime.default_context()
	if len(os.args) < 2 || os.args[1] != "--recovery-fixture" {
		return
	}

	assert(len(os.args) == 5)
	switch os.args[2] {
	case "write":
		child_write_stage(os.args[3], os.args[4])
	case "verify":
		verify(os.args[3], os.args[4])
	case:
		panic("Unknown recovery operation")
	}

	os.exit(0)
}

@(test)
send_state_survives_process_exit :: proc(t: ^testing.T) {
	for stage in ([]string {
			"control",
			"before-commit",
			"after-intent",
			"after-pending-wire",
			"after-positive-ack",
			"after-ack-journal",
		}) {
		directory, err := os.make_directory_temp("/tmp", "wa-recovery-*", context.allocator)
		assert(err == nil)
		defer delete(directory)

		defer os.remove_all(directory)

		writer := child.start("write", directory, stage)
		defer child.close(&writer)

		if stage == "control" {
			child.wait(&writer)
		} else {
			testing.expect_value(
				t,
				child.read_line(&writer),
				fmt.tprintf("BOUNDARY_READY %s", stage),
			)
			child.kill_at_boundary(&writer)
		}

		reader := child.start("verify", directory, stage)
		defer child.close(&reader)

		child.wait(&reader)
	}
}

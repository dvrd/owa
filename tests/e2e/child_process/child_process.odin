package child_process

import "core:fmt"
import "core:os"
import "core:sync"
import "core:sys/posix"
import "core:time"

Child :: struct {
	process: os.Process,
	output:  ^os.File,
	running: bool,
}

start_mutex: sync.Mutex

// Reuse the test executable so the child has exactly the parent's compiler and sanitizer flags.
start :: proc(args: ..string) -> Child {
	sync.mutex_lock(&start_mutex)
	defer sync.mutex_unlock(&start_mutex)

	exe, lookup := os.get_executable_path(context.allocator)
	assert(lookup == nil)
	defer delete(exe)

	command := make([]string, 2 + len(args))
	defer delete(command)

	command[0], command[1] = exe, "--recovery-fixture"
	copy(command[2:], args)
	reader, writer, pipe_error := os.pipe()
	assert(pipe_error == nil)
	defer os.close(writer)

	process, err := os.process_start({command = command, stdout = writer, stderr = os.stderr})

	assert(err == nil)
	return {process, reader, true}
}

read_line :: proc(child: ^Child) -> string {
	buffer: [512]u8
	started := time.tick_now()
	fd := posix.pollfd {
		fd     = posix.FD(os.fd(child.output)),
		events = {.IN},
	}

	for i in 0 ..< len(buffer) {
		for {
			remaining := 15 * time.Second - time.tick_since(started)
			assert(remaining > 0, "Child output timeout")
			ready := posix.poll(&fd, 1, i32(remaining / time.Millisecond))
			if ready < 0 && posix.errno() == .EINTR {continue}

			assert(ready > 0, "Child output timeout")
			break
		}

		n, err := os.read(child.output, buffer[i:i + 1])
		assert(err == nil && n == 1, "Child closed stdout before expected line")
		if buffer[i] == '\n' {
			return fmt.tprintf("%s", string(buffer[:i]))
		}
	}

	panic("Child output line exceeds fixture limit")
}

wait :: proc(child: ^Child, killed := false) {
	state, err := os.process_wait(child.process, 20 * time.Second)
	if err == os.General_Error.Timeout {
		_ = os.process_kill(child.process)
		_, _ = os.process_wait(child.process)
	}

	child.running = false
	assert(err == nil && state.exited)
	if killed {
		assert(!state.success && state.exit_code == int(posix.SIGKILL))
	} else {
		assert(state.success)
	}
}

kill_at_boundary :: proc(child: ^Child) {
	assert(os.process_kill(child.process) == nil)
	wait(child, true)
}

close :: proc(child: ^Child) {
	if child.running {
		_ = os.process_kill(child.process)
		_, _ = os.process_wait(child.process)
	}

	os.close(child.output)
}

#+feature dynamic-literals
package main

import "core:fmt"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:time"

STRICT := []string {
	"-vet",
	"-warnings-as-errors",
	"-define:ODIN_TEST_THREADS=1",
	"-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true",
}

check_pairs :: proc(source, tests: string) -> os.Error {
	for dir in ([]string{source, tests}) {
		entries := os.read_directory_by_path(dir, -1, context.allocator) or_return
		for entry in entries {
			suffix := ".odin" if dir == source else "_test.odin"
			if !strings.has_suffix(entry.name, suffix) {
				continue
			}

			stem := entry.name[:len(entry.name) - len(suffix)]
			want :=
				join(tests, fmt.aprintf("%s_test.odin", stem)) if \
					dir == source else \
					join(source, fmt.aprintf("%s.odin", stem))
			if !os.is_file(want) {
				fmt.eprintln("Missing counterpart for", join(dir, entry.name), ":", want)
				return .Not_Exist
			}
		}
	}

	return nil
}

suites :: proc(selector: string, internal: bool) -> (result: [dynamic]string, err: os.Error) {
	selected := selector
	switch selector {
	case "public_api", "tests":
		selected = "."
	case "tools/protocol_watch":
		selected = "tools/protocol_watcher"
	case "tools/protocol_watcher/tests":
		selected = "tests/unit/protocol_watcher"
	case "encrypted_recovery", "loopback_noise", "recovery_campaign", "version_http":
		selected = join("e2e", selector)
	}

	candidates := [dynamic]string{"tests/unit", "tests/unit/protocol_watcher"}

	dirs := os.read_directory_by_path("tests/e2e", -1, context.allocator) or_return
	for dir in dirs {
		if dir.type == .Directory {
			append(&candidates, join("tests/e2e", dir.name))
		}
	}

	slice.sort(candidates[2:])
	for path in candidates {
		owner := strings.trim_prefix(path, "tests/")
		switch path {
		case "tests/unit":
			owner = "."
		case "tests/unit/protocol_watcher":
			owner = "tools/protocol_watcher"
		}

		if internal && owner != "." {
			continue
		}

		if selected != "all" &&
		   selected != path &&
		   selected != owner &&
		   !(selected == "e2e" && strings.has_prefix(owner, "e2e/")) &&
		   !(selected == "tools/protocol_watcher" && owner == "e2e/protocol_watch") {
			continue
		}

		files := os.read_directory_by_path(path, -1, context.allocator) or_return
		for file in files {
			if strings.has_suffix(file.name, "_test.odin") {
				append(&result, path); break
			}
		}
	}

	if len(result) == 0 {
		fmt.eprintln("No matching test suites for", selected)
		return result, .Invalid_Path
	}

	return result, nil
}

interrupted: i32
on_interrupt :: proc "c" (sig: posix.Signal) {
	sync.atomic_store(&interrupted, i32(sig))
}

// The suite becomes its own process group before exec so its compiler and
// loopback peers can all be stopped on cancellation or timeout.
exec_suite :: proc(args: []string) -> os.Error {
	if len(args) == 0 || posix.setpgid(0, 0) != .OK {
		return .Invalid_Command
	}

	argv := make([]cstring, len(args) + 1)
	for arg, i in args {argv[i] = strings.clone_to_cstring(arg)}

	posix.execvp(argv[0], raw_data(argv))
	return .Invalid_Command
}

timed_suite :: proc(args: []string, dir: string) -> os.Error {
	self := os.get_executable_path(context.allocator) or_return
	command := [dynamic]string{self, "exec-suite"}

	append(&command, ..args)
	child := os.process_start(
		{command = command[:], working_dir = dir, stdout = os.stdout, stderr = os.stderr},
	) or_return
	start := time.tick_now()
	for sync.atomic_load(&interrupted) == 0 && time.tick_since(start) < 300 * time.Second {
		state, err := os.process_wait(child, 250 * time.Millisecond)
		if err == .Timeout {
			continue
		}

		if err != nil {
			return err
		}

		if state.exit_code != 0 {
			fmt.eprintln("Test process exited with status", state.exit_code)
			return .Invalid_Command
		}

		return nil
	}

	fmt.eprintln("Test interrupted or timed out:", args[2])
	group := -posix.pid_t(child.pid)
	posix.kill(group, .SIGTERM)
	// If interrupted before setpgid, the compiler has not started yet.
	_ = os.process_terminate(child)
	time.sleep(5 * time.Second)
	posix.kill(group, .SIGKILL)
	_, _ = os.process_wait(child)
	return .Timeout
}

test_command :: proc(mode: string, args: []string) -> os.Error {
	root := os.get_working_directory(context.allocator) or_return
	compiler := env_or("ODIN", "odin")
	deps := env_or("WEBTOOLS_SHARED", join(env_or("HOME", ""), "dev/oss/Odin/shared"))
	options := args
	selected := "all"
	internal := false
	flags: [dynamic]string
	if mode == "protocol" {
		compiler = env_or("OWA_ODIN_BIN", compiler)
		deps = env_or("OWA_SHARED_ROOT", deps)
		append(&flags, "-thread-count:1")
	}

	if mode == "check" {
		check_pairs("src", "tests/unit") or_return
		check_pairs("tools/protocol_watcher/src", "tests/unit/protocol_watcher") or_return
	}

	if mode != "test" {
		append(&flags, ..STRICT)
	}

	for mode != "protocol" && len(options) > 0 {
		key := options[0]
		switch key {
		case "--":
			options = options[1:]
			break
		case "--help", "-h":
			fmt.println(
				"Usage: task test:odin -- [--odin PATH] [--shared DIR] [--package PATH] [--internal-only] [-- Odin flags]",
			)
			return nil
		case "--internal-only":
			internal = true
			options = options[1:]
			continue
		case "--odin", "--shared", "--package":
			if len(options) < 2 {
				fmt.eprintln("Missing argument for", key)
				return .Invalid_Command
			}

			switch key {
			case "--odin":
				compiler = options[1]
			case "--shared":
				deps = options[1]
			case "--package":
				selected = options[1]
			}

			options = options[2:]
			continue
		}

		break
	}

	if strings.contains(compiler, "/") && !os.is_absolute_path(compiler) {
		compiler = join(root, compiler)
	}

	has_output := false
	for flag in options {
		if strings.has_prefix(flag, "-collection:shared=") {
			deps = strings.trim_prefix(flag, "-collection:shared="); continue
		}

		if strings.has_prefix(flag, "-out:") {
			has_output = true
		}

		append(&flags, flag)
	}

	work := os.make_directory_temp("", "owa-tests-*", context.allocator) or_return
	defer os.remove_all(work)

	os.chmod(work, {.Read_User, .Write_User, .Execute_User}) or_return
	dir := root
	targets := [dynamic]string{"tests/unit/protocol_watcher", "tests/e2e/protocol_watch"}

	if mode != "protocol" {
		targets = suites(selected, internal) or_return
		stage(root, work, compiler, deps) or_return
		dir = join(work, "repository")
		deps = join(work, "shared")
	}

	if !has_output {
		append(&flags, fmt.aprintf("-out:%s", join(work, "tests")))
	}

	for sig in ([]posix.Signal{.SIGTERM, .SIGINT, .SIGHUP}) {
		posix.signal(sig, on_interrupt)
	}

	for suite in targets {
		fmt.println("Testing", suite)
		command := [dynamic]string {
			compiler,
			"test",
			join(dir, suite),
			fmt.aprintf("-collection:shared=%s", deps),
		}

		append(&command, ..flags[:])
		timed_suite(command[:], dir) or_return
	}

	return nil
}

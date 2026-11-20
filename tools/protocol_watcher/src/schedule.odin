package protocol_watch
import "core:fmt"
import "core:slice"
import "core:c"
import j "core:encoding/json"
import "core:os"
import "core:strings"
import p "core:sys/posix"
import "core:time"
MAX_OUTPUT :: 65536
MAX_STREAM :: 2 * 1024 * 1024
LABEL :: "com.webtools.whatsapp.protocol-review"
SCHEDULE_SCHEMA :: #load("../result-schema.json")
Schedule :: struct {
	state_dir, manifest, library, codex, executable, approved_contract: string,
	budget_seconds:                                                     int,
}
validate_result :: proc(value: Value) -> Failure {
	if !has_exact_object_fields(value, []string{"status", "summary", "findings"}) ||
	   !slice.contains([]string{"NO_ACTION", "REVIEW_REQUIRED", "FAILED"}, str(get(value, "status"))) ||
	   !text_limit(get(value, "summary"), 0, 2000) {
		return "AGENT_RESULT_INVALID"
	}

	entries, ok := get(value, "findings").(j.Array)

	if !ok || len(entries) > 10 {
		return "AGENT_RESULT_INVALID"
	}

	for item in entries {
		if !has_exact_object_fields(item, []string{"severity", "source", "path", "recommendation"}) ||
		   !slice.contains([]string{"low", "medium", "high"}, str(get(item, "severity"))) ||
		   !text_limit(get(item, "source"), 0, 200) ||
		   !text_limit(get(item, "path"), 0, 200) ||
		   !text_limit(get(item, "recommendation"), 0, 2000) {
			return "AGENT_RESULT_INVALID"
		}
	}

	return nil
}
build_review_agent_argv :: proc(codex, library, schema: string) -> []string {
	values := []string {
		codex,
		"exec",
		"--sandbox",
		"read-only",
		"--ephemeral",
		"-C",
		library,
		"--output-schema",
		schema,
		"--color",
		"never",
		"-",
	}; result := make([]string, len(values)); copy(result, values); return result
}
agent_environment :: proc() -> []string {
	entries := make([dynamic]string)

	for name in ([]string{"HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "LC_ALL", "SHELL", "CODEX_HOME"}) {
		if value, ok := os.lookup_env(name, context.allocator); ok {
			append(&entries, concatenate_strings(name, "=", value))
		}
	}

	return entries[:]
}
capture :: proc(
	argv: []string,
	prompt: []u8,
	budget: time.Duration,
	kind: string,
	clock: proc "contextless" () -> time.Tick = time.tick_now,
) -> (
	output: []u8,
	code: int,
	failure: Failure,
) {
	if len(argv) == 0 || !strings.has_prefix(argv[0], "/") {
		return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
	}
	cargv := make([]cstring, len(argv) + 1)
	for item, i in argv {
		cargv[i] = strings.clone_to_cstring(item)
	}
	env := agent_environment()
	cenv := make([]cstring, len(env) + 1)
	for item, i in env {
		cenv[i] = strings.clone_to_cstring(item)
	}
	input, stdout, stderr: [2]p.FD
	if p.pipe(&input) != {} {
		return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
	}; defer {
		p.close(input[0])
		if input[1] >= 0 {
			p.close(input[1])
		}
	}
	if p.pipe(&stdout) != {} {
		return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
	}; defer {p.close(stdout[0]); p.close(stdout[1])}
	if p.pipe(&stderr) != {} {
		return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
	}; defer {p.close(stderr[0]); p.close(stderr[1])}
	old_signal: p.sigaction_t
	ignore: p.sigaction_t
	ignore.sa_handler = transmute(proc "c" (_: p.Signal))uintptr(1)
	if p.sigaction(p.Signal(p.SIGPIPE), &ignore, &old_signal) != {} {
		return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
	}; defer p.sigaction(p.Signal(p.SIGPIPE), &old_signal, nil)
	pid := p.fork()
	if pid < 0 {
		return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
	}
	if pid == 0 {
		if p.setsid() < 0 {
			p._exit(127)
		}

		if p.dup2(input[0], 0) < 0 || p.dup2(stdout[1], 1) < 0 || p.dup2(stderr[1], 2) < 0 {
			p._exit(127)
		}

		p.close(input[0])
		p.close(input[1])
		p.close(stdout[0])
		p.close(stdout[1])
		p.close(stderr[0])
		p.close(stderr[1])
		_ = p.execve(cargv[0], raw_data(cargv), raw_data(cenv))
		p._exit(127)
	}
	p.close(input[0])
	input[0] = -1
	p.close(stdout[1])
	stdout[1] = -1
	p.close(stderr[1])
	stderr[1] = -1
	for fd in ([3]p.FD{input[1], stdout[0], stderr[0]}) {_ = p.fcntl(fd, .SETFL, c.int(p.O_NONBLOCK))}
	reaped := false
	status: c.int
	defer {
		if !reaped {
			_ = p.kill(-pid, p.Signal(p.SIGKILL))
			_ = p.kill(pid, p.Signal(p.SIGKILL))
			_ = p.waitpid(pid, &status, {})
		}
	}
	deadline := time.tick_add(clock(), budget)
	offset, total := 0, 0
	collected := make([dynamic]u8)
	polls := [3]p.pollfd {
		{fd = input[1], events = {.OUT}},
		{fd = stdout[0], events = {.IN}},
		{fd = stderr[0], events = {.IN}},
	}
	if len(prompt) == 0 {
		p.close(input[1])
		input[1] = -1
		polls[0].fd = -1
	}
	for {
		if time.tick_diff(clock(), deadline) <= 0 {
			return nil, 0, concatenate_strings(kind, "_DEADLINE")
		}

		alive := 0

		for fd in polls {
			if fd.fd >= 0 {
				alive += 1
			}
		}; if alive == 0 {
			break
		}

		ready := p.poll(&polls[0], 3, 25)

		if ready < 0 {
			if p.errno() == .EINTR {
				continue
			}; return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
		}

		for &item, index in polls {
			if item.fd < 0 || item.revents == {} {
				continue
			}

			if index == 0 {
				n := p.write(item.fd, raw_data(prompt[offset:]), c.size_t(min(4096, len(prompt) - offset)))

				if n < 0 {
					if p.errno() == .EAGAIN || p.errno() == .EINTR {
						continue
					}; return nil, 0, concatenate_strings(kind, "_INPUT_FAILED")
				}; offset += int(n)
				if offset == len(prompt) {
					p.close(input[1])
					input[1] = -1
					item.fd = -1
				}
			} else {
				buffer: [4096]u8
				n := p.read(item.fd, &buffer[0], len(buffer))

				if n < 0 {
					if p.errno() == .EAGAIN || p.errno() == .EINTR {
						continue
					}; return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
				}

				if n == 0 {
					item.fd = -1
					continue
				}; total += int(n); if total > MAX_STREAM {
					return nil, 0, concatenate_strings(kind, "_STREAM_LIMIT")
				}

				if index == 1 {
					append(&collected, ..buffer[:n])

					if len(collected) > MAX_OUTPUT {
						return nil, 0, concatenate_strings(kind, "_OUTPUT_LIMIT")
					}
				}
			}
		}
	}
	for {
		if time.tick_diff(clock(), deadline) <= 0 {
			return nil, 0, concatenate_strings(kind, "_DEADLINE")
		}

		information: p.siginfo_t

		if p.waitid(.P_PID, p.id_t(pid), &information, {.NOHANG, .NOWAIT, .EXITED}) < 0 {
			if p.errno() == .EINTR {
				continue
			}; return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
		}

		if information.si_pid == pid {
			// Keep the leader unreaped while stopping its descendants, so its PID cannot be reused.
			if kind == "AGENT" {
				_ = p.kill(-pid, p.Signal(p.SIGKILL))
			}

			if p.waitpid(pid, &status, {}) != pid {
				return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
			}; reaped = true; break
		}

		time.sleep(time.Millisecond)
	}
	if !p.WIFEXITED(status) {
		return nil, 0, concatenate_strings(kind, "_EXEC_FAILED")
	}; return collected[:], int(p.WEXITSTATUS(status)), nil
}
agent_run :: proc(argv: []string, prompt: []u8, seconds: int) -> (value: Value, failure: Failure) {
	if seconds < 1 || seconds > 600 {
		return null(), "BUDGET_INVALID"
	}

	output, code := capture(argv, prompt, time.Duration(seconds) * time.Second, "AGENT") or_return

	if code != 0 {
		return null(), "AGENT_EXEC_FAILED"
	}; decoded, error := decode(output, MAX_OUTPUT); if error != "" {
		return null(), "AGENT_RESULT_INVALID"
	}; validate_result(decoded) or_return; return decoded, nil
}
watch_capture :: proc(argv: []string, budget := 240 * time.Second) -> (value: Value, failure: Failure) {
	output, code := capture(argv, nil, budget, "WATCH") or_return

	if code != 0 && code != 3 {
		return null(), "WATCH_EXEC_FAILED"
	}; decoded, error := decode(output, MAX_OUTPUT)
	expected := "NO_MONITORED_DRIFT" if code == 0 else "REVIEW_REQUIRED"

	if error != "" || str(get(decoded, "status")) != expected {
		return null(), "WATCH_RESULT_INVALID"
	}; return decoded, nil
}
Report_File :: struct {
	fd:     p.FD,
	device: p.dev_t,
	inode:  p.ino_t,
}
open_private_watch_report :: proc(path: string) -> (file: Report_File, failure: Failure) {
	fd := p.open(strings.clone_to_cstring(path), {.NOFOLLOW, .NONBLOCK, .CLOEXEC})

	if fd < 0 {
		return {}, "WATCH_REPORT_UNSAFE"
	}; info: p.stat_t
	if p.fstat(fd, &info) != {} || !is_private_state_file(info) {
		p.close(fd)
		return {}, "WATCH_REPORT_UNSAFE"
	}; return {fd, info.st_dev, info.st_ino}, nil
}
watch_run :: proc(args: Schedule, argv: []string = nil) -> (value: Value, failure: Failure) {
	path := join(args.state_dir, "report.json")
	previous: Report_File
	had_previous := false

	info: p.stat_t

	if p.lstat(strings.clone_to_cstring(path), &info) == {} {
		previous = open_private_watch_report(path) or_return
		had_previous = true
	}

	defer if had_previous {
		p.close(previous.fd)
	}

	invocation := argv

	if invocation == nil {
		command := make([dynamic]string, 0, 8)
		append(&command, args.executable, "watch", "--manifest", args.manifest, "--state-dir", args.state_dir)

		if args.approved_contract != "" {
			append(&command, "--approved-contract", args.approved_contract)
		}

		invocation = command[:]
	}

	summary := watch_capture(invocation) or_return
	current := open_private_watch_report(path) or_return
	defer p.close(current.fd)

	if had_previous && current.device == previous.device && current.inode == previous.inode {
		return null(), "WATCH_REPORT_STALE"
	}

	data := make([]u8, MAX_REPORT + 1)
	used := 0

	for used < len(data) {
		n := p.read(current.fd, raw_data(data[used:]), c.size_t(int(len(data)) - used))

		if n < 0 {
			return null(), "WATCH_REPORT_INVALID"
		}

		if n == 0 {
			break
		}

		used += int(n)
	}

	if used > MAX_REPORT {
		return null(), "WATCH_REPORT_LIMIT"
	}

	report, error := decode(data[:used])

	if error != "" {
		return null(), "WATCH_REPORT_INVALID"
	}

	if _, ok := get(report, "observation").(j.Object); !ok {
		return null(), "WATCH_REPORT_INVALID"
	}

	without := object()

	for key in keys(report) {
		if key != "observation" {
			put(&without, key, get(report, key))
		}
	}

	if !equal(summary, without) {
		return null(), "WATCH_REPORT_MISMATCH"
	}

	return report, nil
}
WatchRun :: proc(args: Schedule) -> (Value, Failure)
AgentRun :: proc(argv: []string, prompt: []u8, seconds: int) -> (Value, Failure)
schedule_run :: proc(
	args: Schedule,
	watcher: WatchRun = default_watch_run,
	agent: AgentRun = agent_run,
) -> (
	result: Value,
	failure: Failure,
) {
	if args.budget_seconds < 1 || args.budget_seconds > 600 {
		return null(), "BUDGET_INVALID"
	}
	if canonical_path(args.library) == "" || canonical_path(args.library) != canonical_path(library_root()) {
		return null(), "LIBRARY_SCOPE_INVALID"
	}
	fd := locked_state(args.state_dir) or_return
	p.close(fd)
	state := join(args.state_dir, "review-agent")
	lock := locked_state(state) or_return
	defer p.close(lock)
	result = object(
		{"status", text("FAILED")},
		{"compatibility_approved", boolean(false)},
		{"runtime_version_changed", boolean(false)},
	)
	review, review_error := schedule_review(args, state, watcher, agent)
	if review_error != nil {
		put(&result, "reason", text(review_error.(string)))
	} else {
		result = review
	}
	atomic_json(join(state, "agent-review.json"), result) or_return
	status := str(get(result, "status"))
	if status == "FAILED" || status == "REVIEW_REQUIRED" {
		reason := get(result, "reason")

		if equal(reason, null()) {
			reason = text("PUBLIC_PROTOCOL_REVIEW_REQUIRED")
		}

		atomic_json(
			join(state, "alert.json"),
			object(
				{"status", text(status)},
				{"checked_at_unix", number(time.to_unix_seconds(time.now()))},
				{"reason", reason},
				{"compatibility_approved", boolean(false)},
			),
		) or_return
	} else {
		_ = os.remove(join(state, "alert.json"))
	}; return
}
default_watch_run :: proc(args: Schedule) -> (Value, Failure) {
	return watch_run(args)
}
schedule_review :: proc(
	args: Schedule,
	state: string,
	watcher: WatchRun,
	agent: AgentRun,
) -> (
	result: Value,
	failure: Failure,
) {
	report := watcher(args) or_return
	status := str(get(report, "status"))
	if status != "REVIEW_REQUIRED" && status != "NO_MONITORED_DRIFT" {
		return null(), "WATCH_FAILED"
	}
	data := encode(report)
	if len(data) > MAX_REPORT {
		return null(), "PUBLIC_REPORT_LIMIT"
	}; schema, error := decode(transmute([]u8)SCHEDULE_SCHEMA); if error != "" {
		return null(), "SCHEDULE_FAILED"
	}; path := join(state, "result-schema.json"); atomic_json(path, schema) or_return
	prompt := concatenate_strings(#load("../review-agent-prompt.md"), "\nPUBLIC REPORT JSON:\n", data)
	review := agent(build_review_agent_argv(args.codex, args.library, path), transmute([]u8)prompt, args.budget_seconds) or_return
	validate_result(review) or_return
	allowed := object()
	for source in items(get(get(report, "observation"), "sources")) {
		paths := object()

		for file in items(get(source, "files")) {
			put(&paths, str(get(file, "path")), boolean(true))
		}

		put(&allowed, str(get(source, "name")), paths)
	}
	for finding in items(get(review, "findings")) {
		if !json_boolean_equals(get(get(allowed, str(get(finding, "source"))), str(get(finding, "path")))) {
			return null(), "AGENT_SOURCE_INVALID"
		}
	}
	if str(get(review, "status")) == "FAILED" || str(get(review, "status")) == "REVIEW_REQUIRED" {
		status = str(get(review, "status"))
	}
	return object(
			{"status", text(status)},
			{"compatibility_approved", boolean(false)},
			{"runtime_version_changed", boolean(false)},
			{"agent_review", review},
			{"checked_at_unix", number(time.to_unix_seconds(time.now()))},
		),
		nil
}
library_root :: proc() -> string {
	if root, ok := os.lookup_env("OWA_LIBRARY_ROOT", context.allocator); ok && root != "" {
		return root
	}
	return canonical_path(".")
}
xml_quote :: proc(value: string) -> string {
	return replace(
		replace(replace(replace(replace(value, "&", "&amp;"), "<", "&lt;"), ">", "&gt;"), "\"", "&quot;"),
		"'",
		"&apos;",
	)
}
plist :: proc(args: Schedule) -> (data: string, failure: Failure) {
	if args.budget_seconds < 1 || args.budget_seconds > 600 {
		return "", "BUDGET_INVALID"
	}

	for path in ([]string{args.state_dir, args.manifest, args.library, args.codex, args.executable}) {
		if !strings.has_prefix(path, "/") {
			return "", "PATH_INVALID"
		}; for r in path {
			if r < 32 || r == 127 {
				return "", "PATH_INVALID"
			}
		}
	}

	argv := []string {
		args.executable,
		"schedule",
		"run",
		"--manifest",
		args.manifest,
		"--state-dir",
		args.state_dir,
		"--library",
		args.library,
		"--codex",
		args.codex,
		"--budget-seconds",
		fmt.aprint(args.budget_seconds),
	}

	builder: strings.Builder
	strings.write_string(
		&builder,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>" +
		LABEL +
		"</string><key>ProgramArguments</key><array>",
	)

	for arg in argv {
		strings.write_string(&builder, concatenate_strings("<string>", xml_quote(arg), "</string>"))
	}

	strings.write_string(
		&builder,
		concatenate_strings(
			"</array><key>StartCalendarInterval</key><dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict><key>RunAtLoad</key><false/><key>ProcessType</key><string>Background</string><key>ExitTimeOut</key><integer>15</integer><key>WorkingDirectory</key><string>",
			xml_quote(args.library),
			"</string><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string><key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin</string></dict><key>Umask</key><integer>63</integer></dict></plist>\n",
		),
	); return strings.to_string(builder), nil
}
write_plist :: proc(args: Schedule) -> (value: Value, failure: Failure) {
	fd := locked_state(args.state_dir) or_return
	p.close(fd)
	state := join(args.state_dir, "review-agent")
	lock := locked_state(state) or_return
	defer p.close(lock)
	data := plist(args) or_return
	path := join(state, "daily-review.plist")
	atomic_bytes(path, transmute([]u8)data) or_return
	saved, error := read_file(path, MAX_REPORT)

	if error != "" || string(saved) != data {
		return null(), "PLIST_INVALID"
	}

	return object(
			{"status", text("PLIST_PREPARED")},
			{"installed", boolean(false)},
			{"daily_local_time", text("09:00")},
		),
		nil
}

canonical_path :: proc(path: string) -> string {
	buffer: [p.PATH_MAX + 1]u8
	resolved := p.realpath(strings.clone_to_cstring(path), &buffer[0])

	if resolved == nil {
		return ""
	}; return strings.clone(string(resolved))
}

package main

import "core:crypto/sha2"
import "core:encoding/endian"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"

Package :: struct {
	name, source, tag, commit, hash: string,
}

Lock :: struct {
	format:   int,
	packages: []Package,
}

collect_files :: proc(root, prefix: string, paths: ^[dynamic]string) -> os.Error {
	entries := os.read_directory_by_path(root, -1, context.allocator) or_return

	for entry in entries {
		name := strings.concatenate({prefix, entry.name})

		#partial switch entry.type {
		case .Directory:
			collect_files(
				fmt.aprintf("%s/%s", root, entry.name),
				strings.concatenate({name, "/"}),
				paths,
			) or_return
		case .Regular:
			append(paths, name)
		case:
			fmt.eprintln("Unexpected file type in locked package:", name)
			return .Invalid_File
		}
	}

	return nil
}

// Hash the installed tree in KRS order. Copy mirror files from the same bytes
// that enter the digest so later changes to the mirror cannot affect the build.
verify_package :: proc(pkg: Package, shared, mirror: string) -> os.Error {
	dest := fmt.aprintf("%s/%s", shared, pkg.name)
	root := dest if mirror == "" else fmt.aprintf("%s/%s", mirror, pkg.name)

	paths: [dynamic]string
	collect_files(root, "", &paths) or_return
	slice.sort(paths[:])

	hash: sha2.Context_256
	sha2.init_256(&hash)

	for path in paths {
		data := os.read_entire_file(fmt.aprintf("%s/%s", root, path), context.allocator) or_return
		defer delete(data)

		length: [8]u8
		endian.put_u64(length[:], .Little, u64(len(data)))

		sha2.update(&hash, transmute([]u8)path)
		sha2.update(&hash, []u8{0})

		sha2.update(&hash, length[:])
		sha2.update(&hash, data)

		if mirror != "" {
			parent := path[:max(0, strings.last_index(path, "/"))]
			if err := os.make_directory_all(fmt.aprintf("%s/%s", dest, parent));
			   err != nil && err != .Exist {
				return err
			}

			os.write_entire_file(fmt.aprintf("%s/%s", dest, path), data) or_return
		}
	}

	digest: [sha2.DIGEST_SIZE_256]u8
	sha2.final(&hash, digest[:])
	if string(hex.encode(digest[:])) != pkg.hash {
		fmt.eprintln("Locked package mismatch:", pkg.name)
		return .Invalid_File
	}

	return nil
}

// Materialize the source files, embedded data and license used by the locked
// releases. Reading Git objects keeps concurrent checkout edits out of the build.
install_locked_release :: proc(pkg: Package, work, shared, repositories: string) -> os.Error {
	repo := join(repositories, pkg.name)
	if repositories == "" {
		repo = join(work, pkg.name)
		run({"git", "clone", "--quiet", "--depth=1", "--no-checkout", "--branch", pkg.tag, "--", pkg.source, repo}) or_return
	}

	files := capture({"git", "-C", repo, "ls-tree", "-rz", "--name-only", pkg.commit, "--", "src", "LICENSE"}) or_return
	dest := join(shared, pkg.name)
	for file in strings.split_iterator(&files, "\x00") {
		if file != "LICENSE" && !strings.has_suffix(file, ".odin") && !strings.has_suffix(file, ".bin") {
			continue
		}

		target := join(dest, strings.trim_prefix(file, "src/"))
		if err := os.make_directory_all(os.dir(target)); err != nil && err != .Exist {
			return err
		}

		blob := capture({"git", "-C", repo, "show", fmt.aprintf("%s:%s", pkg.commit, file)}) or_return
		os.write_entire_file(target, transmute([]u8)blob) or_return
	}

	return nil
}

run :: proc(command: []string, dir := "") -> os.Error {
	child := os.process_start(
		{command = command, working_dir = dir, stdout = os.stdout, stderr = os.stderr},
	) or_return
	state := os.process_wait(child) or_return

	if state.exit_code != 0 {
		fmt.eprintln(command[0], "exited with status", state.exit_code)
		return .Invalid_File
	}

	return nil
}

run_tests :: proc() -> (output: string, err: os.Error) {
	reader, writer := os.pipe() or_return
	defer os.close(reader)

	self := os.get_executable_path(context.allocator) or_return
	child, start_err := os.process_start(
		{command = {self, "check"}, stdout = writer, stderr = writer},
	)
	os.close(writer)
	if start_err != nil {
		return "", start_err
	}

	log: [dynamic]u8
	buffer: [8192]u8
	for {
		n, read_err := os.read(reader, buffer[:])
		if n > 0 {
			append(&log, ..buffer[:n])
			fmt.print(string(buffer[:n]))
		}

		if n == 0 || read_err != nil {
			if read_err != .EOF && read_err != .Broken_Pipe {
				err = read_err
			}

			break
		}
	}

	state := os.process_wait(child) or_return
	if state.exit_code != 0 {
		return "", .Invalid_File
	}

	return string(log[:]), err
}

report :: proc(output: string) -> os.Error {
	counts: [3]int
	group := -1
	lines := output
	for line in strings.split_lines_iterator(&lines) {
		switch {
		case line == "Testing tests/unit":
			group = 0
		case line == "Testing tests/unit/protocol_watcher":
			group = 1
		case strings.has_prefix(line, "Testing tests/e2e/"):
			group = 2
		case group >= 0 && strings.has_prefix(line, "Finished "):
			rest := line[len("Finished "):]
			field, _ := strings.split_iterator(&rest, " ")
			count, ok := strconv.parse_int(field)
			if !ok {
				return .Invalid_File
			}

			counts[group] += count
		}
	}

	summary := fmt.aprintf(
		"Library %d\nWatcher %d\nE2E %d\nPrivate audio example compiled\n",
		counts[0],
		counts[1],
		counts[2],
	)
	fmt.print(summary)
	if path := os.get_env("GITHUB_STEP_SUMMARY", context.allocator); path != "" {
		file := os.open(path, {.Write, .Create, .Append}) or_return
		defer os.close(file)

		_ = os.write_string(file, summary) or_return
	}

	return nil
}

check :: proc() -> os.Error {
	compiler := os.get_env("ODIN", context.allocator)
	if compiler == "" {
		compiler = "odin"
	}

	pin_bytes := os.read_entire_file("ODIN_VERSION", context.allocator) or_return
	pin := strings.trim_space(string(pin_bytes))
	state, version, _, err := os.process_exec({command = {compiler, "version"}}, context.allocator)
	if err != nil {
		return err
	}

	label := strings.trim_space(string(version))
	colon := strings.last_index(label, ":")
	revision := label[colon + 1:]
	if state.exit_code != 0 ||
	   colon < 0 ||
	   len(pin) != 40 ||
	   len(revision) < 7 ||
	   !strings.has_prefix(pin, revision) {
		fmt.eprintln("Expected Odin revision", pin, "found", strings.trim_space(string(version)))
		return .Invalid_File
	}

	bytes := os.read_entire_file(".krs/packages.json", context.allocator) or_return
	lock: Lock
	if json.unmarshal(bytes, &lock) != nil || lock.format != 1 || len(lock.packages) == 0 {
		return .Invalid_File
	}

	work := os.make_directory_temp("", "owa-locked-*", context.allocator) or_return
	defer os.remove_all(work)

	os.chmod(work, {.Read_User, .Write_User, .Execute_User}) or_return

	sdk := fmt.aprintf("%s/sdk", work)
	shared := fmt.aprintf("%s/shared", sdk)
	os.make_directory_all(shared) or_return

	mirror := os.get_env("OWA_LOCKED_SHARED", context.allocator)
	repositories := os.get_env("OWA_LOCKED_REPOS", context.allocator)
	for pkg in lock.packages {
		if pkg.name == "" || strings.index_any(pkg.name, "/\\.") >= 0 {
			return .Invalid_File
		}

		if mirror == "" {
			install_locked_release(pkg, work, shared, repositories) or_return
		}

		verify_package(pkg, shared, mirror) or_return
	}

	root := os.get_working_directory(context.allocator) or_return
	os.symlink(fmt.aprintf("%s/src", root), fmt.aprintf("%s/whatsapp", shared)) or_return
	os.set_env("WEBTOOLS_SHARED", shared) or_return
	output := run_tests() or_return
	run(
		{
			compiler,
			"check",
			"examples/private_audio",
			fmt.aprintf("-collection:shared=%s", shared),
			"-no-entry-point",
			"-vet",
			OWA_VET_PACKAGES,
			"-warnings-as-errors",
		},
	) or_return

	return report(output)
}

dispatch :: proc(args: []string) -> os.Error {
	if len(args) == 0 {
		return check()
	}

	switch args[0] {
	case "locked":
		return check()
	case "check", "test", "protocol":
		return test_command(args[0], args[1:])
	case "exec-suite":
		return exec_suite(args[1:])
	case "hooks":
		return run({"git", "config", "--local", "core.hooksPath", ".githooks"})


	case "publish":
		return publish()
	}

	fmt.eprintln("Unknown CI command:", args[0])
	return .Invalid_Command
}

main :: proc() {
	if err := dispatch(os.args[1:]); err != nil {
		fmt.eprintln("CI command failed:", err)
		os.exit(1)
	}
}

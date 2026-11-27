package main

import "core:crypto/sha2"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strings"

capture :: proc(command: []string) -> (output: string, err: os.Error) {
	state, stdout, stderr := os.process_exec({command = command}, context.allocator) or_return
	if state.exit_code != 0 {
		fmt.eprint(string(stderr))
		return "", .Invalid_Command
	}

	return string(stdout), nil
}

publish :: proc() -> os.Error {
	watcher :: "tools/protocol_watcher"
	asset :: "protocol-watch-linux-amd64"
	repo :: "dvrd/owa"
	checksum :: watcher + "/linux-amd64.sha256"
	rev := capture({"git", "rev-parse", "--verify", "HEAD^{commit}"}) or_return
	source := strings.trim_space(rev)
	status := capture(
		{
			"git",
			"status",
			"--porcelain",
			"--untracked-files=all",
			"--",
			watcher,
			":(exclude)" + checksum,
		},
	) or_return
	if status != "" {
		fmt.eprintln("Commit the protocol watcher inputs before publishing.")
		return .Invalid_File
	}

	work := os.make_directory_temp("", "owa-publish-*", context.allocator) or_return
	defer os.remove_all(work)

	archive := join(work, "source.tar")
	run({"git", "archive", fmt.aprintf("--output=%s", archive), source, "--", watcher}) or_return
	run({"tar", "-xf", archive, "-C", work}) or_return
	compiler := env_or("ODIN", "odin")
	shared := env_or("WEBTOOLS_SHARED", "")
	if shared == "" {
		sdk := capture({compiler, "root"}) or_return
		shared = join(strings.trim_space(sdk), "shared")
	}

	obj := join(work, "watch.o")
	binary := join(work, asset)
	run(
		{
			compiler,
			"build",
			join(work, watcher + "/src"),
			fmt.aprintf("-collection:shared=%s", shared),
			"-target:linux_amd64",
			"-microarch:generic",
			"-build-mode:obj",
			"-use-single-module",
			"-o:speed",
			"-source-code-locations:filename",
			"-vet",
			OWA_VET_PACKAGES,
			"-warnings-as-errors",
			fmt.aprintf("-out:%s", obj),
		},
	) or_return
	run({"zig", "cc", "-target", "x86_64-linux-gnu.2.35", obj, "-s", "-o", binary}) or_return
	bytes := os.read_entire_file(binary, context.allocator) or_return
	hash: sha2.Context_256
	sha2.init_256(&hash)
	sha2.update(&hash, bytes)
	digest: [32]u8
	sha2.final(&hash, digest[:])
	full := string(hex.encode(digest[:]))
	tag := fmt.aprintf("protocol-watch-%s-%s", source, full[:16])
	run(
		{
			"git",
			"push",
			"https://github.com/" + repo + ".git",
			fmt.aprintf("%s:refs/tags/%s", source, tag),
		},
	) or_return
	view, _, _, err := os.process_exec(
		{command = {"gh", "release", "view", tag, "--repo", repo}},
		context.allocator,
	)
	if err != nil {
		return err
	}

	if view.exit_code != 0 {
		run(
			{
				"gh",
				"release",
				"create",
				tag,
				binary,
				"--repo",
				repo,
				"--verify-tag",
				"--target",
				source,
				"--latest=false",
				"--title",
				fmt.aprintf("Protocol watcher %s", full[:16]),
				"--notes",
				fmt.aprintf("Built from %s. SHA-256: %s.", source, full),
			},
		) or_return
	}

	download := join(work, "download")
	run(
		{"gh", "release", "download", tag, "--repo", repo, "--pattern", asset, "--dir", download},
	) or_return
	copy := os.read_entire_file(join(download, asset), context.allocator) or_return
	if string(bytes) != string(copy) {
		fmt.eprintln("Downloaded release asset differs from the build")
		return .Invalid_File
	}

	return os.write_entire_file(
		checksum,
		fmt.aprintf("%s  %s\n# source %s\n", full, asset, source),
	)
}

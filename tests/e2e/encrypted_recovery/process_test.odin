package main

import child "../child_process"
import "core:bytes"
import "core:crypto/hash"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:testing"

make_owned_directory :: proc() -> string {
	directory, err := os.make_directory_temp("/tmp", "wa-encrypted-*", context.allocator)
	assert(err == nil)
	assert(
		os.write_entire_file(
			fmt.tprintf("%s/owner", directory),
			OWNER,
			{.Read_User, .Write_User},
		) ==
		nil,
	)
	return directory
}

fixture_file :: proc(directory, name: string) -> []u8 {
	data, err := os.read_entire_file(fmt.tprintf("%s/%s", directory, name), context.temp_allocator)
	assert(err == nil)
	return data
}

run_to_exit :: proc(args: ..string) {
	process := child.start(..args)
	defer child.close(&process)

	child.wait(&process)
}

socket_peer_handoff :: proc(
	t: ^testing.T,
	peer: ^child.Child,
	directory: string,
	replay, received, ack: bool,
) {
	if received {
		handoff := child.read_line(peer)
		packet := fixture_file(directory, "replay.bin" if replay else "transport.bin")
		assert(0 < len(packet) && len(packet) <= 8192)
		digest: [32]u8
		hash.hash_bytes_to_buffer(.SHA256, packet, digest[:])
		encoded, err := hex.encode(digest[:])
		assert(err == nil)
		defer delete(encoded)

		testing.expect_value(
			t,
			handoff,
			fmt.tprintf(
				"ENCRYPTED_TCP_HANDOFF hash=%s bytes=%d authenticated=true replay=%t",
				string(encoded),
				len(packet),
				replay,
			),
		)
	}

	if ack {
		line := child.read_line(peer)
		header, _, value := strings.partition(line, "=")
		size, valid := strconv.parse_int(value)
		testing.expect(
			t,
			header == "ENCRYPTED_TCP_ACK_SENT bytes" && valid && size > 0 && size <= 2048,
		)
	}
}

exercise_socket_stage :: proc(t: ^testing.T, directory, stage: string, replay: bool) {
	mode := "replay" if replay else "stage"
	peer := child.start("tcp-peer", directory, fmt.tprintf("%s:%s", mode, stage))
	defer child.close(&peer)

	line := child.read_line(&peer)
	header, _, port := strings.partition(line, "=")
	n, valid := strconv.parse_int(port)
	assert(header == "ENCRYPTED_TCP_PEER_READY port" && valid && n > 0 && n < 65536)
	writer := child.start("verify" if replay else "stage", directory, stage, port)
	defer child.close(&writer)

	received := stage != "socket-before-send" && stage != "socket-after-commit-before-write"
	ack := !replay && (stage == "socket-after-positive-ack" || stage == "socket-after-ack-journal")
	if replay {
		received =
			stage == "socket-after-commit-before-write" ||
			stage == "socket-after-wire-before-return" ||
			stage == "socket-after-send-before-ack"
		child.wait(&writer)
	} else {
		testing.expect_value(
			t,
			child.read_line(&writer),
			fmt.tprintf("ENCRYPTED_BOUNDARY_READY %s", stage),
		)
	}

	socket_peer_handoff(t, &peer, directory, replay, received, ack)
	if !replay {
		child.kill_at_boundary(&writer)
	}

	testing.expect_value(
		t,
		child.read_line(&peer),
		fmt.tprintf(
			"ENCRYPTED_TCP_PEER_DONE received=%t ack=%t replay=%t closed=true",
			received,
			ack,
			replay,
		),
	)
	child.wait(&peer)
}

@(test)
encrypted_state_survives_crash_boundaries :: proc(t: ^testing.T) {
	stages := []string {
		"receiver-before-commit",
		"receiver-after-commit",
		"sender-before-commit",
		"sender-after-commit",
		"receiver-after-message-commit",
		"socket-before-send",
		"socket-after-commit-before-write",
		"socket-after-wire-before-return",
		"socket-after-send-before-ack",
		"socket-after-positive-ack",
		"socket-after-ack-journal",
	}

	for stage in stages {
		directory := make_owned_directory()
		defer delete(directory)

		defer os.remove_all(directory)

		socket := strings.has_prefix(stage, "socket-")
		if socket {
			exercise_socket_stage(t, directory, stage, false)
		} else {
			writer := child.start("stage", directory, stage)
			defer child.close(&writer)

			testing.expect_value(
				t,
				child.read_line(&writer),
				fmt.tprintf("ENCRYPTED_BOUNDARY_READY %s", stage),
			)
			child.kill_at_boundary(&writer)
		}

		state := fixture_file(directory, "state.bin")
		has_prekeys := os.exists(fmt.tprintf("%s/prekeys.bin", directory))
		prekeys := fixture_file(directory, "prekeys.bin") if has_prekeys else nil
		if socket {
			exercise_socket_stage(t, directory, stage, true)
		} else {
			run_to_exit("verify", directory, stage)
		}

		testing.expect(t, bytes.equal(state, fixture_file(directory, "state.bin")))
		if has_prekeys {
			testing.expect(t, bytes.equal(prekeys, fixture_file(directory, "prekeys.bin")))
		}
	}
}

@(test)
failed_write_and_corrupt_snapshots_preserve_sessions :: proc(t: ^testing.T) {
	directory := make_owned_directory()
	defer delete(directory)

	defer os.remove_all(directory)

	run_to_exit("prepare", directory, "control")
	state := fixture_file(directory, "state.bin")
	run_to_exit("limited-write", directory, "file-limit")
	testing.expect(t, bytes.equal(state, fixture_file(directory, "state.bin")))
	files, err := os.read_directory_by_path(directory, -1, context.allocator)
	assert(err == nil)
	defer os.file_info_slice_delete(files, context.allocator)

	for f in files {testing.expect(t, !strings.has_prefix(f.name, "state.bin.tmp-"))}

	run_to_exit("verify", directory, "file-limit")
	corrupt := fixture_file(directory, "state.bin")
	corrupt[len(corrupt) - 1] ~= 1
	for kind in ([]string{"corrupt", "truncated"}) {
		data := corrupt if kind == "corrupt" else state[:len(state) / 2]
		assert(
			os.write_entire_file(
				fmt.tprintf("%s/%s.bin", directory, kind),
				data,
				{.Read_User, .Write_User},
			) ==
			nil,
		)
		run_to_exit("corrupt-load", directory, kind)
		testing.expect(t, bytes.equal(state, fixture_file(directory, "state.bin")))
	}
}

@(test)
read_sessions_written_by_prior_revision :: proc(t: ^testing.T) {
	// Generated once by compat-produce built against this historical library revision.
	state := #load("testdata/fa2734f60b60cc9770809bb1be873cea60fe3c12/state.fixture")
	prekeys := #load("testdata/fa2734f60b60cc9770809bb1be873cea60fe3c12/prekeys.fixture")
	directory := make_owned_directory()
	defer delete(directory)

	defer os.remove_all(directory)

	assert(
		os.write_entire_file(
			fmt.tprintf("%s/state.bin", directory),
			state,
			{.Read_User, .Write_User},
		) ==
		nil,
	)
	assert(
		os.write_entire_file(
			fmt.tprintf("%s/prekeys.bin", directory),
			prekeys,
			{.Read_User, .Write_User},
		) ==
		nil,
	)
	for _ in 0 ..< 2 {
		run_to_exit("compat-verify", directory, "same-format")
		testing.expect(t, bytes.equal(state, fixture_file(directory, "state.bin")))
		testing.expect(t, bytes.equal(prekeys, fixture_file(directory, "prekeys.bin")))
	}
}

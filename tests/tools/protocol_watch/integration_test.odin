package protocol_watch_test
import w "../../../tools/protocol_watch"
import "core:mem"
import "core:os"
import "core:strings"
import p "core:sys/posix"
import "core:testing"
import "core:time"
Observe_Bytes :: struct {
	before, after: []u8,
	reference:     string,
}
observe_get :: proc(data: rawptr, url: string, timeout: time.Duration) -> ([]u8, bool, w.Failure) {
	assert(timeout > 0 && timeout <= 10 * time.Second); fixture := cast(^Observe_Bytes)data
	if strings.contains(url, "/commits/") {
		return transmute([]u8)w.encode(w.object({"sha", w.text(HEAD)})), true, nil
	}
	return fixture.before if strings.contains(url, fixture.reference) else fixture.after, true, nil
}
integrated_observation :: proc(root, path, before, after: string) -> w.Value {
	source := w.clone(w.items(w.get(w.default_manifest(), "sources"))[0])
	w.put(&source, "paths", w.array(w.text(path)))
	manifest := w.object({"schema", w.number(1)}, {"sources", w.array(source)})
	fixture := Observe_Bytes {
		transmute([]u8)before,
		transmute([]u8)after,
		w.str(w.get(source, "reference_commit")),
	}
	value, failure := w.observe(
		manifest,
		w.Observation{fetch = observe_get, data = &fixture, root = root},
	); assert(failure == nil)
	return w.items(w.get(w.items(w.get(value, "sources"))[0], "files"))[0]
}
integration_case :: proc(t: ^testing.T, mode: int) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-integration-*", context.allocator)
	assert(error == nil); defer os.remove_all(root)
	for name in ([]string {
			"socket.odin",
			"connection.odin",
			"binary_node.odin",
			"auth.odin",
			"pairing.odin",
		}) {assert(os.write_entire_file(w.join(root, name), "package whatsapp\n") == nil)}
	before, after := "const x=1; // old\n", "const x = 1; // new\n"; path := "src/Socket/socket.ts"
	if mode == 1 {
		before = "const x=1;\n"; after = "const x=2;\n"
	}; if mode == 3 {
		after = before
	}
	if mode == 2 {
		old, current := make([]string, 236), make([]string, 236)
		for &value, i in old {value = w.cat("token-", w.string_number(i)); current[i] = value}
		current[7] = "replacement"
		before = w.cat("export const SINGLE_BYTE_TOKENS = ", w.encode(w.value_strings(old)), ";\n")
		after = w.cat(
			"export const SINGLE_BYTE_TOKENS = ",
			w.encode(w.value_strings(current)),
			";\n",
		)
		// Odin table syntax differs from the upstream JavaScript array.
		assert(
			os.write_entire_file(
				w.join(root, "binary_tokens.odin"),
				w.cat(
					"package whatsapp\nSINGLE_BYTE_TOKENS := [236]string {",
					strings.trim_suffix(
						strings.trim_prefix(w.encode(w.value_strings(old)), "["),
						"]",
					),
					"}\n",
				),
			) ==
			nil,
		); path = "src/WABinary/constants.ts"
	}
	file := integrated_observation(root, path, before, after)
	assessment := w.get(file, "assessment")
	if mode == 0 {
		testing.expect(
			t,
			w.truth(w.get(file, "changed_from_reference")) &&
			!w.equal(
					w.get(w.get(file, "reference"), "sha256"),
					w.get(w.get(file, "current"), "sha256"),
				) &&
			w.str(w.get(assessment, "kind")) == "NO_ACTION",
		)
		testing.expect(
			t,
			w.equal(w.get(w.get(assessment, "evidence"), "reference"), w.get(file, "reference")) &&
			w.equal(w.get(w.get(assessment, "evidence"), "current"), w.get(file, "current")),
		)
	}
	if mode == 1 {
		testing.expect(
			t,
			w.str(w.get(assessment, "kind")) == "SPIKE" &&
			w.str(w.get(assessment, "reason")) == "BEHAVIOR_CHANGE_UNRESOLVED" &&
			len(w.items(w.get(assessment, "local_targets"))) == 4 &&
			len(w.items(w.get(assessment, "checks"))) > 0 &&
			len(w.items(w.get(assessment, "acceptance"))) > 0 &&
			w.truth(w.get(w.get(assessment, "evidence"), "server_compatibility_proven"), false),
		)
	}
	if mode == 2 {
		testing.expect(
			t,
			w.str(w.get(assessment, "kind")) == "SPIKE" &&
			w.equal(w.get(w.get(assessment, "evidence"), "changed_indices"), w.array(w.number(7))),
		)
	}
	if mode == 3 {
		testing.expect(
			t,
			w.truth(w.get(file, "changed_from_reference"), false) &&
			!w.contains_string(w.keys(file), "assessment"),
		)
	}
}
@(test)
integration_comment_drift_has_no_action_proof :: proc(t: ^testing.T) {integration_case(t, 0)}
@(test)
integration_behavior_drift_specific_spike :: proc(t: ^testing.T) {integration_case(t, 1)}
@(test)
integration_unapproved_table_spike_indices :: proc(t: ^testing.T) {integration_case(t, 2)}
@(test)
integration_unchanged_no_assessment :: proc(t: ^testing.T) {integration_case(t, 3)}
@(test)
integration_completed_watcher_returns_without_signal :: proc(t: ^testing.T) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	result, failure := w.watch_capture(
		shell_argv("printf '%s\\n' '{\"status\":\"NO_MONITORED_DRIFT\"}'"),
	); testing.expect(t, failure == nil && w.str(w.get(result, "status")) == "NO_MONITORED_DRIFT")
}
contract_scan :: proc(data: rawptr, state, approved_contract: string) -> (w.Value, w.Failure) {
	seen := cast(^[dynamic]string)data; append(seen, approved_contract)
	return w.object({"status", w.text("NO_MONITORED_DRIFT")}), nil
}
@(test)
integration_ci_only_explicit_contract :: proc(t: ^testing.T) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-integration-*", context.allocator)
	assert(error == nil); defer os.remove_all(root); seen := make([dynamic]string)
	_, failure := w.ci_prepare(
		w.join(root, "state"),
		w.join(root, "out1"),
		"",
		contract_scan,
		&seen,
	); testing.expect(t, failure == nil)
	_, failure = w.ci_prepare(
		w.join(root, "state"),
		w.join(root, "out2"),
		"tools/protocol_watch/contracts/reviewed.json",
		contract_scan,
		&seen,
	)
	testing.expect(
		t,
		failure == nil &&
		len(seen) == 2 &&
		seen[0] == "" &&
		seen[1] == "tools/protocol_watch/contracts/reviewed.json",
	)
}
@(test)
integration_source_reference_presence_is_strict :: proc(t: ^testing.T) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	source := w.object(
		{"name", w.text("baileys")},
		{"repository", w.text("WhiskeySockets/Baileys")},
		{"reference_commit", w.null()},
	)
	value := w.assess(
		source,
		"src/Socket/socket.ts",
		transmute([]u8)string("x"),
		transmute([]u8)string("y"),
		true,
		true,
		ROOT,
	); testing.expect_value(t, w.str(w.get(value, "reason")), "SOURCE_BINDING_UNKNOWN")
}
@(test)
integration_watch_runner_forwards_contract_without_execution :: proc(t: ^testing.T) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-integration-*", context.allocator)
	assert(error == nil); defer os.remove_all(root); args := args_for(root)
	fd, failure := w.locked_state(args.state_dir); assert(failure == nil); p.close(fd)
	marker := w.join(root, "must-not-exist")
	args.approved_contract = w.cat("tools/protocol_watch/contracts/$(touch ", marker, ").json")
	args.executable = w.join(root, "watcher")
	script := w.cat(
		"#!/bin/sh\nset -eu\ntest \"$6\" = --approved-contract\ntest \"$7\" = '",
		args.approved_contract,
		"'\nprintf '%s\\n' '{\"status\":\"NO_MONITORED_DRIFT\",\"observation\":{}}' > \"$5/new.json\"\nchmod 600 \"$5/new.json\"\nmv \"$5/new.json\" \"$5/report.json\"\nprintf '%s\\n' '{\"status\":\"NO_MONITORED_DRIFT\"}'\n",
	)
	assert(os.write_entire_file(args.executable, script) == nil)
	assert(p.chmod(strings.clone_to_cstring(args.executable), {.IRUSR, .IWUSR, .IXUSR}) == {})
	_, failure = w.watch_run(args); testing.expect(t, failure == nil && !os.exists(marker))
}

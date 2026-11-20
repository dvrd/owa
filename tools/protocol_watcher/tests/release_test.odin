package protocol_watch_test

import w "../src"
import test_fixtures "../../../tests/fixtures/protocol_watch"
import j "core:encoding/json"
import "core:mem"
import "core:os"
import "core:slice"
import "core:strings"
import "core:testing"

receipt_inputs :: proc(root: string) -> (w.Value, w.Value) {
	assert(os.write_entire_file(w.join(root, "runtime.odin"), "package synthetic\n") == nil)
	digest, _, error := w.hash_candidate_source_files(root)
	assert(error == nil)
	evidence := "synthetic executed-check fixture\n"
	assert(os.write_entire_file(w.join(root, "evidence.txt"), evidence) == nil)
	proof := w.object(
		{"evidence_file", w.text("evidence.txt")},
		{"evidence_sha256", w.text(w.sha256(transmute([]u8)evidence))},
	); checks := w.object()

	for name in w.REQUIRED {
		check := j.clone_value(proof)
		w.put(&check, "status", w.text("PASS"))
		w.put(&check, "candidate_source_digest", w.text(digest))
		w.put(&checks, name, check)
	}

	offline := w.object(
		{"candidate_source_digest", w.text(digest)},
		{"compiler_sha256", w.text("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")},
		{"checks", checks},
	)
	live := j.clone_value(proof)
	w.put(&live, "candidate_source_digest", w.text(digest))
	w.put(&live, "duplicates_reported", w.boolean(false))

	for name in ([]string {
			"isolated_group_verified",
			"text_server_acked",
			"pdf_server_acked",
			"recipient_confirmed",
			"pdf_opened",
			"same_ids_after_restart",
		}) {w.put(&live, name, w.boolean(true))}
	return offline, live
}

gate_case :: proc(t: ^testing.T, mode: int) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-gate-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	offline, live := receipt_inputs(root)

	if mode == 1 {
		assert(os.write_entire_file(w.join(root, "runtime.odin"), "package changed\n") == nil)
	}

	if mode == 2 {
		w.put(&live, "recipient_confirmed", w.boolean(false))
		checks := w.get(offline, "checks")
		unit := w.get(checks, "unit_asan")
		w.put(&unit, "status", w.text("SKIPPED"))
		w.put(&checks, "unit_asan", unit)
		w.put(&checks, "protocol_review", w.null())
		w.put(&offline, "checks", checks)
	}

	if mode == 3 {
		assert(os.write_entire_file(w.join(root, "evidence.txt"), "changed after validation\n") == nil)
	}

	result, failure := w.evaluate(root, offline, live, root)
	testing.expect(t, failure == nil)
	testing.expect_value(t, w.str(w.get(result, "status")), "ELIGIBLE_FOR_REVIEW" if mode == 0 else "BLOCKED")
	testing.expect(
		t,
		w.json_boolean_equals(w.get(result, "deployment_authorized"), false) &&
		w.json_boolean_equals(w.get(result, "state_rollback_authorized"), false),
	)
	failures := w.items(w.get(result, "failures"))

	if mode == 1 {
		testing.expect(
			t,
			slice.contains(array_strings(failures[:]), "OFFLINE_SOURCE_MISMATCH") &&
			slice.contains(array_strings(failures[:]), "LIVE_SOURCE_MISMATCH"),
		)
	}; if mode == 2 {
		for expected in ([]string {
				"LIVE_QUALIFICATION_INCOMPLETE",
				"MISSING_OR_INVALID_UNIT_ASAN",
				"MISSING_OR_INVALID_PROTOCOL_REVIEW",
			}) {testing.expect(t, slice.contains(array_strings(failures[:]), expected))}
	}; if mode == 3 {
		testing.expect(t, slice.contains(array_strings(failures[:]), "LIVE_EVIDENCE_MISSING_OR_CHANGED"))
	}
}

array_strings :: proc(value: []w.Value) -> []string {
	out := make([]string, len(value))

	for item, i in value {
		out[i] = w.str(item)
	}

	return out
}

@(test)
gate_never_authorizes_deployment :: proc(t: ^testing.T) {
	gate_case(t, 0)
}

@(test)
gate_source_change_invalidates_receipts :: proc(t: ^testing.T) {
	gate_case(t, 1)
}

@(test)
gate_ack_alone_and_skipped_checks_fail :: proc(t: ^testing.T) {
	gate_case(t, 2)
}

@(test)
gate_changed_evidence_rejected :: proc(t: ^testing.T) {
	gate_case(t, 3)
}

ci_scan :: proc(data: rawptr, state, approved_contract: string) -> (w.Value, w.Failure) {
	mode := (cast(^int)data)^

	if mode == 1 {
		return w.null(), "private-secret"
	}

	return w.object(
			{"status", w.text("REVIEW_REQUIRED" if mode == 0 else "NO_MONITORED_DRIFT")},
			{"observation", w.object({"sources", w.array()})},
		),
		nil
}

ci_case :: proc(t: ^testing.T, mode: int) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-ci-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root); output := w.join(root, "out"); kind := mode
	result, failure := w.ci_prepare(w.join(root, "state"), output, "", ci_scan, &kind)
	testing.expect(t, failure == nil)
	testing.expect_value(
		t,
		w.str(w.get(result, "status")),
		"REVIEW_REQUIRED" if mode == 0 else "FAILED" if mode == 1 else "NO_MONITORED_DRIFT",
	); testing.expect(t, w.json_boolean_equals(w.get(result, "compatibility_approved"), false))
	testing.expect(t, w.json_boolean_equals(w.get(result, "report_ready"), mode != 1))
	testing.expect(t, !os.exists(w.join(output, "prompt.txt")) && !os.exists(w.join(output, "schema.json")))

	if mode == 1 {
		bytes, _ := os.read_entire_file(w.join(output, "result.json"), context.allocator)
		testing.expect(t, !strings.contains(string(bytes), "private-secret"))
	} else {
		testing.expect(t, w.private_file(w.join(output, "report.json")) == nil)
	}
}

@(test)
ci_prepares_public_drift_without_downgrading :: proc(t: ^testing.T) {
	ci_case(t, 0)
}

@(test)
ci_failure_redacts_raw_error :: proc(t: ^testing.T) {
	ci_case(t, 1)
}

@(test)
ci_clean_scan_never_approves :: proc(t: ^testing.T) {
	ci_case(t, 2)
}

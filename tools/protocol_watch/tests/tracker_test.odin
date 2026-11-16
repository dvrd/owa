package protocol_watch_test

import w ".."
import j "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:testing"
import "core:time"

inflate :: proc(value, blobs: w.Value) -> w.Value {
	switch v in value {
	case j.Object:
		if len(v) == 1 {
			if ref, ok := v["$text"]; ok {
				return w.text(string(fixture_blob(blobs, ref)))
			}; if _, ok := v["$float"]; ok {
				return j.Float(transmute(f64)u64(0x7ff8000000000000))
			}
		}
		out := make(j.Object, max(64, len(v) + 16))
		for key, item in v {out[key] = inflate(item, blobs)}; return out
	case j.Array:
		out := make(j.Array); for item in v {append(&out, inflate(item, blobs))}; return out
	case j.Null, j.String, j.Integer, j.Float, j.Boolean:
		return value
	}
	return value
}
Replay :: struct {
	trace:                j.Array,
	index:                int,
	name, expected_error: string,
	api:                  ^w.API,
	t:                    ^testing.T,
}
operation_name :: proc(query: string) -> string {
	if query == w.SCAN {
		return "SCAN"
	}; if query == w.LOOKUP {
		return "LOOKUP"
	}; if query == w.COMMENTS {
		return "COMMENTS"
	}
	if query == w.COMMENT_LOOKUP {
		return "COMMENT_LOOKUP"
	}; if query == w.CREATE {
		return "CREATE"
	}; if query == w.COMMENT_CREATE {
		return "COMMENT_CREATE"
	}; return query
}
replay_call :: proc(data: rawptr, query: string, variables: w.Value) -> (w.Value, w.Failure) {
	replay := cast(^Replay)data
	if replay.index >= len(replay.trace) {
		fmt.eprintf("EXTRA CALL %s %s\n", replay.name, operation_name(query))
		return w.null(), "UNEXPECTED_API_CALL"
	}
	expected := replay.trace[replay.index]; replay.index += 1
	name := operation_name(query)
	if name != w.str(w.get(expected, "query")) ||
	   !w.equal(variables, w.get(expected, "variables")) {
		fmt.eprintf(
			"TRACE MISMATCH %s %d EXPECTED %s %s ACTUAL %s %s\n",
			replay.name,
			replay.index,
			w.str(w.get(expected, "query")),
			w.encode(w.get(expected, "variables")),
			name,
			w.encode(variables),
		)
		testing.expect(replay.t, false); return w.null(), "TRACE_MISMATCH"
	}
	if replay.index == len(replay.trace) && replay.expected_error == "LINEAR_SCAN_BUDGET" {
		replay.api.started = time.tick_add(time.tick_now(), -121 * time.Second)
	}
	if error, ok := w.get(expected, "error").(j.String); ok {
		return w.null(), string(error)
	}
	result := w.get(expected, "result")
	if w.truth(w.get(result, "$invalid")) {
		return w.null(), "LINEAR_RESPONSE_INVALID"
	}
	return w.clone(result), nil
}
tracker_dispatch :: proc(
	test_case: w.Value,
	root: string,
	replay: ^Replay,
) -> (
	value: w.Value,
	failure: w.Failure,
) {
	args := w.items(w.get(test_case, "args")); operation := w.str(w.get(test_case, "operation"))
	switch operation {
	case "track":
		api := w.API {
			call = replay_call,
			data = replay,
		}; if strings.contains(replay.name, "test_scan_call_budget_fails_before_mutation") {
			api.max_calls = 1
		}; replay.api = &api; defer replay.api = nil
		if len(replay.trace) == 0 && replay.expected_error == "LINEAR_SCAN_BUDGET" {
			api.started = time.tick_add(time.tick_now(), -121 * time.Second)
		}
		return w.track(args[0], w.str(args[1]), root, &api)
	case "snapshot":
		fingerprint, changed := w.snapshot(args[0]) or_return
		pairs := make(j.Array)
		for item in changed {append(&pairs, w.array(item.source, item.file))}
		return w.array(w.text(fingerprint), pairs), nil
	case "findings":
		return w.findings(args[0], root)
	case "ticket":
		id, marker, payload := w.ticket(args[0], w.str(args[1]), root) or_return
		return w.array(w.text(id), w.text(marker), payload), nil
	case "v2_coverage":
		return w.v2_coverage(w.str(args[0]), root)
	case "legacy_coverage":
		return w.legacy_coverage(args[0]), nil
	case "change_identity":
		return w.text(w.change_identity(w.str(args[0]), w.str(args[1]), args[2], args[3])), nil
	case "stable_id":
		return w.text(w.stable_id(w.str(args[0]), args[1])), nil
	case "comment_identity":
		return w.text(w.comment_identity(w.str(args[0]), w.items(args[1]))), nil
	case "validate_issue":
		w.validate_issue(args[0]) or_return; return args[0], nil
	case "assessment":
		verify := true
		if len(args) > 2 {
			verify = w.truth(args[2])
		}
		if kw, ok := w.get(test_case, "kwargs").(j.Object); ok {
			if flag, present := kw["verify_contract"]; present {
				verify = w.truth(flag)
			}
		}
		return w.validate_assessment(args[0], args[1], root, verify)
	case:
		return w.null(), "TEST_OPERATION_INVALID"
	}
}
tracker_cases :: proc(t: ^testing.T, suffix: string) {
	arena: mem.Dynamic_Arena; mem.dynamic_arena_init(&arena)
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	corpus, parse_error := j.parse(#load("fixtures/tracker.json"), .JSON, true)
	if !testing.expect_value(t, parse_error, j.Error.None) {
		return
	}
	blobs := w.get(corpus, "blobs"); executed := 0
	for raw in w.items(w.get(corpus, "cases")) {
		if !strings.has_suffix(w.str(w.get(raw, "test")), suffix) {
			continue
		}
		test_case := inflate(raw, blobs)
		root, create_error := os.make_directory_temp("", "owa-tracker-*", context.allocator)
		if !testing.expect_value(t, create_error, nil) {
			return
		}; defer {cleanup := os.remove_all(root); _ = cleanup}
		for path, entry in w.get(test_case, "files").(j.Object) {
			target := w.join(root, path); slash := strings.last_index(target, "/")
			mkdir := os.make_directory_all(target[:slash])
			assert(mkdir == nil || mkdir == os.Error(os.General_Error.Exist))
			if symlink, ok := w.get(entry, "symlink").(j.String); ok {
				linked := os.symlink(string(symlink), target); assert(linked == nil)
			} else {
				bytes := fixture_blob(blobs, w.get(entry, "blob"))
				if canonical, canonical_ok := w.get(entry, "canonical").(j.String); canonical_ok {
					loaded, error := os.read_entire_file(
						w.join(ROOT, string(canonical)),
						context.allocator,
					); assert(error == nil); bytes = loaded
				}
				written := os.write_entire_file(target, bytes); assert(written == nil)
			}
		}
		replay := Replay {
			trace          = w.items(w.get(test_case, "trace")),
			name           = cat_case(suffix, w.str(w.get(test_case, "operation"))),
			expected_error = w.str(w.get(test_case, "error")),
			t              = t,
		}
		actual, failure := tracker_dispatch(test_case, root, &replay)
		if replay.expected_error != "" {
			error := ""; if message, ok := failure.(string); ok {
				error = message
			}
			if error != replay.expected_error {
				fmt.eprintf(
					"ERROR PARITY %s EXPECTED %s ACTUAL %s\n",
					replay.name,
					replay.expected_error,
					error,
				); testing.expect(t, false)
			}
		} else if failure != nil || !w.equal(actual, w.get(test_case, "expected")) {
			fmt.eprintf(
				"RESULT PARITY %s ERROR %v EXPECTED %s ACTUAL %s\n",
				replay.name,
				failure,
				w.encode(w.get(test_case, "expected")),
				w.encode(actual),
			); testing.expect(t, false)
		}
		if replay.index != len(replay.trace) {
			fmt.eprintf(
				"INCOMPLETE TRACE %s %d/%d\n",
				replay.name,
				replay.index,
				len(replay.trace),
			); testing.expect(t, false)
		}
		removed := os.remove_all(root); assert(removed == nil); executed += 1
	}
	testing.expect(t, executed > 0)
}
cat_case :: proc(a, b: string) -> string {return fmt.aprintf("%s/%s", a, b)}

@(test)
tracker_all_covered_makes_no_comment :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_all_covered_makes_no_comment")
}

@(test)
tracker_all_no_action_and_clean_scan_have_no_linear_calls :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_all_no_action_and_clean_scan_have_no_linear_calls")
}

@(test)
tracker_already_implemented_without_bound_current_table_is_invalid :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_already_implemented_without_bound_current_table_is_invalid")
}

@(test)
tracker_append_preserves_human_body_and_prior_sections :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_append_preserves_human_body_and_prior_sections")
}

@(test)
tracker_approved_fix_promotion_keeps_ready_proof_human_readable :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_approved_fix_promotion_keeps_ready_proof_human_readable")
}

@(test)
tracker_bool_assessment_schema_is_invalid :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_bool_assessment_schema_is_invalid")
}

@(test)
tracker_byte_identical_denial_with_changed_digests_is_invalid :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_byte_identical_denial_with_changed_digests_is_invalid")
}

@(test)
tracker_close_race_does_not_comment_or_reopen_closed_issue :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_close_race_does_not_comment_or_reopen_closed_issue")
}

@(test)
tracker_closed_and_archived_description_coverage_never_reopens :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_closed_and_archived_description_coverage_never_reopens")
}

@(test)
tracker_closed_comment_coverage_survives_without_reopening :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_closed_comment_coverage_survives_without_reopening")
}

@(test)
tracker_closed_spike_same_change_does_not_promote :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_closed_spike_same_change_does_not_promote")
}

@(test)
tracker_comment_full_body_is_bounded_before_mutation :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_comment_full_body_is_bounded_before_mutation")
}

@(test)
tracker_comment_lookup_never_confirms_two_empty_coverages :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_comment_lookup_never_confirms_two_empty_coverages")
}

@(test)
tracker_comment_only_discovery_after_human_title_and_body_change :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_comment_only_discovery_after_human_title_and_body_change")
}

@(test)
tracker_concurrent_human_comment_never_overwritten :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_concurrent_human_comment_never_overwritten")
}

@(test)
tracker_conflicting_scopes_fail_before_any_mutation :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_conflicting_scopes_fail_before_any_mutation")
}

@(test)
tracker_contract_target_binding_mismatch_rejects_new_fix :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_contract_target_binding_mismatch_rejects_new_fix")
}

@(test)
tracker_deterministic_uuid4_only_new_findings :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_deterministic_uuid4_only_new_findings")
}

@(test)
tracker_duplicate_json_and_nonfinite_are_rejected :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_duplicate_json_and_nonfinite_are_rejected")
}

@(test)
tracker_duplicate_legacy_path_or_conflicting_evidence_is_not_coverage :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_duplicate_legacy_path_or_conflicting_evidence_is_not_coverage")
}

@(test)
tracker_duplicate_state_is_terminal_not_an_append_target :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_duplicate_state_is_terminal_not_an_append_target")
}

@(test)
tracker_expired_scan_budget_never_performs_api_call :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_expired_scan_budget_never_performs_api_call")
}

@(test)
tracker_fix_complete_indices_and_proof_invalid_fail_closed :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_fix_complete_indices_and_proof_invalid_fail_closed")
}

@(test)
tracker_fresh_append_rechecks_scope_changed_after_initial_scan :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_fresh_append_rechecks_scope_changed_after_initial_scan")
}

@(test)
tracker_full_v2_manual_claim_on_unbound_issue_fails_closed :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_full_v2_manual_claim_on_unbound_issue_fails_closed")
}

@(test)
tracker_full_v2_manual_comment_on_wrong_id_fails_closed :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_full_v2_manual_comment_on_wrong_id_fails_closed")
}

@(test)
tracker_historical_completed_fix_does_not_monitor_current_source_forever :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_historical_completed_fix_does_not_monitor_current_source_forever")
}

@(test)
tracker_human_prefix_note_keeps_legacy_binding :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_human_prefix_note_keeps_legacy_binding")
}

@(test)
tracker_human_title_rename_keeps_legacy_and_v2_coverage :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_human_title_rename_keeps_legacy_and_v2_coverage")
}

@(test)
tracker_identity_ignores_heads_runs_unrelated_files_and_size :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_identity_ignores_heads_runs_unrelated_files_and_size")
}

@(test)
tracker_invalid_assessment_on_clean_file_is_not_skipped :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_invalid_assessment_on_clean_file_is_not_skipped")
}

@(test)
tracker_invalid_scan_bindings_and_clean_status_fail_before_api :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_invalid_scan_bindings_and_clean_status_fail_before_api")
}

@(test)
tracker_known_rejection_not_replayed :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_known_rejection_not_replayed")
}

@(test)
tracker_legacy_seven_files_are_covered_when_whatsmeow_changes :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_legacy_seven_files_are_covered_when_whatsmeow_changes")
}

@(test)
tracker_lookalike_spike_title_without_binding_never_selected_for_append :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_lookalike_spike_title_without_binding_never_selected_for_append")
}

@(test)
tracker_lost_comment_is_queried_once_not_replayed :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_lost_comment_is_queried_once_not_replayed")
}

@(test)
tracker_lost_create_is_queried_once_not_replayed :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_lost_create_is_queried_once_not_replayed")
}

@(test)
tracker_malformed_legacy_manual_or_foreign_claims_do_not_cover :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_malformed_legacy_manual_or_foreign_claims_do_not_cover")
}

@(test)
tracker_manual_v2_marker_without_valid_machine_record_does_not_cover :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_manual_v2_marker_without_valid_machine_record_does_not_cover")
}

@(test)
tracker_new_baileys_delta_does_not_append_to_mixed_whatsmeow_review :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_new_baileys_delta_does_not_append_to_mixed_whatsmeow_review")
}

@(test)
tracker_new_revision_reuses_same_open_source_spike :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_new_revision_reuses_same_open_source_spike")
}

@(test)
tracker_new_whatsmeow_delta_appends_to_scoped_mixed_review :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_new_whatsmeow_delta_appends_to_scoped_mixed_review")
}

@(test)
tracker_normalized_legacy_markdown_has_exact_same_coverage :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_normalized_legacy_markdown_has_exact_same_coverage")
}

@(test)
tracker_open_spike_same_change_promotes_once_in_place :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_open_spike_same_change_promotes_once_in_place")
}

@(test)
tracker_owner_source_changed_rejects_new_fix :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_owner_source_changed_rejects_new_fix")
}

@(test)
tracker_pagination_cycle_fails_before_mutation :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_pagination_cycle_fails_before_mutation")
}

@(test)
tracker_project_and_comment_pagination_scan_all_pages :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_project_and_comment_pagination_scan_all_pages")
}

@(test)
tracker_real_classifier_fix_produces_ready_implementation_issue :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_real_classifier_fix_produces_ready_implementation_issue")
}

@(test)
tracker_recognized_malformed_v2_fails_instead_of_duplicate_create :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_recognized_malformed_v2_fails_instead_of_duplicate_create")
}

@(test)
tracker_run_url_is_exact_owa :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_run_url_is_exact_owa")
}

@(test)
tracker_same_source_new_path_reuses_one_spike :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_same_source_new_path_reuses_one_spike")
}

@(test)
tracker_scan_call_budget_fails_before_mutation :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_scan_call_budget_fails_before_mutation")
}

@(test)
tracker_scan_error_and_bound_never_create :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_scan_error_and_bound_never_create")
}

@(test)
tracker_scope_alone_does_not_cover_change_or_authorize_fix :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_scope_alone_does_not_cover_change_or_authorize_fix")
}

@(test)
tracker_scope_marker_keeps_all_legacy_coverage_unchanged :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_scope_marker_keeps_all_legacy_coverage_unchanged")
}

@(test)
tracker_shallow_approval_flag_never_authorizes_fix :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_shallow_approval_flag_never_authorizes_fix")
}

@(test)
tracker_source_owned_requirement_is_revalidated_not_boolean_trusted :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_source_owned_requirement_is_revalidated_not_boolean_trusted")
}

@(test)
tracker_stale_assessment_evidence_fails_before_api :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_stale_assessment_evidence_fails_before_api")
}

@(test)
tracker_three_snapshot_overlap_does_not_repeat_seven_baileys_files :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_three_snapshot_overlap_does_not_repeat_seven_baileys_files")
}

@(test)
tracker_truncated_page_error_prevents_mutation :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_truncated_page_error_prevents_mutation")
}

@(test)
tracker_unapproved_table_difference_is_investigation_not_runtime_fix :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_unapproved_table_difference_is_investigation_not_runtime_fix")
}

@(test)
tracker_unknown_comment_is_not_retried :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_unknown_comment_is_not_retried")
}

@(test)
tracker_unknown_scope_value_is_not_a_routing_authority :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_unknown_scope_value_is_not_a_routing_authority")
}

@(test)
tracker_unknown_uncommitted_create_is_not_retried :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_unknown_uncommitted_create_is_not_retried")
}

@(test)
tracker_unsupported_assessment_and_fix_without_proof_fail_before_api :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_unsupported_assessment_and_fix_without_proof_fail_before_api")
}

@(test)
tracker_updates_render_readable_investigation_and_immutable_links :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_updates_render_readable_investigation_and_immutable_links")
}

@(test)
tracker_wrong_v2_identity_or_foreign_repo_is_not_coverage :: proc(t: ^testing.T) {
	tracker_cases(t, ".test_wrong_v2_identity_or_foreign_repo_is_not_coverage")
}

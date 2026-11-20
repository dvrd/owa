package protocol_watch_test

import w "../src"
import test_fixtures "../../../tests/fixtures/protocol_watch"
import "core:encoding/base64"
import j "core:encoding/json"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strings"
import "core:testing"

SOURCE :: test_fixtures.ROOT + "/src"

fixture_blob :: proc(blobs, key: w.Value) -> []u8 {
	record := w.get(blobs, w.str(key))

	if v, ok := w.get(record, "base64").(j.String); ok {
		bytes, error := base64.decode(string(v))
		assert(error == nil)
		return bytes
	}

	if repeat, ok := w.integer(w.get(record, "repeat")); ok {
		n, _ := w.integer(w.get(record, "length"))
		data := make([]u8, int(n))
		for &c in data {c = u8(repeat)}; return data
	}

	data := make([dynamic]u8)

	for part in w.items(w.get(record, "parts")) {
		if encoded, ok := w.get(part, "base64").(j.String); ok {
			bytes, error := base64.decode(string(encoded))
			assert(error == nil)
			append(&data, ..bytes)
		} else {
			repeat, _ := w.integer(w.get(part, "repeat"))
			n, _ := w.integer(w.get(part, "length"))

			for _ in 0 ..< int(n) {
				append(&data, u8(repeat))
			}
		}
	}

	return data[:]
}

triage_cases :: proc(t: ^testing.T, suffix: string) {
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena)
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	corpus, error := w.decode(#load("fixtures/triage.json"), 16 * 1024 * 1024)

	if !testing.expect_value(t, error, "") {
		return
	}

	blobs := w.get(corpus, "blobs")
	executed := 0

	for test in w.items(w.get(corpus, "cases")) {
		if !strings.has_suffix(w.str(w.get(test, "test")), suffix) {
			continue
		}

		root, create_error := os.make_directory_temp("", "owa-triage-*", context.allocator)

		if !testing.expect_value(t, create_error, nil) {
			return
		}

		defer {
			cleanup_error := os.remove_all(root)
			_ = cleanup_error
		}

		expected := w.get(test, "expected")

		for relative, entry in w.get(test, "files").(j.Object) {
			path := w.join(root, relative)
			slash := strings.last_index(path, "/")
			mkdir_error := os.make_directory_all(path[:slash])

			if !testing.expect(t, mkdir_error == nil || mkdir_error == os.Error(os.General_Error.Exist)) {
				return
			}

			if symlink, ok := w.get(entry, "symlink").(j.String); ok {
				link_error := os.symlink(string(symlink), path)

				if !testing.expect_value(t, link_error, nil) {
					return
				}
			} else {
				bytes := fixture_blob(blobs, w.get(entry, "blob"))

				if canonical, is_canonical := w.get(entry, "canonical").(j.String); is_canonical {
					loaded_bytes, read_error := os.read_entire_file(w.join(SOURCE, string(canonical)), context.allocator)
					assert(read_error == nil)
					write_error := os.write_entire_file(path, loaded_bytes)
					assert(write_error == nil)

					for &target in w.items(w.get(expected, "local_targets")) {
						if w.str(w.get(target, "path")) == relative {
							w.put(&target, "sha256", w.text(w.sha256(loaded_bytes)))
						}
					}

					continue
				}

				write_error := os.write_entire_file(path, bytes)
				assert(write_error == nil)
			}
		}

		if w.str(w.get(test, "operation")) == "assess" {
			before, after := w.get(test, "before"), w.get(test, "after")
			_, bp := before.(j.String)
			_, ap := after.(j.String)
			actual := w.assess_upstream_file_change(
				w.get(test, "source"),
				w.str(w.get(test, "path")),
				fixture_blob(blobs, before),
				fixture_blob(blobs, after),
				bp,
				ap,
				root,
				w.str(w.get(test, "approved_contract")),
			)

			if !w.equal(actual, expected) {
				fmt.eprintf("PARITY %s\nEXPECTED %s\nACTUAL %s\n", suffix, w.encode(expected), w.encode(actual))
				testing.expect(t, false)
			}
		} else {
			actual := w.validate_approved_contract(w.get(test, "assessment"), root)
			testing.expect_value(t, actual, w.json_boolean_equals(expected))
		}

		removed := os.remove_all(root)
		testing.expect_value(t, removed, nil)
		executed += 1
	}

	testing.expect(t, executed > 0)
}

@(test)
triage_identical_known_bytes_are_no_action :: proc(t: ^testing.T) {
	triage_cases(t, ".test_identical_known_bytes_are_no_action")
}

@(test)
triage_conservative_comment_and_horizontal_format_proof :: proc(t: ^testing.T) {
	triage_cases(t, ".test_conservative_comment_and_horizontal_format_proof")
}

@(test)
triage_newlines_asi_operators_and_literals_are_not_ignored :: proc(t: ^testing.T) {
	triage_cases(t, ".test_newlines_asi_operators_and_literals_are_not_ignored")
}

@(test)
triage_changed_directives_and_license_are_spikes :: proc(t: ^testing.T) {
	triage_cases(t, ".test_changed_directives_and_license_are_spikes")
}

@(test)
triage_slash_and_syntax_uncertainty_refuse_equivalence :: proc(t: ^testing.T) {
	triage_cases(t, ".test_slash_and_syntax_uncertainty_refuse_equivalence")
}

@(test)
triage_json_semantics_and_duplicate_key_refusal :: proc(t: ^testing.T) {
	triage_cases(t, ".test_json_semantics_and_duplicate_key_refusal")
}

@(test)
triage_binding_missing_targets_and_limits_fail_closed :: proc(t: ^testing.T) {
	triage_cases(t, ".test_binding_missing_targets_and_limits_fail_closed")
}

@(test)
triage_all_seventeen_paths_bind_existing_local_owners :: proc(t: ^testing.T) {
	triage_cases(t, ".test_all_seventeen_paths_bind_existing_local_owners")
}

@(test)
triage_exact_dictionary_drift_is_relevant_but_unqualified_spike :: proc(t: ^testing.T) {
	triage_cases(t, ".test_exact_dictionary_drift_is_relevant_but_unqualified_spike")
}

@(test)
triage_already_implemented_dictionary_is_no_action :: proc(t: ^testing.T) {
	triage_cases(t, ".test_already_implemented_dictionary_is_no_action")
}

@(test)
triage_table_other_changes_unknown_local_baseline_and_counts_are_spikes :: proc(t: ^testing.T) {
	triage_cases(t, ".test_table_other_changes_unknown_local_baseline_and_counts_are_spikes")
}

@(test)
triage_table_escaped_strings_and_bounded_evidence :: proc(t: ^testing.T) {
	triage_cases(t, ".test_table_escaped_strings_and_bounded_evidence")
}

@(test)
triage_directive_position_and_indentation_are_not_harmless :: proc(t: ^testing.T) {
	triage_cases(t, ".test_directive_position_and_indentation_are_not_harmless")
}

@(test)
triage_template_expression_html_numeric_and_resource_ambiguity :: proc(t: ^testing.T) {
	triage_cases(t, ".test_template_expression_html_numeric_and_resource_ambiguity")
}

@(test)
triage_go_raw_strings_and_go_or_proto_comments :: proc(t: ^testing.T) {
	triage_cases(t, ".test_go_raw_strings_and_go_or_proto_comments")
}

@(test)
triage_go_build_line_preamble_and_carriage_return_are_not_stripped :: proc(t: ^testing.T) {
	triage_cases(t, ".test_go_build_line_preamble_and_carriage_return_are_not_stripped")
}

@(test)
triage_nested_tables_and_unsupported_escape_are_spikes :: proc(t: ^testing.T) {
	triage_cases(t, ".test_nested_tables_and_unsupported_escape_are_spikes")
}

@(test)
triage_explicit_reviewed_contract_enables_static_gap_fix :: proc(t: ^testing.T) {
	triage_cases(t, ".test_explicit_reviewed_contract_enables_static_gap_fix")
}

@(test)
triage_approved_contract_binding_path_symlink_and_weak_claims_fail_closed :: proc(t: ^testing.T) {
	triage_cases(t, ".test_approved_contract_binding_path_symlink_and_weak_claims_fail_closed")
}

@(test)
triage_new_fix_proof_revalidation_detects_stale_owners_and_forged_metadata :: proc(t: ^testing.T) {
	triage_cases(t, ".test_new_fix_proof_revalidation_detects_stale_owners_and_forged_metadata")
}

@(test)
triage_table_sensitive_comment_change_is_not_a_fix :: proc(t: ^testing.T) {
	triage_cases(t, ".test_table_sensitive_comment_change_is_not_a_fix")
}

@(test)
triage_real_owned_dictionary :: proc(t: ^testing.T) {
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena)
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	bytes, error := w.read_file(w.join(SOURCE, "binary_tokens.odin"))

	if !testing.expect_value(t, error, "") {
		return
	}

	tokens, lex_error := w.lex(bytes, "odin")

	if !testing.expect_value(t, lex_error, "") {
		return
	}

	values, _, table_error := w.extract_single_byte_token_table(tokens.tokens[:], "odin")
	testing.expect_value(t, table_error, "")
	testing.expect_value(t, len(values), 236)
}

@(test)
reviewed_contract_paths_follow_the_watcher_directory :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, err := os.make_directory_temp("", "owa-contract-path-*", context.allocator)
	if !testing.expect_value(t, err, nil) { return }
	defer os.remove_all(root)
	// A missing file in the owned directory passes path validation and reaches the filesystem.
	_, missing := w.approved_metadata(w.null(), root, "tools/protocol_watcher/contracts/missing.json")
	testing.expect_value(t, missing, "CONTRACT_FILE")
	_, outside := w.approved_metadata(w.null(), root, "tools/protocol_watcher/src/missing.json")
	testing.expect_value(t, outside, "CONTRACT_PATH")
}

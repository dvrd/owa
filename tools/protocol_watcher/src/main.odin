package protocol_watch

import "core:fmt"
import "core:mem"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:time"

read_json :: proc(path: string, maximum := MAX_REPORT) -> (value: Value, failure: Failure) {
	data, error := read_file(path, maximum)
	if error != "" {
		return null(), "TRACKING_METADATA_INVALID"
	}

	decoded, parse_error := decode(data, maximum)
	if parse_error != "" {
		return null(), "TRACKING_METADATA_INVALID"
	}

	return decoded, nil
}

arg :: proc(options: Value, key: string, fallback: string = "") -> string {
	value := str(get(options, key))
	return value if value != "" else fallback
}

parse_option_pairs :: proc(values: []string) -> (result: Value, failure: Failure) {
	result = object()
	for i := 0; i < len(values); i += 2 {
		if i + 1 >= len(values) ||
		   !strings.has_prefix(values[i], "--") ||
		   slice.contains(keys(result), values[i]) {
			return null(), "ARGUMENTS_INVALID"
		}

		put(&result, values[i], text(values[i + 1]))
	}

	return
}

load_source_manifest :: proc(options: Value) -> (value: Value, failure: Failure) {
	path := arg(
		options,
		"--manifest",
		join(library_root(), "tools/protocol_watcher/sources.json"),
	)

	data, error := read_file(path, MAX_REPORT)
	if error != "" {
		return null(), "MANIFEST_INVALID"
	}

	return manifest_read(data)
}

public_scan :: proc(
	data: rawptr,
	state, approved: string,
) -> (
	value: Value,
	failure: Failure,
) {
	original := cast(^Value)data

	settings := Observation {
		root              = library_root(),
		approved_contract = approved,
	}

	return check_upstream_changes(original^, state, settings)
}

append_to_env_named_file :: proc(name, value: string) {
	if path, ok := os.lookup_env(name, context.allocator); ok && path != "" {
		file, error := os.open(path, {.Write, .Append})
		if error == nil {
			_, _ = os.write(file, transmute([]u8)value)
			os.close(file)
		}
	}
}

execute :: proc(
	mode: string,
	values: []string,
) -> (
	result: Value,
	code: int,
	failure: Failure,
) {
	opts := parse_option_pairs(values) or_return

	allowed := []string {
		"--manifest",
		"--state-dir",
		"--approved-contract",
		"--output-dir",
		"--report",
		"--output",
		"--run-url",
		"--source-root",
		"--offline-receipt",
		"--live-receipt",
		"--evidence-dir",
		"--library",
		"--codex",
		"--budget-seconds",
	}
	for name in keys(opts) {
		if !slice.contains(allowed, name) {
			return null(), 2, "ARGUMENTS_INVALID"
		}
	}

	state := arg(opts, "--state-dir")
	approved := arg(opts, "--approved-contract")

	switch mode {
	case "watch":
		source := load_source_manifest(opts) or_return
		result = check_upstream_changes(
			source,
			state,
			Observation{root = library_root(), approved_contract = approved},
		) or_return

		summary := object()
		for key in keys(result) {
			if key != "observation" {
				put(&summary, key, get(result, key))
			}
		}

		result = summary
		return result, 3 if str(get(result, "status")) == "REVIEW_REQUIRED" else 0, nil
	case "ci":
		source := load_source_manifest(opts) or_return
		result = ci_prepare(
			state,
			arg(opts, "--output-dir"),
			approved,
			public_scan,
			&source,
		) or_return

		append_to_env_named_file("GITHUB_OUTPUT", concatenate_strings("status=", str(get(result, "status")), "\n"))
		return result, 2 if str(get(result, "status")) == "FAILED" else 0, nil
	case "linear":
		report, tracking_error := read_json(arg(opts, "--report"))

		key, _ := os.lookup_env("LINEAR_API", context.allocator)

		network := Network {
			linear_key = key,
		}

		api := API {
			call    = linear_transport,
			data    = &network,
			started = time.tick_now(),
		}

		if tracking_error == nil {
			result, tracking_error = sync_review_findings(
				report,
				arg(opts, "--run-url"),
				library_root(),
				&api,
			)
		}

		if tracking_error != nil {
			result = object(
				{"status", text("FAILED")},
				{"reason", text(tracking_error.(string))},
			)
		}

		atomic_json(arg(opts, "--output"), result) or_return

		if str(get(result, "status")) != "FAILED" {
			summary := concatenate_strings("Protocol scan: ", str(get(result, "status")), ".\n")
			for issue in items(get(result, "issues")) {
				summary = concatenate_strings(
					summary,
					"\nTriage: [",
					str(get(issue, "identifier")),
					"](",
					str(get(issue, "url")),
					").\n",
				)
			}

			append_to_env_named_file("GITHUB_STEP_SUMMARY", summary)
		}

		return result, 2 if str(get(result, "status")) == "FAILED" else 0, nil
	case "promotion":
		offline := read_json(arg(opts, "--offline-receipt"), 1024 * 1024) or_return
		live := read_json(arg(opts, "--live-receipt"), 1024 * 1024) or_return

		result = evaluate(
			arg(opts, "--source-root"),
			offline,
			live,
			arg(opts, "--evidence-dir"),
		) or_return

		return result, 0 if str(get(result, "status")) == "ELIGIBLE_FOR_REVIEW" else 1, nil
	case "schedule-run", "schedule-plist":
		budget, ok := strconv.parse_int(arg(opts, "--budget-seconds", "600"))
		if !ok {
			return null(), 2, "BUDGET_INVALID"
		}

		binary, error := os.get_executable_path(context.allocator)
		if error != nil {
			return null(), 2, "SCHEDULE_FAILED"
		}

		args := Schedule {
			state_dir         = state,
			manifest          = arg(
				opts,
				"--manifest",
				join(library_root(), "tools/protocol_watcher/sources.json"),
			),
			library           = arg(opts, "--library", library_root()),
			codex             = arg(opts, "--codex", "/opt/homebrew/bin/codex"),
			executable        = binary,
			approved_contract = approved,
			budget_seconds    = budget,
		}

		if mode == "schedule-run" {
			result = schedule_run(args) or_return
		} else {
			result = write_plist(args) or_return
		}

		return result, 2 if str(get(result, "status")) == "FAILED" else 0, nil
	case:
		return null(), 2, "ARGUMENTS_INVALID"
	}
}

main :: proc() {
	arena: mem.Dynamic_Arena
	mem.dynamic_arena_init(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)

	mode := ""
	args := os.args[1:]
	if len(args) > 0 {
		mode = args[0]
		args = args[1:]
	}

	if mode == "schedule" && len(args) > 0 {
		mode = concatenate_strings(mode, "-", args[0])
		args = args[1:]
	}

	result, code, failure := execute(mode, args)
	if failure != nil && mode == "promotion" {
		result = object(
			{"status", text("BLOCKED")},
			{"failures", array(text("INVALID_SOURCE_OR_RECEIPT"))},
			{"deployment_authorized", boolean(false)},
			{"state_rollback_authorized", boolean(false)},
		)
		code = 1
	} else if failure != nil {
		result = object(
			{"status", text("FAILED")},
			{"reason", text(failure.(string))},
			{"compatibility_approved", boolean(false)},
		)
		code = 2
	}

	fmt.println(encode(result))
	mem.dynamic_arena_destroy(&arena)
	os.exit(code)
}

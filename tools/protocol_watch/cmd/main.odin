package main

import "core:slice"
import w ".."
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

read_json :: proc(path: string, maximum := w.MAX_REPORT) -> (value: w.Value, failure: w.Failure) {
	data, error := w.read_file(path, maximum)
	if error != "" {
		return w.null(), "TRACKING_METADATA_INVALID"
	}

	decoded, parse_error := w.decode(data, maximum)
	if parse_error != "" {
		return w.null(), "TRACKING_METADATA_INVALID"
	}

	return decoded, nil
}

arg :: proc(options: w.Value, key: string, fallback: string = "") -> string {
	value := w.str(w.get(options, key))
	return value if value != "" else fallback
}

parse_option_pairs :: proc(values: []string) -> (result: w.Value, failure: w.Failure) {
	result = w.object()
	for i := 0; i < len(values); i += 2 {
		if i + 1 >= len(values) ||
		   !strings.has_prefix(values[i], "--") ||
		   slice.contains(w.keys(result), values[i]) {
			return w.null(), "ARGUMENTS_INVALID"
		}

		w.put(&result, values[i], w.text(values[i + 1]))
	}

	return
}

load_source_manifest :: proc(options: w.Value) -> (value: w.Value, failure: w.Failure) {
	path := arg(
		options,
		"--manifest",
		w.join(w.library_root(), "tools/protocol_watch/sources.json"),
	)

	data, error := w.read_file(path, w.MAX_REPORT)
	if error != "" {
		return w.null(), "MANIFEST_INVALID"
	}

	return w.manifest_read(data)
}

public_scan :: proc(
	data: rawptr,
	state, approved: string,
) -> (
	value: w.Value,
	failure: w.Failure,
) {
	original := cast(^w.Value)data

	settings := w.Observation {
		root              = w.library_root(),
		approved_contract = approved,
	}

	return w.check_upstream_changes(original^, state, settings)
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
	result: w.Value,
	code: int,
	failure: w.Failure,
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
	for name in w.keys(opts) {
		if !slice.contains(allowed, name) {
			return w.null(), 2, "ARGUMENTS_INVALID"
		}
	}

	state := arg(opts, "--state-dir")
	approved := arg(opts, "--approved-contract")

	switch mode {
	case "watch":
		source := load_source_manifest(opts) or_return
		result = w.check_upstream_changes(
			source,
			state,
			w.Observation{root = w.library_root(), approved_contract = approved},
		) or_return

		summary := w.object()
		for key in w.keys(result) {
			if key != "observation" {
				w.put(&summary, key, w.get(result, key))
			}
		}

		result = summary
		return result, 3 if w.str(w.get(result, "status")) == "REVIEW_REQUIRED" else 0, nil
	case "ci":
		source := load_source_manifest(opts) or_return
		result = w.ci_prepare(
			state,
			arg(opts, "--output-dir"),
			approved,
			public_scan,
			&source,
		) or_return

		append_to_env_named_file("GITHUB_OUTPUT", w.concatenate_strings("status=", w.str(w.get(result, "status")), "\n"))
		return result, 2 if w.str(w.get(result, "status")) == "FAILED" else 0, nil
	case "linear":
		report, tracking_error := read_json(arg(opts, "--report"))

		key, _ := os.lookup_env("LINEAR_API", context.allocator)

		network := w.Network {
			linear_key = key,
		}

		api := w.API {
			call    = w.linear_transport,
			data    = &network,
			started = time.tick_now(),
		}

		if tracking_error == nil {
			result, tracking_error = w.sync_review_findings(
				report,
				arg(opts, "--run-url"),
				w.library_root(),
				&api,
			)
		}

		if tracking_error != nil {
			result = w.object(
				{"status", w.text("FAILED")},
				{"reason", w.text(tracking_error.(string))},
			)
		}

		w.atomic_json(arg(opts, "--output"), result) or_return

		if w.str(w.get(result, "status")) != "FAILED" {
			summary := w.concatenate_strings("Protocol scan: ", w.str(w.get(result, "status")), ".\n")
			for issue in w.items(w.get(result, "issues")) {
				summary = w.concatenate_strings(
					summary,
					"\nTriage: [",
					w.str(w.get(issue, "identifier")),
					"](",
					w.str(w.get(issue, "url")),
					").\n",
				)
			}

			append_to_env_named_file("GITHUB_STEP_SUMMARY", summary)
		}

		return result, 2 if w.str(w.get(result, "status")) == "FAILED" else 0, nil
	case "promotion":
		offline := read_json(arg(opts, "--offline-receipt"), 1024 * 1024) or_return
		live := read_json(arg(opts, "--live-receipt"), 1024 * 1024) or_return

		result = w.evaluate(
			arg(opts, "--source-root"),
			offline,
			live,
			arg(opts, "--evidence-dir"),
		) or_return

		return result, 0 if w.str(w.get(result, "status")) == "ELIGIBLE_FOR_REVIEW" else 1, nil
	case "schedule-run", "schedule-plist":
		budget, ok := strconv.parse_int(arg(opts, "--budget-seconds", "600"))
		if !ok {
			return w.null(), 2, "BUDGET_INVALID"
		}

		binary, error := os.get_executable_path(context.allocator)
		if error != nil {
			return w.null(), 2, "SCHEDULE_FAILED"
		}

		args := w.Schedule {
			state_dir         = state,
			manifest          = arg(
				opts,
				"--manifest",
				w.join(w.library_root(), "tools/protocol_watch/sources.json"),
			),
			library           = arg(opts, "--library", w.library_root()),
			codex             = arg(opts, "--codex", "/opt/homebrew/bin/codex"),
			executable        = binary,
			approved_contract = approved,
			budget_seconds    = budget,
		}

		if mode == "schedule-run" {
			result = w.schedule_run(args) or_return
		} else {
			result = w.write_plist(args) or_return
		}

		return result, 2 if w.str(w.get(result, "status")) == "FAILED" else 0, nil
	case:
		return w.null(), 2, "ARGUMENTS_INVALID"
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
		mode = w.concatenate_strings(mode, "-", args[0])
		args = args[1:]
	}

	result, code, failure := execute(mode, args)
	if failure != nil && mode == "promotion" {
		result = w.object(
			{"status", w.text("BLOCKED")},
			{"failures", w.array(w.text("INVALID_SOURCE_OR_RECEIPT"))},
			{"deployment_authorized", w.boolean(false)},
			{"state_rollback_authorized", w.boolean(false)},
		)
		code = 1
	} else if failure != nil {
		result = w.object(
			{"status", w.text("FAILED")},
			{"reason", w.text(failure.(string))},
			{"compatibility_approved", w.boolean(false)},
		)
		code = 2
	}

	fmt.println(w.encode(result))
	mem.dynamic_arena_destroy(&arena)
	os.exit(code)
}

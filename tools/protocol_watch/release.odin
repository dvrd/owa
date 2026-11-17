package protocol_watch
import "core:os"
import "core:strings"
import p "core:sys/posix"

REQUIRED := []string{"consumer", "noise_loopback", "protocol_review", "unit_asan"}
source_digest :: proc(root: string) -> (digest: string, files: Value, failure: Failure) {
	entries, error := os.read_directory_by_path(root, -1, context.allocator)

	if error != nil {
		return "", null(), "SOURCE_SET_INVALID"
	}; files = object(); count := 0
	for file in entries {
		name := file.name

		if !strings.has_suffix(name, ".odin") || strings.has_suffix(name, "_test.odin") {
			continue
		}; count += 1; if count > 100 {
			return "", null(), "SOURCE_SET_INVALID"
		}; bytes, read_error := read_file(join(root, name)); if read_error != "" {
			return "", null(), "SOURCE_SET_INVALID"
		}; put(&files, name, text(sha256(bytes)))
	}

	if count == 0 {
		return "", null(), "SOURCE_SET_INVALID"
	}; return sha256(transmute([]u8)encode(files, true)), files, nil
}
evidence_matches :: proc(check: Value, directory: string) -> bool {
	name := str(get(check, "evidence_file"))

	if name == "" || len(name) > 200 || strings.has_prefix(name, "/") {
		return false
	}

	for part in strings.split(name, "/") {
		if part == ".." {
			return false
		}
	}

	// Resolve each component without following symlinks, including directories.
	current := directory

	for part in strings.split(name, "/") {
		if part == "." || part == "" {
			continue
		}; current = join(current, part); info: p.stat_t
		if p.lstat(strings.clone_to_cstring(current), &info) != {} || p.S_ISLNK(info.st_mode) {
			return false
		}
	}

	bytes, error := read_file(current, 16 * 1024 * 1024)

	return error == "" && sha256(bytes) == str(get(check, "evidence_sha256"))
}
evaluate :: proc(root: string, offline, live: Value, evidence_dir: string) -> (result: Value, failure: Failure) {
	digest, files := source_digest(root) or_return
	failures := make_strings()

	if str(get(offline, "candidate_source_digest")) != digest {
		append(&failures, "OFFLINE_SOURCE_MISMATCH")
	}

	checks := get(offline, "checks")

	for name in REQUIRED {
		check := get(checks, name)
		if str(get(check, "status")) != "PASS" ||
		   str(get(check, "candidate_source_digest")) != digest ||
		   !hex_valid(str(get(check, "evidence_sha256")), 64) ||
		   !evidence_matches(check, evidence_dir) {
			append(&failures, cat("MISSING_OR_INVALID_", strings.to_upper(name)))
		}
	}

	if !hex_valid(str(get(offline, "compiler_sha256")), 64) {
		append(&failures, "COMPILER_UNBOUND")
	}

	if str(get(live, "candidate_source_digest")) != digest {
		append(&failures, "LIVE_SOURCE_MISMATCH")
	}

	if !evidence_matches(live, evidence_dir) {
		append(&failures, "LIVE_EVIDENCE_MISSING_OR_CHANGED")
	}

	complete := truth(get(live, "duplicates_reported"), false)

	for name in ([]string {
			"isolated_group_verified",
			"text_server_acked",
			"pdf_server_acked",
			"recipient_confirmed",
			"pdf_opened",
			"same_ids_after_restart",
		}) {complete = complete && truth(get(live, name))}
	if !complete {
		append(&failures, "LIVE_QUALIFICATION_INCOMPLETE")
	}

	return object(
			{"status", text("ELIGIBLE_FOR_REVIEW" if len(failures) == 0 else "BLOCKED")},
			{"candidate_source_digest", text(digest)},
			{"source_files", files},
			{"failures", value_strings(failures[:])},
			{"deployment_authorized", boolean(false)},
			{"state_rollback_authorized", boolean(false)},
		),
		nil
}
make_strings :: proc() -> [dynamic]string {
	return make([dynamic]string)
}
Scan :: proc(data: rawptr, state, approved_contract: string) -> (Value, Failure)
ci_prepare :: proc(
	state, output, approved_contract: string,
	scan: Scan,
	data: rawptr,
) -> (
	result: Value,
	failure: Failure,
) {
	fd := locked_state(output) or_return
	defer p.close(fd)
	report, scan_error := scan(data, state, approved_contract)
	status := str(get(report, "status"))
	encoded := encode(report)
	if scan_error != nil ||
	   status != "REVIEW_REQUIRED" && status != "NO_MONITORED_DRIFT" ||
	   encoded == "" ||
	   len(encoded) > MAX_REPORT {
		result = object(
			{"status", text("FAILED")},
			{"report_ready", boolean(false)},
			{"compatibility_approved", boolean(false)},
			{"reason", text("PUBLIC_SCAN_FAILED")},
		)
	} else {
		atomic_json(join(output, "report.json"), report) or_return
		result = object(
			{"status", text(status)},
			{"report_ready", boolean(true)},
			{"compatibility_approved", boolean(false)},
		)
	}
	atomic_json(join(output, "result.json"), result) or_return
	return
}

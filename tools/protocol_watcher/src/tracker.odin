package protocol_watch

import "core:slice"
CREATE :: "mutation($input:IssueCreateInput!){issueCreate(input:$input){success}}"

SCAN :: "query($after:String){issues(filter:{project:{id:{eq:\"b16b3039-a8cd-4080-adc2-d032669d0365\"}},or:[{title:{contains:\"OWA:\"}},{description:{contains:\"owa-protocol-drift:v1:\"}},{description:{contains:\"owa-protocol-review:v2\"}},{comments:{some:{body:{contains:\"owa-protocol-review:v2:begin\"}}}}]},includeArchived:true,first:10,after:$after){nodes{id identifier url title description archivedAt state{type} project{id}}pageInfo{hasNextPage endCursor}}}"

LOOKUP :: "query($ids:[ID!]!){issues(filter:{id:{in:$ids}},includeArchived:true,first:2){nodes{id identifier url title description archivedAt state{type} project{id}}}}"

COMMENTS :: "query($id:String!,$after:String){issue(id:$id){id project{id}\n comments(first:20,after:$after){nodes{id body}pageInfo{hasNextPage endCursor}}}}"

COMMENT_LOOKUP :: "query($id:ID!){comments(filter:{id:{eq:$id}},first:2){nodes{id body issue{id project{id}}}}}"

COMMENT_CREATE :: "mutation($input:CommentCreateInput!){commentCreate(input:$input){success}}"
import j "core:encoding/json"
import "core:fmt"
import "core:strings"
import "core:time"

APICall :: proc(data: rawptr, query: string, variables: Value) -> (Value, Failure)
API :: struct {
	call:                    APICall,
	data:                    rawptr,
	calls, bytes, max_calls: int,
	started:                 time.Tick,
}

Item :: struct {
	source, file: Value,
}

REASONS := []string {
	"SOURCE_BINDING_UNKNOWN",
	"INPUT_UNAVAILABLE",
	"LOCAL_OWNER_UNAVAILABLE",
	"BYTE_IDENTICAL",
	"LEXICALLY_EQUIVALENT",
	"JSON_NORMALIZED_EQUIVALENT",
	"LEXICAL_PROOF_UNAVAILABLE",
	"DIRECTIVE_OR_LICENSE_CHANGED",
	"BEHAVIOR_CHANGE_UNRESOLVED",
	"TABLE_PROOF_UNAVAILABLE",
	"TABLE_OUTSIDE_CHANGE",
	"LOCAL_BASELINE_UNKNOWN",
	"ALREADY_IMPLEMENTED",
	"LOCAL_DICTIONARY_CONTRACT_DRIFT",
	"APPROVED_DICTIONARY_CONTRACT_GAP",
	"APPROVED_CONTRACT_UNAVAILABLE",
	"ASSESSMENT_MISSING",
}

api_call :: proc(api: ^API, query: string, variables: Value) -> (value: Value, failure: Failure) {
	if time.tick_diff(api.started, time.tick_now()) >= 120 * time.Second {
		return null(), "LINEAR_SCAN_BUDGET"
	}

	api.calls += 1

	if api.calls > (api.max_calls if api.max_calls > 0 else 64) {
		return null(), "LINEAR_SCAN_BOUND"
	}

	value = api.call(api.data, query, variables) or_return
	encoded := encode(value, true)

	if encoded == "" {
		return null(), "LINEAR_RESPONSE_INVALID"
	}

	api.bytes += len(encoded)

	if api.bytes > MAX_REPORT {
		return null(), "LINEAR_SCAN_BOUND"
	}

	return
}

manifest_read :: proc(bytes: []u8) -> (manifest: Value, failure: Failure) {
	value, error := decode(bytes)

	if error != "" {
		return null(), "MANIFEST_INVALID"
	}

	schema, schema_ok := integer(get(value, "schema"))
	sources := items(get(value, "sources"))

	if !schema_ok || schema != 1 || len(sources) < 1 || len(sources) > 2 {
		return null(), "MANIFEST_INVALID"
	}

	seen := make(map[string]bool)

	for source in sources {
		name := str(get(source, "name"))
		repo := str(get(source, "repository"))
		branch := str(get(source, "branch"))
		paths := items(get(source, "paths"))
		if !path_valid(name) ||
		   strings.contains(name, "/") ||
		   seen[name] ||
		   !path_valid(branch) ||
		   strings.contains(branch, "/") ||
		   repo != "WhiskeySockets/Baileys" && repo != "tulir/whatsmeow" ||
		   !hex_valid(str(get(source, "reference_commit")), 40) ||
		   len(paths) < 1 ||
		   len(paths) > 16 {
			return null(), "MANIFEST_INVALID"
		}

		seen[name] = true
		paths_seen := make(map[string]bool)

		for path_value in paths {
			path := str(path_value)

			if !path_valid(path) || paths_seen[path] {
				return null(), "MANIFEST_INVALID"
			}

			paths_seen[path] = true
		}
	}

	return value, nil
}

default_manifest :: proc() -> Value {
	value, error := manifest_read(#load("../sources.json"))
	assert(error == nil)

	return value
}

validate_digest :: proc(value: Value) -> Failure {
	if !has_exact_object_fields(value, []string{"present", "bytes", "sha256"}) {
		return "REPORT_DIGEST_INVALID"
	}

	present, present_ok := get(value, "present").(j.Boolean)
	size, size_ok := integer(get(value, "bytes"))
	hash := get(value, "sha256")

	if !present_ok || !size_ok || size < 0 || size > MAX_BYTES {
		return "REPORT_DIGEST_INVALID"
	}

	if bool(present) {
		if !hex_valid(str(hash), 64) {
			return "REPORT_DIGEST_INVALID"
		}
	} else {
		if _, ok := hash.(j.Null); !ok || size != 0 {
			return "REPORT_DIGEST_INVALID"
		}
	}

	return nil
}

snapshot :: proc(report: Value) -> (fingerprint: string, changed: [dynamic]Item, failure: Failure) {
	expected := items(get(default_manifest(), "sources"))
	sources := items(get(get(report, "observation"), "sources"))

	if len(sources) != len(expected) {
		return "", nil, "REPORT_SOURCES_INVALID"
	}

	canonical := make(j.Array)

	for source, i in sources {
		for key in ([]string{"name", "repository", "reference_commit"}) {
			if !equal(get(source, key), get(expected[i], key)) {
				return "", nil, "REPORT_SOURCE_INVALID"
			}
		}

		if !hex_valid(str(get(source, "head_commit")), 40) {
			return "", nil, "REPORT_HEAD_INVALID"
		}

		files := items(get(source, "files"))
		paths := items(get(expected[i], "paths"))

		if len(files) != len(paths) {
			return "", nil, "REPORT_PATHS_INVALID"
		}

		entries := make(j.Array)

		for file, index in files {
			if !equal(get(file, "path"), paths[index]) {
				return "", nil, "REPORT_PATHS_INVALID"
			}

			reference, current := get(file, "reference"), get(file, "current")
			validate_digest(reference) or_return
			validate_digest(current) or_return

			if !json_boolean_equals(get(reference, "present")) && !json_boolean_equals(get(current, "present")) {
				return "", nil, "REPORT_PATH_MISSING"
			}

			if equal(get(reference, "sha256"), get(current, "sha256")) &&
			   !equal(get(reference, "bytes"), get(current, "bytes")) {
				return "", nil, "REPORT_DIGEST_INVALID"
			}

			differs := !equal(reference, current)

			if !json_boolean_equals(get(file, "changed_from_reference"), differs) {
				return "", nil, "REPORT_CHANGE_INVALID"
			}

			append(&entries, object({"path", get(file, "path")}, {"reference", reference}, {"current", current}))

			if differs {
				append(&changed, Item{source, file})
			}
		}

		append(
			&canonical,
			object(
				{"name", get(source, "name")},
				{"repository", get(source, "repository")},
				{"reference_commit", get(source, "reference_commit")},
				{"files", entries},
			),
		)
	}

	if !json_boolean_equals(get(report, "compatibility_approved"), false) || !json_boolean_equals(get(report, "runtime_version_changed"), false) {
		return "", nil, "REPORT_POLICY_INVALID"
	}

	if str(get(report, "status")) == "NO_MONITORED_DRIFT" && len(changed) > 0 {
		return "", nil, "REPORT_STATUS_INVALID"
	}

	return sha256(transmute([]u8)encode(canonical)), changed, nil
}

bounded_strings :: proc(value: Value, maximum_count, maximum_length: int) -> bool {
	values, ok := value.(j.Array)

	if !ok || len(values) > maximum_count {
		return false
	}

	for item in values {
		if !text_limit(item, 1, maximum_length) {
			return false
		}
	}

	return true
}

validate_assessment :: proc(
	source, file: Value,
	root: string,
	verify_contract := true,
) -> (
	value: Value,
	failure: Failure,
) {
	owner, bound := owner_for(str(get(source, "name")), str(get(file, "path")))
	if !bound {
		return null(), "ASSESSMENT_BINDING_INVALID"
	}

	if obj, ok := file.(j.Object); ok {
		if _, present := obj["assessment"]; !present {
			return object(
					{"schema", number(1)},
					{"kind", text("SPIKE")},
					{"reason", text("ASSESSMENT_MISSING")},
					{
						"summary",
						text("Does this changed reference affect the local implementation? Impact is unassessed."),
					},
					{"source", get(source, "name")},
					{"path", get(file, "path")},
					{"local_targets", array()},
					{"checks", array(text("Establish the affected contract and inspect local ownership."))},
					{"acceptance", array(text("Record evidence for no action or a bounded implementation fix."))},
					{
						"evidence",
						object(
							{"reference", get(file, "reference")},
							{"current", get(file, "current")},
							{"question", text(owner.question)},
							{"server_compatibility_proven", boolean(false)},
						),
					},
				),
				nil
		}
	}

	value = get(file, "assessment")
	kind, reason := str(get(value, "kind")), str(get(value, "reason"))
	schema, ok := integer(get(value, "schema"))
	if !has_exact_object_fields(
		   value,
		   []string {
			   "schema",
			   "kind",
			   "reason",
			   "summary",
			   "source",
			   "path",
			   "local_targets",
			   "checks",
			   "acceptance",
			   "evidence",
		   },
	   ) ||
	   !ok ||
	   schema != 1 ||
	   !slice.contains([]string{"NO_ACTION", "SPIKE", "FIX"}, kind) ||
	   !slice.contains(REASONS, reason) ||
	   !text_limit(get(value, "summary"), 1, 2000) {
		return null(), "ASSESSMENT_INVALID"
	}

	if !equal(get(value, "source"), get(source, "name")) || !equal(get(value, "path"), get(file, "path")) {
		return null(), "ASSESSMENT_BINDING_INVALID"
	}

	if !bounded_strings(get(value, "checks"), 32, 1000) || !bounded_strings(get(value, "acceptance"), 32, 1000) {
		return null(), "ASSESSMENT_INVALID"
	}

	targets, target_ok := get(value, "local_targets").(j.Array)
	if !target_ok || len(targets) > 32 {
		return null(), "ASSESSMENT_INVALID"
	}

	for target in targets {
		if !has_exact_object_fields(target, []string{"path", "sha256"}) ||
		   !path_valid(str(get(target, "path"))) ||
		   !hex_valid(str(get(target, "sha256")), 64) {
			return null(), "ASSESSMENT_INVALID"
		}
	}

	evidence := get(value, "evidence")
	if _, evidence_ok := evidence.(j.Object);
	   !evidence_ok ||
	   !equal(get(evidence, "reference"), get(file, "reference")) ||
	   !equal(get(evidence, "current"), get(file, "current")) {
		return null(), "ASSESSMENT_EVIDENCE_INVALID"
	}

	if kind == "FIX" &&
	   (len(targets) == 0 || len(items(get(value, "checks"))) == 0 || len(items(get(value, "acceptance"))) == 0) {
		return null(), "FIX_PROOF_REQUIRED"
	}

	for target in targets {
		if !slice.contains(owner.targets, str(get(target, "path"))) {
			return null(), "ASSESSMENT_TARGET_INVALID"
		}
	}

	harmless := slice.contains(
		[]string{"BYTE_IDENTICAL", "LEXICALLY_EQUIVALENT", "JSON_NORMALIZED_EQUIVALENT", "ALREADY_IMPLEMENTED"},
		reason,
	)
	if (kind == "NO_ACTION") != harmless ||
	   (kind == "FIX") != (reason == "APPROVED_DICTIONARY_CONTRACT_GAP") ||
	   reason == "BYTE_IDENTICAL" && !equal(get(file, "reference"), get(file, "current")) {
		return null(), "ASSESSMENT_KIND_INVALID"
	}

	if kind == "NO_ACTION" || kind == "FIX" || reason == "LOCAL_DICTIONARY_CONTRACT_DRIFT" {
		if len(targets) != len(owner.targets) {
			return null(), "ASSESSMENT_TARGET_INVALID"
		}

		for target, i in targets {
			if str(get(target, "path")) != owner.targets[i] {
				return null(), "ASSESSMENT_TARGET_INVALID"
			}
		}
	}

	if reason == "ALREADY_IMPLEMENTED" &&
	   (owner.source != "baileys" ||
			   owner.path != "src/WABinary/constants.ts" ||
			   str(get(evidence, "local_table_matches")) != "current" ||
			   !json_boolean_equals(get(evidence, "server_compatibility_proven"), false)) {
		return null(), "ASSESSMENT_EVIDENCE_INVALID"
	}

	if kind == "FIX" || reason == "LOCAL_DICTIONARY_CONTRACT_DRIFT" {
		count, count_ok := integer(get(evidence, "changed_count"))
		table_count, table_ok := integer(get(evidence, "table_count"))
		changes := items(get(evidence, "changes"))
		indices := items(get(evidence, "changed_indices"))
		if owner.source != "baileys" ||
		   owner.path != "src/WABinary/constants.ts" ||
		   !table_ok ||
		   table_count != 236 ||
		   !json_boolean_equals(get(evidence, "outside_tokens_equal")) ||
		   str(get(evidence, "local_table_matches")) != "reference" ||
		   !json_boolean_equals(get(evidence, "server_compatibility_proven"), false) ||
		   !count_ok ||
		   count < 1 ||
		   count > 236 ||
		   i64(len(changes)) != min(count, 32) ||
		   !json_boolean_equals(get(evidence, "changes_truncated"), count > 32) ||
		   i64(len(indices)) != count {
			return null(), "FIX_PROOF_REQUIRED"
		}

		last: i64 = -1

		for index in indices {
			n, index_ok := integer(index)

			if !index_ok || n < 0 || n >= 236 || n <= last {
				return null(), "FIX_PROOF_REQUIRED"
			}

			last = n
		}

		for change, i in changes {
			n, index_ok := integer(get(change, "index"))
			wanted, _ := integer(indices[i])
			if !has_exact_object_fields(change, []string{"index", "old", "new", "old_sha256", "new_sha256"}) ||
			   !index_ok ||
			   n != wanted ||
			   !text_limit(get(change, "old"), 0, 128) ||
			   !text_limit(get(change, "new"), 0, 128) ||
			   !hex_valid(str(get(change, "old_sha256")), 64) ||
			   !hex_valid(str(get(change, "new_sha256")), 64) ||
			   equal(get(change, "old_sha256"), get(change, "new_sha256")) {
				return null(), "FIX_PROOF_REQUIRED"
			}
		}
	}

	if kind == "FIX" {
		proof := get(evidence, "approved_contract")
		if !has_required_and_allowed_fields(
			   proof,
			   []string{"path", "sha256", "target_table_sha256", "requirement", "basis", "trust_limit"},
			   []string{"fixture"},
		   ) ||
		   str(get(proof, "basis")) != "explicit_reviewed_requirement_and_owned_indexed_comparison" ||
		   !text_limit(get(proof, "trust_limit"), 1, 500) ||
		   str(get(evidence, "static_regression")) != "indexed_table_comparison" {
			return null(), "FIX_CONTRACT_REQUIRED"
		}

		for key in ([]string{"reference_table_sha256", "target_table_sha256", "local_table_sha256"}) {
			if !hex_valid(str(get(evidence, key)), 64) {
				return null(), "FIX_CONTRACT_REQUIRED"
			}
		}

		if !equal(get(proof, "target_table_sha256"), get(evidence, "target_table_sha256")) ||
		   !equal(get(evidence, "local_table_sha256"), get(evidence, "reference_table_sha256")) ||
		   equal(get(evidence, "target_table_sha256"), get(evidence, "reference_table_sha256")) {
			return null(), "FIX_CONTRACT_REQUIRED"
		}

		records := make([dynamic]Value, 0, 3)
		suffixes := make([dynamic]string, 0, 3)
		append(&records, proof, get(proof, "requirement"))
		append(&suffixes, ".json", ".md")

		if p, proof_ok := proof.(j.Object); proof_ok {
			if fixture, present := p["fixture"]; present {
				append(&records, fixture)
				append(&suffixes, "")
			}
		}

		for record, i in records {
			path := str(get(record, "path"))
			prefix := contract_directory(path) if i < 2 else "tests/"
			if !path_valid(path) ||
			   !strings.has_prefix(path, prefix) ||
			   suffixes[i] != "" && !strings.has_suffix(path, suffixes[i]) ||
			   !hex_valid(str(get(record, "sha256")), 64) {
				return null(), "FIX_CONTRACT_REQUIRED"
			}
		}

		if verify_contract && !validate_approved_contract(value, root) {
			return null(), "FIX_CONTRACT_INVALID"
		}
	}

	if encode(value) == "" {
		return null(), "ASSESSMENT_INVALID"
	}

	if len(encode(value)) > 16384 {
		return null(), "ASSESSMENT_TOO_LARGE"
	}

	return
}

findings :: proc(report: Value, root: string) -> (result: j.Array, failure: Failure) {
	changed: [dynamic]Item
	_, changed, failure = snapshot(report)

	if failure != nil {
		return nil, failure
	}

	for source in items(get(get(report, "observation"), "sources")) {
		for file in items(get(source, "files")) {
			if obj, ok := file.(j.Object); ok {
				if "assessment" in obj {
					validate_assessment(source, file, root) or_return
				}
			}
		}
	}

	result = make(j.Array)

	for item in changed {
		assessment := validate_assessment(item.source, item.file, root) or_return

		if str(get(assessment, "kind")) == "NO_ACTION" {
			continue
		}

		repo, path := str(get(item.source, "repository")), str(get(item.file, "path"))
		reference, current := get(item.file, "reference"), get(item.file, "current")
		append(
			&result,
			object(
				{"id", text(change_identity(repo, path, reference, current))},
				{"source", get(item.source, "name")},
				{"repository", text(repo)},
				{"path", text(path)},
				{"reference", reference},
				{"current", current},
				{"reference_commit", get(item.source, "reference_commit")},
				{"head_commit", get(item.source, "head_commit")},
				{"assessment", assessment},
			),
		)
	}

	return
}

concatenate_strings :: proc(parts: ..string) -> string {
	return strings.concatenate(parts)
}

find_manifest_source_for_path :: proc(repo, path: string) -> (Value, bool) {
	for source in items(get(default_manifest(), "sources")) {
		if str(get(source, "repository")) == repo {
			for p in items(get(source, "paths")) {
				if str(p) == path {
					return source, true
				}
			}
		}
	}

	return null(), false
}

machine_section :: proc(findings: j.Array, run: string) -> (body: string, failure: Failure) {
	markers := make(j.Array)

	for item in findings {
		append(&markers, text(concatenate_strings("owa-protocol-change:v2:", str(get(item, "id")))))
	}

	value := object({"schema", number(2)}, {"run", text(run)}, {"findings", findings}, {"markers", markers})

	body = concatenate_strings(BEGIN, "\n\n```json\n", encode(value), "\n```\n\n", END)

	if len(body) > MAX_REPORT {
		return "", "MACHINE_SECTION_TOO_LARGE"
	}

	return
}

v2_coverage :: proc(body: string, root: string) -> (result: Value, failure: Failure) {
	result = coverage_object()

	if len(body) > MAX_REPORT {
		return
	}

	starts, ends := 0, 0

	for line in strings.split(body, "\n") {
		if line == BEGIN {
			starts += 1
		}

		if line == END {
			ends += 1
		}
	}

	parsed, cursor := 0, 0; prefix := BEGIN + "\n\n```json\n"; suffix := "\n```\n\n" + END

	for cursor < len(body) {
		found := strings.index(body[cursor:], prefix)

		if found < 0 {
			break
		}

		begin := cursor + found + len(prefix)
		ending := strings.index(body[begin:], suffix)

		if ending < 0 {
			return object(), "LINEAR_V2_INVALID"
		}

		encoded := body[begin:begin + ending]
		cursor = begin + ending + len(suffix)
		parsed += 1
		value, parse_error := decode(transmute([]u8)encoded)
		schema, schema_ok := integer(get(value, "schema"))
		entries, entries_ok := get(value, "findings").(j.Array)
		if parse_error != "" ||
		   !has_exact_object_fields(value, []string{"schema", "run", "findings", "markers"}) ||
		   !schema_ok ||
		   schema != 2 ||
		   !is_project_actions_run_url(str(get(value, "run"))) ||
		   !entries_ok ||
		   len(entries) < 1 ||
		   len(entries) > 32 {
			return object(), "LINEAR_V2_INVALID"
		}

		markers := make(j.Array)
		seen := make(map[string]bool)

		for item in entries {
			if !has_exact_object_fields(
				item,
				[]string {
					"id",
					"source",
					"repository",
					"path",
					"reference",
					"current",
					"reference_commit",
					"head_commit",
					"assessment",
				},
			) {
				return object(), "LINEAR_V2_INVALID"
			}

			source, bound := find_manifest_source_for_path(str(get(item, "repository")), str(get(item, "path")))
			if !bound ||
			   !equal(get(item, "source"), get(source, "name")) ||
			   !equal(get(item, "reference_commit"), get(source, "reference_commit")) ||
			   !hex_valid(str(get(item, "head_commit")), 40) {
				return object(), "LINEAR_V2_INVALID"
			}

			reference, current := get(item, "reference"), get(item, "current")

			if validate_digest(reference) != nil || validate_digest(current) != nil || equal(reference, current) {
				return object(), "LINEAR_V2_INVALID"
			}

			identity := str(get(item, "id"))
			if identity != change_identity(str(get(item, "repository")), str(get(item, "path")), reference, current) ||
			   seen[identity] {
				return object(), "LINEAR_V2_INVALID"
			}

			assessment, assessment_error := validate_assessment(source, item, root, false)

			if assessment_error != nil || str(get(assessment, "kind")) == "NO_ACTION" {
				return object(), "LINEAR_V2_INVALID"
			}

			seen[identity] = true
			put(&result, identity, item)
			append(&markers, text(concatenate_strings("owa-protocol-change:v2:", identity)))
		}

		if !equal(markers, get(value, "markers")) {
			return object(), "LINEAR_V2_INVALID"
		}
	}

	if starts != parsed || ends != parsed {
		return object(), "LINEAR_V2_INVALID"
	}

	return
}

legacy_coverage :: proc(issue: Value) -> Value {
	body := str(get(issue, "description"))
	lines := strings.split(body, "\n")
	normalized := make([dynamic]string)

	for line in lines {
		clean := line

		if strings.has_prefix(line, "* ") {
			clean = concatenate_strings("- ", line[2:])
		} else if strings.has_prefix(line, "  * ") {
			clean = concatenate_strings("  - ", line[4:])
		}

		if strings.contains(clean, "(<https://github.com/") {
			clean = replace(replace(clean, "(<https://github.com/", "(https://github.com/"), ">)", ")")
		}

		if strings.has_prefix(clean, "Evidence: [https://github.com/dvrd/owa/actions/runs/") {
			closing := strings.index(clean, "](")

			if closing > 10 {
				url := clean[len("Evidence: ["):closing]

				if is_project_actions_run_url(url) && clean[closing:] == concatenate_strings("](", url, ")") {
					clean = concatenate_strings("Evidence: ", url)
				}
			}
		}

		append(&normalized, clean)
	}

	body = strings.join(normalized[:], "\n")
	marker := "owa-protocol-drift:v1:"
	fingerprint := ""
	marker_count, prose, evidence_count, snapshot_count := 0, 0, 0, 0

	for line in normalized {
		if strings.has_prefix(line, marker) && hex_valid(line[len(marker):], 64) {
			fingerprint = line[len(marker):]
			marker_count += 1
		}

		if line == "Review public upstream protocol changes detected by OWA. No automated agent or fix was run." {
			prose += 1
		}

		if strings.has_prefix(line, "Evidence: ") && is_project_actions_run_url(line[len("Evidence: "):]) {
			evidence_count += 1
		}
	}

	if marker_count != 1 ||
	   prose != 1 ||
	   evidence_count != 1 ||
	   str(get(issue, "id")) != stable_uuid(concatenate_strings(PROJECT, "/owa-protocol-review/v1/", fingerprint)) {
		return object()
	}

	for line in normalized {
		if line == concatenate_strings("Snapshot fingerprint: `", fingerprint, "`") {
			snapshot_count += 1
		}
	}

	if snapshot_count != 1 {
		return object()
	}

	heading := "## Monitored differences from reference\n\n"
	start := strings.index(body, heading)

	if start < 0 {
		return object()
	}

	tail := body[start + len(heading):]
	end := strings.index(tail, "\n## Human review and follow-up")

	if end < 0 {
		return object()
	}

	tail = strings.trim_space(tail[:end])
	result := coverage_object()
	heads := make(map[string]string)
	last := -1

	for len(tail) > 0 {
		entries := strings.split(tail, "\n")

		if len(entries) < 3 {
			return object()
		}

		first, links, hashes := entries[0], entries[1], entries[2]

		if !strings.has_prefix(first, "- ") || !strings.has_suffix(first, "`") {
			return object()
		}

		separator := strings.index(first, ": `"); if separator < 2 {
			return object()
		}

		name, path := first[2:separator], first[separator + 3:len(first) - 1]
		_, bound := owner_for(name, path)

		if !bound {
			return object()
		}

		repo, reference := repository(name), reference_commit(name)
		reference_link := concatenate_strings(
			"  - [reference](https://github.com/",
			repo,
			"/blob/",
			reference,
			"/",
			path,
			") / [observed](https://github.com/",
			repo,
			"/blob/",
		)

		if !strings.has_prefix(links, reference_link) || len(links) < len(reference_link) + 42 {
			return object()
		}

		remainder := links[len(reference_link):]
		head := remainder[:40]

		if !hex_valid(head, 40) || remainder[40:] != concatenate_strings("/", path, ")") || heads[repo] != "" && heads[repo] != head {
			return object()
		}

		index := -1

		for owner, i in OWNERS {
			if owner.source == name && owner.path == path {
				index = i
			}
		}

		if index <= last {
			return object()
		}

		last = index; heads[repo] = head
		if !strings.has_prefix(hashes, "  - SHA256: `") || !strings.has_suffix(hashes, "`") {
			return object()
		}

		parts := strings.split(hashes[len("  - SHA256: `"):len(hashes) - 1], "` → `")
		if len(parts) != 2 ||
		   parts[0] != "None" && !hex_valid(parts[0], 64) ||
		   parts[1] != "None" && !hex_valid(parts[1], 64) ||
		   parts[0] == parts[1] {
			return object()
		}

		ref := object(
			{"present", boolean(parts[0] != "None")},
			{"sha256", text(parts[0]) if parts[0] != "None" else null()},
		)
		cur := object(
			{"present", boolean(parts[1] != "None")},
			{"sha256", text(parts[1]) if parts[1] != "None" else null()},
		)
		identity := change_identity(repo, path, ref, cur)

		if slice.contains(keys(result), identity) {
			return object()
		}

		put(
			&result,
			identity,
			object(
				{"id", text(identity)},
				{"source", text(name)},
				{"repository", text(repo)},
				{"path", text(path)},
				{"reference", ref},
				{"current", cur},
				{"reference_commit", text(reference)},
				{"head_commit", text(head)},
			),
		)
		consumed := len(first) + len(links) + len(hashes) + 2
		tail = strings.trim_space(tail[consumed:])
	}

	return result
}

issue_is_terminal :: proc(issue: Value) -> bool {
	return slice.contains([]string{"completed", "canceled", "duplicate"}, str(get(get(issue, "state"), "type")))
}

validate_issue :: proc(issue: Value) -> Failure {
	if !equal(get(get(issue, "project"), "id"), text(PROJECT)) ||
	   !text_limit(get(issue, "id"), 1, 100) ||
	   !text_limit(get(issue, "description"), 0, MAX_REPORT) ||
	   !text_limit(get(issue, "title"), 0, MAX_REPORT) ||
	   !slice.contains(keys(issue), "archivedAt") ||
	   !slice.contains(
			   []string{"triage", "backlog", "unstarted", "started", "completed", "canceled", "duplicate"},
			   str(get(get(issue, "state"), "type")),
		   ) {
		return "LINEAR_ISSUE_INVALID"
	}

	id := str(get(issue, "id")); digits := replace(id, "-", "")

	if !hex_valid(strings.to_lower(digits), 32) {
		return "LINEAR_ISSUE_INVALID"
	}

	identifier := str(get(issue, "identifier")); prefix := "OKAMI-"

	if !strings.has_prefix(identifier, prefix) || len(identifier) == len(prefix) {
		return "LINEAR_ISSUE_INVALID"
	}

	if strings.trim_left(identifier[len(prefix):], DECIMAL_DIGITS) != "" {
		return "LINEAR_ISSUE_INVALID"
	}

	url := str(get(issue, "url"))
	url_prefix := concatenate_strings("https://linear.app/devoured/issue/", identifier)

	if !strings.has_prefix(url, url_prefix) {
		return "LINEAR_ISSUE_INVALID"
	}

	if len(url) > len(url_prefix) {
		suffix := url[len(url_prefix):]
		if !strings.has_prefix(suffix, "/") ||
		   len(suffix) < 2 ||
		   !path_valid(suffix[1:]) ||
		   strings.contains(suffix[1:], "/") {
			return "LINEAR_ISSUE_INVALID"
		}
	}

	return nil
}

merge_coverage :: proc(target: ^Value, incoming: Value) {
	if values, ok := incoming.(j.Object); ok {
		for identity, item in values {
			if str(get(get(get(target^, identity), "assessment"), "kind")) != "FIX" {
				put(target, identity, item)
			}
		}
	}
}

issue_coverage :: proc(issue: Value, root: string) -> (result: Value, failure: Failure) {
	result = legacy_coverage(issue)
	current := v2_coverage(str(get(issue, "description")), root) or_return
	current_keys := keys(current)

	if len(current_keys) > 0 {
		kinds := make(map[string]bool); ids := make(j.Array)

		for id in current_keys {
			kinds[str(get(get(get(current, id), "assessment"), "kind"))] = true
			append(&ids, text(id))
		}

		if len(kinds) != 1 {
			return null(), "LINEAR_V2_BINDING_MISMATCH"
		}

		kind := ""; for k in kinds {kind = k}

		if stable_id("owa-protocol-review/v2", array(text(kind), ids)) != str(get(issue, "id")) {
			return null(), "LINEAR_V2_BINDING_MISMATCH"
		}

		merge_coverage(&result, current)
	}

	return
}

comment_identity :: proc(issue_id: string, entries: j.Array) -> string {
	rows := make([dynamic]string)

	for item in entries {
		append(
			&rows,
			encode(
				array(
					get(item, "id"),
					get(get(item, "assessment"), "kind"),
					get(get(item, "assessment"), "reason"),
					text("assessment-v1"),
				),
			),
		)
	}

	slice.sort(rows[:]); values := make(j.Array)
	for row in rows {v, _ := decode(transmute([]u8)row); append(&values, v)}

	return stable_id("owa-protocol-review-comment/v2", array(text(issue_id), values))
}

fetch_linear_page :: proc(
	api: ^API,
	query: string,
	cursor: Value,
	issue_id := "",
) -> (
	nodes: j.Array,
	info: Value,
	failure: Failure,
) {
	variables := object({"after", cursor})

	if issue_id != "" {
		put(&variables, "id", text(issue_id))
	}

	response := api_call(api, query, variables) or_return; data := get(response, "issues")
	if issue_id != "" {
		issue := get(response, "issue")

		if str(get(issue, "id")) != issue_id || str(get(get(issue, "project"), "id")) != PROJECT {
			return nil, null(), "LINEAR_BINDING_MISMATCH"
		}

		data = get(issue, "comments")
	}

	parsed, nodes_ok := get(data, "nodes").(j.Array); info = get(data, "pageInfo")
	_, more_ok := get(info, "hasNextPage").(j.Boolean)
	if !nodes_ok || !more_ok {
		return nil, null(), "LINEAR_PAGINATION_INVALID"
	}

	return parsed, info, nil
}

advance_linear_cursor :: proc(info: Value, cursor: ^Value, seen: ^map[string]bool) -> (more: bool, failure: Failure) {
	if !json_boolean_equals(get(info, "hasNextPage")) {
		return false, nil
	}

	next := str(get(info, "endCursor"))

	if next == "" || len(next) > 512 || seen^[next] {
		return false, "LINEAR_PAGINATION_INVALID"
	}

	seen^[next] = true; cursor^ = text(next); return true, nil
}

comments :: proc(api: ^API, issue: ^Value, root: string) -> (result: Value, failure: Failure) {
	result = coverage_object(); scopes := make(map[string]bool, 64)
	seen := make(map[string]bool, 4096); cursors := make(map[string]bool, 64); cursor := null()

	for {
		entries, info := fetch_linear_page(api, COMMENTS, cursor, str(get(issue^, "id"))) or_return

		for comment in entries {
			id := str(get(comment, "id"))

			if id == "" || seen[id] || !text_limit(get(comment, "body"), 0, MAX_REPORT) {
				return null(), "LINEAR_COMMENTS_INVALID"
			}

			seen[id] = true
			for line in strings.split(str(get(comment, "body")), "\n") {
				if strings.has_prefix(line, SCOPE_PREFIX) {
					scope := line[len(SCOPE_PREFIX):]

					if scope != "baileys" && scope != "whatsmeow" {
						return null(), "LINEAR_REVIEW_SCOPE_INVALID"
					}

					scopes[scope] = true
				}
			}

			if len(scopes) > 1 {
				return null(), "LINEAR_REVIEW_SCOPE_CONFLICT"
			}

			found := v2_coverage(str(get(comment, "body")), root) or_return
			found_values := make(j.Array)
			for key in keys(found) {append(&found_values, get(found, key))}

			if len(found_values) > 0 && id != comment_identity(str(get(issue^, "id")), found_values) {
				return null(), "LINEAR_V2_BINDING_MISMATCH"
			}

			merge_coverage(&result, found)
		}

		more := advance_linear_cursor(info, &cursor, &cursors) or_return; if !more {
			break
		}
	}

	scope := null(); for key in scopes {scope = text(key)}

	put(issue, "_review_scope", scope)

	return
}

scan :: proc(api: ^API, root: string) -> (issues: j.Array, covered: Value, failure: Failure) {
	issues = make(j.Array); covered = coverage_object(); seen := make(map[string]bool, 256)
	cursors := make(map[string]bool, 64); cursor := null()

	for {
		nodes, info := fetch_linear_page(api, SCAN, cursor) or_return

		for raw in nodes {
			validate_issue(raw) or_return
			issue := j.clone_value(raw); id := str(get(issue, "id"))

			if seen[id] || len(issues) >= 200 {
				return nil, null(), "LINEAR_SCAN_BOUND"
			}

			seen[id] = true
			own := issue_coverage(issue, root) or_return
			additional := comments(api, &issue, root) or_return
			merge_coverage(&own, additional); put(&issue, "_coverage", own)
			merge_coverage(&covered, own); append(&issues, issue)
		}

		more := advance_linear_cursor(info, &cursor, &cursors) or_return; if !more {
			break
		}
	}

	return
}

fetch_current_issue :: proc(api: ^API, id: string) -> (value: Value, failure: Failure) {
	response := api_call(api, LOOKUP, object({"ids", array(text(id))})) or_return
	nodes := items(get(get(response, "issues"), "nodes")); if len(nodes) == 0 {
		return null(), nil
	}

	if len(nodes) != 1 || str(get(nodes[0], "id")) != id {
		return null(), "LINEAR_LOOKUP_INVALID"
	}

	validate_issue(nodes[0]) or_return; return j.clone_value(nodes[0]), nil
}

public_issue :: proc(issue: Value) -> Value {
	return object({"identifier", get(issue, "identifier")}, {"url", get(issue, "url")})
}

readable_findings :: proc(entries: j.Array) -> []string {
	lines := make([dynamic]string)

	for item in entries {
		a := get(item, "assessment")
		append(
			&lines,
			fmt.aprintf("- %s: `%s` — %s", str(get(item, "source")), str(get(item, "path")), str(get(a, "summary"))),
		)
		evidence := get(a, "evidence"); question := str(get(evidence, "question"))

		if question != "" {
			append(&lines, concatenate_strings("  - Question: ", question))
		}

		for check in items(get(a, "checks")) {append(&lines, concatenate_strings("  - Check: ", str(check)))}

		for accept in items(get(a, "acceptance")) {append(&lines, concatenate_strings("  - Accept: ", str(accept)))}

		for target in items(
			get(a, "local_targets"),
		) {append(&lines, concatenate_strings("  - Local target: `", str(get(target, "path")), "` SHA256 `", str(get(target, "sha256")), "`"))}

		if e, ok := evidence.(j.Object); ok {
			if _, present := e["changed_indices"]; present {
				n, _ := integer(get(evidence, "changed_count"))
				append(
					&lines,
					fmt.aprintf(
						"  - Complete changed indices (%d): %s",
						n,
						encode(get(evidence, "changed_indices"), true),
					),
				)
				append(
					&lines,
					concatenate_strings(
						"  - Excerpts are capped at32; truncated: ",
						"true" if json_boolean_equals(get(evidence, "changes_truncated")) else "false",
					),
				)
			}
		}

		append(
			&lines,
			concatenate_strings(
				"  - Immutable reference: https://github.com/",
				str(get(item, "repository")),
				"/blob/",
				str(get(item, "reference_commit")),
				"/",
				str(get(item, "path")),
			),
		)
		append(
			&lines,
			concatenate_strings(
				"  - Immutable observed: https://github.com/",
				str(get(item, "repository")),
				"/blob/",
				str(get(item, "head_commit")),
				"/",
				str(get(item, "path")),
			),
		)
	}

	return lines[:]
}

payload_for :: proc(entries: j.Array, run: string) -> (result: Value, failure: Failure) {
	first := entries[0]; a := get(first, "assessment"); kind := str(get(a, "kind"))
	ids := make([dynamic]string)
	for item in entries {append(&ids, str(get(item, "id")))}

	slice.sort(ids[:])
	id := stable_id("owa-protocol-review/v2", array(text(kind), string_array(ids[:])))
	summary := str(get(a, "summary")); reason := str(get(a, "reason"))
	title :=
		concatenate_strings("OWA: FIX ", unicode_prefix(summary, 150)) if \
			kind == "FIX" else \
			concatenate_strings(
				"OWA: SPIKE Does ",
				str(get(first, "source")),
				" drift affect our implementation? (",
				unicode_prefix(reason, 60),
				")",
			)
	lines := make([dynamic]string)
	append(
		&lines,
		summary,
		"",
		concatenate_strings("## ", "Implementation evidence" if kind == "FIX" else "Question and investigation checklist"),
		"",
	)
	append(&lines, ..readable_findings(entries))
	section := machine_section(entries, run) or_return
	append(
		&lines,
		"",
		"Hash drift alone is not a compatibility decision. No automated source adoption, runtime version change or completed review is implied.",
		"",
		section,
	)
	result = object(
		{"id", text(id)},
		{"title", text(title)},
		{"description", text(strings.join(lines[:], "\n"))},
		{"projectId", text(PROJECT)},
		{"teamId", text(TEAM)},
		{"stateId", text(READY if kind == "FIX" else BACKLOG)},
		{"priority", number(2 if kind == "FIX" else 3)},
	)

	if len(encode(result)) > MAX_REPORT {
		return null(), "LINEAR_PAYLOAD_BOUND"
	}

	return
}

lookup_comment :: proc(api: ^API, comment_id, issue_id, body, root: string) -> (found: bool, failure: Failure) {
	expected := v2_coverage(body, root) or_return

	if len(keys(expected)) == 0 || len(body) > MAX_REPORT {
		return false, "LINEAR_COMMENT_BINDING_MISMATCH"
	}

	response := api_call(api, COMMENT_LOOKUP, object({"id", text(comment_id)})) or_return
	nodes := items(get(get(response, "comments"), "nodes")); if len(nodes) == 0 {
		return false, nil
	}

	if len(nodes) != 1 {
		return false, "LINEAR_COMMENT_BINDING_MISMATCH"
	}

	value := nodes[0]; actual, parse_error := v2_coverage(str(get(value, "body")), root)
	if parse_error != nil ||
	   str(get(value, "id")) != comment_id ||
	   str(get(get(value, "issue"), "id")) != issue_id ||
	   str(get(get(get(value, "issue"), "project"), "id")) != PROJECT ||
	   !equal(expected, actual) {
		return false, "LINEAR_COMMENT_BINDING_MISMATCH"
	}

	return true, nil
}

append_findings :: proc(
	api: ^API,
	issue: Value,
	entries: j.Array,
	run, root: string,
	promote := false,
) -> (
	result: Value,
	failure: Failure,
) {
	current := fetch_current_issue(api, str(get(issue, "id"))) or_return
	if _, is_null := current.(j.Null); is_null || !equal(get(current, "archivedAt"), null()) || issue_is_terminal(current) {
		return null(), nil
	}

	covered := issue_coverage(current, root) or_return
	additional := comments(api, &current, root) or_return; merge_coverage(&covered, additional)
	scope := str(get(current, "_review_scope"))
	if scope != "" && scope != str(get(entries[0], "source")) {
		return null(), nil
	}

	pending := make(j.Array)
	for item in entries {
		existing := get(covered, str(get(item, "id")))
		if _, missing := existing.(j.Null);
		   missing || promote && str(get(get(existing, "assessment"), "kind")) != "FIX" {
			append(&pending, item)
		}
	}

	result = public_issue(current)
	if len(pending) == 0 {
		put(&result, "status", text("EXISTING")); return
	}

	heading :=
		"## FIX readiness: exact proof and acceptance" if \
			promote else \
			"## SPIKE: new evidence; investigation remains open"
	section := machine_section(pending, run) or_return
	body := concatenate_strings(heading, "\n\n", strings.join(readable_findings(pending), "\n"), "\n\n", section)
	if len(body) > MAX_REPORT {
		return null(), "LINEAR_PAYLOAD_BOUND"
	}

	cid := comment_identity(str(get(current, "id")), pending)
	exists := lookup_comment(api, cid, str(get(current, "id")), body, root) or_return
	if exists {
		put(&result, "status", text("EXISTING")); return
	}

	response, mutation_error := api_call(
		api,
		COMMENT_CREATE,
		object(
			{
				"input",
				object(
					{"id", text(cid)},
					{"issueId", get(current, "id")},
					{"body", text(body)},
					{"doNotSubscribeToIssue", boolean(true)},
				),
			},
		),
	)
	if mutation_error == nil && !json_boolean_equals(get(get(response, "commentCreate"), "success")) {
		mutation_error = "LINEAR_COMMENT_UNCONFIRMED"
	}

	confirmed := lookup_comment(api, cid, str(get(current, "id")), body, root) or_return
	if !confirmed {
		if mutation_error == Failure("LINEAR_API_REJECTED") {
			return null(), mutation_error
		}

		return null(), "LINEAR_COMMENT_OUTCOME_UNKNOWN"
	}

	put(&result, "status", text("UPDATED")); ready := make(j.Array)
	if promote {
		for item in pending {append(&ready, get(item, "id"))}
	}

	put(&result, "ready_findings", ready); return
}

create_findings :: proc(api: ^API, entries: j.Array, run, root: string) -> (result: Value, failure: Failure) {
	payload := payload_for(entries, run) or_return; id := str(get(payload, "id"))
	current := fetch_current_issue(api, id) or_return

	if _, missing := current.(j.Null); !missing {
		coverage := v2_coverage(str(get(current, "description")), root) or_return

		for item in entries {
			if !slice.contains(keys(coverage), str(get(item, "id"))) {
				return null(), "LINEAR_BINDING_MISMATCH"
			}
		}

		result = public_issue(current); put(&result, "status", text("EXISTING")); return
	}

	response, mutation_error := api_call(api, CREATE, object({"input", payload}))

	if mutation_error == nil && !json_boolean_equals(get(get(response, "issueCreate"), "success")) {
		mutation_error = "LINEAR_CREATE_UNCONFIRMED"
	}

	current = fetch_current_issue(api, id) or_return

	if _, missing := current.(j.Null); missing {
		if mutation_error == Failure("LINEAR_API_REJECTED") {
			return null(), mutation_error
		}

		return null(), "LINEAR_CREATE_OUTCOME_UNKNOWN"
	}

	coverage := v2_coverage(str(get(current, "description")), root) or_return

	for item in entries {
		if !slice.contains(keys(coverage), str(get(item, "id"))) {
			return null(), "LINEAR_BINDING_MISMATCH"
		}
	}

	result = public_issue(current)
	put(&result, "status", text("CREATED" if mutation_error == nil else "EXISTING")); return
}

sort_by_id :: proc(values: j.Array) {
	slice.stable_sort_by(values[:], proc(a, b: Value) -> bool {
		return str(get(a, "id")) < str(get(b, "id"))
	})
}

sync_review_findings :: proc(report: Value, run, root: string, api: ^API) -> (result: Value, failure: Failure) {
	status := str(get(report, "status"))

	if status != "REVIEW_REQUIRED" && status != "NO_MONITORED_DRIFT" {
		return null(), "SCAN_NOT_SUCCESSFUL"
	}

	if !is_project_actions_run_url(run) {
		return null(), "RUN_URL_INVALID"
	}

	entries := findings(report, root) or_return

	if status == "NO_MONITORED_DRIFT" || len(entries) == 0 {
		return object({"status", text("NO_REVIEW_NEEDED")}, {"compatibility_approved", boolean(false)}), nil
	}

	if api.started == (time.Tick{}) {
		api.started = time.tick_now()
	}

	issues, covered := scan(api, root) or_return
	results, pending := make(j.Array), make(j.Array)

	for item in entries {
		identity := str(get(item, "id")); old := get(covered, identity)

		if _, missing := old.(j.Null); missing {
			append(&pending, item); continue
		}

		if str(get(get(item, "assessment"), "kind")) != "FIX" || str(get(get(old, "assessment"), "kind")) == "FIX" {
			continue
		}

		owners := make(j.Array); closed := false

		for issue in issues {
			if !slice.contains(keys(get(issue, "_coverage")), identity) {
				continue
			}

			append(&owners, issue)

			if issue_is_terminal(issue) || !equal(get(issue, "archivedAt"), null()) {
				closed = true
			}
		}

		if closed || len(owners) == 0 {
			continue
		}

		sort_by_id(owners)
		updated := append_findings(api, owners[0], array(item).(j.Array), run, root, true) or_return

		if _, missing := updated.(j.Null); !missing {
			append(&results, updated)
		}
	}

	if len(pending) == 0 && len(results) == 0 {
		return object({"status", text("EXISTING")}, {"compatibility_approved", boolean(false)}), nil
	}

	groups := make(map[string]j.Array)

	for item in pending {
		kind := str(get(get(item, "assessment"), "kind"))
		key := concatenate_strings(kind, "/", str(get(item, "source")) if kind == "SPIKE" else str(get(item, "id")))
		group := groups[key]; append(&group, item); groups[key] = group
	}

	group_keys, err := slice.map_keys(groups)
	assert(err == nil)
	slice.sort(group_keys)

	for key in group_keys {
		group := groups[key]; kind := str(get(get(group[0], "assessment"), "kind"))
		source := str(get(group[0], "source")); related := make(j.Array)

		for issue in issues {
			if issue_is_terminal(issue) || !equal(get(issue, "archivedAt"), null()) {
				continue
			}

			scope := str(get(issue, "_review_scope")); if scope != "" && scope != source {
				continue
			}

			for identity in keys(get(issue, "_coverage")) {
				finding := get(get(issue, "_coverage"), identity)

				if str(get(finding, "source")) == source && str(get(get(finding, "assessment"), "kind")) != "FIX" {
					append(&related, issue); break
				}
			}
		}

		result_item := null()

		if kind == "SPIKE" && len(related) > 0 {
			sort_by_id(related)
			result_item = append_findings(api, related[0], group, run, root) or_return
		}

		if _, missing := result_item.(j.Null); missing {
			result_item = create_findings(api, group, run, root) or_return
		}

		append(&results, result_item)
	}

	overall := "EXISTING"

	for item in results {
		if str(get(item, "status")) == "CREATED" {
			overall = "CREATED"
		}
	}

	for item in results {
		if str(get(item, "status")) == "UPDATED" {
			overall = "UPDATED"
		}
	}

	result = public_issue(results[0]); put(&result, "status", text(overall))
	put(&result, "issues", results); put(&result, "compatibility_approved", boolean(false))

	if len(encode(result)) > MAX_REPORT {
		return null(), "TRACKING_OUTPUT_BOUND"
	}

	return
}

build_review_ticket :: proc(report: Value, run, root: string) -> (id, marker: string, payload: Value, failure: Failure) {
	if !is_project_actions_run_url(run) {
		return "", "", null(), "RUN_URL_INVALID"
	}

	entries := findings(report, root) or_return

	if len(entries) == 0 {
		return "", "", null(), "NO_FINDINGS"
	}

	payload = payload_for(entries, run) or_return

	return str(get(payload, "id")), concatenate_strings("owa-protocol-change:v2:", str(get(entries[0], "id"))), payload, nil
}

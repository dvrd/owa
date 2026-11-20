# Development and operations tools

[Catalog index](README.md) · [Name changes](renames.md)

130 entries across 7 source files. Select a function to open its declaration.

| Source file | Functions |
|---|---:|
| [tools/protocol_watch/cmd/main.odin](#file-tools-protocol-watch-cmd-main-odin) | 8 |
| [tools/protocol_watch/release.odin](#file-tools-protocol-watch-release-odin) | 4 |
| [tools/protocol_watch/schedule.odin](#file-tools-protocol-watch-schedule-odin) | 16 |
| [tools/protocol_watch/tracker.odin](#file-tools-protocol-watch-tracker-odin) | 32 |
| [tools/protocol_watch/triage.odin](#file-tools-protocol-watch-triage-odin) | 19 |
| [tools/protocol_watch/value.odin](#file-tools-protocol-watch-value-odin) | 36 |
| [tools/protocol_watch/watch.odin](#file-tools-protocol-watch-watch-odin) | 15 |

<a id="file-tools-protocol-watch-cmd-main-odin"></a>

## tools/protocol_watch/cmd/main.odin

| Function | Behavior |
|---|---|
| [`read_json`](../../tools/protocol_watch/cmd/main.odin#L12) | Read and decode a bounded JSON input file. |
| [`arg`](../../tools/protocol_watch/cmd/main.odin#L26) | Get a named CLI option or its fallback value. |
| [`parse_option_pairs`](../../tools/protocol_watch/cmd/main.odin#L31) | Parse unique option/value pairs into a JSON object. |
| [`load_source_manifest`](../../tools/protocol_watch/cmd/main.odin#L46) | Load the configured or default upstream manifest. |
| [`public_scan`](../../tools/protocol_watch/cmd/main.odin#L61) | Run the release scan against the supplied manifest and state directory. |
| [`append_to_env_named_file`](../../tools/protocol_watch/cmd/main.odin#L78) | Append output to the file named by a CI environment variable. |
| [`execute`](../../tools/protocol_watch/cmd/main.odin#L88) | Validate command options and dispatch the requested watcher operation. |
| [`main`](../../tools/protocol_watch/cmd/main.odin#L252) | Run the protocol-watch CLI and emit its machine-readable result. |

<a id="file-tools-protocol-watch-release-odin"></a>

## tools/protocol_watch/release.odin

| Function | Behavior |
|---|---|
| [`hash_candidate_source_files`](../../tools/protocol_watch/release.odin#L7) | Hash the candidate's Odin source set and build its file manifest. |
| [`check_evidence_file_digest`](../../tools/protocol_watch/release.odin#L29) | Verify a release check's recorded digest against its evidence file. |
| [`evaluate`](../../tools/protocol_watch/release.odin#L58) | Evaluate release gates from the candidate source, checks and evidence. |
| [`ci_prepare`](../../tools/protocol_watch/release.odin#L115) | Run the protocol scan under lock and prepare the CI promotion result. |

<a id="file-tools-protocol-watch-schedule-odin"></a>

## tools/protocol_watch/schedule.odin

| Function | Behavior |
|---|---|
| [`validate_result`](../../tools/protocol_watch/schedule.odin#L18) | Validate the review agent's structured result. |
| [`build_review_agent_argv`](../../tools/protocol_watch/schedule.odin#L43) | Build the argument vector for the read-only review agent. |
| [`agent_environment`](../../tools/protocol_watch/schedule.odin#L59) | Construct the allowlisted child environment for the agent. |
| [`capture`](../../tools/protocol_watch/schedule.odin#L70) | Run a child process with bounded input, output and execution time. |
| [`agent_run`](../../tools/protocol_watch/schedule.odin#L263) | Invoke the review agent and decode its validated result. |
| [`watch_capture`](../../tools/protocol_watch/schedule.odin#L276) | Execute a watch command and validate its returned status. |
| [`open_private_watch_report`](../../tools/protocol_watch/schedule.odin#L293) | Open a private report file and validate its metadata. |
| [`watch_run`](../../tools/protocol_watch/schedule.odin#L304) | Run the watcher and verify that it produced a fresh report. |
| [`schedule_run`](../../tools/protocol_watch/schedule.odin#L388) | Coordinate one scheduled protocol review under lock and budget. |
| [`default_watch_run`](../../tools/protocol_watch/schedule.odin#L440) | Invoke the standard watcher for a scheduled run. |
| [`schedule_review`](../../tools/protocol_watch/schedule.odin#L443) | Interpret a watch result and request a review when the report requires one. |
| [`library_root`](../../tools/protocol_watch/schedule.odin#L493) | Use the configured WhatsApp checkout or resolve the current working directory. |
| [`xml_quote`](../../tools/protocol_watch/schedule.odin#L499) | Escape text for an XML property list. |
| [`plist`](../../tools/protocol_watch/schedule.odin#L506) | Build the launchd property list for scheduled review. |
| [`write_plist`](../../tools/protocol_watch/schedule.odin#L558) | Write the validated schedule property list to local state. |
| [`canonical_path`](../../tools/protocol_watch/schedule.odin#L581) | Resolve a path to its canonical filesystem location. |

<a id="file-tools-protocol-watch-tracker-odin"></a>

## tools/protocol_watch/tracker.odin

| Function | Behavior |
|---|---|
| [`api_call`](../../tools/protocol_watch/tracker.odin#L50) | Issue a bounded Linear API request under the scan deadline. |
| [`manifest_read`](../../tools/protocol_watch/tracker.odin#L76) | Decode and validate the monitored-source manifest. |
| [`default_manifest`](../../tools/protocol_watch/tracker.odin#L123) | Read the built-in default source manifest. |
| [`validate_digest`](../../tools/protocol_watch/tracker.odin#L129) | Check the schema and content of a monitored file digest. |
| [`snapshot`](../../tools/protocol_watch/tracker.odin#L154) | Validate the source observation and build its changed-file snapshot. |
| [`bounded_strings`](../../tools/protocol_watch/tracker.odin#L236) | Check that a sequence of text values fits the specified bounds. |
| [`validate_assessment`](../../tools/protocol_watch/tracker.odin#L249) | Validate an assessment's source binding and evidence before tracking. |
| [`findings`](../../tools/protocol_watch/tracker.odin#L480) | Convert a validated report into individual review findings. |
| [`concatenate_strings`](../../tools/protocol_watch/tracker.odin#L527) | Concatenate string fragments. |
| [`find_manifest_source_for_path`](../../tools/protocol_watch/tracker.odin#L530) | Find the manifest source that owns a repository path. |
| [`machine_section`](../../tools/protocol_watch/tracker.odin#L543) | Encode the machine-readable section of a review issue or comment. |
| [`v2_coverage`](../../tools/protocol_watch/tracker.odin#L557) | Decode version-two coverage and validate its finding identities. |
| [`legacy_coverage`](../../tools/protocol_watch/tracker.odin#L666) | Recover covered findings from an older issue description. |
| [`issue_is_terminal`](../../tools/protocol_watch/tracker.odin#L856) | Check whether a Linear issue is in a terminal state. |
| [`validate_issue`](../../tools/protocol_watch/tracker.odin#L859) | Check the issue's project, required fields and supported state. |
| [`merge_coverage`](../../tools/protocol_watch/tracker.odin#L907) | Merge covered findings while preserving their assessment semantics. |
| [`issue_coverage`](../../tools/protocol_watch/tracker.odin#L916) | Combine the issue's legacy and current coverage records. |
| [`comment_identity`](../../tools/protocol_watch/tracker.odin#L944) | Calculate the stable identity of a proposed review comment. |
| [`fetch_linear_page`](../../tools/protocol_watch/tracker.odin#L966) | Fetch a bound page of Linear issues or comments. |
| [`advance_linear_cursor`](../../tools/protocol_watch/tracker.odin#L995) | Validate the next cursor and advance paginated scanning. |
| [`comments`](../../tools/protocol_watch/tracker.odin#L1008) | Read issue comments and accumulate their covered findings. |
| [`scan`](../../tools/protocol_watch/tracker.odin#L1055) | Scan eligible project issues and collect existing coverage. |
| [`fetch_current_issue`](../../tools/protocol_watch/tracker.odin#L1082) | Fetch and validate an issue by its exact ID immediately before use. |
| [`public_issue`](../../tools/protocol_watch/tracker.odin#L1094) | Return the issue identifier and URL suitable for public output. |
| [`readable_findings`](../../tools/protocol_watch/tracker.odin#L1097) | Format findings for the human-readable review body. |
| [`payload_for`](../../tools/protocol_watch/tracker.odin#L1165) | Build a bounded, identifiable issue or comment payload. |
| [`lookup_comment`](../../tools/protocol_watch/tracker.odin#L1212) | Find an existing comment and validate its identity and issue binding. |
| [`append_findings`](../../tools/protocol_watch/tracker.odin#L1239) | Append uncovered findings to an eligible issue and verify the result. |
| [`create_findings`](../../tools/protocol_watch/tracker.odin#L1315) | Create or recover the review issue for a group of findings. |
| [`sort_by_id`](../../tools/protocol_watch/tracker.odin#L1356) | Sort the findings by stable ID. |
| [`sync_review_findings`](../../tools/protocol_watch/tracker.odin#L1361) | Reconcile a protocol report with existing review issues and comments. |
| [`build_review_ticket`](../../tools/protocol_watch/tracker.odin#L1493) | Build the review title, body and machine payload for a report. |

<a id="file-tools-protocol-watch-triage-odin"></a>

## tools/protocol_watch/triage.odin

| Function | Behavior |
|---|---|
| [`owner_for`](../../tools/protocol_watch/triage.odin#L209) | Look up the local implementation and tests mapped to an upstream file. |
| [`repository`](../../tools/protocol_watch/triage.odin#L218) | Resolve a configured source name to its repository. |
| [`reference_commit`](../../tools/protocol_watch/triage.odin#L225) | Return the pinned comparison commit for a source. |
| [`identifier_start`](../../tools/protocol_watch/triage.odin#L236) | Check whether a byte can begin a source identifier. |
| [`is_identifier_continuation`](../../tools/protocol_watch/triage.odin#L239) | Check whether a byte can continue a source identifier. |
| [`sensitive_comment`](../../tools/protocol_watch/triage.odin#L242) | Recognize comments whose legal or tooling meaning affects classification. |
| [`find_numeric_token_end`](../../tools/protocol_watch/triage.odin#L295) | Locate the end of a numeric token. |
| [`lex`](../../tools/protocol_watch/triage.odin#L359) | Tokenize the supported source subset and retain significant comments. |
| [`literal_string`](../../tools/protocol_watch/triage.odin#L554) | Decode a supported string literal, rejecting ambiguous escapes. |
| [`extract_single_byte_token_table`](../../tools/protocol_watch/triage.odin#L626) | Extract the single-byte dictionary and surrounding tokens from a TypeScript or Odin token stream. |
| [`owner_root`](../../tools/protocol_watch/triage.odin#L721) | Find the local source root used to resolve mapped implementation files. |
| [`owned_bytes`](../../tools/protocol_watch/triage.odin#L730) | Read a repository-owned file while enforcing path and symlink restrictions. |
| [`record_bound`](../../tools/protocol_watch/triage.odin#L760) | Check a contract record against the current digest of its local file. |
| [`value_strings`](../../tools/protocol_watch/triage.odin#L775) | Construct a JSON string array from the supplied string slice. |
| [`finish_change_assessment`](../../tools/protocol_watch/triage.odin#L776) | Populate a triage assessment with its classification, reason and summary. |
| [`approved_metadata`](../../tools/protocol_watch/triage.odin#L781) | Load and verify the approved contract and its bound evidence. |
| [`validate_approved_contract`](../../tools/protocol_watch/triage.odin#L904) | Check that an assessment's contract matches the approved metadata. |
| [`assess_upstream_file_change`](../../tools/protocol_watch/triage.odin#L918) | Classify an upstream change against its reference, local ownership and evidence. |
| [`excerpt`](../../tools/protocol_watch/triage.odin#L1198) | Limit a source excerpt to a bounded readable representation. |

<a id="file-tools-protocol-watch-value-odin"></a>

## tools/protocol_watch/value.odin

| Function | Behavior |
|---|---|
| [`text`](../../tools/protocol_watch/value.odin#L35) | Construct a JSON string value. |
| [`number`](../../tools/protocol_watch/value.odin#L38) | Construct a JSON integer value. |
| [`boolean`](../../tools/protocol_watch/value.odin#L41) | Construct a JSON boolean value. |
| [`null`](../../tools/protocol_watch/value.odin#L44) | Construct the JSON null value. |
| [`object`](../../tools/protocol_watch/value.odin#L47) | Construct a JSON object from key/value pairs. |
| [`array`](../../tools/protocol_watch/value.odin#L56) | Construct a JSON array from supplied values. |
| [`string_array`](../../tools/protocol_watch/value.odin#L61) | Convert a string slice to a JSON array. |
| [`get`](../../tools/protocol_watch/value.odin#L70) | Look up a field of a JSON object. |
| [`put`](../../tools/protocol_watch/value.odin#L79) | Assign a field of a JSON object. |
| [`str`](../../tools/protocol_watch/value.odin#L85) | Extract a JSON string value. |
| [`integer`](../../tools/protocol_watch/value.odin#L90) | Extract a JSON integer and report success. |
| [`json_boolean_equals`](../../tools/protocol_watch/value.odin#L95) | Check whether a JSON boolean equals the expected value. |
| [`items`](../../tools/protocol_watch/value.odin#L100) | Return the members of a JSON array. |
| [`keys`](../../tools/protocol_watch/value.odin#L105) | Return the JSON object’s field names in sorted order. |
| [`has_exact_object_fields`](../../tools/protocol_watch/value.odin#L119) | Check that an object has exactly the expected fields. |
| [`hex_valid`](../../tools/protocol_watch/value.odin#L134) | Validate a fixed-length lowercase hexadecimal string. |
| [`path_valid`](../../tools/protocol_watch/value.odin#L141) | Validate a relative upstream repository path. |
| [`sha256`](../../tools/protocol_watch/value.odin#L158) | Return the SHA-256 digest of bytes as hexadecimal text. |
| [`digest`](../../tools/protocol_watch/value.odin#L163) | Build a JSON digest description for present or missing content. |
| [`quote`](../../tools/protocol_watch/value.odin#L170) | Write an escaped JSON string to the builder. |
| [`encode_value`](../../tools/protocol_watch/value.odin#L205) | Append the representation of one nested JSON value. |
| [`encode`](../../tools/protocol_watch/value.odin#L257) | Serialize a JSON value with the requested spacing. |
| [`equal`](../../tools/protocol_watch/value.odin#L266) | Compare two JSON values by their canonical representations. |
| [`decode`](../../tools/protocol_watch/value.odin#L269) | Parse bounded JSON and validate its token structure. |
| [`read_file`](../../tools/protocol_watch/value.odin#L323) | Read a file within a maximum byte count. |
| [`replace`](../../tools/protocol_watch/value.odin#L355) | Replace occurrences of a substring in text. |
| [`has_required_and_allowed_fields`](../../tools/protocol_watch/value.odin#L360) | Check required and optional JSON object fields. |
| [`join`](../../tools/protocol_watch/value.odin#L382) | Join two filesystem path components. |
| [`text_limit`](../../tools/protocol_watch/value.odin#L388) | Check that a JSON string's length falls within the given limits. |
| [`is_project_actions_run_url`](../../tools/protocol_watch/value.odin#L399) | Validate the exact GitHub Actions run URL for the monitored repository. |
| [`stable_uuid`](../../tools/protocol_watch/value.odin#L408) | Derive a deterministic UUID from a seed. |
| [`stable_id`](../../tools/protocol_watch/value.odin#L424) | Derive a stable identifier from a namespace and structured values. |
| [`change_identity`](../../tools/protocol_watch/value.odin#L427) | Derive a change ID from the repository, path and two file digests. |
| [`coverage_object`](../../tools/protocol_watch/value.odin#L440) | Create the initial coverage object for review findings. |
| [`parse_tokens`](../../tools/protocol_watch/value.odin#L443) | Recursively build a JSON value from bounded parser tokens. |
| [`unicode_prefix`](../../tools/protocol_watch/value.odin#L523) | Return a prefix containing at most the requested number of Unicode characters. |

<a id="file-tools-protocol-watch-watch-odin"></a>

## tools/protocol_watch/watch.odin

| Function | Behavior |
|---|---|
| [`native_flock`](../../tools/protocol_watch/watch.odin#L20) | Call the native advisory file lock operation. |
| [`transport`](../../tools/protocol_watch/watch.odin#L31) | Fetch upstream bytes through a bounded HTTP request. |
| [`linear_transport`](../../tools/protocol_watch/watch.odin#L74) | Send a bounded authenticated GraphQL request to Linear. |
| [`file_digest`](../../tools/protocol_watch/watch.odin#L135) | Describe a file's presence, length and SHA-256 digest. |
| [`version_decode`](../../tools/protocol_watch/watch.odin#L142) | Decode the version tuple from an upstream version document. |
| [`bounded_get`](../../tools/protocol_watch/watch.odin#L168) | Fetch a URL within the remaining observation deadline. |
| [`observe`](../../tools/protocol_watch/watch.odin#L177) | Collect current and reference file digests for monitored sources. |
| [`compare`](../../tools/protocol_watch/watch.odin#L286) | Compare observations to identify changed files. |
| [`is_private_state_file`](../../tools/protocol_watch/watch.odin#L322) | Check that a state file's stat data meets private ownership and mode requirements. |
| [`private_file`](../../tools/protocol_watch/watch.odin#L331) | Check an on-disk state file's type, ownership and permissions. |
| [`locked_state`](../../tools/protocol_watch/watch.odin#L338) | Open and exclusively lock the protocol watch state directory. |
| [`atomic_bytes`](../../tools/protocol_watch/watch.odin#L372) | Atomically replace a report or state file with the supplied bytes. |
| [`atomic_json`](../../tools/protocol_watch/watch.odin#L425) | Encode JSON and atomically persist it. |
| [`check_unlocked`](../../tools/protocol_watch/watch.odin#L432) | Collect, compare and persist observations while holding the state lock. |
| [`check_upstream_changes`](../../tools/protocol_watch/watch.odin#L462) | Lock the state directory, run the check and record its outcome. |

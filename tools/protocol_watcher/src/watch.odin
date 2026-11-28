package protocol_watch

import "core:slice"
import "core:c"
import j "core:encoding/json"
import "core:strings"
import p "core:sys/posix"
import "core:time"
import "shared:surf"

when ODIN_OS == .Darwin {
	foreign import libc "system:System"
} else {
	foreign import libc "system:c"
}

foreign libc {
	@(link_name = "flock")
	native_flock :: proc(fd: p.FD, operation: c.int) -> c.int ---
}

Fetch :: proc(data: rawptr, url: string, timeout: time.Duration) -> (bytes: []u8, present: bool, failure: Failure)
Network :: struct {
	linear_key, linear_url: string,
	allow_loopback:         bool,
}

transport :: proc(
	data: rawptr,
	url: string,
	timeout: time.Duration,
) -> (
	bytes: []u8,
	present: bool,
	failure: Failure,
) {
	config := surf.Config {
		max_body_size = MAX_BYTES,
		timeout       = timeout,
		max_redirects = 0,
	}

	if data != nil {
		config.allow_http = (cast(^Network)data).allow_loopback
	}

	response, error := surf.execute(
		surf.Request {
			method = .GET,
			url = url,
			headers = []surf.Header{{"User-Agent", "webtools-whatsapp-protocol-watch"}},
		},
		config,
	)
	if error.kind != .None {
		if error.kind == .Body_Oversized {
			return nil, false, "UPSTREAM_OVERSIZED"
		}

		return nil, false, "UPSTREAM_FETCH_FAILED"
	}
	defer surf.response_destroy(&response)

	if response.status >= 300 && response.status < 400 {
		return nil, false, "UPSTREAM_REDIRECT"
	}

	if response.status == 404 {
		return nil, false, nil
	}

	if response.status < 200 || response.status >= 300 {
		return nil, false, "UPSTREAM_HTTP_FAILED"
	}

	return slice.clone(response.body), true, nil
}

linear_transport :: proc(data: rawptr, query: string, variables: Value) -> (value: Value, failure: Failure) {
	network := cast(^Network)data

	if network == nil {
		return null(), "LINEAR_CREDENTIAL_MISSING"
	}

	key := strings.trim_space(network.linear_key)

	if len(key) == 0 || len(key) > 4096 || strings.contains_any(key, "\r\n") {
		return null(), "LINEAR_CREDENTIAL_MISSING"
	}

	endpoint := "https://api.linear.app/graphql"

	if network.allow_loopback && strings.has_prefix(network.linear_url, "http://127.0.0.1:") {
		endpoint = network.linear_url
	}

	response, error := surf.execute(
		surf.Request {
			method = .POST,
			url = endpoint,
			headers = []surf.Header{{"Authorization", key}, {"Content-Type", "application/json"}},
			body = transmute([]u8)encode(object({"query", text(query)}, {"variables", variables})),
		},
		surf.Config {
			max_body_size = MAX_REPORT,
			timeout = 20 * time.Second,
			max_redirects = 0,
			allow_http = network.allow_loopback,
		},
	)

	if error.kind != .None {
		return null(), "LINEAR_REQUEST_FAILED"
	}
	defer surf.response_destroy(&response)

	if response.status < 200 || response.status >= 300 {
		return null(), "LINEAR_REQUEST_FAILED"
	}

	decoded, parse_error := decode(response.body)

	if parse_error != "" {
		return null(), "LINEAR_REQUEST_FAILED"
	}

	if errors := get(decoded, "errors");
	   !equal(errors, null()) &&
	   !equal(errors, array()) &&
	   !equal(errors, object()) &&
	   !equal(errors, text("")) &&
	   !equal(errors, boolean(false)) &&
	   !equal(errors, number(0)) {
		return null(), "LINEAR_API_REJECTED"
	}

	if _, valid := get(decoded, "data").(j.Object); !valid {
		return null(), "LINEAR_REQUEST_FAILED"
	}

	return get(decoded, "data"), nil
}

file_digest :: proc(bytes: []u8, present: bool) -> Value {
	return object(
		{"present", boolean(present)},
		{"bytes", number(i64(len(bytes)) if present else 0)},
		{"sha256", text(sha256(bytes)) if present else null()},
	)
}

version_decode :: proc(bytes: []u8) -> (value: Value, failure: Failure) {
	decoded, error := decode(bytes)
	version := get(decoded, "version")
	entries, valid := version.(j.Array)

	if error != "" || !valid || len(entries) != 3 {
		return null(), "VERSION_FEED_INVALID"
	}

	for item in entries {
		n, ok := integer(item)

		if !ok || n < 0 || n > 0xffffffff {
			return null(), "VERSION_FEED_INVALID"
		}
	}

	return version, nil
}

Observation :: struct {
	fetch:                   Fetch,
	data:                    rawptr,
	started:                 time.Tick,
	budget:                  time.Duration,
	root, approved_contract: string,
}

bounded_get :: proc(config: ^Observation, url: string) -> ([]u8, bool, Failure) {
	remaining := config.budget - time.tick_diff(config.started, time.tick_now())

	if remaining <= 0 {
		return nil, false, "CHECK_BUDGET_EXPIRED"
	}

	return config.fetch(config.data, url, min(10 * time.Second, remaining))
}

observe :: proc(manifest: Value, config: Observation) -> (observed: Value, failure: Failure) {
	settings := config

	if settings.fetch == nil {
		settings.fetch = transport
	}

	if settings.budget == 0 {
		settings.budget = 180 * time.Second
	}

	if settings.started == {} {
		settings.started = time.tick_now()
	}

	sources := make(j.Array)
	observed = object(
		{"schema", number(1)},
		{"checked_at_unix", number(time.to_unix_seconds(time.now()))},
		{"sources", sources},
	)

	for source in items(get(manifest, "sources")) {
		repo := str(get(source, "repository"))
		head_bytes, present := bounded_get(
			&settings,
			concatenate_strings("https://api.github.com/repos/", repo, "/commits/", str(get(source, "branch"))),
		) or_return

		if !present {
			return null(), "UPSTREAM_HEAD_MISSING"
		}

		head_value, parse_error := decode(head_bytes); head := str(get(head_value, "sha"))
		if parse_error != "" || !hex_valid(head, 40) {
			return null(), "UPSTREAM_HEAD_INVALID"
		}

		files := make(j.Array)
		result := object(
			{"name", get(source, "name")},
			{"repository", get(source, "repository")},
			{"reference_commit", get(source, "reference_commit")},
			{"reference_scope", get(source, "reference_scope")},
			{"head_commit", text(head)},
			{"files", files},
		)

		for path_value in items(get(source, "paths")) {
			path := str(path_value)
			prefix := concatenate_strings("https://raw.githubusercontent.com/", repo, "/")
			reference_bytes, reference_present := bounded_get(
				&settings,
				concatenate_strings(prefix, str(get(source, "reference_commit")), "/", path),
			) or_return
			current_bytes, current_present := reference_bytes, reference_present

			if head != str(get(source, "reference_commit")) {
				current_bytes, current_present = bounded_get(&settings, concatenate_strings(prefix, head, "/", path)) or_return
			}

			reference, current :=
				file_digest(reference_bytes, reference_present), file_digest(current_bytes, current_present)

			if !reference_present && !current_present {
				return null(), "MONITORED_PATH_MISSING"
			}

			file := object(
				{"path", text(path)},
				{"reference", reference},
				{"current", current},
				{"changed_from_reference", boolean(!equal(reference, current))},
			)

			if !equal(reference, current) {
				assessment := assess_upstream_file_change(
					object({"name", get(source, "name")}, {"repository", text(repo)}),
					path,
					reference_bytes,
					current_bytes,
					reference_present,
					current_present,
					settings.root,
					settings.approved_contract,
				)
				put(&file, "assessment", assessment)
			}

			append(&files, file)

			if strings.has_suffix(path, "baileys-version.json") {
				a := version_decode(reference_bytes) or_return
				b := version_decode(current_bytes) or_return
				put(
					&result,
					"advertised_versions",
					object(
						{"reference", a},
						{"current", b},
						{"fallback_used", boolean(false)},
						{"auto_adopted", boolean(false)},
					),
				)
			}
		}

		put(&result, "files", files)
		append(&sources, result)
	}

	put(&observed, "sources", sources)

	return
}

compare :: proc(observed: Value, previous: Value = nil) -> Value {
	historical, changes := make(j.Array), make(j.Array)
	old := object()
	first := previous == nil || equal(previous, null())

	for source in items(get(previous, "sources")) {
		put(&old, str(get(source, "name")), source)
	}

	for source in items(get(observed, "sources")) {
		prior := object()

		for file in items(get(get(old, str(get(source, "name"))), "files")) {
			put(&prior, str(get(file, "path")), get(file, "current"))
		}

		for file in items(get(source, "files")) {
			key := text(concatenate_strings(str(get(source, "name")), ":", str(get(file, "path"))))

			if json_boolean_equals(get(file, "changed_from_reference")) {
				append(&historical, key)
			}

			if !first && !equal(get(prior, str(get(file, "path"))), get(file, "current")) {
				append(&changes, key)
			}
		}
	}

	return object(
		{"status", text("REVIEW_REQUIRED" if len(historical) > 0 || len(changes) > 0 else "NO_MONITORED_DRIFT")},
		{"first_observation", boolean(first)},
		{"historical_reference_drift", historical},
		{"changes_since_observation", changes},
		{"compatibility_approved", boolean(false)},
		{"runtime_version_changed", boolean(false)},
	)
}

is_private_state_file :: proc(info: p.stat_t) -> bool {
	return(
		p.S_ISREG(info.st_mode) &&
		info.st_uid == p.geteuid() &&
		(info.st_mode & p.mode_t{.IRGRP, .IWGRP, .IXGRP, .IROTH, .IWOTH, .IXOTH}) == {} &&
		info.st_nlink == 1 &&
		info.st_size <= MAX_REPORT \
	)
}

private_file :: proc(path: string) -> Failure {
	info: p.stat_t

	if p.lstat(strings.clone_to_cstring(path), &info) != {} || !is_private_state_file(info) {
		return "STATE_FILE_UNSAFE"
	}

	return nil
}

locked_state :: proc(path: string) -> (fd: p.FD, failure: Failure) {
	fd = -1

	if !strings.has_prefix(path, "/") {
		return -1, "STATE_PATH_INVALID"
	}

	name := strings.clone_to_cstring(path)
	_ = p.mkdir(name, {.IRUSR, .IWUSR, .IXUSR})

	info: p.stat_t
	if p.lstat(name, &info) != {} ||
	   !p.S_ISDIR(info.st_mode) ||
	   info.st_uid != p.geteuid() ||
	   (info.st_mode & p.mode_t{.IRGRP, .IWGRP, .IXGRP, .IROTH, .IWOTH, .IXOTH}) != {} {
		return -1, "STATE_DIRECTORY_UNSAFE"
	}

	lock := join(path, "watch.lock")
	fd = p.open(strings.clone_to_cstring(lock), {.CREAT, .RDWR, .NOFOLLOW, .CLOEXEC}, p.mode_t{.IRUSR, .IWUSR})

	if fd < 0 {
		return -1, "STATE_FILE_UNSAFE"
	}

	if p.fstat(fd, &info) != {} || !is_private_state_file(info) {
		p.close(fd)
		return -1, "STATE_FILE_UNSAFE"
	}

	if native_flock(fd, 2 | 4) != 0 {
		p.close(fd)
		return -1, "ALREADY_RUNNING"
	}

	return
}

atomic_bytes :: proc(path: string, data: []u8) -> Failure {
	if len(data) > MAX_REPORT {
		return "REPORT_TOO_LARGE"
	}

	if path == "" {
		return "LOCAL_STATE_FAILED"
	}

	slash := strings.last_index(path, "/")
	directory := "."

	if slash == 0 {
		directory = "/"
	} else if slash > 0 {
		directory = path[:slash]
	}

	name := strings.clone_to_cstring(join(directory, ".watch-XXXXXX"))
	fd := p.mkstemp(name)

	if fd < 0 {
		return "LOCAL_STATE_FAILED"
	}

	defer {
		p.close(fd)
		p.unlink(name)
	}

	offset := 0

	for offset < len(data) {
		n := p.write(fd, raw_data(data[offset:]), c.size_t(int(len(data)) - offset))

		if n <= 0 {
			return "LOCAL_STATE_FAILED"
		}

		offset += int(n)
	}

	if p.fsync(fd) != {} || p.rename(name, strings.clone_to_cstring(path)) != 0 {
		return "LOCAL_STATE_FAILED"
	}

	directory_fd := p.open(strings.clone_to_cstring(directory), {.CLOEXEC})

	if directory_fd < 0 {
		return "LOCAL_STATE_FAILED"
	}

	defer p.close(directory_fd)

	if p.fsync(directory_fd) != {} {
		return "LOCAL_STATE_FAILED"
	}

	return nil
}

atomic_json :: proc(path: string, value: Value) -> Failure {
	data := encode(value)

	if data == "" {
		return "JSON_INVALID"
	}

	return atomic_bytes(path, transmute([]u8)concatenate_strings(data, "\n"))
}

check_unlocked :: proc(manifest: Value, state: string, config: Observation) -> (result: Value, failure: Failure) {
	previous := null()
	previous_path := join(state, "observed.json")
	info: p.stat_t

	if p.lstat(strings.clone_to_cstring(previous_path), &info) == {} {
		private_file(previous_path) or_return
		bytes, read_error := read_file(previous_path, MAX_REPORT)

		if read_error != "" {
			return null(), "STATE_OR_SOURCE_INVALID"
		}

		parse_error: string; previous, parse_error = decode(bytes); if parse_error != "" {
			return null(), "STATE_OR_SOURCE_INVALID"
		}
	}

	observation := observe(manifest, config) or_return
	result = compare(observation, previous)
	put(&result, "observation", observation)
	atomic_json(join(state, "report.json"), result) or_return
	atomic_json(previous_path, observation) or_return
	atomic_json(
		join(state, "last_attempt.json"),
		object(
			{"status", get(result, "status")},
			{"checked_at_unix", get(observation, "checked_at_unix")},
			{"compatibility_approved", boolean(false)},
		),
	) or_return; return
}

check_upstream_changes :: proc(manifest: Value, state: string, config: Observation) -> (result: Value, failure: Failure) {
	fd := locked_state(state) or_return
	defer p.close(fd)

	result, failure = check_unlocked(manifest, state, config)

	if failure != nil {
		reason := failure.(string)
		write_error := atomic_json(
			join(state, "last_attempt.json"),
			object(
				{"status", text("FAILED")},
				{"reason", text(reason)},
				{"checked_at_unix", number(time.to_unix_seconds(time.now()))},
				{"compatibility_approved", boolean(false)},
			),
		); if write_error != nil {
			return null(), write_error
		}
	}

	return
}

package protocol_watch_test

import w "../src"
import test_fixtures "../../../tests/fixtures/protocol_watch"
import j "core:encoding/json"
import "core:mem"
import "core:os"
import "core:strings"
import p "core:sys/posix"
import "core:testing"
import "core:time"

BASE :: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

watch_manifest :: proc() -> w.Value {
	return w.object(
		{"schema", w.number(1)},
		{
			"sources",
			w.array(
				w.object(
					{"name", w.text("baileys")},
					{"repository", w.text("WhiskeySockets/Baileys")},
					{"branch", w.text("master")},
					{"reference_commit", w.text(BASE)},
					{"reference_scope", w.text("synthetic fixture")},
					{"paths", w.array(w.text("schema.proto"), w.text("auth.ts"))},
				),
			),
		},
	)
}

Stub :: struct {
	remove, fail, missing: bool,
	head:                  []u8,
}

upstream :: proc(data: rawptr, url: string, timeout: time.Duration) -> ([]u8, bool, w.Failure) {
	assert(timeout > 0 && timeout <= 10 * time.Second)
	fixture := cast(^Stub)data

	if fixture != nil && fixture.fail {
		return nil, false, "UPSTREAM_FETCH_FAILED"
	}

	if strings.contains(url, "/commits/") {
		if fixture != nil && fixture.head != nil {
			return fixture.head, true, nil
		}; return transmute([]u8)w.encode(w.object({"sha", w.text(test_fixtures.HEAD)})), true, nil
	}

	if fixture != nil &&
	   (fixture.missing || fixture.remove && strings.has_suffix(url, "schema.proto") && strings.contains(url, test_fixtures.HEAD)) {
		return nil, false, nil
	}

	return transmute([]u8)string("old schema" if strings.contains(url, BASE) else "new schema"), true, nil
}

@(test)
watch_drift_never_approves :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	observation, error := w.observe(watch_manifest(), w.Observation{fetch = upstream, root = test_fixtures.ROOT})
	testing.expect(t, error == nil)
	first := w.compare(observation)
	second := w.compare(observation, observation)
	testing.expect_value(t, w.str(w.get(first, "status")), "REVIEW_REQUIRED")
	testing.expect_value(t, len(w.items(w.get(second, "historical_reference_drift"))), 2)
	testing.expect_value(t, len(w.items(w.get(second, "changes_since_observation"))), 0)
	testing.expect(
		t,
		w.json_boolean_equals(w.get(second, "compatibility_approved"), false) &&
		w.json_boolean_equals(w.get(second, "runtime_version_changed"), false),
	)
}

@(test)
watch_removal_visible :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	previous, _ := w.observe(watch_manifest(), w.Observation{fetch = upstream, root = test_fixtures.ROOT})
	stub := Stub {
		remove = true,
	}

	current, error := w.observe(watch_manifest(), w.Observation{fetch = upstream, data = &stub, root = test_fixtures.ROOT})
	testing.expect(t, error == nil)
	testing.expect(
		t,
		w.equal(
			w.get(w.compare(current, previous), "changes_since_observation"),
			w.array(w.text("baileys:schema.proto")),
		),
	)
	testing.expect(
		t,
		w.json_boolean_equals(
			w.get(w.get(w.items(w.get(w.items(w.get(current, "sources"))[0], "files"))[0], "current"), "present"),
			false,
		),
	)
}

@(test)
watch_failed_fetch_preserves_success :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-watch-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	state := w.join(root, "state")
	_, failure := w.check_upstream_changes(watch_manifest(), state, w.Observation{fetch = upstream, root = test_fixtures.ROOT})
	testing.expect(t, failure == nil)
	before, _ := os.read_entire_file(w.join(state, "observed.json"), context.allocator)
	report, _ := os.read_entire_file(w.join(state, "report.json"), context.allocator)
	stub := Stub {
		fail = true,
	}

	_, failure = w.check_upstream_changes(watch_manifest(), state, w.Observation{fetch = upstream, data = &stub, root = test_fixtures.ROOT})
	testing.expect(t, failure == w.Failure("UPSTREAM_FETCH_FAILED"))
	after, _ := os.read_entire_file(w.join(state, "observed.json"), context.allocator)
	later, _ := os.read_entire_file(w.join(state, "report.json"), context.allocator)
	testing.expect_value(t, string(before), string(after))
	testing.expect_value(t, string(report), string(later))
	bytes, _ := os.read_entire_file(w.join(state, "last_attempt.json"), context.allocator)
	value, _ := w.decode(bytes)
	testing.expect_value(t, w.str(w.get(value, "status")), "FAILED")
}

@(test)
watch_invalid_head_missing_path_budget :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)

	for head in ([]string{"{}", "{\"sha\":\"bad\"}", "[]"}) {
		stub := Stub {
			head = transmute([]u8)head,
		}; _, failure := w.observe(watch_manifest(), w.Observation{fetch = upstream, data = &stub})
		testing.expect(t, failure != nil)
	}

	stub := Stub {
		missing = true,
	}; _, failure := w.observe(watch_manifest(), w.Observation{fetch = upstream, data = &stub})
	testing.expect(t, failure == w.Failure("MONITORED_PATH_MISSING"))
	_, failure = w.observe(
		watch_manifest(),
		w.Observation{fetch = upstream, started = time.tick_add(time.tick_now(), -181 * time.Second)},
	); testing.expect(t, failure == w.Failure("CHECK_BUDGET_EXPIRED"))
}

@(test)
watch_private_state_and_parallel_owner :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	root, error := os.make_directory_temp("", "owa-watch-*", context.allocator)
	assert(error == nil)
	defer os.remove_all(root)
	shared := w.join(root, "shared")
	assert(os.make_directory(shared) == nil)
	p.chmod(strings.clone_to_cstring(shared), {.IRUSR, .IWUSR, .IXUSR, .IRGRP, .IXGRP, .IROTH, .IXOTH})
	_, failure := w.locked_state(shared)
	testing.expect(t, failure == w.Failure("STATE_DIRECTORY_UNSAFE"))
	state := w.join(root, "state")
	fd, lock_error := w.locked_state(state)
	assert(lock_error == nil)
	_, failure = w.locked_state(state)
	testing.expect(t, failure == w.Failure("ALREADY_RUNNING"))
	p.close(fd)
	link := w.join(root, "link")
	assert(os.symlink(state, link) == nil)
	_, failure = w.locked_state(link)
	testing.expect(t, failure != nil)
	external := w.join(root, "external")
	assert(os.write_entire_file(external, transmute([]u8)string("{}")) == nil)
	p.chmod(strings.clone_to_cstring(external), {.IRUSR, .IWUSR})
	assert(p.link(strings.clone_to_cstring(external), strings.clone_to_cstring(w.join(state, "observed.json"))) == {})
	_, failure = w.check_upstream_changes(watch_manifest(), state, w.Observation{fetch = upstream})
	testing.expect(t, failure == w.Failure("STATE_FILE_UNSAFE"))
}

@(test)
watch_manifest_rejects_untrusted_sources :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	value := watch_manifest()
	_, failure := w.manifest_read(transmute([]u8)w.encode(value))
	testing.expect(t, failure == nil)

	for key, i in ([]string{"repository", "paths", "reference_commit"}) {
		bad := j.clone_value(value)
		sources := w.items(w.get(bad, "sources"))
		source := sources[0]
		wrong := w.text("other/repo")

		if i == 1 {
			wrong = w.array(w.text("../private"))
		}; if i == 2 {
			wrong = w.text("master")
		}; w.put(&source, key, wrong); sources[0] = source; w.put(&bad, "sources", sources)
		_, failure = w.manifest_read(transmute([]u8)w.encode(bad))
		testing.expect(t, failure != nil)
	}
}

@(test)
watch_version_never_falls_back :: proc(t: ^testing.T) {
	arena := test_fixtures.setup_arena()
	defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	value, error := w.version_decode(transmute([]u8)string("{\"version\":[2,3000,42]}"))
	testing.expect(t, error == nil && w.equal(value, w.array(w.number(2), w.number(3000), w.number(42))))

	for bytes in ([]string {
			"{}",
			"{\"version\":[true,2,3]}",
			"{\"version\":[1,2]}",
			"{\"version\":[-1,2,3]}",
			"not JSON",
			"",
		}) {
		_, failure := w.version_decode(transmute([]u8)bytes)
		testing.expect(t, failure == w.Failure("VERSION_FEED_INVALID"))
	}
}

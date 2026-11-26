package whatsapp_test

import "core:os"
import test_fixtures "../fixtures/client"
import "core:strings"
import "core:testing"
import wa "shared:whatsapp"

@(test)
state_atomic_write_replaces_the_file_and_reports_a_missing_directory :: proc(t: ^testing.T) {
	directory, directory_error := os.make_directory_temp("", "wa-atomic-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer {
		os.remove_all(directory)
		delete(directory)
	}

	path := strings.concatenate({directory, "/state.bin"})

	defer delete(path)

	testing.expect_value(t, wa.state_atomic_write(path, transmute([]u8)string("one")).kind, wa.State_Error_Kind.None)
	testing.expect_value(t, wa.state_atomic_write(path, transmute([]u8)string("two!")).kind, wa.State_Error_Kind.None)
	data, read_error := os.read_entire_file(path, context.allocator)
	testing.expect(t, read_error == nil)
	defer delete(data)

	testing.expect_value(t, string(data), "two!")
	missing := strings.concatenate({directory, "/absent/state.bin"})

	defer delete(missing)

	testing.expect_value(t, wa.state_atomic_write(missing, transmute([]u8)string("x")).kind, wa.State_Error_Kind.Write_Failed)
}

@(test)
consumer_can_store_read_and_replace_session :: proc(t: ^testing.T) {
	identity: [32]u8
	identity[0] = 1
	store: wa.State_Store
	testing.expect(t, wa.state_store_init(&store, identity).kind == .None)
	defer wa.state_store_clear(&store)

	testing.expect(
		t,
		wa.state_store_set(&store, .Session, "example-session", []u8{1, 2, 3}).kind == .None,
	)
	value, found := wa.state_store_get(&store, .Session, "example-session")
	testing.expect(t, found && len(value) == 3 && value[0] == 1 && value[2] == 3)
	testing.expect(
		t,
		wa.state_store_set(&store, .Session, "example-session", []u8{4}).kind == .None,
	)
	value, found = wa.state_store_get(&store, .Session, "example-session")
	testing.expect(t, found && len(value) == 1 && value[0] == 4)
}

@(test)
post_rename_directory_failure_requires_reloading_replaced_state :: proc(t: ^testing.T) {
	f := test_fixtures.negative_ack_fixture()
	defer test_fixtures.negative_ack_destroy(f)

	next: wa.State_Store
	defer wa.state_store_clear(&next)

	assert(wa.socket_store_clone(&next, &f.store).kind == .None)
	assert(wa.state_store_set(&next, .Session, "new-session", []u8{42}).kind == .None)
	// Allow replacement in this directory but deny opening it for fsync.
	assert(os.chmod(f.directory, {.Write_User, .Execute_User}) == nil)
	defer os.chmod(f.directory, {.Read_User, .Write_User, .Execute_User})

	if directory, err := os.open(f.directory); err == nil {
		os.close(directory)
		// Privileged test users can bypass directory permissions.
		return
	}

	err := wa.socket_store_commit(&f.socket, &next)
	testing.expect(t, err.kind == .State_Failed && err.state.kind == .Directory_Flush_Failed)
	testing.expect(t, f.store.requires_reload && f.socket.phase == .Failed)
	testing.expect_value(t, wa.state_store_save(&f.store, f.path).kind, .Directory_Flush_Failed)
	identity := f.store.identity
	testing.expect_value(t, wa.state_store_load(&f.store, f.path, identity).kind, .Directory_Flush_Failed)
	testing.expect(t, f.store.requires_reload)
	assert(os.chmod(f.directory, {.Read_User, .Write_User, .Execute_User}) == nil)
	assert(wa.state_store_load(&f.store, f.path, identity).kind == .None)
	value, found := wa.state_store_get(&f.store, .Session, "new-session")
	testing.expect(t, !f.store.requires_reload && found && len(value) == 1 && value[0] == 42)
}

@(test)
rollback_export_preserves_session_and_queue_with_legacy_contact_fields :: proc(t: ^testing.T) {
	dir, err := os.make_directory_temp("", "owa-rollback-*", context.allocator)
	if !testing.expect(t, err == nil) {return}
	defer {os.remove_all(dir); delete(dir)}

	path := strings.concatenate({dir, "/export.bin"})

	defer delete(path)

	store, old: wa.State_Store
	defer wa.state_store_clear(&store)

	defer wa.state_store_clear(&old)

	assert(wa.state_store_init(&store, [32]u8{0=1}).kind == .None)
	cursor: [136]u8
	cursor[7] = 5
	stamp := [9]u8{7 = 13, 8 = 1}

	for r in ([]wa.State_Record{
		{.Session, "device", []u8{42}}, {.Outbound_Message, "id", []u8{15}},
		{.Pending_Profile_History, "history", []u8{2}},
		{.Chat_History_Cursor, "123@lid", []u8{0,0,0,0,0,0,0,9,0,'m'}},
		{.Contact_Name, "123@lid", transmute([]u8)string("Test\x00\x00")},
		{.Contact_Sync_State, "contacts-cursor", cursor[:]},
		{.Contact_Sync_State, "server-version", cursor[:8]},
		{.Contact_Sync_State, "ready", []u8{1}},
		{.Processed_Message, "history", stamp[:]},
	}) {assert(wa.state_store_set(&store, r.kind, r.name, r.data).kind == .None)}

	_, dirty := wa.state_store_export_v0_2(&store, path)
	testing.expect_value(t, dirty.kind, .Invalid_State)
	original := strings.concatenate({dir, "/original.bin"})

	defer delete(original)

	assert(wa.state_store_save(&store, original).kind == .None)
	_, overwrite := wa.state_store_export_v0_2(&store, original)
	testing.expect_value(t, overwrite.kind, .Rename_Failed)
	count, exported := wa.state_store_export_v0_2(&store, path)
	testing.expect(t, count == 1 && exported.kind == .None)
	assert(wa.state_store_load(&old, path, store.identity).kind == .None)
	for r in old.records {
		testing.expect(t, r.kind <= .Contact_Sync_State)
		if r.kind == .Contact_Sync_State {
			testing.expect(t, r.name == "cursor" || r.name == "required-version" || r.name == "ready")
		}
	}

	for r in store.records {
		if r.kind == .Pending_Profile_History || r.kind == .Chat_History_Cursor {continue}

		key, data := r.name, r.data
		if key == "contacts-cursor" {key = "cursor"}

		if key == "server-version" {key = "required-version"}

		if r.kind == .Processed_Message {data = data[:8]}

		actual, found := wa.state_store_get(&old, r.kind, key)
		testing.expect(t, found && string(actual) == string(data))
	}

	_, present := wa.state_store_get(&store, .Pending_Profile_History, "history")
	testing.expect(t, present)
}

package whatsapp_test

import "core:os"
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

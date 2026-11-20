package public_api_test

import "core:testing"
import wa "shared:whatsapp"

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

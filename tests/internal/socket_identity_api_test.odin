package whatsapp

import "core:bytes"
import "core:fmt"
import "core:os"
import "core:testing"

Identity_Api_Fixture :: struct {
	socket:          Socket,
	auth:            Auth_State,
	store:           State_Store,
	prekeys:         Prekey_Store,
	directory, path, prekey_path: string,
}

identity_api_fixture :: proc() -> ^Identity_Api_Fixture {
	fixture := new(Identity_Api_Fixture)
	directory, error := os.make_directory_temp("", "whatsapp-identity-api-*", context.allocator)
	assert(error == nil)
	fixture.directory = directory
	fixture.path = fmt.aprintf("%s/state", directory)
	fixture.prekey_path = fmt.aprintf("%s/prekeys", directory)
	identity: [32]u8
	identity[0] = 3
	assert(state_store_init(&fixture.store, identity).kind == .None)
	credentials, credentials_error := device_credentials_generate()
	assert(credentials_error == .None)
	fixture.auth.credentials = credentials
	assert(prekey_store_init(&fixture.prekeys, &fixture.auth.credentials).kind == .None)
	assert(prekey_store_generate(&fixture.prekeys, 2).kind == .None)
	assert(prekey_store_save(fixture.prekey_path, &fixture.prekeys).kind == .None)
	fixture.socket = {
		phase = .Online,
		store = &fixture.store,
		prekeys = &fixture.prekeys,
		auth = &fixture.auth,
		config = {state_path = fixture.path, prekey_path = fixture.prekey_path},
	}

	return fixture
}

identity_api_fixture_destroy :: proc(fixture: ^Identity_Api_Fixture) {
	state_store_clear(&fixture.store)
	prekey_store_clear(&fixture.prekeys)
	device_credentials_clear(&fixture.auth.credentials)
	assert(os.remove_all(fixture.directory) == nil)
	delete(fixture.path)
	delete(fixture.prekey_path)
	delete(fixture.directory)
	free(fixture)
}

identity_api_pin :: proc(seed: u8) -> [32]u8 {
	pin: [32]u8
	for &b, i in pin {
		b = seed + u8(i)
	}

	return pin
}

identity_api_has :: proc(store: ^State_Store, kind: State_Record_Kind, name: string) -> bool {
	_, found := state_store_get(store, kind, name)

	return found
}

@(test)
lid_mapping_records_both_directions_durably_and_is_idempotent :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	error := socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid")
	testing.expect_value(t, error.kind, Socket_Error_Kind.None)

	forward, forward_found := state_store_get(&fixture.store, .LID_Mapping, "pn:555@s.whatsapp.net")
	testing.expect(t, forward_found)
	testing.expect_value(t, string(forward), "777@lid")

	reverse, reverse_found := state_store_get(&fixture.store, .LID_Mapping, "lid:777@lid")
	testing.expect(t, reverse_found)
	testing.expect_value(t, string(reverse), "555@s.whatsapp.net")
	testing.expect_value(t, fixture.store.revision, fixture.store.durable_revision)

	loaded: State_Store
	defer state_store_clear(&loaded)
	identity: [32]u8
	identity[0] = 3
	testing.expect_value(t, state_store_load(&loaded, fixture.path, identity).kind, State_Error_Kind.None)
	testing.expect(t, identity_api_has(&loaded, .LID_Mapping, "pn:555@s.whatsapp.net"))

	revision := fixture.store.revision
	error = socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid")
	testing.expect_value(t, error.kind, Socket_Error_Kind.None)
	testing.expect_value(t, fixture.store.revision, revision)

	// The legacy @c.us domain and a device suffix normalise to the bare pair.
	error = socket_record_lid_mapping(&fixture.socket, "555:0@c.us", "777:0@lid")
	testing.expect_value(t, error.kind, Socket_Error_Kind.None)
	testing.expect_value(t, fixture.store.revision, revision)
}

@(test)
lid_mapping_rejects_conflicts_and_malformed_pairs_without_mutation :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	testing.expect_value(t, socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid").kind, Socket_Error_Kind.None)
	revision := fixture.store.revision

	conflicts := [?][2]string{{"555@s.whatsapp.net", "888@lid"}, {"556@s.whatsapp.net", "777@lid"}}
	for pair in conflicts {
		error := socket_record_lid_mapping(&fixture.socket, pair[0], pair[1])
		testing.expect_value(t, error.kind, Socket_Error_Kind.Identity_Changed)
		testing.expect_value(t, fixture.store.revision, revision)
	}

	malformed := [?][2]string {
		{"555@lid", "777@lid"},
		{"555@s.whatsapp.net", "777@s.whatsapp.net"},
		{"555:1@s.whatsapp.net", "777:2@lid"},
		{"", "777@lid"},
		{"555@s.whatsapp.net", ""},
	}
	for pair in malformed {
		error := socket_record_lid_mapping(&fixture.socket, pair[0], pair[1])
		testing.expect_value(t, error.kind, Socket_Error_Kind.Invalid_Config)
	}

	testing.expect_value(t, fixture.store.revision, revision)
	testing.expect_value(t, socket_record_lid_mapping(nil, "555@s.whatsapp.net", "777@lid").kind, Socket_Error_Kind.Invalid_State)
	bare := Socket{}
	testing.expect_value(t, socket_record_lid_mapping(&bare, "555@s.whatsapp.net", "777@lid").kind, Socket_Error_Kind.Invalid_State)
}

@(test)
lid_mapping_migrates_existing_lid_state_to_the_phone_address :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	pin := identity_api_pin(1)
	testing.expect_value(t, state_store_set(&fixture.store, .Identity, "777:1@lid", pin[:]).kind, State_Error_Kind.None)

	testing.expect_value(t, socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid").kind, Socket_Error_Kind.None)

	migrated, found := state_store_get(&fixture.store, .Identity, "555:1@s.whatsapp.net")
	testing.expect(t, found)
	testing.expect(t, bytes.equal(migrated, pin[:]))
	testing.expect(t, !identity_api_has(&fixture.store, .Identity, "777:1@lid"))

	canonical, address_error := socket_signal_address(&fixture.socket, "777:1@lid")
	defer delete(canonical)
	testing.expect_value(t, address_error.kind, Socket_Error_Kind.None)
	testing.expect_value(t, canonical, "555:1@s.whatsapp.net")
}

@(test)
lid_mapping_failed_save_keeps_the_store_unchanged :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)
	fixture.socket.config.state_path = "/nonexistent-whatsapp-library-directory/state"
	revision := fixture.store.revision

	error := socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid")

	testing.expect_value(t, error.kind, Socket_Error_Kind.State_Failed)
	testing.expect_value(t, fixture.store.revision, revision)
	testing.expect(t, !identity_api_has(&fixture.store, .LID_Mapping, "pn:555@s.whatsapp.net"))
}

@(test)
trust_identity_pins_new_key_and_drops_sessions_and_sender_keys_of_that_device :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	original := identity_api_pin(1)
	replacement := identity_api_pin(40)
	device := "555:1@s.whatsapp.net"
	testing.expect_value(t, state_store_set(&fixture.store, .Identity, device, original[:]).kind, State_Error_Kind.None)
	doomed := [?]struct {
		kind: State_Record_Kind,
		name: string,
	} {
		{.Session, "555:1@s.whatsapp.net"},
		{.Session, "555:1@s.whatsapp.net#prior-base"},
		{.Sender_Key, "123@g.us|555:1@s.whatsapp.net"},
		{.Sender_Key_Membership, "123@g.us|555:1@s.whatsapp.net"},
	}
	survivors := [?]struct {
		kind: State_Record_Kind,
		name: string,
	}{{.Session, "999:1@s.whatsapp.net"}, {.Sender_Key, "123@g.us|999:1@s.whatsapp.net"}, {.Session, "555:2@s.whatsapp.net"}}
	for record in doomed {
		testing.expect_value(t, state_store_set(&fixture.store, record.kind, record.name, []u8{1}).kind, State_Error_Kind.None)
	}

	for record in survivors {
		testing.expect_value(t, state_store_set(&fixture.store, record.kind, record.name, []u8{1}).kind, State_Error_Kind.None)
	}

	testing.expect_value(t, socket_trust_identity(&fixture.socket, device, replacement).kind, Socket_Error_Kind.None)

	pin, found := state_store_get(&fixture.store, .Identity, device)
	testing.expect(t, found)
	testing.expect(t, bytes.equal(pin, replacement[:]))

	for record in doomed {
		testing.expectf(t, !identity_api_has(&fixture.store, record.kind, record.name), "%v %s survived", record.kind, record.name)
	}

	for record in survivors {
		testing.expectf(t, identity_api_has(&fixture.store, record.kind, record.name), "%v %s lost", record.kind, record.name)
	}

	testing.expect_value(t, fixture.store.revision, fixture.store.durable_revision)
}

@(test)
trust_identity_rejects_invalid_input_and_failed_save_keeps_pin_and_sessions :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	original := identity_api_pin(1)
	replacement := identity_api_pin(40)
	device := "555:1@s.whatsapp.net"
	testing.expect_value(t, state_store_set(&fixture.store, .Identity, device, original[:]).kind, State_Error_Kind.None)
	testing.expect_value(t, state_store_set(&fixture.store, .Session, device, []u8{1}).kind, State_Error_Kind.None)
	revision := fixture.store.revision

	zero: [32]u8
	testing.expect_value(t, socket_trust_identity(&fixture.socket, device, zero).kind, Socket_Error_Kind.Invalid_Config)
	testing.expect_value(t, socket_trust_identity(&fixture.socket, "not-a-jid", replacement).kind, Socket_Error_Kind.Invalid_Config)
	testing.expect_value(t, socket_trust_identity(&fixture.socket, "555@g.us", replacement).kind, Socket_Error_Kind.Invalid_Config)
	testing.expect_value(t, socket_trust_identity(nil, device, replacement).kind, Socket_Error_Kind.Invalid_Config)

	fixture.socket.config.state_path = "/nonexistent-whatsapp-library-directory/state"
	testing.expect_value(t, socket_trust_identity(&fixture.socket, device, replacement).kind, Socket_Error_Kind.State_Failed)

	pin, found := state_store_get(&fixture.store, .Identity, device)
	testing.expect(t, found)
	testing.expect(t, bytes.equal(pin, original[:]))
	testing.expect(t, identity_api_has(&fixture.store, .Session, device))
	testing.expect_value(t, fixture.store.revision, revision)
}

package whatsapp_test

import "core:bytes"
import "core:fmt"
import "core:os"
import "core:testing"
import wa "shared:whatsapp"

@(test)
group_metadata_query_encode_builds_the_interactive_query_and_validates_input :: proc(t: ^testing.T) {
	buffer: [256]u8
	size, error := wa.group_metadata_query_encode(buffer[:], "120363000000000000@g.us", "req-1")
	testing.expect_value(t, error.kind, wa.Group_Error_Kind.None)
	document, decode_error := wa.binary_node_decode(buffer[:size])
	defer wa.binary_document_destroy(&document)
	testing.expect_value(t, decode_error.kind, wa.Binary_Node_Error_Kind.None)
	xmlns, _ := wa.node_attr(document.root, "xmlns")
	to, _ := wa.node_attr(document.root, "to")
	testing.expect_value(t, xmlns, "w:g2")
	testing.expect_value(t, to, "120363000000000000@g.us")
	testing.expect_value(t, document.root.tag, "iq")
	query := wa.node_child(document.root, "query")
	testing.expect(t, query != nil)
	request, _ := wa.node_attr(query^, "request")
	testing.expect_value(t, request, "interactive")
	_, bad_jid := wa.group_metadata_query_encode(buffer[:], "not-a-group", "req-1")
	testing.expect_value(t, bad_jid.kind, wa.Group_Error_Kind.Invalid_Group_JID)
	_, empty_id := wa.group_metadata_query_encode(buffer[:], "120363000000000000@g.us", "")
	testing.expect_value(t, empty_id.kind, wa.Group_Error_Kind.Invalid_Request_ID)
	_, small := wa.group_metadata_query_encode(buffer[:4], "120363000000000000@g.us", "req-1")
	testing.expect_value(t, small.kind, wa.Group_Error_Kind.Binary_Node_Failed)
}

Identity_Api_Fixture :: struct {
	socket:          wa.Socket,
	auth:            wa.Auth_State,
	store:           wa.State_Store,
	prekeys:         wa.Prekey_Store,
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
	assert(wa.state_store_init(&fixture.store, identity).kind == .None)
	credentials, credentials_error := wa.device_credentials_generate()
	assert(credentials_error == .None)
	fixture.auth.credentials = credentials
	assert(wa.prekey_store_init(&fixture.prekeys, &fixture.auth.credentials).kind == .None)
	assert(wa.prekey_store_generate(&fixture.prekeys, 2).kind == .None)
	assert(wa.prekey_store_save(fixture.prekey_path, &fixture.prekeys).kind == .None)
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
	wa.state_store_clear(&fixture.store)
	wa.prekey_store_clear(&fixture.prekeys)
	wa.device_credentials_clear(&fixture.auth.credentials)
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

identity_api_has :: proc(store: ^wa.State_Store, kind: wa.State_Record_Kind, name: string) -> bool {
	_, found := wa.state_store_get(store, kind, name)

	return found
}

@(test)
lid_mapping_records_both_directions_durably_and_is_idempotent :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	error := wa.socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid")
	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)

	forward, forward_found := wa.state_store_get(&fixture.store, .LID_Mapping, "pn:555@s.whatsapp.net")
	testing.expect(t, forward_found)
	testing.expect_value(t, string(forward), "777@lid")

	reverse, reverse_found := wa.state_store_get(&fixture.store, .LID_Mapping, "lid:777@lid")
	testing.expect(t, reverse_found)
	testing.expect_value(t, string(reverse), "555@s.whatsapp.net")
	testing.expect_value(t, fixture.store.revision, fixture.store.durable_revision)

	loaded: wa.State_Store
	defer wa.state_store_clear(&loaded)
	identity: [32]u8
	identity[0] = 3
	testing.expect_value(t, wa.state_store_load(&loaded, fixture.path, identity).kind, wa.State_Error_Kind.None)
	testing.expect(t, identity_api_has(&loaded, .LID_Mapping, "pn:555@s.whatsapp.net"))

	revision := fixture.store.revision
	error = wa.socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid")
	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, fixture.store.revision, revision)

	// The legacy @c.us domain and a device suffix normalise to the bare pair.
	error = wa.socket_record_lid_mapping(&fixture.socket, "555:0@c.us", "777:0@lid")
	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, fixture.store.revision, revision)
}

@(test)
lid_mapping_rejects_conflicts_and_malformed_pairs_without_mutation :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	testing.expect_value(t, wa.socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid").kind, wa.Socket_Error_Kind.None)
	revision := fixture.store.revision

	conflicts := [?][2]string{{"555@s.whatsapp.net", "888@lid"}, {"556@s.whatsapp.net", "777@lid"}}
	for pair in conflicts {
		error := wa.socket_record_lid_mapping(&fixture.socket, pair[0], pair[1])
		testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Identity_Changed)
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
		error := wa.socket_record_lid_mapping(&fixture.socket, pair[0], pair[1])
		testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Invalid_Config)
	}

	testing.expect_value(t, fixture.store.revision, revision)
	testing.expect_value(t, wa.socket_record_lid_mapping(nil, "555@s.whatsapp.net", "777@lid").kind, wa.Socket_Error_Kind.Invalid_State)
	bare := wa.Socket{}
	testing.expect_value(t, wa.socket_record_lid_mapping(&bare, "555@s.whatsapp.net", "777@lid").kind, wa.Socket_Error_Kind.Invalid_State)
}

@(test)
lid_mapping_migrates_existing_lid_state_to_the_phone_address :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)

	pin := identity_api_pin(1)
	testing.expect_value(t, wa.state_store_set(&fixture.store, .Identity, "777:1@lid", pin[:]).kind, wa.State_Error_Kind.None)

	testing.expect_value(t, wa.socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid").kind, wa.Socket_Error_Kind.None)

	migrated, found := wa.state_store_get(&fixture.store, .Identity, "555:1@s.whatsapp.net")
	testing.expect(t, found)
	testing.expect(t, bytes.equal(migrated, pin[:]))
	testing.expect(t, !identity_api_has(&fixture.store, .Identity, "777:1@lid"))

	canonical, address_error := wa.socket_signal_address(&fixture.socket, "777:1@lid")
	defer delete(canonical)
	testing.expect_value(t, address_error.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, canonical, "555:1@s.whatsapp.net")
}

@(test)
lid_mapping_failed_save_keeps_the_store_unchanged :: proc(t: ^testing.T) {
	fixture := identity_api_fixture()
	defer identity_api_fixture_destroy(fixture)
	fixture.socket.config.state_path = "/nonexistent-whatsapp-library-directory/state"
	revision := fixture.store.revision

	error := wa.socket_record_lid_mapping(&fixture.socket, "555@s.whatsapp.net", "777@lid")

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.State_Failed)
	testing.expect_value(t, fixture.store.revision, revision)
	testing.expect(t, !identity_api_has(&fixture.store, .LID_Mapping, "pn:555@s.whatsapp.net"))
}

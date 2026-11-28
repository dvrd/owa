package whatsapp_test

import test_fixtures "../../fixtures/client"
import "core:testing"
import wa "shared:whatsapp"

@(test)
send_id_successful_pending_replay_preserves_exact_inner_packet :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)

	wire: test_fixtures.Send_Id_Wire
	socket := &fixture.socket
	test_fixtures.send_id_wire_connect(socket, &wire)
	defer wa.frame_transport_clear(&socket.client.frames)

	revision := fixture.store.revision
	id, error := wa.socket_send_group(
		socket,
		"123@g.us",
		transmute([]u8)string("original content"),
		message_id = "stable-id",
	)
	defer delete(id)

	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, id, "stable-id")
	testing.expect_value(t, fixture.store.revision, revision)
	testing.expect_value(t, socket.sequence, u64(0))
	plain: [1024]u8
	testing.expect_value(t, test_fixtures.send_id_wire_plain(&wire, plain[:]), "original wire")
}

@(test)
send_id_targeted_retry_bypasses_pending_replay_without_changing_intent :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)

	id, handled, error := wa.socket_group_existing_send(
		&fixture.socket,
		"123@g.us",
		"",
		"stable-id",
		"222:1@s.whatsapp.net",
		transmute([]u8)string("original content"),
	)
	defer delete(id)

	testing.expect(t, !handled)
	testing.expect_value(t, error.kind, .None)
	_, conflict, conflict_error := wa.socket_group_existing_send(
		&fixture.socket,
		"123@g.us",
		"",
		"stable-id",
		"222:1@s.whatsapp.net",
		transmute([]u8)string("changed content"),
	)
	testing.expect(t, conflict)
	testing.expect_value(t, conflict_error.kind, .Invalid_Config)
}

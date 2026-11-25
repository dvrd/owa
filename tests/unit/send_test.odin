package whatsapp_test

import "core:bytes"
import "core:testing"
import test_fixtures "../fixtures/client"
import wa "shared:whatsapp"

@(test)
send_id_conflicting_commit_preserves_pending_wire_and_durable_state :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)
	revision := fixture.store.revision
	error := wa.socket_group_outbound_commit(
		&fixture.socket,
		"456@g.us",
		"",
		"stable-id",
		transmute([]u8)string("replacement content"),
		transmute([]u8)string("replacement wire"),
	)
	testing.expect_value(t, error.kind, .Invalid_Config)
	wire, present := wa.state_store_get(&fixture.store, .Outbound_Message, "stable-id")
	testing.expect(t, present && bytes.equal(wire, transmute([]u8)string("original wire")))
	testing.expect_value(t, fixture.store.revision, revision)
	restored: wa.State_Store
	defer wa.state_store_clear(&restored)
	loaded := wa.state_store_load(&restored, fixture.path, fixture.store.identity)
	testing.expect_value(t, loaded.kind, .None)
	durable, found := wa.state_store_get(&restored, .Outbound_Message, "stable-id")
	testing.expect(t, found && bytes.equal(durable, transmute([]u8)string("original wire")))
}

@(test)
send_id_conflict_is_rejected_before_metadata_or_cryptographic_work :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)
	revision := fixture.store.revision
	id, error := wa.socket_send_group(
		&fixture.socket,
		"456@g.us",
		transmute([]u8)string("replacement content"),
		message_id = "stable-id",
	)
	defer delete(id)
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, id, "")
	testing.expect_value(t, fixture.store.revision, revision)
	testing.expect_value(t, fixture.socket.sequence, u64(0))
	testing.expect_value(t, fixture.socket.phase, .Online)
}

@(test)
send_id_pending_same_intent_reuses_id_without_queries_or_new_state :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)
	revision := fixture.store.revision
	id, error := wa.socket_send_group(
		&fixture.socket,
		"123@g.us",
		transmute([]u8)string("original content"),
		message_id = "stable-id",
	)
	defer delete(id)
	// No initialized wire client: replay fails closed, retaining the original ID and packet.
	testing.expect_value(t, error.kind, .Session_Failed)
	testing.expect_value(t, id, "stable-id")
	testing.expect_value(t, fixture.socket.sequence, u64(0))
	testing.expect_value(t, fixture.store.revision, revision)
	wire, present := wa.state_store_get(&fixture.store, .Outbound_Message, "stable-id")
	testing.expect(t, present && bytes.equal(wire, transmute([]u8)string("original wire")))
}

@(test)
send_id_retained_content_does_not_fabricate_acknowledgment :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)
	assert(wa.state_store_delete(&fixture.store, .Outbound_Message, "stable-id").kind == .None)
	id, handled, error := wa.socket_group_existing_send(
		&fixture.socket,
		"123@g.us",
		"",
		"stable-id",
		"",
		transmute([]u8)string("original content"),
	)
	defer delete(id)
	testing.expect(t, !handled)
	testing.expect_value(t, error.kind, .None)
}

send_id_media_fixture :: proc(fixture: ^test_fixtures.Send_Id_Fixture) {
	assert(wa.state_store_delete(&fixture.store, .Outbound_Content, "stable-id").kind == .None)
	assert(wa.state_store_delete(&fixture.store, .Outbound_Message, "stable-id").kind == .None)
	hash := wa.sha256(transmute([]u8)string("%PDF-original"))
	key: [32]u8
	key[0] = 1
	message := wa.Media_Message {
		kind            = .Document,
		url             = "https://mmg.whatsapp.net/a.enc",
		direct_path     = "/a.enc",
		mime_type       = "application/pdf",
		caption         = "caption",
		file_name       = "a.pdf",
		media_key       = key[:],
		file_sha256     = hash[:],
		file_enc_sha256 = hash[:],
		file_length     = 13,
		has_file_length = true,
	}

	buffer: [1024]u8
	count, error := wa.media_message_encode(buffer[:], message)
	assert(error.kind == .None)
	assert(
		wa.socket_group_outbound_commit(&fixture.socket, "123@g.us", "document", "stable-id", buffer[:count], transmute([]u8)string("original media wire")).kind ==
		.None,
	)
}

@(test)
send_id_high_level_document_replay_does_not_upload_again :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)
	send_id_media_fixture(fixture)
	wire_capture: test_fixtures.Send_Id_Wire
	test_fixtures.send_id_wire_connect(&fixture.socket, &wire_capture)
	defer wa.frame_transport_clear(&fixture.socket.client.frames)
	revision := fixture.store.revision
	id, error := wa.socket_send_document(
		&fixture.socket,
		"123@g.us",
		transmute([]u8)string("%PDF-original"),
		"a.pdf",
		"caption",
		"application/pdf",
		"stable-id",
	)
	defer delete(id)
	testing.expect_value(t, id, "stable-id")
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, test_fixtures.send_id_http_calls, 0)
	testing.expect(t, wire_capture.used > 0)
	plain: [1024]u8
	testing.expect_value(t, test_fixtures.send_id_wire_plain(&wire_capture, plain[:]), "original media wire")
	testing.expect_value(t, fixture.store.revision, revision)
	testing.expect_value(t, fixture.socket.sequence, u64(0))
	wire, found := wa.state_store_get(&fixture.store, .Outbound_Message, "stable-id")
	testing.expect(t, found && string(wire) == "original media wire")
}

@(test)
send_id_high_level_document_conflicts_fail_before_upload :: proc(t: ^testing.T) {
	fixture := test_fixtures.send_id_fixture()
	defer test_fixtures.send_id_fixture_destroy(fixture)
	send_id_media_fixture(fixture)
	fixture.socket.config.http_execute = test_fixtures.send_id_http
	test_fixtures.send_id_http_calls = 0

	for row in ([]struct {
			group, content, name, caption: string,
		} {
			{"456@g.us", "%PDF-original", "a.pdf", "caption"},
			{"123@g.us", "%PDF-changed!", "a.pdf", "caption"},
			{"123@g.us", "%PDF-original", "b.pdf", "caption"},
			{"123@g.us", "%PDF-original", "a.pdf", "changed"},
		}) {
		id, error := wa.socket_send_document(
			&fixture.socket,
			row.group,
			transmute([]u8)row.content,
			row.name,
			row.caption,
			"application/pdf",
			"stable-id",
		)
		delete(id)
		testing.expect_value(t, error.kind, .Invalid_Config)
		testing.expect_value(t, fixture.socket.sequence, u64(0))
		testing.expect_value(t, test_fixtures.send_id_http_calls, 0)
		fixture.socket.phase = .Online
	}
}

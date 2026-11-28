package whatsapp_test

import "core:testing"
import "core:time"
import "shared:surf"
import test_fixtures "../fixtures/client"
import wa "shared:whatsapp"

@(test)
contact_sync_rejects_forged_records_and_collection_signatures :: proc(t: ^testing.T) {
	raw := test_fixtures.codec_api_hex(string(#load("../fixtures/contact_sync/snapshot.hex")))
	share := test_fixtures.codec_api_hex(string(#load("../fixtures/contact_sync/key-share.hex")))
	// Locate each signed part in the independent vector and change one byte.
	for target in 0 ..< 3 {
		checkpoint := make([]u8, len(raw))
		defer delete(checkpoint)

		copy(checkpoint, raw)
		if target == 2 {
			signature, valid := wa.read_unique_protobuf_field(checkpoint, 3, 2)
			testing.expect(t, valid)
			signature.data[0] ~= 1
		} else {
			at := 0
			for at < len(checkpoint) {
				record, _ := wa.protobuf_field_read(checkpoint, &at)
				if record.number != 2 {
					continue
				}

				part, _ := wa.read_unique_protobuf_field(record.data, u32(target + 1), 2)
				blob, _ := wa.read_unique_protobuf_field(part.data, 1, 2)
				blob.data[0] ~= 1
				break
			}
		}

		store: wa.State_Store
		testing.expect_value(
			t,
			wa.state_store_init(&store, [32]u8{0 = 1}).kind,
			wa.State_Error_Kind.None,
		)
		defer wa.state_store_clear(&store)

		testing.expect_value(
			t,
			wa.store_contact_sync_key_share(&store, share).kind,
			wa.Socket_Error_Kind.None,
		)
		staged: wa.State_Store
		defer wa.state_store_clear(&staged)

		testing.expect_value(t, wa.socket_store_clone(&staged, &store).kind, wa.Socket_Error_Kind.None)
		page := wa.Contact_Sync_Page {
			store = &staged,
		}

		error := wa.apply_authenticated_contact_batch(nil, &page, checkpoint, true)
		testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Protocol_Error)
		found, status, _ := wa.search_contact_jids(&store, "Daniel")
		defer delete(found)

		testing.expect(t, len(found) == 0 && status == .Syncing)
	}
}

@(test)
alternate_contact_index_renames_and_removes_one_saved_contact :: proc(t: ^testing.T) {
	store: wa.State_Store
	assert(wa.state_store_init(&store, [32]u8{0 = 1}).kind == .None)
	defer wa.state_store_clear(&store)

	for reverse in ([]bool{false, true}) {
		primary := "123@s.whatsapp.net" if !reverse else "999@lid"
		value := "Daniel\x00Dan\x00999@lid" if !reverse else "Daniel\x00Dan\x00123@s.whatsapp.net"
		index := `["contact","999@lid"]` if !reverse else `["contact","123@s.whatsapp.net"]`
		assert(wa.state_store_set(&store, .Contact_Name, primary, transmute([]u8)value).kind == .None)
		testing.expect(t, wa.apply_contact_action(&store, transmute([]u8)index, []u8{26, 3, 10, 1, 'B'}, false))
		old, _, _ := wa.search_contact_jids(&store, "Daniel")
		defer delete(old)

		testing.expect_value(t, len(old), 0)
		updated, _, _ := wa.search_contact_jids(&store, "B")
		defer delete(updated)

		testing.expect(t, len(updated) == 1 && updated[0] == primary)
		testing.expect(t, wa.apply_contact_action(&store, transmute([]u8)index, nil, true))
		_, found := wa.contact_by_jid(&store, primary)
		testing.expect(t, !found)
	}
}

@(test)
contact_add_patch_round_trips_through_authenticated_sync :: proc(t: ^testing.T) {
	store: wa.State_Store
	assert(wa.state_store_init(&store, [32]u8{0 = 1}).kind == .None)
	defer wa.state_store_clear(&store)

	key_id := []u8{4}

	key := [32]u8{0 = 7}

	assert(wa.state_store_set(&store, .Contact_Sync_Key, "04", key[:]).kind == .None)
	jid := "123@s.whatsapp.net"
	assert(wa.socket_lid_mapping_stage(&store, jid, "987@lid").kind == .None)
	page := wa.Contact_Sync_Page{store = &store}

	cursor: [136]u8
	for name in ([]string{"Test Person", "José Gómez"}) {
		patch: [8192]u8
		n, e := wa.encode_contact_add_patch(patch[:], &store, jid, name, key_id, cursor[:])
		testing.expect_value(t, e.kind, .None)
		if e.kind != .None {return}

		err := wa.apply_authenticated_contact_batch(nil, &page, patch[:n], false)
		testing.expect_value(t, err.kind, .None)
		contact, found := wa.contact_by_jid(&store, "987@lid")
		testing.expect(t, found && contact.jid == jid && contact.full_name == name)
		cursor[7] = u8(page.version)
		copy(cursor[8:], page.hash[:])
	}

	testing.expect_value(t, page.version, 2)
	dst: [8]u8
	_, short := wa.encode_contact_add_patch(dst[:], &store, jid, "Test", key_id, cursor[:])
	testing.expect_value(t, short.kind, .Invalid_Config)
	testing.expect_value(t, wa.socket_add_contact(nil, "123@g.us", "Test").kind, .Invalid_Config)
}

@(test)
external_history_chunk_uses_remaining_query_budget :: proc(t: ^testing.T) {
	socket: wa.Socket
	socket.config.query_timeout = time.Minute
	socket.config.http_execute = proc(_: surf.Request, config: surf.Config) -> (surf.Response, surf.HTTP_Error) {
		assert(config.timeout > 0 && config.timeout <= time.Second)
		return {status = 503}, {}
	}

	digest: [32]u8
	source := wa.Media_Message{
		kind = .History, direct_path = "/fixture", media_key = digest[:],
		file_sha256 = digest[:], file_enc_sha256 = digest[:], has_file_length = true,
	}

	socket.history_deadline = time.time_add(time.now(), time.Second)
	_, e := wa.download_contact_media(&socket, source)
	testing.expect_value(t, e.kind, .Media_Failed)
	testing.expect_value(t, e.media.kind, .HTTP_Status)

	socket.history_deadline = time.time_add(time.now(), -time.Second)
	_, expired := wa.download_contact_media(&socket, source)
	testing.expect_value(t, expired.kind, .Query_Timeout)
}

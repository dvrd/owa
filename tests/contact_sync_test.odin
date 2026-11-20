package whatsapp_test

import "core:testing"
import test_fixtures "fixtures/client"
import wa "shared:whatsapp"

@(test)
contact_sync_rejects_forged_records_and_collection_signatures :: proc(t: ^testing.T) {
	raw := test_fixtures.codec_api_hex(string(#load("fixtures/contact_sync/snapshot.hex")))
	share := test_fixtures.codec_api_hex(string(#load("fixtures/contact_sync/key-share.hex")))
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

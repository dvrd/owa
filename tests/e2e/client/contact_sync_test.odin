package whatsapp_test

import test_fixtures "../../fixtures/client"
import "core:bytes"
import "core:testing"
import wa "shared:whatsapp"

// Independently generated protobuf, AES-CBC, HKDF and HMAC vectors for two
// contacts. The key share comes from the linked account, not from a chat.
@(test)
contact_sync_searches_saved_names_and_resumes_after_restart :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	testing.expect_value(
		t,
		wa.state_store_set(&peer.store, .LID_Mapping, "self", transmute([]u8)string("777:1@lid")).kind,
		wa.State_Error_Kind.None,
	)
	jids, initial, query_err := wa.search_contact_jids(&peer.store, "Daniel")
	defer delete(jids)
	testing.expect_value(t, initial, wa.Contact_Sync_Status.Syncing)
	testing.expect_value(t, query_err.kind, wa.State_Error_Kind.None)
	testing.expect_value(t, len(jids), 0)

	share := test_fixtures.codec_api_hex(string(#load("../../fixtures/contact_sync/key-share.hex")))

	history := test_fixtures.codec_api_hex(string(#load("../../fixtures/contact_sync/profile-history.hex")))
	testing.expect_value(
		t,
		wa.store_historical_contact_profiles(&peer.socket, &peer.store, history).kind,
		wa.Socket_Error_Kind.None,
	)
	profile_only, known := wa.contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect(
		t,
		known && !profile_only.is_saved && profile_only.profile_name == "Public nickname",
	)
	raw := test_fixtures.codec_api_hex(string(#load("../../fixtures/contact_sync/snapshot.hex")))
	cipher := make([]u8, len(raw) + 32)
	defer delete(cipher)
	n, meta, encrypted := wa.media_encrypt(cipher, raw, .App_State, [32]u8{0 = 1})
	testing.expect_value(t, encrypted.kind, wa.Media_Error_Kind.None)
	download := test_fixtures.Download_State {
		encrypted = cipher[:n],
	}
	previous := context.user_ptr
	context.user_ptr = &download
	defer context.user_ptr = previous
	peer.socket.config.http_execute = test_fixtures.download_http
	ref: [256]u8
	writer := wa.Protobuf_Writer {
		dst = ref[:],
	}
	wa.protobuf_write_bytes(&writer, 1, meta.media_key[:])
	wa.protobuf_write_string(&writer, 2, "/test/snapshot")
	// The external reference can omit the plaintext file length.
	wa.protobuf_write_bytes(&writer, 5, meta.file_sha256[:])
	wa.protobuf_write_bytes(&writer, 6, meta.file_enc_sha256[:])
	base := []wa.Binary_Node_Attribute{{"name", wa.CONTACT_COLLECTION}}
	initial_reply := wa.Binary_Node {
		tag     = "collection",
		attrs   = base,
		content = []wa.Binary_Node{{tag = "snapshot", content = ref[:writer.at]}},
	}
	peer.contact_replies = []wa.Binary_Node{initial_reply, initial_reply}
	peer.contact_versions = []string{"", ""}
	waiting, missing_error := wa.socket_sync_contacts(&peer.socket)
	testing.expect(t, waiting == .Syncing && missing_error.kind == .None && !peer.failed)
	testing.expect(t, peer.last_size > 0 && peer.durable)
	if peer.failed || peer.last_size == 0 {
		return
	}
	request := wa.unwrap_protocol_message(peer.last_plain[:peer.last_size], 0)
	type_field, valid_type := wa.read_unique_protobuf_field(request, 2, 0)
	key_request, _ := wa.read_unique_protobuf_field(request, 8, 2)
	key_id, _ := wa.read_unique_protobuf_field(key_request.data, 1, 2)
	key_bytes, _ := wa.read_unique_protobuf_field(key_id.data, 1, 2)
	testing.expect(
		t,
		valid_type && type_field.value == 7 && bytes.equal(key_bytes.data, []u8{0, 1}),
	)
	// The primary device answers on the ratchet established by the key request.
	payload, encoded_share: [512]u8
	envelope := wa.Protobuf_Writer {
		dst = payload[:],
	}
	wa.protobuf_write_bytes(&envelope, 12, share)
	padded := wa.pad_outbound_message(payload[:envelope.at])
	defer delete(padded)
	_, wire_size, signal_err := wa.signal_session_encrypt(
		&peer.pairwise[0],
		encoded_share[:],
		padded,
		peer.pairwise[0].remote_identity_public,
	)
	testing.expect_value(t, signal_err.kind, wa.Signal_Session_Error_Kind.None)
	share_stanza := wa.Binary_Node {
		tag     = "message",
		attrs   = []wa.Binary_Node_Attribute{{"from", "111@s.whatsapp.net"}, {"id", "key-share"}},
		content = []wa.Binary_Node {
			{
				tag = "enc",
				attrs = []wa.Binary_Node_Attribute{{"type", "msg"}, {"v", "2"}},
				content = encoded_share[:wire_size],
			},
		},
	}
	share_event, share_err := wa.socket_process_message(&peer.socket, share_stanza, nil)
	testing.expect(t, share_event.kind == .None && share_err.kind == .None)
	status, err := wa.socket_sync_contacts(&peer.socket)
	testing.expect_value(t, err.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, status, wa.Contact_Sync_Status.Ready)
	found, _, e := wa.search_contact_jids(&peer.store, " DaNiEL ")
	defer delete(found)
	testing.expect_value(t, e.kind, wa.State_Error_Kind.None)
	testing.expect(t, len(found) == 2 && found[0] == "123@s.whatsapp.net" && found[1] == "456@lid")
	contact, ok := wa.contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect(
		t,
		ok &&
		contact.is_saved &&
		contact.full_name == "Daniel Mesa" &&
		contact.profile_name == "Public nickname",
	)
	alias, matched := wa.contact_by_jid(&peer.store, "999@lid")
	testing.expect(
		t,
		matched && alias.jid == contact.jid && alias.profile_name == contact.profile_name,
	)
	profiles, _, _ := wa.search_contact_jids(&peer.store, "Public nickname")
	defer delete(profiles)
	testing.expect_value(t, len(profiles), 0)
	identity := peer.store.identity
	wa.state_store_clear(&peer.store)
	testing.expect_value(
		t,
		wa.state_store_load(&peer.store, peer.path, identity).kind,
		wa.State_Error_Kind.None,
	)
	again, after_restart, _ := wa.search_contact_jids(&peer.store, "Daniel")
	defer delete(again)
	testing.expect(t, len(again) == 2 && after_restart == .Ready)

	update := wa.Binary_Node {
		tag     = "notification",
		attrs   = []wa.Binary_Node_Attribute{{"type", "server_sync"}},
		content = []wa.Binary_Node {
			{
				tag = "collection",
				attrs = []wa.Binary_Node_Attribute{{"name", wa.CONTACT_COLLECTION}, {"version", "3"}},
			},
		},
	}
	testing.expect_value(
		t,
		wa.socket_note_contact_update(&peer.socket, update).kind,
		wa.Socket_Error_Kind.None,
	)
	testing.expect_value(t, wa.contact_sync_status(&peer.store), wa.Contact_Sync_Status.Syncing)
	rename := test_fixtures.codec_api_hex(string(#load("../../fixtures/contact_sync/rename.hex")))
	remove := test_fixtures.codec_api_hex(string(#load("../../fixtures/contact_sync/remove.hex")))
	invalid := make([]u8, len(rename))
	defer delete(invalid)
	copy(invalid, rename)
	patch_mac, _ := wa.read_unique_protobuf_field(invalid, 5, 2)
	patch_mac.data[0] ~= 1
	peer.contact_requests = 0
	patch_nodes := [3]wa.Binary_Node {
		{tag = "patch", content = invalid},
		{tag = "patch", content = rename},
		{tag = "patch", content = remove},
	}
	replies, patch_lists: [3]wa.Binary_Node
	more_attrs := []wa.Binary_Node_Attribute {
		{"name", wa.CONTACT_COLLECTION},
		{"has_more_patches", "true"},
	}
	for i in 0 ..< 3 {
		attrs := base
		if i == 1 {
			attrs = more_attrs
		}
		patch_lists[i] = {
			tag     = "patches",
			content = patch_nodes[i:i + 1],
		}
		replies[i] = {
			tag     = "collection",
			attrs   = attrs,
			content = patch_lists[i:i + 1],
		}
	}
	peer.contact_replies = replies[:]
	peer.contact_versions = []string{"1", "1", "2"}
	_, invalid_error := wa.socket_sync_contacts(&peer.socket)
	testing.expect_value(t, invalid_error.kind, wa.Socket_Error_Kind.Protocol_Error)
	unchanged, _ := wa.contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect_value(t, unchanged.full_name, "Daniel Mesa")
	final_status, final_error := wa.socket_sync_contacts(&peer.socket)
	testing.expect_value(t, final_error.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, final_status, wa.Contact_Sync_Status.Ready)
	none, complete, _ := wa.search_contact_jids(&peer.store, "Daniel")
	defer delete(none)
	testing.expect(t, len(none) == 0 && complete == .Ready)
	renamed, _ := wa.contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect(
		t,
		renamed.full_name == "Dani Mesa" && renamed.profile_name == "Public nickname",
	)
	_, deleted := wa.contact_by_jid(&peer.store, "456@lid")
	testing.expect(t, !deleted && !peer.failed)
}

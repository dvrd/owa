package whatsapp_test

import test_fixtures "../../fixtures/client"
import "core:bytes"
import "core:testing"
import "shared:async/http"
import network_client "shared:surf"
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
	download := Contact_Download_Test{store = &peer.store, download = {encrypted = cipher[:n]}}
	previous := context.user_ptr
	context.user_ptr = &download
	defer context.user_ptr = previous
	peer.socket.config.http_execute = contact_download_during_update
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
	legacy_cursor: [136]u8
	legacy_cursor[7] = 1
	old_hint := [8]u8{0 = 255}
	assert(wa.state_store_set(&peer.store, .Contact_Sync_State, "required-version", old_hint[:]).kind == .None)
	assert(wa.state_store_set(&peer.store, .Contact_Sync_State, "cursor", legacy_cursor[:]).kind == .None)
	assert(wa.state_store_set(&peer.store, .Contact_Sync_State, "ready", []u8{1}).kind == .None)
	assert(wa.state_store_set(&peer.store, .Contact_Name, "800@lid", transmute([]u8)string("Stale\x00\x00")).kind == .None)
	testing.expect_value(t, wa.contact_sync_status(&peer.store), .Syncing)
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
	// Deliver an encrypted direct message before the second IQ reply.
	text := wa.pad_outbound_message([]u8{10, 2, 'h', 'i'})
	defer delete(text)
	_, text_size, text_error := wa.signal_session_encrypt(
		&peer.pairwise[0], encoded_share[:], text, peer.pairwise[0].remote_identity_public,
	)
	assert(text_error.kind == .None)
	incoming := share_stanza
	incoming.attrs = []wa.Binary_Node_Attribute{{"from", "111@s.whatsapp.net"}, {"id", "during-contact-sync"}, {"recipient", "333@s.whatsapp.net"}}
	incoming.content.([]wa.Binary_Node)[0].content = encoded_share[:text_size]
	send_peer_enqueue(peer, incoming)
	status, err := wa.socket_sync_contacts(&peer.socket)
	testing.expect_value(t, err.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, status, wa.Contact_Sync_Status.Ready)
	_, stale := wa.contact_by_jid(&peer.store, "800@lid")
	testing.expect(t, !stale)
	live, exists := wa.contact_by_jid(&peer.store, "888@lid")
	testing.expect(t, exists && live.profile_name == "Live name")
	ready, poll_error := wa.socket_poll(&peer.socket, 0)
	testing.expect(t, ready && poll_error.kind == .None)
	event, receive_error := wa.socket_receive(&peer.socket)
	assert(receive_error.kind == .None && event.message != nil)
	testing.expect_value(t, event.message.id, "during-contact-sync")
	testing.expect_value(t, event.message.recipient, "333@s.whatsapp.net")
	assert(wa.socket_inbox_restore(&peer.socket).kind == .None)
	restored_event, restored_error := wa.socket_read(&peer.socket)
	assert(restored_error.kind == .None && restored_event.message != nil)
	testing.expect_value(t, restored_event.message.recipient, "333@s.whatsapp.net")
	wa.socket_message_destroy(restored_event.message)
	wa.socket_message_destroy(event.message)
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
		attrs   = []wa.Binary_Node_Attribute{{"type", "server_sync"}, {"from", "@s.whatsapp.net"}, {"id", "update-3"}},
		content = []wa.Binary_Node {
			{
				tag = "collection",
				attrs = []wa.Binary_Node_Attribute{{"name", wa.CONTACT_COLLECTION}, {"version", "3"}},
			},
		},
	}
	for attrs in ([][]wa.Binary_Node_Attribute{
		{{"type", "server_sync"}, {"from", "@s.whatsapp.net"}},
		{{"type", "server_sync"}, {"id", "missing-origin"}},
		{{"type", "server_sync"}, {"from", "111@s.whatsapp.net"}, {"id", "unexpected-origin"}},
	}) {
		invalid := update
		invalid.attrs = attrs
		before := peer.store.revision
		testing.expect_value(t, wa.socket_note_contact_update(&peer.socket, invalid).kind, .Protocol_Error)
		testing.expect_value(t, peer.store.revision, before)
		testing.expect_value(t, wa.contact_sync_status(&peer.store), .Ready)
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

// Simulate a live store update at the same point where the native worker
// allows the socket pump to process incoming messages.
Contact_Download_Test :: struct {
	download: test_fixtures.Download_State,
	store: ^wa.State_Store,
}

contact_download_during_update :: proc(request: http.Request, config: network_client.Config) -> (network_client.Response, network_client.HTTP_Error) {
	state := cast(^Contact_Download_Test)context.user_ptr
	assert(wa.state_store_set(state.store, .Contact_Profile, "888@lid", transmute([]u8)string("Live name" if state.download.calls > 0 else "Initial")).kind == .None)
	context.user_ptr = &state.download
	return test_fixtures.download_http(request, config)
}

@(test)
external_profile_history_resumes_and_preserves_incoming_updates :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	notification := test_fixtures.codec_api_hex(string(#load("../../fixtures/contact_sync/profile-history.hex")))
	inline, valid := wa.read_unique_protobuf_field(notification, 11, 2)
	assert(valid && inline.number != 0)
	cipher := make([]u8, len(inline.data) + 32)
	defer delete(cipher)
	n, meta, encrypted := wa.media_encrypt(cipher, inline.data, .History, [32]u8{0 = 1})
	assert(encrypted.kind == .None)
	ref: [256]u8
	w := wa.Protobuf_Writer{dst = ref[:]}
	wa.protobuf_write_bytes(&w, 1, meta.file_sha256[:])
	wa.protobuf_write_uint(&w, 2, meta.file_length)
	wa.protobuf_write_bytes(&w, 3, meta.media_key[:])
	wa.protobuf_write_bytes(&w, 4, meta.file_enc_sha256[:])
	wa.protobuf_write_string(&w, 5, "/test/profiles")
	wa.protobuf_write_uint(&w, 6, 4)
	assert(wa.store_historical_contact_profiles(&peer.socket, &peer.store, ref[:w.at], pending_name = "history-id").kind == .None)
	assert(wa.state_store_save(&peer.store, peer.path).kind == .None)
	identity := peer.store.identity
	assert(wa.state_store_load(&peer.store, peer.path, identity).kind == .None)
	state := Contact_Download_Test{store = &peer.store, download = {encrypted = cipher[:n], status = 503}}
	context.user_ptr = &state
	peer.socket.config.http_execute = contact_download_during_update
	testing.expect_value(t, wa.socket_import_pending_contact_history(&peer.socket).kind, .Media_Failed)
	_, pending := wa.state_store_get(&peer.store, .Pending_Profile_History, "history-id")
	testing.expect(t, pending)
	state.download.status = 0
	testing.expect_value(t, wa.socket_import_pending_contact_history(&peer.socket).kind, .None)
	assert(wa.state_store_load(&peer.store, peer.path, identity).kind == .None)
	_, pending = wa.state_store_get(&peer.store, .Pending_Profile_History, "history-id")
	older, known := wa.contact_by_jid(&peer.store, "123@s.whatsapp.net")
	current, live := wa.contact_by_jid(&peer.store, "888@lid")
	testing.expect(t, !pending && known && live && older.profile_name == "Public nickname" && current.profile_name == "Live name")
}

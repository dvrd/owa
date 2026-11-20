package whatsapp

import "core:bytes"
import "core:testing"

// Independently generated protobuf, AES-CBC, HKDF and HMAC vectors for two
// contacts. The key share comes from the linked account, not from a chat.
@(test)
contact_sync_searches_saved_names_and_resumes_after_restart :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	testing.expect_value(
		t,
		state_store_set(&peer.store, .LID_Mapping, "self", transmute([]u8)string("777:1@lid")).kind,
		State_Error_Kind.None,
	)
	jids, initial, query_err := search_contact_jids(&peer.store, "Daniel")
	defer delete(jids)
	testing.expect_value(t, initial, Contact_Sync_Status.Syncing)
	testing.expect_value(t, query_err.kind, State_Error_Kind.None)
	testing.expect_value(t, len(jids), 0)

	share := codec_api_hex(string(#load("../tests/contact_sync/key-share.hex")))

	history := codec_api_hex(string(#load("../tests/contact_sync/profile-history.hex")))
	testing.expect_value(
		t,
		store_historical_contact_profiles(&peer.socket, &peer.store, history).kind,
		Socket_Error_Kind.None,
	)
	profile_only, known := contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect(
		t,
		known && !profile_only.is_saved && profile_only.profile_name == "Public nickname",
	)
	raw := codec_api_hex(string(#load("../tests/contact_sync/snapshot.hex")))
	cipher := make([]u8, len(raw) + 32)
	defer delete(cipher)
	n, meta, encrypted := media_encrypt(cipher, raw, .App_State, [32]u8{0 = 1})
	testing.expect_value(t, encrypted.kind, Media_Error_Kind.None)
	download := Download_State {
		encrypted = cipher[:n],
	}
	previous := context.user_ptr
	context.user_ptr = &download
	defer context.user_ptr = previous
	peer.socket.config.http_execute = download_http
	ref: [256]u8
	writer := Protobuf_Writer {
		dst = ref[:],
	}
	protobuf_write_bytes(&writer, 1, meta.media_key[:])
	protobuf_write_string(&writer, 2, "/test/snapshot")
	// The external reference can omit the plaintext file length.
	protobuf_write_bytes(&writer, 5, meta.file_sha256[:])
	protobuf_write_bytes(&writer, 6, meta.file_enc_sha256[:])
	base := []Binary_Node_Attribute{{"name", CONTACT_COLLECTION}}
	initial_reply := Binary_Node {
		tag     = "collection",
		attrs   = base,
		content = []Binary_Node{{tag = "snapshot", content = ref[:writer.at]}},
	}
	peer.contact_replies = []Binary_Node{initial_reply, initial_reply}
	peer.contact_versions = []string{"", ""}
	waiting, missing_error := socket_sync_contacts(&peer.socket)
	testing.expect(t, waiting == .Syncing && missing_error.kind == .None && !peer.failed)
	testing.expect(t, peer.last_size > 0 && peer.durable)
	if peer.failed || peer.last_size == 0 {
		return
	}
	request := unwrap_protocol_message(peer.last_plain[:peer.last_size], 0)
	type_field, valid_type := read_unique_protobuf_field(request, 2, 0)
	key_request, _ := read_unique_protobuf_field(request, 8, 2)
	key_id, _ := read_unique_protobuf_field(key_request.data, 1, 2)
	key_bytes, _ := read_unique_protobuf_field(key_id.data, 1, 2)
	testing.expect(
		t,
		valid_type && type_field.value == 7 && bytes.equal(key_bytes.data, []u8{0, 1}),
	)
	// The primary device answers on the ratchet established by the key request.
	payload, encoded_share: [512]u8
	envelope := Protobuf_Writer {
		dst = payload[:],
	}
	protobuf_write_bytes(&envelope, 12, share)
	padded := pad_outbound_message(payload[:envelope.at])
	defer delete(padded)
	_, wire_size, signal_err := signal_session_encrypt(
		&peer.pairwise[0],
		encoded_share[:],
		padded,
		peer.pairwise[0].remote_identity_public,
	)
	testing.expect_value(t, signal_err.kind, Signal_Session_Error_Kind.None)
	share_stanza := Binary_Node {
		tag     = "message",
		attrs   = []Binary_Node_Attribute{{"from", "111@s.whatsapp.net"}, {"id", "key-share"}},
		content = []Binary_Node {
			{
				tag = "enc",
				attrs = []Binary_Node_Attribute{{"type", "msg"}, {"v", "2"}},
				content = encoded_share[:wire_size],
			},
		},
	}
	share_event, share_err := socket_process_message(&peer.socket, share_stanza, nil)
	testing.expect(t, share_event.kind == .None && share_err.kind == .None)
	status, err := socket_sync_contacts(&peer.socket)
	testing.expect_value(t, err.kind, Socket_Error_Kind.None)
	testing.expect_value(t, status, Contact_Sync_Status.Ready)
	found, _, e := search_contact_jids(&peer.store, " DaNiEL ")
	defer delete(found)
	testing.expect_value(t, e.kind, State_Error_Kind.None)
	testing.expect(t, len(found) == 2 && found[0] == "123@s.whatsapp.net" && found[1] == "456@lid")
	contact, ok := contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect(
		t,
		ok &&
		contact.is_saved &&
		contact.full_name == "Daniel Mesa" &&
		contact.profile_name == "Public nickname",
	)
	alias, matched := contact_by_jid(&peer.store, "999@lid")
	testing.expect(
		t,
		matched && alias.jid == contact.jid && alias.profile_name == contact.profile_name,
	)
	profiles, _, _ := search_contact_jids(&peer.store, "Public nickname")
	defer delete(profiles)
	testing.expect_value(t, len(profiles), 0)
	identity := peer.store.identity
	state_store_clear(&peer.store)
	testing.expect_value(
		t,
		state_store_load(&peer.store, peer.path, identity).kind,
		State_Error_Kind.None,
	)
	again, after_restart, _ := search_contact_jids(&peer.store, "Daniel")
	defer delete(again)
	testing.expect(t, len(again) == 2 && after_restart == .Ready)

	update := Binary_Node {
		tag     = "notification",
		attrs   = []Binary_Node_Attribute{{"type", "server_sync"}},
		content = []Binary_Node {
			{
				tag = "collection",
				attrs = []Binary_Node_Attribute{{"name", CONTACT_COLLECTION}, {"version", "3"}},
			},
		},
	}
	testing.expect_value(
		t,
		socket_note_contact_update(&peer.socket, update).kind,
		Socket_Error_Kind.None,
	)
	testing.expect_value(t, contact_sync_status(&peer.store), Contact_Sync_Status.Syncing)
	rename := codec_api_hex(string(#load("../tests/contact_sync/rename.hex")))
	remove := codec_api_hex(string(#load("../tests/contact_sync/remove.hex")))
	invalid := make([]u8, len(rename))
	defer delete(invalid)
	copy(invalid, rename)
	patch_mac, _ := read_unique_protobuf_field(invalid, 5, 2)
	patch_mac.data[0] ~= 1
	peer.contact_requests = 0
	patch_nodes := [3]Binary_Node {
		{tag = "patch", content = invalid},
		{tag = "patch", content = rename},
		{tag = "patch", content = remove},
	}
	replies, patch_lists: [3]Binary_Node
	more_attrs := []Binary_Node_Attribute {
		{"name", CONTACT_COLLECTION},
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
	_, invalid_error := socket_sync_contacts(&peer.socket)
	testing.expect_value(t, invalid_error.kind, Socket_Error_Kind.Protocol_Error)
	unchanged, _ := contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect_value(t, unchanged.full_name, "Daniel Mesa")
	final_status, final_error := socket_sync_contacts(&peer.socket)
	testing.expect_value(t, final_error.kind, Socket_Error_Kind.None)
	testing.expect_value(t, final_status, Contact_Sync_Status.Ready)
	none, complete, _ := search_contact_jids(&peer.store, "Daniel")
	defer delete(none)
	testing.expect(t, len(none) == 0 && complete == .Ready)
	renamed, _ := contact_by_jid(&peer.store, "123@s.whatsapp.net")
	testing.expect(
		t,
		renamed.full_name == "Dani Mesa" && renamed.profile_name == "Public nickname",
	)
	_, deleted := contact_by_jid(&peer.store, "456@lid")
	testing.expect(t, !deleted && !peer.failed)
}

@(test)
contact_sync_rejects_forged_records_and_collection_signatures :: proc(t: ^testing.T) {
	raw := codec_api_hex(string(#load("../tests/contact_sync/snapshot.hex")))
	share := codec_api_hex(string(#load("../tests/contact_sync/key-share.hex")))
	// Locate each signed part in the independent vector and change one byte.
	for target in 0 ..< 3 {
		checkpoint := make([]u8, len(raw))
		defer delete(checkpoint)
		copy(checkpoint, raw)
		if target == 2 {
			signature, valid := read_unique_protobuf_field(checkpoint, 3, 2)
			testing.expect(t, valid)
			signature.data[0] ~= 1
		} else {
			at := 0
			for at < len(checkpoint) {
				record, _ := protobuf_field_read(checkpoint, &at)
				if record.number != 2 {
					continue
				}
				part, _ := read_unique_protobuf_field(record.data, u32(target + 1), 2)
				blob, _ := read_unique_protobuf_field(part.data, 1, 2)
				blob.data[0] ~= 1
				break
			}
		}
		store: State_Store
		testing.expect_value(
			t,
			state_store_init(&store, [32]u8{0 = 1}).kind,
			State_Error_Kind.None,
		)
		defer state_store_clear(&store)
		testing.expect_value(
			t,
			store_contact_sync_key_share(&store, share).kind,
			Socket_Error_Kind.None,
		)
		staged: State_Store
		defer state_store_clear(&staged)
		testing.expect_value(t, socket_store_clone(&staged, &store).kind, Socket_Error_Kind.None)
		page := Contact_Sync_Page {
			store = &staged,
		}
		error := apply_authenticated_contact_batch(nil, &page, checkpoint, true)
		testing.expect_value(t, error.kind, Socket_Error_Kind.Protocol_Error)
		found, status, _ := search_contact_jids(&store, "Daniel")
		defer delete(found)
		testing.expect(t, len(found) == 0 && status == .Syncing)
	}
}

package whatsapp

import "core:bytes"
import "core:crypto"
import "core:crypto/hkdf"
import "core:crypto/hmac"
import "core:encoding/base64"
import "core:encoding/endian"
import "core:encoding/hex"
import "core:encoding/json"
import "core:fmt"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:time"
import network_client "shared:surf"
import zlib "vendor:zlib"

CONTACT_COLLECTION :: "critical_unblock_low"

Contact_Sync_Page :: struct {
	store:        ^State_Store,
	version:      u64,
	hash:         [128]u8,
	missing_id:   [128]u8,
	missing_size: int,
}

// Read one singular protobuf field. Empty optional fields can be distinguished
// from a missing field by number. Unknown fields are skipped by the wire reader.
read_unique_protobuf_field :: proc(
	data: []u8,
	number: u32,
	wire: u8,
) -> (
	field: Protobuf_Field,
	ok: bool,
) {
	at := 0
	for at < len(data) {
		f, err := protobuf_field_read(data, &at)
		if err != .None {
			return {}, false
		}
		if f.number != number {
			continue
		}
		if f.wire_type != wire || field.number != 0 {
			return {}, false
		}
		field = f
	}
	return field, true
}

store_contact_sync_key_share :: proc(store: ^State_Store, protocol: []u8) -> Socket_Error {
	kind, valid_kind := read_unique_protobuf_field(protocol, 2, 0)
	if !valid_kind || kind.value != 6 {
		return {}
	}
	share, valid := read_unique_protobuf_field(protocol, 7, 2)
	if !valid || share.number == 0 {
		return {kind = .Protocol_Error}
	}
	at := 0
	for at < len(share.data) {
		entry, e := protobuf_field_read(share.data, &at)
		if e != .None {
			return {kind = .Protocol_Error}
		}
		if entry.number != 1 {
			continue
		}
		id_message, valid_id_message := read_unique_protobuf_field(entry.data, 1, 2)
		key_message, valid_key_message := read_unique_protobuf_field(entry.data, 2, 2)
		id, valid_id := read_unique_protobuf_field(id_message.data, 1, 2)
		key, valid_key := read_unique_protobuf_field(key_message.data, 1, 2)
		if entry.wire_type != 2 ||
		   !(valid_id_message && valid_key_message && valid_id && valid_key) ||
		   len(id.data) == 0 ||
		   len(id.data) > 128 ||
		   len(key.data) != 32 {
			return {kind = .Protocol_Error}
		}
		name := hex.encode(id.data)
		defer delete(name)
		if old, known := state_store_get(store, .Contact_Sync_Key, string(name)); known {
			if !bytes.equal(old, key.data) {
				return {kind = .Protocol_Error}
			}
		} else if err := state_store_set(store, .Contact_Sync_Key, string(name), key.data);
		   err.kind != .None {
			return {kind = .State_Failed, state = err}
		}
	}
	return {}
}

derive_contact_mutation_keys :: proc(
	page: ^Contact_Sync_Page,
	key_id: []u8,
) -> (
	keys: [160]u8,
	ok: bool,
) {
	if len(key_id) == 0 || len(key_id) > len(page.missing_id) {
		return {}, false
	}
	name := hex.encode(key_id)
	defer delete(name)
	key, found := state_store_get(page.store, .Contact_Sync_Key, string(name))
	if !found {
		page.missing_size = copy(page.missing_id[:], key_id)
		return {}, false
	}
	if len(key) != 32 {
		return {}, false
	}
	hkdf.extract_and_expand(
		.SHA256,
		nil,
		key,
		transmute([]u8)string("WhatsApp Mutation Keys"),
		keys[:],
	)
	return keys, true
}

update_contact_collection_hash :: proc(page: ^Contact_Sync_Page, mac: []u8, subtract: bool) {
	expanded: [128]u8
	hkdf.extract_and_expand(
		.SHA256,
		nil,
		mac,
		transmute([]u8)string("WhatsApp Patch Integrity"),
		expanded[:],
	)
	for offset := 0; offset < len(expanded); offset += 2 {
		word := endian.unchecked_get_u16le(page.hash[offset:][:2])
		delta := endian.unchecked_get_u16le(expanded[offset:][:2])
		endian.unchecked_put_u16le(
			page.hash[offset:][:2],
			word - delta if subtract else word + delta,
		)
	}
}

apply_contact_action :: proc(store: ^State_Store, index, value: []u8, remove: bool) -> bool {
	parts: []string
	defer {
		for part in parts {delete(part)}
		delete(parts)
	}
	if len(index) > 4096 || json.unmarshal(index, &parts) != nil || len(parts) == 0 {
		return false
	}
	if parts[0] != "contact" {
		return true
	}
	if len(parts) != 2 || !device_user_jid_valid(parts[1], false) {
		return false
	}
	jid := parts[1]
	if remove {
		return state_store_delete(store, .Contact_Name, jid).kind == .None
	}
	action, ok := read_unique_protobuf_field(value, 3, 2)
	full, a := read_unique_protobuf_field(action.data, 1, 2)
	first, b := read_unique_protobuf_field(action.data, 2, 2)
	if !ok ||
	   !a ||
	   !b ||
	   action.number == 0 ||
	   !contact_name_valid(string(full.data)) ||
	   !contact_name_valid(string(first.data)) {
		return false
	}
	alias_field: u32 = 3 // lidJID for a phone-number index.
	if strings.has_suffix(jid, "@lid") {
		alias_field = 5
	} // pnJID for a LID index.
	alternate, valid_alias := read_unique_protobuf_field(action.data, alias_field, 2)
	alias := string(alternate.data)
	if !valid_alias ||
	   (alias != "" &&
			   (!device_user_jid_valid(alias, false) ||
					   strings.has_suffix(alias, "@lid") == strings.has_suffix(jid, "@lid"))) {
		return false
	}
	names := fmt.aprintf("%s\x00%s\x00%s", string(full.data), string(first.data), alias)
	defer delete(names)
	return state_store_set(store, .Contact_Name, jid, transmute([]u8)names).kind == .None
}

apply_contact_record :: proc(
	page: ^Contact_Sync_Page,
	record: []u8,
	operation: u64,
	patch_mac: ^hmac.Context,
) -> bool {
	idx, a := read_unique_protobuf_field(record, 1, 2)
	val, b := read_unique_protobuf_field(record, 2, 2)
	key, c := read_unique_protobuf_field(record, 3, 2)
	index_mac, d := read_unique_protobuf_field(idx.data, 1, 2)
	blob, e := read_unique_protobuf_field(val.data, 1, 2)
	id, f := read_unique_protobuf_field(key.data, 1, 2)
	if !(a && b && c && d && e && f) ||
	   len(index_mac.data) != 32 ||
	   len(blob.data) < 64 ||
	   operation > 1 {
		return false
	}
	keys, found := derive_contact_mutation_keys(page, id.data)
	defer crypto.zero_explicit(&keys, size_of(keys))
	if !found {
		return false
	}
	content := blob.data[:len(blob.data) - 32]
	value_mac := blob.data[len(content):]
	content_mac: hmac.Context
	hmac.init(&content_mac, .SHA512, keys[64:96])
	op := [1]u8{u8(operation + 1)}
	length: [8]u8
	endian.unchecked_put_u64be(length[:], u64(1 + len(id.data)))
	for part in ([]([]u8){op[:], id.data, content, length[:]}) {hmac.update(&content_mac, part)}
	expected: [64]u8
	hmac.final(&content_mac, expected[:])
	if crypto.compare_constant_time(expected[:32], value_mac) != 1 {
		return false
	}

	plaintext := make([]u8, len(content) - 16)
	defer {crypto.zero_explicit(raw_data(plaintext), len(plaintext)); delete(plaintext)}
	cipher_key: [32]u8
	defer crypto.zero_explicit(&cipher_key, 32)
	iv: [16]u8
	copy(cipher_key[:], keys[32:64])
	copy(iv[:], content[:16])
	n, err := signal_cbc_decrypt(plaintext, cipher_key, iv, content[16:])
	if err != .None {
		return false
	}
	index, g := read_unique_protobuf_field(plaintext[:n], 1, 2)
	action, h := read_unique_protobuf_field(plaintext[:n], 2, 2)
	if !g || !h || index.number == 0 {
		return false
	}
	if !hmac.verify(.SHA256, index_mac.data, index.data, keys[:32]) {
		return false
	}

	name := hex.encode(index_mac.data)
	defer delete(name)
	if previous, exists := state_store_get(page.store, .Contact_Index_MAC, string(name)); exists {
		if len(previous) != 32 {
			return false
		}
		update_contact_collection_hash(page, previous, true)
	}
	if operation == 0 {
		update_contact_collection_hash(page, value_mac, false)
		if state_store_set(page.store, .Contact_Index_MAC, string(name), value_mac).kind != .None {
			return false
		}
	} else if state_store_delete(page.store, .Contact_Index_MAC, string(name)).kind != .None {
		return false
	}
	if patch_mac != nil {
		hmac.update(patch_mac, value_mac)
	}
	return apply_contact_action(page.store, index.data, action.data, operation == 1)
}

download_contact_sync_blob :: proc(socket: ^Socket, reference: []u8) -> ([]u8, Socket_Error) {
	key, a := read_unique_protobuf_field(reference, 1, 2)
	path, b := read_unique_protobuf_field(reference, 2, 2)
	length, c := read_unique_protobuf_field(reference, 4, 0)
	plain, d := read_unique_protobuf_field(reference, 5, 2)
	cipher, e := read_unique_protobuf_field(reference, 6, 2)
	if !(a && b && c && d && e) || length.value > DEFAULT_MAX_MEDIA_SIZE {
		return nil, {kind = .Protocol_Error}
	}
	message := Media_Message {
		kind            = .App_State,
		media_key       = key.data,
		direct_path     = string(path.data),
		file_length     = length.value,
		has_file_length = length.number != 0,
		file_sha256     = plain.data,
		file_enc_sha256 = cipher.data,
	}
	return download_contact_media(socket, message)
}

apply_authenticated_contact_batch :: proc(
	socket: ^Socket,
	page: ^Contact_Sync_Page,
	data: []u8,
	snapshot: bool,
) -> Socket_Error {
	version_msg, a := read_unique_protobuf_field(data, 1, 2)
	version, b := read_unique_protobuf_field(version_msg.data, 1, 0)
	mac, c := read_unique_protobuf_field(data, 3 if snapshot else 4, 2)
	key, d := read_unique_protobuf_field(data, 4 if snapshot else 6, 2)
	id, e := read_unique_protobuf_field(key.data, 1, 2)
	if !(a && b && c && d && e) || len(mac.data) != 32 {
		return {kind = .Protocol_Error}
	}
	if snapshot {
		if page.version != 0 || version.number == 0 {
			return {kind = .Protocol_Error}
		}
		page.version = version.value
	} else {
		if page.version == max(u64) || (version.number != 0 && version.value != page.version + 1) {
			return {kind = .Protocol_Error}
		}
		page.version += 1
	}
	keys, ok := derive_contact_mutation_keys(page, id.data)
	defer crypto.zero_explicit(&keys, size_of(keys))
	if !ok {
		return {kind = .Protocol_Error}
	}

	records, repeated := data, u32(2)
	patch_digest: hmac.Context
	defer hmac.reset(&patch_digest)
	if !snapshot {
		external, valid := read_unique_protobuf_field(data, 3, 2)
		if !valid {
			return {kind = .Protocol_Error}
		}
		if external.number != 0 {
			var_error: Socket_Error
			records, var_error = download_contact_sync_blob(socket, external.data)
			if var_error.kind != .None {
				return var_error
			}
			repeated = 1
		}
		hmac.init(&patch_digest, .SHA256, keys[128:])
		hmac.update(&patch_digest, mac.data)
	}
	defer if repeated == 1 {
		delete(records)
	}

	at := 0
	for at < len(records) {
		f, err := protobuf_field_read(records, &at)
		if err != .None {
			return {kind = .Protocol_Error}
		}
		if f.number != repeated {
			continue
		}
		if f.wire_type != 2 {
			return {kind = .Protocol_Error}
		}
		if snapshot {
			if !apply_contact_record(page, f.data, 0, nil) {
				return {kind = .Protocol_Error}
			}
		} else {
			op, good_op := read_unique_protobuf_field(f.data, 1, 0)
			record, good_record := read_unique_protobuf_field(f.data, 2, 2)
			if !good_op ||
			   !good_record ||
			   !apply_contact_record(page, record.data, op.value, &patch_digest) {
				return {kind = .Protocol_Error}
			}
		}
	}
	version_bytes: [8]u8
	endian.unchecked_put_u64be(version_bytes[:], page.version)
	name := transmute([]u8)string(CONTACT_COLLECTION)
	expected: [32]u8
	if !snapshot {
		signed, valid := read_unique_protobuf_field(data, 5, 2)
		hmac.update(&patch_digest, version_bytes[:])
		hmac.update(&patch_digest, name)
		hmac.final(&patch_digest, expected[:])
		if !valid ||
		   len(signed.data) != 32 ||
		   crypto.compare_constant_time(expected[:], signed.data) != 1 {
			return {kind = .Protocol_Error}
		}
	}
	hmac.init(&patch_digest, .SHA256, keys[96:128])
	hmac.update(&patch_digest, page.hash[:])
	hmac.update(&patch_digest, version_bytes[:])
	hmac.update(&patch_digest, name)
	hmac.final(&patch_digest, expected[:])
	if crypto.compare_constant_time(expected[:], mac.data) != 1 {
		return {kind = .Protocol_Error}
	}
	return {}
}

apply_contact_collection :: proc(
	socket: ^Socket,
	page: ^Contact_Sync_Page,
	collection: Binary_Node,
) -> Socket_Error {
	nodes, is_list := collection.content.([]Binary_Node)
	if collection.content != nil && !is_list {
		return {kind = .Protocol_Error}
	}
	have_snapshot, have_patches := false, false
	for node in nodes {
		switch node.tag {
		case "snapshot":
			if have_snapshot || page.version != 0 {
				return {kind = .Protocol_Error}
			}
			have_snapshot = true
		case "patches":
			if have_patches {
				return {kind = .Protocol_Error}
			}
			have_patches = true
		case:
			return {kind = .Protocol_Error}
		}
	}
	if snapshot, ok := pairing_node_child(collection, "snapshot"); ok {
		ref, valid := snapshot.content.([]u8)
		if !valid {
			return {kind = .Protocol_Error}
		}
		raw, err := download_contact_sync_blob(socket, ref)
		if err.kind != .None {
			return err
		}
		defer delete(raw)
		if e := apply_authenticated_contact_batch(socket, page, raw, true); e.kind != .None {
			return e
		}
	}
	if patches, ok := pairing_node_child(collection, "patches"); ok {
		list, valid := patches.content.([]Binary_Node)
		if patches.content != nil && !valid {
			return {kind = .Protocol_Error}
		}
		for patch in list {
			raw, good := patch.content.([]u8)
			if patch.tag != "patch" || !good {
				return {kind = .Protocol_Error}
			}
			if e := apply_authenticated_contact_batch(socket, page, raw, false); e.kind != .None {
				return e
			}
		}
	}
	return {}
}

// Call after login and on a server_sync notification for critical_unblock_low.
// Each authenticated page commits atomically. A retry resumes at the last
// committed version. While awaiting keys, pump socket_receive and call again.
socket_sync_contacts :: proc(socket: ^Socket) -> (Contact_Sync_Status, Socket_Error) {
	if socket == nil ||
	   socket.phase != .Online ||
	   socket.store == nil ||
	   !socket.store.initialized {
		return .Syncing, {kind = .Invalid_State}
	}
	for _ in 0 ..< 64 {
		page := Contact_Sync_Page{}
		cursor, resumed := state_store_get(socket.store, .Contact_Sync_State, "cursor")
		if resumed {
			if len(cursor) != 136 {
				return .Syncing, {kind = .Protocol_Error}
			}
			page.version = endian.unchecked_get_u64be(cursor[:8])
			copy(page.hash[:], cursor[8:])
		}
		from_version := page.version
		version := fmt.aprintf("%d", from_version)
		defer delete(version)
		attrs := [3]Binary_Node_Attribute {
			{"name", CONTACT_COLLECTION},
			{"return_snapshot", "true"},
			{"version", version},
		}
		count := 2
		if from_version > 0 {
			attrs[1].value = "false"; count = 3
		}
		doc, err := socket_query(
			socket,
			{
				tag = "iq",
				attrs = []Binary_Node_Attribute {
					{"to", "@s.whatsapp.net"},
					{"type", "set"},
					{"xmlns", "w:sync:app:state"},
				},
				content = []Binary_Node {
					{
						tag = "sync",
						content = []Binary_Node{{tag = "collection", attrs = attrs[:count]}},
					},
				},
			},
		)
		if err.kind != .None {
			return .Syncing, err
		}
		defer binary_document_destroy(&doc)
		response_id, _ := node_attr(doc.root, "id")
		if checked := device_response_validate(doc.root, response_id); checked.kind != .None {
			return .Syncing, {kind = .Device_Failed, device = checked}
		}
		sync, a := device_unique_child(doc.root, "sync")
		collection, b := device_unique_child(sync, "collection")
		name, _ := node_attr(collection, "name")
		more, _ := node_attr(collection, "has_more_patches")
		if a.kind != .None ||
		   b.kind != .None ||
		   name != CONTACT_COLLECTION ||
		   (more != "" && more != "true" && more != "false") {
			return .Syncing, {kind = .Protocol_Error}
		}
		if kind, _ := node_attr(collection, "type"); kind == "error" {
			return .Syncing, {kind = .Server_Rejected}
		}
		candidate: State_Store
		defer state_store_clear(&candidate)
		if e := socket_store_clone(&candidate, socket.store); e.kind != .None {
			return .Syncing, e
		}
		page.store = &candidate
		if e := apply_contact_collection(socket, &page, collection); e.kind != .None {
			if page.missing_size > 0 {
				return .Syncing, socket_request_contact_key(
					socket,
					page.missing_id[:page.missing_size],
				)
			}
			return .Syncing, e
		}
		if more == "true" && page.version <= from_version {
			return .Syncing, {kind = .Protocol_Error}
		}
		buf: [136]u8
		endian.unchecked_put_u64be(buf[:8], page.version)
		copy(buf[8:], page.hash[:])
		if e := state_store_set(&candidate, .Contact_Sync_State, "cursor", buf[:]);
		   e.kind != .None {
			return .Syncing, {kind = .State_Failed, state = e}
		}
		status: State_Error
		required, _ := state_store_get(&candidate, .Contact_Sync_State, "required-version")
		behind := len(required) == 8 && endian.unchecked_get_u64be(required) > page.version
		if more == "true" || behind {
			status = state_store_delete(&candidate, .Contact_Sync_State, "ready")
		} else {
			status = state_store_set(&candidate, .Contact_Sync_State, "ready", []u8{1})
		}
		if status.kind != .None {
			return .Syncing, {kind = .State_Failed, state = status}
		}
		if e := socket_store_commit(socket, &candidate); e.kind != .None {
			return .Syncing, e
		}
		if more != "true" {
			return .Syncing if behind else .Ready, {}
		}
	}
	return .Syncing, {}
}

// Send the missing key ID only to the account's primary device. Commit the
// advanced pairwise ratchet together with the exact stanza before transmission.
socket_request_contact_key :: proc(socket: ^Socket, key_id: []u8) -> Socket_Error {
	if socket.auth == nil || len(key_id) == 0 || len(key_id) > 128 {
		return {kind = .Invalid_State}
	}
	now := time.now()
	if bytes.equal(socket.contact_key_requested[:socket.contact_key_size], key_id) &&
	   time.diff(now, socket.contact_key_retry_after) > 0 {
		return {}
	}
	me := string(socket.auth.account.jid[:socket.auth.account.jid_size])
	user, _, e := pairing_jid_decode(me)
	if e.kind != .None {
		return {kind = .Invalid_State}
	}
	server := "@lid" if strings.has_suffix(me, "@lid") else "@s.whatsapp.net"
	jid := fmt.aprintf("%s%s", user, server)
	defer delete(jid)
	id_buf, req_buf, protocol_buf, msg_buf: [256]u8
	id_writer := Protobuf_Writer {
		dst = id_buf[:],
	}
	protobuf_write_bytes(&id_writer, 1, key_id)
	req_writer := Protobuf_Writer {
		dst = req_buf[:],
	}
	protobuf_write_bytes(&req_writer, 1, id_buf[:id_writer.at])
	protocol_writer := Protobuf_Writer {
		dst = protocol_buf[:],
	}
	protobuf_write_uint(&protocol_writer, 2, 7)
	protobuf_write_bytes(&protocol_writer, 8, req_buf[:req_writer.at])
	msg_writer := Protobuf_Writer {
		dst = msg_buf[:],
	}
	protobuf_write_bytes(&msg_writer, 12, protocol_buf[:protocol_writer.at])
	padded := pad_outbound_message(msg_buf[:msg_writer.at])
	defer delete(padded)
	session := new(Signal_Session)
	defer {signal_session_clear(session); free(session)}
	encryption_jid := jid
	owned_lid: string
	defer delete(owned_lid)
	if own_lid, known := state_store_get(socket.store, .LID_Mapping, "self");
	   known && strings.has_suffix(jid, "@s.whatsapp.net") {
		lid_user, _, invalid := pairing_jid_decode(string(own_lid))
		if invalid.kind != .None || !strings.has_suffix(string(own_lid), "@lid") {
			return {kind = .Protocol_Error}
		}
		owned_lid = fmt.aprintf("%s@lid", lid_user)
		if err := socket_record_lid_mapping(socket, jid, owned_lid); err.kind != .None {
			return err
		}
		// Keep an owned value across the prekey IQ, which can replace the store.
		encryption_jid = owned_lid
	}
	if err := socket_outgoing_session(socket, encryption_jid, session); err.kind != .None {
		return err
	}
	cipher: [2048]u8
	kind, n, encrypt_err := signal_session_encrypt(
		session,
		cipher[:],
		padded,
		session.remote_identity_public,
	)
	if encrypt_err.kind != .None {
		return {kind = .Signal_Failed, signal = encrypt_err}
	}
	id := generate_outbound_message_id()
	defer delete(id)
	enc_type := "pkmsg" if kind == .Prekey else "msg"
	children := [3]Binary_Node {
		{tag = "meta", attrs = []Binary_Node_Attribute{{"appdata", "default"}}},
		{
			tag = "enc",
			attrs = []Binary_Node_Attribute{{"v", "2"}, {"type", enc_type}},
			content = cipher[:n],
		},
		{},
	}
	count := 2
	identity: [2048]u8
	if kind == .Prekey {
		acc := &socket.auth.account
		size, error := pairing_signed_identity_encode(
			identity[:],
			{
				details = acc.details[:acc.details_size],
				account_signature_key = acc.account_signature_key[:],
				account_signature = acc.account_signature[:],
				device_signature = acc.device_signature[:],
			},
			true,
		)
		if error != .None {
			return {kind = .Protocol_Error}
		}
		children[2] = {
			tag     = "device-identity",
			content = identity[:size],
		}
		count = 3
	}
	node := Binary_Node {
		tag     = "message",
		attrs   = []Binary_Node_Attribute {
			{"id", id},
			{"type", "text"},
			{"category", "peer"},
			{"to", jid},
			{"push_priority", "high"},
		},
		content = children[:count],
	}
	wire: [8192]u8
	size, error := binary_node_encode(wire[:], node)
	if error.kind != .None {
		return {kind = .Binary_Failed, binary = error}
	}
	candidate: State_Store
	defer state_store_clear(&candidate)
	if err := socket_store_clone(&candidate, socket.store); err.kind != .None {
		return err
	}
	staged := new(Socket)
	defer free(staged)
	staged.store = &candidate
	if err := socket_stage_session(staged, encryption_jid, session); err.kind != .None {
		return err
	}
	if err := state_store_set(&candidate, .Outbound_Message, id, wire[:size]); err.kind != .None {
		return {kind = .State_Failed, state = err}
	}
	if err := socket_store_commit(socket, &candidate); err.kind != .None {
		return err
	}
	if err := socket_write(socket, wire[:size]); err.kind != .None {
		return err
	}
	socket.contact_key_size = copy(socket.contact_key_requested[:], key_id)
	socket.contact_key_retry_after = time.time_add(now, time.Minute)
	return {}
}

socket_note_contact_update :: proc(socket: ^Socket, node: Binary_Node) -> Socket_Error {
	kind, _ := node_attr(node, "type")
	if node.tag != "notification" || kind != "server_sync" {
		return {}
	}
	children, _ := node.content.([]Binary_Node)
	for collection in children {
		name, _ := node_attr(collection, "name")
		if collection.tag != "collection" || name != CONTACT_COLLECTION {
			continue
		}
		raw_version, _ := node_attr(collection, "version")
		version, ok := strconv.parse_u64(raw_version)
		if !ok {
			return {kind = .Protocol_Error}
		}
		cursor, _ := state_store_get(socket.store, .Contact_Sync_State, "cursor")
		if len(cursor) == 136 && endian.unchecked_get_u64be(cursor[:8]) >= version {
			continue
		}
		pending, _ := state_store_get(socket.store, .Contact_Sync_State, "required-version")
		if len(pending) == 8 && endian.unchecked_get_u64be(pending) >= version {
			continue
		}
		staged: State_Store
		defer state_store_clear(&staged)
		if e := socket_store_clone(&staged, socket.store); e.kind != .None {
			return e
		}
		buf: [8]u8
		endian.unchecked_put_u64be(buf[:], version)
		if e := state_store_set(&staged, .Contact_Sync_State, "required-version", buf[:]);
		   e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
		if e := state_store_delete(&staged, .Contact_Sync_State, "ready"); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
		if e := socket_store_commit(socket, &staged); e.kind != .None {
			return e
		}
		socket.contact_refresh_due = true
		socket.contact_refresh_after = {}
	}
	return {}
}

store_historical_contact_profiles :: proc(
	socket: ^Socket,
	store: ^State_Store,
	notification: []u8,
) -> Socket_Error {
	kind, k := read_unique_protobuf_field(notification, 6, 0)
	if !k {
		return {kind = .Protocol_Error}
	}
	if kind.value != 4 {
		return {}
	} // PUSH_NAME history chunks carry profile names.
	inline, present := read_unique_protobuf_field(notification, 11, 2)
	if !present {
		return {kind = .Protocol_Error}
	}
	compressed := inline.data
	if inline.number == 0 {
		plain, a := read_unique_protobuf_field(notification, 1, 2)
		length, b := read_unique_protobuf_field(notification, 2, 0)
		key, c := read_unique_protobuf_field(notification, 3, 2)
		cipher, d := read_unique_protobuf_field(notification, 4, 2)
		path, e := read_unique_protobuf_field(notification, 5, 2)
		if !(a && b && c && d && e) || length.value > DEFAULT_MAX_MEDIA_SIZE {
			return {kind = .Protocol_Error}
		}
		msg := Media_Message {
			kind            = .History,
			media_key       = key.data,
			file_sha256     = plain.data,
			file_length     = length.value,
			has_file_length = length.number != 0,
			file_enc_sha256 = cipher.data,
			direct_path     = string(path.data),
		}
		download_error: Socket_Error
		compressed, download_error = download_contact_media(socket, msg)
		if download_error.kind != .None {
			return download_error
		}
	}
	defer if inline.number == 0 {
		delete(compressed)
	}
	if len(compressed) == 0 {
		return {kind = .Protocol_Error}
	}
	raw := make([]u8, DEFAULT_MAX_MEDIA_SIZE)
	defer {crypto.zero_explicit(raw_data(raw), len(raw)); delete(raw)}
	out_size := zlib.uLongf(len(raw))
	in_size := zlib.uLong(len(compressed))
	if zlib.uncompress2(raw_data(raw), &out_size, raw_data(compressed), &in_size) != zlib.OK ||
	   int(in_size) != len(compressed) {
		return {kind = .Protocol_Error}
	}
	chunk := raw[:int(out_size)]
	history_kind, valid := read_unique_protobuf_field(chunk, 1, 0)
	if !valid || history_kind.value != 4 {
		return {kind = .Protocol_Error}
	}
	at := 0
	for at < len(chunk) {
		entry, err := protobuf_field_read(chunk, &at)
		if err != .None {
			return {kind = .Protocol_Error}
		}
		if entry.number != 7 {
			continue
		}
		jid, a := read_unique_protobuf_field(entry.data, 1, 2)
		profile, b := read_unique_protobuf_field(entry.data, 2, 2)
		if entry.wire_type != 2 || !a || !b || !contact_name_valid(string(profile.data)) {
			return {kind = .Protocol_Error}
		}
		if len(profile.data) == 0 ||
		   string(profile.data) == "-" ||
		   !device_user_jid_valid(string(jid.data), false) {
			continue
		}
		if _, known := state_store_get(store, .Contact_Profile, string(jid.data)); known {
			continue
		}
		if e := state_store_set(store, .Contact_Profile, string(jid.data), profile.data);
		   e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}
	return {}
}

// An external sync reference may omit file length. Authenticate the bounded
// ciphertext first, then validate padding and the separate plaintext digest.
download_contact_media :: proc(socket: ^Socket, message: Media_Message) -> ([]u8, Socket_Error) {
	if len(message.media_key) != 32 ||
	   len(message.file_sha256) != 32 ||
	   len(message.file_enc_sha256) != 32 {
		return nil, {kind = .Protocol_Error}
	}
	maximum := u64(DEFAULT_MAX_MEDIA_SIZE)
	if message.has_file_length {
		if message.file_length > maximum {
			return nil, {kind = .Media_Failed, media = {kind = .Media_Oversized}}
		}
		maximum = message.file_length
	}
	source := message
	hash_text: [44]u8
	base64.encode_into_buf(hash_text[:], message.file_enc_sha256, base64.ENC_URL_TABLE)
	separator := "&" if strings.contains(message.direct_path, "?") else "?"
	media_type := "md-msg-hist" if message.kind == .History else "md-app-state"
	source.direct_path = fmt.aprintf(
		"%s%shash=%s&mms-type=%s&__wa-mms=",
		message.direct_path,
		separator,
		string(hash_text[:]),
		media_type,
	)
	defer delete(source.direct_path)
	response, fetch_error := fetch_media_ciphertext(
		source,
		{tls = socket.config.tls},
		maximum,
		socket.config.http_execute,
	)
	if fetch_error.kind != .None {
		return nil, {kind = .Media_Failed, media = fetch_error}
	}
	defer network_client.response_destroy(&response)
	size := len(response.body) - MEDIA_MAC_SIZE
	if size < 16 || size % 16 != 0 || size > int(maximum) + 16 {
		return nil, {kind = .Media_Failed, media = {kind = .Invalid_Encrypted_Length}}
	}
	meta := Media_Metadata{}
	defer media_metadata_clear(&meta)
	copy(meta.media_key[:], message.media_key)
	copy(meta.file_sha256[:], message.file_sha256)
	copy(meta.file_enc_sha256[:], message.file_enc_sha256)
	keys, key_error := media_keys_derive(message.kind, meta.media_key)
	defer media_keys_clear(&keys)
	if key_error.kind != .None {
		return nil, {kind = .Media_Failed, media = key_error}
	}
	if e := media_ciphertext_authenticate(response.body, &meta, &keys); e.kind != .None {
		return nil, {kind = .Media_Failed, media = e}
	}
	plain, alloc_error := make([]u8, size)
	if alloc_error != nil {
		return nil, {kind = .Allocation_Failed, allocation = alloc_error}
	}
	defer {crypto.zero_explicit(raw_data(plain), len(plain)); delete(plain)}
	media_cbc_decrypt_blocks(plain, response.body, size, &keys)
	n := size - int(plain[size - 1])
	if message.has_file_length {
		n = int(message.file_length)
	}
	if e := media_plaintext_validate(plain, size, n, &meta); e.kind != .None {
		return nil, {kind = .Media_Failed, media = e}
	}
	if n > int(maximum) {
		return nil, {kind = .Media_Failed, media = {kind = .Media_Oversized}}
	}
	result, err := slice.clone(plain[:n])
	if err != nil {
		return nil, {kind = .Allocation_Failed, allocation = err}
	}
	return result, {}
}

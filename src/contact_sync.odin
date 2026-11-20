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
	authenticated_key: [128]u8,
	authenticated_key_size: int,
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
		alias := ""
		if saved, found := contact_by_jid(store, jid); found && saved.is_saved {
			alias = saved.alternate_jid if saved.jid == jid else saved.jid
		}
		// Removing the saved record can free both of its JIDs.
		owned, err := strings.clone(alias)
		if err != nil { return false }
		defer delete(owned)
		return remove_saved_contact_aliases(store, jid, owned, "")
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
	// Preserve the link when a rename supplies only the other index.
	primary := jid
	if existing, found := contact_by_jid(store, jid); found && existing.is_saved {
		primary = existing.jid
		if primary != jid {
			if alias != "" && alias != primary { primary = jid } else { alias = jid }
		} else if alias == "" {
			alias = existing.alternate_jid
		}
	} else if alias != "" {
		if linked, known := contact_by_jid(store, alias); known && linked.is_saved && linked.jid == alias {
			primary, alias = alias, jid
		}
	}
	names := fmt.aprintf("%s\x00%s\x00%s", string(full.data), string(first.data), alias)
	defer delete(names)
	// Remove legacy duplicates before replacing the primary record. The
	// encoded names own their bytes independently of any removed record.
	return remove_saved_contact_aliases(store, primary, alias, primary) &&
		state_store_set(store, .Contact_Name, primary, transmute([]u8)names).kind == .None
}

remove_saved_contact_aliases :: proc(store: ^State_Store, jid, alias, keep: string) -> bool {
	for i := len(store.records) - 1; i >= 0; i -= 1 {
		record := store.records[i]
		if record.kind != .Contact_Name || record.name == keep { continue }
		entry, ok := decode_saved_contact(record.name, record.data)
		if !ok { return false }
		if entry.jid == jid || entry.alternate_jid == jid ||
		   (alias != "" && (entry.jid == alias || entry.alternate_jid == alias)) {
			if state_store_delete(store, .Contact_Name, record.name).kind != .None { return false }
		}
	}
	return true
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
	expected := contact_value_mac(keys[64:96], id.data, content, operation)
	if crypto.compare_constant_time(expected[:], value_mac) != 1 {
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
	page.authenticated_key_size = copy(page.authenticated_key[:], id.data)
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

rebase_contact_collection :: proc(page, current: ^State_Store) -> Socket_Error {
	latest: State_Store
	defer state_store_clear(&latest)
	if e := socket_store_clone(&latest, current); e.kind != .None { return e }
	for i := len(latest.records) - 1; i >= 0; i -= 1 {
		r := latest.records[i]
		if r.kind != .Contact_Name && r.kind != .Contact_Index_MAC { continue }
		if _, found := state_store_get(page, r.kind, r.name); !found {
			if e := state_store_delete(&latest, r.kind, r.name); e.kind != .None {
				return {kind = .State_Failed, state = e}
			}
		}
	}
	for r in page.records {
		if r.kind != .Contact_Name && r.kind != .Contact_Index_MAC { continue }
		if data, found := state_store_get(&latest, r.kind, r.name); found && bytes.equal(data, r.data) { continue }
		if e := state_store_set(&latest, r.kind, r.name, r.data); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}
	page^, latest = latest, page^
	return {}
}

// Call after login and on a server_sync notification for critical_unblock_low.
// Each authenticated page commits atomically. A retry resumes at the last
// committed version. While awaiting keys, call socket_read and call again.
socket_sync_contacts :: proc(socket: ^Socket, request_snapshot := false) -> (Contact_Sync_Status, Socket_Error) {
	if socket == nil ||
	   socket.phase != .Online ||
	   socket.store == nil ||
	   !socket.store.initialized {
		return .Syncing, {kind = .Invalid_State}
	}
	refresh_snapshot := request_snapshot
	for _ in 0 ..< 64 {
		page := Contact_Sync_Page{}
		cursor, resumed := state_store_get(socket.store, .Contact_Sync_State, "contacts-cursor")
		if resumed {
			if len(cursor) != 136 {
				return .Syncing, {kind = .Protocol_Error}
			}
			page.version = endian.unchecked_get_u64be(cursor[:8])
			copy(page.hash[:], cursor[8:])
		}
		stored_version := page.version
		if refresh_snapshot {page.version = 0; page.hash = {}}
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
		base_revision := socket.store.revision
		candidate: State_Store
		defer state_store_clear(&candidate)
		if e := socket_store_clone(&candidate, socket.store); e.kind != .None {
			return .Syncing, e
		}
		if _, legacy := state_store_get(&candidate, .Contact_Sync_State, "cursor"); legacy || refresh_snapshot {
			// The old index could retain a deleted name. Rebuild from version
			// zero, preserving the offline cache until a page authenticates.
			for i := len(candidate.records) - 1; i >= 0; i -= 1 {
				r := candidate.records[i]
				if r.kind == .Contact_Name || r.kind == .Contact_Index_MAC {
					if removed := state_store_delete(&candidate, r.kind, r.name); removed.kind != .None {
						return .Syncing, {kind = .State_Failed, state = removed}
					}
				}
			}
		}
		page.store = &candidate
		if e := apply_contact_collection(socket, &page, collection); e.kind != .None {
			if page.missing_size > 0 {
				key := hex.encode(page.missing_id[:page.missing_size])
				defer delete(key)
				if _, arrived := state_store_get(socket.store, .Contact_Sync_Key, string(key)); arrived {
					continue
				}
				return .Syncing, socket_request_contact_key(
					socket,
					page.missing_id[:page.missing_size],
				)
			}
			return .Syncing, e
		}
		if refresh_snapshot && more != "true" && page.version < stored_version {
			return .Syncing, {kind = .Protocol_Error}
		}
		if more == "true" && page.version <= from_version {
			return .Syncing, {kind = .Protocol_Error}
		}
		// The HTTP worker pumps incoming stanzas. Keep inbox, ratchet, profile
		// and required-version changes committed while this page was in flight.
		if socket.store.revision != base_revision {
			if e := rebase_contact_collection(&candidate, socket.store); e.kind != .None {
				return .Syncing, e
			}
		}
		// Earlier versions accepted the required version before checking its sender.
		for legacy in ([3]string{"cursor", "required-version", "contacts-key-id"}) {
			if e := state_store_delete(&candidate, .Contact_Sync_State, legacy); e.kind != .None {
				return .Syncing, {kind = .State_Failed, state = e}
			}
		}
		buf: [136]u8
		endian.unchecked_put_u64be(buf[:8], page.version)
		copy(buf[8:], page.hash[:])
		if e := state_store_set(&candidate, .Contact_Sync_State, "contacts-cursor", buf[:]);
		   e.kind != .None {
			return .Syncing, {kind = .State_Failed, state = e}
		}
		status: State_Error
		required, _ := state_store_get(&candidate, .Contact_Sync_State, "server-version")
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
		if page.authenticated_key_size > 0 {
			socket.contact_write_key_size = copy(socket.contact_write_key_id[:], page.authenticated_key[:page.authenticated_key_size])
		}
		refresh_snapshot = false
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
	from, _ := node_attr(node, "from")
	id, _ := node_attr(node, "id")
	if (from != "s.whatsapp.net" && from != "@s.whatsapp.net") || !socket_inbox_id_valid(id) {
		return {kind = .Protocol_Error}
	}
	children, ok := node.content.([]Binary_Node)
	if !ok { return {kind = .Protocol_Error} }
	required: u64
	for collection in children {
		name, _ := node_attr(collection, "name")
		if collection.tag != "collection" || name != CONTACT_COLLECTION {
			continue
		}
		raw_version, _ := node_attr(collection, "version")
		version, parsed := strconv.parse_u64(raw_version)
		if !parsed {
			return {kind = .Protocol_Error}
		}
		required = max(required, version)
	}
	if required == 0 { return {} }
	cursor, _ := state_store_get(socket.store, .Contact_Sync_State, "contacts-cursor")
	if len(cursor) == 136 && endian.unchecked_get_u64be(cursor[:8]) >= required {
		return {}
	}
	pending, _ := state_store_get(socket.store, .Contact_Sync_State, "server-version")
	if len(pending) == 8 && endian.unchecked_get_u64be(pending) >= required {
		return {}
	}
	staged: State_Store
	defer state_store_clear(&staged)
	if e := socket_store_clone(&staged, socket.store); e.kind != .None {
		return e
	}
	buf: [8]u8
	endian.unchecked_put_u64be(buf[:], required)
	if e := state_store_set(&staged, .Contact_Sync_State, "server-version", buf[:]);
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
	return {}
}

// Explicitly import one history notification. The receive loop stages external
// references so it can finish committing the ratchet before fetching them.
store_historical_contact_profiles :: proc(socket: ^Socket, store: ^State_Store, notification: []u8, pending_name := "") -> Socket_Error {
	kind, valid := read_unique_protobuf_field(notification, 6, 0)
	if !valid { return {kind = .Protocol_Error} }
	if kind.value != 4 { return {} }
	inline, ok := read_unique_protobuf_field(notification, 11, 2)
	if !ok { return {kind = .Protocol_Error} }
	if inline.number != 0 { return import_compressed_contact_profiles(store, inline.data) }
	if pending_name != "" {
		if _, parsed := contact_history_media(notification); parsed.kind != .None { return parsed }
		if e := state_store_set(store, .Pending_Profile_History, pending_name, notification); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
		return {}
	}
	compressed, e := download_contact_history(socket, notification)
	if e.kind != .None { return e }
	defer {crypto.zero_explicit(raw_data(compressed), len(compressed)); delete(compressed)}
	return import_compressed_contact_profiles(store, compressed)
}

download_contact_history :: proc(socket: ^Socket, notification: []u8) -> ([]u8, Socket_Error) {
	// Network reads can replace both the active session document and store.
	ref, allocation := slice.clone(notification)
	if allocation != nil { return nil, {kind = .Allocation_Failed, allocation = allocation} }
	defer {crypto.zero_explicit(raw_data(ref), len(ref)); delete(ref)}
	source, parsed := contact_history_media(ref)
	if parsed.kind != .None { return nil, parsed }
	return download_contact_media(socket, source)
}

socket_import_pending_contact_history :: proc(socket: ^Socket) -> Socket_Error {
	for record in socket.store.records {
		if record.kind != .Pending_Profile_History { continue }
		// The socket pump can replace the entire store during the download.
		name, ae := strings.clone(record.name)
		if ae != nil { return {kind = .Allocation_Failed, allocation = ae} }
		defer delete(name)
		compressed, fetched := download_contact_history(socket, record.data)
		if fetched.kind != .None { return fetched }
		defer {crypto.zero_explicit(raw_data(compressed), len(compressed)); delete(compressed)}
		candidate: State_Store
		defer state_store_clear(&candidate)
		if e := socket_store_clone(&candidate, socket.store); e.kind != .None { return e }
		if e := import_compressed_contact_profiles(&candidate, compressed); e.kind != .None { return e }
		if e := state_store_delete(&candidate, .Pending_Profile_History, name); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
		return socket_store_commit(socket, &candidate)
	}
	socket.profile_history_pending = false
	return {}
}

contact_history_media :: proc(notification: []u8) -> (Media_Message, Socket_Error) {
	plain, a := read_unique_protobuf_field(notification, 1, 2)
	length, b := read_unique_protobuf_field(notification, 2, 0)
	key, c := read_unique_protobuf_field(notification, 3, 2)
	cipher, d := read_unique_protobuf_field(notification, 4, 2)
	path, e := read_unique_protobuf_field(notification, 5, 2)
	if !(a && b && c && d && e) || length.value > DEFAULT_MAX_MEDIA_SIZE ||
	   len(key.data) != 32 || len(plain.data) != 32 || len(cipher.data) != 32 || len(path.data) == 0 {
		return {}, {kind = .Protocol_Error}
	}
	return {
		kind            = .History,
		media_key       = key.data,
		file_sha256     = plain.data,
		file_length     = length.value,
		has_file_length = length.number != 0,
		file_enc_sha256 = cipher.data,
		direct_path     = string(path.data),
	}, {}
}

import_compressed_contact_profiles :: proc(store: ^State_Store, compressed: []u8) -> Socket_Error {
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
	config := network_client.Config{tls = socket.config.tls, timeout = socket.config.query_timeout}
	response: network_client.Response
	fetch_error: Media_Error
	if socket.config.http_execute != nil {
		// Injected media executors run synchronously on the calling thread.
		response, fetch_error = fetch_media_ciphertext(source, config, maximum, socket.config.http_execute)
	} else {
		job := Socket_HTTP_Job{kind = .Contact_Blob, message = source, config = config, max_plaintext = maximum}
		if e := socket_http_run(socket, &job); e.kind != .None {
			network_client.response_destroy(&job.response)
			return nil, e
		}
		response, fetch_error = job.response, job.media_error
	}
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

// Compute the signature over one encrypted SET or REMOVE value in a sync record.
contact_value_mac :: proc(key, id, ciphertext: []u8, operation: u64) -> [32]u8 {
	digest: hmac.Context
	hmac.init(&digest, .SHA512, key)
	op := [1]u8{u8(operation + 1)}
	length: [8]u8
	endian.unchecked_put_u64be(length[:], u64(1 + len(id)))
	for part in ([]([]u8){op[:], id, ciphertext, length[:]}) {hmac.update(&digest, part)}
	full: [64]u8
	hmac.final(&digest, full[:])
	result: [32]u8
	copy(result[:], full[:32])
	return result
}

// Encode one app-state SET against the supplied cursor. The read-side store
// advances only when WhatsApp returns the authenticated update.
encode_contact_add_patch :: proc(dst: []u8, store: ^State_Store, jid, name: string, key_id, cursor: []u8) -> (int, Socket_Error) {
	if !device_user_jid_valid(jid, false) || !strings.has_suffix(jid, "@s.whatsapp.net") ||
	   !contact_name_valid(name) || strings.trim_space(name) == "" {
		return 0, {kind = .Invalid_Config}
	}
	if len(cursor) != 136 {return 0, {kind = .Invalid_State}}
	page := Contact_Sync_Page{store = store, version = endian.unchecked_get_u64be(cursor[:8])}
	if page.version == max(u64) {return 0, {kind = .Protocol_Error}}
	copy(page.hash[:], cursor[8:])
	keys, ok := derive_contact_mutation_keys(&page, key_id)
	defer crypto.zero_explicit(&keys, size_of(keys))
	if !ok {return 0, {kind = .Invalid_State}}

	index := fmt.aprintf(`["contact","%s"]`, jid)
	defer delete(index)
	mapping_name := fmt.aprintf("pn:%s", jid)
	defer delete(mapping_name)
	lid, mapped := state_store_get(store, .LID_Mapping, mapping_name)
	if mapped && (!device_user_jid_valid(string(lid), false) || !strings.has_suffix(string(lid), "@lid")) {
		return 0, {kind = .Protocol_Error}
	}
	action_size := message_field_size(1, len(name)) + 2 // saveOnPrimaryAddressbook
	if mapped {action_size += message_field_size(3, len(lid))}
	now := u64(time.to_unix_nanoseconds(time.now()) / 1_000_000)
	value_size := 1 + protobuf_varint_size(now) + message_field_size(3, action_size)
	plain: [8192]u8
	defer crypto.zero_explicit(&plain, size_of(plain))
	data := Protobuf_Writer{dst = plain[:]}
	protobuf_write_string(&data, 1, index)
	protobuf_write_header(&data, 2, value_size)
	protobuf_write_uint(&data, 1, now)
	protobuf_write_header(&data, 3, action_size)
	protobuf_write_string(&data, 1, name)
	if mapped {protobuf_write_bytes(&data, 3, lid)}
	protobuf_write_uint(&data, 4, 1)
	protobuf_write_bytes(&data, 3, nil)
	protobuf_write_uint(&data, 4, 2)
	if data.err != .None {return 0, {kind = .Invalid_Config}}

	iv: [16]u8
	crypto.rand_bytes(iv[:])
	blob: [8192 + 64]u8
	copy(blob[:16], iv[:])
	cipher_key: [32]u8
	defer crypto.zero_explicit(&cipher_key, size_of(cipher_key))
	copy(cipher_key[:], keys[32:64])
	n, encryption_error := signal_cbc_encrypt(blob[16:], cipher_key, iv, plain[:data.at])
	if encryption_error != .None {return 0, {kind = .Protocol_Error}}
	value_mac := contact_value_mac(keys[64:96], key_id, blob[:16+n], 0)
	copy(blob[16+n:], value_mac[:])
	encrypted := blob[:16+n+32]
	index_mac: [32]u8
	hmac.sum(.SHA256, index_mac[:], transmute([]u8)index, keys[:32])
	index_key := hex.encode(index_mac[:])
	defer delete(index_key)
	if previous, exists := state_store_get(store, .Contact_Index_MAC, string(index_key)); exists {
		if len(previous) != 32 {return 0, {kind = .Protocol_Error}}
		update_contact_collection_hash(&page, previous, true)
	}
	update_contact_collection_hash(&page, value_mac[:], false)
	version: [8]u8
	endian.unchecked_put_u64be(version[:], page.version + 1)
	collection := transmute([]u8)string(CONTACT_COLLECTION)
	snapshot_mac, patch_mac: [32]u8
	digest: hmac.Context
	hmac.init(&digest, .SHA256, keys[96:128])
	for part in ([]([]u8){page.hash[:], version[:], collection}) {hmac.update(&digest, part)}
	hmac.final(&digest, snapshot_mac[:])
	hmac.init(&digest, .SHA256, keys[128:])
	for part in ([]([]u8){snapshot_mac[:], value_mac[:], version[:], collection}) {hmac.update(&digest, part)}
	hmac.final(&digest, patch_mac[:])

	idx_size := message_field_size(1, len(index_mac))
	blob_size := message_field_size(1, len(encrypted))
	key_size := message_field_size(1, len(key_id))
	record_size := message_field_size(1, idx_size) + message_field_size(2, blob_size) + message_field_size(3, key_size)
	patch := Protobuf_Writer{dst = dst}
	protobuf_write_header(&patch, 2, 2 + message_field_size(2, record_size))
	protobuf_write_uint(&patch, 1, 0)
	protobuf_write_header(&patch, 2, record_size)
	protobuf_write_header(&patch, 1, idx_size)
	protobuf_write_bytes(&patch, 1, index_mac[:])
	protobuf_write_header(&patch, 2, blob_size)
	protobuf_write_bytes(&patch, 1, encrypted)
	protobuf_write_header(&patch, 3, key_size)
	protobuf_write_bytes(&patch, 1, key_id)
	protobuf_write_bytes(&patch, 4, snapshot_mac[:])
	protobuf_write_bytes(&patch, 5, patch_mac[:])
	protobuf_write_header(&patch, 6, key_size)
	protobuf_write_bytes(&patch, 1, key_id)
	if patch.err != .None {return 0, {kind = .Invalid_Config}}
	return patch.at, {}
}

// Add a saved contact by phone-number JID. Repeating the same request is
// idempotent. Success means the saved name was read back from WhatsApp.
socket_add_contact :: proc(socket: ^Socket, phone_jid, full_name: string) -> Socket_Error {
	if !device_user_jid_valid(phone_jid, false) || !strings.has_suffix(phone_jid, "@s.whatsapp.net") ||
	   !contact_name_valid(full_name) || strings.trim_space(full_name) == "" {
		return {kind = .Invalid_Config}
	}
	if socket == nil || socket.store == nil || socket.phase != .Online {return {kind = .Invalid_State}}
	// Callers can supply strings borrowed from the store replaced during sync.
	jid, je := strings.clone(phone_jid)
	if je != nil {return {kind = .Allocation_Failed, allocation = je}}
	defer delete(jid)
	name, ne := strings.clone(full_name)
	if ne != nil {return {kind = .Allocation_Failed, allocation = ne}}
	defer delete(name)
	// Already-saved entries require only an incremental read. A fresh
	// connection may need a snapshot to learn the collection's active key.
	for refresh in ([2]bool{false, true}) {
		ready, err := socket_sync_contacts(socket, refresh)
		if err.kind != .None {return err}
		if ready != .Ready {return {kind = .Contacts_Syncing}}
		if contact, found := contact_by_jid(socket.store, jid); found && contact.is_saved {
			if contact.full_name == name {return {}}
			return {kind = .Contact_Already_Exists}
		}
		if socket.contact_write_key_size != 0 {break}
	}
	cursor, _ := state_store_get(socket.store, .Contact_Sync_State, "contacts-cursor")
	key_id := socket.contact_write_key_id[:socket.contact_write_key_size]
	// An empty collection may have no signed page yet. Its sole shared key
	// unambiguously identifies the key to use for the first mutation.
	if len(key_id) == 0 {
		for record in socket.store.records {
			if record.kind != .Contact_Sync_Key {continue}
			if len(key_id) != 0 {return {kind = .Invalid_State}}
			var_ok: bool
			key_id, var_ok = hex.decode_into_buffer(transmute([]u8)record.name, socket.contact_write_key_id[:])
			if !var_ok {return {kind = .Protocol_Error}}
		}
	}
	encoded: [8192]u8
	n, encode_error := encode_contact_add_patch(encoded[:], socket.store, jid, name, key_id, cursor)
	if encode_error.kind != .None {return encode_error}
	version := fmt.aprintf("%d", endian.unchecked_get_u64be(cursor[:8]))
	defer delete(version)
	collection := Binary_Node{
		tag = "collection",
		attrs = []Binary_Node_Attribute{{"name", CONTACT_COLLECTION}, {"version", version}, {"return_snapshot", "false"}},
		content = []Binary_Node{{tag = "patch", content = encoded[:n]}},
	}
	doc, query_error := socket_query(socket, {
		tag = "iq",
		attrs = []Binary_Node_Attribute{{"to", "@s.whatsapp.net"}, {"type", "set"}, {"xmlns", "w:sync:app:state"}},
		content = []Binary_Node{{tag = "sync", content = []Binary_Node{collection}}},
	})
	if query_error.kind != .None {return query_error}
	defer binary_document_destroy(&doc)
	id, _ := node_attr(doc.root, "id")
	if e := device_response_validate(doc.root, id); e.kind != .None {return {kind = .Device_Failed, device = e}}
	sync, se := device_unique_child(doc.root, "sync")
	result, re := device_unique_child(sync, "collection")
	response_name, _ := node_attr(result, "name")
	if se.kind != .None || re.kind != .None || response_name != CONTACT_COLLECTION {return {kind = .Protocol_Error}}
	if kind, _ := node_attr(result, "type"); kind == "error" {return {kind = .Server_Rejected}}
	ready, err := socket_sync_contacts(socket)
	if err.kind != .None {return err}
	if ready != .Ready {return {kind = .Contacts_Syncing}}
	contact, found := contact_by_jid(socket.store, jid)
	if !found || !contact.is_saved || contact.full_name != name {return {kind = .Contact_Unconfirmed}}
	return {}
}

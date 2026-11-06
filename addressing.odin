package whatsapp

import "core:fmt"
import "core:slice"
import "core:strconv"
import "core:strings"
import ascii "../ascii"
import "core:unicode/utf8"
import "core:bytes"
import "core:crypto"

// Device discovery and remote key bundles.

MAX_DEVICE_QUERY_USERS :: 256
MAX_USER_DEVICES :: 256

Device_Error_Kind :: enum {
	None,
	Invalid_Request,
	Invalid_JID,
	Unexpected_Response,
	Server_Error,
	Invalid_Response,
	Destination_Undersized,
	Limit_Exceeded,
	Duplicate_Device,
	Invalid_Key,
	Invalid_Signature,
	Binary_Node_Failed,
}
Device_Error :: struct {
	kind:        Device_Error_Kind,
	required:    int,
	server_code: u32,
	binary:      Binary_Node_Error,
}
Remote_Device :: struct {
	user_jid:      string, // Borrows the decoded response document.
	id, key_index: u32,
	is_hosted:     bool,
}

Remote_Key_Bundle :: struct {
	jid:    string, // Borrows response document.
	bundle: Signal_Prekey_Bundle,
}

// Validate all requested users and signed prekeys before exposing any bundle.
// The application still chooses/trusts an identity explicitly before X3DH.
device_keys_response_decode :: proc(
	node: Binary_Node,
	jids: []string,
	request_id: string,
	storage: []Remote_Key_Bundle,
) -> (
	int,
	Device_Error,
) {
	if validation_error := device_query_response_validate(node, jids, request_id, true);
	   validation_error.kind != .None do return 0, validation_error

	list, err := device_unique_child(node, "list")
	if err.kind != .None do return 0, err

	children, ok := list.content.([]Binary_Node)
	if !ok do return 0, {kind = .Invalid_Response}

	seen: [MAX_DEVICE_QUERY_USERS]bool
	count := 0
	for child in children {
		if child.tag != "user" do continue

		jid, _ := pairing_node_attr(child, "jid")
		index := -1
		for requested, i in jids do if requested == jid {
			index = i
		}

		if index < 0 || seen[index] {
			return 0, {kind = .Unexpected_Response}
		}

		seen[index] = true
		_, parse_err := device_bundle_decode(child)
		if parse_err.kind != .None do return 0, parse_err

		count += 1
	}
	for found in seen[:len(jids)] do if !found {
		return 0, {kind = .Invalid_Response}
	}

	if len(storage) < count {
		return 0, {kind = .Destination_Undersized, required = count}
	}

	at := 0
	for child in children {
		if child.tag != "user" do continue

		jid, _ := pairing_node_attr(child, "jid")
		bundle, _ := device_bundle_decode(child)
		storage[at] = {
			jid    = jid,
			bundle = bundle,
		}
		at += 1
	}
	return count, {}
}

device_query_response_validate :: proc(
	node: Binary_Node, users: []string, request_id: string, allow_device: bool,
) -> Device_Error {
	if len(users) == 0 ||
	   len(users) > MAX_DEVICE_QUERY_USERS ||
	   !device_request_valid(request_id) {
		return {kind = .Invalid_Request}
	}

	for jid in users do if !device_user_valid(jid, allow_device) {
		return {kind = .Invalid_JID}
	}

	if err := device_response_validate(node, request_id);
	   err.kind != .None {
		return err
	}

	return {}
}

device_bundle_decode :: proc(
	node: Binary_Node,
) -> (
	Signal_Prekey_Bundle,
	Device_Error,
) {
	if _, found := pairing_node_child(node, "error"); found {
		return {}, {kind = .Server_Error}
	}

	registration, reg_err := device_child_bytes(
		node,
		"registration",
		4,
	)
	if reg_err.kind != .None do return {}, reg_err

	identity, identity_err := device_child_bytes(
		node,
		"identity",
		32,
	)
	if identity_err.kind != .None do return {}, identity_err

	signed, signed_err := device_unique_child(node, "skey")
	if signed_err.kind != .None do return {}, signed_err

	id, id_err := device_child_bytes(signed, "id", 3)
	if id_err.kind != .None do return {}, id_err

	value, key_err := device_child_bytes(signed, "value", 32)
	if key_err.kind != .None do return {}, key_err

	signature, sig_err := device_child_bytes(signed, "signature", 64)
	if sig_err.kind != .None do return {}, sig_err

	result: Signal_Prekey_Bundle
	for c in registration do result.registration_id = result.registration_id << 8 | cast(u32)c
	for c in id do result.signed_prekey_id = result.signed_prekey_id << 8 | cast(u32)c
	copy(result.identity_public[:], identity)
	copy(result.signed_prekey_public[:], value)
	copy(result.signed_prekey_signature[:], signature)
	signed_input: [33]u8
	signed_input[0] = 5
	copy(signed_input[1:], value)
	if signal_curve_verify(
		   result.identity_public,
		   signed_input[:],
		   signature,
	   ) !=
	   .None {
		return {}, {kind = .Invalid_Signature}
	}

	if prekey_error := device_bundle_prekey_decode(node, &result);
	   prekey_error.kind != .None do return {}, prekey_error

	return result, {}
}

device_bundle_prekey_decode :: proc(
	node: Binary_Node, result: ^Signal_Prekey_Bundle,
) -> Device_Error {
	if _, has_key := pairing_node_child(node, "key"); has_key {
		key, e := device_unique_child(node, "key")
		if e.kind != .None do return e

		prekey_id, ie := device_child_bytes(key, "id", 3)
		if ie.kind != .None do return ie

		prekey, pe := device_child_bytes(key, "value", 32)
		if pe.kind != .None do return pe

		result.has_prekey = true
		for c in prekey_id do result.prekey_id = result.prekey_id << 8 | cast(u32)c
		copy(result.prekey_public[:], prekey)
	}

	return {}
}

device_child_bytes :: proc(
	node: Binary_Node,
	tag: string,
	length: int,
) -> (
	[]u8,
	Device_Error,
) {
	child, err := device_unique_child(node, tag)
	if err.kind != .None do return nil, err

	data, ok := child.content.([]u8)
	if !ok || len(data) != length {
		return nil, {kind = .Invalid_Key}
	}

	return data, {}
}

// Queries all recipient devices, including primary phones (device zero).
// Users must be normalized PN or LID JIDs, without a device/agent suffix.
devices_query_encode :: proc(
	dst: []u8,
	users: []string,
	request_id: string,
) -> (
	int,
	Device_Error,
) {
	if !device_request_valid(request_id) || len(users) == 0 {
		return 0, {kind = .Invalid_Request}
	}

	if len(users) > MAX_DEVICE_QUERY_USERS {
		return 0, {kind = .Limit_Exceeded}
	}

	attrs: [MAX_DEVICE_QUERY_USERS][1]Binary_Node_Attribute
	nodes: [MAX_DEVICE_QUERY_USERS]Binary_Node
	if node_error := devices_query_nodes_prepare(users, attrs[:], nodes[:]);
	   node_error.kind != .None do return 0, node_error
	children := [?]Binary_Node {
		{
			tag = "query",
			content = []Binary_Node {
				{
					tag = "devices",
					attrs = []Binary_Node_Attribute {
						{"version", "2"},
					},
				},
			},
		},
		{tag = "list", content = nodes[:len(users)]},
	}
	root := Binary_Node {
		tag     = "iq",
		attrs   = []Binary_Node_Attribute {
			{"to", "@s.whatsapp.net"},
			{"type", "get"},
			{"xmlns", "usync"},
			{"id", request_id},
		},
		content = []Binary_Node {
			{
				tag = "usync",
				attrs = []Binary_Node_Attribute {
					{"context", "message"},
					{"mode", "query"},
					{"sid", request_id},
					{"last", "true"},
					{"index", "0"},
				},
				content = children[:],
			},
		},
	}
	n, err := binary_node_encode(dst, root)
	if err.kind != .None {
		return n, {kind = .Binary_Node_Failed, binary = err}
	}

	return n, {}
}

devices_query_nodes_prepare :: proc(
	users: []string, attrs: [][1]Binary_Node_Attribute, nodes: []Binary_Node,
) -> Device_Error {
	for user, i in users {
		if !device_user_valid(user, false) {
			return {kind = .Invalid_JID}
		}

		for previous in users[:i] do if user == previous {
			return {kind = .Invalid_Request}
		}

		attrs[i] = {{"jid", user}}
		nodes[i] = {
			tag     = "user",
			attrs   = attrs[i][:],
			content = []Binary_Node{},
		}
	}
	return {}
}

// Decode into caller storage, after validating the entire reply. Missing users
// are errors: sending only to a subset would silently miss group members.
devices_response_decode :: proc(
	node: Binary_Node,
	users: []string,
	request_id: string,
	storage: []Remote_Device,
) -> (
	int,
	Device_Error,
) {
	if validation_error := device_query_response_validate(node, users, request_id, false);
	   validation_error.kind != .None do return 0, validation_error

	usync, err := device_unique_child(node, "usync")
	if err.kind != .None do return 0, err

	list, list_err := device_unique_child(usync, "list")
	if list_err.kind != .None do return 0, list_err

	children, ok := list.content.([]Binary_Node)
	if !ok do return 0, {kind = .Invalid_Response}

	count, children_error := devices_response_children_validate(children, users)
	if children_error.kind != .None do return 0, children_error

	if len(storage) < count {
		return 0, {kind = .Destination_Undersized, required = count}
	}

	at := 0
	for child in children {
		if child.tag != "user" do continue

		jid, _ := pairing_node_attr(child, "jid")
		devices, _ := device_unique_child(child, "devices")
		device_list, _ := device_unique_child(devices, "device-list")
		entries, _ := device_list.content.([]Binary_Node)
		for entry in entries {
			if entry.tag != "device" do continue

			d, _ := device_entry_decode(jid, entry)
			if d.id != 0 && d.key_index == 0 do continue

			storage[at] = d
			at += 1
		}
	}
	return count, {}
}

devices_response_user_validate :: proc(child: Binary_Node, jid: string) -> (int, Device_Error) {
	count := 0
	if _, found := pairing_node_child(child, "error"); found {
		return 0, {kind = .Server_Error}
	}

	devices, dev_err := device_unique_child(child, "devices")
	if dev_err.kind != .None do return 0, dev_err

	device_list, dl_err := device_unique_child(
		devices,
		"device-list",
	)
	if dl_err.kind != .None do return 0, dl_err

	entries, valid := device_list.content.([]Binary_Node)
	if !valid do return 0, {kind = .Invalid_Response}

	local_seen: [MAX_USER_DEVICES]bool
	for entry in entries {
		if entry.tag != "device" do continue

		d, parse_err := device_entry_decode(jid, entry)
		if parse_err.kind != .None {
			return 0, parse_err
		}

		if local_seen[d.id] {
			return 0, {kind = .Duplicate_Device}
		}

		local_seen[d.id] = true
		// Pinned extractDeviceJids excludes non-primary devices without a
		// key-index. They cannot receive a Signal distribution safely.
		if d.id != 0 && d.key_index == 0 do continue

		count += 1
	}
	return count, {}
}

devices_response_children_validate :: proc(
	children: []Binary_Node, users: []string,
) -> (int, Device_Error) {
	seen: [MAX_DEVICE_QUERY_USERS]bool
	count := 0
	for child in children {
		if child.tag != "user" do continue

		jid, _ := pairing_node_attr(child, "jid")
		index := -1
		for user, i in users do if user == jid do index = i

		if index < 0 || seen[index] {
			return 0, {kind = .Unexpected_Response}
		}

		seen[index] = true
		device_count, child_error := devices_response_user_validate(child, jid)
		if child_error.kind != .None do return 0, child_error
		count += device_count
	}
	for found in seen[:len(users)] do if !found {
		return 0, {kind = .Invalid_Response}
	}

	return count, {}
}

remote_device_jid :: proc(
	dst: []u8,
	device: Remote_Device,
) -> (
	string,
	Device_Error,
) {
	if !device_user_valid(device.user_jid, false) ||
	   device.id >= MAX_USER_DEVICES {
		return "", {kind = .Invalid_JID}
	}

	if device.id == 0 {
		if len(dst) < len(device.user_jid) {
			return "", {
				kind = .Destination_Undersized,
				required = len(device.user_jid),
			}
		}

		copy(dst, transmute([]u8)device.user_jid)
		return cast(string)dst[:len(device.user_jid)], {}
	}

	at := strings.index_byte(device.user_jid, '@')
	buffer: [256]u8
	text := fmt.bprintf(
		buffer[:],
		"%s:%d%s",
		device.user_jid[:at],
		device.id,
		device.user_jid[at:],
	)
	if len(dst) < len(text) {
		return "", {
			kind = .Destination_Undersized,
			required = len(text),
		}
	}

	copy(dst, transmute([]u8)text)
	return cast(string)dst[:len(text)], {}
}

device_keys_query_encode :: proc(
	dst: []u8,
	jids: []string,
	request_id: string,
) -> (
	int,
	Device_Error,
) {
	if len(jids) == 0 || !device_request_valid(request_id) {
		return 0, {kind = .Invalid_Request}
	}

	if len(jids) > MAX_DEVICE_QUERY_USERS {
		return 0, {kind = .Limit_Exceeded}
	}

	attrs: [MAX_DEVICE_QUERY_USERS][1]Binary_Node_Attribute
	nodes: [MAX_DEVICE_QUERY_USERS]Binary_Node
	for jid, i in jids {
		if !device_user_valid(jid, true) {
			return 0, {kind = .Invalid_JID}
		}

		for previous in jids[:i] do if previous == jid {
			return 0, {kind = .Invalid_Request}
		}

		attrs[i] = {{"jid", jid}}
		nodes[i] = {
			tag   = "user",
			attrs = attrs[i][:],
		}
	}
	n, err := binary_node_encode(
		dst,
		{
			tag = "iq",
			attrs = []Binary_Node_Attribute {
				{"xmlns", "encrypt"},
				{"type", "get"},
				{"to", "@s.whatsapp.net"},
				{"id", request_id},
			},
			content = []Binary_Node {
				{tag = "key", content = nodes[:len(jids)]},
			},
		},
	)
	if err.kind != .None {
		return n, {kind = .Binary_Node_Failed, binary = err}
	}

	return n, {}
}

device_request_valid :: proc(id: string) -> bool {
	if len(id) == 0 || len(id) > 128 do return false

	for c in id do if c < 33 || c > 126 do return false

	return true
}
device_user_valid :: proc(jid: string, allow_device: bool) -> bool {
	if len(jid) > 128 ||
	   !(strings.has_suffix(jid, "@s.whatsapp.net") ||
			   strings.has_suffix(jid, "@lid")) {
		return false
	}

	_, dev, err := pairing_jid_decode(jid)
	if err.kind != .None || dev >= MAX_USER_DEVICES {
		return false
	}

	if !allow_device &&
	   (strings.contains(jid, ":") || strings.contains(jid, "_")) {
		return false
	}

	return true
}
device_response_validate :: proc(
	node: Binary_Node,
	request_id: string,
) -> Device_Error {
	id, _ := pairing_node_attr(node, "id")
	from, has_from := pairing_node_attr(node, "from")
	if node.tag != "iq" ||
	   id != request_id ||
	   (has_from &&
			   !slice.contains(
					   []string{"s.whatsapp.net", "@s.whatsapp.net"},
					   from,
				   )) {
		return {kind = .Unexpected_Response}
	}

	kind, _ := pairing_node_attr(node, "type")
	if kind == "error" do return {kind = .Server_Error}

	if kind != "result" {
		return {kind = .Unexpected_Response}
	}

	return {}
}
device_unique_child :: proc(
	node: Binary_Node,
	tag: string,
) -> (
	Binary_Node,
	Device_Error,
) {
	children, _ := node.content.([]Binary_Node)
	found := false
	result: Binary_Node
	for child in children {
		if child.tag != tag do continue

		if found do return {}, {kind = .Invalid_Response}

		result, found = child, true
	}
	if !found do return {}, {kind = .Invalid_Response}

	return result, {}
}
device_entry_decode :: proc(
	jid: string,
	node: Binary_Node,
) -> (
	Remote_Device,
	Device_Error,
) {
	id, _ := pairing_node_attr(node, "id")
	n, valid := strconv.parse_uint(id, 10)
	if !valid || n >= MAX_USER_DEVICES {
		return {}, {kind = .Invalid_Response}
	}

	index, has_index := pairing_node_attr(node, "key-index")
	key_index: u32
	if has_index {
		value, ok := strconv.parse_uint(index, 10)
		if !ok || value > cast(uint)max(u32) {
			return {}, {kind = .Invalid_Response}
		}

		key_index = cast(u32)value
	}

	hosted, _ := pairing_node_attr(node, "is_hosted")
	return {
		user_jid = jid,
		id = cast(u32)n,
		key_index = key_index,
		is_hosted = hosted == "true",
	}, {}
}

// Group metadata codecs.

MAX_GROUP_PARTICIPANTS :: 2048

Group_Participant :: struct {
	// Keep the wire identity and its PN/LID mappings distinct. Resolving a
	// participant's devices belongs to the Signal delivery layer.
	jid, phone_number, lid, role: string,
}

Group_Metadata :: struct {
	jid,
	subject,
	description,
	description_id,
	addressing_mode: string,
	participants:                                               []Group_Participant,
}

Group_Error_Kind :: enum {
	None,
	Invalid_Group_JID,
	Invalid_Request_ID,
	Unexpected_Response,
	Server_Error,
	Invalid_Metadata,
	Invalid_UTF8,
	Duplicate_Participant,
	Participant_Limit,
	Destination_Undersized,
	Binary_Node_Failed,
}

Group_Error :: struct {
	kind:                  Group_Error_Kind,
	server_code:           u32,
	required_participants: int,
	binary:                Binary_Node_Error,
}

// Encodes the pinned Baileys groupMetadata query. Caller assigns a unique IQ
// ID and routes the matching result; this function performs no network I/O.
group_metadata_query_encode :: proc(
	dst: []u8,
	jid, request_id: string,
) -> (
	int,
	Group_Error,
) {
	if !group_jid_valid(jid) {
		return 0, {kind = .Invalid_Group_JID}
	}

	if len(request_id) == 0 ||
	   len(request_id) > 128 ||
	   !utf8.valid_string(request_id) {
		return 0, {kind = .Invalid_Request_ID}
	}

	node := Binary_Node {
		tag     = "iq",
		attrs   = []Binary_Node_Attribute {
			{"type", "get"},
			{"xmlns", "w:g2"},
			{"to", jid},
			{"id", request_id},
		},
		content = []Binary_Node {
			{
				tag = "query",
				attrs = []Binary_Node_Attribute {
					{"request", "interactive"},
				},
			},
		},
	}
	n, err := binary_node_encode(dst, node)
	if err.kind != .None {
		return n, {kind = .Binary_Node_Failed, binary = err}
	}

	return n, {}
}

// Strings borrow node's document (except jid, which borrows expected_jid).
// Participant storage belongs to the caller. Consume/copy before destroying
// the document. Validation completes before participant storage is modified.
group_metadata_decode :: proc(
	node: Binary_Node,
	expected_jid, request_id: string,
	storage: []Group_Participant,
) -> (
	Group_Metadata,
	Group_Error,
) {
	group, group_error := group_metadata_response_group(node, expected_jid, request_id)
	if group_error.kind != .None do return {}, group_error

	result := Group_Metadata {
		jid = expected_jid,
	}
	result.subject, _ = pairing_node_attr(group^, "subject")
	result.addressing_mode, _ = pairing_node_attr(
		group^,
		"addressing_mode",
	)
	if !utf8.valid_string(result.subject) {
		return {}, {kind = .Invalid_UTF8}
	}

	children, _ := group.content.([]Binary_Node)
	count, descriptions := 0, 0
	for child, i in children {
		if child.tag == "description" {
			descriptions += 1
			if descriptions > 1 {
				return {}, {kind = .Invalid_Metadata}
			}

			if description_error := group_metadata_description_decode(&result, child);
			   description_error.kind != .None do return {}, description_error
		}

		if child.tag != "participant" do continue

		participant, err := group_participant_decode(child)
		if err.kind != .None do return {}, err

		for previous in children[:i] {
			if previous.tag != "participant" do continue

			previous_jid, _ := pairing_node_attr(previous, "jid")
			if previous_jid == participant.jid {
				return {}, {kind = .Duplicate_Participant}
			}

		}
		count += 1
		if count > MAX_GROUP_PARTICIPANTS {
			return {}, {kind = .Participant_Limit}
		}

	}
	if len(storage) < count {
		return {}, {
			kind = .Destination_Undersized,
			required_participants = count,
		}
	}

	group_metadata_participants_copy(children, storage)
	result.participants = storage[:count]
	return result, {}
}

group_metadata_participants_copy :: proc(children: []Binary_Node, storage: []Group_Participant) {
	index := 0
	for child in children {
		if child.tag != "participant" do continue

		storage[index], _ = group_participant_decode(child)
		index += 1
	}
}

group_metadata_response_group :: proc(
	node: Binary_Node, expected_jid, request_id: string,
) -> (^Binary_Node, Group_Error) {
	if !group_jid_valid(expected_jid) {
		return nil, {kind = .Invalid_Group_JID}
	}

	if len(request_id) == 0 ||
	   len(request_id) > 128 ||
	   !utf8.valid_string(request_id) {
		return nil, {kind = .Invalid_Request_ID}
	}

	id, _ := pairing_node_attr(node, "id")
	kind, _ := pairing_node_attr(node, "type")
	from, has_from := pairing_node_attr(node, "from")
	if node.tag != "iq" ||
	   id != request_id ||
	   (has_from && from != expected_jid) {
		return nil, {kind = .Unexpected_Response}
	}

	if kind == "error" {
		code: u32
		if child, found := pairing_node_child(node, "error"); found {
			text, _ := pairing_node_attr(child^, "code")
			n, valid := strconv.parse_uint(text, 10)
			if valid && n <= cast(uint)max(u32) {
				code = cast(u32)n
			}

		}

		return nil, {kind = .Server_Error, server_code = code}
	}

	if kind != "result" {
		return nil, {kind = .Unexpected_Response}
	}

	group, found := pairing_node_child(node, "group")
	if !found do return nil, {kind = .Invalid_Metadata}

	root_children, _ := node.content.([]Binary_Node)
	groups := 0
	for child in root_children do if child.tag == "group" {
		groups += 1
	}

	if groups != 1 do return nil, {kind = .Invalid_Metadata}

	group_id, _ := pairing_node_attr(group^, "id")
	bare := expected_jid[:len(expected_jid) - len("@g.us")]
	if !slice.contains(
		[]type_of(group_id){expected_jid, bare},
		group_id,
	) {
		return nil, {kind = .Unexpected_Response}
	}

	return group, {}
}

group_metadata_description_decode :: proc(
	result: ^Group_Metadata, child: Binary_Node,
) -> Group_Error {
	result.description_id, _ = pairing_node_attr(child, "id")
	bodies := 0
	parts, _ := child.content.([]Binary_Node)
	for part in parts {
		if part.tag != "body" do continue

		bodies += 1
		if bodies > 1 {
			return {kind = .Invalid_Metadata}
		}

		data, bytes_content := part.content.([]u8)
		if !bytes_content {
			return {kind = .Invalid_Metadata}
		}

		result.description = cast(string)data
		if !utf8.valid_string(result.description) {
			return {kind = .Invalid_UTF8}
		}

	}
	return {}
}

group_jid_valid :: proc(jid: string) -> bool {
	if !strings.has_suffix(jid, "@g.us") ||
	   len(jid) <= len("@g.us") ||
	   len(jid) > 128 {
		return false
	}

	local := jid[:len(jid) - len("@g.us")]
	if !ascii.is_digit(local[0]) || !ascii.is_digit(local[len(local) - 1]) {
		return false
	}

	for c in local {
		if (!ascii.is_digit(c)) && c != '-' do return false

	}
	return true
}

group_participant_decode :: proc(
	node: Binary_Node,
) -> (
	Group_Participant,
	Group_Error,
) {
	result: Group_Participant
	result.jid, _ = pairing_node_attr(node, "jid")
	result.phone_number, _ = pairing_node_attr(node, "phone_number")
	result.lid, _ = pairing_node_attr(node, "lid")
	result.role, _ = pairing_node_attr(node, "type")
	// Unknown roles are retained. A new server role must not silently exclude
	// a participant from the recipient set.
	values := [4]string {
		result.jid,
		result.phone_number,
		result.lid,
		result.role,
	}
	for value in values {
		if !utf8.valid_string(value) {
			return {}, {kind = .Invalid_UTF8}
		}

	}
	if len(result.jid) == 0 ||
	   len(result.jid) > 256 ||
	   !(strings.has_suffix(result.jid, "@s.whatsapp.net") ||
			   strings.has_suffix(result.jid, "@lid")) {
		return {}, {kind = .Invalid_Metadata}
	}

	if _, _, err := pairing_jid_decode(result.jid);
	   err.kind != .None {
		return {}, {kind = .Invalid_Metadata}
	}

	if result.phone_number != "" {
		if !(strings.has_suffix(
				   result.phone_number,
				   "@s.whatsapp.net",
			   ) ||
			   strings.has_suffix(result.phone_number, "@c.us")) {
			return {}, {kind = .Invalid_Metadata}
		}

		if _, _, err := pairing_jid_decode(result.phone_number);
		   err.kind != .None {
			return {}, {kind = .Invalid_Metadata}
		}

	}

	if result.lid != "" {
		if !strings.has_suffix(result.lid, "@lid") {
			return {}, {kind = .Invalid_Metadata}
		}

		if _, _, err := pairing_jid_decode(result.lid);
		   err.kind != .None {
			return {}, {kind = .Invalid_Metadata}
		}

	}

	return result, {}
}

// PN/LID mappings and identity trust.

// Call only for PN/LID pairs from an authenticated, validated server query
// (for example fresh group metadata). Sender-provided protobuf/stanza claims
// must never call this API. Existing aliases and pinned identities cannot be
// silently reassigned. Returned addresses are owned and must be deleted.
socket_signal_address :: proc(
	socket: ^Socket,
	jid: string,
) -> (
	string,
	Socket_Error,
) {
	if socket == nil ||
	   socket.store == nil ||
	   !socket.store.initialized {
		return "", {kind = .Invalid_State}
	}

	return socket_signal_address_store(socket.store, jid)
}

socket_record_lid_mapping :: proc(
	socket: ^Socket,
	pn, lid: string,
) -> Socket_Error {
	if socket == nil || socket.store == nil {
		return {kind = .Invalid_State}
	}

	candidate: State_Store; defer state_store_clear(&candidate)
	if e := socket_store_clone(&candidate, socket.store);
	   e.kind != .None {
		return e
	}

	if e := socket_lid_mapping_stage(&candidate, pn, lid);
	   e.kind != .None {
		return e
	}

	if e := socket_lid_migrate(&candidate, socket.store);
	   e.kind != .None {
		return e
	}

	if candidate.revision == socket.store.revision {
		return {}
	}

	return socket_store_commit(socket, &candidate)
}

// Group metadata already passed the response id/group/server validation. All
// mappings and affected ratchets are committed together, including conflicts.
socket_record_group_lid_mappings :: proc(
	socket: ^Socket,
	metadata: Group_Metadata,
) -> Socket_Error {
	if socket == nil || socket.store == nil {
		return {kind = .Invalid_State}
	}

	candidate: State_Store; defer state_store_clear(&candidate)
	if e := socket_store_clone(&candidate, socket.store);
	   e.kind != .None {
		return e
	}

	for participant in metadata.participants {
		pn, lid := participant.phone_number, participant.lid
		if pn == "" &&
		   (strings.has_suffix(participant.jid, "@s.whatsapp.net") ||
				   strings.has_suffix(participant.jid, "@c.us")) {
			pn = participant.jid
		}

		if lid == "" && strings.has_suffix(participant.jid, "@lid") {
			lid = participant.jid
		}

		if pn == "" || lid == "" do continue

		if e := socket_lid_mapping_stage(&candidate, pn, lid);
		   e.kind != .None {
			return e
		}

	}
	if e := socket_lid_migrate(&candidate, socket.store);
	   e.kind != .None {
		return e
	}

	if candidate.revision == socket.store.revision {
		return {}
	}

	return socket_store_commit(socket, &candidate)
}

socket_signal_address_store :: proc(
	store: ^State_Store,
	jid: string,
) -> (
	string,
	Socket_Error,
) {
	user, device, e := pairing_jid_decode(jid)
	if e.kind != .None ||
	   device >= MAX_USER_DEVICES ||
	   len(jid) > 128 {
		return "", {kind = .Invalid_Config}
	}

	domain := jid[strings.index_byte(jid, '@') + 1:]
	if domain == "c.us" do domain = "s.whatsapp.net"

	bare := fmt.aprintf("%s@%s", user, domain); defer delete(bare)
	resolved := bare
	if domain == "lid" {
		key := fmt.aprintf("lid:%s", bare); defer delete(key)
		if target, have := state_store_get(store, .LID_Mapping, key);
		   have {
			pn := cast(string)target
			_, d, pe := pairing_jid_decode(pn)
			if pe.kind != .None ||
			   d != 0 ||
			   !strings.has_suffix(pn, "@s.whatsapp.net") {
				return "", {kind = .Protocol_Error}
			}

			reverse_key := fmt.aprintf("pn:%s", pn)
			defer delete(reverse_key)
			reverse, have_reverse := state_store_get(
				store,
				.LID_Mapping,
				reverse_key,
			)
			if !have_reverse || cast(string)reverse != bare {
				return "", {kind = .Protocol_Error}
			}

			resolved = pn
		}

	}

	at := strings.index_byte(resolved, '@')
	if device == 0 do return strings.clone(resolved), {}

	return fmt.aprintf(
		"%s:%d%s",
		resolved[:at],
		device,
		resolved[at:],
	), {}
}

socket_lid_mapping_stage :: proc(
	store: ^State_Store,
	pn, lid: string,
) -> Socket_Error {
	pn_user, pn_device, pe := pairing_jid_decode(pn)
	lid_user, lid_device, le := pairing_jid_decode(lid)
	if pe.kind != .None ||
	   le.kind != .None ||
	   pn_device != lid_device ||
	   pn_device >= MAX_USER_DEVICES ||
	   len(pn) > 128 ||
	   len(lid) > 128 ||
	   !(strings.has_suffix(pn, "@s.whatsapp.net") ||
			   strings.has_suffix(pn, "@c.us")) ||
	   !strings.has_suffix(lid, "@lid") {
		return {kind = .Invalid_Config}
	}

	bare_pn := fmt.aprintf("%s@s.whatsapp.net", pn_user)
	defer delete(bare_pn)
	bare_lid := fmt.aprintf("%s@lid", lid_user)
	defer delete(bare_lid)
	pn_key := fmt.aprintf("pn:%s", bare_pn); defer delete(pn_key)
	lid_key := fmt.aprintf("lid:%s", bare_lid); defer delete(lid_key)
	old_lid, have_pn := state_store_get(store, .LID_Mapping, pn_key)
	old_pn, have_lid := state_store_get(store, .LID_Mapping, lid_key)
	if have_pn && cast(string)old_lid != bare_lid ||
	   have_lid && cast(string)old_pn != bare_pn {
		return {kind = .Identity_Changed}
	}

	if !have_pn {
		if e := state_store_set(
			store,
			.LID_Mapping,
			pn_key,
			transmute([]u8)bare_lid,
		); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}

	}

	if !have_lid {
		if e := state_store_set(
			store,
			.LID_Mapping,
			lid_key,
			transmute([]u8)bare_pn,
		); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}

	}

	return {}
}

socket_lid_migrate :: proc(
	next, original: ^State_Store,
) -> Socket_Error {
	// Identity pins first: a mapping cannot bridge different cryptographic peers.
	kinds := [6]State_Record_Kind {
		.Identity,
		.Session,
		.Sender_Key,
		.Sender_Key_Membership,
		.Processed_Message,
		.Inbox_Message,
	}
	for kind in kinds {
		for record in original.records {
			if record.kind != kind do continue

			name, e := socket_lid_record_name(
				next,
				record.kind,
				record.name,
			)
			if e.kind != .None do return e

			defer delete(name)
			if name == record.name do continue

			if kind == .Session {
				if pin_error := socket_lid_session_pin_validate(next, record, name);
				   pin_error.kind != .None do return pin_error
			}

			if merge_error := socket_lid_record_merge(next, record, name);
			   merge_error.kind != .None do return merge_error

			if e := state_store_delete(next, kind, record.name);
			   e.kind != .None {
				return {kind = .State_Failed, state = e}
			}

		}
	}
	return {}
}

socket_lid_session_pin_validate :: proc(
	next: ^State_Store, record: State_Record, name: string,
) -> Socket_Error {
	owner := name
	if hash := strings.index_byte(owner, '#');
	   hash >= 0 {
		owner = owner[:hash]
	}

	if pin, found := state_store_get(
		next,
		.Identity,
		owner,
	); found {
		decoded := new(Signal_Session)
		defer {
			signal_session_clear(decoded); free(decoded)
		}
		if e := signal_session_decode(
			decoded,
			record.data,
		); e.kind != .None {
			return {kind = .Signal_Failed, signal = e}
		}

		if len(pin) != 32 ||
		   crypto.compare_constant_time(
			   pin,
			   decoded.remote_identity_public[:],
		   ) !=
			   1 {
			return {kind = .Identity_Changed}
		}

	}


	return {}
}

socket_lid_session_archive :: proc(
	next: ^State_Store, record: State_Record, name: string, existing: []u8,
) -> Socket_Error {
	incoming, current :=
		new(Signal_Session), new(Signal_Session)
	defer {
		signal_session_clear(incoming)
		signal_session_clear(current)
		free(incoming); free(current)
	}
	if e := signal_session_decode(
		incoming,
		record.data,
	); e.kind != .None {
		return {
			kind = .Signal_Failed,
			signal = e,
		}
	}

	if e := signal_session_decode(
		current,
		existing,
	); e.kind != .None {
		return {
			kind = .Signal_Failed,
			signal = e,
		}
	}

	if incoming.remote_identity_public !=
	   current.remote_identity_public {
		return {kind = .Identity_Changed}
	}

	// Divergent copies of one base cannot be merged without risking replay
	// or key/nonce reuse. Separate X3DH generations can be safely archived.
	if incoming.base_public ==
	   current.base_public {
		return {kind = .Invalid_State}
	}

	temporary := new(Socket)
	defer {
		crypto.zero_explicit(
			temporary,
			size_of(Socket),
		); free(temporary)
	}; temporary.store = next
	if archive_error := socket_archive_session(
		temporary,
		name,
		incoming,
	); archive_error.kind != .None {
		return archive_error
	}

	return {}
}

socket_lid_record_merge :: proc(
	next: ^State_Store, record: State_Record, name: string,
) -> Socket_Error {
	kind := record.kind
	if existing, have := state_store_get(next, kind, name);
	   have {
		if !bytes.equal(existing, record.data) {
			if kind == .Identity {
				return {kind = .Identity_Changed}
			}

			if kind == .Processed_Message {
				if len(record.data) == 8 &&
				   (len(existing) != 8 ||
						   bytes.compare(
							   record.data,
							   existing,
						   ) >
							   0) {
					if e := state_store_set(
						next,
						kind,
						name,
						record.data,
					); e.kind != .None {
						return {
							kind = .State_Failed,
							state = e,
						}
					}

				}

			} else if kind == .Session {
			if archive_error := socket_lid_session_archive(next, record, name, existing);
			   archive_error.kind != .None do return archive_error
			} else do return {kind = .Invalid_State}

		}

	} else {
		if e := state_store_set(
			next,
			kind,
			name,
			record.data,
		); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}

	}

	return {}
}

socket_lid_record_name :: proc(
	store: ^State_Store,
	kind: State_Record_Kind,
	name: string,
) -> (
	string,
	Socket_Error,
) {
	prefix, suffix, jid := "", "", name
	if kind == .Session {
		if at := strings.index_byte(name, '#'); at >= 0 {
			jid = name[:at]; suffix = name[at:]
		}

	} else if slice.contains(
		[]type_of(kind){.Sender_Key, .Sender_Key_Membership},
		kind,
	) {
		at := strings.index_byte(name, '|')
		if at < 0 do return "", {kind = .Protocol_Error}

		prefix = name[:at + 1]; jid = name[at + 1:]
	} else if slice.contains(
		[]type_of(kind){.Processed_Message, .Inbox_Message},
		kind,
	) {
		first := strings.index_byte(name, '|')
		if first < 0 do return strings.clone(name), {}

		second := strings.index_byte(name[first + 1:], '|')
		if second < 0 do return "", {kind = .Protocol_Error}

		second += first + 1; prefix = name[:first + 1]
		jid = name[first + 1:second]; suffix = name[second:]
	}

	resolved, e := socket_signal_address_store(store, jid)
	if e.kind != .None do return "", e

	defer delete(resolved)
	return fmt.aprintf("%s%s%s", prefix, resolved, suffix), {}
}

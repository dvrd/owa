package whatsapp


import "core:bytes"
import "core:crypto"
import "core:fmt"
import "core:slice"
import "core:strings"
import "core:time"
import "core:unicode/utf8"

Socket_Group_Summary :: struct {
	jid, subject: string,
}

socket_group_summaries_destroy :: proc(
	groups: ^[dynamic]Socket_Group_Summary,
) {
	if groups == nil do return

	for group in groups^ {
		delete(group.jid)
		delete(group.subject)
	}
	delete(groups^)
	groups^ = {}
}

// This request matches Baileys' participating-groups IQ. The returned
// summaries own their strings and remain valid after the response is freed.
socket_groups_participating :: proc(
	socket: ^Socket,
) -> (
	[dynamic]Socket_Group_Summary,
	Socket_Error,
) {
	if socket == nil do return {}, {kind = .Invalid_Config}

	id_buffer: [128]u8
	id := socket_next_id(socket, id_buffer[:])
	doc, query_error := socket_query(
		socket,
		{
			tag = "iq",
			attrs = []Binary_Node_Attribute {
				{"type", "get"},
				{"xmlns", "w:g2"},
				{"to", "@g.us"},
				{"id", id},
			},
			content = []Binary_Node {
				{
					tag = "participating",
					content = []Binary_Node {
						{tag = "participants"},
						{tag = "description"},
					},
				},
			},
		},
	)
	if query_error.kind != .None do return {}, query_error

	defer binary_document_destroy(&doc)
	return socket_groups_decode(doc.root, id)
}

socket_groups_decode :: proc(
	root: Binary_Node,
	request_id: string,
) -> (
	[dynamic]Socket_Group_Summary,
	Socket_Error,
) {
	children, children_error := socket_groups_children_decode(root, request_id)
	if children_error.kind != .None do return {}, children_error

	groups: [dynamic]Socket_Group_Summary
	groups.allocator = context.allocator
	seen := make(map[string]bool)
	defer delete(seen)
	success := false
	defer if !success do socket_group_summaries_destroy(&groups)
	for child in children {
		if child.tag != "group" do continue

		if len(groups) >= 10000 {
			return {}, {kind = .Protocol_Error}
		}

		group_id, present := pairing_node_attr(child, "id")
		subject, _ := pairing_node_attr(child, "subject")
		if !present ||
		   !utf8.valid_string(group_id) ||
		   !utf8.valid_string(subject) {
			return {}, {kind = .Protocol_Error}
		}

		jid := strings.clone(group_id)
		if !strings.contains(group_id, "@") {
			delete(jid)
			jid = fmt.aprintf("%s@g.us", group_id)
		}
		if !group_jid_valid(jid) {
			delete(jid)
			return {}, {kind = .Protocol_Error}
		}

		if jid in seen {
			delete(jid)
			return {}, {kind = .Protocol_Error}
		}

		subject_copy := strings.clone(subject)
		if _, err := append(
			&groups,
			{jid = jid, subject = subject_copy},
		); err != nil {
			delete(jid)
			delete(subject_copy)
			return {}, {kind = .Protocol_Error}
		}
		seen[jid] = true
	}
	success = true
	return groups, {}
}

socket_groups_children_decode :: proc(
	root: Binary_Node, request_id: string,
) -> ([]Binary_Node, Socket_Error) {
	id, _ := pairing_node_attr(root, "id")
	kind, _ := pairing_node_attr(root, "type")
	if root.tag != "iq" || id != request_id || kind != "result" {
		return nil, {kind = .Protocol_Error}
	}

	container, found := pairing_node_child(root, "groups")
	if !found do return nil, {kind = .Protocol_Error}

	children, ok := container.content.([]Binary_Node)
	if !ok && container.content != nil {
		return nil, {kind = .Protocol_Error}
	}

	return children, {}
}

Socket_Group :: struct {
	metadata:     Group_Metadata,
	document:     Binary_Document,
	participants: []Group_Participant,
	jid:          string,
}
socket_group_destroy :: proc(group: ^Socket_Group) {
	if group == nil do return

	binary_document_destroy(&group.document)
	delete(group.participants)
	delete(group.jid)
	group^ = {}
}

socket_group_metadata :: proc(
	socket: ^Socket,
	jid: string,
) -> (
	Socket_Group,
	Socket_Error,
) {
	result: Socket_Group
	if !group_jid_valid(jid) {
		return {}, {kind = .Invalid_Config}
	}

	id_buffer: [128]u8
	id := socket_next_id(socket, id_buffer[:])
	doc, query_err := socket_query(
		socket,
		{
			tag = "iq",
			attrs = []Binary_Node_Attribute {
				{"type", "get"},
				{"xmlns", "w:g2"},
				{"to", jid},
				{"id", id},
			},
			content = []Binary_Node {
				{
					tag = "query",
					attrs = []Binary_Node_Attribute {
						{"request", "interactive"},
					},
				},
			},
		},
	)
	if query_err.kind != .None do return {}, query_err

	result.document = doc
	success := false
	defer if !success do socket_group_destroy(&result)

	if metadata_error := socket_group_metadata_decode(&result, doc, jid, id);
	   metadata_error.kind != .None do return {}, metadata_error
	metadata := result.metadata
	if e := socket_record_group_lid_mappings(socket, metadata);
	   e.kind != .None {
		return {}, e
	}

	success = true
	return result, {}
}

socket_group_metadata_decode :: proc(
	result: ^Socket_Group, doc: Binary_Document, jid, id: string,
) -> Socket_Error {
	result.jid = strings.clone(jid)
	_, measured := group_metadata_decode(
		doc.root,
		result.jid,
		id,
		nil,
	)
	if !slice.contains(
		[]type_of(measured.kind){.None, .Destination_Undersized},
		measured.kind,
	) {
		return {kind = .Protocol_Error}
	}

	result.participants = make(
		[]Group_Participant,
		measured.required_participants,
	)
	metadata, decoded := group_metadata_decode(
		doc.root,
		result.jid,
		id,
		result.participants,
	)
	if decoded.kind != .None {
		return {kind = .Protocol_Error}
	}

	result.metadata = metadata
	return {}
}

socket_send_text :: proc(
	socket: ^Socket,
	group, text: string,
	quote: ^Socket_Message = nil,
) -> (
	string,
	Socket_Error,
) {
	message := Text_Message {
		kind = .Conversation,
		text = text,
	}
	if quote != nil {
		if quote.group != group {
			return "", {kind = .Invalid_Config}
		}

		message.kind, message.has_context = .Extended_Text, true
		message.context_info = {
			stanza_id          = quote.id,
			participant        = quote.participant,
			remote_jid         = group,
			quoted_message     = quote.protobuf,
			has_stanza_id      = true,
			has_participant    = true,
			has_remote_jid     = true,
			has_quoted_message = true,
		}
	}

	buffer := make(
		[]u8,
		min(
			MAX_SIGNAL_PLAINTEXT_SIZE,
			len(text) +
			1024 +
			(quote == nil ? 0 : len(quote.protobuf)),
		),
	)
	defer delete(buffer)
	n, err := text_message_encode(buffer, message)
	if err != .None {
		return "", {kind = .Message_Failed, message = err}
	}

	return socket_send_group(socket, group, buffer[:n])
}

// Returns an owned message ID. Caller releases it after retaining its value
// wherever application quote/confirmation tracking requires it.
socket_send_group :: proc(
	socket: ^Socket,
	group: string,
	protobuf: []u8,
	media_type: string = "",
	message_id: string = "",
	only_device: string = "",
) -> (
	string,
	Socket_Error,
) {
	if socket == nil ||
	   socket.phase != .Online ||
	   len(protobuf) + 16 > MAX_SIGNAL_PLAINTEXT_SIZE {
		return "", {kind = .Invalid_State}
	}

	metadata, meta_err := socket_group_metadata(socket, group)
	if meta_err.kind != .None do return "", meta_err

	defer socket_group_destroy(&metadata)
	devices, device_err := socket_group_devices(
		socket,
		metadata.metadata,
	)
	if device_err.kind == .None && only_device != "" {
		devices, device_err = socket_group_device_select(socket, devices, only_device)
	}

	if device_err.kind != .None do return "", device_err

	defer {for jid in devices do delete(jid); delete(devices)}
	mode := metadata.metadata.addressing_mode
	me := cast(string)socket.auth.account.jid[:socket.auth.account.jid_size]
	self_lid_copy := ""
	defer delete(self_lid_copy)
	if mode == "lid" {
		lid, found := state_store_get(
			socket.store,
			.LID_Mapping,
			"self",
		)
		if !found do return "", {kind = .Invalid_State}

		// Queries can replace the state store. Keep this copy until the whole
		// send finishes, beyond the lifetime of this conditional block.
		self_lid_copy = strings.clone(cast(string)lid)
		me = self_lid_copy
	}

	canonical_me, canonical_err := socket_signal_address(socket, me)
	if canonical_err.kind != .None {
		return "", canonical_err
	}

	defer delete(canonical_me)
	return socket_group_send_prepared(
		socket, group, mode, media_type, message_id, only_device, canonical_me, protobuf, devices,
	)
}

socket_group_device_select :: proc(
	socket: ^Socket, devices: []string, only_device: string,
) -> ([]string, Socket_Error) {
	if !device_user_valid(only_device, true) {
		for jid in devices do delete(jid); delete(devices)
		return nil, {kind = .Invalid_Config}
	}

	requested, e := socket_signal_address(socket, only_device)
	if e.kind != .None {
		for jid in devices do delete(jid); delete(devices)
		return nil, e
	}

	defer delete(requested)
	selected := ""
	for jid in devices {
		canonical, canonical_err := socket_signal_address(socket, jid)
		if canonical_err.kind != .None {
			for item in devices do delete(item); delete(devices)
			return nil, canonical_err
		}

		if canonical == requested {
			delete(selected); selected = strings.clone(jid)
		}

		delete(canonical)
	}
	for jid in devices do delete(jid)
	delete(devices)
	if selected == "" {
		return nil, {kind = .Invalid_Config}
	}

	selected_devices := make([]string, 1)
	selected_devices[0] = selected
	return selected_devices, {}
}

socket_group_sender_prepare :: proc(
	socket: ^Socket, record: ^Signal_Group_Record, key_name, members, only_device: string,
) -> Socket_Error {
	if snapshot, found := state_store_get(
		socket.store,
		.Sender_Key,
		key_name,
	); found {
		if e := signal_group_record_decode(record, snapshot);
		   e != .None {
			return {kind = .Group_Failed, group = e}
		}
	}

	// Fresh metadata/device discovery is used for every send. A changed
	// recipient set rotates the sender key, excluding removed devices.
	old_members, have_members := state_store_get(
		socket.store,
		.Sender_Key_Membership,
		key_name,
	)
	if record.count == 0 ||
	   only_device == "" &&
		   (!have_members ||
				   !bytes.equal(
						   old_members,
						   transmute([]u8)members,
					   )) {
		seed, signing: [32]u8
		id_bytes: [4]u8
		crypto.rand_bytes(seed[:]); crypto.rand_bytes(signing[:])
		crypto.rand_bytes(id_bytes[:])
		defer crypto.zero_explicit(&seed, size_of(seed))
		defer crypto.zero_explicit(&signing, size_of(signing))
		id :=
			cast(u32)id_bytes[0] << 24 |
			cast(u32)id_bytes[1] << 16 |
			cast(u32)id_bytes[2] << 8 |
			cast(u32)id_bytes[3]
		if e := signal_group_init_sender(record, id, seed, signing);
		   e != .None {
			return {kind = .Group_Failed, group = e}
		}
	}

	return {}
}

socket_group_distribution_pad :: proc(
	group: string, record: ^Signal_Group_Record,
) -> ([]u8, Socket_Error) {
	distribution: [256]u8
	distribution_size, dist_err := signal_group_distribution_encode(
		distribution[:],
		record,
	)
	if dist_err != .None {
		return nil, {kind = .Group_Failed, group = dist_err}
	}

	distro_message: [512]u8
	distro_size, message_err := text_message_encode(
		distro_message[:],
		{
			has_sender_key_distribution = true,
			sender_key_distribution = {
				group_id = group,
				distribution = distribution[:distribution_size],
				has_group_id = true,
				has_distribution = true,
			},
		},
	)
	if message_err != .None {
		return nil, {kind = .Message_Failed, message = message_err}
	}

	padded_distribution := socket_pad(distro_message[:distro_size])
	return padded_distribution, {}
}

Socket_Group_Participants :: struct {
	participant_nodes: []Binary_Node,
	participant_children: [][1]Binary_Node,
	participant_attrs: [][1]Binary_Node_Attribute,
	ciphertexts: [][]u8,
	enc_attrs: [][3]Binary_Node_Attribute,
	include_identity: bool,
}

socket_group_participants_destroy :: proc(participants: ^Socket_Group_Participants) {
	for data in participants.ciphertexts do delete(data)
	delete(participants.ciphertexts)
	delete(participants.participant_nodes)
	delete(participants.participant_children)
	delete(participants.participant_attrs)
	delete(participants.enc_attrs)
	participants^ = {}
}


socket_group_distribution_encrypt :: proc(
	socket: ^Socket, jid: string, ciphertext, padded_distribution: []u8,
) -> (Signal_Message_Type, int, Socket_Error) {
	session := new(Signal_Session)
	defer {signal_session_clear(session); free(session)}
	if e := socket_outgoing_session(socket, jid, session);
	   e.kind != .None {
		return {}, 0, e
	}

	kind, size, e := signal_session_encrypt(
		session,
		ciphertext,
		padded_distribution,
		session.remote_identity_public,
	)
	if e.kind != .None {
		return {}, 0, {kind = .Signal_Failed, signal = e}
	}

	if saved := socket_stage_session(socket, jid, session);
	   saved.kind != .None {
		return {}, 0, saved
	}

	return kind, size, {}
}

socket_group_participants_prepare :: proc(
	socket: ^Socket, devices: []string, padded_distribution: []u8, media_type: string,
) -> (Socket_Group_Participants, Socket_Error) {
	result: Socket_Group_Participants
	result.participant_nodes = make([]Binary_Node, len(devices))
	result.participant_children = make([][1]Binary_Node, len(devices))
	result.participant_attrs = make(
		[][1]Binary_Node_Attribute,
		len(devices),
	)
	result.ciphertexts = make([][]u8, len(devices))
	result.enc_attrs = make([][3]Binary_Node_Attribute, len(devices))
	success := false
	defer if !success do socket_group_participants_destroy(&result)
	for jid, i in devices {
		result.ciphertexts[i] = make([]u8, 2048)
		kind, size, encryption_error := socket_group_distribution_encrypt(
			socket, jid, result.ciphertexts[i], padded_distribution,
		)
		if encryption_error.kind != .None do return {}, encryption_error
		type := "msg"
		if kind == .Prekey {
			type = "pkmsg"; result.include_identity = true
		}

		result.enc_attrs[i] = {
			{"v", "2"},
			{"type", type},
			{"mediatype", media_type},
		}
		attr_count := media_type == "" ? 2 : 3
		result.participant_children[i] = {
			{
				tag = "enc",
				attrs = result.enc_attrs[i][:attr_count],
				content = result.ciphertexts[i][:size],
			},
		}
		result.participant_attrs[i] = {{"jid", jid}}
		result.participant_nodes[i] = {
			tag     = "to",
			attrs   = result.participant_attrs[i][:],
			content = result.participant_children[i][:],
		}
	}
	success = true
	return result, {}
}

socket_group_sender_stage :: proc(
	socket: ^Socket, record: ^Signal_Group_Record, key_name, members, only_device: string,
) -> Socket_Error {
	group_snapshot := make([]u8, MAX_STATE_RECORD_SIZE)
	defer {
		crypto.zero_explicit(
			raw_data(group_snapshot),
			len(group_snapshot),
		); delete(group_snapshot)
	}
	group_size, stored := signal_group_record_encode(
		group_snapshot,
		record,
	)
	if stored != .None {
		return {kind = .Group_Failed, group = stored}
	}

	if e := state_store_set(
		socket.store,
		.Sender_Key,
		key_name,
		group_snapshot[:group_size],
	); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	if only_device == "" {
		if e := state_store_set(
			socket.store,
			.Sender_Key_Membership,
			key_name,
			transmute([]u8)members,
		); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}

	return {}
}

socket_group_stanza_wire :: proc(
	group, mode, only_device, id: string, ciphertext, identity: []u8,
	participant_nodes: []Binary_Node, include_identity: bool,
) -> ([]u8, Socket_Error) {
	children := [?]Binary_Node {
		{
			tag = "enc",
			attrs = []Binary_Node_Attribute {
				{"v", "2"},
				{"type", "skmsg"},
			},
			content = ciphertext,
		},
		{tag = "participants", content = participant_nodes[:]},
		{
			tag = "device-identity",
			content = identity,
		},
	}
	child_count := include_identity ? 3 : 2
	effective_mode := mode
	if effective_mode == "" do effective_mode = "pn"

	node := Binary_Node {
		tag     = "message",
		attrs   = []Binary_Node_Attribute {
			{"id", id},
			{"type", "text"},
			{"to", group},
			{"addressing_mode", effective_mode},
		},
		content = children[:child_count],
	}
	node_attrs := [5]Binary_Node_Attribute {
		{"id", id},
		{"type", "text"},
		{"to", group},
		{"addressing_mode", effective_mode},
		{"participant", only_device},
	}
	node.attrs = node_attrs[:only_device == "" ? 4 : 5]
	size, measured := binary_node_encode(nil, node)
	if measured.kind != .Destination_Undersized {
		return nil, {kind = .Binary_Failed, binary = measured}
	}

	wire := make([]u8, size)
	_, encoded := binary_node_encode(wire, node)
	if encoded.kind != .None {
		delete(wire)
		return nil, {kind = .Binary_Failed, binary = encoded}
	}

	return wire, {}
}

socket_group_stanza_encode :: proc(
	socket: ^Socket, group, mode, only_device, id: string, ciphertext: []u8,
	participants: ^Socket_Group_Participants,
) -> ([]u8, Socket_Error) {
	identity: [MAX_PAIRING_IDENTITY_SIZE]u8
	identity_size := 0
	if participants.include_identity {
		a := &socket.auth.account
		n, e := pairing_signed_identity_encode(
			identity[:],
			{
				details = a.details[:a.details_size],
				account_signature_key = a.account_signature_key[:],
				account_signature = a.account_signature[:],
				device_signature = a.device_signature[:],
			},
			true,
		)
		if e != .None do return nil, {kind = .Protocol_Error}

		identity_size = n
	}

	return socket_group_stanza_wire(
		group, mode, only_device, id, ciphertext, identity[:identity_size],
		participants.participant_nodes, participants.include_identity,
	)
}

socket_group_content_stage :: proc(
	socket: ^Socket, group, media_type, id: string, protobuf: []u8,
) -> Socket_Error {
	// Ratchets and the exact ciphertext share one atomic transaction. Reconnect
	// can replay this stanza without ever regenerating a used message key.
	created := fmt.aprintf("%d", time.now()._nsec / 1_000_000_000)
	defer delete(created)
	saved_content := Binary_Node {
		tag     = "saved",
		attrs   = []Binary_Node_Attribute {
			{"to", group},
			{"mediatype", media_type},
			{"t", created},
		},
		content = protobuf,
	}
	content_size, _ := binary_node_encode(nil, saved_content)
	content_wire := make([]u8, content_size)
	defer delete(content_wire)
	if _, e := binary_node_encode(content_wire, saved_content);
	   e.kind != .None {
		return {kind = .Binary_Failed, binary = e}
	}

	if e := state_store_set(
		socket.store,
		.Outbound_Content,
		id,
		content_wire,
	); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	return {}
}

socket_group_outbound_commit :: proc(
	socket: ^Socket, group, media_type, id: string, protobuf, wire: []u8,
) -> Socket_Error {
	if content_error := socket_group_content_stage(socket, group, media_type, id, protobuf);
	   content_error.kind != .None do return content_error
	if e := state_store_set(
		socket.store,
		.Outbound_Message,
		id,
		wire,
	); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	if e := state_store_save(socket.store, socket.config.state_path);
	   e.kind != .None {
		return socket_fail(
			socket,
			{kind = .State_Failed, state = e},
		)
	}

	return {}
}

socket_group_dispatch :: proc(
	socket: ^Socket, group, mode, media_type, message_id, only_device: string,
	protobuf, ciphertext: []u8, participants: ^Socket_Group_Participants,
) -> (string, Socket_Error) {
	id := socket_message_id()
	if message_id != "" {
		delete(id); id = strings.clone(message_id)
	}

	success := false
	defer if !success do delete(id)

	wire, wire_error := socket_group_stanza_encode(
		socket, group, mode, only_device, id, ciphertext, participants,
	)
	if wire_error.kind != .None do return "", wire_error
	defer delete(wire)
	if commit_error := socket_group_outbound_commit(socket, group, media_type, id, protobuf, wire);
	   commit_error.kind != .None do return "", commit_error

	success = true
	if e := socket_write(socket, wire); e.kind != .None {
		return id, e
	}

	return id, {}
}

socket_group_payload_send :: proc(
	socket: ^Socket, group, mode, media_type, message_id, only_device, key_name, members: string,
	protobuf: []u8, record: ^Signal_Group_Record, participants: ^Socket_Group_Participants,
) -> (string, Socket_Error) {
	padded := socket_pad(protobuf)
	defer {
		crypto.zero_explicit(raw_data(padded), len(padded))
		delete(padded)
	}
	ciphertext := make([]u8, len(padded) + 256)
	defer delete(ciphertext)
	cipher_size, group_err := signal_group_encrypt(
		ciphertext,
		record,
		padded,
	)
	if group_err != .None {
		return "", {kind = .Group_Failed, group = group_err}
	}

	if stage_error := socket_group_sender_stage(socket, record, key_name, members, only_device);
	   stage_error.kind != .None do return "", stage_error
	return socket_group_dispatch(
		socket, group, mode, media_type, message_id, only_device,
		protobuf, ciphertext[:cipher_size], participants,
	)
}

socket_group_send_prepared :: proc(
	socket: ^Socket, group, mode, media_type, message_id, only_device, canonical_me: string,
	protobuf: []u8, devices: []string,
) -> (string, Socket_Error) {
	key_name := fmt.aprintf("%s|%s", group, canonical_me)
	defer delete(key_name)
	record := new(Signal_Group_Record)
	defer {signal_group_record_clear(record); free(record)}
	members := strings.join(devices[:], "\n")
	defer delete(members)
	if sender_error := socket_group_sender_prepare(socket, record, key_name, members, only_device);
	   sender_error.kind != .None do return "", sender_error
	padded_distribution, distribution_error := socket_group_distribution_pad(group, record)
	if distribution_error.kind != .None do return "", distribution_error
	defer {
		crypto.zero_explicit(
			raw_data(padded_distribution),
			len(padded_distribution),
		); delete(padded_distribution)
	}
	participants, participant_error := socket_group_participants_prepare(
		socket, devices, padded_distribution, media_type,
	)
	if participant_error.kind != .None do return "", participant_error
	defer socket_group_participants_destroy(&participants)
	return socket_group_payload_send(
		socket, group, mode, media_type, message_id, only_device, key_name, members,
		protobuf, record, &participants,
	)
}

socket_stage_session :: proc(
	socket: ^Socket,
	jid: string,
	session: ^Signal_Session,
) -> Socket_Error {
	base, suffix := jid, ""
	if at := strings.index_byte(jid, '#'); at >= 0 {
		base = jid[:at]; suffix = jid[at:]
	}

	canonical, e := socket_signal_address(socket, base)
	if e.kind != .None do return e

	defer delete(canonical)
	address := fmt.aprintf("%s%s", canonical, suffix)
	defer delete(address)
	buffer := make([]u8, MAX_SIGNAL_SESSION_STORE_SIZE)
	defer {
		crypto.zero_explicit(raw_data(buffer), len(buffer))
		delete(buffer)
	}
	n, err := signal_session_encode(buffer, session)
	if err.kind != .None {
		return {kind = .Signal_Failed, signal = err}
	}

	if e := state_store_set(
		socket.store,
		.Session,
		address,
		buffer[:n],
	); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	return {}
}

socket_outgoing_session :: proc(
	socket: ^Socket,
	jid: string,
	session: ^Signal_Session,
) -> Socket_Error {
	address, address_err := socket_signal_address(socket, jid)
	if address_err.kind != .None do return address_err

	defer delete(address)
	if data, found := state_store_get(
		socket.store,
		.Session,
		address,
	); found {
		return socket_outgoing_session_cached(socket, session, data, address)
	}

	id_buffer: [128]u8
	id := socket_next_id(socket, id_buffer[:])
	doc, query_err := socket_outgoing_keys_query(socket, jid, id)
	if query_err.kind != .None do return query_err

	defer binary_document_destroy(&doc)
	requested := [1]string{jid}
	bundles: [1]Remote_Key_Bundle
	_, e := device_keys_response_decode(
		doc.root,
		requested[:],
		id,
		bundles[:],
	)
	if e.kind != .None {
		return {kind = .Device_Failed, device = e}
	}

	bundle := bundles[0].bundle
	if identity_error := socket_outgoing_identity_validate(socket, address, &bundle);
	   identity_error.kind != .None do return identity_error

	if err := signal_session_init_initiator(
		session,
		socket.auth.credentials.identity_private,
		socket.auth.credentials.registration_id,
		bundle,
		bundle.identity_public,
	); err.kind != .None {
		return {kind = .Signal_Failed, signal = err}
	}

	if e := state_store_set(
		socket.store,
		.Identity,
		address,
		bundle.identity_public[:],
	); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	return {}
}

socket_outgoing_identity_validate :: proc(
	socket: ^Socket, address: string, bundle: ^Signal_Prekey_Bundle,
) -> Socket_Error {
	if old, found := state_store_get(
		socket.store,
		.Identity,
		address,
	); found {
		if len(old) != 32 ||
		   crypto.compare_constant_time(
			   old,
			   bundle.identity_public[:],
		   ) !=
			   1 {
			return {kind = .Identity_Changed}
		}
	}

	return {}
}

socket_outgoing_session_cached :: proc(
	socket: ^Socket, session: ^Signal_Session, data: []u8, address: string,
) -> Socket_Error {
	if e := signal_session_decode(session, data);
	   e.kind != .None {
		return {kind = .Signal_Failed, signal = e}
	}

	identity, pinned := state_store_get(
		socket.store,
		.Identity,
		address,
	)
	if !pinned ||
	   len(identity) != 32 ||
	   crypto.compare_constant_time(
		   identity,
		   session.remote_identity_public[:],
	   ) !=
		   1 {
		return {kind = .Identity_Changed}
	}

	return {}
}

socket_outgoing_keys_query :: proc(
	socket: ^Socket, jid, id: string,
) -> (Binary_Document, Socket_Error) {
	return socket_query(
		socket,
		{
			tag = "iq",
			attrs = []Binary_Node_Attribute {
				{"xmlns", "encrypt"},
				{"type", "get"},
				{"to", "@s.whatsapp.net"},
				{"id", id},
			},
			content = []Binary_Node {
				{
					tag = "key",
					content = []Binary_Node {
						{
							tag = "user",
							attrs = []Binary_Node_Attribute {
								{"jid", jid},
							},
						},
					},
				},
			},
		},
	)
}

socket_group_devices :: proc(
	socket: ^Socket,
	group: Group_Metadata,
) -> (
	result: []string,
	err: Socket_Error,
) {
	users := make([dynamic]string)
	defer {for user in users do delete(user); delete(users)}
	if users_error := socket_group_users_collect(group, &users);
	   users_error.kind != .None do return nil, users_error
	devices := make([dynamic]string)
	success := false
	defer if !success {
		for jid in devices do delete(jid); delete(devices)
	}

	me := cast(string)socket.auth.account.jid[:socket.auth.account.jid_size]
	lid_bytes, have_lid := state_store_get(
		socket.store,
		.LID_Mapping,
		"self",
	)
	lid := strings.clone(cast(string)lid_bytes)
	defer delete(lid)
	for start := 0;
	    start < len(users);
	    start += MAX_DEVICE_QUERY_USERS {
		batch := users[start:min(
			start + MAX_DEVICE_QUERY_USERS,
			len(users),
		)]
		if batch_error := socket_group_devices_batch(socket, batch, &devices, me, lid, have_lid);
		   batch_error.kind != .None do return nil, batch_error
	}
	result = make([]string, len(devices))
	copy(result, devices[:])
	delete(devices)
	success = true
	return result, {}
}

socket_group_users_collect :: proc(
	group: Group_Metadata, users: ^[dynamic]string,
) -> Socket_Error {
	for p in group.participants {
		jid := p.jid
		if group.addressing_mode == "lid" &&
		   !strings.has_suffix(jid, "@lid") {
			jid = p.lid
		}

		if group.addressing_mode != "lid" &&
		   !strings.has_suffix(jid, "@s.whatsapp.net") {
			jid = p.phone_number
		}

		user, _, parse_err := pairing_jid_decode(jid)
		if parse_err.kind != .None {
			return {kind = .Invalid_Config}
		}

		domain := jid[strings.index_byte(jid, '@') + 1:]
		if domain == "c.us" do domain = "s.whatsapp.net"

		normalized := fmt.aprintf("%s@%s", user, domain)
		if !device_user_valid(normalized, false) {
			delete(normalized); return {kind = .Invalid_Config}
		}

		duplicate := false
		for existing in users^ do if existing == normalized {
			duplicate = true
		}

		if duplicate {
			delete(normalized)
		} else {
			append(users, normalized)
		}
	}
	return {}
}

socket_group_devices_append :: proc(
	storage: []Remote_Device, devices: ^[dynamic]string, me, lid: string, have_lid: bool,
) -> Socket_Error {
	for device in storage {
		buffer: [128]u8
		jid, jid_err := remote_device_jid(buffer[:], device)
		if jid_err.kind != .None {
			return {kind = .Device_Failed, device = jid_err}
		}

		if socket_same_device(jid, me) ||
		   have_lid && socket_same_device(jid, lid) {
			continue
		}

		duplicate := false
		for existing in devices^ do if jid == existing {
			duplicate = true
		}

		if !duplicate {
			append(devices, strings.clone(jid))
		}
	}
	return {}
}

socket_group_devices_batch :: proc(
	socket: ^Socket, batch: []string, devices: ^[dynamic]string, me, lid: string, have_lid: bool,
) -> Socket_Error {
	query_buffer := make([]u8, 65536)
	defer delete(query_buffer)
	id_buffer: [128]u8
	id := socket_next_id(socket, id_buffer[:])
	n, encoded := devices_query_encode(query_buffer, batch, id)
	if encoded.kind != .None {
		return {kind = .Device_Failed, device = encoded}
	}

	query, decoded := binary_node_decode(query_buffer[:n])
	if decoded.kind != .None {
		return {kind = .Binary_Failed, binary = decoded}
	}

	defer binary_document_destroy(&query)
	doc, query_err := socket_query(socket, query.root)
	if query_err.kind != .None do return query_err

	defer binary_document_destroy(&doc)
	_, measured := devices_response_decode(
		doc.root,
		batch,
		id,
		nil,
	)
	if !slice.contains(
		[]type_of(measured.kind){.None, .Destination_Undersized},
		measured.kind,
	) {
		return {kind = .Device_Failed, device = measured}
	}

	storage := make([]Remote_Device, measured.required)
	defer delete(storage)
	count, parsed := devices_response_decode(
		doc.root,
		batch,
		id,
		storage,
	)
	if parsed.kind != .None {
		return {kind = .Device_Failed, device = parsed}
	}

	return socket_group_devices_append(storage[:count], devices, me, lid, have_lid)
}

socket_pad :: proc(message: []u8) -> []u8 {
	byte: [1]u8
	crypto.rand_bytes(byte[:])
	n := cast(int)(byte[0] & 15) + 1
	result := make([]u8, len(message) + n)
	copy(result, message)
	for &c in result[len(message):] do c = cast(u8)n
	return result
}
socket_message_id :: proc() -> string {
	random: [9]u8
	crypto.rand_bytes(random[:])
	buffer: [22]u8
	copy(buffer[:], []u8{'3', 'E', 'B', '0'})
	digits := "0123456789ABCDEF"
	for b, i in random {
		buffer[4 + i * 2] = digits[b >> 4]
		buffer[5 + i * 2] = digits[b & 15]
	}
	return strings.clone(cast(string)buffer[:])
}

socket_same_device :: proc(a, b: string) -> bool {
	au, ad, ae := pairing_jid_decode(a)
	bu, bd, be := pairing_jid_decode(b)
	if ae.kind != .None || be.kind != .None || au != bu || ad != bd {
		return false
	}

	a_lid := strings.has_suffix(a, "@lid")
	b_lid := strings.has_suffix(b, "@lid")
	return a_lid == b_lid
}

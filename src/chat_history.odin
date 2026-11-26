package whatsapp

import "core:crypto"
import "core:encoding/endian"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:time"

// WhatsApp expects the original Unix timestamp in seconds, including for its
// oldestMsgTimestampMS field. An empty cursor requests initial reverse history.
Chat_History_Cursor :: struct {
	id:        string,
	timestamp: u64,
	from_me:   bool,
}

MAX_CHAT_HISTORY_MESSAGES :: 50
Pending_Chat_History :: struct {
	id:            string,
	notifications: [dynamic][]u8,
	bytes:         int,
}

// The ID borrows the stored record. Only the remote message time can position a history request.
decode_chat_history_cursor :: proc(data: []u8) -> (Chat_History_Cursor, bool) {
	if len(data) < 10 || len(data) > 137 || data[8] > 1 {
		return {}, false
	}

	stamp := endian.unchecked_get_u64be(data[:8])
	id := string(data[9:])
	if stamp == 0 || stamp > u64(max(i64)) || !socket_inbox_id_valid(id) {
		return {}, false
	}

	return {id = id, timestamp = stamp, from_me = data[8] == 1}, true
}

// Keep one reference per private chat in the same transaction as live inbox delivery.
store_chat_history_cursor :: proc(store: ^State_Store, message: ^Socket_Message) -> State_Error {
	if message.group != "" || message.timestamp == 0 || message.timestamp > u64(max(i64)) {
		return {}
	}

	peer := message.recipient if message.from_me else message.participant
	if !device_user_jid_valid(peer, true) {
		return {}
	}

	user, _, _ := pairing_jid_decode(peer)
	jid := strings.concatenate({user, peer[strings.index_byte(peer, '@'):]})

	defer delete(jid)

	if data, found := state_store_get(store, .Chat_History_Cursor, jid); found {
		old, ok := decode_chat_history_cursor(data)
		if !ok {
			return {kind = .Invalid_Record}
		}

		if old.timestamp > message.timestamp {
			return {}
		}
	}

	if !socket_inbox_id_valid(message.id) {
		return {kind = .Invalid_Record}
	}

	buf: [137]u8
	endian.unchecked_put_u64be(buf[:8], message.timestamp)
	buf[8] = u8(message.from_me)
	size := copy(buf[9:], transmute([]u8)message.id)
	return state_store_set(store, .Chat_History_Cursor, jid, buf[:9 + size])
}

// Finds the newest known reference, including messages sent by an older client.
// The returned ID borrows the store until its next mutation.
latest_chat_history_cursor :: proc(
	store: ^State_Store,
	chat: string,
) -> (
	Chat_History_Cursor,
	Socket_Error,
) {
	if store == nil || !store.initialized || !device_user_jid_valid(chat, false) {
		return {}, {kind = .Invalid_Config}
	}

	alternate := chat_history_alternate_jid(store, chat)
	best: Chat_History_Cursor
	for record in store.records {
		#partial switch record.kind {
		case .Chat_History_Cursor:
			if record.name != chat && record.name != alternate {
				continue
			}

			cursor, valid := decode_chat_history_cursor(record.data)
			if !valid {
				return {}, {kind = .Protocol_Error}
			}

			if cursor.timestamp >= best.timestamp {
				best = cursor
			}


		case .Outbound_Content:
			doc, e := binary_node_decode(record.data)
			if e.kind != .None {
				return {}, {kind = .Binary_Failed, binary = e}
			}
			defer binary_document_destroy(&doc)

			to, _ := node_attr(doc.root, "to")
			if doc.root.tag != "saved" || (to != chat && (alternate == "" || to != alternate)) {
				continue
			}

			raw, _ := node_attr(doc.root, "t")
			stamp, ok := strconv.parse_u64(raw)
			if ok &&
			   stamp > best.timestamp &&
			   stamp <= u64(max(i64)) &&
			   socket_inbox_id_valid(record.name) {
				best = {
					id        = record.name,
					timestamp = stamp,
					from_me   = true,
				}
			}
		}
	}

	return best, {}
}

chat_history_request_encode :: proc(
	dst: []u8,
	jid: string,
	before: Chat_History_Cursor,
	count: int,
) -> (
	int,
	Socket_Error,
) {
	if !device_user_jid_valid(jid, false) ||
	   count < 1 ||
	   count > MAX_CHAT_HISTORY_MESSAGES ||
	   (before.id == "" && (before.timestamp != 0 || before.from_me)) ||
	   (before.id != "" &&
			   (!socket_inbox_id_valid(before.id) ||
					   before.timestamp == 0 ||
					   before.timestamp > u64(max(i64)))) {
		return 0, {kind = .Invalid_Config}
	}

	body, operation, protocol: [512]u8
	request := Protobuf_Writer {
		dst = body[:],
	}

	protobuf_write_string(&request, 1, jid)
	if before.id == "" {
		protobuf_write_uint(&request, 8, 1) // INITIAL_REVERSE_HISTORY
	} else {
		protobuf_write_string(&request, 2, before.id)
		protobuf_write_uint(&request, 3, u64(before.from_me))
		protobuf_write_uint(&request, 5, before.timestamp)
	}

	protobuf_write_uint(&request, 4, u64(count))
	op := Protobuf_Writer {
		dst = operation[:],
	}

	protobuf_write_uint(&op, 1, 3) // HISTORY_SYNC_ON_DEMAND
	protobuf_write_bytes(&op, 4, body[:request.at])
	control := Protobuf_Writer {
		dst = protocol[:],
	}

	protobuf_write_uint(&control, 2, 16) // PEER_DATA_OPERATION_REQUEST_MESSAGE
	protobuf_write_bytes(&control, 16, operation[:op.at])
	message := Protobuf_Writer {
		dst = dst,
	}

	protobuf_write_bytes(&message, 12, protocol[:control.at])
	if request.err != .None || op.err != .None || control.err != .None || message.err != .None {
		return 0, {kind = .Invalid_Config}
	}

	return message.at, {}
}

// Called only for authenticated direct control messages from our primary device.
// The Signal transaction finishes before a CDN fetch can re-enter the socket.
collect_chat_history_notification :: proc(
	request: ^Pending_Chat_History,
	notification: []u8,
) -> Socket_Error {
	kind, a := read_unique_protobuf_field(notification, 6, 0)
	id, b := read_unique_protobuf_field(notification, 12, 2)
	if !a || !b {
		return {kind = .Protocol_Error}
	}

	if kind.value != 6 || string(id.data) != request.id {
		return {}
	}

	if len(request.notifications) >= 16 ||
	   len(notification) > DEFAULT_MAX_MEDIA_SIZE - request.bytes {
		return {kind = .Queue_Full}
	}

	buf, ae := slice.clone(notification)
	if ae != nil {
		return {kind = .Allocation_Failed, allocation = ae}
	}

	if _, err := append(&request.notifications, buf); err != nil {
		delete(buf)
		return {kind = .Allocation_Failed, allocation = err}
	}

	request.bytes += len(buf)
	return {}
}

// The alternate address borrows the store. Resolve once when scanning records.
chat_history_alternate_jid :: proc(store: ^State_Store, chat: string) -> string {
	prefix := "lid:" if strings.has_suffix(chat, "@lid") else "pn:"
	key := strings.concatenate({prefix, chat})

	defer delete(key)

	if alias, ok := state_store_get(store, .LID_Mapping, key); ok {
		return string(alias)
	}

	contact, found := contact_by_jid(store, chat)
	if !found {
		return ""
	}

	return contact.alternate_jid if contact.jid == chat else contact.jid
}

decode_chat_history_message :: proc(
	chat, alternate, self: string,
	entry: []u8,
) -> (
	^Socket_Message,
	Socket_Error,
) {
	info, a := read_unique_protobuf_field(entry, 1, 2)
	key, b := read_unique_protobuf_field(info.data, 1, 2)
	payload, c := read_unique_protobuf_field(info.data, 2, 2)
	stamp, d := read_unique_protobuf_field(info.data, 3, 0)
	remote, e := read_unique_protobuf_field(key.data, 1, 2)
	own, f := read_unique_protobuf_field(key.data, 2, 0)
	id, g := read_unique_protobuf_field(key.data, 3, 2)
	if !(a && b && c && d && e && f && g) ||
	   key.number == 0 ||
	   own.value > 1 ||
	   !socket_inbox_id_valid(string(id.data)) ||
	   (remote.number != 0 &&
			   string(remote.data) != chat &&
			   (alternate == "" || string(remote.data) != alternate)) {
		return nil, {kind = .Protocol_Error}
	}

	// Stub entries carry timeline markers without a WhatsApp message body.
	if payload.number == 0 {
		return nil, {}
	}

	if stamp.value == 0 || len(payload.data) > MAX_PROTOBUF_MESSAGE_SIZE {
		return nil, {kind = .Protocol_Error}
	}

	from_me := own.value == 1
	return socket_message_new(
		"",
		self if from_me else chat,
		string(id.data),
		payload.data,
		from_me,
		stamp.value,
		true,
		chat if from_me else "",
	)
}

decode_chat_history_chunk :: proc(
	store: ^State_Store,
	chat, self: string,
	chunk: []u8,
	limit: int,
	messages: ^[dynamic]^Socket_Message,
) -> Socket_Error {
	kind, ok := read_unique_protobuf_field(chunk, 1, 0)
	if !ok || kind.value != 6 {
		return {kind = .Protocol_Error}
	}

	alternate := chat_history_alternate_jid(store, chat)
	size := 0
	for m in messages^ {size += len(m.protobuf)}

	at := 0
	for at < len(chunk) {
		conversation, e := protobuf_field_read(chunk, &at)
		if e != .None {
			return {kind = .Protocol_Error}
		}

		if conversation.number != 2 {
			continue
		}

		jid, valid := read_unique_protobuf_field(conversation.data, 1, 2)
		if conversation.wire_type != 2 ||
		   !valid ||
		   (string(jid.data) != chat && (alternate == "" || string(jid.data) != alternate)) {
			return {kind = .Protocol_Error}
		}

		pos := 0
		for pos < len(conversation.data) {
			entry, err := protobuf_field_read(conversation.data, &pos)
			if err != .None {
				return {kind = .Protocol_Error}
			}

			if entry.number != 2 {
				continue
			}

			if entry.wire_type != 2 {
				return {kind = .Protocol_Error}
			}

			msg, decoded := decode_chat_history_message(chat, alternate, self, entry.data)
			if decoded.kind != .None {
				return decoded
			}

			if msg == nil {
				continue
			}

			duplicate := false
			for previous in messages^ {
				if previous.id == msg.id && previous.from_me == msg.from_me {
					duplicate = true; break
				}
			}

			if duplicate {
				socket_message_destroy(msg); continue
			}

			size += len(msg.protobuf)
			if len(messages^) >= limit || size > DEFAULT_MAX_MEDIA_SIZE {
				socket_message_destroy(msg); return {kind = .Protocol_Error}
			}

			if _, ae := append(messages, msg); ae != nil {
				socket_message_destroy(msg)
				return {kind = .Allocation_Failed, allocation = ae}
			}
		}
	}

	return {}
}

// Without an explicit cursor, use the newest local reference or request initial reverse history.
// Returns one page of private messages. Destroy each with socket_message_destroy
// and delete the array. History never enters the live inbox or triggers a reply.
socket_fetch_chat_history :: proc(
	socket: ^Socket,
	chat_jid: string,
	before := Chat_History_Cursor{},
	count := MAX_CHAT_HISTORY_MESSAGES,
	timeout := 60 * time.Second,
) -> (
	[dynamic]^Socket_Message,
	Socket_Error,
) {
	return socket_fetch_history_page(socket, chat_jid, before, count, timeout, true)
}

Recent_Chat_History :: struct {
	messages:               [dynamic]^Socket_Message,
	// All three pointers borrow messages. Bounds describe only the received page.
	oldest, newest, target: ^Socket_Message,
}

// Request INITIAL_REVERSE_HISTORY even when the store has an older reference.
// target_id identifies an incoming message unless target_from_me is set.
socket_fetch_recent_chat_history :: proc(
	socket: ^Socket,
	chat_jid: string,
	target_id := "",
	target_from_me := false,
	count := MAX_CHAT_HISTORY_MESSAGES,
	timeout := 60 * time.Second,
) -> (
	Recent_Chat_History,
	Socket_Error,
) {
	if target_id != "" && !socket_inbox_id_valid(target_id) {
		return {}, {kind = .Invalid_Config}
	}

	// The caller may have borrowed the ID from a state record before this query.
	id, ae := strings.clone(target_id)
	if ae != nil {
		return {}, {kind = .Allocation_Failed, allocation = ae}
	}
	defer delete(id)

	messages, err := socket_fetch_history_page(socket, chat_jid, {}, count, timeout, false)
	if err.kind != .None {
		return {}, err
	}

	page := Recent_Chat_History {
		messages = messages,
	}

	for msg in messages {
		if page.oldest == nil || msg.timestamp < page.oldest.timestamp {
			page.oldest = msg
		}

		if page.newest == nil || msg.timestamp > page.newest.timestamp {
			page.newest = msg
		}

		if msg.id == id && msg.from_me == target_from_me {
			page.target = msg
		}
	}

	return page, {}
}

@(private)
socket_fetch_history_page :: proc(
	socket: ^Socket, chat_jid: string, before: Chat_History_Cursor, count: int,
	timeout: time.Duration, use_local_cursor: bool,
) -> ([dynamic]^Socket_Message, Socket_Error) {
	if socket == nil ||
	   socket.phase != .Online ||
	   socket.auth == nil ||
	   socket.store == nil ||
	   !socket.store.initialized ||
	   (socket.history_request != nil || socket.message_lookup != nil) {
		return nil, {kind = .Invalid_State}
	}

	if timeout <= 0 || !device_user_jid_valid(chat_jid, false) {
		return nil, {kind = .Invalid_Config}
	}

	buf: [512]u8
	cursor := before
	if use_local_cursor && cursor == (Chat_History_Cursor{}) {
		known, err := latest_chat_history_cursor(socket.store, chat_jid)
		if err.kind != .None {
			return nil, err
		}

		cursor = known
	}

	wire_jid := chat_jid
	if strings.has_suffix(chat_jid, "@lid") {
		if alternate := chat_history_alternate_jid(socket.store, chat_jid);
		   strings.has_suffix(alternate, "@s.whatsapp.net") {
			wire_jid = alternate
		}
	}

	n, e := chat_history_request_encode(buf[:], wire_jid, cursor, count)
	if e.kind != .None {
		return nil, e
	}

	// A caller may pass a JID borrowed from the store; Signal commits replace it.
	chat, ce := strings.clone(chat_jid)
	if ce != nil {
		return nil, {kind = .Allocation_Failed, allocation = ce}
	}
	defer delete(chat)

	request := Pending_Chat_History {
		id = generate_outbound_message_id(),
	}

	socket.history_request = &request
	socket.query_depth += 1
	socket.read_deadline_scopes += 1
	defer {
		socket.history_request = nil
		socket.query_depth -= 1
		socket.read_deadline_scopes -= 1
		delete(request.id)
		for ref in request.notifications {
			crypto.zero_explicit(raw_data(ref), len(ref)); delete(ref)
		}

		delete(request.notifications)
	}

	if err := socket_send_primary_device_message(socket, request.id, buf[:n], history = true);
	   err.kind != .None {
		return nil, err
	}

	deadline := time.time_add(time.now(), timeout)
	self := string(socket.auth.account.jid[:socket.auth.account.jid_size])
	messages: [dynamic]^Socket_Message
	success := false
	defer if !success {
		for msg in messages {socket_message_destroy(msg)}

		delete(messages)
	}

	raw, ae := make([]u8, DEFAULT_MAX_MEDIA_SIZE)
	if ae != nil {
		return nil, {kind = .Allocation_Failed, allocation = ae}
	}
	defer {crypto.zero_explicit(raw_data(raw), len(raw)); delete(raw)}

	for index := 0;; index += 1 {
		for index >= len(request.notifications) {
			if _, err := socket_receive_while_waiting(socket, deadline); err.kind != .None {
				return nil, err
			}
		}

		ref := request.notifications[index]
		progress, p := read_unique_protobuf_field(ref, 9, 0)
		inline_data, i := read_unique_protobuf_field(ref, 11, 2)
		if !p || !i || progress.value > 100 {
			return nil, {kind = .Protocol_Error}
		}

		compressed := inline_data.data
		if inline_data.number == 0 {
			downloaded, err := download_contact_history(socket, ref)
			if err.kind != .None {
				return nil, err
			}

			compressed = downloaded
		}
		defer if inline_data.number == 0 {
			crypto.zero_explicit(raw_data(compressed), len(compressed)); delete(compressed)
		}

		chunk, err := decompress_history_chunk(raw, compressed)
		if err.kind != .None {
			return nil, err
		}

		if parsed := decode_chat_history_chunk(socket.store, chat, self, chunk, count, &messages);
		   parsed.kind != .None {
			return nil, parsed
		}

		if progress.number == 0 || progress.value == 100 {
			break
		}
	}

	success = true
	return messages, {}
}

Pending_Message_Lookup :: struct {
	request_id, chat, target_id: string,
	message:                     ^Socket_Message,
	done:                        bool,
}

// Ask our own primary for an incoming private message by its original key.
// A correlated response without that message returns nil and success.
// The caller owns the message. A timeout does not establish availability.
socket_fetch_private_message_by_id :: proc(
	socket: ^Socket,
	chat, id: string,
	timeout := 60 * time.Second,
) -> (
	^Socket_Message,
	Socket_Error,
) {
	if socket == nil ||
	   socket.phase != .Online ||
	   socket.auth == nil ||
	   socket.store == nil ||
	   !socket.store.initialized ||
	   socket.history_request != nil ||
	   socket.message_lookup != nil {
		return nil, {kind = .Invalid_State}
	}

	if !device_user_jid_valid(chat, false) || !socket_inbox_id_valid(id) || timeout <= 0 {
		return nil, {kind = .Invalid_Config}
	}

	// Inputs can borrow store records invalidated by the outbound Signal commit.
	chat_copy, ce := strings.clone(chat)
	if ce != nil {
		return nil, {kind = .Allocation_Failed, allocation = ce}
	}
	defer delete(chat_copy)

	id_copy, ie := strings.clone(id)
	if ie != nil {
		return nil, {kind = .Allocation_Failed, allocation = ie}
	}
	defer delete(id_copy)

	key_buf, item_buf, op_buf, control_buf, msg_buf: [512]u8
	key := Protobuf_Writer {
		dst = key_buf[:],
	}

	media_emit_message_key(&key, {remote_jid = chat, id = id, has_from_me = true})

	item := Protobuf_Writer {
		dst = item_buf[:],
	}

	protobuf_write_bytes(&item, 1, key_buf[:key.at])
	op := Protobuf_Writer {
		dst = op_buf[:],
	}

	protobuf_write_uint(&op, 1, 4) // PLACEHOLDER_MESSAGE_RESEND
	protobuf_write_bytes(&op, 5, item_buf[:item.at])
	control := Protobuf_Writer {
		dst = control_buf[:],
	}

	protobuf_write_uint(&control, 2, 16)
	protobuf_write_bytes(&control, 16, op_buf[:op.at])
	msg := Protobuf_Writer {
		dst = msg_buf[:],
	}

	protobuf_write_bytes(&msg, 12, control_buf[:control.at])
	if key.err != .None ||
	   item.err != .None ||
	   op.err != .None ||
	   control.err != .None ||
	   msg.err != .None {
		return nil, {kind = .Invalid_Config}
	}

	request := Pending_Message_Lookup {
		request_id = generate_outbound_message_id(),
		chat       = chat_copy,
		target_id  = id_copy,
	}

	socket.message_lookup = &request
	socket.query_depth += 1
	socket.read_deadline_scopes += 1
	defer {
		socket.message_lookup = nil
		socket.query_depth -= 1
		socket.read_deadline_scopes -= 1
		delete(request.request_id)
		socket_message_destroy(request.message)
	}

	if err := socket_send_primary_device_message(
		socket,
		request.request_id,
		msg_buf[:msg.at],
		placeholder_resend = true,
	); err.kind != .None {
		return nil, err
	}

	deadline := time.time_add(time.now(), timeout)
	for !request.done {
		if _, err := socket_receive_while_waiting(socket, deadline); err.kind != .None {
			return nil, err
		}
	}

	message := request.message
	request.message = nil
	return message, {}
}

@(private)
collect_private_message_response :: proc(
	request: ^Pending_Message_Lookup,
	store: ^State_Store,
	protocol: []u8,
) -> Socket_Error {
	kind, a := read_unique_protobuf_field(protocol, 2, 0)
	body, b := read_unique_protobuf_field(protocol, 17, 2)
	op, c := read_unique_protobuf_field(body.data, 1, 0)
	id, d := read_unique_protobuf_field(body.data, 2, 2)
	if !(a && b && c && d) ||
	   kind.value != 17 ||
	   op.value != 4 ||
	   string(id.data) != request.request_id {
		return {}
	}

	alternate := chat_history_alternate_jid(store, request.chat)
	at := 0
	for at < len(body.data) {
		result, err := protobuf_field_read(body.data, &at)
		if err != .None {
			return {kind = .Protocol_Error}
		}

		if result.number != 3 {
			continue
		}

		resend, r := read_unique_protobuf_field(result.data, 4, 2)
		info, i := read_unique_protobuf_field(resend.data, 1, 2)
		if result.wire_type != 2 || !r || !i {
			return {kind = .Protocol_Error}
		}

		if info.number == 0 {
			continue
		}

		key, k := read_unique_protobuf_field(info.data, 1, 2)
		chat, j := read_unique_protobuf_field(key.data, 1, 2)
		target, t := read_unique_protobuf_field(key.data, 3, 2)
		own, o := read_unique_protobuf_field(key.data, 2, 0)
		if !(k && j && t && o) || chat.number == 0 || target.number == 0 || own.value > 1 {
			return {kind = .Protocol_Error}
		}

		if own.value != 0 ||
		   string(target.data) != request.target_id ||
		   (string(chat.data) != request.chat &&
				   (alternate == "" || string(chat.data) != alternate)) {
			continue
		}

		payload, p := read_unique_protobuf_field(info.data, 2, 2)
		stamp, s := read_unique_protobuf_field(info.data, 3, 0)
		if !p || !s || len(payload.data) > MAX_PROTOBUF_MESSAGE_SIZE {
			return {kind = .Protocol_Error}
		}

		if len(payload.data) == 0 {
			continue
		}

		if request.message != nil {
			return {kind = .Protocol_Error}
		}

		message, e := socket_message_new(
			"",
			request.chat,
			request.target_id,
			payload.data,
			false,
			stamp.value,
			true,
		)
		if e.kind != .None {
			return e
		}

		request.message = message
	}

	request.done = true
	return {}
}

package whatsapp

import endian "core:encoding/endian"
import "core:crypto"
import "core:encoding/hex"
import "core:fmt"
import "core:log"
import "core:mem"
import "core:strconv"
import "core:strings"
import "core:time"

// Incoming messages and durable inbox.

// Consume protocol controls while preserving notifications for specialized
// waiters. Plaintext is exposed only after its ratchet and inbox are durable.
socket_process_node :: proc(socket: ^Socket, node: Binary_Node) -> (Socket_Event, Socket_Error) {
	if socket == nil ||
	   (socket.phase != .Online && socket.phase != .Provisioning) ||
	   socket.store == nil ||
	   socket.auth == nil ||
	   socket.prekeys == nil {
		return {}, {kind = .Invalid_State}
	}

	switch node.tag {
	case "status":
		// Top-level status deliveries need their own transport ACK, including
		// the offline batch. This does not emit a chat event or viewed receipt.
		return {}, socket_acknowledge(socket, node)
	case "message":
		return socket_message_node_process(socket, node)
	case "ack":
		return socket_message_ack_process(socket, node)
	case "receipt":
		kind, _ := node_attr(node, "type")

		if e := socket_acknowledge(socket, node); e.kind != .None {
			return {}, e
		}

		if kind == "retry" {
			return {}, socket_defer_retry(socket, node)
		}

		return {}, {}
	case "notification", "call":
		if e := socket_note_contact_update(socket, node); e.kind != .None { return {}, e }
		// A transport ACK does not answer a call. Preserve its node for waiters.
		if e := socket_acknowledge(socket, node); e.kind != .None {
			return {}, e
		}

		return {kind = .Node, node = node}, {}
	case:
		return {kind = .Node, node = node}, {}
	}
}

socket_message_receipts_send :: proc(
	socket: ^Socket,
	node: Binary_Node,
	event: Socket_Event,
	history_receipt: bool,
) -> Socket_Error {
	if e := socket_send_delivery_receipt(socket, node); e.kind != .None {
		if event.message != nil {
			socket_message_destroy(event.message)
		}

		return e
	}

	if history_receipt {
		if e := socket_send_history_receipt(socket, node); e.kind != .None {
			if event.message != nil {
				socket_message_destroy(event.message)
			}

			return e
		}
	}

	if e := socket_acknowledge(socket, node); e.kind != .None {
		if event.message != nil {
			socket_message_destroy(event.message)
		}

		return e
	}

	return {}
}

socket_message_node_process :: proc(socket: ^Socket, node: Binary_Node) -> (Socket_Event, Socket_Error) {
	from, _ := node_attr(node, "from")

	if from == "status@broadcast" {
		// Status updates can arrive in the offline batch before login
		// finishes. Acknowledge transport delivery without exposing them
		// as chat messages or sending a viewed/read receipt.
		return {}, socket_acknowledge(socket, node)
	}

	history_receipt := false
	event, err := socket_process_message(socket, node, &history_receipt)

	if err.kind != .None {
		if err.kind == .Unsupported_Message_Encryption {
			// Negative transport ACK only: never send delivery receipts, retain a
			// success marker or automatically retry an unsupported cipher.
			return {}, socket_acknowledge(socket, node, message_encryption_nack_reason(node))
		}

		if err.kind == .Signal_Failed || err.kind == .Group_Failed || err.kind == .Message_Failed {
			if e := socket_request_retry(socket, node); e.kind != .None {
				return {}, e
			}

			return {}, socket_acknowledge(socket, node)
		}

		return {}, err
	}

	if receipt_error := socket_message_receipts_send(socket, node, event, history_receipt); receipt_error.kind != .None {
		return {}, receipt_error
	}

	return event, {}
}

socket_message_ack_process :: proc(socket: ^Socket, node: Binary_Node) -> (Socket_Event, Socket_Error) {
	class, _ := node_attr(node, "class")

	if class == "message" {
		id, _ := node_attr(node, "id")

		if id != "" {
			// An error attribute is a negative ACK, even if empty or malformed.
			// Retain intent and ciphertext: retries/cancellation remain explicit.
			if _, rejected := node_attr(node, "error"); rejected {
				_, pending := state_store_get(socket.store, .Outbound_Message, id)
				_, retained := state_store_get(socket.store, .Outbound_Content, id)

				if pending || retained {
					return {}, {kind = .Message_Rejected}
				}

				return {}, {}
			}

			candidate: State_Store
			defer state_store_clear(&candidate)

			if e := socket_store_clone(&candidate, socket.store); e.kind != .None {
				return {}, e
			}

			if e := state_store_delete(&candidate, .Outbound_Message, id); e.kind != .None {
				return {}, {kind = .State_Failed, state = e}
			}

			if e := socket_store_commit(socket, &candidate); e.kind != .None {
				return {}, e
			}
		}
	}

	return {}, {}
}

socket_process_message :: proc(
	socket: ^Socket,
	node: Binary_Node,
	history_receipt: ^bool,
) -> (
	Socket_Event,
	Socket_Error,
) {
	group, participant, id, route_error := socket_message_route_decode(node)
	if route_error.kind != .None {
		return {}, route_error
	}

	// Preflight every encrypted child before deduplication, self filtering or
	// staged ratchet work. Mixed supported/unsupported content is indivisible.
	if message_encryption_nack_reason(node) != 0 {
		return {}, {kind = .Unsupported_Message_Encryption}
	}

	candidate: State_Store
	if e := socket_store_clone(&candidate, socket.store); e.kind != .None {
		return {}, e
	}
	defer state_store_clear(&candidate)
	// Known own-group echoes are discarded without decrypting. They must not
	// turn unauthenticated sender hints into independently persisted mappings.
	if group == "" || !socket_sender_is_self(socket, participant) {
		if e := socket_message_alias_stage(&candidate, socket.store, node, participant); e.kind != .None {
			return {}, e
		}
	}

	name, name_error := socket_inbox_key_store(&candidate, group, participant, id)
	if name_error.kind != .None {
		return {}, name_error
	}

	defer delete(name)
	if marker, found := state_store_get(&candidate, .Processed_Message, name); found {
		if history_receipt != nil { history_receipt^ = processed_history_receipt(marker) }
		return {}, {}
	}

	if data, found := state_store_get(&candidate, .Inbox_Message, name); found {
		// A network duplicate must not hand out a second owner while its first
		// event is still being handled. Reconnect restores the durable event.
		_ = data
		return {}, {}
	}

	if group != "" && socket_sender_is_self(socket, participant) {
		return {}, socket_message_processed_commit(socket, &candidate, name)
	}
	var_payload, payload_error := socket_message_payload_decrypt(socket, &candidate, node, group, participant)
	if payload_error.kind != .None {
		return {}, payload_error
	}
	defer if var_payload != nil {
		crypto.zero_explicit(raw_data(var_payload), len(var_payload))
		delete(var_payload)
	}
	if var_payload == nil {
		return {}, socket_message_processed_commit(socket, &candidate, name)
	}
	own := socket_sender_is_self_store(&candidate, socket.auth, participant)
	if !own {
		if profile, ok := node_attr(node, "notify"); ok && profile != "" && profile != "-" && contact_name_valid(profile) {
			user, _, _ := pairing_jid_decode(participant)
			jid := fmt.aprintf("%s%s", user, participant[strings.index_byte(participant, '@'):])
			defer delete(jid)
			if e := state_store_set(&candidate, .Contact_Profile, jid, transmute([]u8)profile); e.kind != .None {
				return {}, {kind = .State_Failed, state = e}
			}
		}
	}
	handled, control_error := socket_message_control_commit(
		socket,
		&candidate,
		name,
		group,
		var_payload,
		own,
		history_receipt,
		participant,
	)
	if handled {
		return {}, control_error
	}
	return socket_message_event_commit(socket, &candidate, node, name, group, participant, id, var_payload, own)
}

socket_message_route_decode :: proc(node: Binary_Node) -> (string, string, string, Socket_Error) {
	from, _ := node_attr(node, "from")
	participant, _ := node_attr(node, "participant")
	id, _ := node_attr(node, "id")

	if !socket_inbox_id_valid(id) {
		return "", "", "", {kind = .Protocol_Error}
	}

	group := ""

	if strings.has_suffix(from, "@g.us") {
		group = from

		if !socket_receive_group_valid(group) || !device_user_jid_valid(participant, true) {
			return "", "", "", {kind = .Protocol_Error}
		}
	} else {
		if !device_user_jid_valid(from, true) {
			return "", "", "", {kind = .Protocol_Error}
		}

		participant = from
	}

	return group, participant, id, {}
}

socket_message_processed_commit :: proc(socket: ^Socket, candidate: ^State_Store, name: string) -> Socket_Error {
	if state_error := socket_processed_set(candidate, name); state_error.kind != .None {
		return {kind = .State_Failed, state = state_error}
	}

	return socket_store_commit(socket, candidate)
}

socket_message_cipher_decrypt :: proc(
	staged: ^Socket,
	group, participant, signal_participant, kind: string,
	cipher, plaintext: []u8,
) -> (
	int,
	Socket_Error,
) {
	count: int
	if kind == "skmsg" {
		if group == "" {
			return 0, {kind = .Protocol_Error}
		}

		key := fmt.aprintf("%s|%s", group, signal_participant)
		defer delete(key)
		record := new(Signal_Group_Record)
		defer {
			signal_group_record_clear(record)
			free(record)
		}

		snapshot, have := state_store_get(staged.store, .Sender_Key, key)

		if !have {
			return 0, {kind = .Group_Failed, group = .Unknown_Key}
		}

		if e := signal_group_record_decode(record, snapshot); e != .None {
			return 0, {kind = .Group_Failed, group = e}
		}

		n, e := signal_group_decrypt(plaintext, record, cipher)

		if e != .None {
			return 0, {kind = .Group_Failed, group = e}
		}

		count = n

		if e := socket_stage_group(staged, key, record); e.kind != .None {
			return 0, e
		}
	} else {
		n, e := socket_pairwise_decrypt(staged, participant, kind, cipher, plaintext)
		if e.kind != .None {
			return 0, e
		}

		count = n
	}

	return count, {}
}

socket_message_distribution_install :: proc(
	staged: ^Socket,
	parsed: Text_Message,
	group, signal_participant, kind: string,
) -> Socket_Error {
	if parsed.has_sender_key_distribution {
		distribution := parsed.sender_key_distribution
		if !distribution.has_group_id ||
		   !distribution.has_distribution ||
		   !socket_receive_group_valid(distribution.group_id) {
			return {kind = .Protocol_Error}
		}

		if group != "" && distribution.group_id != group {
			return {kind = .Protocol_Error}
		}

		// Only pairwise-authenticated distributions may install a group key.
		if kind == "skmsg" {
			return {kind = .Protocol_Error}
		}

		key := fmt.aprintf("%s|%s", distribution.group_id, signal_participant)
		defer delete(key)
		record := new(Signal_Group_Record)
		defer {
			signal_group_record_clear(record)
			free(record)
		}

		if snapshot, have := state_store_get(staged.store, .Sender_Key, key); have {
			if ge := signal_group_record_decode(record, snapshot); ge != .None {
				return {kind = .Group_Failed, group = ge}
			}
		}

		if ge := signal_group_distribution_process(record, distribution.distribution); ge != .None {
			return {kind = .Group_Failed, group = ge}
		}

		if se := socket_stage_group(staged, key, record); se.kind != .None {
			return se
		}
	}

	return {}
}

socket_message_child_decrypt :: proc(
	staged: ^Socket,
	child: Binary_Node,
	group, participant, signal_participant, kind: string,
	var_payload: ^[]u8,
) -> Socket_Error {
	cipher, bytes_ok := child.content.([]u8)
	if !bytes_ok || len(cipher) > MAX_SIGNAL_PACKET_SIZE {
		return {kind = .Protocol_Error}
	}

	plaintext := make([]u8, len(cipher))
	defer {
		crypto.zero_explicit(raw_data(plaintext), len(plaintext)); delete(plaintext)
	}
	count, decrypt_error := socket_message_cipher_decrypt(
		staged,
		group,
		participant,
		signal_participant,
		kind,
		cipher,
		plaintext,
	)
	if decrypt_error.kind != .None {
		return decrypt_error
	}
	unpadded, e := socket_message_unpad(plaintext[:count])
	if e.kind != .None {
		return e
	}

	parsed, pe := text_message_decode(unpadded)
	if pe != .None {
		return {kind = .Message_Failed, message = pe}
	}

	if distribution_error := socket_message_distribution_install(staged, parsed, group, signal_participant, kind); distribution_error.kind != .None {
		return distribution_error
	}

	// Distribution-only/control payloads have no business message. Unknown
	// payloads are retained for the application, including media/protocol.
	if parsed.has_sender_key_distribution && parsed.kind == .None {
		return {}
	}

	if var_payload^ != nil {
		return {kind = .Protocol_Error}
	}

	var_payload^ = make([]u8, len(unpadded))
	copy(var_payload^, unpadded)
	return {}
}

// These are client negative ACK reasons, not server rejection codes.
MESSAGE_NACK_UNRECOGNIZED_ENCRYPTION: u32 : 490
MESSAGE_NACK_MISSING_SECRET: u32 : 495
message_encryption_nack_reason :: proc(node: Binary_Node) -> u32 {
	children, ok := node.content.([]Binary_Node)
	if !ok {
		return 0 // Shape validation remains with the ordinary decoder.
	}
	reason: u32

	for child in children {
		if child.tag != "enc" {
			continue
		}
		kind, _ := node_attr(child, "type")

		switch kind {
		case "pkmsg", "msg", "skmsg":
		case "msmsg":
			reason = MESSAGE_NACK_MISSING_SECRET
		case:
			return MESSAGE_NACK_UNRECOGNIZED_ENCRYPTION
		}
	}

	return reason
}

socket_message_payload_decrypt :: proc(
	socket: ^Socket,
	candidate: ^State_Store,
	node: Binary_Node,
	group, participant: string,
) -> (
	[]u8,
	Socket_Error,
) {
	if message_encryption_nack_reason(node) != 0 {
		return nil, {kind = .Unsupported_Message_Encryption}
	}
	staged := new(Socket)
	defer {
		crypto.zero_explicit(staged, size_of(Socket))
		free(staged)
	}
	staged.store = candidate
	staged.auth = socket.auth
	staged.prekeys = socket.prekeys
	staged.config = socket.config
	signal_participant, address_error := socket_signal_address(staged, participant)
	if address_error.kind != .None {
		return nil, address_error
	}

	defer delete(signal_participant)
	children, ok := node.content.([]Binary_Node)
	if !ok {
		return nil, {kind = .Protocol_Error}
	}

	var_payload: []u8
	success := false
	defer if !success && var_payload != nil {
		crypto.zero_explicit(raw_data(var_payload), len(var_payload))
		delete(var_payload)
	}
	// Pairwise sender-key distributions must be installed before skmsg in the
	// same stanza regardless of the order supplied by the server.
	for pass in 0 ..< 2 {
		for child in children {
			if child.tag != "enc" {
				continue
			}

			kind, _ := node_attr(child, "type")

			if pass == 0 && (kind != "pkmsg" && kind != "msg") {
				continue
			}

			if pass == 1 && kind != "skmsg" {
				continue
			}

			if child_error := socket_message_child_decrypt(staged, child, group, participant, signal_participant, kind, &var_payload); child_error.kind != .None {
				return nil, child_error
			}
		}
	}
	success = true
	return var_payload, {}
}

socket_message_control_commit :: proc(
	socket: ^Socket,
	candidate: ^State_Store,
	name, group: string,
	var_payload: []u8,
	own: bool,
	history_receipt: ^bool,
	participant := "",
) -> (
	bool,
	Socket_Error,
) {
	// Device synchronization/control messages sent by our other device are not
	// business events. Retain text/media sent by the account for app semantics.
	parsed, _ := text_message_decode(var_payload)
	media, _ := media_message_decode(var_payload)
	if own && parsed.kind == .None && media.kind == .None {
		protocol := unwrap_protocol_message(var_payload, 0)
		notification, valid_history := read_unique_protobuf_field(protocol, 6, 2)
		history := group == "" && valid_history && notification.number != 0
		if history && socket.config.sync_contacts {
			if e := store_historical_contact_profiles(socket, candidate, notification.data, pending_name = name); e.kind != .None { return true, e }
		}
		if group == "" {
			if e := store_contact_sync_key_share(candidate, protocol); e.kind != .None {
				return true, e
			}
		}

		if e := socket_processed_set(candidate, name, history); e.kind != .None {
			return true, {kind = .State_Failed, state = e}
		}

		// Authenticate the primary against the previously committed routing state.
		lookup := socket.message_lookup
		primary_lookup := false
		if lookup != nil && !lookup.done && group == "" && socket_sender_is_self(socket, participant) {
			_, device, pe := pairing_jid_decode(participant)
			primary_lookup = pe.kind == .None && device == 0
		}
		if e := socket_store_commit(socket, candidate); e.kind != .None {
			return true, e
		}

		if primary_lookup {
			if e := collect_private_message_response(lookup, socket.store, protocol); e.kind != .None {
				return true, e
			}
		}
		if history && socket.history_request != nil {
			_, device, pe := pairing_jid_decode(participant)
			control_type, valid := read_unique_protobuf_field(protocol, 2, 0)
			if valid && control_type.value == 5 && pe.kind == .None && device == 0 {
				if e := collect_chat_history_notification(socket.history_request, notification.data); e.kind != .None { return true, e }
			}
		}
		if history && socket.config.sync_contacts { socket.profile_history_pending = true }
		if socket.contact_key_size > 0 {
			key := hex.encode(socket.contact_key_requested[:socket.contact_key_size])
			defer delete(key)
			if _, available := state_store_get(socket.store, .Contact_Sync_Key, string(key)); available {
				socket.contact_key_size = 0
				socket.contact_refresh_after = {}
				socket.contact_refresh_due = true
			}
		}
		if history_receipt != nil {
			history_receipt^ = history
		}

		return true, {}
	}

	return false, {}
}

socket_message_event_commit :: proc(
	socket: ^Socket,
	candidate: ^State_Store,
	node: Binary_Node,
	name, group, participant, id: string,
	var_payload: []u8,
	own: bool,
) -> (
	Socket_Event,
	Socket_Error,
) {
	timestamp: u64
	if raw, have := node_attr(node, "t"); have {
		value, valid := strconv.parse_u64(raw)
		if !valid {
			return {}, {kind = .Protocol_Error}
		}

		timestamp = value
	}

	offline, _ := node_attr(node, "offline")
	recipient := ""
	if group == "" && own {
		if to, found := node_attr(node, "recipient"); found && device_user_jid_valid(to, true) {
			recipient = to
		}
	}
	message, message_error := socket_message_new(group, participant, id, var_payload, own, timestamp, offline != "", recipient)
	if message_error.kind != .None {
		return {}, message_error
	}

	success := false
	defer {
		if !success {
			socket_message_destroy(message)
		}
	}
	if socket.config.track_chat_history_cursors {
		if e := store_chat_history_cursor(candidate, message); e.kind != .None {
			return {}, {kind = .State_Failed, state = e}
		}
	}
	if e := socket_inbox_stage(candidate, name, message); e.kind != .None {
		return {}, e
	}

	if e := socket_store_commit(socket, candidate); e.kind != .None {
		return {}, e
	}

	success = true
	return {kind = .Message, message = message}, {}
}

socket_pairwise_decrypt :: proc(socket: ^Socket, jid, kind: string, wire, dst: []u8) -> (int, Socket_Error) {
	address, address_error := socket_signal_address(socket, jid)

	if address_error.kind != .None {
		return 0, address_error
	}

	defer delete(address)
	session := new(Signal_Session)
	defer {
		signal_session_clear(session)
		free(session)
	}

	session_name := strings.clone(address)
	defer delete(session_name)
	trusted: [32]u8
	pinned, state_error := socket_pairwise_state_load(socket, address, session, &trusted)
	if state_error.kind != .None {
		return 0, state_error
	}

	local := Signal_Recipient_Keys {
		identity_private      = socket.auth.credentials.identity_private,
		registration_id       = socket.auth.credentials.registration_id,
		signed_prekey_private = socket.auth.credentials.signed_prekey_private,
		signed_prekey_id      = socket.auth.credentials.signed_prekey_id,
	}

	defer crypto.zero_explicit(&local, size_of(local))
	count: int
	consumed := false
	consumed_id: u32
	var_error: Socket_Error

	if kind == "pkmsg" {
		count, consumed, consumed_id, var_error = socket_pairwise_prekey_open(
			socket,
			address,
			session,
			&session_name,
			wire,
			dst,
			&local,
			&trusted,
			pinned,
		)
	} else {
		count, var_error = socket_pairwise_whisper_open(
			socket,
			address,
			session,
			&session_name,
			wire,
			dst,
			&trusted,
			pinned,
		)
	}

	if var_error.kind != .None {
		return 0, var_error
	}
	if stage_error := socket_pairwise_decryption_stage(socket, address, session_name, session, &trusted, pinned, consumed, consumed_id); stage_error.kind != .None {
		return 0, stage_error
	}

	return count, {}
}

socket_pairwise_state_load :: proc(
	socket: ^Socket,
	address: string,
	session: ^Signal_Session,
	trusted: ^[32]u8,
) -> (
	bool,
	Socket_Error,
) {
	if snapshot, have := state_store_get(socket.store, .Session, address); have {
		if e := signal_session_decode(session, snapshot); e.kind != .None {
			return false, {kind = .Signal_Failed, signal = e}
		}
	}

	pinned := false
	if identity, found := state_store_get(socket.store, .Identity, address); found {
		if len(identity) != 32 {
			return false, {kind = .Identity_Changed}
		}

		copy(trusted[:], identity)
		pinned = true
	}

	return pinned, {}
}

socket_pairwise_prekey_archive_select :: proc(
	socket: ^Socket,
	address: string,
	session: ^Signal_Session,
	session_name: ^string,
	peek: Signal_Prekey_Message,
	trusted: ^[32]u8,
) -> Socket_Error {
	archived := false
	prefix := fmt.aprintf("%s#", address)
	defer delete(prefix)
	old := new(Signal_Session)
	defer {
		signal_session_clear(old)
		free(old)
	}
	for record in socket.store.records {
		if record.kind != .Session || !strings.has_prefix(record.name, prefix) {
			continue
		}

		if de := signal_session_decode(old, record.data); de.kind != .None {
			return {kind = .Signal_Failed, signal = de}
		}

		if old.base_public == peek.base_public {
			if old.remote_identity_public != trusted^ {
				return {kind = .Identity_Changed}
			}

			session^ = old^
			delete(session_name^)
			session_name^ = strings.clone(record.name)
			archived = true
			break
		}
	}
	if !archived {
		if e := socket_archive_session(socket, address, session); e.kind != .None {
			return e
		}

		signal_session_clear(session)
	}

	return {}
}

socket_pairwise_one_time_prekey_load :: proc(
	socket: ^Socket,
	peek: Signal_Prekey_Message,
	local: ^Signal_Recipient_Keys,
) -> Socket_Error {
	marker := fmt.aprintf("%d", peek.prekey_id)
	defer delete(marker)
	if _, found := state_store_get(socket.store, .Consumed_Prekey, marker); found {
		return {kind = .Signal_Failed, signal = {kind = .Missing_Prekey}}
	}

	key := prekey_store_get(socket.prekeys, peek.prekey_id)
	if key == nil {
		return {kind = .Signal_Failed, signal = {kind = .Missing_Prekey}}
	}

	local.has_prekey = true
	local.prekey_id = key.id
	local.prekey_private = key.private
	return {}
}

socket_pairwise_prekey_open :: proc(
	socket: ^Socket,
	address: string,
	session: ^Signal_Session,
	session_name: ^string,
	wire, dst: []u8,
	local: ^Signal_Recipient_Keys,
	trusted: ^[32]u8,
	pinned: bool,
) -> (
	int,
	bool,
	u32,
	Socket_Error,
) {
	peek, e := signal_prekey_message_decode(wire)
	if e.kind != .None {
		return 0, false, 0, {kind = .Signal_Failed, signal = e}
	}

	if pinned && crypto.compare_constant_time(trusted[:], peek.identity_public[:]) != 1 {
		return 0, false, 0, {kind = .Identity_Changed}
	}

	if !pinned {
		trusted^ = peek.identity_public
	}

	if session.initialized && session.base_public != peek.base_public {
		if archive_error := socket_pairwise_prekey_archive_select(socket, address, session, session_name, peek, trusted); archive_error.kind != .None {
			return 0, false, 0, archive_error
		}
	}

	fresh := !session.initialized
	if fresh && peek.has_prekey {
		if key_error := socket_pairwise_one_time_prekey_load(socket, peek, local); key_error.kind != .None {
			return 0, false, 0, key_error
		}
	}

	n, _, de := signal_session_decrypt_prekey(session, dst, wire, local^, trusted^)
	if de.kind != .None {
		return 0, false, 0, {kind = .Signal_Failed, signal = de}
	}

	return n, fresh && peek.has_prekey, peek.prekey_id, {}
}

socket_pairwise_whisper_open :: proc(
	socket: ^Socket,
	address: string,
	session: ^Signal_Session,
	session_name: ^string,
	wire, dst: []u8,
	trusted: ^[32]u8,
	pinned: bool,
) -> (
	int,
	Socket_Error,
) {
	if !pinned {
		return 0, {kind = .Identity_Changed}
	}

	n, e := signal_session_decrypt(session, dst, wire, trusted^)
	if e.kind != .None {
		initial_error := e
		prefix := fmt.aprintf("%s#", address)
		defer delete(prefix)
		recovered := false

		for record in socket.store.records {
			if record.kind != .Session || !strings.has_prefix(record.name, prefix) {
				continue
			}

			if de := signal_session_decode(session, record.data); de.kind != .None {
				return 0, {kind = .Signal_Failed, signal = de}
			}

			if session.remote_identity_public != trusted^ {
				continue
			}

			n, e = signal_session_decrypt(session, dst, wire, trusted^)

			if e.kind == .None {
				delete(session_name^)
				session_name^ = strings.clone(record.name)
				recovered = true
				break
			}
		}

		if !recovered {
			return 0, {kind = .Signal_Failed, signal = initial_error}
		}
	}

	return n, {}
}

socket_pairwise_decryption_stage :: proc(
	socket: ^Socket,
	address, session_name: string,
	session: ^Signal_Session,
	trusted: ^[32]u8,
	pinned, consumed: bool,
	consumed_id: u32,
) -> Socket_Error {
	if !pinned {
		if e := state_store_set(socket.store, .Identity, address, trusted[:]); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}

	if consumed {
		marker := fmt.aprintf("%d", consumed_id)
		defer delete(marker)

		if e := state_store_set(socket.store, .Consumed_Prekey, marker, []u8{1}); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}

	if e := socket_stage_session(socket, session_name, session); e.kind != .None {
		return e
	}

	return {}
}

socket_stage_group :: proc(socket: ^Socket, key: string, record: ^Signal_Group_Record) -> Socket_Error {
	snapshot := make([]u8, MAX_STATE_RECORD_SIZE)
	defer {
		crypto.zero_explicit(raw_data(snapshot), len(snapshot))
		delete(snapshot)
	}

	n, e := signal_group_record_encode(snapshot, record)

	if e != .None {
		return {kind = .Group_Failed, group = e}
	}

	if e := state_store_set(socket.store, .Sender_Key, key, snapshot[:n]); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	return {}
}

// WhatsApp applies a second, random-length pad inside Signal's CBC plaintext.
socket_message_unpad :: proc(message: []u8) -> ([]u8, Socket_Error) {
	if len(message) == 0 {
		return nil, {kind = .Protocol_Error}
	}

	count := cast(int)message[len(message) - 1]

	if count < 1 || count > 16 || count > len(message) {
		return nil, {kind = .Protocol_Error}
	}

	for byte in message[len(message) - count:] {
		if cast(int)byte != count {
			return nil, {kind = .Protocol_Error}
		}
	}

	return message[:len(message) - count], {}
}

socket_store_clone :: proc(destination, source: ^State_Store) -> Socket_Error {
	if source == nil {
		return {kind = .Invalid_State}
	}

	if error := state_store_clone(destination, source, source.allocator); error.kind != .None {
		return {kind = .State_Failed, state = error}
	}

	return {}
}

socket_store_commit :: proc(socket: ^Socket, next: ^State_Store) -> Socket_Error {
	if socket.store.requires_reload { return {kind = .State_Failed, state = {kind = .Directory_Flush_Failed}} }
	if e := state_store_save(next, socket.config.state_path); e.kind != .None {
		if e.kind == .Directory_Flush_Failed {
			socket.store.requires_reload = true
			return socket_fail(socket, {kind = .State_Failed, state = e})
		}
		return {kind = .State_Failed, state = e}
	}

	old := socket.store^
	socket.store^ = next^
	next^ = old

	return socket_cleanup_consumed_prekeys(socket)
}

socket_inbox_id_valid :: proc(id: string) -> bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}

	for byte in transmute([]u8)id {
		if byte < 33 || byte > 126 || byte == '|' {
			return false
		}
	}

	return true
}
socket_receive_group_valid :: proc(jid: string) -> bool {
	if len(jid) > 128 || !strings.has_suffix(jid, "@g.us") {
		return false
	}

	user := jid[:len(jid) - 5]

	if len(user) == 0 {
		return false
	}

	for byte in transmute([]u8)user {
		if !is_digit(byte) && byte != '-' {
			return false
		}
	}

	return true
}
socket_inbox_key :: proc(socket: ^Socket, group, participant, id: string) -> (string, Socket_Error) {
	if socket == nil {
		return "", {kind = .Invalid_State}
	}

	return socket_inbox_key_store(socket.store, group, participant, id)
}
socket_inbox_key_store :: proc(store: ^State_Store, group, participant, id: string) -> (string, Socket_Error) {
	if store == nil || !store.initialized {
		return "", {kind = .Invalid_State}
	}

	canonical, e := socket_signal_address_store(store, participant)
	if e.kind != .None {
		return "", e
	}

	defer delete(canonical)

	return fmt.aprintf("%s|%s|%s", group, canonical, id), {}
}
socket_sender_is_self :: proc(socket: ^Socket, jid: string) -> bool {
	if socket == nil {
		return false
	}

	return socket_sender_is_self_store(socket.store, socket.auth, jid)
}
socket_sender_is_self_store :: proc(store: ^State_Store, auth: ^Auth_State, jid: string) -> bool {
	if store == nil || !store.initialized || auth == nil {
		return false
	}

	user, _, e := pairing_jid_decode(jid)
	if e.kind != .None {
		return false
	}

	domain := jid[strings.index_byte(jid, '@') + 1:]
	if domain == "c.us" {
		domain = "s.whatsapp.net"
	}

	own := cast(string)auth.account.jid[:auth.account.jid_size]
	values := [2]string{own, ""}

	if lid, found := state_store_get(store, .LID_Mapping, "self"); found {
		values[1] = cast(string)lid
	}

	for value in values {
		own_user, _, oe := pairing_jid_decode(value)
		if oe.kind != .None {
			continue
		}

		own_domain := value[strings.index_byte(value, '@') + 1:]

		if own_domain == "c.us" {
			own_domain = "s.whatsapp.net"
		}

		if user == own_user && domain == own_domain {
			return true
		}
	}

	if domain == "lid" {
		canonical, ce := socket_signal_address_store(store, jid)
		if ce.kind != .None {
			return false
		}

		defer delete(canonical)
		canonical_user, _, cpe := pairing_jid_decode(canonical)
		own_user, _, ope := pairing_jid_decode(own)
		if cpe.kind == .None &&
		   ope.kind == .None &&
		   strings.has_suffix(canonical, "@s.whatsapp.net") &&
		   canonical_user == own_user {
			return true
		}
	}

	return false
}

socket_message_new :: proc(
	group, participant, id: string,
	protobuf: []u8,
	from_me: bool,
	timestamp: u64,
	offline: bool = false,
	recipient: string = "",
) -> (
	^Socket_Message,
	Socket_Error,
) {
	a := context.allocator
	message, ae := new(Socket_Message, a)
	if ae != nil {
		return nil, {kind = .Allocation_Failed, allocation = ae}
	}

	message.allocator = a
	success := false
	defer {
		if !success {
			socket_message_destroy(message)
		}
	}
	group_copy, ge := strings.clone(group, a)
	if ge != nil {
		return nil, {kind = .Allocation_Failed, allocation = ge}
	}

	message.group = group_copy
	participant_copy, pe := strings.clone(participant, a)
	if pe != nil {
		return nil, {kind = .Allocation_Failed, allocation = pe}
	}

	message.participant = participant_copy
	if recipient != "" {
		to, e := strings.clone(recipient, a)
		if e != nil { return nil, {kind = .Allocation_Failed, allocation = e} }
		message.recipient = to
	}
	id_copy, ie := strings.clone(id, a)
	if ie != nil {
		return nil, {kind = .Allocation_Failed, allocation = ie}
	}

	message.id = id_copy
	data, de := make([]u8, len(protobuf), a)
	if de != nil {
		return nil, {kind = .Allocation_Failed, allocation = de}
	}

	copy(data, protobuf)
	message.protobuf = data
	message.from_me = from_me
	message.timestamp = timestamp
	message.offline = offline
	success = true
	return message, {}
}

socket_inbox_stage :: proc(store: ^State_Store, name: string, message: ^Socket_Message) -> Socket_Error {
	timestamp := fmt.aprintf("%d", message.timestamp)
	defer delete(timestamp)
	own := message.from_me ? "1" : "0"
	offline := message.offline ? "1" : "0"
	node := Binary_Node {
		tag     = "message",
		attrs   = []Binary_Node_Attribute {
			{"from", message.group},
			{"participant", message.participant},
			{"id", message.id},
			{"t", timestamp},
			{"own", own},
			{"offline", offline},
			{"recipient", message.recipient},
		},
		content = message.protobuf,
	}

	if message.recipient == "" { node.attrs = node.attrs[:len(node.attrs) - 1] }

	n, e := binary_node_encode(nil, node)

	if e.kind != .Destination_Undersized {
		return {kind = .Binary_Failed, binary = e}
	}

	data := make([]u8, n)
	defer {
		crypto.zero_explicit(raw_data(data), len(data))
		delete(data)
	}

	_, e = binary_node_encode(data, node)

	if e.kind != .None {
		return {kind = .Binary_Failed, binary = e}
	}

	if se := state_store_set(store, .Inbox_Message, name, data); se.kind != .None {
		return {kind = .State_Failed, state = se}
	}

	return {}
}

// Completing work is durable; destroying an event alone intentionally leaves
// it in the inbox for redelivery after a crash. Completion does not free it.
socket_message_complete :: proc(socket: ^Socket, message: ^Socket_Message) -> Socket_Error {
	return socket_complete_inbox(socket, message, "")
}

// Call only for incoming audio in a chat the consumer explicitly selected.
socket_complete_private_audio :: proc(
	socket: ^Socket,
	message: ^Socket_Message,
	authorized_chat: string,
) -> Socket_Error {
	if !device_user_jid_valid(authorized_chat, false) {
		return {kind = .Invalid_Config}
	}
	return socket_complete_inbox(socket, message, authorized_chat)
}

MAX_CAPTURED_PRIVATE_AUDIO :: 64
MAX_CAPTURED_AUDIO_RECORD :: 64 << 10

// A missing entry returns nil with success. A restored message owns its bytes.
load_private_audio :: proc(
	store: ^State_Store,
	chat, id: string,
) -> (
	^Socket_Message,
	Socket_Error,
) {
	if store == nil ||
	   !store.initialized ||
	   !device_user_jid_valid(chat, false) ||
	   !socket_inbox_id_valid(id) {
		return nil, {kind = .Invalid_Config}
	}
	for jid in ([2]string{chat, chat_history_alternate_jid(store, chat)}) {
		if jid == "" {
			continue
		}
		key := fmt.aprintf("%s|%s", jid, id)
		defer delete(key)
		if data, have := state_store_get(store, .Private_Audio, key); have {
			return socket_message_new(
				"",
				jid,
				id,
				data[8:],
				false,
				endian.unchecked_get_u64be(data[:8]),
			)
		}
	}
	return nil, {}
}

@(private)
private_audio_chat_matches :: proc(
	store: ^State_Store,
	chat: string,
	message: ^Socket_Message,
) -> bool {
	if message.group != "" ||
	   message.from_me ||
	   !device_user_jid_valid(message.participant, true) {
		return false
	}
	user, _, _ := pairing_jid_decode(message.participant)
	jid := strings.concatenate(
		{user, message.participant[strings.index_byte(message.participant, '@'):]},
	)
	defer delete(jid)
	return jid == chat || jid == chat_history_alternate_jid(store, chat)
}

@(private)
stage_private_audio :: proc(
	store: ^State_Store,
	chat: string,
	message: ^Socket_Message,
) -> Socket_Error {
	if !private_audio_chat_matches(store, chat, message) {
		return {kind = .Invalid_Config}
	}
	media, err := media_message_decode(message.protobuf)
	if err.kind != .None {
		return {kind = .Media_Failed, media = err}
	}
	if media.kind != .Audio {
		return {kind = .Media_Failed, media = {kind = .Invalid_Kind}}
	}
	metadata, validation := media_metadata_from_message(media)
	defer media_metadata_clear(&metadata)
	if validation.kind != .None {
		return {kind = .Media_Failed, media = validation}
	}
	url: [MAX_MEDIA_URL_SIZE]u8
	if _, e := media_download_url(url[:], media); e.kind != .None {
		return {kind = .Media_Failed, media = e}
	}
	if len(message.protobuf) > MAX_CAPTURED_AUDIO_RECORD - 8 {
		return {kind = .Queue_Full}
	}
	key := fmt.aprintf("%s|%s", chat, message.id)
	defer delete(key)
	oldest: string
	count := 0
	for record in store.records {
		if record.kind == .Private_Audio {
			if count == 0 {
				oldest = record.name
			}
			count += 1
		}
	}
	if _, exists := state_store_get(store, .Private_Audio, key);
	   !exists && count >= MAX_CAPTURED_PRIVATE_AUDIO {
		if e := state_store_delete(store, .Private_Audio, oldest); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}
	data, ae := make([]u8, 8 + len(message.protobuf))
	if ae != nil {
		return {kind = .Allocation_Failed, allocation = ae}
	}
	defer {crypto.zero_explicit(raw_data(data), len(data)); delete(data)}
	endian.unchecked_put_u64be(data[:8], message.timestamp)
	copy(data[8:], message.protobuf)
	if e := state_store_set(store, .Private_Audio, key, data); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}
	return {}
}

@(private)
socket_complete_inbox :: proc(
	socket: ^Socket,
	message: ^Socket_Message,
	authorized_chat: string,
) -> Socket_Error {
	if socket == nil || socket.store == nil || message == nil {
		return {kind = .Invalid_State}
	}

	name, name_error := socket_inbox_key(socket, message.group, message.participant, message.id)
	if name_error.kind != .None {
		return name_error
	}

	defer delete(name)
	candidate: State_Store
	defer state_store_clear(&candidate)

	if e := socket_store_clone(&candidate, socket.store); e.kind != .None {
		return e
	}

	inbox, have := state_store_get(&candidate, .Inbox_Message, name)
	if !have {
		if authorized_chat != "" &&
		   private_audio_chat_matches(&candidate, authorized_chat, message) {
			retained, e := load_private_audio(&candidate, authorized_chat, message.id)
			if e.kind != .None {
				return e
			}
			if retained != nil {
				defer socket_message_destroy(retained)
				if _, processed := state_store_get(&candidate, .Processed_Message, name);
				   processed {
					return {}
				}
			}
		}
		return {kind = .Invalid_State}
	}
	if authorized_chat != "" {
		original, e := socket_inbox_record_restore(
			socket,
			{kind = .Inbox_Message, name = name, data = inbox},
		)
		if e.kind != .None {
			return e
		}
		defer socket_message_destroy(original)
		if staged := stage_private_audio(&candidate, authorized_chat, original);
		   staged.kind != .None {
			return staged
		}
	}

	if e := socket_processed_set(&candidate, name); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	if e := state_store_delete(&candidate, .Inbox_Message, name); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	return socket_store_commit(socket, &candidate)
}

socket_inbox_restore :: proc(socket: ^Socket) -> Socket_Error {
	if socket == nil || socket.store == nil || !socket.store.initialized || len(socket.queue) != 0 {
		return {kind = .Invalid_State}
	}

	pending := make([dynamic]^Socket_Message)
	defer delete(pending)
	success := false
	defer {
		if !success {
			for message in pending {
				socket_message_destroy(message)
			}
		}
	}

	for record in socket.store.records {
		if record.kind != .Inbox_Message {
			continue
		}

		message, message_error := socket_inbox_record_restore(socket, record)
		if message_error.kind != .None {
			return message_error
		}

		_, ae := append(&pending, message)

		if ae != nil {
			socket_message_destroy(message)
			return {kind = .Allocation_Failed, allocation = ae}
		}
	}

	for message in pending {
		// Roll back queue ownership on allocation failure.
		if _, ae := append(&socket.queue, message); ae != nil {
			clear(&socket.queue)
			return {kind = .Allocation_Failed, allocation = ae}
		}
	}

	success = true

	return {}
}

socket_inbox_record_restore :: proc(socket: ^Socket, record: State_Record) -> (^Socket_Message, Socket_Error) {
	doc, e := binary_node_decode(record.data)

	if e.kind != .None {
		return nil, {kind = .Binary_Failed, binary = e}
	}

	node := doc.root
	group, _ := node_attr(node, "from")
	participant, _ := node_attr(node, "participant")
	id, _ := node_attr(node, "id")
	timestamp, _ := node_attr(node, "t")
	own, _ := node_attr(node, "own")
	offline, _ := node_attr(node, "offline")
	recipient, _ := node_attr(node, "recipient")
	raw, ok := node.content.([]u8)
	stamp, valid := strconv.parse_u64(timestamp)
	if !ok ||
	   !valid ||
	   (own != "0" && own != "1") ||
	   (offline != "0" && offline != "1") ||
	   (recipient != "" && (own != "1" || group != "" || !device_user_jid_valid(recipient, true))) ||
	   !device_user_jid_valid(participant, true) ||
	   !socket_inbox_id_valid(id) ||
	   (group != "" && !socket_receive_group_valid(group)) {
		binary_document_destroy(&doc)
		return nil, {kind = .Protocol_Error}
	}

	name, name_error := socket_inbox_key(socket, group, participant, id)

	if name_error.kind != .None {
		binary_document_destroy(&doc)
		return nil, name_error
	}

	matches := name == record.name
	delete(name)

	if !matches {
		binary_document_destroy(&doc)
		return nil, {kind = .Protocol_Error}
	}

	message, me := socket_message_new(group, participant, id, raw, own == "1", stamp, offline == "1", recipient)
	binary_document_destroy(&doc)
	if me.kind != .None {
		return nil, me
	}

	return message, {}
}

// Consumption markers are authoritative across the two atomic files. A crash
// between commits leaves an unusable private prekey, never a reusable one.
socket_cleanup_consumed_prekeys :: proc(socket: ^Socket) -> Socket_Error {
	if socket == nil || socket.store == nil || socket.prekeys == nil {
		return {kind = .Invalid_State}
	}

	changed := false

	for record in socket.store.records {
		if record.kind != .Consumed_Prekey {
			continue
		}

		id, ok := strconv.parse_u64(record.name)

		if !ok || id > cast(u64)MAX_DEVICE_PREKEY_ID {
			return {kind = .Protocol_Error}
		}

		if prekey_store_get(socket.prekeys, cast(u32)id) == nil {
			continue
		}

		e := prekey_store_remove_consumed(socket.prekeys, cast(u32)id)
		if e.kind == .Pending_Upload_Exists {
			continue
		}

		if e.kind != .None {
			return {kind = .Prekey_Failed, prekey = e}
		}

		changed = true
	}

	if changed || socket.prekeys.durable_revision != socket.prekeys.revision {
		if e := prekey_store_save(socket.config.prekey_path, socket.prekeys); e.kind != .None {
			return {kind = .Prekey_Failed, prekey = e}
		}
	}

	return {}
}

SOCKET_RETRY_LIMIT :: 5
SOCKET_REPLAY_RETENTION_SECONDS :: 7 * 24 * 60 * 60
SOCKET_RETRY_COUNTER_SIZE :: 9

// Legacy records contain only the count. New records append the local attempt
// time, leaving their first byte compatible with existing state inspection.
socket_retry_counter_read :: proc(data: []u8, found: bool) -> (count: u8, timestamp: u64, error: Socket_Error) {
	if !found {
		return 0, 0, {}
	}

	if len(data) != 1 && len(data) != SOCKET_RETRY_COUNTER_SIZE {
		return 0, 0, {kind = .Protocol_Error}
	}

	if data[0] > SOCKET_RETRY_LIMIT {
		return 0, 0, {kind = .Protocol_Error}
	}

	if len(data) == SOCKET_RETRY_COUNTER_SIZE {
		timestamp = endian.unchecked_get_u64be(data[1:])
	}

	return data[0], timestamp, {}
}

socket_retry_counter_set :: proc(store: ^State_Store, name: string, count: u8) -> Socket_Error {
	if count > SOCKET_RETRY_LIMIT {
		return {kind = .Protocol_Error}
	}

	stamp := encode_current_unix_timestamp()
	data: [SOCKET_RETRY_COUNTER_SIZE]u8
	data[0] = count
	copy(data[1:], stamp[:])

	if error := state_store_set(store, .Retry_Count, name, data[:]); error.kind != .None {
		return {kind = .State_Failed, state = error}
	}

	return {}
}

// Never discard an unconsumed private key to make room for another retry.
// Stop this message's retry sequence durably, report capacity, and keep the
// listener alive. Its protocol ACK is not application completion or plaintext.
socket_retry_prekeys_exhausted :: proc(socket: ^Socket, name: string, capacity: Prekey_Error) -> Socket_Error {
	candidate: State_Store
	defer state_store_clear(&candidate)

	if error := socket_store_clone(&candidate, socket.store); error.kind != .None {
		return error
	}

	if error := socket_retry_counter_set(&candidate, name, SOCKET_RETRY_LIMIT); error.kind != .None {
		return error
	}

	if error := socket_store_commit(socket, &candidate); error.kind != .None {
		return error
	}

	socket.last_error = {
		kind   = .Prekey_Failed,
		prekey = capacity,
	}

	log.warn("WhatsApp retry stopped: prekey capacity unavailable:", capacity.kind)

	return {}
}

Socket_Retry_Body :: struct {
	registration:         [4]u8,
	count_text:           [4]u8,
	type_byte:            [1]u8,
	prekey_id, signed_id: [3]u8,
	identity:             [32]u8,
	device_identity:      [MAX_PAIRING_IDENTITY_SIZE]u8,
	children:             [3]Binary_Node,
	retry_attrs:          [4]Binary_Node_Attribute,
	keys:                 [5]Binary_Node,
	key_children:         [2]Binary_Node,
	signed_children:      [3]Binary_Node,
	child_count:          int,
}

// Own the backing arrays until receipt encoding finishes; Binary_Node slices
// must never borrow locals from a helper that has already returned.
socket_retry_keys_prepare :: proc(socket: ^Socket, body: ^Socket_Retry_Body) -> Socket_Error {
	if error := prekey_store_generate(socket.prekeys, 1); error.kind != .None {
		return {kind = .Prekey_Failed, prekey = error}
	}

	// Persist the private key before exposing its public counterpart.
	if error := prekey_store_save(socket.config.prekey_path, socket.prekeys); error.kind != .None {
		return {kind = .Prekey_Failed, prekey = error}
	}

	key := &socket.prekeys.keys[socket.prekeys.count - 1]
	body.type_byte[0] = 5
	body.prekey_id = encode_prekey_id_u24(key.id)
	body.signed_id = encode_prekey_id_u24(socket.auth.credentials.signed_prekey_id)
	body.identity = signal_curve_public(socket.auth.credentials.identity_private)
	body.key_children = {{tag = "id", content = body.prekey_id[:]}, {tag = "value", content = key.public[:]}}
	body.signed_children = {
		{tag = "id", content = body.signed_id[:]},
		{tag = "value", content = socket.auth.credentials.signed_prekey_public[:]},
		{tag = "signature", content = socket.auth.credentials.signed_prekey_signature[:]},
	}

	account := &socket.auth.account
	size, encoded := pairing_signed_identity_encode(
		body.device_identity[:],
		{
			details = account.details[:account.details_size],
			account_signature_key = account.account_signature_key[:],
			account_signature = account.account_signature[:],
			device_signature = account.device_signature[:],
		},
		true,
	)

	if encoded != .None {
		return {kind = .Protocol_Error}
	}

	body.keys = {
		{tag = "type", content = body.type_byte[:]},
		{tag = "identity", content = body.identity[:]},
		{tag = "key", content = body.key_children[:]},
		{tag = "skey", content = body.signed_children[:]},
		{tag = "device-identity", content = body.device_identity[:size]},
	}

	return {}
}

socket_retry_body_prepare :: proc(
	socket: ^Socket,
	node: Binary_Node,
	count: u8,
	body: ^Socket_Retry_Body,
) -> Socket_Error {
	assert(count > 0)
	assert(count <= SOCKET_RETRY_LIMIT)
	id, _ := node_attr(node, "id")
	timestamp, _ := node_attr(node, "t")
	registration := socket.auth.credentials.registration_id
	endian.unchecked_put_u32be(body.registration[:], registration)
	count_text := fmt.bprintf(body.count_text[:], "%d", count)
	body.retry_attrs = {{"count", count_text}, {"id", id}, {"t", timestamp}, {"v", "1"}}
	body.children = {
		{tag = "retry", attrs = body.retry_attrs[:]},
		{tag = "registration", content = body.registration[:]},
		{},
	}
	body.child_count = 2
	if count > 1 {
		if error := socket_retry_keys_prepare(socket, body); error.kind != .None {
			return error
		}

		body.children[2] = {
			tag     = "keys",
			content = body.keys[:],
		}

		body.child_count = 3
	}
	return {}
}

socket_retry_receipt_send :: proc(socket: ^Socket, node: Binary_Node, body: ^Socket_Retry_Body) -> Socket_Error {
	id, _ := node_attr(node, "id")
	from, _ := node_attr(node, "from")
	participant, _ := node_attr(node, "participant")
	attrs := [5]Binary_Node_Attribute{{"id", id}, {"type", "retry"}, {"to", from}, {}, {}}
	count := 3

	if participant != "" {
		attrs[count] = {"participant", participant}
		count += 1
	}

	if recipient, found := node_attr(node, "recipient"); found {
		attrs[count] = {"recipient", recipient}
		count += 1
	}

	wire: [4096]u8
	size, encoded := binary_node_encode(
		wire[:],
		{tag = "receipt", attrs = attrs[:count], content = body.children[:body.child_count]},
	)

	if encoded.kind != .None {
		return {kind = .Binary_Failed, binary = encoded}
	}

	return socket_write(socket, wire[:size])
}

// Persist a bounded counter before issuing a retry. Capacity exhaustion stops
// this message, never evicts private keys or terminates a healthy listener.
socket_request_retry :: proc(socket: ^Socket, node: Binary_Node) -> Socket_Error {
	id, _ := node_attr(node, "id")
	from, _ := node_attr(node, "from")
	participant, _ := node_attr(node, "participant")
	if !socket_inbox_id_valid(id) ||
	   (!device_user_jid_valid(from, true) && !socket_receive_group_valid(from)) ||
	   (participant != "" && !device_user_jid_valid(participant, true)) {
		return {kind = .Protocol_Error}
	}

	name := fmt.aprintf("in:%s|%s", id, participant)
	defer delete(name)
	previous, found := state_store_get(socket.store, .Retry_Count, name)
	count, _, decoded := socket_retry_counter_read(previous, found)

	if decoded.kind != .None {
		return decoded
	}

	if count >= SOCKET_RETRY_LIMIT {
		return {}
	}

	count += 1
	body: Socket_Retry_Body

	if error := socket_retry_body_prepare(socket, node, count, &body); error.kind != .None {
		if error.kind == .Prekey_Failed && (error.prekey.kind == .Store_Full || error.prekey.kind == .ID_Exhausted) {
			return socket_retry_prekeys_exhausted(socket, name, error.prekey)
		}

		return error
	}

	candidate: State_Store
	defer state_store_clear(&candidate)

	if error := socket_store_clone(&candidate, socket.store); error.kind != .None {
		return error
	}

	if error := socket_retry_counter_set(&candidate, name, count); error.kind != .None {
		return error
	}

	if error := socket_store_commit(socket, &candidate); error.kind != .None {
		return error
	}

	return socket_retry_receipt_send(socket, node, &body)
}

socket_archive_session :: proc(socket: ^Socket, jid: string, session: ^Signal_Session) -> Socket_Error {
	prefix := fmt.aprintf("%s#", jid)
	defer delete(prefix)
	// Retain five prior X3DH generations, matching Signal's bounded historical
	// session model. Removing the oldest archive never rolls back current keys.
	count := 0
	oldest := ""

	for record in socket.store.records {
		if record.kind == .Session && strings.has_prefix(record.name, prefix) {
			count += 1

			if oldest == "" {
				oldest = record.name
			}
		}
	}

	if count >= 5 {
		victim := strings.clone(oldest)
		defer delete(victim)

		if e := state_store_delete(socket.store, .Session, victim); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}

	encoded := hex.encode(session.base_public[:])
	defer delete(encoded)
	name := fmt.aprintf("%s#%s", jid, encoded)
	defer delete(name)

	return socket_stage_session(socket, name, session)
}

socket_send_delivery_receipt :: proc(socket: ^Socket, node: Binary_Node) -> Socket_Error {
	id, _ := node_attr(node, "id")
	from, _ := node_attr(node, "from")
	participant, _ := node_attr(node, "participant")
	category, _ := node_attr(node, "category")
	kind := ""
	author := from
	if participant != "" {
		author = participant
	}

	if category == "peer" {
		kind = "peer_msg"
	} else if socket_sender_is_self(socket, author) {
		kind = "sender"
	}

	attrs: [5]Binary_Node_Attribute
	attrs[0] = {"id", id}
	count := 1

	if kind == "sender" && device_user_jid_valid(from, true) {
		remote := from

		if recipient, have := node_attr(node, "recipient"); have && device_user_jid_valid(recipient, true) {
			remote = recipient
		}

		attrs[count] = {"recipient", remote}
		count += 1
		attrs[count] = {"to", author}
		count += 1
	} else {
		attrs[count] = {"to", from}
		count += 1

		if participant != "" {
			attrs[count] = {"participant", participant}
			count += 1
		}
	}

	if kind != "" {
		attrs[count] = {"type", kind}
		count += 1
	}

	wire: [2048]u8
	n, e := binary_node_encode(wire[:], {tag = "receipt", attrs = attrs[:count]})

	if e.kind != .None {
		return {kind = .Binary_Failed, binary = e}
	}

	return socket_write(socket, wire[:n])
}

// Completion time, rather than remote message time, bounds replay-marker
// retention without prematurely dropping newly processed offline history.
encode_current_unix_timestamp :: proc() -> [8]u8 {
	value := cast(u64)max(0, time.to_unix_seconds(time.now()))
	stamp: [8]u8
	endian.unchecked_put_u64be(stamp[:], value)

	return stamp
}
processed_history_receipt :: proc(marker: []u8) -> bool {
	return len(marker) == 9 && marker[8] == 1
}

socket_processed_set :: proc(store: ^State_Store, name: string, history_receipt := false) -> State_Error {
	stamp := encode_current_unix_timestamp()

	if history_receipt {
		marker: [9]u8
		copy(marker[:8], stamp[:])
		marker[8] = 1
		return state_store_set(store, .Processed_Message, name, marker[:])
	}
	return state_store_set(store, .Processed_Message, name, stamp[:])
}

// Locate the protocol envelope inside supported message wrappers.
unwrap_protocol_message :: proc(message: []u8, depth: int) -> []u8 {
	if depth >= MAX_MESSAGE_NESTING || len(message) > MAX_PROTOBUF_MESSAGE_SIZE {
		return nil
	}

	at := 0
	protocol: []u8
	wrapper: []u8
	wrapper_field: u32

	for at < len(message) {
		field, e := protobuf_field_read(message, &at)
		if e != .None {
			return nil
		}

		switch field.number {
		case 12:
			if field.wire_type != 2 || protocol != nil {
				return nil
			}

			protocol = field.data
		case 31, 37, 40, 53, 55, 58, 59:
			if field.wire_type != 2 || wrapper != nil {
				return nil
			}

			wrapper = field.data
			wrapper_field = field.number == 31 ? 2 : 1
		}
	}

	if protocol != nil {
		if wrapper != nil {
			return nil
		}

		return protocol
	}

	if wrapper != nil {
		at = 0
		inner: []u8

		for at < len(wrapper) {
			field, e := protobuf_field_read(wrapper, &at)
			if e != .None {
				return nil
			}

			if field.number == wrapper_field {
				if field.wire_type != 2 || inner != nil {
					return nil
				}

				inner = field.data
			}
		}

		if inner != nil {
			return unwrap_protocol_message(inner, depth + 1)
		}
	}

	return nil
}

message_contains_history_sync_notification :: proc(message: []u8, depth: int) -> bool {
	return socket_protocol_has_history(unwrap_protocol_message(message, depth))
}

socket_protocol_has_history :: proc(protocol: []u8) -> bool {
	field, ok := read_unique_protobuf_field(protocol, 6, 2)
	return ok && field.number != 0
}

socket_send_history_receipt :: proc(socket: ^Socket, node: Binary_Node) -> Socket_Error {
	from, _ := node_attr(node, "from")
	id, _ := node_attr(node, "id")

	if !socket_sender_is_self(socket, from) || !device_user_jid_valid(from, true) {
		return {kind = .Protocol_Error}
	}

	user, _, e := pairing_jid_decode(from)
	if e.kind != .None {
		return {kind = .Protocol_Error}
	}

	domain := from[strings.index_byte(from, '@') + 1:]
	if domain == "c.us" {
		domain = "s.whatsapp.net"
	}

	destination := fmt.aprintf("%s@%s", user, domain)
	defer delete(destination)
	buffer: [1024]u8
	n, be := binary_node_encode(
		buffer[:],
		{tag = "receipt", attrs = []Binary_Node_Attribute{{"to", destination}, {"id", id}, {"type", "hist_sync"}}},
	)

	if be.kind != .None {
		return {kind = .Binary_Failed, binary = be}
	}

	return socket_write(socket, buffer[:n])
}

// Receipt-triggered sends run outside any outstanding IQ/media wait. Retaining
// an owned node avoids nested queries consuming an outer query's response.
socket_defer_retry :: proc(socket: ^Socket, node: Binary_Node) -> Socket_Error {
	if len(socket.deferred_retries) >= 64 {
		return {kind = .Queue_Full}
	}

	n, measured := binary_node_encode(nil, node)

	if measured.kind != .Destination_Undersized {
		return {kind = .Binary_Failed, binary = measured}
	}

	data, ae := make([]u8, n)

	if ae != nil {
		return {kind = .Allocation_Failed, allocation = ae}
	}

	defer delete(data)
	_, encoded := binary_node_encode(data, node)

	if encoded.kind != .None {
		return {kind = .Binary_Failed, binary = encoded}
	}

	doc, decoded := binary_node_decode(data)

	if decoded.kind != .None {
		return {kind = .Binary_Failed, binary = decoded}
	}

	if _, append_error := append(&socket.deferred_retries, doc); append_error != nil {
		binary_document_destroy(&doc)
		return {kind = .Allocation_Failed, allocation = append_error}
	}

	return {}
}

// Protocol ACKs are distinct from the application's successful-write reaction.
// Invoke after durable receive handling, including for ignored control stanzas.
socket_acknowledge :: proc(socket: ^Socket, node: Binary_Node, error_code: u32 = 0) -> Socket_Error {
	id, has_id := node_attr(node, "id")
	from, has_from := node_attr(node, "from")

	if !has_id || !has_from || len(id) == 0 || len(from) == 0 {
		return {kind = .Protocol_Error}
	}

	attrs: [9]Binary_Node_Attribute
	attrs[0], attrs[1], attrs[2] = {"id", id}, {"to", from}, {"class", node.tag}
	count := 3
	names := [2]string{"participant", "recipient"}

	for name in names {
		if value, found := node_attr(node, name); found {
			attrs[count] = {name, value}
			count += 1
		}
	}

	_, unavailable := pairing_node_child(node, "unavailable")

	if node.tag != "message" || unavailable || error_code != 0 {
		if value, found := node_attr(node, "type"); found {
			attrs[count] = {"type", value}
			count += 1
		}
	}

	buffer_code: [16]u8

	if error_code != 0 {
		attrs[count] = {"error", fmt.bprintf(buffer_code[:], "%d", error_code)}
		count += 1
	}

	if node.tag == "message" && unavailable {
		attrs[count] = {"from", cast(string)socket.auth.account.jid[:socket.auth.account.jid_size]}
		count += 1
	}

	buffer: [2048]u8
	n, err := binary_node_encode(buffer[:], {tag = "ack", attrs = attrs[:count]})

	if err.kind != .None {
		return {kind = .Binary_Failed, binary = err}
	}

	return socket_write(socket, buffer[:n])
}

// Called only for an authenticated-server receipt matching a stored group
// message. It refreshes the requester's pairwise session and sends a fresh
// distribution/ciphertext ONLY to that device, retaining the original ID.
socket_retry_outgoing :: proc(socket: ^Socket, receipt: Binary_Node) -> Socket_Error {
	raw_id, _ := node_attr(receipt, "id")
	id := strings.clone(raw_id)
	defer delete(id)
	from, _ := node_attr(receipt, "from")
	raw_participant, _ := node_attr(receipt, "participant")
	participant := strings.clone(raw_participant)
	defer delete(participant)

	if !group_jid_valid(from) || !device_user_jid_valid(participant, true) {
		return {}
	}

	content, found := state_store_get(socket.store, .Outbound_Content, id)
	if !found {
		return {}
	}

	doc, decoded := binary_node_decode(content)

	if decoded.kind != .None {
		return {kind = .Binary_Failed, binary = decoded}
	}

	defer binary_document_destroy(&doc)
	group, _ := node_attr(doc.root, "to")
	if from != group {
		return {kind = .Protocol_Error}
	}

	media_type, _ := node_attr(doc.root, "mediatype")
	protobuf, ok := doc.root.content.([]u8)
	if !ok {
		return {kind = .Protocol_Error}
	}

	count_name := fmt.aprintf("out:%s|%s", id, participant)
	defer delete(count_name)
	previous, counter_found := state_store_get(socket.store, .Retry_Count, count_name)
	count, _, counter_error := socket_retry_counter_read(previous, counter_found)

	if counter_error.kind != .None {
		return counter_error
	}

	if count >= SOCKET_RETRY_LIMIT {
		return {}
	}

	count += 1

	if error := socket_retry_counter_set(socket.store, count_name, count); error.kind != .None {
		return error
	}

	if archive_error := socket_retry_session_archive(socket, participant); archive_error.kind != .None {
		return archive_error
	}

	new_id, err := socket_send_group(socket, group, protobuf, media_type, id, participant)
	delete(new_id)

	return err
}

socket_retry_session_archive :: proc(socket: ^Socket, participant: string) -> Socket_Error {
	address, address_err := socket_signal_address(socket, participant)
	if address_err.kind != .None {
		return address_err
	}

	defer delete(address)

	if old, session_found := state_store_get(socket.store, .Session, address); session_found {
		prior := new(Signal_Session)
		defer {
			signal_session_clear(prior)
			free(prior)
		}

		if e := signal_session_decode(prior, old); e.kind != .None {
			return {kind = .Signal_Failed, signal = e}
		}

		if e := socket_archive_session(socket, address, prior); e.kind != .None {
			return e
		}

		if e := state_store_delete(socket.store, .Session, address); e.kind != .None {
			return {kind = .State_Failed, state = e}
		}
	}

	return {}
}

socket_replay_outbox :: proc(socket: ^Socket) -> Socket_Error {
	if socket == nil || socket.phase != .Online {
		return {kind = .Invalid_State}
	}

	for record in socket.store.records {
		if record.kind != .Outbound_Message {
			continue
		}

		if e := socket_write(socket, record.data); e.kind != .None {
			return e
		}
	}

	return {}
}

// Administrative identity rotation is explicit. Clear the old session in the
// same durable transaction so the next send fetches a signed current bundle.
socket_trust_identity :: proc(socket: ^Socket, device_jid: string, identity: [32]u8) -> Socket_Error {
	if socket == nil || !device_user_jid_valid(device_jid, true) {
		return {kind = .Invalid_Config}
	}

	key := identity

	if crypto.is_zero_constant_time(key[:]) == 1 {
		return {kind = .Invalid_Config}
	}

	address, address_error := socket_signal_address(socket, device_jid)
	if address_error.kind != .None {
		return address_error
	}

	defer delete(address)
	candidate: State_Store
	defer state_store_clear(&candidate)

	if e := socket_store_clone(&candidate, socket.store); e.kind != .None {
		return e
	}

	if e := state_store_set(&candidate, .Identity, address, key[:]); e.kind != .None {
		return {kind = .State_Failed, state = e}
	}

	archive_prefix := fmt.aprintf("%s#", address)
	defer delete(archive_prefix)

	for record in socket.store.records {
		remove :=
			record.kind == .Session && (record.name == address || strings.has_prefix(record.name, archive_prefix))

		if record.kind == .Sender_Key || record.kind == .Sender_Key_Membership {
			if at := strings.index_byte(record.name, '|'); at >= 0 && record.name[at + 1:] == address {
				remove = true
			}
		}

		if remove {
			if e := state_store_delete(&candidate, record.kind, record.name); e.kind != .None {
				return {kind = .State_Failed, state = e}
			}
		}
	}

	return socket_store_commit(socket, &candidate)
}

// Pending work protects its retry counters even after the replay horizon.
// Hash keys borrow no mutable record strings and bound map memory.
socket_prune_pending_ids :: proc(store: ^State_Store) -> (map[[32]u8]bool, Socket_Error) {
	pending, allocation := make(map[[32]u8]bool, len(store.records))

	if allocation != nil {
		return nil, {kind = .Allocation_Failed, allocation = allocation}
	}

	for record in store.records {
		if record.kind == .Outbound_Message {
			pending[sha256(transmute([]u8)record.name)] = true
		} else if record.kind == .Inbox_Message {
			// socket_inbox_key is group|canonical participant|message ID.
			// Split only the first two delimiters: IDs may themselves contain '|'.
			first := strings.index_byte(record.name, '|')

			if first < 0 {
				continue
			}

			rest := record.name[first + 1:]
			second := strings.index_byte(rest, '|')

			if second < 0 {
				continue
			}

			id := rest[second + 1:]
			pending[sha256(transmute([]u8)id)] = true
		}
	}

	return pending, {}
}

socket_retry_record_id :: proc(name: string) -> string {
	prefix := 0

	if strings.has_prefix(name, "in:") {
		prefix = 3
	}

	if strings.has_prefix(name, "out:") {
		prefix = 4
	}

	separator := strings.last_index_byte(name, '|')

	if prefix == 0 || separator <= prefix {
		return ""
	}

	return name[prefix:separator]
}

socket_prune_retry_record :: proc(
	record: ^State_Record,
	pending: map[[32]u8]bool,
	cutoff, now_seconds: u64,
	allocator: mem.Allocator,
) -> (
	remove, changed: bool,
	error: Socket_Error,
) {
	count, timestamp, decoded := socket_retry_counter_read(record.data, true)
	if decoded.kind != .None {
		return false, false, decoded
	}
	if len(record.data) == 1 {
		// Legacy snapshots have no age evidence. Start their full retention
		// window locally; never reset their retry count during migration.
		data, allocation := make([]u8, SOCKET_RETRY_COUNTER_SIZE, allocator)

		if allocation != nil {
			return false, false, {kind = .Allocation_Failed, allocation = allocation}
		}

		data[0] = count

		endian.unchecked_put_u64be(data[1:], now_seconds)

		crypto.zero_explicit(raw_data(record.data), len(record.data))
		delete(record.data, allocator)
		record.data = data
		timestamp, changed = now_seconds, true
	}
	id := socket_retry_record_id(record.name)
	if id == "" || pending[sha256(transmute([]u8)id)] {
		return false, changed, {}
	}
	return timestamp < cutoff, changed, {}
}

socket_prune_record :: proc(
	record: ^State_Record,
	pending: map[[32]u8]bool,
	cutoff, now_seconds: u64,
	allocator: mem.Allocator,
) -> (
	remove, changed: bool,
	error: Socket_Error,
) {
	if record.kind == .Retry_Count {
		return socket_prune_retry_record(record, pending, cutoff, now_seconds, allocator)
	}
	timestamp: u64
	if record.kind == .Processed_Message {
		if len(record.data) != 8 && !processed_history_receipt(record.data) {
			return false, false, {}
		}

		timestamp = endian.unchecked_get_u64be(record.data[:8])
	} else if record.kind == .Outbound_Content {
		if pending[sha256(transmute([]u8)record.name)] {
			return false, false, {}
		}

		document, decoded := binary_node_decode(record.data)

		if decoded.kind != .None {
			return false, false, {kind = .Binary_Failed, binary = decoded}
		}

		text, _ := node_attr(document.root, "t")
		value, valid := strconv.parse_u64(text)
		binary_document_destroy(&document)

		if !valid {
			return false, false, {}
		}

		timestamp = value
	} else {
		return false, false, {}
	}
	return timestamp < cutoff, false, {}
}

// Prune in one compaction pass. Pending inbox/outbox and cryptographic records
// remain owned and intact; legacy retry counters receive a conservative age.
socket_prune_state :: proc(socket: ^Socket, now: time.Time) -> Socket_Error {
	if socket == nil || socket.store == nil {
		return {kind = .Invalid_State}
	}

	now_seconds := time.to_unix_seconds(now)
	cutoff := now_seconds - SOCKET_REPLAY_RETENTION_SECONDS

	if cutoff <= 0 {
		return {}
	}

	candidate: State_Store
	defer state_store_clear(&candidate)

	if error := socket_store_clone(&candidate, socket.store); error.kind != .None {
		return error
	}

	pending, pending_error := socket_prune_pending_ids(&candidate)

	if pending_error.kind != .None {
		return pending_error
	}

	defer delete(pending)
	kept := 0
	changed := false

	for _, index in candidate.records {
		record := &candidate.records[index]
		remove, updated, error := socket_prune_record(
			record,
			pending,
			cast(u64)cutoff,
			cast(u64)now_seconds,
			candidate.allocator,
		)

		if error.kind != .None {
			return error
		}

		changed = changed || remove || updated

		if remove {
			crypto.zero_explicit(raw_data(record.data), len(record.data))
			delete(record.data, candidate.allocator)
			delete(record.name, candidate.allocator)
			record^ = {}
		} else {
			if kept != index {
				candidate.records[kept] = record^
				record^ = {}
			}

			kept += 1
		}
	}

	for index in kept ..< len(candidate.records) {
		candidate.records[index] = {}
	}

	if allocation := resize(&candidate.records, kept); allocation != nil {
		return {kind = .Allocation_Failed, allocation = allocation}
	}

	if changed {
		if candidate.revision == max(u64) {
			return {kind = .State_Failed, state = {kind = .Revision_Exhausted}}
		}

		candidate.revision += 1

		if error := socket_store_commit(socket, &candidate); error.kind != .None {
			return error
		}
	}

	socket.last_prune = now

	return {}
}

// Sender aliases are metadata from the authenticated message envelope, not a
// replacement for ciphertext authentication or the existing identity pins. Stage
// them only in the message candidate so failures cannot persist a routing hint.
// The pinned upstream decoder supplies bare alternates; preserve the primary
// sender device while normalizing the mapping itself to bare PN/LID identities.
socket_message_alias_stage :: proc(
	next, original: ^State_Store,
	node: Binary_Node,
	participant: string,
) -> Socket_Error {
	// No encrypted payload means no authentication gate for a new sender alias.
	children, encrypted_children := node.content.([]Binary_Node)
	if !encrypted_children {
		return {}
	}
	has_encrypted := false
	for child in children {
		if child.tag == "enc" {
			has_encrypted = true
			break
		}
	}
	if !has_encrypted {
		return {}
	}
	primary_user, primary_device, primary_error := pairing_jid_decode(participant)
	if primary_error.kind != .None {
		return {kind = .Protocol_Error}
	}
	primary_lid := strings.has_suffix(participant, "@lid")
	primary_pn := strings.has_suffix(participant, "@s.whatsapp.net") || strings.has_suffix(participant, "@c.us")
	if !primary_lid && !primary_pn {
		return {kind = .Protocol_Error}
	}

	alternate, mode := "", ""
	seen: u8
	for attr in node.attrs {
		bit: u8

		switch attr.key {
		case "participant_pn":
			bit = 1
		case "sender_pn":
			bit = 2
		case "participant_lid":
			bit = 4
		case "sender_lid":
			bit = 8
		case "addressing_mode":
			bit = 16
		case:
			continue
		}

		if seen & bit != 0 {
			return {kind = .Protocol_Error}
		}

		seen |= bit

		if bit == 16 {
			mode = attr.value
			continue
		}

		// Only the opposite-domain sender hint can establish this mapping. Recipient
		// and peer_recipient hints are intentionally outside this sender-only policy.
		if len(attr.value) > 128 || primary_lid && bit & 12 != 0 || primary_pn && bit & 3 != 0 {
			return {kind = .Protocol_Error}
		}

		user, device, error := pairing_jid_decode(attr.value)

		if error.kind != .None || device >= MAX_USER_DEVICES || device != 0 && device != primary_device {
			return {kind = .Protocol_Error}
		}

		alternate_pn := strings.has_suffix(attr.value, "@s.whatsapp.net") || strings.has_suffix(attr.value, "@c.us")

		if primary_lid && !alternate_pn || primary_pn && !strings.has_suffix(attr.value, "@lid") {
			return {kind = .Protocol_Error}
		}

		// Attribute aliases may repeat the same bare user, but must not disagree.
		if alternate != "" && alternate != user {
			return {kind = .Identity_Changed}
		}

		alternate = user
	}
	if alternate == "" {
		return {}
	}
	if seen & 16 != 0 && mode != (primary_lid ? "lid" : "pn") {
		return {kind = .Protocol_Error}
	}
	pn := fmt.aprintf("%s@s.whatsapp.net", primary_lid ? alternate : primary_user)
	lid := fmt.aprintf("%s@lid", primary_lid ? primary_user : alternate)
	defer {
		delete(pn)
		delete(lid)
	}
	if error := socket_lid_mapping_stage(next, pn, lid); error.kind != .None {
		return error
	}
	return socket_lid_migrate(next, original)
}

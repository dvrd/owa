package whatsapp

import "core:crypto"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:strconv"
import "core:sync"
import "core:time"
import "shared:surf"

// Application socket lifecycle.

Socket_Phase :: enum {
	Uninitialized,
	Connecting,
	Pairing,
	Provisioning,
	Online,
	Restart_Required,
	Failed,
	Closed,
}

Socket_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	Websocket_Failed,
	Session_Failed,
	Prekey_Failed,
	State_Failed,
	Binary_Failed,
	Allocation_Failed,
	Query_Timeout,
	Server_Rejected,
	Protocol_Error,
	Identity_Changed,
	Signal_Failed,
	Group_Failed,
	Message_Failed,
	Media_Failed,
	Poll_Failed,
	Queue_Full,
	Device_Failed,
	// Deprecated. Query timeouts use Query_Timeout. Reserved for enum compatibility.
	Deadline_Failed,
	// A tracked outgoing message was rejected; explicit caller retry/cancel only.
	Message_Rejected,
	// Incoming encrypted content is unsupported; no successful receive occurred.
	Unsupported_Message_Encryption,
	Contacts_Syncing,
	Contact_Already_Exists,
	Contact_Unconfirmed,
}

Socket_Error :: struct {
	kind:       Socket_Error_Kind,
	websocket:  surf.WebSocket_Error,
	stream:     surf.WebSocket_Error,
	session:    Session_Error,
	prekey:     Prekey_Error,
	state:      State_Error,
	binary:     Binary_Node_Error,
	allocation: mem.Allocator_Error,
	signal:     Signal_Session_Error,
	group:      Signal_Group_Error,
	message:    Message_Error,
	media:      Media_Error,
	device:     Device_Error,
}

Socket_Config :: struct {
	track_chat_history_cursors:         bool, // Keep the newest private message ID, direction and original time per chat.
	sync_contacts:                      bool, // Refresh the address book after login and server updates in socket_tick.
	host, target, origin:               string,
	port:                               int,
	// The released WebSocket transport supports roots only. Other TLS options return Invalid_Config.
	tls:                                surf.TLS_Config,
	http_execute:                       Media_HTTP_Execute,
	// Nil verifies the signed Noise chain, static-key binding and validity times.
	// An explicit callback replaces that policy. Verified TLS is still required.
	// Applications may reject the Noise certificate before ClientFinish is sent.
	verify_certificate:                 Certificate_Verifier,
	payload:                            Payload_Config,
	qr_write_format_bits:               Pairing_QR_Format,
	auth_path, prekey_path, state_path: string,
	query_timeout:                      time.Duration,
	observe_node:                       Protocol_Node_Observer,
	observer_data:                      rawptr,
	// Reuse HTTPS connections for online media downloads. TLS settings and roots must stay immutable until close.
	pool_media_downloads:               bool,
}

Socket_Event_Kind :: enum {
	None,
	QR,
	Paired,
	Online,
	Restart_Required,
	Node,
	Message,
}

Socket_Event :: struct {
	kind:    Socket_Event_Kind,
	qr:      string,
	node:    Binary_Node,
	message: ^Socket_Message,
}

// The application owns returned messages, including their metadata strings and
// protobuf storage. Parsed text/media/quote slices borrow protobuf until destroy.
Socket_Message :: struct {
	group, participant, id: string,
	recipient:              string, // Direct-chat peer on messages from another linked device.
	protobuf:               []u8,
	from_me:                bool,
	offline:                bool,
	timestamp:              u64,
	allocator:              mem.Allocator,
}

socket_message_destroy :: proc(message: ^Socket_Message) {
	if message == nil {
		return
	}

	a := message.allocator
	delete(message.group, a)
	delete(message.participant, a)
	delete(message.recipient, a)
	delete(message.id, a)
	crypto.zero_explicit(raw_data(message.protobuf), len(message.protobuf))
	delete(message.protobuf, a)
	free(message, a)
}

// All borrowed settings/auth/stores must outlive this stable-address object.
// Only one caller may use it. Nil TLS roots select system trust. Reconnect uses
// a fresh Socket with the SAME Auth_State, Prekey_Store and State_Store.
Socket :: struct {
	media_pool:                  ^Media_HTTP_Pool,
	history_deadline:            time.Time,
	history_request:             ^Pending_Chat_History,
	message_lookup:              ^Pending_Message_Lookup,
	contact_refresh_due:         bool,
	profile_history_pending:     bool,
	profile_history_retry_after: time.Time,
	contact_refresh_after:       time.Time,
	contact_write_key_id:        [128]u8,
	contact_write_key_size:      int,
	contact_key_requested:       [128]u8,
	contact_key_size:            int,
	contact_key_retry_after:     time.Time,
	phase:                       Socket_Phase,
	config:                      Socket_Config,
	auth:                        ^Auth_State,
	prekeys:                     ^Prekey_Store,
	store:                       ^State_Store,
	websocket:                   Message_Connection,
	client:                      Client,
	session:                     Session,
	sequence:                    u64,
	provision_id:                [128]u8,
	provision_id_size:           int,
	provision_deadline:          time.Time,
	provision_stage:             enum {
		None,
		Count,
		Upload,
		Active,
	},
	queue:                       [dynamic]^Socket_Message,
	query_depth:                 int,
	deferred_retries:            [dynamic]Binary_Document,
	pending_media_retry:         [dynamic]Binary_Document,
	last_error:                  Socket_Error,
	last_prune:                  time.Time,
}

socket_connect :: proc(
	socket: ^Socket,
	auth: ^Auth_State,
	prekeys: ^Prekey_Store,
	store: ^State_Store,
	config: Socket_Config,
) -> Socket_Error {
	if validation_error := socket_connect_validate(socket, auth, prekeys, store, config);
	   validation_error.kind != .None {
		return validation_error
	}

	settings, settings_error := socket_connect_settings(config)
	if settings_error.kind != .None {
		return settings_error
	}

	socket.config, socket.auth, socket.prekeys, socket.store = settings, auth, prekeys, store
	socket.phase = .Connecting
	if websocket_error := socket_websocket_dial(socket, settings); websocket_error.kind != .None {
		return websocket_error
	}

	if e := socket_client_init(socket, settings); e.kind != .None {
		return socket_fail(
			socket,
			{kind = .Session_Failed, session = {kind = .Client_Failed, client = e}},
		)
	}

	if e := session_init(
		&socket.session,
		&socket.client,
		auth,
		{
			payload = settings.payload,
			qr_write_format_bits = settings.qr_write_format_bits,
			auth_path = settings.auth_path,
			observe_node = settings.observe_node,
			observer_data = settings.observer_data,
		},
	); e.kind != .None {
		return socket_fail(socket, {kind = .Session_Failed, session = e})
	}

	if e := session_start(&socket.session, time.now()); e.kind != .None {
		return socket_fail(socket, {kind = .Session_Failed, session = e})
	}

	socket.phase = .Pairing
	socket.queue = make([dynamic]^Socket_Message)
	return {}
}

// The initialized transport and caller-owned auth stay pinned through the handshake.
socket_client_init :: proc(socket: ^Socket, settings: Socket_Config) -> Client_Error {
	assert(socket != nil && socket.auth != nil)

	return client_init(
		&socket.client,
		&socket.websocket,
		{static_private_key = socket.auth.credentials.noise_private},
		{verify_certificate = settings.verify_certificate},
	)
}

socket_websocket_settings :: proc(settings: Socket_Config) -> Message_Connection_Config {
	return {
		host = settings.host, port = settings.port, target = settings.target, origin = settings.origin,
		secure = true, tls = settings.tls, max_message_size = MAX_BINARY_NODE_PAYLOAD + 32,
		max_queued_bytes = MAX_BINARY_NODE_PAYLOAD + 32,
		// session_tick sends encrypted WhatsApp keepalives. On this endpoint,
		// transport pings can surface an empty Pong as binary application data.
		ping_interval = surf.WEBSOCKET_PING_OFF,
		frame_timeout = 15 * time.Second, message_timeout = 15 * time.Second,
	}
}

socket_websocket_dial :: proc(socket: ^Socket, settings: Socket_Config) -> Socket_Error {
	err := message_connection_open(&socket.websocket, socket_websocket_settings(settings))

	if err.kind != .None {
		return socket_fail(socket, {kind = .Websocket_Failed, websocket = err})
	}

	return {}
}

socket_connect_validate :: proc(
	socket: ^Socket,
	auth: ^Auth_State,
	prekeys: ^Prekey_Store,
	store: ^State_Store,
	config: Socket_Config,
) -> Socket_Error {
	if socket == nil ||
	   socket.phase != .Uninitialized ||
	   auth == nil ||
	   prekeys == nil ||
	   store == nil {
		return {kind = .Invalid_State}
	}

	if !prekeys.initialized ||
	   !store.initialized ||
	   store.requires_reload ||
	   config.prekey_path == "" ||
	   config.state_path == "" {
		return {kind = .Invalid_Config}
	}

	if e := device_credentials_validate(&auth.credentials); e != .None {
		return {kind = .Invalid_Config}
	}

	identity := signal_curve_public(auth.credentials.identity_private)
	if crypto.compare_constant_time(identity[:], store.identity[:]) != 1 ||
	   crypto.compare_constant_time(identity[:], prekeys.identity_public[:]) != 1 {
		return {kind = .Invalid_Config}
	}

	return {}
}

socket_connect_settings :: proc(config: Socket_Config) -> (Socket_Config, Socket_Error) {
	if config.tls.client_credentials != nil || config.tls.session_cache != nil ||
	   !pairing_qr_format_valid(config.qr_write_format_bits) {
		return {}, {kind = .Invalid_Config}
	}

	settings := config

	if settings.host == "" {
		settings.host = "web.whatsapp.com"
	}

	if settings.port == 0 {
		settings.port = 443
	}

	if settings.target == "" {
		settings.target = "/ws/chat"
	}

	if settings.origin == "" {
		settings.origin = "https://web.whatsapp.com"
	}

	if settings.query_timeout == 0 {
		settings.query_timeout = 30 * time.Second
	}

	if settings.query_timeout < 0 {
		return {}, {kind = .Invalid_Config}
	}

	if settings.payload.version == ([3]u32{}) {
		settings.payload = default_client_payload_config()
	}

	return settings, {}
}

socket_close :: proc(socket: ^Socket) {
	if socket == nil {
		return
	}

	media_http_pool_close(socket.media_pool)
	socket.media_pool = nil

	if socket.session.phase != .Uninitialized {
		session_close(&socket.session)
	} else if socket.websocket.phase != .Uninitialized {
		message_connection_close(&socket.websocket)
	}

	for message in socket.queue {
		socket_message_destroy(message)
	}

	delete(socket.queue)
	for &doc in socket.deferred_retries {
		binary_document_destroy(&doc)
	}

	delete(socket.deferred_retries)
	socket.deferred_retries = nil
	for &doc in socket.pending_media_retry {
		binary_document_destroy(&doc)
	}

	delete(socket.pending_media_retry)
	socket.pending_media_retry = nil
	socket.queue = nil
	socket.provision_stage = .None
	socket.provision_deadline = {}

	socket.phase = .Closed
}

socket_tick :: proc(socket: ^Socket, now: time.Time) -> (Socket_Event, Socket_Error) {
	if socket == nil || socket.phase == .Failed || socket.phase == .Closed {
		return {}, {kind = .Invalid_State}
	}

	// Keepalive traffic proves the connection is alive, not that a specific
	// provisioning IQ completed. A timeout reconnects with persisted keys.
	if socket.provision_stage != .None &&
	   socket.provision_deadline != (time.Time{}) &&
	   now._nsec >= socket.provision_deadline._nsec {
		return {}, socket_fail(socket, {kind = .Query_Timeout})
	}

	event, err := session_tick(&socket.session, now)

	if err.kind != .None {
		return {}, socket_fail(socket, {kind = .Session_Failed, session = err})
	}

	if event.kind == .QR {
		return {kind = .QR, qr = event.qr}, {}
	}

	if socket.phase == .Online &&
	   socket.query_depth == 0 &&
	   (socket.last_prune == (time.Time{}) || time.diff(socket.last_prune, now) > time.Hour) {
		if e := socket_prune_state(socket, now); e.kind != .None {
			return {}, e
		}
	}

	if socket.config.sync_contacts &&
	   socket.contact_refresh_due &&
	   socket.query_depth == 0 &&
	   socket.phase == .Online &&
	   time.diff(socket.contact_refresh_after, now) >= 0 {
		socket.contact_refresh_after = time.time_add(now, time.Minute)
		status, sync_err := socket_sync_contacts(socket)
		if sync_err.kind != .None {
			return {}, sync_err
		}

		socket.contact_refresh_due = status == .Syncing
	}

	if socket.phase == .Online && socket.query_depth == 0 && len(socket.deferred_retries) > 0 {
		doc := socket.deferred_retries[0]
		ordered_remove(&socket.deferred_retries, 0)
		defer binary_document_destroy(&doc)

		if e := socket_retry_outgoing(socket, doc.root); e.kind != .None {
			return {}, e
		}
	}

	if socket.config.sync_contacts &&
	   socket.profile_history_pending &&
	   socket.query_depth == 0 &&
	   socket.phase == .Online &&
	   time.diff(socket.profile_history_retry_after, now) >= 0 {
		if e := socket_import_pending_contact_history(socket); e.kind != .None {
			socket.profile_history_retry_after = time.time_add(now, time.Minute)
			return {}, e
		}
	}

	return {}, {}
}

socket_receive_wire :: proc(socket: ^Socket, deadline: time.Time = {}) -> (Socket_Event, Socket_Error) {
	if socket == nil || socket.phase == .Closed || socket.phase == .Failed {
		return {}, {kind = .Invalid_State}
	}

	previous := socket.websocket.read_deadline
	socket.websocket.read_deadline = socket_limit_deadline(socket, deadline if deadline != {} else time.time_add(time.now(), 15 * time.Second))
	defer socket.websocket.read_deadline = previous

	if deadline != {} || socket.history_deadline != {} {
		ready, frame_err := frame_transport_prepare(&socket.client.frames, socket.websocket.read_deadline)
		if !ready && frame_err.kind == .None {
			return {}, {kind = .Query_Timeout}
		}

		// A terminal frame error is retained by the reader. The normal session
		// read below reports it and performs Noise and socket cleanup.
	}

	return socket_receive_inner(socket)
}

socket_receive_inner :: proc(socket: ^Socket) -> (Socket_Event, Socket_Error) {
	event, err := session_read(&socket.session, time.now())

	if err.kind != .None {
		return {}, socket_fail(socket, {kind = .Session_Failed, session = err})
	}

	#partial switch event.kind {
	case .QR:
		return {kind = .QR, qr = event.qr}, {}


	case .Pairing_Complete:
		return {kind = .Paired}, {}


	case .Restart_Required:
		socket.phase = .Restart_Required
		return {kind = .Restart_Required}, {}


	case .Login_Accepted:
		return socket_login_provision_start(socket, event)
	case .Node:
		if socket.provision_stage != .None {
			id, _ := node_attr(event.node, "id")

			if event.node.tag == "iq" &&
			   id == cast(string)socket.provision_id[:socket.provision_id_size] {
				return socket_provision(socket, event.node)
			}
		}

		process := socket.phase == .Online
		if socket.phase == .Provisioning {
			// The server can send offline_preview before activation
			// finishes. Request its batch immediately.
			switch event.node.tag {
			case "message", "status", "receipt", "call", "notification", "ib":
				process = true
			}
		}

		if process {
			output, e := socket_process_node(socket, event.node)
			if e.kind != .None {
				return output, e
			}

			if control_err := socket_control_node(socket, event.node); control_err.kind != .None {
				return {}, control_err
			}

			return output, {}
		}

		return {kind = .Node, node = event.node}, {}


	case:
		return {}, {}
	}
}

socket_login_provision_start :: proc(
	socket: ^Socket,
	event: Session_Event,
) -> (
	Socket_Event,
	Socket_Error,
) {
	socket.phase = .Provisioning

	if lid, found := node_attr(event.node, "lid"); found && device_user_jid_valid(lid, true) {
		if e := state_store_set(socket.store, .LID_Mapping, "self", transmute([]u8)lid);
		   e.kind != .None {
			return {}, socket_fail(socket, {kind = .State_Failed, state = e})
		}

		if e := state_store_save(socket.store, socket.config.state_path); e.kind != .None {
			return {}, socket_fail(socket, {kind = .State_Failed, state = e})
		}
	}

	id := socket_next_iq_id(socket, socket.provision_id[:])
	socket.provision_id_size = len(id)
	buffer: [1024]u8
	n, e := prekey_count_query_encode(buffer[:], id)

	if e.kind != .None {
		return {}, socket_fail(socket, {kind = .Prekey_Failed, prekey = e})
	}

	socket.provision_stage = .Count

	if e := socket_provision_write(socket, buffer[:n]); e.kind != .None {
		return {}, e
	}

	return {}, {}
}

socket_provision :: proc(socket: ^Socket, node: Binary_Node) -> (Socket_Event, Socket_Error) {
	socket.provision_deadline = {}

	#partial switch socket.provision_stage {
	case .Count:
		return socket_provision_count(socket, node)
	case .Upload:
		return socket_provision_upload(socket, node)
	case .Active:
		return socket_handle_activation_response(socket, node)
	case:
		return {}, socket_fail(socket, {kind = .Protocol_Error})
	}
}

socket_provision_count :: proc(
	socket: ^Socket,
	node: Binary_Node,
) -> (
	Socket_Event,
	Socket_Error,
) {
	buffer: [65536]u8
	count, err := decode_prekey_count_response(
		node,
		cast(string)socket.provision_id[:socket.provision_id_size],
	)

	if err.kind != .None {
		return {}, socket_fail(socket, {kind = .Prekey_Failed, prekey = err})
	}

	if count <= PREKEY_SERVER_MIN_COUNT || socket.prekeys.pending_count > 0 {
		id := socket_next_iq_id(socket, socket.provision_id[:])
		socket.provision_id_size = len(id)
		upload_err :=
			socket.prekeys.pending_count > 0 \
				? prekey_upload_retry(socket.prekeys, id) \
				: prekey_upload_prepare(socket.prekeys, id)

		if upload_err.kind != .None {
			return {}, socket_fail(socket, {kind = .Prekey_Failed, prekey = upload_err})
		}

		if e := prekey_store_save(socket.config.prekey_path, socket.prekeys); e.kind != .None {
			return {}, socket_fail(socket, {kind = .Prekey_Failed, prekey = e})
		}

		n, e := prekey_upload_encode(buffer[:], socket.prekeys, &socket.auth.credentials)

		if e.kind != .None {
			return {}, socket_fail(socket, {kind = .Prekey_Failed, prekey = e})
		}

		socket.provision_stage = .Upload
		return {}, socket_provision_write(socket, buffer[:n])
	}

	if socket.phase == .Online {
		socket.provision_stage = .None
		return {}, {}
	}

	return {}, socket_request_activation(socket)
}

socket_provision_upload :: proc(
	socket: ^Socket,
	node: Binary_Node,
) -> (
	Socket_Event,
	Socket_Error,
) {
	if e := prekey_upload_handle_response(socket.prekeys, node); e.kind != .None {
		return {}, socket_fail(socket, {kind = .Prekey_Failed, prekey = e})
	}

	if e := prekey_store_save(socket.config.prekey_path, socket.prekeys); e.kind != .None {
		return {}, socket_fail(socket, {kind = .Prekey_Failed, prekey = e})
	}

	if e := socket_cleanup_consumed_prekeys(socket); e.kind != .None {
		return {}, socket_fail(socket, e)
	}

	if socket.phase == .Online {
		socket.provision_stage = .None
		return {}, {}
	}

	return {}, socket_request_activation(socket)
}

socket_handle_activation_response :: proc(
	socket: ^Socket,
	node: Binary_Node,
) -> (
	Socket_Event,
	Socket_Error,
) {
	if e := device_response_validate(
		node,
		cast(string)socket.provision_id[:socket.provision_id_size],
	); e.kind != .None {
		return {}, socket_fail(socket, {kind = .Server_Rejected})
	}

	socket.provision_stage = .None
	socket.phase = .Online
	socket.profile_history_pending = socket.config.sync_contacts
	socket.contact_refresh_due = socket.config.sync_contacts

	if e := socket_cleanup_consumed_prekeys(socket); e.kind != .None {
		return {}, socket_fail(socket, e)
	}

	if len(socket.queue) == 0 {
		if e := socket_inbox_restore(socket); e.kind != .None {
			return {}, socket_fail(socket, e)
		}
	}

	presence: [512]u8
	n, e := binary_node_encode(
		presence[:],
		{
			tag = "presence",
			attrs = []Binary_Node_Attribute {
				{"name", cast(string)socket.auth.account.name[:socket.auth.account.name_size]},
				{"type", "available"},
			},
		},
	)

	if e.kind != .None {
		return {}, socket_fail(socket, {kind = .Binary_Failed, binary = e})
	}

	if e := socket_write(socket, presence[:n]); e.kind != .None {
		return {}, e
	}

	if e := socket_replay_outbox(socket); e.kind != .None {
		return {}, e
	}

	return {kind = .Online}, {}
}

socket_request_activation :: proc(socket: ^Socket) -> Socket_Error {
	id := socket_next_iq_id(socket, socket.provision_id[:])
	socket.provision_id_size = len(id)
	buffer: [1024]u8
	n, err := binary_node_encode(
		buffer[:],
		{
			tag = "iq",
			attrs = []Binary_Node_Attribute {
				{"to", "@s.whatsapp.net"},
				{"xmlns", "passive"},
				{"type", "set"},
				{"id", id},
			},
			content = []Binary_Node{{tag = "active"}},
		},
	)

	if err.kind != .None {
		return socket_fail(socket, {kind = .Binary_Failed, binary = err})
	}

	socket.provision_stage = .Active

	return socket_provision_write(socket, buffer[:n])
}

socket_provision_write :: proc(socket: ^Socket, encoded: []u8) -> Socket_Error {
	timeout := socket.config.query_timeout

	if timeout == 0 {
		timeout = 30 * time.Second
	}

	socket.provision_deadline = time.time_add(time.now(), timeout)

	return socket_write(socket, encoded)
}

socket_next_iq_id :: proc(socket: ^Socket, dst: []u8) -> string {
	socket.sequence += 1

	return fmt.bprintf(dst, "odin-%d-%d", time.to_unix_nanoseconds(time.now()), socket.sequence)
}

@(private)
socket_limit_deadline :: proc(socket: ^Socket, deadline: time.Time) -> time.Time {
	if socket.history_deadline != {} && socket.history_deadline._nsec < deadline._nsec {
		return socket.history_deadline
	}

	return deadline
}

socket_write :: proc(socket: ^Socket, encoded: []u8) -> Socket_Error {
	timeout := socket.config.query_timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	previous := socket.websocket.write_deadline
	socket.websocket.write_deadline = socket_limit_deadline(socket, time.time_add(time.now(), timeout))
	defer socket.websocket.write_deadline = previous

	if socket.history_deadline != {} && time.now()._nsec >= socket.history_deadline._nsec {
		return {kind = .Query_Timeout}
	}

	if err := client_write(&socket.client, encoded); err.kind != .None {
		return socket_fail(
			socket,
			{kind = .Session_Failed, session = {kind = .Client_Failed, client = err}},
		)
	}

	return {}
}

socket_fail :: proc(socket: ^Socket, err: Socket_Error) -> Socket_Error {
	socket.last_error = err

	if socket.websocket.phase == .Open {
		socket.websocket.phase = .Failed
	}

	socket_close(socket)
	socket.phase = .Failed

	return err
}

// Queued events retain their owned storage while synchronous IQ queries run.
socket_read :: proc(socket: ^Socket) -> (Socket_Event, Socket_Error) {
	if socket != nil && len(socket.queue) > 0 {
		message := socket.queue[0]
		ordered_remove(&socket.queue, 0)
		return {kind = .Message, message = message}, {}
	}

	return socket_receive_wire(socket)
}

// Existing callers of socket_receive also receive events queued by synchronous queries.
socket_receive :: socket_read

socket_control_node :: proc(socket: ^Socket, node: Binary_Node) -> Socket_Error {
	if node.tag == "ib" {
		if _, found := pairing_node_child(node, "offline_preview"); found {
			buffer: [512]u8
			n, e := binary_node_encode(
				buffer[:],
				{
					tag = "ib",
					content = []Binary_Node {
						{tag = "offline_batch", attrs = []Binary_Node_Attribute{{"count", "100"}}},
					},
				},
			)

			if e.kind != .None {
				return {kind = .Binary_Failed, binary = e}
			}

			return socket_write(socket, buffer[:n])
		}
	}

	if node.tag != "notification" || socket.phase != .Online || socket.provision_stage != .None {
		return {}
	}

	kind, _ := node_attr(node, "type")
	from, _ := node_attr(node, "from")

	if kind != "encrypt" || (from != "@s.whatsapp.net" && from != "s.whatsapp.net") {
		return {}
	}

	count, found := pairing_node_child(node, "count")
	if !found {
		return {}
	}

	value, _ := node_attr(count^, "value")
	n, valid := strconv.parse_uint(value, 10)
	if !valid || n >= PREKEY_SERVER_MIN_COUNT {
		return {}
	}

	id := socket_next_iq_id(socket, socket.provision_id[:])
	socket.provision_id_size = len(id)
	buffer: [1024]u8
	size, e := prekey_count_query_encode(buffer[:], id)

	if e.kind != .None {
		return {kind = .Prekey_Failed, prekey = e}
	}

	socket.provision_stage = .Count

	return socket_provision_write(socket, buffer[:size])
}

// Surf retains a partial WebSocket message across polls so the owner can
// service timers and HTTP completions while waiting for the rest.
socket_poll :: proc(
	socket: ^Socket,
	timeout: time.Duration = 250 * time.Millisecond,
) -> (
	bool,
	Socket_Error,
) {
	if socket == nil {
		return false, {kind = .Invalid_State}
	}

	#partial switch socket.phase {
	case .Uninitialized, .Failed, .Closed, .Restart_Required:
		return false, {kind = .Invalid_State}
	}

	if timeout < 0 || timeout > time.Second {
		return false, {kind = .Invalid_Config}
	}

	if len(socket.queue) > 0 {
		return true, {}
	}

	return socket_network_poll(socket, timeout)
}

socket_network_poll :: proc(socket: ^Socket, timeout: time.Duration) -> (bool, Socket_Error) {
	return socket_network_poll_with_wakeup(socket, timeout, nil)
}

// A wakeup interrupts the wait. Only WebSocket readiness authorizes a wire read.
@(private)
socket_network_poll_with_wakeup :: proc(
	socket: ^Socket,
	timeout: time.Duration,
	wakeup: ^os.File,
) -> (bool, Socket_Error) {
	w := &socket.websocket
	t := &socket.client.frames
	if t.ready || t.ws_at < t.ws_size {
		return true, {}
	}

	if w.poll == nil {
		return w.phase == .Open, {}
	}

	ready, err := w.poll(w.data, timeout, wakeup)
	if err.kind != .None {
		return false, socket_fail(socket, {kind = .Poll_Failed, websocket = err})
	}

	return ready, {}
}

// Optional process-wide observer of socket_query round trips for application
// metrics. It is called once per query that was sent or failed to send, with the
// tick taken before sending and whether a response was received without error.
// Queries refused before sending are not observed. It runs on the socket's thread
// and must not block.
Query_Observer :: #type proc(started: time.Tick, ok: bool)

query_observer: Query_Observer

// Installs the query observer; nil removes it. Install it before sockets connect.
query_observer_set :: proc(observer: Query_Observer) {
	sync.atomic_store(&query_observer, observer)
}

query_observe :: proc(started: time.Tick, ok: bool) {
	observer := sync.atomic_load(&query_observer)

	if observer != nil {
		observer(started, ok)
	}
}

// Owns the returned document. Incoming messages encountered while waiting are
// processed normally and queued for socket_read. No nested receive threads.
socket_query :: proc(socket: ^Socket, query: Binary_Node) -> (Binary_Document, Socket_Error) {
	if socket == nil || socket.phase != .Online {
		return {}, {kind = .Invalid_State}
	}

	if query.tag != "iq" || len(query.attrs) > 16 {
		return {}, {kind = .Invalid_Config}
	}

	socket.query_depth += 1
	defer socket.query_depth -= 1

	attrs: [17]Binary_Node_Attribute
	copy(attrs[:], query.attrs)
	count := len(query.attrs)
	buffer_id: [128]u8
	id, has_id := node_attr(query, "id")

	if has_id {
		if !stanza_id_valid(id) {
			return {}, {kind = .Invalid_Config}
		}

		copy(buffer_id[:], transmute([]u8)id)
		id = cast(string)buffer_id[:len(id)]
	} else {
		id = socket_next_iq_id(socket, buffer_id[:])
		attrs[count] = {"id", id}

		count += 1
	}

	request := query
	request.attrs = attrs[:count]
	started := time.tick_now()

	if send_error := socket_query_send(socket, request); send_error.kind != .None {
		query_observe(started, false)
		return {}, send_error
	}

	document, error := socket_query_response_receive(socket, id)
	query_observe(started, error.kind == .None)

	return document, error
}

socket_query_send :: proc(socket: ^Socket, request: Binary_Node) -> Socket_Error {
	n, measured := binary_node_encode(nil, request)

	if measured.kind != .Destination_Undersized {
		return {kind = .Binary_Failed, binary = measured}
	}

	encoded, alloc_err := make([]u8, n)

	if alloc_err != nil {
		return {kind = .Allocation_Failed, allocation = alloc_err}
	}
	defer delete(encoded)

	_, encode_err := binary_node_encode(encoded, request)

	if encode_err.kind != .None {
		return {kind = .Binary_Failed, binary = encode_err}
	}

	if err := socket_write(socket, encoded); err.kind != .None {
		return err
	}

	return {}
}

socket_query_message_enqueue :: proc(socket: ^Socket, event: Socket_Event) -> Socket_Error {
	if len(socket.queue) >= 1024 {
		socket_message_destroy(event.message)
		return socket_fail(socket, {kind = .Queue_Full})
	}

	if _, allocation_err := append(&socket.queue, event.message); allocation_err != nil {
		socket_message_destroy(event.message)
		return socket_fail(socket, {kind = .Allocation_Failed, allocation = allocation_err})
	}

	return {}
}

socket_query_response_copy :: proc(node: Binary_Node) -> (Binary_Document, Socket_Error) {
	size, response_measure := binary_node_encode(nil, node)

	if response_measure.kind != .Destination_Undersized {
		return {}, {kind = .Binary_Failed, binary = response_measure}
	}

	storage, allocation_err := make([]u8, size)

	if allocation_err != nil {
		return {}, {kind = .Allocation_Failed, allocation = allocation_err}
	}
	defer delete(storage)

	_, e := binary_node_encode(storage, node)

	if e.kind != .None {
		return {}, {kind = .Binary_Failed, binary = e}
	}

	document, decoded := binary_node_decode(storage)

	if decoded.kind != .None {
		return {}, {kind = .Binary_Failed, binary = decoded}
	}

	return document, {}
}

socket_query_response_receive :: proc(
	socket: ^Socket,
	id: string,
) -> (
	Binary_Document,
	Socket_Error,
) {
	deadline := socket_limit_deadline(socket, time.time_add(time.now(), socket.config.query_timeout))

	for {
		event, e := socket_receive_while_waiting(socket, deadline)
		if e.kind == .Query_Timeout && socket.phase != .Failed && deadline != socket.history_deadline {
			return {}, socket_fail(socket, e)
		}

		if e.kind != .None {
			return {}, e
		}

		if event.kind != .Node || event.node.tag != "iq" {
			continue
		}

		response_id, _ := node_attr(event.node, "id")
		if response_id != id {
			continue
		}

		return socket_query_response_copy(event.node)
	}
}

// Read one frame during a synchronous operation. Preserve unrelated live messages for socket_read.
socket_receive_while_waiting :: proc(
	socket: ^Socket,
	deadline: time.Time,
) -> (
	Socket_Event,
	Socket_Error,
) {
	if time.now()._nsec >= deadline._nsec {
		return {}, {kind = .Query_Timeout}
	}

	if _, err := socket_tick(socket, time.now()); err.kind != .None {
		return {}, err
	}

	ready, poll_err := socket_network_poll(socket, clamp(time.diff(time.now(), deadline), time.Duration(0), 100 * time.Millisecond))
	if poll_err.kind != .None {
		return {}, poll_err
	}

	if !ready {
		return {}, {}
	}

	event, err := socket_receive_wire(socket, deadline)
	if err.kind != .None {
		return {}, err
	}

	if event.kind == .Message {
		if enqueue_error := socket_query_message_enqueue(socket, event);
		   enqueue_error.kind != .None {
			return {}, enqueue_error
		}

		return {}, {}
	}

	if event.kind == .Restart_Required {
		return {}, {kind = .Invalid_State}
	}

	return event, {}
}

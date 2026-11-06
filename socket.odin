package whatsapp

import tls "core:crypto/tls"
import network_client "../client"
import "core:crypto"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:strconv"
import "core:time"
import "core:sys/posix"

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
	Deadline_Failed,
}
Socket_Error :: struct {
	kind:       Socket_Error_Kind,
	websocket:  network_client.WebSocket_Dial_Error,
	stream:     network_client.WebSocket_Stream_Error,
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
	host, target, origin:               string,
	port:                               int,
	tls:                                tls.Config,
	http_execute:                       Media_HTTP_Execute,
	payload:                            Payload_Config,
	auth_path, prekey_path, state_path: string,
	query_timeout:                      time.Duration,
	observe_node:                       Protocol_Node_Observer,
	observer_data:                      rawptr,
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
	protobuf:               []u8,
	from_me:                bool,
	offline:                bool,
	timestamp:              u64,
	allocator:              mem.Allocator,
}
socket_message_destroy :: proc(message: ^Socket_Message) {
	if message == nil do return

	a := message.allocator
	delete(message.group, a); delete(message.participant, a)
	delete(message.id, a)
	crypto.zero_explicit(
		raw_data(message.protobuf),
		len(message.protobuf),
	)
	delete(message.protobuf, a)
	free(message, a)
}

// All borrowed settings/auth/stores must outlive this stable-address object.
// Only one caller may use it. Config requires trusted CA roots. Reconnect uses
// a fresh Socket with the SAME Auth_State, Prekey_Store and State_Store.
Socket :: struct {
	phase:                Socket_Phase,
	config:               Socket_Config,
	auth:                 ^Auth_State,
	prekeys:              ^Prekey_Store,
	store:                ^State_Store,
	websocket:            network_client.WebSocket_Conn,
	client:               Client,
	session:              Session,
	sequence:             u64,
	provision_id:         [128]u8,
	provision_id_size:    int,
	provision_deadline:   time.Time,
	provision_stage:      enum {
		None,
		Count,
		Upload,
		Active,
	},
	queue:                [dynamic]^Socket_Message,
	query_depth:          int,
	read_deadline_scopes: int,
	deferred_retries:     [dynamic]Binary_Document,
	pending_media_retry:  [dynamic]Binary_Document,
	last_error:           Socket_Error,
	last_prune:           time.Time,
}

socket_connect :: proc(
	socket: ^Socket,
	auth: ^Auth_State,
	prekeys: ^Prekey_Store,
	store: ^State_Store,
	config: Socket_Config,
) -> Socket_Error {
	if validation_error := socket_connect_validate(socket, auth, prekeys, store, config);
	   validation_error.kind != .None do return validation_error
	settings, settings_error := socket_connect_settings(config)
	if settings_error.kind != .None do return settings_error

	socket.config, socket.auth, socket.prekeys, socket.store =
		settings, auth, prekeys, store
	socket.phase = .Connecting
	if websocket_error := socket_websocket_dial(socket, settings);
	   websocket_error.kind != .None do return websocket_error

	if e := client_init(
		&socket.client,
		&socket.websocket,
		{static_private_key = auth.credentials.noise_private},
	); e.kind != .None {
		return socket_fail(
			socket,
			{
				kind = .Session_Failed,
				session = {kind = .Client_Failed, client = e},
			},
		)
	}

	if e := session_init(
		&socket.session,
		&socket.client,
		auth,
		{
			payload = settings.payload,
			auth_path = settings.auth_path,
			observe_node = settings.observe_node,
			observer_data = settings.observer_data,
		},
	); e.kind != .None {
		return socket_fail(
			socket,
			{kind = .Session_Failed, session = e},
		)
	}

	if e := session_start(&socket.session, time.now());
	   e.kind != .None {
		return socket_fail(
			socket,
			{kind = .Session_Failed, session = e},
		)
	}

	socket.phase = .Pairing
	socket.queue = make([dynamic]^Socket_Message)
	return {}
}

socket_websocket_dial :: proc(socket: ^Socket, settings: Socket_Config) -> Socket_Error {
	err := network_client.websocket_dial(
		&socket.websocket,
		settings.host,
		settings.port,
		{
			host = settings.host,
			target = settings.target,
			origin = settings.origin,
			max_message_size = MAX_BINARY_NODE_PAYLOAD + 32,
		},
		settings.tls,
	)
	if err.kind != .None {
		return socket_fail(
			socket,
			{kind = .Websocket_Failed, websocket = err},
		)
	}

	return {}
}

socket_connect_validate :: proc(
	socket: ^Socket, auth: ^Auth_State, prekeys: ^Prekey_Store,
	store: ^State_Store, config: Socket_Config,
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
	   config.prekey_path == "" ||
	   config.state_path == "" {
		return {kind = .Invalid_Config}
	}

	if e := device_credentials_validate(&auth.credentials);
	   e != .None {
		return {kind = .Invalid_Config}
	}

	identity := signal_curve_public(
		auth.credentials.identity_private,
	)
	if crypto.compare_constant_time(
		   identity[:],
		   store.identity[:],
	   ) !=
		   1 ||
	   crypto.compare_constant_time(
		   identity[:],
		   prekeys.identity_public[:],
	   ) !=
		   1 {
		return {kind = .Invalid_Config}
	}

	return {}
}

socket_connect_settings :: proc(config: Socket_Config) -> (Socket_Config, Socket_Error) {
	settings := config
	if settings.host == "" {
		settings.host = "web.whatsapp.com"
	}

	if settings.port == 0 do settings.port = 443

	if settings.target == "" do settings.target = "/ws/chat"

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
		settings.payload = default_payload_config()
	}

	if len(settings.tls.root_cas) == 0 {
		return {}, {kind = .Invalid_Config}
	}

	return settings, {}
}

socket_close :: proc(socket: ^Socket) {
	if socket == nil do return

	if socket.websocket.phase == .Open &&
	   socket.websocket.stream.set_write_deadline != nil {
		if e := network_client.websocket_set_write_deadline(
			&socket.websocket,
			time.time_add(time.now(), time.Second),
		); e.kind != .None {
			socket.websocket.phase = .Failed
		}

	}

	if socket.session.phase != .Uninitialized {
		session_close(&socket.session)
	} else if socket.websocket.phase != .Uninitialized {
		network_client.websocket_close(&socket.websocket)
	}

	for message in socket.queue do socket_message_destroy(message)
	delete(socket.queue)
	for &doc in socket.deferred_retries do binary_document_destroy(&doc)
	delete(socket.deferred_retries)
	socket.deferred_retries = nil
	for &doc in socket.pending_media_retry do binary_document_destroy(&doc)
	delete(socket.pending_media_retry)
	socket.pending_media_retry = nil
	socket.queue = nil
	socket.provision_stage = .None
	socket.provision_deadline = {}
	socket.phase = .Closed
}

socket_tick :: proc(
	socket: ^Socket,
	now: time.Time,
) -> (
	Socket_Event,
	Socket_Error,
) {
	if socket == nil ||
	   slice.contains(
		   []type_of(socket.phase){.Failed, .Closed},
		   socket.phase,
	   ) {
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
		return {}, socket_fail(
			socket,
			{kind = .Session_Failed, session = err},
		)
	}

	if event.kind == .QR {
		return {kind = .QR, qr = event.qr}, {}
	}

	if socket.phase == .Online &&
	   socket.query_depth == 0 &&
	   (socket.last_prune == (time.Time{}) ||
			   time.diff(socket.last_prune, now) > time.Hour) {
		if e := socket_prune_state(socket, now); e.kind != .None {
			return {}, e
		}

	}

	if socket.phase == .Online &&
	   socket.query_depth == 0 &&
	   len(socket.deferred_retries) > 0 {
		doc := socket.deferred_retries[0]
		ordered_remove(&socket.deferred_retries, 0)
		defer binary_document_destroy(&doc)
		if e := socket_retry_outgoing(socket, doc.root);
		   e.kind != .None {
			return {}, e
		}

	}

	return {}, {}
}

socket_receive :: proc(
	socket: ^Socket,
) -> (
	Socket_Event,
	Socket_Error,
) {
	if socket == nil ||
	   slice.contains(
		   []type_of(socket.phase){.Closed, .Failed},
		   socket.phase,
	   ) {
		return {}, {kind = .Invalid_State}
	}

	scoped :=
		socket.websocket.stream.set_read_deadline != nil &&
		socket.read_deadline_scopes == 0
	if scoped {
		if e := socket_read_deadline(
			socket,
			time.time_add(time.now(), 15 * time.Second),
		); e.kind != .None {
			return {}, e
		}

	}

	output, failure := socket_receive_inner(socket)
	if scoped && socket.websocket.phase == .Open {
		if e := socket_read_deadline(socket, {}); e.kind != .None {
			if output.message != nil {
				socket_message_destroy(output.message)
			}

			return {}, e
		}

	}

	return output, failure
}
socket_receive_inner :: proc(
	socket: ^Socket,
) -> (
	Socket_Event,
	Socket_Error,
) {
	event, err := session_read(&socket.session, time.now())
	if err.kind != .None {
		return {}, socket_fail(
			socket,
			{kind = .Session_Failed, session = err},
		)
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
			id, _ := pairing_node_attr(event.node, "id")
			if event.node.tag == "iq" &&
			   id ==
				   cast(string)socket.provision_id[:socket.provision_id_size] {
				return socket_provision(socket, event.node)
			}

		}

		if socket.phase == .Online ||
		   socket.phase == .Provisioning &&
			   (slice.contains(
						   // The server can send offline_preview before activation
						   // finishes. Request its batch immediately, as Baileys does.
						   []string{"message", "notification", "ib"},
						   event.node.tag,
					   )) {
			output, e := socket_process_node(socket, event.node)
			if e.kind != .None do return output, e

			if control_err := socket_control_node(socket, event.node);
			   control_err.kind != .None {
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
	socket: ^Socket, event: Session_Event,
) -> (Socket_Event, Socket_Error) {
	socket.phase = .Provisioning
	if lid, found := pairing_node_attr(event.node, "lid");
	   found && device_user_valid(lid, true) {
		if e := state_store_set(
			socket.store,
			.LID_Mapping,
			"self",
			transmute([]u8)lid,
		); e.kind != .None {
			return {}, socket_fail(
				socket,
				{kind = .State_Failed, state = e},
			)
		}

		if e := state_store_save(
			socket.store,
			socket.config.state_path,
		); e.kind != .None {
			return {}, socket_fail(
				socket,
				{kind = .State_Failed, state = e},
			)
		}

	}

	id := socket_next_id(socket, socket.provision_id[:])
	socket.provision_id_size = len(id)
	buffer: [1024]u8
	n, e := prekey_count_query_encode(buffer[:], id)
	if e.kind != .None {
		return {}, socket_fail(
			socket,
			{kind = .Prekey_Failed, prekey = e},
		)
	}

	socket.provision_stage = .Count
	if e := socket_provision_write(socket, buffer[:n]);
	   e.kind != .None {
		return {}, e
	}

	return {}, {}
}

socket_provision :: proc(
	socket: ^Socket,
	node: Binary_Node,
) -> (
	Socket_Event,
	Socket_Error,
) {
	socket.provision_deadline = {}
	#partial switch socket.provision_stage {
	case .Count:
		return socket_provision_count(socket, node)
	case .Upload:
		return socket_provision_upload(socket, node)
	case .Active:
		return socket_provision_active(socket, node)
	case:
		return {}, socket_fail(socket, {kind = .Protocol_Error})
	}
}

socket_provision_count :: proc(socket: ^Socket, node: Binary_Node) -> (Socket_Event, Socket_Error) {
	buffer: [65536]u8
	count, err := prekey_count_response(
		node,
		cast(string)socket.provision_id[:socket.provision_id_size],
	)
	if err.kind != .None {
		return {}, socket_fail(
			socket,
			{kind = .Prekey_Failed, prekey = err},
		)
	}

	if count <= PREKEY_SERVER_MIN_COUNT ||
	   socket.prekeys.pending_count > 0 {
		id := socket_next_id(socket, socket.provision_id[:])
		socket.provision_id_size = len(id)
		upload_err :=
			socket.prekeys.pending_count > 0 \
				? prekey_upload_retry(socket.prekeys, id) \
				: prekey_upload_prepare(socket.prekeys, id)
		if upload_err.kind != .None {
			return {}, socket_fail(
				socket,
				{kind = .Prekey_Failed, prekey = upload_err},
			)
		}

		if e := prekey_store_save(
			socket.config.prekey_path,
			socket.prekeys,
		); e.kind != .None {
			return {}, socket_fail(
				socket,
				{kind = .Prekey_Failed, prekey = e},
			)
		}

		n, e := prekey_upload_encode(
			buffer[:],
			socket.prekeys,
			&socket.auth.credentials,
		)
		if e.kind != .None {
			return {}, socket_fail(
				socket,
				{kind = .Prekey_Failed, prekey = e},
			)
		}

		socket.provision_stage = .Upload
		return {}, socket_provision_write(socket, buffer[:n])
	}

	if socket.phase == .Online {
		socket.provision_stage = .None; return {}, {}
	}

	return {}, socket_activate(socket)
}

socket_provision_upload :: proc(
	socket: ^Socket, node: Binary_Node,
) -> (Socket_Event, Socket_Error) {
	if e := prekey_upload_handle_response(socket.prekeys, node);
	   e.kind != .None {
		return {}, socket_fail(
			socket,
			{kind = .Prekey_Failed, prekey = e},
		)
	}

	if e := prekey_store_save(
		socket.config.prekey_path,
		socket.prekeys,
	); e.kind != .None {
		return {}, socket_fail(
			socket,
			{kind = .Prekey_Failed, prekey = e},
		)
	}

	if e := socket_cleanup_consumed_prekeys(socket);
	   e.kind != .None {
		return {}, socket_fail(socket, e)
	}

	if socket.phase == .Online {
		socket.provision_stage = .None; return {}, {}
	}

	return {}, socket_activate(socket)
}

socket_provision_active :: proc(
	socket: ^Socket, node: Binary_Node,
) -> (Socket_Event, Socket_Error) {
	if e := device_response_validate(
		node,
		cast(string)socket.provision_id[:socket.provision_id_size],
	); e.kind != .None {
		return {}, socket_fail(socket, {kind = .Server_Rejected})
	}

	socket.provision_stage = .None
	socket.phase = .Online
	if e := socket_cleanup_consumed_prekeys(socket);
	   e.kind != .None {
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
				{
					"name",
					cast(string)socket.auth.account.name[:socket.auth.account.name_size],
				},
				{"type", "available"},
			},
		},
	)
	if e.kind != .None {
		return {}, socket_fail(
			socket,
			{kind = .Binary_Failed, binary = e},
		)
	}

	if e := socket_write(socket, presence[:n]); e.kind != .None {
		return {}, e
	}

	if e := socket_replay_outbox(socket); e.kind != .None {
		return {}, e
	}

	return {kind = .Online}, {}
}

socket_activate :: proc(socket: ^Socket) -> Socket_Error {
	id := socket_next_id(socket, socket.provision_id[:])
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
		return socket_fail(
			socket,
			{kind = .Binary_Failed, binary = err},
		)
	}

	socket.provision_stage = .Active
	return socket_provision_write(socket, buffer[:n])
}

socket_provision_write :: proc(
	socket: ^Socket,
	encoded: []u8,
) -> Socket_Error {
	timeout := socket.config.query_timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	socket.provision_deadline = time.time_add(time.now(), timeout)
	return socket_write(socket, encoded)
}
socket_next_id :: proc(socket: ^Socket, dst: []u8) -> string {
	socket.sequence += 1
	return fmt.bprintf(
		dst,
		"odin-%d-%d",
		time.now()._nsec,
		socket.sequence,
	)
}
socket_write :: proc(
	socket: ^Socket,
	encoded: []u8,
) -> Socket_Error {
	deadline_set := false
	if socket.websocket.stream.set_write_deadline != nil {
		timeout := socket.config.query_timeout
		if timeout == 0 do timeout = 30 * time.Second

		if e := socket_write_deadline(
			socket,
			time.time_add(time.now(), timeout),
		); e.kind != .None {
			return e
		}

		deadline_set = true
	}

	if err := client_write(&socket.client, encoded);
	   err.kind != .None {
		return socket_fail(
			socket,
			{
				kind = .Session_Failed,
				session = {kind = .Client_Failed, client = err},
			},
		)
	}

	if deadline_set {
		if e := socket_write_deadline(socket, {}); e.kind != .None {
			return e
		}

	}

	return {}
}
socket_fail :: proc(
	socket: ^Socket,
	err: Socket_Error,
) -> Socket_Error {
	socket.last_error = err
	if socket.websocket.phase == .Open {
		socket.websocket.phase = .Failed
	}

	socket_close(socket)
	socket.phase = .Failed
	return err
}

// Queued events retain their owned storage while synchronous IQ queries run.
socket_read :: proc(
	socket: ^Socket,
) -> (
	Socket_Event,
	Socket_Error,
) {
	if socket != nil && len(socket.queue) > 0 {
		message := socket.queue[0]
		ordered_remove(&socket.queue, 0)
		return {kind = .Message, message = message}, {}
	}

	return socket_receive(socket)
}

socket_control_node :: proc(
	socket: ^Socket,
	node: Binary_Node,
) -> Socket_Error {
	if node.tag == "ib" {
		if _, found := pairing_node_child(node, "offline_preview");
		   found {
			buffer: [512]u8
			n, e := binary_node_encode(
				buffer[:],
				{
					tag = "ib",
					content = []Binary_Node {
						{
							tag = "offline_batch",
							attrs = []Binary_Node_Attribute {
								{"count", "100"},
							},
						},
					},
				},
			)
			if e.kind != .None {
				return {kind = .Binary_Failed, binary = e}
			}

			return socket_write(socket, buffer[:n])
		}

	}

	if node.tag != "notification" ||
	   socket.phase != .Online ||
	   socket.provision_stage != .None {
		return {}
	}

	kind, _ := pairing_node_attr(node, "type")
	from, _ := pairing_node_attr(node, "from")
	if kind != "encrypt" ||
	   !slice.contains(
			   []string{"@s.whatsapp.net", "s.whatsapp.net"},
			   from,
		   ) {
		return {}
	}

	count, found := pairing_node_child(node, "count")
	if !found do return {}

	value, _ := pairing_node_attr(count^, "value")
	n, valid := strconv.parse_uint(value, 10)
	if !valid || n >= PREKEY_SERVER_MIN_COUNT do return {}

	id := socket_next_id(socket, socket.provision_id[:])
	socket.provision_id_size = len(id)
	buffer: [1024]u8
	size, e := prekey_count_query_encode(buffer[:], id)
	if e.kind != .None {
		return {kind = .Prekey_Failed, prekey = e}
	}

	socket.provision_stage = .Count
	return socket_provision_write(socket, buffer[:size])
}

// Synchronous queries and group metadata access.

// Polls the native connection without consuming an incomplete TLS/WS record.
// This keeps timers on the same thread as I/O. Once a peer starts a frame, the
// bounded read deadline prevents a partial frame from stalling indefinitely.
socket_poll :: proc(
	socket: ^Socket,
	timeout: time.Duration = 250 * time.Millisecond,
) -> (
	bool,
	Socket_Error,
) {
	if socket == nil ||
	   slice.contains(
		   []type_of(socket.phase) {
			   .Uninitialized,
			   .Failed,
			   .Closed,
			   .Restart_Required,
		   },
		   socket.phase,
	   ) {
		return false, {kind = .Invalid_State}
	}

	if timeout < 0 || timeout > time.Second {
		return false, {kind = .Invalid_Config}
	}

	if len(socket.queue) > 0 do return true, {}

	return socket_network_poll(socket, timeout)
}

socket_network_poll :: proc(
	socket: ^Socket,
	timeout: time.Duration,
) -> (
	bool,
	Socket_Error,
) {
	w := &socket.websocket
	t := &socket.client.frames
	if t.ready ||
	   t.ws_at < t.ws_size ||
	   w.message_ready ||
	   w.prefetched_at < w.prefetched_size ||
	   w.tls_client.application.inbound_at <
		   w.tls_client.application.inbound_size {
		return true, {}
	}

	when (ODIN_OS in bit_set[type_of(ODIN_OS)]{.Darwin, .Linux}) {
		fd := posix.pollfd {
			fd     = cast(posix.FD)w.tls_client.tcp.socket,
			events = {.IN},
		}
		result := posix.poll(
			&fd,
			1,
			cast(i32)(timeout / time.Millisecond),
		)
		if result < 0 {
			return false, socket_fail(socket, {kind = .Poll_Failed})
		}

		return result > 0, {}
	} else {
		return false, {kind = .Poll_Failed}
	}
}

// Owns the returned document. Incoming messages encountered while waiting are
// processed normally and queued for socket_read. No nested receive threads.
socket_query :: proc(
	socket: ^Socket,
	query: Binary_Node,
) -> (
	Binary_Document,
	Socket_Error,
) {
	if socket == nil || socket.phase != .Online {
		return {}, {kind = .Invalid_State}
	}

	if query.tag != "iq" || len(query.attrs) > 16 {
		return {}, {kind = .Invalid_Config}
	}

	socket.query_depth += 1
	socket.read_deadline_scopes += 1
	defer {socket.query_depth -= 1; socket.read_deadline_scopes -= 1}
	attrs: [17]Binary_Node_Attribute
	copy(attrs[:], query.attrs)
	count := len(query.attrs)
	buffer_id: [128]u8
	id, has_id := pairing_node_attr(query, "id")
	if has_id {
		if !device_request_valid(id) {
			return {}, {kind = .Invalid_Config}
		}

		copy(buffer_id[:], transmute([]u8)id)
		id = cast(string)buffer_id[:len(id)]
	} else {
		id = socket_next_id(socket, buffer_id[:])
		attrs[count] = {"id", id}
		count += 1
	}

	request := query
	request.attrs = attrs[:count]
	if send_error := socket_query_send(socket, request);
	   send_error.kind != .None do return {}, send_error
	return socket_query_response_receive(socket, id)
}

socket_query_send :: proc(socket: ^Socket, request: Binary_Node) -> Socket_Error {
	n, measured := binary_node_encode(nil, request)
	if measured.kind != .Destination_Undersized {
		return {kind = .Binary_Failed, binary = measured}
	}

	encoded, alloc_err := make([]u8, n)
	if alloc_err != nil {
		return {
			kind = .Allocation_Failed,
			allocation = alloc_err,
		}
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

	if _, allocation_err := append(
		&socket.queue,
		event.message,
	); allocation_err != nil {
		socket_message_destroy(event.message)
		return socket_fail(
			socket,
			{
				kind = .Allocation_Failed,
				allocation = allocation_err,
			},
		)
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
		return {}, {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
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
	socket: ^Socket, id: string,
) -> (Binary_Document, Socket_Error) {
	deadline := time.time_add(
		time.now(),
		socket.config.query_timeout,
	)
	for {
		if time.now()._nsec >= deadline._nsec {
			return {}, socket_fail(socket, {kind = .Query_Timeout})
		}

		if _, err := socket_tick(socket, time.now());
		   err.kind != .None {
			return {}, err
		}

		ready, poll_err := socket_network_poll(
			socket,
			100 * time.Millisecond,
		)
		if poll_err.kind != .None do return {}, poll_err

		if !ready do continue

		if e := socket_read_deadline(socket, deadline);
		   e.kind != .None {
			return {}, e
		}

		event, err := socket_receive(socket)
		if err.kind != .None do return {}, err

		if e := socket_read_deadline(socket, {}); e.kind != .None {
			if event.message != nil {
				socket_message_destroy(event.message)
			}

			return {}, e
		}

		if event.kind == .Message {
			if enqueue_error := socket_query_message_enqueue(socket, event);
			   enqueue_error.kind != .None do return {}, enqueue_error
		}

		if event.kind == .Restart_Required {
			return {}, {kind = .Invalid_State}
		}

		if event.kind != .Node || event.node.tag != "iq" {
			continue
		}

		response_id, _ := pairing_node_attr(event.node, "id")
		if response_id != id do continue

		return socket_query_response_copy(event.node)
	}
}

socket_read_deadline :: proc(
	socket: ^Socket,
	deadline: time.Time,
) -> Socket_Error {
	if deadline == (time.Time{}) &&
	   (slice.contains(
				   []type_of(socket.websocket.phase) {
					   .Closed,
					   .Failed,
				   },
				   socket.websocket.phase,
			   )) {
		return {}
	}

	if socket.websocket.stream.set_read_deadline == nil {
		return {}
	}

	if e := socket.websocket.stream.set_read_deadline(
		socket.websocket.stream.data,
		deadline,
	); e.kind != .None {
		return socket_fail(
			socket,
			{kind = .Deadline_Failed, stream = e},
		)
	}

	return {}
}
socket_write_deadline :: proc(
	socket: ^Socket,
	deadline: time.Time,
) -> Socket_Error {
	if socket.websocket.stream.set_write_deadline == nil {
		return {}
	}

	if e := socket.websocket.stream.set_write_deadline(
		socket.websocket.stream.data,
		deadline,
	); e.kind != .None {
		return socket_fail(
			socket,
			{kind = .Deadline_Failed, stream = e},
		)
	}

	return {}
}

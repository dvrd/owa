package whatsapp

import http "shared:http"
import "core:crypto"
import "core:crypto/hmac"
import "core:encoding/base64"
import "core:fmt"
import "core:mem"
import "core:strconv"
import "core:strings"
import "core:time"
import "core:unicode/utf8"
import network_client "shared:surf"

// Registration, pairing and session establishment.

Session_Phase :: enum {
	Uninitialized,
	Initialized,
	Awaiting_Pairing,
	Authenticating,
	Paired,
	Restart_Required,
	Login_Accepted,
	Failed,
	Closed,
}

Session_Event_Kind :: enum {
	None,
	QR,
	Pairing_Complete,
	Restart_Required,
	Login_Accepted,
	Node,
}

Session_Event :: struct {
	kind:    Session_Event_Kind,
	qr:      string, // Borrows Session.qr until the next tick/event/close.
	node:    Binary_Node, // Borrows Session.document until the next process/read.
	account: ^Paired_Account, // Borrows the caller-owned Auth_State.
}

// Fixed diagnostic classification only; no routing or retry policy depends on it.
Protocol_Ack_Class :: enum u8 {
	Unknown,
	Message,
	Receipt,
	Notification,
	Status,
	Call,
	Other,
}

// Diagnostic metadata only; slices borrow the current document/callback frame.
// No stanza IDs, addresses, QR references or content bytes are exposed here.
Protocol_Node_Info :: struct {
	tag, kind: string,
	children:  []string,
	ack_class: Protocol_Ack_Class,
}
Protocol_Node_Observer :: #type proc(data: rawptr, info: Protocol_Node_Info)

// Application-level pairing progress. The library does not raise these events
// itself; applications translate Session state into them and share one callback type.
Pairing_Event_Kind :: enum {
	Connecting,
	QR,
	Paired,
	Online,
	Disconnected,
	Failed,
}

Pairing_Event :: struct {
	kind:       Pairing_Event_Kind,
	qr:         string,
	expires_at: time.Time,
}

Pairing_Observer :: #type proc(data: rawptr, event: Pairing_Event)

// Legacy keeps the historical four-field QR. Linked_Device opts in to the
// current URL and companion web-client field; login payloads are unchanged.
Pairing_QR_Format :: enum {
	Legacy,
	Linked_Device,
}

Session_Config :: struct {
	payload:            Payload_Config,
	qr_write_format_bits:          Pairing_QR_Format,
	// Empty leaves persistence to the caller; otherwise checkpoint before
	// starting registration and before acknowledging successful pairing.
	auth_path:          string,
	keepalive_interval: time.Duration, // Zero defaults to 30 seconds.
	observe_node:       Protocol_Node_Observer,
	observer_data:      rawptr,
}

Session_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	Invalid_Account,
	Authentication_State_Failed,
	Payload_Failed,
	Client_Failed,
	Binary_Node_Failed,
	Pairing_Failed,
	Server_Failure,
	Connection_Lost,
	QR_Expired,
	Allocation_Failed,
}

Session_Error :: struct {
	kind:        Session_Error_Kind,
	auth:        Auth_Store_Error,
	payload:     Payload_Error,
	client:      Client_Error,
	binary:      Binary_Node_Error,
	pairing:     Pairing_Error,
	server_code: u32,
	allocation:  mem.Allocator_Error,
}

// Serialized, caller-driven session. Client must have been initialized with
// auth.credentials.noise_private. Auth_State remains owned by the application.
// Login_Accepted precedes prekey upload/app-state sync/message provisioning.
Session :: struct {
	client:                   ^Client,
	auth:                     ^Auth_State,
	config:                   Session_Config,
	phase:                    Session_Phase,
	qr_state:                 Pairing_QR_State,
	qr:                       [MAX_PAIRING_QR_SIZE]u8,
	document:                 Binary_Document,
	last_received, next_ping: time.Time,
	ping_sequence:            u64,
	last_error:               Session_Error,
}

// The compiled version is the last-resort fallback of web_version_discover: the
// client_revision published by web.whatsapp.com/sw.js on 2026-11-17, not a claim
// of the current service version. The default browser identity sets
// DeviceProps.os to "Mac OS" and the platform to CHROME.
// Applications may use official discovery or supply an explicit version.
WA_WEB_VERSION_PINNED :: [3]u32{2, 3000, 1054981628}
WA_WEB_BROWSER_OS :: "Mac OS"
WA_WEB_BROWSER_NAME :: "Chrome"

default_client_payload_config :: proc() -> Payload_Config {
	return {
		version = WA_WEB_VERSION_PINNED,
		browser_os = WA_WEB_BROWSER_OS,
		browser_name = WA_WEB_BROWSER_NAME,
		country_code = "US",
	}
}

session_init :: proc(session: ^Session, client: ^Client, auth: ^Auth_State, config: Session_Config) -> Session_Error {
	if session == nil ||
	   session.phase != .Uninitialized ||
	   client == nil ||
	   client.phase != .Initialized ||
	   auth == nil {
		return {kind = .Invalid_State}
	}

	if !pairing_qr_format_valid(config.qr_write_format_bits) {
		return {kind = .Invalid_Config}
	}

	if err := auth_state_validate(auth); err.kind != .None {
		return {kind = .Authentication_State_Failed, auth = err}
	}

	settings := config

	if settings.keepalive_interval == 0 {
		settings.keepalive_interval = 30 * time.Second
	}

	if settings.keepalive_interval < 0 || settings.keepalive_interval > 24 * time.Hour {
		return {kind = .Invalid_Config}
	}

	expected := signal_curve_public(auth.credentials.noise_private)

	if expected != client.static_public {
		return {kind = .Invalid_Account}
	}

	payload: [MAX_CLIENT_PAYLOAD_SIZE]u8
	_, payload_err := session_payload_encode(payload[:], auth, settings.payload)
	if payload_err.kind != .None {
		return payload_err
	}

	session^ = {
		client = client,
		auth   = auth,
		config = settings,
		phase  = .Initialized,
	}

	return {}
}

session_start :: proc(session: ^Session, now: time.Time) -> Session_Error {
	if session == nil || session.phase != .Initialized {
		return {kind = .Invalid_State}
	}

	if err := session_checkpoint(session); err.kind != .None {
		return session_fail(session, err)
	}

	payload: [MAX_CLIENT_PAYLOAD_SIZE]u8
	size, payload_err := session_payload_encode(payload[:], session.auth, session.config.payload)

	if payload_err.kind != .None {
		return session_fail(session, payload_err)
	}

	if err := client_handshake(session.client, payload[:size]); err.kind != .None {
		return session_fail(session, {kind = .Client_Failed, client = err})
	}

	session.phase = session.auth.credentials.registered ? .Authenticating : .Awaiting_Pairing
	session.last_received = now
	session.next_ping = time.time_add(now, session.config.keepalive_interval)

	return {}
}

// Read one decrypted binary node. The return borrows the session's decoded
// document; consume the event before the next read/process or session_close.
session_read :: proc(session: ^Session, now: time.Time) -> (event: Session_Event, error: Session_Error) {
	if !session_can_receive(session) {
		return {}, session_state_error(session)
	}

	buffer, allocation_err := make([]u8, min(session.client.config.max_frame_payload, MAX_BINARY_NODE_PAYLOAD))

	if allocation_err != nil {
		return {}, session_fail(session, {kind = .Allocation_Failed, allocation = allocation_err})
	}

	defer delete(buffer)
	size, read_err := client_read(session.client, buffer)

	if read_err.kind != .None {
		return {}, session_fail(session, {kind = .Client_Failed, client = read_err})
	}

	return session_process(session, buffer[:size], now)
}

// Separate from transport reads so an application's readiness/timer loop can
// dispatch network bytes and QR/keepalive ticks without concurrent Conn access.
session_process :: proc(
	session: ^Session,
	encoded: []u8,
	now: time.Time,
) -> (
	event: Session_Event,
	error: Session_Error,
) {
	if !session_can_receive(session) {
		return {}, session_state_error(session)
	}

	binary_document_destroy(&session.document)
	document, decode_err := binary_node_decode(encoded)
	if decode_err.kind != .None {
		return {}, session_fail(session, {kind = .Binary_Node_Failed, binary = decode_err})
	}

	session.document = document
	session.last_received = now
	node := document.root
	session_node_observe(session, node)

	if node.tag == "stream:error" {
		return session_stream_error(session, node)
	}

	if node.tag == "failure" {
		reason, _ := node_attr(node, "reason")
		code, valid_code := strconv.parse_uint(reason, 10)

		if !valid_code || code > cast(uint)max(u32) {
			code = 0
		}

		return {}, session_fail(session, {kind = .Server_Failure, server_code = cast(u32)code})
	}

	if node.tag == "success" {
		return session_login_accept(session, node)
	}

	if node.tag == "iq" {
		if _, found := pairing_node_child(node, "pair-device"); found {
			return session_pair_device(session, node, now)
		}

		if _, found := pairing_node_child(node, "pair-success"); found {
			return session_pair_success(session, node)
		}
	}

	return {kind = .Node, node = node}, {}
}

session_node_observe :: proc(session: ^Session, node: Binary_Node) {
	if session.config.observe_node != nil {
		kind, _ := node_attr(node, "type")
		tags: [32]string
		count := 0

		if children, found := node.content.([]Binary_Node); found {
			for child in children {
				if count == len(tags) {
					break
				}

				tags[count] = child.tag
				count += 1
			}
		}

		session.config.observe_node(
			session.config.observer_data,
			{tag = node.tag, kind = kind, children = tags[:count], ack_class = session_stream_ack_class(node)},
		)
	}
}

// Inspect at most the same 32 direct children exposed by the observer. Conflicting
// ACK classes or excessive metadata are deliberately reported as Unknown.
session_stream_ack_class :: proc(node: Binary_Node) -> Protocol_Ack_Class {
	if node.tag != "stream:error" {
		return .Unknown
	}

	children, found := node.content.([]Binary_Node)

	if !found || len(children) > 32 {
		return .Unknown
	}

	result: Protocol_Ack_Class
	seen, conflict := false, false

	for child in children[:min(len(children), 32)] {
		if child.tag != "ack" {
			continue
		}

		current := session_ack_class(child)

		if seen && current != result {
			conflict = true
		}

		if !seen {
			result = current
		}

		seen = true
	}

	if conflict {
		return .Unknown
	}

	return result
}

session_ack_class :: proc(node: Binary_Node) -> Protocol_Ack_Class {
	if len(node.attrs) > 32 {
		return .Unknown
	}

	result: Protocol_Ack_Class
	seen := false

	for attr in node.attrs {
		if attr.key != "class" {
			continue
		}

		if seen {
			return .Unknown
		}

		seen = true

		switch attr.value {
		case "":
			result = .Unknown
		case "message":
			result = .Message
		case "receipt":
			result = .Receipt
		case "notification":
			result = .Notification
		case "status":
			result = .Status
		case "call":
			result = .Call
		case:
			result = .Other
		}
	}

	return result
}

session_stream_error :: proc(session: ^Session, node: Binary_Node) -> (Session_Event, Session_Error) {
	code_text, _ := node_attr(node, "code")
	code, valid_code := strconv.parse_uint(code_text, 10)

	if valid_code && code == 515 && session.auth.credentials.registered {
		session.phase = .Restart_Required
		client_close(session.client)
		return {kind = .Restart_Required, account = &session.auth.account}, {}
	}

	if !valid_code || code > cast(uint)max(u32) {
		code = 0
	}

	return {}, session_fail(session, {kind = .Server_Failure, server_code = cast(u32)code})
}

session_login_accept :: proc(session: ^Session, node: Binary_Node) -> (Session_Event, Session_Error) {
	if !session.auth.credentials.registered || !session.auth.account.valid {
		return {}, session_fail(session, {kind = .Invalid_Account})
	}

	session.phase = .Login_Accepted
	pairing_qr_clear(&session.qr_state)
	crypto.zero_explicit(&session.qr, size_of(session.qr))

	return {kind = .Login_Accepted, node = node, account = &session.auth.account}, {}
}

session_pair_device :: proc(session: ^Session, node: Binary_Node, now: time.Time) -> (Session_Event, Session_Error) {
	if session.phase != .Awaiting_Pairing {
		return {}, session_fail(session, {kind = .Invalid_State})
	}

	reply: [MAX_PAIRING_IDENTITY_SIZE]u8
	size, pair_err := pairing_device_handle(&session.qr_state, node, &session.auth.credentials, now, reply[:])

	if pair_err.kind != .None {
		return {}, session_fail(session, {kind = .Pairing_Failed, pairing = pair_err})
	}

	if send_err := client_write(session.client, reply[:size]); send_err.kind != .None {
		return {}, session_fail(session, {kind = .Client_Failed, client = send_err})
	}

	written, qr_err := pairing_qr_next(
		&session.qr_state,
		now,
		session.qr[:],
		session.config.qr_write_format_bits,
		session.config.payload.browser_os,
		session.config.payload.browser_name,
	)

	if qr_err.kind != .None {
		return {}, session_fail(session, {kind = .Pairing_Failed, pairing = qr_err})
	}

	return {kind = .QR, qr = cast(string)session.qr[:written]}, {}
}

session_pair_success :: proc(session: ^Session, node: Binary_Node) -> (Session_Event, Session_Error) {
	if session.phase != .Awaiting_Pairing {
		return {}, session_fail(session, {kind = .Invalid_State})
	}

	reply: [MAX_PAIRING_IDENTITY_SIZE]u8
	size, pair_err := pairing_success_handle(&session.auth.account, node, &session.auth.credentials, reply[:])

	if pair_err.kind != .None {
		return {}, session_fail(session, {kind = .Pairing_Failed, pairing = pair_err})
	}

	session.auth.credentials.registered = true
	// Keep verified keys/account even if the acknowledgment transport
	// fails; the device may already have been paired on the phone.
	if save_err := session_checkpoint(session); save_err.kind != .None {
		return {}, session_fail(session, save_err)
	}

	if send_err := client_write(session.client, reply[:size]); send_err.kind != .None {
		return {}, session_fail(session, {kind = .Client_Failed, client = send_err})
	}

	pairing_qr_clear(&session.qr_state)
	crypto.zero_explicit(&session.qr, size_of(session.qr))
	session.phase = .Paired

	return {kind = .Pairing_Complete, account = &session.auth.account}, {}
}

session_tick :: proc(session: ^Session, now: time.Time) -> (event: Session_Event, error: Session_Error) {
	if !session_can_receive(session) {
		return {}, session_state_error(session)
	}

	// An unpaired connection can be quiet while the user scans. Its finite
	// QR reference deadlines bound this wait; the online idle timeout would
	// otherwise discard a 60-second code after only 35 seconds.
	if !session.qr_state.initialized &&
	   time.diff(session.last_received, now) > session.config.keepalive_interval + 5 * time.Second {
		return {}, session_fail(session, {kind = .Connection_Lost})
	}

	if now._nsec >= session.next_ping._nsec {
		if err := session_send_keepalive_ping(session); err.kind != .None {
			return {}, session_fail(session, err)
		}

		session.next_ping = time.time_add(now, session.config.keepalive_interval)
	}

	if session.qr_state.initialized && now._nsec >= session.qr_state.next_at._nsec {
		size, qr_err := pairing_qr_next(
			&session.qr_state,
			now,
			session.qr[:],
			session.config.qr_write_format_bits,
			session.config.payload.browser_os,
			session.config.payload.browser_name,
		)

		if qr_err.kind == .QR_Expired {
			return {}, session_fail(session, {kind = .QR_Expired, pairing = qr_err})
		}

		if qr_err.kind != .None {
			return {}, session_fail(session, {kind = .Pairing_Failed, pairing = qr_err})
		}

		return {kind = .QR, qr = cast(string)session.qr[:size]}, {}
	}

	return {}, {}
}

session_close :: proc(session: ^Session) -> Session_Error {
	if session == nil || session.phase == .Uninitialized {
		return {kind = .Invalid_State}
	}

	if session.phase == .Closed {
		return {}
	}

	binary_document_destroy(&session.document)
	pairing_qr_clear(&session.qr_state)
	crypto.zero_explicit(&session.qr, size_of(session.qr))
	session.phase = .Closed

	if err := client_close(session.client); err.kind != .None {
		return {kind = .Client_Failed, client = err}
	}

	return {}
}

session_payload_encode :: proc(dst: []u8, auth: ^Auth_State, config: Payload_Config) -> (int, Session_Error) {
	if auth.credentials.registered {
		jid := cast(string)auth.account.jid[:auth.account.jid_size]
		user, device, jid_err := pairing_jid_decode(jid)

		if jid_err.kind != .None {
			return 0, {kind = .Invalid_Account, pairing = jid_err}
		}

		size, err := login_payload_encode(dst, config, user, device, include_device = strings.contains(jid, ":"))

		if err != .None {
			return 0, {kind = .Payload_Failed, payload = err}
		}

		return size, {}
	}

	size, err := registration_payload_encode(
		dst,
		config,
		{
			registration_id = auth.credentials.registration_id,
			identity_public = signal_curve_public(auth.credentials.identity_private),
			signed_prekey_id = auth.credentials.signed_prekey_id,
			signed_prekey_public = auth.credentials.signed_prekey_public,
			signed_prekey_signature = auth.credentials.signed_prekey_signature,
		},
	)

	if err != .None {
		return 0, {kind = .Payload_Failed, payload = err}
	}

	return size, {}
}

session_checkpoint :: proc(session: ^Session) -> Session_Error {
	if session.config.auth_path == "" {
		return {}
	}

	if err := auth_state_save(session.config.auth_path, session.auth); err.kind != .None {
		return {kind = .Authentication_State_Failed, auth = err}
	}

	return {}
}

session_can_receive :: proc(session: ^Session) -> bool {
	if session == nil {
		return false
	}

	#partial switch session.phase {
	case .Awaiting_Pairing, .Authenticating, .Paired, .Login_Accepted:
		return true
	}

	return false
}

session_state_error :: proc(session: ^Session) -> Session_Error {
	if session != nil && session.phase == .Failed {
		return session.last_error
	}

	return {kind = .Invalid_State}
}

session_fail :: proc(session: ^Session, err: Session_Error) -> Session_Error {
	session.phase = .Failed
	session.last_error = err
	client_close(session.client)
	binary_document_destroy(&session.document)
	pairing_qr_clear(&session.qr_state)
	crypto.zero_explicit(&session.qr, size_of(session.qr))

	return err
}

session_send_keepalive_ping :: proc(session: ^Session) -> Session_Error {
	if session.ping_sequence == max(u64) {
		return {kind = .Invalid_State}
	}

	session.ping_sequence += 1
	id_buffer: [32]u8
	id := fmt.bprintf(id_buffer[:], "odin-ping-%d", session.ping_sequence)
	attrs := [?]Binary_Node_Attribute{{"id", id}, {"to", PAIRING_SERVER}, {"type", "get"}, {"xmlns", "w:p"}}
	children := [?]Binary_Node{{tag = "ping"}}
	buffer: [256]u8
	size, err := binary_node_encode(buffer[:], {tag = "iq", attrs = attrs[:], content = children[:]})

	if err.kind != .None {
		return {kind = .Binary_Node_Failed, binary = err}
	}

	if write_err := client_write(session.client, buffer[:size]); write_err.kind != .None {
		return {kind = .Client_Failed, client = write_err}
	}

	return {}
}

MAX_PAIRING_REFS :: 16
MAX_PAIRING_REF_SIZE :: 1024
PAIRING_LINKED_DEVICE_QR_PREFIX :: "https://wa.me/settings/linked_devices#"
MAX_PAIRING_QR_SIZE :: MAX_PAIRING_REF_SIZE + 3 * 44 + 3 + len(PAIRING_LINKED_DEVICE_QR_PREFIX) + 2
MAX_PAIRING_DETAILS_SIZE :: 4096
MAX_PAIRING_IDENTITY_SIZE :: 16384
PAIRING_SERVER :: "@s.whatsapp.net"

Pairing_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Credentials,
	Invalid_Stanza,
	Missing_ID,
	Missing_Pairing_Refs,
	Too_Many_Refs,
	Invalid_Ref,
	Data_Oversized,
	Destination_Undersized,
	QR_Not_Ready,
	QR_Expired,
	Missing_Device,
	Invalid_JID,
	Invalid_Identity,
	Invalid_Account_Type,
	Invalid_HMAC,
	Invalid_Account_Signature,
	Missing_Key_Index,
	Protobuf_Failed,
	Signal_Failed,
	Binary_Node_Failed,
	Invalid_QR_Format,
}

Pairing_Error :: struct {
	kind:     Pairing_Error_Kind,
	protobuf: Protobuf_Error,
	signal:   Signal_Error,
	binary:   Binary_Node_Error,
}

// Fixed owned storage; copying a completed account does not leave borrowed
// pointers into a decrypted stanza. This contains public identity metadata.
// Legacy is the exact historical v1 persistence contract. Current is selected
// only by new pair-success handling and never tries alternate signature domains.
Pairing_Signature_Policy :: enum u8 {
	Legacy,
	Current,
}

Paired_Account :: struct {
	signature_policy:                    Pairing_Signature_Policy,
	valid, hosted:                       bool,
	jid:                                 [160]u8,
	jid_size:                            int,
	name:                                [512]u8,
	name_size:                           int,
	platform:                            [128]u8,
	platform_size:                       int,
	details:                             [MAX_PAIRING_DETAILS_SIZE]u8,
	details_size:                        int,
	account_signature_key:               [32]u8,
	account_signature, device_signature: [64]u8,
	key_index:                           u32,
}

Pairing_QR_State :: struct {
	refs:                                      [MAX_PAIRING_REFS][MAX_PAIRING_REF_SIZE]u8,
	ref_sizes:                                 [MAX_PAIRING_REFS]int,
	count, next:                               int,
	noise_public, identity_public, adv_secret: [32]u8,
	next_at:                                   time.Time,
	initial_timeout, subsequent_timeout:       time.Duration,
	initialized:                               bool,
}

pairing_node_child :: proc(node: Binary_Node, tag: string) -> (^Binary_Node, bool) {
	if children, ok := node.content.([]Binary_Node); ok {
		for &child in children {
			if child.tag == tag {
				return &child, true
			}
		}
	}

	return nil, false
}

// Parses the phone/account JID required by login payloads. Domain selection
// remains explicit; group/broadcast addresses cannot become login identities.
pairing_jid_decode :: proc(jid: string) -> (user: string, device: u32, err: Pairing_Error) {
	at := strings.index_byte(jid, '@')
	if at <= 0 {
		return "", 0, {kind = .Invalid_JID}
	}

	domain := jid[at + 1:]

	if domain != "s.whatsapp.net" && domain != "c.us" && domain != "lid" {
		return "", 0, {kind = .Invalid_JID}
	}

	local := jid[:at]
	colon := strings.index_byte(local, ':')

	if colon >= 0 {
		if colon == 0 || colon == len(local) - 1 {
			return "", 0, {kind = .Invalid_JID}
		}

		for c in local[colon + 1:] {
			if !is_digit(c) {
				return "", 0, {kind = .Invalid_JID}
			}
		}

		value, valid := strconv.parse_uint(local[colon + 1:], 10)

		if !valid || value > cast(uint)max(u32) {
			return "", 0, {kind = .Invalid_JID}
		}

		device = cast(u32)value
		local = local[:colon]
	}

	if underscore := strings.index_byte(local, '_'); underscore >= 0 {
		for c in local[underscore + 1:] {
			if !is_digit(c) {
				return "", 0, {kind = .Invalid_JID}
			}
		}

		if underscore == len(local) - 1 {
			return "", 0, {kind = .Invalid_JID}
		}

		local = local[:underscore]
	}

	if len(local) == 0 {
		return "", 0, {kind = .Invalid_JID}
	}

	for c in local {
		if !is_digit(c) {
			return "", 0, {kind = .Invalid_JID}
		}
	}

	_, valid := strconv.parse_u64(local, 10)
	if !valid {
		return "", 0, {kind = .Invalid_JID}
	}

	return local, device, {}
}

pairing_qr_format_valid :: proc(format: Pairing_QR_Format) -> bool {
	return format == .Legacy || format == .Linked_Device
}

// Pinned 81345beb companion-reg-client-utils.ts. This enum is distinct from
// DeviceProps.PlatformType, which describes a different protocol field.
pairing_qr_companion_type :: proc(browser_os, browser_name: string) -> u8 {
	if browser_name == "Desktop" {
		return browser_os == "Windows" ? 8 : 7
	}

	switch browser_name {
	case "Chrome":
		return 1
	case "Edge":
		return 2
	case "Firefox":
		return 3
	case "IE":
		return 4
	case "Opera":
		return 5
	case "Safari":
		return 6
	case:
		return 9
	}
}

pairing_qr_encode :: proc(
	dst: []u8,
	ref: string,
	noise_public, identity_public, adv_secret: [32]u8,
	format: Pairing_QR_Format = .Legacy,
	browser_os: string = "Ubuntu",
	browser_name: string = "Chrome",
) -> (
	n: int,
	err: Pairing_Error,
) {
	if !pairing_qr_format_valid(format) {
		return 0, {kind = .Invalid_QR_Format}
	}
	if !pairing_ref_valid(ref) {
		return 0, {kind = .Invalid_Ref}
	}

	required := len(ref) + 3 * 44 + 3
	if format == .Linked_Device {
		required += len(PAIRING_LINKED_DEVICE_QR_PREFIX) + 2
	}
	if len(dst) < required {
		return required, {kind = .Destination_Undersized}
	}
	// Profile strings may also borrow dst; read them before output writes.
	companion_type := pairing_qr_companion_type(browser_os, browser_name)

	if format == .Linked_Device {
		// A caller may borrow ref from dst. Save it before writing the prefix.
		reference: [MAX_PAIRING_REF_SIZE]u8
		copy(reference[:], ref)
		n = copy(dst, PAIRING_LINKED_DEVICE_QR_PREFIX)
		n += copy(dst[n:], reference[:len(ref)])
		crypto.zero_explicit(&reference, size_of(reference))
	} else {
		n = copy(dst, ref)
	}
	keys := [?][32]u8{noise_public, identity_public, adv_secret}
	defer crypto.zero_explicit(&keys, size_of(keys))
	for &key in keys {
		dst[n] = ','
		n += 1
		_, encode_err := base64.encode_into_buf(dst[n:][:44], key[:])
		assert(encode_err == nil)
		n += 44
	}
	if format == .Linked_Device {
		dst[n], dst[n + 1] = ',', '0' + companion_type
		n += 2
	}
	return n, {}
}

// Initializes a new set of references only after the server's pair-device
// stanza has been received. Returned acknowledgment bytes must be sent first.
pairing_device_handle :: proc(
	state: ^Pairing_QR_State,
	iq: Binary_Node,
	credentials: ^Device_Credentials,
	now: time.Time,
	reply: []u8,
) -> (
	n: int,
	err: Pairing_Error,
) {
	if state == nil || credentials == nil {
		return 0, {kind = .Invalid_State}
	}

	if device_credentials_validate(credentials) != .None {
		return 0, {kind = .Invalid_Credentials}
	}

	if iq.tag != "iq" {
		return 0, {kind = .Invalid_Stanza}
	}

	if kind, ok := node_attr(iq, "type"); !ok || kind != "set" {
		return 0, {kind = .Invalid_Stanza}
	}

	id, id_present := node_attr(iq, "id")
	if !id_present || len(id) == 0 {
		return 0, {kind = .Missing_ID}
	}

	pair, found := pairing_node_child(iq, "pair-device")
	if !found {
		return 0, {kind = .Invalid_Stanza}
	}

	children, children_ok := pair.content.([]Binary_Node)
	if !children_ok {
		return 0, {kind = .Missing_Pairing_Refs}
	}

	next: Pairing_QR_State
	defer crypto.zero_explicit(&next, size_of(next))
	if ref_error := pairing_refs_decode(&next, children); ref_error.kind != .None {
		return 0, ref_error
	}

	attrs := [?]Binary_Node_Attribute{{"to", PAIRING_SERVER}, {"type", "result"}, {"id", id}}
	written, node_err := binary_node_encode(reply, {tag = "iq", attrs = attrs[:]})
	if node_err.kind != .None {
		return 0, {kind = .Binary_Node_Failed, binary = node_err}
	}

	next.noise_public = signal_curve_public(credentials.noise_private)
	next.identity_public = signal_curve_public(credentials.identity_private)
	next.adv_secret = credentials.adv_secret
	next.next_at = now
	next.initial_timeout, next.subsequent_timeout = 60 * time.Second, 20 * time.Second
	next.initialized = true
	state^ = next
	return written, {}
}

pairing_refs_decode :: proc(next: ^Pairing_QR_State, children: []Binary_Node) -> Pairing_Error {
	for child in children {
		if child.tag != "ref" {
			continue
		}

		if next.count == MAX_PAIRING_REFS {
			return {kind = .Too_Many_Refs}
		}

		data, valid := child.content.([]u8)

		if !valid || !pairing_ref_valid(cast(string)data) {
			return {kind = .Invalid_Ref}
		}

		copy(next.refs[next.count][:], data)
		next.ref_sizes[next.count] = len(data)
		next.count += 1
	}

	if next.count == 0 {
		return {kind = .Missing_Pairing_Refs}
	}

	return {}
}

pairing_qr_next :: proc(
	state: ^Pairing_QR_State,
	now: time.Time,
	dst: []u8,
	format: Pairing_QR_Format = .Legacy,
	browser_os: string = "Ubuntu",
	browser_name: string = "Chrome",
) -> (
	n: int,
	err: Pairing_Error,
) {
	if state == nil || !state.initialized {
		return 0, {kind = .Invalid_State}
	}

	if now._nsec < state.next_at._nsec {
		return 0, {kind = .QR_Not_Ready}
	}

	if state.next >= state.count {
		return 0, {kind = .QR_Expired}
	}

	ref := cast(string)state.refs[state.next][:state.ref_sizes[state.next]]
	written, encode_err := pairing_qr_encode(
		dst,
		ref,
		state.noise_public,
		state.identity_public,
		state.adv_secret,
		format,
		browser_os,
		browser_name,
	)
	if encode_err.kind != .None {
		return written, encode_err
	}

	duration := state.subsequent_timeout
	if state.next == 0 {
		duration = state.initial_timeout
	}

	state.next += 1
	state.next_at = time.time_add(now, duration)
	return written, {}
}

pairing_qr_clear :: proc(state: ^Pairing_QR_State) {
	if state != nil {
		crypto.zero_explicit(state, size_of(Pairing_QR_State))
	}
}

// Validates the account HMAC and Signal signatures before changing account.
// The reply contains pair-device-sign and omits accountSignatureKey.
pairing_success_handle :: proc(
	account: ^Paired_Account,
	iq: Binary_Node,
	credentials: ^Device_Credentials,
	reply: []u8,
) -> (
	n: int,
	err: Pairing_Error,
) {
	if account == nil || credentials == nil {
		return 0, {kind = .Invalid_State}
	}

	if device_credentials_validate(credentials) != .None {
		return 0, {kind = .Invalid_Credentials}
	}

	id, pair, identity_node, device_node, stanza_error := pairing_success_stanza_decode(iq)
	if stanza_error.kind != .None {
		return 0, stanza_error
	}
	identity_bytes, has_bytes := identity_node.content.([]u8)
	if !has_bytes || len(identity_bytes) > MAX_PAIRING_IDENTITY_SIZE {
		return 0, {kind = .Invalid_Identity}
	}

	wrapper, wrapper_error := pairing_success_hmac_decode(identity_bytes, credentials)
	if wrapper_error.kind != .None {
		return 0, wrapper_error
	}
	identity, details, identity_error := pairing_success_signed_identity_decode(wrapper)
	if identity_error.kind != .None {
		return 0, identity_error
	}
	next := Paired_Account {
		valid            = true,
		hosted           = wrapper.account_type == 1,
		key_index        = details.key_index,
		signature_policy = .Current,
	}
	if metadata_error := pairing_success_metadata_decode(&next, pair, device_node); metadata_error.kind != .None {
		return 0, metadata_error
	}
	if signature_error := pairing_success_signatures_prepare(&next, credentials, identity, details); signature_error.kind != .None {
		return 0, signature_error
	}
	written, reply_error := pairing_success_reply_encode(reply, &next, id)
	if reply_error.kind != .None {
		return 0, reply_error
	}

	account^ = next
	return written, {}
}

pairing_success_stanza_decode :: proc(
	iq: Binary_Node,
) -> (
	string,
	^Binary_Node,
	^Binary_Node,
	^Binary_Node,
	Pairing_Error,
) {
	if iq.tag != "iq" {
		return "", nil, nil, nil, {kind = .Invalid_Stanza}
	}

	id, present := node_attr(iq, "id")
	if !present || id == "" {
		return "", nil, nil, nil, {kind = .Missing_ID}
	}

	pair, found := pairing_node_child(iq, "pair-success")
	if !found {
		return "", nil, nil, nil, {kind = .Invalid_Stanza}
	}

	identity_node, has_identity := pairing_node_child(pair^, "device-identity")
	device_node, has_device := pairing_node_child(pair^, "device")
	if !has_identity || !has_device {
		return "", nil, nil, nil, {kind = .Missing_Device}
	}

	return id, pair, identity_node, device_node, {}
}

pairing_success_hmac_decode :: proc(
	identity_bytes: []u8,
	credentials: ^Device_Credentials,
) -> (
	Pairing_Device_Identity_HMAC,
	Pairing_Error,
) {
	wrapper, wrapper_err := pairing_identity_hmac_decode(identity_bytes)
	if wrapper_err != .None {
		return {}, {kind = .Protobuf_Failed, protobuf = wrapper_err}
	}

	if wrapper.account_type > 1 {
		return {}, {kind = .Invalid_Account_Type}
	}

	if len(wrapper.hmac) != 32 {
		return {}, {kind = .Invalid_HMAC}
	}

	mac: [32]u8
	mac_context: hmac.Context
	defer crypto.zero_explicit(&mac_context, size_of(mac_context))
	hmac.init(&mac_context, .SHA256, credentials.adv_secret[:])
	if wrapper.account_type == 1 {
		hmac.update(&mac_context, []u8{6, 5})
	}

	hmac.update(&mac_context, wrapper.details)
	hmac.final(&mac_context, mac[:])
	if crypto.compare_constant_time(mac[:], wrapper.hmac) != 1 {
		return {}, {kind = .Invalid_HMAC}
	}

	return wrapper, {}
}

pairing_success_signed_identity_decode :: proc(
	wrapper: Pairing_Device_Identity_HMAC,
) -> (
	Pairing_Signed_Identity,
	Pairing_Device_Details,
	Pairing_Error,
) {
	identity, identity_err := pairing_signed_identity_decode(wrapper.details)
	if identity_err != .None {
		return {}, {}, {kind = .Protobuf_Failed, protobuf = identity_err}
	}

	if len(identity.account_signature_key) != 32 ||
	   len(identity.account_signature) != 64 ||
	   len(identity.details) > MAX_PAIRING_DETAILS_SIZE ||
	   len(identity.details) == 0 {
		return {}, {}, {kind = .Invalid_Identity}
	}

	details, details_err := pairing_device_details_decode(identity.details)
	if details_err != .None {
		return {}, {}, {kind = .Protobuf_Failed, protobuf = details_err}
	}

	if !details.has_key_index {
		return {}, {}, {kind = .Missing_Key_Index}
	}

	return identity, details, {}
}

pairing_success_metadata_decode :: proc(next: ^Paired_Account, pair, device_node: ^Binary_Node) -> Pairing_Error {
	jid, has_jid := node_attr(device_node^, "jid")
	if !has_jid {
		return {kind = .Invalid_JID}
	}

	if _, _, jid_err := pairing_jid_decode(jid); jid_err.kind != .None {
		return jid_err
	}

	name, platform := "", ""

	if biz, ok := pairing_node_child(pair^, "biz"); ok {
		name, _ = node_attr(biz^, "name")
	}

	if os_node, ok := pairing_node_child(pair^, "platform"); ok {
		platform, _ = node_attr(os_node^, "name")
	}

	if len(jid) > 160 ||
	   len(name) > 512 ||
	   len(platform) > 128 ||
	   !utf8.valid_string(name) ||
	   !utf8.valid_string(platform) {
		return {kind = .Data_Oversized}
	}

	next.jid_size, next.name_size, next.platform_size = len(jid), len(name), len(platform)
	copy(next.jid[:], jid)
	copy(next.name[:], name)
	copy(next.platform[:], platform)

	return {}
}

pairing_success_signatures_prepare :: proc(
	next: ^Paired_Account,
	credentials: ^Device_Credentials,
	identity: Pairing_Signed_Identity,
	details: Pairing_Device_Details,
) -> Pairing_Error {
	identity_public := signal_curve_public(credentials.identity_private)
	account_key: [32]u8
	copy(account_key[:], identity.account_signature_key)
	signed: [2 + MAX_PAIRING_DETAILS_SIZE + 32 + 32]u8
	account_domain, domain_error := paired_account_signature_domain(.Current, details)
	if domain_error.kind != .None {
		return domain_error
	}
	signed[0], signed[1] = 6, account_domain
	copy(signed[2:], identity.details)
	copy(signed[2 + len(identity.details):], identity_public[:])
	if err := signal_curve_verify(account_key, signed[:2 + len(identity.details) + 32], identity.account_signature);
	   err != .None {
		return {kind = .Invalid_Account_Signature, signal = err}
	}

	signed[1] = 1 // New companion signatures always use the standard device domain.

	copy(signed[2 + len(identity.details) + 32:], account_key[:])
	device_signature, signature_err := signal_curve_sign(
		credentials.identity_private,
		signed[:2 + len(identity.details) + 64],
	)
	if signature_err != .None {
		return {kind = .Signal_Failed, signal = signature_err}
	}

	next.details_size = len(identity.details)
	copy(next.details[:], identity.details)
	next.account_signature_key = account_key
	copy(next.account_signature[:], identity.account_signature)
	next.device_signature = device_signature
	return {}
}

pairing_success_reply_encode :: proc(reply: []u8, next: ^Paired_Account, id: string) -> (int, Pairing_Error) {
	encoded_account: [MAX_PAIRING_DETAILS_SIZE + 200]u8
	encoded_size, encoded_err := pairing_signed_identity_encode(
		encoded_account[:],
		{
			details = next.details[:next.details_size],
			account_signature = next.account_signature[:],
			device_signature = next.device_signature[:],
		},
		false,
	)

	if encoded_err != .None {
		return 0, {kind = .Protobuf_Failed, protobuf = encoded_err}
	}

	key_index_buffer: [16]u8
	key_index := fmt.bprintf(key_index_buffer[:], "%d", next.key_index)
	identity_attrs := [?]Binary_Node_Attribute{{"key-index", key_index}}
	identity_children := [?]Binary_Node {
		{tag = "device-identity", attrs = identity_attrs[:], content = encoded_account[:encoded_size]},
	}

	reply_children := [?]Binary_Node{{tag = "pair-device-sign", content = identity_children[:]}}
	attrs := [?]Binary_Node_Attribute{{"to", PAIRING_SERVER}, {"type", "result"}, {"id", id}}
	written, binary_err := binary_node_encode(reply, {tag = "iq", attrs = attrs[:], content = reply_children[:]})

	if binary_err.kind != .None {
		return 0, {kind = .Binary_Node_Failed, binary = binary_err}
	}

	return written, {}
}

pairing_ref_valid :: proc(ref: string) -> bool {
	if len(ref) == 0 || len(ref) > MAX_PAIRING_REF_SIZE {
		return false
	}

	for c in ref {
		if c <= ' ' || c > '~' || c == ',' {
			return false
		}
	}

	return true
}

// Recheck persisted public account signatures against this device identity.
// A checksum alone is not sufficient to accept loaded pairing metadata.
paired_account_validate :: proc(account: ^Paired_Account, credentials: ^Device_Credentials) -> Pairing_Error {
	if account == nil || credentials == nil || !account.valid {
		return {kind = .Invalid_State}
	}

	if account.jid_size <= 0 ||
	   account.jid_size > len(account.jid) ||
	   account.name_size < 0 ||
	   account.name_size > len(account.name) ||
	   account.platform_size < 0 ||
	   account.platform_size > len(account.platform) ||
	   account.details_size <= 0 ||
	   account.details_size > len(account.details) {
		return {kind = .Data_Oversized}
	}

	if _, _, err := pairing_jid_decode(cast(string)account.jid[:account.jid_size]); err.kind != .None {
		return err
	}

	if !utf8.valid_string(cast(string)account.name[:account.name_size]) ||
	   !utf8.valid_string(cast(string)account.platform[:account.platform_size]) {
		return {kind = .Invalid_Identity}
	}

	details, details_err := pairing_device_details_decode(account.details[:account.details_size])

	if details_err != .None {
		return {kind = .Protobuf_Failed, protobuf = details_err}
	}

	if !details.has_key_index || details.key_index != account.key_index {
		return {kind = .Missing_Key_Index}
	}

	return paired_account_signatures_validate(account, credentials, details)
}

paired_account_signature_domain :: proc(
	policy: Pairing_Signature_Policy,
	details: Pairing_Device_Details,
) -> (
	u8,
	Pairing_Error,
) {
	switch policy {
	case .Legacy:
		return 0, {}
	case .Current:
		if details.device_type > 1 {
			return 0, {kind = .Invalid_Account_Type}
		}
		return details.device_type == 1 ? 5 : 0, {}
	case:
		return 0, {kind = .Invalid_Account_Type}
	}
}

paired_account_signatures_validate :: proc(
	account: ^Paired_Account,
	credentials: ^Device_Credentials,
	details: Pairing_Device_Details,
) -> Pairing_Error {
	identity_public := signal_curve_public(credentials.identity_private)
	message: [2 + MAX_PAIRING_DETAILS_SIZE + 64]u8
	account_domain, domain_error := paired_account_signature_domain(account.signature_policy, details)
	if domain_error.kind != .None {
		return domain_error
	}
	message[0], message[1] = 6, account_domain
	copy(message[2:], account.details[:account.details_size])
	copy(message[2 + account.details_size:], identity_public[:])
	if err := signal_curve_verify(
		account.account_signature_key,
		message[:2 + account.details_size + 32],
		account.account_signature[:],
	); err != .None {
		return {kind = .Invalid_Account_Signature, signal = err}
	}

	message[1] = 1
	if account.signature_policy == .Legacy && account.hosted {
		message[1] = 6
	}
	copy(message[2 + account.details_size + 32:], account.account_signature_key[:])
	if err := signal_curve_verify(
		identity_public,
		message[:2 + account.details_size + 64],
		account.device_signature[:],
	); err != .None {
		return {kind = .Invalid_Identity, signal = err}
	}

	return {}
}

/* 
 * QR Code generator library (C)
 * 
 * Copyright (c) Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/qr-code-generator-library
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

// Native Odin byte-mode/ECC-L adaptation. Source:
// https://github.com/nayuki/QR-Code-generator/blob/master/c/qrcodegen.c
// Version1..40, eight-mask penalty selection, no heap allocation in encoding.

QR_MAX_SIZE :: 177
QR_MAX_TEXT_BYTES :: 2953
QR_QUIET_ZONE :: 4
QR_Error :: enum {
	None,
	Text_Oversized,
	Invalid_UTF8,
	Invalid_Code,
	Allocation_Failed,
}
// Owns all modules, stored at y*size+x. No backing allocation or borrowed text.
QR_Code :: struct {
	version, size, mask: int,
	modules:             [QR_MAX_SIZE * QR_MAX_SIZE]bool,
}

QR_ECC_PER_BLOCK := [41]int {
	-1,
	7,
	10,
	15,
	20,
	26,
	18,
	20,
	24,
	30,
	18,
	20,
	24,
	26,
	30,
	22,
	24,
	28,
	30,
	28,
	28,
	28,
	28,
	30,
	30,
	26,
	28,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
	30,
}
QR_BLOCKS := [41]int {
	-1,
	1,
	1,
	1,
	1,
	1,
	2,
	2,
	2,
	2,
	4,
	4,
	4,
	4,
	4,
	6,
	6,
	6,
	6,
	7,
	8,
	8,
	9,
	9,
	10,
	12,
	12,
	12,
	13,
	14,
	15,
	16,
	17,
	18,
	19,
	19,
	20,
	21,
	22,
	24,
	25,
}

qr_encode :: proc(text: string) -> (code: QR_Code, err: QR_Error) {
	if len(text) > QR_MAX_TEXT_BYTES {
		return {}, .Text_Oversized
	}

	if !utf8.valid_string(text) {
		return {}, .Invalid_UTF8
	}

	version := 1

	for ; version <= 40; version += 1 {
		count_bits := version < 10 ? 8 : 16

		if len(text) < 1 << cast(uint)count_bits && 4 + count_bits + len(text) * 8 <= qr_data_codeword_count(version) * 8 {
			break
		}
	}

	if version > 40 {
		return {}, .Text_Oversized
	}

	code.version, code.size = version, version * 4 + 17
	data, interleaved: [3706]u8
	qr_data_encode(data[:], text, version)
	qr_interleave(data[:], version, interleaved[:])
	functions: [QR_MAX_SIZE * QR_MAX_SIZE]bool
	qr_draw_function_patterns(&code, &functions)
	bit := 0

	for right := code.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}

		for vert in 0 ..< code.size {
			for j in 0 ..< 2 {
				x := right - j
				y := ((right + 1) & 2) == 0 ? code.size - 1 - vert : vert
				index := y * code.size + x

				if !functions[index] && bit < qr_count_raw_data_modules(version) / 8 * 8 {
					code.modules[index] = (interleaved[bit / 8] >> cast(uint)(7 - bit % 8)) & 1 != 0
					bit += 1
				}
			}
		}
	}

	best_penalty := max(int)

	for mask in 0 ..< 8 {
		qr_apply_data_mask(&code, &functions, mask)
		qr_write_format_bits(&code, &functions, mask)
		penalty := qr_penalty(&code)

		if penalty < best_penalty {
			best_penalty = penalty
			code.mask = mask
		}

		qr_apply_data_mask(&code, &functions, mask)
	}

	qr_apply_data_mask(&code, &functions, code.mask)
	qr_write_format_bits(&code, &functions, code.mask)

	return code, .None
}

qr_data_encode :: proc(data: []u8, text: string, version: int) {
	bits := 0
	qr_bits_write(data, &bits, 4, 4) // Byte-mode indicator.
	qr_bits_write(data, &bits, cast(u32)len(text), version < 10 ? 8 : 16)
	for i in 0 ..< len(text) {
		qr_bits_write(data, &bits, cast(u32)text[i], 8)
	}
	capacity := qr_data_codeword_count(version) * 8
	qr_bits_write(data, &bits, 0, min(4, capacity - bits))
	qr_bits_write(data, &bits, 0, (8 - bits % 8) % 8)
	pad: u32 = 0xec

	for bits < capacity {
		qr_bits_write(data, &bits, pad, 8)
		pad ~= 0xec ~ 0x11
	}
}

qr_module_is_dark :: proc(code: ^QR_Code, x, y: int) -> bool {
	if code == nil || code.size < 21 || code.size > QR_MAX_SIZE || x < 0 || y < 0 || x >= code.size || y >= code.size {
		return false
	}

	return code.modules[y * code.size + x]
}

// Black modules on an explicit white background, independent of terminal
// theme. Each UTF8 cell represents two vertical modules. Four quiet modules
// surround every side (the odd final row adds one white module below).
// Output owns its allocation; destroy using the same allocator. QR pairing
// strings are credentials: display only where the caller intends to pair.
qr_terminal_render :: proc(code: ^QR_Code, allocator := context.allocator) -> (string, QR_Error) {
	if code == nil ||
	   code.version < 1 ||
	   code.version > 40 ||
	   code.size != code.version * 4 + 17 ||
	   code.mask < 0 ||
	   code.mask > 7 {
		return "", .Invalid_Code
	}

	width := code.size + QR_QUIET_ZONE * 2
	rows := (width + 1) / 2
	// ANSI black foreground / white background; each cell <=3 UTF8 bytes.
	prefix := cast(string)"\x1b[30;47m"
	suffix := cast(string)"\x1b[0m\n"
	size := rows * (len(prefix) + len(suffix))

	for row in 0 ..< rows {
		for col in 0 ..< width {
			x, y := col - QR_QUIET_ZONE, row * 2 - QR_QUIET_ZONE
			size += qr_module_is_dark(code, x, y) || qr_module_is_dark(code, x, y + 1) ? 3 : 1
		}
	}

	buffer, ae := make([]u8, size, allocator)
	if ae != nil {
		return "", .Allocation_Failed
	}

	at := 0

	for row in 0 ..< rows {
		at += copy(buffer[at:], transmute([]u8)prefix)

		for col in 0 ..< width {
			x, y := col - QR_QUIET_ZONE, row * 2 - QR_QUIET_ZONE
			top, bottom := qr_module_is_dark(code, x, y), qr_module_is_dark(code, x, y + 1)
			glyph := " "

			if top && bottom {
				glyph = "█"
			} else if top {
				glyph = "▀"
			} else if bottom {
				glyph = "▄"
			}

			at += copy(buffer[at:], transmute([]u8)glyph)
		}

		at += copy(buffer[at:], transmute([]u8)suffix)
	}

	return cast(string)buffer, .None
}
qr_terminal_destroy :: proc(text: string, allocator := context.allocator) {
	delete(text, allocator)
}

qr_bits_write :: proc(data: []u8, at: ^int, value: u32, count: int) {
	for i := count - 1; i >= 0; i -= 1 {
		data[at^ / 8] |= cast(u8)((value >> cast(uint)i) & 1) << cast(uint)(7 - at^ % 8)
		at^ += 1
	}
}
qr_count_raw_data_modules :: proc(version: int) -> int {
	result := (16 * version + 128) * version + 64

	if version >= 2 {
		n := version / 7 + 2
		result -= (25 * n - 10) * n - 55
		if version >= 7 {
			result -= 36
		}
	}

	return result
}
qr_data_codeword_count :: proc(version: int) -> int {
	return qr_count_raw_data_modules(version) / 8 - QR_ECC_PER_BLOCK[version] * QR_BLOCKS[version]
}
qr_gf256_multiply :: proc(x, y: u8) -> u8 {
	z: u8

	for i := 7; i >= 0; i -= 1 {
		z = cast(u8)((cast(u16)z << 1) ~ (cast(u16)(z >> 7) * 0x11d))
		z ~= ((y >> cast(uint)i) & 1) * x
	}

	return z
}
qr_interleave :: proc(data: []u8, version: int, result: []u8) {
	blocks, ecc_size := QR_BLOCKS[version], QR_ECC_PER_BLOCK[version]
	raw_words, data_size := qr_count_raw_data_modules(version) / 8, qr_data_codeword_count(version)
	short_blocks := blocks - raw_words % blocks
	short_data_size := raw_words / blocks - ecc_size
	divisor: [30]u8
	divisor[ecc_size - 1] = 1
	root: u8 = 1

	for _ in 0 ..< ecc_size {
		for j in 0 ..< ecc_size {
			divisor[j] = qr_gf256_multiply(divisor[j], root)

			if j + 1 < ecc_size {
				divisor[j] ~= divisor[j + 1]
			}
		}

		root = qr_gf256_multiply(root, 2)
	}

	at := 0

	for block in 0 ..< blocks {
		size := short_data_size + (block < short_blocks ? 0 : 1)
		ecc: [30]u8

		for value in data[at:at + size] {
			factor := value ~ ecc[0]
			for j in 0 ..< ecc_size - 1 {
				ecc[j] = ecc[j + 1]
			}
			ecc[ecc_size - 1] = 0
			for j in 0 ..< ecc_size {
				ecc[j] ~= qr_gf256_multiply(divisor[j], factor)
			}
		}

		for j, k := 0, block; j < size; j, k = j + 1, k + blocks {
			index := k
			if j == short_data_size {
				index -= short_blocks
			}

			result[index] = data[at + j]
		}

		for j, k := 0, data_size + block; j < ecc_size; j, k = j + 1, k + blocks {
			result[k] = ecc[j]
		}

		at += size
	}
}

qr_set_function :: proc(code: ^QR_Code, functions: ^[QR_MAX_SIZE * QR_MAX_SIZE]bool, x, y: int, dark: bool) {
	if x < 0 || y < 0 || x >= code.size || y >= code.size {
		return
	}

	index := y * code.size + x
	code.modules[index], functions[index] = dark, true
}
qr_draw_function_patterns :: proc(code: ^QR_Code, functions: ^[QR_MAX_SIZE * QR_MAX_SIZE]bool) {
	for i in 0 ..< code.size {
		qr_set_function(code, functions, 6, i, i % 2 == 0)
		qr_set_function(code, functions, i, 6, i % 2 == 0)
	}

	for center in ([3][2]int{{3, 3}, {code.size - 4, 3}, {3, code.size - 4}}) {
		for dy in -4 ..= 4 {
			for dx in -4 ..= 4 {
				dist := max(abs(dx), abs(dy))
				qr_set_function(code, functions, center[0] + dx, center[1] + dy, dist != 2 && dist != 4)
			}
		}
	}

	if code.version > 1 {
		count := code.version / 7 + 2
		step := (code.version * 8 + count * 3 + 5) / (count * 4 - 4) * 2
		positions: [7]int
		positions[0] = 6

		for i, pos := count - 1, code.version * 4 + 10; i >= 1; i, pos = i - 1, pos - step {
			positions[i] = pos
		}

		for i in 0 ..< count {
			for j in 0 ..< count {
				if i == 0 && j == 0 || i == 0 && j == count - 1 || i == count - 1 && j == 0 {
					continue
				}

				for dy in -2 ..= 2 {
					for dx in -2 ..= 2 {
						qr_set_function(
							code,
							functions,
							positions[i] + dx,
							positions[j] + dy,
							max(abs(dx), abs(dy)) != 1,
						)
					}
				}
			}
		}
	}

	qr_write_format_bits(code, functions, 0)

	if code.version >= 7 {
		remainder := code.version
		for _ in 0 ..< 12 {
			remainder = (remainder << 1) ~ ((remainder >> 11) * 0x1f25)
		}
		bits := code.version << 12 | remainder

		for i in 0 ..< 18 {
			a, b := code.size - 11 + i % 3, i / 3
			dark := (bits >> cast(uint)i) & 1 != 0
			qr_set_function(code, functions, a, b, dark)
			qr_set_function(code, functions, b, a, dark)
		}
	}
}
qr_write_format_bits :: proc(code: ^QR_Code, functions: ^[QR_MAX_SIZE * QR_MAX_SIZE]bool, mask: int) {
	data := 1 << 3 | mask // ECC-L format selector = 1.
	remainder := data
	for _ in 0 ..< 10 {
		remainder = (remainder << 1) ~ ((remainder >> 9) * 0x537)
	}
	bits := (data << 10 | remainder) ~ 0x5412
	for i in 0 ..< 6 {
		qr_set_function(code, functions, 8, i, (bits >> cast(uint)i) & 1 != 0)
	}
	qr_set_function(code, functions, 8, 7, (bits >> 6) & 1 != 0)
	qr_set_function(code, functions, 8, 8, (bits >> 7) & 1 != 0)
	qr_set_function(code, functions, 7, 8, (bits >> 8) & 1 != 0)
	for i in 9 ..< 15 {
		qr_set_function(code, functions, 14 - i, 8, (bits >> cast(uint)i) & 1 != 0)
	}

	for i in 0 ..< 8 {
		qr_set_function(code, functions, code.size - 1 - i, 8, (bits >> cast(uint)i) & 1 != 0)
	}

	for i in 8 ..< 15 {
		qr_set_function(code, functions, 8, code.size - 15 + i, (bits >> cast(uint)i) & 1 != 0)
	}

	qr_set_function(code, functions, 8, code.size - 8, true)
}
qr_apply_data_mask :: proc(code: ^QR_Code, functions: ^[QR_MAX_SIZE * QR_MAX_SIZE]bool, mask: int) {
	for y in 0 ..< code.size {
		for x in 0 ..< code.size {
			index := y * code.size + x
			if functions[index] {
				continue
			}

			invert := false

			switch mask {
			case 0:
				invert = (x + y) % 2 == 0
			case 1:
				invert = y % 2 == 0
			case 2:
				invert = x % 3 == 0
			case 3:
				invert = (x + y) % 3 == 0
			case 4:
				invert = (x / 3 + y / 2) % 2 == 0
			case 5:
				invert = x * y % 2 + x * y % 3 == 0
			case 6:
				invert = (x * y % 2 + x * y % 3) % 2 == 0
			case 7:
				invert = ((x + y) % 2 + x * y % 3) % 2 == 0
			}

			code.modules[index] = code.modules[index] != invert
		}
	}
}
qr_penalty :: proc(code: ^QR_Code) -> int {
	score := 0

	for direction in 0 ..< 2 {
		for fixed in 0 ..< code.size {
			color := false
			run := 0
			history: [7]int

			for moving in 0 ..< code.size {
				x, y := moving, fixed
				if direction == 1 {
					x, y = y, x
				}

				current := qr_module_is_dark(code, x, y)

				if current == color {
					run += 1

					if run == 5 {
						score += 3
					} else if run > 5 {
						score += 1
					}
				} else {
					qr_history_add(&history, run, code.size)

					if !color {
						score += qr_history_patterns(&history) * 40
					}

					color, run = current, 1
				}
			}

			if color {
				qr_history_add(&history, run, code.size)
				run = 0
			}

			qr_history_add(&history, run + code.size, code.size)
			score += qr_history_patterns(&history) * 40
		}
	}

	dark := 0

	for y in 0 ..< code.size {
		for x in 0 ..< code.size {
			c := qr_module_is_dark(code, x, y)
			if c {
				dark += 1
			}

			if x + 1 < code.size &&
			   y + 1 < code.size &&
			   c == qr_module_is_dark(code, x + 1, y) &&
			   c == qr_module_is_dark(code, x, y + 1) &&
			   c == qr_module_is_dark(code, x + 1, y + 1) {
				score += 3
			}
		}
	}

	total := code.size * code.size
	score += ((abs(dark * 20 - total * 10) + total - 1) / total - 1) * 10

	return score
}
qr_history_add :: proc(history: ^[7]int, run, size: int) {
	value := run
	if history[0] == 0 {
		value += size
	}

	for i := 6; i > 0; i -= 1 {
		history[i] = history[i - 1]
	}
	history[0] = value
}
qr_history_patterns :: proc(h: ^[7]int) -> int {
	n := h[1]
	core := n > 0 && h[2] == n && h[3] == n * 3 && h[4] == n && h[5] == n

	return (core && h[0] >= n * 4 && h[6] >= n ? 1 : 0) + (core && h[6] >= n * 4 && h[0] >= n ? 1 : 0)
}

// The service worker at web.whatsapp.com publishes client_revision. The
// handshake triple is 2.3000 plus that revision. The compiled pin is used
// only when that request fails. An explicit caller version bypasses this.
WA_WEB_VERSION_URL :: "https://web.whatsapp.com/sw.js"
WA_WEB_VERSION_BODY_MAX :: 4 << 20
WA_WEB_VERSION_MAJOR :: 2
WA_WEB_VERSION_MINOR :: 3000
CLIENT_REVISION_KEY :: "client_revision"
WA_WEB_USER_AGENT ::
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " + "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
Web_Version_Source :: enum {
	WhatsApp,
	Pinned, // the compiled WA_WEB_VERSION_PINNED
	Configured, // the caller's fallback
}
Version_Error_Kind :: enum {
	None,
	HTTP_Failed,
	HTTP_Status,
	Body_Oversized,
	Missing_Version,
	Invalid_Version,
}
Version_Error :: struct {
	kind:   Version_Error_Kind,
	http:   network_client.HTTP_Error,
	status: int,
}
Web_Version_Result :: struct {
	version:     [3]u32,
	source:      Web_Version_Source,
	fetch_error: Version_Error,
}
// A callback transfers ownership of its Response to discovery, which always
// destroys it. This seam permits deterministic/offline fixture tests.
Version_Fetcher :: struct {
	data: rawptr,
	get:  proc(
		data: rawptr,
		url: string,
		config: network_client.Config,
	) -> (
		network_client.Response,
		network_client.HTTP_Error,
	),
}

// A failed fetch keeps the fallback (a zero fallback = the compiled pin).
// Callers report fetch_error. An explicit caller version bypasses this function.
web_version_discover :: proc(
	config: network_client.Config,
	fetcher: Version_Fetcher = {},
	fallback: [3]u32 = {},
) -> (
	result: Web_Version_Result,
) {
	settings := config
	if settings.max_body_size <= 0 || settings.max_body_size > WA_WEB_VERSION_BODY_MAX {
		settings.max_body_size = WA_WEB_VERSION_BODY_MAX
	}
	get := fetcher.get
	if get == nil {
		get = version_fetch_http
	}

	result.version = WA_WEB_VERSION_PINNED
	result.source = .Pinned

	if fallback != ([3]u32{}) {
		result.version = fallback
		result.source = .Configured
	}

	response, he := get(fetcher.data, WA_WEB_VERSION_URL, settings)
	defer network_client.response_destroy(&response)
	if he.kind != .None {
		result.fetch_error = {
			kind = .HTTP_Failed,
			http = he,
		}

		return result
	}
	if response.status != 200 {
		result.fetch_error = {
			kind   = .HTTP_Status,
			status = response.status,
		}

		return result
	}
	if len(response.body) > settings.max_body_size {
		result.fetch_error = {
			kind = .Body_Oversized,
		}

		return result
	}
	revision, err := web_version_revision(response.body)
	if err.kind != .None {
		result.fetch_error = err
		return result
	}
	result.version = {WA_WEB_VERSION_MAJOR, WA_WEB_VERSION_MINOR, revision}
	result.source = .WhatsApp
	return result
}

// Parse only an exact named unsigned literal, in normal or singly escaped
// quotes. Conflicting repeated literals are ambiguous and retain the tested pin.
// This bounded scanner does not execute or interpret the worker's JavaScript.
web_version_revision :: proc(src: []u8) -> (revision: u32, err: Version_Error) {
	if len(src) > WA_WEB_VERSION_BODY_MAX {
		return 0, {kind = .Body_Oversized}
	}

	key := CLIENT_REVISION_KEY

	if len(src) < len(key) + 4 {
		return 0, {kind = .Missing_Version}
	}

	found := false
	last := len(src) - len(key)

	for i in 0 ..= last {
		matches, escaped := match_client_revision_key_at(src, i)
		if !matches {
			continue
		}
		value, ok, invalid := parse_client_revision_digits(src, i + len(key), escaped)
		if invalid {
			return 0, {kind = .Invalid_Version}
		}
		if !ok {
			continue
		}
		if found && revision != value {
			return 0, {kind = .Invalid_Version}
		}
		revision = value
		found = true
	}

	if found {
		return revision, {}
	}

	return 0, {kind = .Missing_Version}
}

match_client_revision_key_at :: proc(src: []u8, i: int) -> (matches, escaped: bool) {
	key := CLIENT_REVISION_KEY
	if i < 1 || i + len(key) > len(src) {
		return false, false
	}
	if src[i - 1] != '"' {
		return false, false
	}
	for c, n in key {
		if src[i + n] != cast(u8)c {
			return false, false
		}
	}
	after := i + len(key)

	if after < len(src) && src[after] != '"' && src[after] != '\\' {
		return false, false // A longer property name is not this key.
	}

	escaped = i >= 2 && src[i - 2] == '\\'
	// More escaping layers are outside this literal format.
	if escaped && i >= 3 && src[i - 3] == '\\' {
		return false, false
	}

	return true, escaped
}

parse_client_revision_digits :: proc(src: []u8, at: int, escaped: bool) -> (value: u32, ok, invalid: bool) {
	i := at

	if escaped {
		if i >= len(src) || src[i] != '\\' {
			return 0, false, true
		}
		i += 1
	}

	if i >= len(src) || src[i] != '"' {
		return 0, false, true
	}
	i += 1
	for i < len(src) && revision_space(src[i]) {
		i += 1
	}
	if i >= len(src) || src[i] != ':' {
		return 0, false, false
	}
	i += 1
	for i < len(src) && revision_space(src[i]) {
		i += 1
	}
	start := i

	for i < len(src) && i - start < 10 && is_digit(src[i]) {
		i += 1
	}

	if i == start {
		return 0, false, true
	}
	if i < len(src) && is_digit(src[i]) {
		return 0, false, true
	}
	end := i
	for i < len(src) && revision_space(src[i]) {
		i += 1
	}

	if i >= len(src) || (src[i] != ',' && src[i] != '}') {
		return 0, false, true // Numeric prefixes and incomplete literals are refused.
	}

	n, valid := strconv.parse_u64(cast(string)src[start:end], 10)

	if !valid || n == 0 || n > cast(u64)max(u32) {
		return 0, false, true
	}

	return cast(u32)n, true, false
}

revision_space :: proc(c: u8) -> bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

web_version_parse :: proc(text: string) -> (version: [3]u32, err: Version_Error_Kind) {
	if len(text) < 5 || len(text) > 32 {
		return {}, .Invalid_Version
	}

	at := 0

	for component in 0 ..< 3 {
		end := len(text)

		if component < 2 {
			dot := strings.index_byte(text[at:], '.')
			if dot < 0 {
				return {}, .Invalid_Version
			}

			end = at + dot
		}

		if end == at {
			return {}, .Invalid_Version
		}

		for c in text[at:end] {
			if !is_digit(c) {
				return {}, .Invalid_Version
			}
		}

		n, valid := strconv.parse_u64(text[at:end], 10)

		if !valid || n > cast(u64)max(u32) {
			return {}, .Invalid_Version
		}

		version[component] = cast(u32)n
		at = end + 1
	}

	if version == ([3]u32{}) {
		return {}, .Invalid_Version
	}

	return version, .None
}
version_fetch_http :: proc(
	data: rawptr,
	url: string,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	headers := [2]http.Header {
		{name = "User-Agent", value = WA_WEB_USER_AGENT},
		{name = "Sec-Fetch-Site", value = "none"},
	}
	return network_client.execute({url = url, headers = headers[:]}, config)
}

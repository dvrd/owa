package whatsapp_test

import "core:crypto"
import "core:crypto/hmac"
import "core:mem"
import "core:strings"
import "core:testing"
import "core:time"
import test_fixtures "../fixtures/client"
import "shared:async/http"
import "shared:surf"
import wa "shared:whatsapp"

@(test)
pairing_observer_receives_application_events :: proc(t: ^testing.T) {
	count: int
	observer: wa.Pairing_Observer = proc(data: rawptr, event: wa.Pairing_Event) {
		(cast(^int)data)^ += 1 if event.kind == .QR && event.qr == "qr" else 0
	}

	observer(&count, {kind = .QR, qr = "qr"})

	observer(&count, {kind = .Online})

	testing.expect_value(t, count, 1)
}

Official_Version_Peer :: struct {
	calls: int,
	url:   string,
}

official_version_peer_get :: proc(
	data: rawptr,
	url: string,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	peer := cast(^Official_Version_Peer)data
	peer.calls += 1
	peer.url = url
	return {status = 200, body = transmute([]u8)string(`self.cfg={"client_revision":1234567890};`)}, {}
}

@(test)
official_version_discovery_does_not_use_third_party_feeds :: proc(t: ^testing.T) {
	peer: Official_Version_Peer
	result := wa.web_version_discover({}, {data = &peer, get = official_version_peer_get})

	testing.expect_value(t, peer.calls, 1)
	testing.expect_value(t, peer.url, "https://web.whatsapp.com/sw.js")
	testing.expect_value(t, result.version, [3]u32{2, 3000, 1234567890})

	testing.expect(t, result.source != .Pinned)
}

// Owned synthetic identities only. The signing and HMAC domains here are
// independent literal expectations from the immutable upstream declaration.
Pairing_Domain_Fixture :: struct {
	credentials:            wa.Device_Credentials,
	account_private:        [32]u8,
	details:                [64]u8,
	details_size:           int,
	identity:               [512]u8,
	identity_size:          int,
	wrapper:                [1024]u8,
	wrapper_size:           int,
	iq_attrs, device_attrs: [1]wa.Binary_Node_Attribute,
	iq_children:            [1]wa.Binary_Node,
	pair_children:          [2]wa.Binary_Node,
}

pairing_domain_field :: proc(dst: []u8, at: ^int, number: u64, value: []u8) {
	wa.protobuf_varint_write(dst, at, number << 3 | 2)
	wa.protobuf_varint_write(dst, at, u64(len(value)))
	at^ += copy(dst[at^:], value)
}

pairing_domain_fixture :: proc(
	wrapper_type: u32,
	device_type: int,
	account_domain: u8 = 255,
) -> ^Pairing_Domain_Fixture {
	f := new(Pairing_Domain_Fixture)
	error: wa.Credentials_Error
	f.credentials, error = wa.device_credentials_generate()
	assert(error == .None)
	for &b, i in f.account_private {
		b = u8(i + 129)
	}

	f.account_private[0] &= 248
	f.account_private[31] = f.account_private[31] & 127 | 64
	// rawId=42, timestamp=1, keyIndex=7; deviceType absent is ordinary default.
	copy(f.details[:], []u8{8, 42, 16, 1, 24, 7})

	f.details_size = 6
	if device_type >= 0 {
		f.details[6], f.details[7] = 40, u8(device_type)
		f.details_size = 8
	}

	prefix := account_domain
	if prefix == 255 {
		prefix = device_type == 1 ? 5 : 0
	}

	account_key := wa.signal_curve_public(f.account_private)
	identity_key := wa.signal_curve_public(f.credentials.identity_private)
	signed: [128]u8
	signed[0], signed[1] = 6, prefix
	copy(signed[2:], f.details[:f.details_size])
	copy(signed[2 + f.details_size:], identity_key[:])
	signature, sign_error := wa.signal_curve_sign(f.account_private, signed[:2 + f.details_size + 32])
	assert(sign_error == .None)
	at := 0
	pairing_domain_field(f.identity[:], &at, 1, f.details[:f.details_size])
	pairing_domain_field(f.identity[:], &at, 2, account_key[:])
	pairing_domain_field(f.identity[:], &at, 3, signature[:])
	f.identity_size = at
	mac: [32]u8
	mac_context: hmac.Context
	hmac.init(&mac_context, .SHA256, f.credentials.adv_secret[:])
	if wrapper_type == 1 {
		hmac.update(&mac_context, []u8{6, 5})
	}

	hmac.update(&mac_context, f.identity[:f.identity_size])
	hmac.final(&mac_context, mac[:])
	crypto.zero_explicit(&mac_context, size_of(mac_context))
	at = 0
	pairing_domain_field(f.wrapper[:], &at, 1, f.identity[:f.identity_size])
	pairing_domain_field(f.wrapper[:], &at, 2, mac[:])
	wa.protobuf_varint_write(f.wrapper[:], &at, 3 << 3)
	wa.protobuf_varint_write(f.wrapper[:], &at, u64(wrapper_type))
	f.wrapper_size = at
	f.device_attrs = {{"jid", "123:4@s.whatsapp.net"}}

	f.iq_attrs = {{"id", "synthetic-pair"}}

	f.pair_children = {
		{tag = "device-identity", content = f.wrapper[:f.wrapper_size]},
		{tag = "device", attrs = f.device_attrs[:]},
	}

	f.iq_children = {{tag = "pair-success", content = f.pair_children[:]}}

	return f
}

pairing_domain_iq :: proc(f: ^Pairing_Domain_Fixture) -> wa.Binary_Node {
	return {tag = "iq", attrs = f.iq_attrs[:], content = f.iq_children[:]}
}

pairing_domain_free :: proc(f: ^Pairing_Domain_Fixture) {
	crypto.zero_explicit(f, size_of(Pairing_Domain_Fixture))
	free(f)
}

pairing_domain_companion_verify :: proc(
	account: ^wa.Paired_Account,
	credentials: ^wa.Device_Credentials,
	domain: u8,
) -> wa.Signal_Error {
	public := wa.signal_curve_public(credentials.identity_private)
	message: [2 + wa.MAX_PAIRING_DETAILS_SIZE + 64]u8
	message[0], message[1] = 6, domain
	copy(message[2:], account.details[:account.details_size])
	copy(message[2 + account.details_size:], public[:])
	copy(message[2 + account.details_size + 32:], account.account_signature_key[:])
	return wa.signal_curve_verify(public, message[:2 + account.details_size + 64], account.device_signature[:])
}

@(test)
pairing_current_domains_follow_signed_device_type_independent_of_wrapper :: proc(t: ^testing.T) {
	for wrapper in 0 ..< 2 {
		for device in ([]int{-1, 0, 1}) {
			f := pairing_domain_fixture(u32(wrapper), device)
			defer pairing_domain_free(f)

			account: wa.Paired_Account
			reply: [2048]u8
			_, error := wa.pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
			testing.expect_value(t, error.kind, .None)

			if error.kind != .None {
				continue
			}

			testing.expect_value(t, pairing_domain_companion_verify(&account, &f.credentials, 1), .None)
			testing.expect(t, pairing_domain_companion_verify(&account, &f.credentials, 6) != .None)
			testing.expect_value(t, wa.paired_account_validate(&account, &f.credentials).kind, .None)
		}
	}
}

pairing_domain_legacy_account :: proc(f: ^Pairing_Domain_Fixture, hosted: bool) -> wa.Paired_Account {
	identity, error := wa.pairing_signed_identity_decode(f.identity[:f.identity_size])
	assert(error == .None)
	account := wa.Paired_Account {
		valid            = true,
		hosted           = hosted,
		key_index        = 7,
		signature_policy = .Legacy,
		jid_size         = len("123:4@s.whatsapp.net"),
		details_size     = f.details_size,
	}

	copy(account.jid[:], "123:4@s.whatsapp.net")
	copy(account.details[:], f.details[:f.details_size])
	copy(account.account_signature_key[:], identity.account_signature_key)
	copy(account.account_signature[:], identity.account_signature)
	public := wa.signal_curve_public(f.credentials.identity_private)
	message: [128]u8
	message[0], message[1] = 6, hosted ? 6 : 1
	copy(message[2:], f.details[:f.details_size])
	copy(message[2 + f.details_size:], public[:])
	copy(message[2 + f.details_size + 32:], account.account_signature_key[:])
	sign_error: wa.Signal_Error
	account.device_signature, sign_error = wa.signal_curve_sign(
		f.credentials.identity_private,
		message[:2 + f.details_size + 64],
	); assert(sign_error == .None)

	return account
}

@(test)
pairing_current_rejects_wrong_domains_unknown_types_and_tampered_identity :: proc(t: ^testing.T) {
	for scenario in 0 ..< 6 {
		// Domain0 over hosted-declared details is valid under the legacy policy,
		// never an alternate acceptance path for new pairing.
		f := pairing_domain_fixture(0, 1, scenario == 0 ? 0 : 5)
		defer pairing_domain_free(f)

		if scenario == 1 {
			f.wrapper[f.wrapper_size - 1] = 2 // wrapper accountType checked before HMAC.
		}

		if scenario == 2 {
			bad := pairing_domain_fixture(0, 2)
			defer pairing_domain_free(bad)

			account: wa.Paired_Account
			reply: [2048]u8
			_, error := wa.pairing_success_handle(&account, pairing_domain_iq(bad), &bad.credentials, reply[:])
			testing.expect_value(t, error.kind, .Invalid_Account_Type)
			testing.expect(t, !account.valid)
			continue
		}

		if scenario == 3 {
			f.wrapper[f.wrapper_size - 4] ~= 1
		} // HMAC bytes.

		if scenario == 4 {
			f.wrapper[5] ~= 1
		} // Signed details without matching HMAC.

		if scenario == 5 {
			f.credentials.adv_secret[0] ~= 1
		}

		target: wa.Paired_Account
		target.jid[0] = 0xa5
		reply: [2048]u8

		for &b in reply {
			b = 0xa5
		}

		_, error := wa.pairing_success_handle(&target, pairing_domain_iq(f), &f.credentials, reply[:])
		testing.expect(t, error.kind != .None)
		testing.expect(t, !target.valid && target.jid[0] == 0xa5)

		for b in reply {
			testing.expect_value(t, b, u8(0xa5))
		}
	}
}

@(test)
pairing_current_persisted_identity_rejects_tampering_and_legacy_companion_domain :: proc(t: ^testing.T) {
	f := pairing_domain_fixture(1, 1)
	defer pairing_domain_free(f)

	account: wa.Paired_Account
	reply: [2048]u8
	_, error := wa.pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
	assert(error.kind == .None)

	for scenario in 0 ..< 5 {
		changed := account

		switch scenario {
		case 0:
			changed.account_signature[0] ~= 1
		case 1:
			changed.account_signature_key[0] ~= 1
		case 2:
			changed.device_signature[0] ~= 1
		case 3:
			changed.details[1] ~= 1
		case 4:
			public := wa.signal_curve_public(f.credentials.identity_private)
			message: [128]u8
			message[0], message[1] = 6, 6
			copy(message[2:], changed.details[:changed.details_size])
			copy(message[2 + changed.details_size:], public[:])
			copy(message[2 + changed.details_size + 32:], changed.account_signature_key[:])
			sign_error: wa.Signal_Error
			changed.device_signature, sign_error = wa.signal_curve_sign(
				f.credentials.identity_private,
				message[:2 + changed.details_size + 64],
			); assert(sign_error == .None)
		}

		testing.expect(t, wa.paired_account_validate(&changed, &f.credentials).kind != .None)
	}
}

@(test)
linked_device_qr_matches_observed_url_and_companion_field :: proc(t: ^testing.T) {
	zero: [32]u8
	buffer: [2048]u8
	size, error := wa.pairing_qr_encode(
		buffer[:],
		"synthetic-ref",
		zero,
		zero,
		zero,
		.Linked_Device,
		"Ubuntu",
		"Chrome",
	)

	expected :=
		"https://wa.me/settings/linked_devices#synthetic-ref," +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=," +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=," +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,1"
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, string(buffer[:size]), expected)
}

@(test)
linked_device_qr_companion_mapping_and_legacy_default_are_distinct :: proc(t: ^testing.T) {
	cases := [11]struct {
		os, browser, suffix: string,
	} {
		{"Ubuntu", "Chrome", ",1"},
		{"Ubuntu", "Edge", ",2"},
		{"Ubuntu", "Firefox", ",3"},
		{"Ubuntu", "IE", ",4"},
		{"Ubuntu", "Opera", ",5"},
		{"Mac OS", "Safari", ",6"},
		{"Windows", "Desktop", ",8"},
		{"Mac OS", "Desktop", ",7"},
		{"Linux", "Desktop", ",7"},
		{"Ubuntu", "Other", ",9"},
		{"Ubuntu", "chrome", ",9"},
	}

	keys: [3][32]u8
	keys[0][0], keys[1][0], keys[2][0] = 1, 2, 3
	legacy, explicit, linked: [wa.MAX_PAIRING_QR_SIZE]u8
	legacy_size, legacy_error := wa.pairing_qr_encode(legacy[:], "reference", keys[0], keys[1], keys[2])
	assert(legacy_error.kind == .None)

	for item in cases {
		size, error := wa.pairing_qr_encode(
			linked[:],
			"reference",
			keys[0],
			keys[1],
			keys[2],
			.Linked_Device,
			item.os,
			item.browser,
		)
		assert(error.kind == .None)
		testing.expect_value(t, size, legacy_size + len(wa.PAIRING_LINKED_DEVICE_QR_PREFIX) + 2)
		testing.expect_value(t, string(linked[:len(wa.PAIRING_LINKED_DEVICE_QR_PREFIX)]), wa.PAIRING_LINKED_DEVICE_QR_PREFIX)
		testing.expect_value(
			t,
			string(linked[len(wa.PAIRING_LINKED_DEVICE_QR_PREFIX):size - 2]),
			string(legacy[:legacy_size]),
		)
		testing.expect_value(t, string(linked[size - 2:size]), item.suffix)
		explicit_size, explicit_error := wa.pairing_qr_encode(
			explicit[:],
			"reference",
			keys[0],
			keys[1],
			keys[2],
			.Legacy,
			item.os,
			item.browser,
		)
		testing.expect_value(t, explicit_error.kind, .None)
		testing.expect_value(t, string(explicit[:explicit_size]), string(legacy[:legacy_size]))
	}
}

@(test)
linked_device_qr_bounds_errors_and_borrowed_reference_are_atomic :: proc(t: ^testing.T) {
	keys: [3][32]u8
	reference: [wa.MAX_PAIRING_REF_SIZE]u8

	for &value in reference {
		value = 'r'
	}

	size, error := wa.pairing_qr_encode(nil, string(reference[:]), keys[0], keys[1], keys[2], .Linked_Device)
	testing.expect_value(t, error.kind, .Destination_Undersized)
	testing.expect_value(t, size, wa.MAX_PAIRING_QR_SIZE)
	buffer: [wa.MAX_PAIRING_QR_SIZE + 1]u8

	for &value in buffer {
		value = 0x7f
	}

	short_size, short_error := wa.pairing_qr_encode(
		buffer[:size - 1],
		string(reference[:]),
		keys[0],
		keys[1],
		keys[2],
		.Linked_Device,
	)
	testing.expect_value(t, short_size, size)
	testing.expect_value(t, short_error.kind, .Destination_Undersized)

	for value in buffer {
		testing.expect_value(t, value, u8(0x7f))
	}

	written, valid := wa.pairing_qr_encode(buffer[:size], string(reference[:]), keys[0], keys[1], keys[2], .Linked_Device)
	testing.expect_value(t, valid.kind, .None)
	testing.expect_value(t, written, size)
	testing.expect_value(t, buffer[size], u8(0x7f))

	for ref in ([]string{"", "bad,reference", "bad\nreference"}) {
		for &value in buffer {
			value = 0x7f
		}

		_, invalid := wa.pairing_qr_encode(buffer[:], ref, keys[0], keys[1], keys[2], .Linked_Device)
		testing.expect_value(t, invalid.kind, .Invalid_Ref)

		for value in buffer {
			testing.expect_value(t, value, u8(0x7f))
		}
	}

	_, invalid_format := wa.pairing_qr_encode(buffer[:], "reference", keys[0], keys[1], keys[2], wa.Pairing_QR_Format(255))
	testing.expect_value(t, invalid_format.kind, .Invalid_QR_Format)

	for value in buffer {
		testing.expect_value(t, value, u8(0x7f))
	}

	// Prefix writing must not overwrite a reference borrowed from the destination.
	copy(buffer[:], "borrowed-ref")
	alias_size, alias_error := wa.pairing_qr_encode(
		buffer[:],
		string(buffer[:12]),
		keys[0],
		keys[1],
		keys[2],
		.Linked_Device,
	)
	testing.expect_value(t, alias_error.kind, .None)
	testing.expect_value(
		t,
		string(buffer[len(wa.PAIRING_LINKED_DEVICE_QR_PREFIX):len(wa.PAIRING_LINKED_DEVICE_QR_PREFIX) + 12]),
		"borrowed-ref",
	)
	testing.expect_value(t, alias_size, len(wa.PAIRING_LINKED_DEVICE_QR_PREFIX) + 12 + 3 * 44 + 3 + 2)
}

@(test)
linked_device_qr_failed_encoding_does_not_consume_reference :: proc(t: ^testing.T) {
	state := wa.Pairing_QR_State {
		initialized        = true,
		count              = 2,
		initial_timeout    = time.Minute,
		subsequent_timeout = 20 * time.Second,
	}

	copy(state.refs[0][:], "first")
	state.ref_sizes[0] = 5
	copy(state.refs[1][:], "second")
	state.ref_sizes[1] = 6
	now := time.Time{}

	_, short := wa.pairing_qr_next(&state, now, nil, .Linked_Device)
	testing.expect_value(t, short.kind, .Destination_Undersized)
	testing.expect_value(t, state.next, 0)
	testing.expect_value(t, state.next_at._nsec, i64(0))
	buffer: [wa.MAX_PAIRING_QR_SIZE]u8
	_, invalid := wa.pairing_qr_next(&state, now, buffer[:], wa.Pairing_QR_Format(255))
	testing.expect_value(t, invalid.kind, .Invalid_QR_Format)
	testing.expect_value(t, state.next, 0)

	for index in 0 ..< 2 {
		count, error := wa.pairing_qr_next(&state, now, buffer[:], .Linked_Device, "Windows", "Desktop")
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, state.next, index + 1)
		testing.expect_value(t, string(buffer[count - 2:count]), ",8")

		if index == 0 {
			testing.expect_value(t, state.next_at._nsec, time.time_add(now, time.Minute)._nsec)
		} else {
			testing.expect_value(t, state.next_at._nsec, time.time_add(now, 20 * time.Second)._nsec)
		}

		now = state.next_at
	}

	_, expired := wa.pairing_qr_next(&state, now, buffer[:], .Linked_Device)
	testing.expect_value(t, expired.kind, .QR_Expired)
}

QR_Profile_Fixture :: struct {
	socket:  wa.Socket,
	auth:    wa.Auth_State,
	prekeys: wa.Prekey_Store,
	store:   wa.State_Store,
	wire:    test_fixtures.Send_Id_Wire,
}

qr_profile_fixture :: proc() -> ^QR_Profile_Fixture {
	f := new(QR_Profile_Fixture)
	credentials, error := wa.device_credentials_generate()
	assert(error == .None)
	f.auth.credentials = credentials
	assert(wa.prekey_store_init(&f.prekeys, &f.auth.credentials).kind == .None)
	assert(wa.state_store_init(&f.store, wa.signal_curve_public(f.auth.credentials.identity_private)).kind == .None)
	test_fixtures.send_id_wire_connect(&f.socket, &f.wire)
	f.socket.client.static_public = wa.signal_curve_public(f.auth.credentials.noise_private)
	f.socket.client.phase = .Initialized

	return f
}

qr_profile_destroy :: proc(f: ^QR_Profile_Fixture) {
	wa.frame_transport_clear(&f.socket.client.frames)
	wa.state_store_clear(&f.store)
	wa.prekey_store_clear(&f.prekeys)
	wa.device_credentials_clear(&f.auth.credentials)
	free(f)
}

@(test)
linked_device_qr_session_initial_and_timer_events_honor_selected_format :: proc(t: ^testing.T) {
	for format in ([]wa.Pairing_QR_Format{.Legacy, .Linked_Device}) {
		f := qr_profile_fixture()
		defer qr_profile_destroy(f)

		config := wa.Session_Config {
			payload   = wa.default_client_payload_config(),
			qr_write_format_bits = format,
		}

		config.payload.browser_os = "Windows"
		config.payload.browser_name = "Desktop"
		testing.expect_value(t, wa.session_init(&f.socket.session, &f.socket.client, &f.auth, config).kind, .None)
		f.socket.client.phase = .Noise_Ready
		f.socket.session.phase = .Awaiting_Pairing
		now := time.Time{}

		f.socket.session.last_received = now
		f.socket.session.next_ping = time.time_add(now, time.Hour)
		refs := [2]wa.Binary_Node {
			{tag = "ref", content = []u8{'f', 'i', 'r', 's', 't'}},
			{tag = "ref", content = []u8{'s', 'e', 'c', 'o', 'n', 'd'}},
		}

		pair := [1]wa.Binary_Node{{tag = "pair-device", content = refs[:]}}

		attrs := [2]wa.Binary_Node_Attribute{{"type", "set"}, {"id", "synthetic-pair"}}

		event, error := wa.session_pair_device(&f.socket.session, {tag = "iq", attrs = attrs[:], content = pair[:]}, now)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .QR)
		testing.expect(
			t,
			strings.has_prefix(
				event.qr,
				format == .Linked_Device ? wa.PAIRING_LINKED_DEVICE_QR_PREFIX + "first," : "first,",
			),
		)

		if format == .Linked_Device {
			testing.expect(t, strings.has_suffix(event.qr, ",8"))
		}

		event, error = wa.session_tick(&f.socket.session, f.socket.session.qr_state.next_at)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .QR)
		testing.expect(
			t,
			strings.has_prefix(
				event.qr,
				format == .Linked_Device ? wa.PAIRING_LINKED_DEVICE_QR_PREFIX + "second," : "second,",
			),
		)

		if format == .Linked_Device {
			testing.expect(t, strings.has_suffix(event.qr, ",8"))
		}
	}
}

@(test)
linked_device_qr_invalid_configuration_is_rejected_before_initialization :: proc(t: ^testing.T) {
	f := qr_profile_fixture()
	defer qr_profile_destroy(f)

	f.socket.session.last_error.server_code = 123
	before := f.auth.credentials
	error := wa.session_init(
		&f.socket.session,
		&f.socket.client,
		&f.auth,
		{payload = wa.default_client_payload_config(), qr_write_format_bits = wa.Pairing_QR_Format(255)},
	)
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, f.socket.session.phase, .Uninitialized)
	testing.expect_value(t, f.socket.session.last_error.server_code, u32(123))
	testing.expect_value(t, f.socket.client.phase, .Initialized)
	testing.expect(t, f.auth.credentials == before)
	fresh := new(wa.Socket)
	defer free(fresh)

	socket_error := wa.socket_connect(
		fresh,
		&f.auth,
		&f.prekeys,
		&f.store,
		{prekey_path = "synthetic-prekeys", state_path = "synthetic-state", qr_write_format_bits = wa.Pairing_QR_Format(255)},
	)
	testing.expect_value(t, socket_error.kind, .Invalid_Config)
	testing.expect_value(t, fresh.phase, .Uninitialized)
	testing.expect(t, fresh.auth == nil && fresh.store == nil && fresh.prekeys == nil)
	testing.expect_value(t, fresh.websocket.phase, .Uninitialized)
}

@(test)
linked_device_qr_borrowed_profile_is_read_before_writing :: proc(t: ^testing.T) {
	keys: [3][32]u8
	buffer: [wa.MAX_PAIRING_QR_SIZE]u8
	copy(buffer[:], "WindowsDesktop")
	size, error := wa.pairing_qr_encode(
		buffer[:],
		"reference",
		keys[0],
		keys[1],
		keys[2],
		.Linked_Device,
		string(buffer[:7]),
		string(buffer[7:14]),
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, string(buffer[size - 2:size]), ",8")
}

Protocol_Ack_Capture :: struct {
	class:              wa.Protocol_Ack_Class,
	calls, children:    int,
	metadata_unchanged: bool,
}

protocol_ack_capture :: proc(data: rawptr, info: wa.Protocol_Node_Info) {
	capture := cast(^Protocol_Ack_Capture)data
	capture.calls += 1
	capture.class = info.ack_class
	capture.children = len(info.children)
	capture.metadata_unchanged =
		info.tag == "stream:error" &&
		info.kind == "private-top-type" &&
		len(info.children) == 1 &&
		info.children[0] == "ack"
}

@(test)
protocol_ack_observer_retains_only_fixed_class_after_document_release :: proc(t: ^testing.T) {
	for fixture in ([]struct {
			raw:   string,
			class: wa.Protocol_Ack_Class,
		} {
			{"message", .Message},
			{"receipt", .Receipt},
			{"notification", .Notification},
			{"status", .Status},
			{"call", .Call},
			{"private-unknown-class", .Other},
			{"", .Unknown},
		}) {
		capture: Protocol_Ack_Capture
		client: wa.Client
		auth: wa.Auth_State
		session := wa.Session {
			phase = .Login_Accepted,
			client = &client,
			auth = &auth,
			config = {observe_node = protocol_ack_capture, observer_data = &capture},
		}

		wire: [2048]u8
		count, encoded := wa.binary_node_encode(
			wire[:],
			{
				tag = "stream:error",
				attrs = {{"type", "private-top-type"}},
				content = []wa.Binary_Node {
					{
						tag = "ack",
						attrs = {{"class", fixture.raw}, {"type", "private-child-type"}, {"id", "private-stanza-id"}},
					},
				},
			},
		)
		assert(encoded.kind == .None)
		_, failure := wa.session_process(&session, wire[:count], time.now())
		testing.expect_value(t, failure.kind, .Server_Failure)
		for &byte in wire {
			byte = 0xa5
		}

		testing.expect_value(t, capture.class, fixture.class)
		testing.expect_value(t, capture.calls, 1)
		testing.expect(t, capture.metadata_unchanged)
	}
}

@(test)
protocol_ack_observer_limits_context_and_rejects_conflicting_classes :: proc(t: ^testing.T) {
	children: [33]wa.Binary_Node

	for &child in children {
		child = {
			tag = "private-child",
		}
	}

	children[32] = {
		tag   = "ack",
		attrs = {{"class", "status"}},
	}

	testing.expect_value(t, wa.session_stream_ack_class({tag = "stream:error", content = children[:]}), .Unknown)
	children[0] = {
		tag   = "ack",
		attrs = {{"class", "message"}},
	}

	testing.expect_value(t, wa.session_stream_ack_class({tag = "stream:error", content = children[:]}), .Unknown)
	testing.expect_value(t, wa.session_stream_ack_class({tag = "stream:error", content = children[:32]}), .Message)
	children[1] = {
		tag   = "ack",
		attrs = {{"class", "status"}},
	}

	testing.expect_value(t, wa.session_stream_ack_class({tag = "stream:error", content = children[:]}), .Unknown)
	testing.expect_value(t, wa.session_stream_ack_class({tag = "failure", content = children[:]}), .Unknown)
	testing.expect_value(t, wa.session_ack_class({attrs = {{"class", "status"}, {"class", "status"}}}), .Unknown)
	attrs: [33]wa.Binary_Node_Attribute
	attrs[0] = {"class", "status"}

	testing.expect_value(t, wa.session_ack_class({attrs = attrs[:]}), .Unknown)
}

codec_api_qr_blank :: proc() -> ^wa.QR_Code {
	code := new(wa.QR_Code)
	code.version = 1
	code.size = 21
	code.mask = 0

	return code
}

@(test)
qr_terminal_render_blank_code_is_a_white_quiet_field :: proc(t: ^testing.T) {
	code := codec_api_qr_blank()
	defer free(code)

	text, error := wa.qr_terminal_render(code)
	defer wa.qr_terminal_destroy(text)

	testing.expect_value(t, error, wa.QR_Error.None)

	width := code.size + wa.QR_QUIET_ZONE * 2
	row := strings.concatenate({"\x1b[30;47m", strings.repeat(" ", width, context.temp_allocator), "\x1b[0m\n"}, context.temp_allocator)
	rows := (width + 1) / 2
	testing.expect_value(t, rows, 15)
	testing.expect_value(t, text, strings.repeat(row, rows, context.temp_allocator))
}

@(test)
qr_terminal_render_pairs_vertical_modules_into_half_blocks :: proc(t: ^testing.T) {
	code := codec_api_qr_blank()
	defer free(code)

	// Row 2 of the output covers module rows 0 and 1 (four quiet rows above).
	code.modules[0 * code.size + 0] = true
	code.modules[1 * code.size + 1] = true
	code.modules[0 * code.size + 2] = true
	code.modules[1 * code.size + 2] = true
	// The final module row (20) is the top half of the last, odd, output row.
	code.modules[20 * code.size + 3] = true

	text, error := wa.qr_terminal_render(code)
	defer wa.qr_terminal_destroy(text)

	testing.expect_value(t, error, wa.QR_Error.None)

	lines := strings.split(text, "\n", context.temp_allocator)
	testing.expect_value(t, len(lines), 16)
	prefix := "\x1b[30;47m"
	suffix := "\x1b[0m"

	for line in lines[:15] {
		testing.expect(t, strings.has_prefix(line, prefix))
		testing.expect(t, strings.has_suffix(line, suffix))
	}

	body := lines[2][len(prefix):len(lines[2]) - len(suffix)]
	expected := strings.concatenate({"    ", "▀", "▄", "█", strings.repeat(" ", 29 - 7, context.temp_allocator)}, context.temp_allocator)
	testing.expect_value(t, body, expected)

	// Output row 12 starts at module row 20; row 14 is the pure quiet bottom.
	last := lines[12][len(prefix):len(lines[12]) - len(suffix)]
	testing.expect_value(t, last, strings.concatenate({"    ", "   ", "▀", strings.repeat(" ", 29 - 8, context.temp_allocator)}, context.temp_allocator))
}

@(test)
qr_terminal_render_matches_every_module_of_a_real_code :: proc(t: ^testing.T) {
	code, encode_error := wa.qr_encode("1@synthetic-reference,AAAA,BBBB,CCCC")
	testing.expect_value(t, encode_error, wa.QR_Error.None)
	text, error := wa.qr_terminal_render(&code)
	defer wa.qr_terminal_destroy(text)

	testing.expect_value(t, error, wa.QR_Error.None)

	width := code.size + wa.QR_QUIET_ZONE * 2
	rows := strings.split(text, "\n", context.temp_allocator)
	testing.expect_value(t, len(rows), (width + 1) / 2 + 1)

	for row, y in rows[:len(rows) - 1] {
		body := row[len("\x1b[30;47m"):len(row) - len("\x1b[0m")]
		x := 0

		for glyph in body {
			top := glyph == '▀' || glyph == '█'
			bottom := glyph == '▄' || glyph == '█'
			testing.expect_value(t, top, wa.qr_module_is_dark(&code, x - wa.QR_QUIET_ZONE, y * 2 - wa.QR_QUIET_ZONE))
			testing.expect_value(t, bottom, wa.qr_module_is_dark(&code, x - wa.QR_QUIET_ZONE, y * 2 - wa.QR_QUIET_ZONE + 1))
			x += 1
		}

		testing.expect_value(t, x, width)
	}
}

@(test)
qr_terminal_render_rejects_inconsistent_codes_and_destroy_honours_allocator :: proc(t: ^testing.T) {
	_, nil_error := wa.qr_terminal_render(nil)
	testing.expect_value(t, nil_error, wa.QR_Error.Invalid_Code)

	bad := codec_api_qr_blank()
	defer free(bad)

	bad.size = 25
	_, size_error := wa.qr_terminal_render(bad)
	testing.expect_value(t, size_error, wa.QR_Error.Invalid_Code)

	bad.size, bad.mask = 21, 8
	_, mask_error := wa.qr_terminal_render(bad)
	testing.expect_value(t, mask_error, wa.QR_Error.Invalid_Code)

	bad.mask, bad.version = 0, 41
	_, version_error := wa.qr_terminal_render(bad)
	testing.expect_value(t, version_error, wa.QR_Error.Invalid_Code)

	// The tracking allocator reports a leak if destroy used another allocator.
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)

	allocator := mem.tracking_allocator(&track)
	blank := codec_api_qr_blank()
	defer free(blank)

	text, error := wa.qr_terminal_render(blank, allocator)
	testing.expect_value(t, error, wa.QR_Error.None)
	wa.qr_terminal_destroy(text, allocator)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
whatsapp_version_worker_revision_requires_an_exact_unsigned_integer :: proc(t: ^testing.T) {
	for fixture in ([?]struct {
			body:     string,
			revision: u32,
		} {
			{`self.cfg={"client_revision":1234567890};`, 1234567890},
			{`"{\"client_revision\":4294967295}"`, max(u32)},
			{`{"client_revision": 1234 }`, 1234},
		}) {
		revision, error := wa.web_version_revision(transmute([]u8)fixture.body)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, revision, fixture.revision)
	}

	for body in ([?]string {
			`{"client_revision":0}`,
			`{"client_revision":-1}`,
			`{"client_revision":4294967296}`,
			`{"client_revision":12345678901}`,
			`{"client_revision":"1234"}`,
			`{"client_revision":1234.5}`,
			`{"client_revision":1234e2}`,
			`{"client_revision":1234abc}`,
			`{"other_revision":1234}`,
			`{"xclient_revision":1234}`,
			``,
		}) {
		_, error := wa.web_version_revision(transmute([]u8)body)
		testing.expect(t, error.kind != .None, body)
	}
}

Version_Test_Fetch :: struct {
	calls:         int,
	body:          string,
	status:        int,
	failure:       http.Error_Kind,
	url:           string,
	max_body_size: int,
}

version_test_fetch :: proc(
	data: rawptr,
	url: string,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	peer := cast(^Version_Test_Fetch)data
	peer.calls += 1
	peer.url, peer.max_body_size = url, config.max_body_size
	if peer.calls > 1 {
		return {}, {kind = .Invalid_Config}
	}

	if peer.failure != .None {
		return {}, {kind = peer.failure}
	}

	// Static fixture bytes have no owned allocator; discovery still destroys the response.
	return {status = peer.status, body = transmute([]u8)peer.body}, {}
}

@(test)
whatsapp_version_discovery_uses_official_worker_or_pinned_default :: proc(t: ^testing.T) {
	peer := Version_Test_Fetch {
		body   = `{"client_revision":1234567890}`,
		status = 200,
	}

	result := wa.web_version_discover({}, {data = &peer, get = version_test_fetch})

	testing.expect_value(t, result.source, .WhatsApp)
	testing.expect_value(t, result.version, [3]u32{2, 3000, 1234567890})

	testing.expect_value(t, peer.calls, 1)
	testing.expect_value(t, peer.url, wa.WA_WEB_VERSION_URL)
	testing.expect_value(t, peer.max_body_size, wa.WA_WEB_VERSION_BODY_MAX)

	for sample in ([?]struct {
			body:     string,
			status:   int,
			failure:  http.Error_Kind,
			expected: wa.Version_Error_Kind,
		} {
			{`{"client_revision":1}`, 503, .None, .HTTP_Status},
			{``, 200, .TLS_Failed, .HTTP_Failed},
			{`{"client_revision":0}`, 200, .None, .Invalid_Version},
			{`{"other":1234}`, 200, .None, .Missing_Version},
		}) {
		peer = {
			body    = sample.body,
			status  = sample.status,
			failure = sample.failure,
		}

		result = wa.web_version_discover({}, {data = &peer, get = version_test_fetch})

		testing.expect_value(t, result.source, .Pinned)
		testing.expect_value(t, result.version, wa.default_client_payload_config().version)
		testing.expect_value(t, result.fetch_error.kind, sample.expected)
		testing.expect_value(t, peer.calls, 1)
		if sample.status == 503 {
			testing.expect_value(t, result.fetch_error.status, 503)
		}
	}
}

@(test)
whatsapp_version_discovery_prefers_a_caller_fallback_to_the_pin :: proc(t: ^testing.T) {
	testing.expect_value(t, wa.default_client_payload_config().version, wa.WA_WEB_VERSION_PINNED)
	fallback := [3]u32{2, 3000, 1000000001}

	peer := Version_Test_Fetch{failure = .TLS_Failed}

	result := wa.web_version_discover({}, {data = &peer, get = version_test_fetch}, fallback)
	testing.expect_value(t, result.source, wa.Web_Version_Source.Configured)
	testing.expect_value(t, result.version, fallback)
	testing.expect_value(t, result.fetch_error.kind, wa.Version_Error_Kind.HTTP_Failed)

	peer = {body = `{"client_revision":1234567890}`, status = 200}

	result = wa.web_version_discover({}, {data = &peer, get = version_test_fetch}, fallback)
	testing.expect_value(t, result.source, wa.Web_Version_Source.WhatsApp)
	testing.expect_value(t, result.version, [3]u32{2, 3000, 1234567890})

	peer = {status = 503}

	result = wa.web_version_discover({}, {data = &peer, get = version_test_fetch})

	testing.expect_value(t, result.source, wa.Web_Version_Source.Pinned)
	testing.expect_value(t, result.version, wa.WA_WEB_VERSION_PINNED)
}

@(test)
whatsapp_version_preserves_body_and_explicit_triplet_bounds :: proc(t: ^testing.T) {
	body := make([]u8, wa.WA_WEB_VERSION_BODY_MAX + 1)
	defer delete(body)

	_, oversized := wa.web_version_revision(body)
	testing.expect_value(t, oversized.kind, .Body_Oversized)

	for text in ([?]string{"2.3000.1234567890", "2.3000.4294967295"}) {
		_, error := wa.web_version_parse(text)
		testing.expect_value(t, error, .None)
	}

	for text in ([?]string {
			"",
			"2.3",
			"2.3.4.5",
			"v2.3.4",
			"2.-3.4",
			"2.3.4294967296",
			"2.3.4-beta",
			"2.3.4 ",
			"2..4",
			"0.0.0",
		}) {
		_, error := wa.web_version_parse(text)
		testing.expect_value(t, error, .Invalid_Version)
	}
}

version_test_failed_allocator :: proc(
	_: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed {
		return nil, .Out_Of_Memory
	}

	return nil, nil
}

@(test)
whatsapp_version_revision_needs_no_heap_allocation :: proc(t: ^testing.T) {
	context.allocator = {
		procedure = version_test_failed_allocator,
	}

	input := `{"client_revision":1234567890}`
	revision, error := wa.web_version_revision(transmute([]u8)input)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, revision, u32(1234567890))
}

@(test)
official_version_literal_boundaries_and_conflicts_fail_closed :: proc(t: ^testing.T) {
	for fixture in ([?]struct {
			body:  string,
			value: u32,
		} {
			{`{"client_revision" : 1234}`, 1234},
			{`{"client_revision":1234,"client_revision":1234}`, 1234},
			{`{"client_revision":1234,"other":"x"}`, 1234},
			{`{"client_revision_extra":99,"client_revision":1234}`, 1234},
		}) {
		value, error := wa.web_version_revision(transmute([]u8)fixture.body)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, value, fixture.value)
	}

	for body in ([?]string {
			`{"client_revision":1234,"client_revision":5678}`,
			`{"client_revision":1234 x}`,
			`{"client_revision":1234 e2}`,
			`{"client_revision":1234`,
			`{"client_revision\":1234}`,
			`{"client_revision":1234,"client_revision":0}`,
		}) {
		_, error := wa.web_version_revision(transmute([]u8)body)
		testing.expect_value(t, error.kind, .Invalid_Version)
	}
}

@(test)
official_version_discovery_preserves_tighter_body_budget :: proc(t: ^testing.T) {
	peer := Version_Test_Fetch {
		body   = `{"client_revision":1234567890}`,
		status = 200,
	}

	result := wa.web_version_discover({max_body_size = 8}, {data = &peer, get = version_test_fetch})

	testing.expect_value(t, peer.max_body_size, 8)
	testing.expect_value(t, result.source, .Pinned)
	testing.expect_value(t, result.fetch_error.kind, .Body_Oversized)
	testing.expect_value(t, peer.calls, 1)
}

Owned_Version_Peer :: struct {
	status: int,
	body:   string,
	fail:   bool,
}

owned_version_fetch :: proc(
	data: rawptr,
	url: string,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	peer := cast(^Owned_Version_Peer)data
	storage := make([dynamic]u8, 0, len(peer.body))
	append(&storage, peer.body)
	response := surf.Response {
		status       = peer.status,
		body         = storage[:],
		body_storage = storage,
		allocator    = context.allocator,
	}

	if peer.fail {
		return response, {kind = .IO_Failed}
	}

	return response, {}
}

@(test)
official_version_discovery_releases_owned_response_on_every_outcome :: proc(t: ^testing.T) {
	// The test runner's allocator tracking verifies response ownership is released
	// for success, rejected status, parse failure and transport failure.
	for peer in ([]Owned_Version_Peer {
			{200, `{"client_revision":1234}`, false},
			{503, `temporary failure`, false},
			{200, `{"client_revision":0}`, false},
			{200, `{"client_revision":1234}`, true},
		}) {
		actual := peer
		result := wa.web_version_discover({}, {data = &actual, get = owned_version_fetch})

		expected := wa.Web_Version_Source.Pinned
		if peer.status == 200 && !peer.fail && peer.body == `{"client_revision":1234}` {
			expected = .WhatsApp
		}

		testing.expect_value(t, result.source, expected)
	}
}

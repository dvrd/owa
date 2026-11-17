package whatsapp

import "core:testing"
import "core:strings"
import "core:time"

@(test)
linked_device_qr_matches_observed_url_and_companion_field :: proc(t: ^testing.T) {
	zero: [32]u8
	buffer: [2048]u8
	size: int
	error: Pairing_Error
	// The historical API fallback makes the missing-format regression runnable
	// against the old package instead of failing at unresolved API names.
	when #defined(Pairing_QR_Format) {
		size, error = pairing_qr_encode(
			buffer[:],
			"synthetic-ref",
			zero,
			zero,
			zero,
			.Linked_Device,
			"Ubuntu",
			"Chrome",
		)
	} else {
		size, error = pairing_qr_encode(buffer[:], "synthetic-ref", zero, zero, zero)
	}

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
	legacy, explicit, linked: [MAX_PAIRING_QR_SIZE]u8
	legacy_size, legacy_error := pairing_qr_encode(legacy[:], "reference", keys[0], keys[1], keys[2])
	assert(legacy_error.kind == .None)

	for item in cases {
		size, error := pairing_qr_encode(
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
		testing.expect_value(t, size, legacy_size + len(PAIRING_LINKED_DEVICE_QR_PREFIX) + 2)
		testing.expect_value(t, string(linked[:len(PAIRING_LINKED_DEVICE_QR_PREFIX)]), PAIRING_LINKED_DEVICE_QR_PREFIX)
		testing.expect_value(
			t,
			string(linked[len(PAIRING_LINKED_DEVICE_QR_PREFIX):size - 2]),
			string(legacy[:legacy_size]),
		)
		testing.expect_value(t, string(linked[size - 2:size]), item.suffix)
		explicit_size, explicit_error := pairing_qr_encode(
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
	reference: [MAX_PAIRING_REF_SIZE]u8

	for &value in reference {
		value = 'r'
	}

	size, error := pairing_qr_encode(nil, string(reference[:]), keys[0], keys[1], keys[2], .Linked_Device)
	testing.expect_value(t, error.kind, .Destination_Undersized)
	testing.expect_value(t, size, MAX_PAIRING_QR_SIZE)
	buffer: [MAX_PAIRING_QR_SIZE + 1]u8

	for &value in buffer {
		value = 0x7f
	}

	short_size, short_error := pairing_qr_encode(
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

	written, valid := pairing_qr_encode(buffer[:size], string(reference[:]), keys[0], keys[1], keys[2], .Linked_Device)
	testing.expect_value(t, valid.kind, .None)
	testing.expect_value(t, written, size)
	testing.expect_value(t, buffer[size], u8(0x7f))

	for ref in ([]string{"", "bad,reference", "bad\nreference"}) {
		for &value in buffer {
			value = 0x7f
		}

		_, invalid := pairing_qr_encode(buffer[:], ref, keys[0], keys[1], keys[2], .Linked_Device)
		testing.expect_value(t, invalid.kind, .Invalid_Ref)

		for value in buffer {
			testing.expect_value(t, value, u8(0x7f))
		}
	}

	_, invalid_format := pairing_qr_encode(buffer[:], "reference", keys[0], keys[1], keys[2], Pairing_QR_Format(255))
	testing.expect_value(t, invalid_format.kind, .Invalid_QR_Format)

	for value in buffer {
		testing.expect_value(t, value, u8(0x7f))
	}

	// Prefix writing must not overwrite a reference borrowed from the destination.
	copy(buffer[:], "borrowed-ref")
	alias_size, alias_error := pairing_qr_encode(
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
		string(buffer[len(PAIRING_LINKED_DEVICE_QR_PREFIX):len(PAIRING_LINKED_DEVICE_QR_PREFIX) + 12]),
		"borrowed-ref",
	)
	testing.expect_value(t, alias_size, len(PAIRING_LINKED_DEVICE_QR_PREFIX) + 12 + 3 * 44 + 3 + 2)
}

@(test)
linked_device_qr_failed_encoding_does_not_consume_reference :: proc(t: ^testing.T) {
	state := Pairing_QR_State {
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
	_, short := pairing_qr_next(&state, now, nil, .Linked_Device)
	testing.expect_value(t, short.kind, .Destination_Undersized)
	testing.expect_value(t, state.next, 0)
	testing.expect_value(t, state.next_at._nsec, i64(0))
	buffer: [MAX_PAIRING_QR_SIZE]u8
	_, invalid := pairing_qr_next(&state, now, buffer[:], Pairing_QR_Format(255))
	testing.expect_value(t, invalid.kind, .Invalid_QR_Format)
	testing.expect_value(t, state.next, 0)

	for index in 0 ..< 2 {
		count, error := pairing_qr_next(&state, now, buffer[:], .Linked_Device, "Windows", "Desktop")
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

	_, expired := pairing_qr_next(&state, now, buffer[:], .Linked_Device)
	testing.expect_value(t, expired.kind, .QR_Expired)
}

QR_Profile_Fixture :: struct {
	socket:  Socket,
	auth:    Auth_State,
	prekeys: Prekey_Store,
	store:   State_Store,
	wire:    Send_Id_Wire,
}
qr_profile_fixture :: proc() -> ^QR_Profile_Fixture {
	f := new(QR_Profile_Fixture)
	credentials, error := device_credentials_generate()
	assert(error == .None)
	f.auth.credentials = credentials
	assert(prekey_store_init(&f.prekeys, &f.auth.credentials).kind == .None)
	assert(state_store_init(&f.store, signal_curve_public(f.auth.credentials.identity_private)).kind == .None)
	send_id_wire_connect(&f.socket, &f.wire)
	f.socket.client.static_public = signal_curve_public(f.auth.credentials.noise_private)
	f.socket.client.phase = .Initialized

	return f
}
qr_profile_destroy :: proc(f: ^QR_Profile_Fixture) {
	frame_transport_clear(&f.socket.client.frames)
	state_store_clear(&f.store)
	prekey_store_clear(&f.prekeys)
	device_credentials_clear(&f.auth.credentials)
	free(f)
}

@(test)
linked_device_qr_session_initial_and_timer_events_honor_selected_format :: proc(t: ^testing.T) {
	for format in ([]Pairing_QR_Format{.Legacy, .Linked_Device}) {
		f := qr_profile_fixture()
		defer qr_profile_destroy(f)
		config := Session_Config {
			payload   = default_payload_config(),
			qr_format = format,
		}

		config.payload.browser_os = "Windows"
		config.payload.browser_name = "Desktop"
		testing.expect_value(t, session_init(&f.socket.session, &f.socket.client, &f.auth, config).kind, .None)
		f.socket.client.phase = .Noise_Ready
		f.socket.session.phase = .Awaiting_Pairing
		now := time.Time{}
		f.socket.session.last_received = now
		f.socket.session.next_ping = time.time_add(now, time.Hour)
		refs := [2]Binary_Node {
			{tag = "ref", content = []u8{'f', 'i', 'r', 's', 't'}},
			{tag = "ref", content = []u8{'s', 'e', 'c', 'o', 'n', 'd'}},
		}

		pair := [1]Binary_Node{{tag = "pair-device", content = refs[:]}}
		attrs := [2]Binary_Node_Attribute{{"type", "set"}, {"id", "synthetic-pair"}}
		event, error := session_pair_device(&f.socket.session, {tag = "iq", attrs = attrs[:], content = pair[:]}, now)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .QR)
		testing.expect(
			t,
			strings.has_prefix(
				event.qr,
				format == .Linked_Device ? PAIRING_LINKED_DEVICE_QR_PREFIX + "first," : "first,",
			),
		)

		if format == .Linked_Device {
			testing.expect(t, strings.has_suffix(event.qr, ",8"))
		}

		event, error = session_tick(&f.socket.session, f.socket.session.qr_state.next_at)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, event.kind, .QR)
		testing.expect(
			t,
			strings.has_prefix(
				event.qr,
				format == .Linked_Device ? PAIRING_LINKED_DEVICE_QR_PREFIX + "second," : "second,",
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
	error := session_init(
		&f.socket.session,
		&f.socket.client,
		&f.auth,
		{payload = default_payload_config(), qr_format = Pairing_QR_Format(255)},
	)
	testing.expect_value(t, error.kind, .Invalid_Config)
	testing.expect_value(t, f.socket.session.phase, .Uninitialized)
	testing.expect_value(t, f.socket.session.last_error.server_code, u32(123))
	testing.expect_value(t, f.socket.client.phase, .Initialized)
	testing.expect(t, f.auth.credentials == before)
	fresh := new(Socket)
	defer free(fresh)
	socket_error := socket_connect(
		fresh,
		&f.auth,
		&f.prekeys,
		&f.store,
		{prekey_path = "synthetic-prekeys", state_path = "synthetic-state", qr_format = Pairing_QR_Format(255)},
	)
	testing.expect_value(t, socket_error.kind, .Invalid_Config)
	testing.expect_value(t, fresh.phase, .Uninitialized)
	testing.expect(t, fresh.auth == nil && fresh.store == nil && fresh.prekeys == nil)
	testing.expect_value(t, fresh.websocket.phase, .Uninitialized)
}

@(test)
linked_device_qr_borrowed_profile_is_read_before_writing :: proc(t: ^testing.T) {
	keys: [3][32]u8
	buffer: [MAX_PAIRING_QR_SIZE]u8
	copy(buffer[:], "WindowsDesktop")
	size, error := pairing_qr_encode(
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

package whatsapp

import ascii "../ascii"
import "core:bytes"
import "core:crypto/legacy/md5"
import "core:slice"
import "core:unicode/utf8"

// Protobuf fields, login payloads and pairing codecs.

// Noise handshake and certificate protobufs

// Field numbers match Baileys 6.7.23 WAProto/WAProto.proto, HandshakeMessage
// and CertChain. This deliberately implements only these small wire messages;
// field semantics and Noise cryptographic lengths belong to the handshake.
MAX_PROTOBUF_MESSAGE_SIZE :: MAX_FRAME_PAYLOAD

Protobuf_Error :: enum {
	None,
	Truncated_Varint,
	Varint_Overflow,
	Invalid_Field_Number,
	Unsupported_Wire_Type,
	Wrong_Wire_Type,
	Truncated_Field,
	Integer_Overflow,
	Duplicate_Field,
	Multiple_Handshake_Messages,
	Missing_Handshake_Message,
	Destination_Undersized,
	Message_Oversized,
	Overlapping_Buffers,
}

Handshake_Message_Kind :: enum {
	Client_Hello,
	Server_Hello,
	Client_Finish,
}

// All byte slices borrow the encoded message. Presence distinguishes absent
// optional fields from explicitly encoded zero-length byte strings.
Handshake_Message :: struct {
	kind:                                   Handshake_Message_Kind,
	ephemeral, static, payload:             []u8,
	has_ephemeral, has_static, has_payload: bool,
}

Noise_Certificate :: struct {
	details, signature:         []u8,
	has_details, has_signature: bool,
}

Cert_Chain :: struct {
	leaf, intermediate:         Noise_Certificate,
	has_leaf, has_intermediate: bool,
}

Certificate_Details :: struct {
	serial, issuer_serial:                  u32,
	key:                                    []u8,
	not_before, not_after:                  u64,
	has_serial, has_issuer_serial, has_key: bool,
	has_not_before, has_not_after:          bool,
}

handshake_client_hello_encode :: proc(
	dst: []u8,
	ephemeral: [32]u8,
) -> (
	written: int,
	error: Protobuf_Error,
) {
	if len(dst) < 36 do return 0, .Destination_Undersized

	key_copy := ephemeral
	dst[0], dst[1], dst[2], dst[3] = 0x12, 34, 0x0a, 32
	copy(dst[4:36], key_copy[:])
	return 36, .None
}

// Preflights the complete bounded size and source aliasing before writing.
// Ciphertext is opaque here, including a present empty value if requested.
handshake_client_finish_encode :: proc(
	dst, encrypted_static, encrypted_payload: []u8,
) -> (
	written: int,
	error: Protobuf_Error,
) {
	if len(encrypted_static) > MAX_PROTOBUF_MESSAGE_SIZE ||
	   len(encrypted_payload) > MAX_PROTOBUF_MESSAGE_SIZE {
		return 0, .Message_Oversized
	}

	inner_size :=
		2 +
		protobuf_varint_size(cast(u64)len(encrypted_static)) +
		len(encrypted_static) +
		protobuf_varint_size(cast(u64)len(encrypted_payload)) +
		len(encrypted_payload)
	if inner_size > MAX_PROTOBUF_MESSAGE_SIZE {
		return 0, .Message_Oversized
	}

	required :=
		1 + protobuf_varint_size(cast(u64)inner_size) + inner_size
	if required > MAX_PROTOBUF_MESSAGE_SIZE {
		return 0, .Message_Oversized
	}

	if len(dst) < required {
		return 0, .Destination_Undersized
	}

	if bytes.alias(dst[:required], encrypted_static) ||
	   bytes.alias(dst[:required], encrypted_payload) {
		return 0, .Overlapping_Buffers
	}

	dst[0] = 0x22 // HandshakeMessage.clientFinish = 4.
	written = 1
	protobuf_varint_write(dst, &written, cast(u64)inner_size)
	dst[written] = 0x0a
	written += 1
	protobuf_varint_write(
		dst,
		&written,
		cast(u64)len(encrypted_static),
	)
	written += copy(dst[written:], encrypted_static)
	dst[written] = 0x12
	written += 1
	protobuf_varint_write(
		dst,
		&written,
		cast(u64)len(encrypted_payload),
	)
	written += copy(dst[written:], encrypted_payload)
	return written, .None
}

handshake_message_decode :: proc(
	src: []u8,
) -> (
	message: Handshake_Message,
	error: Protobuf_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Message_Oversized
	}

	at := 0
	seen: bool
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		if field.number < 2 || field.number > 4 do continue

		if field.wire_type != 2 {
			return {}, .Wrong_Wire_Type
		}

		kind := cast(Handshake_Message_Kind)(field.number - 2)
		if seen {
			if kind == message.kind {
				return {}, .Duplicate_Field
			}

			return {}, .Multiple_Handshake_Messages
		}

		seen = true
		parsed, parse_err := protobuf_handshake_inner_decode(
			field.data,
			kind,
		)
		if parse_err != .None do return {}, parse_err

		message = parsed
	}
	if !seen do return {}, .Missing_Handshake_Message

	return message, .None
}

cert_chain_decode :: proc(
	src: []u8,
) -> (
	chain: Cert_Chain,
	error: Protobuf_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Message_Oversized
	}

	at := 0
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		if !slice.contains(
			[]type_of(field.number){1, 2},
			field.number,
		) {
			continue
		}

		if field.wire_type != 2 {
			return {}, .Wrong_Wire_Type
		}

		if field.number == 1 && chain.has_leaf ||
		   field.number == 2 && chain.has_intermediate {
			return {}, .Duplicate_Field
		}

		cert, cert_err := protobuf_certificate_decode(field.data)
		if cert_err != .None do return {}, cert_err

		if field.number == 1 {
			chain.leaf, chain.has_leaf = cert, true
		} else {
			chain.intermediate, chain.has_intermediate = cert, true
		}

	}
	return chain, .None
}

certificate_details_decode :: proc(
	src: []u8,
) -> (
	details: Certificate_Details,
	error: Protobuf_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Message_Oversized
	}

	at := 0
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		if field_error := certificate_details_field_decode(&details, field);
		   field_error != .None do return {}, field_error
	}
	return details, .None
}

certificate_details_field_decode :: proc(
	details: ^Certificate_Details, field: Protobuf_Field,
) -> Protobuf_Error {
	switch field.number {
	case 1, 2:
		if field.wire_type != 0 {
			return .Wrong_Wire_Type
		}

		if field.value > 0xffff_ffff {
			return .Integer_Overflow
		}

		if field.number == 1 {
			if details.has_serial {
				return .Duplicate_Field
			}

			details.serial, details.has_serial =
				cast(u32)field.value, true
		} else {
			if details.has_issuer_serial {
				return .Duplicate_Field
			}

			details.issuer_serial, details.has_issuer_serial =
				cast(u32)field.value, true
		}

	case 3:
		if field.wire_type != 2 {
			return .Wrong_Wire_Type
		}

		if details.has_key {
			return .Duplicate_Field
		}

		details.key, details.has_key = field.data, true
	case 4, 5:
		if field.wire_type != 0 {
			return .Wrong_Wire_Type
		}

		if field.number == 4 {
			if details.has_not_before {
				return .Duplicate_Field
			}

			details.not_before, details.has_not_before =
				field.value, true
		} else {
			if details.has_not_after {
				return .Duplicate_Field
			}

			details.not_after, details.has_not_after =
				field.value, true
		}

	}
	return .None
}

Protobuf_Field :: struct {
	number:    u32,
	wire_type: u8,
	value:     u64,
	data:      []u8,
}

protobuf_handshake_inner_decode :: proc(
	src: []u8,
	kind: Handshake_Message_Kind,
) -> (
	message: Handshake_Message,
	error: Protobuf_Error,
) {
	message.kind = kind
	at := 0
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		if field_error := protobuf_handshake_field_decode(&message, field);
		   field_error != .None do return {}, field_error
	}
	return message, .None
}

protobuf_handshake_field_decode :: proc(
	message: ^Handshake_Message, field: Protobuf_Field,
) -> Protobuf_Error {
	if message.kind == .Client_Finish {
		if !slice.contains(
			[]type_of(field.number){1, 2},
			field.number,
		) {
			return .None
		}

		if field.wire_type != 2 {
			return .Wrong_Wire_Type
		}

		if field.number == 1 {
			if message.has_static {
				return .Duplicate_Field
			}

			message.static, message.has_static = field.data, true
		} else {
			if message.has_payload {
				return .Duplicate_Field
			}

			message.payload, message.has_payload =
				field.data, true
		}

	} else {
		if field.number < 1 || field.number > 3 {
			return .None
		}

		if field.wire_type != 2 {
			return .Wrong_Wire_Type
		}

		switch field.number {
		case 1:
			if message.has_ephemeral {
				return .Duplicate_Field
			}

			message.ephemeral, message.has_ephemeral =
				field.data, true
		case 2:
			if message.has_static {
				return .Duplicate_Field
			}

			message.static, message.has_static = field.data, true
		case 3:
			if message.has_payload {
				return .Duplicate_Field
			}

			message.payload, message.has_payload =
				field.data, true
		}
	}

	return .None
}

protobuf_certificate_decode :: proc(
	src: []u8,
) -> (
	cert: Noise_Certificate,
	error: Protobuf_Error,
) {
	at := 0
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		if !slice.contains(
			[]type_of(field.number){1, 2},
			field.number,
		) {
			continue
		}

		if field.wire_type != 2 {
			return {}, .Wrong_Wire_Type
		}

		if field.number == 1 {
			if cert.has_details {
				return {}, .Duplicate_Field
			}

			cert.details, cert.has_details = field.data, true
		} else {
			if cert.has_signature {
				return {}, .Duplicate_Field
			}

			cert.signature, cert.has_signature = field.data, true
		}

	}
	return cert, .None
}

// Read/skip every supported wire type in one place. Lengths are compared as
// u64 before converting to int, so an attacker cannot wrap a slice index.
protobuf_field_read :: proc(
	src: []u8,
	at: ^int,
) -> (
	field: Protobuf_Field,
	error: Protobuf_Error,
) {
	tag, tag_err := protobuf_varint_read(src, at)
	if tag_err != .None do return {}, tag_err

	if tag >> 3 == 0 || tag >> 3 > 0x1fff_ffff {
		return {}, .Invalid_Field_Number
	}

	field.number, field.wire_type =
		cast(u32)(tag >> 3), cast(u8)(tag & 7)
	switch field.wire_type {
	case 0:
		field.value, error = protobuf_varint_read(src, at)
		if error != .None do return {}, error

	case 1:
		if len(src) - at^ < 8 do return {}, .Truncated_Field

		at^ += 8
	case 2:
		size, size_err := protobuf_varint_read(src, at)
		if size_err != .None do return {}, size_err

		if size > cast(u64)(len(src) - at^) {
			return {}, .Truncated_Field
		}

		field.data = src[at^:at^ + cast(int)size]
		at^ += cast(int)size
	case 5:
		if len(src) - at^ < 4 do return {}, .Truncated_Field

		at^ += 4
	case:
		return {}, .Unsupported_Wire_Type
	}
	return field, .None
}

protobuf_varint_read :: proc(
	src: []u8,
	at: ^int,
) -> (
	value: u64,
	error: Protobuf_Error,
) {
	for i in 0 ..< 10 {
		if at^ == len(src) do return 0, .Truncated_Varint

		b := src[at^]
		at^ += 1
		if i == 9 && b > 1 do return 0, .Varint_Overflow

		value |= cast(u64)(b & 0x7f) << cast(uint)(i * 7)
		if b & 0x80 == 0 do return value, .None

	}
	return 0, .Varint_Overflow
}

protobuf_varint_size :: proc(value: u64) -> int {
	n, remaining := 1, value
	for remaining >= 0x80 {
		remaining >>= 7
		n += 1
	}
	return n
}

protobuf_varint_write :: proc(dst: []u8, at: ^int, value: u64) {
	remaining := value
	for remaining >= 0x80 {
		dst[at^] = cast(u8)(remaining & 0x7f) | 0x80
		at^ += 1
		remaining >>= 7
	}
	dst[at^] = cast(u8)remaining
	at^ += 1
}

// Registration and login payload protobufs

MAX_CLIENT_PAYLOAD_SIZE :: 16384
MAX_PAYLOAD_BROWSER_STRING_SIZE :: 255

Payload_Config :: struct {
	version:                                [3]u32,
	browser_os, browser_name, country_code: string,
	sync_full_history:                      bool,
}

Registration_Keys :: struct {
	registration_id:         u32,
	identity_public:         [32]u8,
	signed_prekey_id:        u32,
	signed_prekey_public:    [32]u8,
	signed_prekey_signature: [64]u8,
}

Payload_Error :: enum {
	None,
	Invalid_Browser_OS,
	Invalid_Browser_Name,
	Invalid_Country_Code,
	Invalid_Registration_ID,
	Invalid_Signed_Prekey_ID,
	Invalid_Username,
	Destination_Undersized,
	Payload_Oversized,
	Overlapping_Buffers,
}

// Matches the pinned Baileys 6.7.23 validate-connection.js registration
// ClientPayload. The bounded staging buffer guarantees dst is unchanged on
// every validation/size/alias error. Inputs contain public key material only.
registration_payload_encode :: proc(
	dst: []u8,
	config: Payload_Config,
	keys: Registration_Keys,
) -> (
	n: int,
	error: Payload_Error,
) {
	if err := payload_config_validate(config); err != .None {
		return 0, err
	}

	if keys.registration_id > 0x3fff {
		return 0, .Invalid_Registration_ID
	}

	if keys.signed_prekey_id > 0xff_ffff {
		return 0, .Invalid_Signed_Prekey_ID
	}

	key_copy := keys
	device_props: [1024]u8
	props_size, props_err := device_props_encode(
		device_props[:],
		config,
	)
	if props_err != .None do return 0, props_err

	build_hash := registration_build_hash(config.version)
	registration_id := [4]u8 {
		cast(u8)(keys.registration_id >> 24),
		cast(u8)(keys.registration_id >> 16),
		cast(u8)(keys.registration_id >> 8),
		cast(u8)keys.registration_id,
	}
	prekey_id := [3]u8 {
		cast(u8)(keys.signed_prekey_id >> 16),
		cast(u8)(keys.signed_prekey_id >> 8),
		cast(u8)keys.signed_prekey_id,
	}
	key_type := [?]u8{5}
	pairing_buffer: [2048]u8
	pairing := Payload_Writer {
		dst = pairing_buffer[:],
	}
	payload_bytes(&pairing, 1, registration_id[:])
	payload_bytes(&pairing, 2, key_type[:])
	payload_bytes(&pairing, 3, key_copy.identity_public[:])
	payload_bytes(&pairing, 4, prekey_id[:])
	payload_bytes(&pairing, 5, key_copy.signed_prekey_public[:])
	payload_bytes(&pairing, 6, key_copy.signed_prekey_signature[:])
	payload_bytes(&pairing, 7, build_hash[:])
	payload_bytes(&pairing, 8, device_props[:props_size])
	if pairing.err != .None do return 0, pairing.err

	staging: [MAX_CLIENT_PAYLOAD_SIZE]u8
	writer := Payload_Writer {
		dst = staging[:],
	}
	payload_common(
		&writer,
		config,
		false,
		0,
		0,
		pairing_buffer[:pairing.at],
	)
	return payload_copy_result(dst, config, "", &writer)
}

registration_build_hash :: proc(version: [3]u32) -> [16]u8 {
	version_text: [32]u8
	version_size := 0
	for value, i in version {
		if i > 0 {
			version_text[version_size] = '.'; version_size += 1
		}

		version_size += payload_decimal(
			version_text[version_size:],
			value,
		)
	}
	// Protocol build identifier, not a password hash: MD5(version.join('.')).
	build_hash: [16]u8
	hash: md5.Context
	md5.init(&hash)
	md5.update(&hash, version_text[:version_size])
	md5.final(&hash, build_hash[:])
	return build_hash
}

// Username is 1..20 ASCII decimal digits fitting uint64. Unlike JS's +user,
// this preserves IDs beyond Number.MAX_SAFE_INTEGER without rounding them.
// A bare login JID has no device property; pass include_device=false to omit
// that field, preserving the pinned builder's undefined-versus-zero behavior.
login_payload_encode :: proc(
	dst: []u8,
	config: Payload_Config,
	user: string,
	device: u32,
	include_device: bool = true,
) -> (
	n: int,
	error: Payload_Error,
) {
	if err := payload_config_validate(config); err != .None {
		return 0, err
	}

	if len(user) == 0 || len(user) > 20 {
		return 0, .Invalid_Username
	}

	username: u64
	for c in user {
		if !ascii.is_digit(c) do return 0, .Invalid_Username

		digit := cast(u64)(c - '0')
		if username > (0xffff_ffff_ffff_ffff - digit) / 10 {
			return 0, .Invalid_Username
		}

		username = username * 10 + digit
	}
	staging: [MAX_CLIENT_PAYLOAD_SIZE]u8
	writer := Payload_Writer {
		dst = staging[:],
	}
	payload_common(
		&writer,
		config,
		true,
		username,
		device,
		nil,
		include_device,
	)
	return payload_copy_result(dst, config, user, &writer)
}

// DeviceProps has no version field in the pinned registration builder.
// Explicit false values remain present, matching protobufjs own properties.
device_props_encode :: proc(
	dst: []u8,
	config: Payload_Config,
) -> (
	n: int,
	error: Payload_Error,
) {
	if err := payload_config_validate(config); err != .None {
		return 0, err
	}

	history_buffer: [64]u8
	history := Payload_Writer {
		dst = history_buffer[:],
	}
	payload_uint(&history, 3, 10240)
	// Pinned source leaves fields1/2/5/13 undefined, not encoded as zero.
	history_fields := [?]u32{4, 6, 7, 8, 9, 10, 11, 12, 14}
	for field in history_fields {
		value: u64 = 1
		if field == 6 do value = 0

		payload_uint(&history, field, value)
	}
	staging: [1024]u8
	writer := Payload_Writer {
		dst = staging[:],
	}
	payload_string(&writer, 1, config.browser_os)
	payload_uint(
		&writer,
		3,
		cast(u64)payload_platform(config.browser_name),
	)
	payload_uint(&writer, 4, cast(u64)config.sync_full_history)
	payload_bytes(&writer, 5, history_buffer[:history.at])
	return payload_copy_result(dst, config, "", &writer)
}

Payload_Writer :: struct {
	dst: []u8,
	at:  int,
	err: Payload_Error,
}

payload_common :: proc(
	writer: ^Payload_Writer,
	config: Payload_Config,
	login: bool,
	username: u64,
	device: u32,
	pairing: []u8,
	include_device: bool = true,
) {
	version_buffer: [32]u8
	version := Payload_Writer {
		dst = version_buffer[:],
	}
	for value, i in config.version do payload_uint(&version, cast(u32)(i + 1), cast(u64)value)
	agent_buffer: [512]u8
	agent := Payload_Writer {
		dst = agent_buffer[:],
	}
	payload_uint(&agent, 1, 14) // UserAgent.Platform.WEB
	payload_bytes(&agent, 2, version_buffer[:version.at])
	payload_string(&agent, 3, "000") // mcc
	payload_string(&agent, 4, "000") // mnc
	payload_string(&agent, 5, "0.1")
	payload_string(&agent, 7, "Desktop")
	payload_string(&agent, 8, "0.1")
	payload_uint(&agent, 10, 0) // ReleaseChannel.RELEASE, explicitly present.
	payload_string(&agent, 11, "en")
	payload_string(&agent, 12, config.country_code)
	web_subplatform: u64
	if config.sync_full_history {
		if config.browser_os == "Mac OS" {
			web_subplatform = 3
		} // DARWIN

		if config.browser_os == "Windows" {
			web_subplatform = 4
		} // WIN32

	}

	web_buffer: [2]u8
	web := Payload_Writer {
		dst = web_buffer[:],
	}
	payload_uint(&web, 4, web_subplatform)
	if version.err != .None ||
	   agent.err != .None ||
	   web.err != .None {
		writer.err = .Payload_Oversized
		return
	}

	if login do payload_uint(writer, 1, username)

	payload_uint(writer, 3, 0) // passive:false for login and registration.
	payload_bytes(writer, 5, agent_buffer[:agent.at])
	payload_bytes(writer, 6, web_buffer[:web.at])
	payload_uint(writer, 12, 1) // WIFI_UNKNOWN
	payload_uint(writer, 13, 1) // USER_ACTIVATED
	if login && include_device {
		payload_uint(writer, 18, cast(u64)device)
	}

	if !login do payload_bytes(writer, 19, pairing)

	payload_uint(writer, 33, cast(u64)login) // pull:true login, false registration.
}

payload_config_validate :: proc(
	config: Payload_Config,
) -> Payload_Error {
	if len(config.browser_os) == 0 ||
	   len(config.browser_os) > MAX_PAYLOAD_BROWSER_STRING_SIZE ||
	   !utf8.valid_string(config.browser_os) {
		return .Invalid_Browser_OS
	}

	if len(config.browser_name) == 0 ||
	   len(config.browser_name) > MAX_PAYLOAD_BROWSER_STRING_SIZE {
		return .Invalid_Browser_Name
	}

	for c in config.browser_name {
		if c < 32 || c > 126 do return .Invalid_Browser_Name

	}
	if len(config.country_code) != 2 {
		return .Invalid_Country_Code
	}

	for c in config.country_code {
		if !(ascii.is_alpha(c)) {
			return .Invalid_Country_Code
		}

	}
	return .None
}

payload_platform :: proc(browser: string) -> u32 {
	names := [?]string {
		"CHROME",
		"FIREFOX",
		"IE",
		"OPERA",
		"SAFARI",
		"EDGE",
		"DESKTOP",
		"IPAD",
		"ANDROID_TABLET",
		"OHANA",
		"ALOHA",
		"CATALINA",
		"TCL_TV",
		"IOS_PHONE",
		"IOS_CATALYST",
		"ANDROID_PHONE",
		"ANDROID_AMBIGUOUS",
		"WEAR_OS",
		"AR_WRIST",
		"AR_DEVICE",
		"UWP",
		"VR",
		"CLOUD_API",
		"SMARTGLASSES",
	}
	for name, i in names {
		if len(name) != len(browser) do continue

		match := true
		for c, j in browser {
			upper := c
			if upper >= 'a' && upper <= 'z' {
				upper -= 'a' - 'A'
			}

			if upper != cast(rune)name[j] {
				match = false; break
			}

		}
		if match do return cast(u32)(i + 1)

	}
	// JS's `PlatformType[name] || DESKTOP` maps UNKNOWN(0) here too.
	return 7
}

payload_copy_result :: proc(
	dst: []u8,
	config: Payload_Config,
	username: string,
	writer: ^Payload_Writer,
) -> (
	int,
	Payload_Error,
) {
	if writer.err != .None do return 0, writer.err

	if len(dst) < writer.at {
		return 0, .Destination_Undersized
	}

	sources := [?]string {
		config.browser_os,
		config.browser_name,
		config.country_code,
		username,
	}
	for source in sources {
		if bytes.alias(dst[:writer.at], transmute([]u8)source) {
			return 0, .Overlapping_Buffers
		}

	}
	copy(dst[:writer.at], writer.dst[:writer.at])
	return writer.at, .None
}

payload_varint :: proc(writer: ^Payload_Writer, value: u64) {
	if writer.err != .None do return

	remaining := value
	for {
		if writer.at == len(writer.dst) {
			writer.err = .Payload_Oversized; return
		}

		b := cast(u8)(remaining & 0x7f)
		remaining >>= 7
		if remaining != 0 do b |= 0x80

		writer.dst[writer.at] = b
		writer.at += 1
		if remaining == 0 do return

	}
}

payload_uint :: proc(
	writer: ^Payload_Writer,
	field: u32,
	value: u64,
) {
	payload_varint(writer, cast(u64)field << 3)
	payload_varint(writer, value)
}

payload_bytes :: proc(
	writer: ^Payload_Writer,
	field: u32,
	value: []u8,
) {
	payload_varint(writer, cast(u64)field << 3 | 2)
	payload_varint(writer, cast(u64)len(value))
	if writer.err != .None do return

	if len(value) > len(writer.dst) - writer.at {
		writer.err = .Payload_Oversized; return
	}

	writer.at += copy(writer.dst[writer.at:], value)
}

payload_string :: proc(
	writer: ^Payload_Writer,
	field: u32,
	value: string,
) {
	payload_bytes(writer, field, transmute([]u8)value)
}

payload_decimal :: proc(dst: []u8, value: u32) -> int {
	remaining := value
	reversed: [10]u8
	size := 0
	for {
		reversed[size] = '0' + cast(u8)(remaining % 10)
		size += 1
		remaining /= 10
		if remaining == 0 do break

	}
	for i in 0 ..< size do dst[i] = reversed[size - 1 - i]
	return size
}

// Pairing identity protobufs

// ADV* field numbers from the pinned Baileys 6.7.23 WAProto schema.
// All decoded byte strings borrow src, including the signed raw details.
Pairing_Device_Identity_HMAC :: struct {
	details, hmac:                           []u8,
	account_type:                            u32,
	has_details, has_hmac, has_account_type: bool,
}

Pairing_Signed_Identity :: struct {
	details,
	account_signature_key,
	account_signature,
	device_signature: []u8,
	has_details,
	has_account_signature_key:                              bool,
	has_account_signature,
	has_device_signature:                         bool,
}

Pairing_Device_Details :: struct {
	raw_id:                                   u32,
	timestamp:                                u64,
	key_index, account_type, device_type:     u32,
	has_raw_id, has_timestamp, has_key_index: bool,
	has_account_type, has_device_type:        bool,
}

pairing_identity_hmac_decode :: proc(
	src: []u8,
) -> (
	identity: Pairing_Device_Identity_HMAC,
	error: Protobuf_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Message_Oversized
	}

	at := 0
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		switch field.number {
		case 1, 2:
			if field.wire_type != 2 {
				return {}, .Wrong_Wire_Type
			}

			if field.number == 1 {
				if identity.has_details {
					return {}, .Duplicate_Field
				}

				identity.details, identity.has_details =
					field.data, true
			} else {
				if identity.has_hmac {
					return {}, .Duplicate_Field
				}

				identity.hmac, identity.has_hmac = field.data, true
			}

		case 3:
			if field.wire_type != 0 {
				return {}, .Wrong_Wire_Type
			}

			if field.value > 0xffff_ffff {
				return {}, .Integer_Overflow
			}

			if identity.has_account_type {
				return {}, .Duplicate_Field
			}

			identity.account_type, identity.has_account_type =
				cast(u32)field.value, true
		}
	}
	return identity, .None
}

pairing_signed_identity_decode :: proc(
	src: []u8,
) -> (
	identity: Pairing_Signed_Identity,
	error: Protobuf_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Message_Oversized
	}

	at := 0
	seen: [4]bool
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		if field.number < 1 || field.number > 4 do continue

		if field.wire_type != 2 {
			return {}, .Wrong_Wire_Type
		}

		if seen[field.number - 1] {
			return {}, .Duplicate_Field
		}

		seen[field.number - 1] = true
		switch field.number {
		case 1:
			identity.details, identity.has_details = field.data, true
		case 2:
			identity.account_signature_key, identity.has_account_signature_key =
				field.data, true
		case 3:
			identity.account_signature, identity.has_account_signature =
				field.data, true
		case 4:
			identity.device_signature, identity.has_device_signature =
				field.data, true
		}
	}
	return identity, .None
}

pairing_device_details_decode :: proc(
	src: []u8,
) -> (
	details: Pairing_Device_Details,
	error: Protobuf_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Message_Oversized
	}

	at := 0
	seen: [5]bool
	for at < len(src) {
		field, field_err := protobuf_field_read(src, &at)
		if field_err != .None do return {}, field_err

		if field.number < 1 || field.number > 5 do continue

		if field.wire_type != 0 {
			return {}, .Wrong_Wire_Type
		}

		if field.number != 2 && field.value > 0xffff_ffff {
			return {}, .Integer_Overflow
		}

		if seen[field.number - 1] {
			return {}, .Duplicate_Field
		}

		seen[field.number - 1] = true
		switch field.number {
		case 1:
			details.raw_id, details.has_raw_id =
				cast(u32)field.value, true
		case 2:
			details.timestamp, details.has_timestamp =
				field.value, true
		case 3:
			details.key_index, details.has_key_index =
				cast(u32)field.value, true
		case 4:
			details.account_type, details.has_account_type =
				cast(u32)field.value, true
		case 5:
			details.device_type, details.has_device_type =
				cast(u32)field.value, true
		}
	}
	return details, .None
}

// Pinned encodeSignedDeviceIdentity omits the account key by default and also
// omits an empty key when include_signature_key is true. Other present empty
// fields remain representable via their presence flags. No writes on failure.
pairing_signed_identity_encode :: proc(
	dst: []u8,
	identity: Pairing_Signed_Identity,
	include_signature_key: bool = false,
) -> (
	written: int,
	error: Protobuf_Error,
) {
	fields := [4][]u8 {
		identity.details,
		identity.account_signature_key,
		identity.account_signature,
		identity.device_signature,
	}
	present := [4]bool {
		identity.has_details,
		identity.has_account_signature_key,
		identity.has_account_signature,
		identity.has_device_signature,
	}
	required := 0
	for value, i in fields {
		present[i] = present[i] || len(value) > 0
		if i == 1 {
			present[i] = include_signature_key && len(value) > 0
		}

		if !present[i] do continue

		if len(value) > MAX_PROTOBUF_MESSAGE_SIZE {
			return 0, .Message_Oversized
		}

		size :=
			1 +
			protobuf_varint_size(cast(u64)len(value)) +
			len(value)
		if size > MAX_PROTOBUF_MESSAGE_SIZE - required {
			return 0, .Message_Oversized
		}

		required += size
	}
	if len(dst) < required {
		return 0, .Destination_Undersized
	}

	for value, i in fields {
		if present[i] && bytes.alias(dst[:required], value) {
			return 0, .Overlapping_Buffers
		}

	}
	for value, i in fields {
		if !present[i] do continue

		dst[written] = cast(u8)((i + 1) << 3 | 2)
		written += 1
		protobuf_varint_write(dst, &written, cast(u64)len(value))
		written += copy(dst[written:], value)
	}
	return written, .None
}

// Text messages and quoted context.

// Baileys 6.7.23 WAProto.proto: Message, ExtendedTextMessage, ContextInfo,
// FutureProofMessage and Message.SenderKeyDistributionMessage. This codec
// deliberately ignores other message kinds; it does not implement media.
MAX_MESSAGE_NESTING :: 8
Text_Message_Kind :: enum {
	None,
	Conversation,
	Extended_Text,
}
Message_Error :: enum {
	None,
	Invalid_Protobuf,
	Duplicate_Field,
	Conflicting_Content,
	Invalid_UTF8,
	Nesting_Limit,
	Message_Oversized,
	Destination_Undersized,
	Overlapping_Buffers,
}
Message_Context :: struct {
	stanza_id,
	participant,
	remote_jid:                                 string,
	quoted_message:                                                     []u8,
	has_stanza_id,
	has_participant,
	has_remote_jid,
	has_quoted_message: bool,
}
Sender_Key_Distribution :: struct {
	group_id:                       string,
	distribution:                   []u8,
	has_group_id, has_distribution: bool,
}
// All strings and slices borrow the source buffer, including quoted_message.
// They remain valid only while the caller retains that buffer unchanged.
// Recognized wrappers are normalized; quote bytes retain their original wire.
Text_Message :: struct {
	kind:                        Text_Message_Kind,
	text:                        string,
	context_info:                Message_Context,
	has_context:                 bool,
	sender_key_distribution:     Sender_Key_Distribution,
	has_sender_key_distribution: bool,
	wrapper_depth:               int,
}

text_message_decode :: proc(
	src: []u8,
) -> (
	Text_Message,
	Message_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Message_Oversized
	}

	return message_decode_inner(src, 0)
}

message_decode_inner :: proc(
	src: []u8,
	depth: int,
) -> (
	message: Text_Message,
	error: Message_Error,
) {
	if depth > MAX_MESSAGE_NESTING {
		return {}, .Nesting_Limit
	}

	at := 0
	content_seen := false
	content_field: u32
	for at < len(src) {
		field, e := protobuf_field_read(src, &at)
		if e != .None do return {}, .Invalid_Protobuf

		switch field.number {
		case 1, 6, 37, 40, 53, 55, 59:
			if field.wire_type != 2 {
				return {}, .Invalid_Protobuf
			}

			if content_seen {
				if content_field == field.number {
					return {}, .Duplicate_Field
				}

				return {}, .Conflicting_Content
			}

			content_field = field.number
			content_seen = true
			if field.number == 1 {
				if !utf8.valid_string(cast(string)field.data) {
					return {}, .Invalid_UTF8
				}

				message.kind, message.text =
					.Conversation, cast(string)field.data
			} else if field.number == 6 {
				if extended_error := message_extended_text_decode(&message, field, depth);
				   extended_error != .None do return {}, extended_error
			} else {
				if wrapper_error := message_wrapper_decode(&message, field, depth);
				   wrapper_error != .None do return {}, wrapper_error
			}

		case 2:
			if distribution_error := message_sender_key_distribution_decode(&message, field);
			   distribution_error != .None do return {}, distribution_error
		}
	}
	return message, .None
}

message_extended_text_decode :: proc(
	message: ^Text_Message, field: Protobuf_Field, depth: int,
) -> Message_Error {
	error: Message_Error
	message.kind = .Extended_Text
	inner_at := 0
	text_seen := false
	for inner_at < len(field.data) {
		f, fe := protobuf_field_read(
			field.data,
			&inner_at,
		)
		if fe != .None {
			return .Invalid_Protobuf
		}

		if !slice.contains(
			[]type_of(f.number){1, 17},
			f.number,
		) {
			continue
		}

		if f.wire_type != 2 {
			return .Invalid_Protobuf
		}

		if f.number == 1 {
			if text_seen {
				return .Duplicate_Field
			}

			text_seen = true
			if !utf8.valid_string(cast(string)f.data) {
				return .Invalid_UTF8
			}

			message.text = cast(string)f.data
		} else {
			if message.has_context {
				return .Duplicate_Field
			}

			message.has_context = true
			message.context_info, error =
				message_context_decode(f.data, depth)
			if error != .None do return error

		}

	}
	return .None
}

message_wrapper_decode :: proc(
	message: ^Text_Message, field: Protobuf_Field, depth: int,
) -> Message_Error {
	error: Message_Error
	wrapper_at := 0
	seen := false
	wrapped: Text_Message
	for wrapper_at < len(field.data) {
		f, fe := protobuf_field_read(
			field.data,
			&wrapper_at,
		)
		if fe != .None {
			return .Invalid_Protobuf
		}

		if f.number != 1 do continue

		if f.wire_type != 2 {
			return .Invalid_Protobuf
		}

		if seen do return .Duplicate_Field

		seen = true
		wrapped, error = message_decode_inner(
			f.data,
			depth + 1,
		)
		if error != .None do return error

	}
	if !seen do return .Invalid_Protobuf

	if message.has_sender_key_distribution {
		if wrapped.has_sender_key_distribution {
			return .Duplicate_Field
		}

		wrapped.sender_key_distribution =
			message.sender_key_distribution
		wrapped.has_sender_key_distribution = true
	}

	message^ = wrapped
	message.wrapper_depth += 1
	return .None
}

message_sender_key_distribution_decode :: proc(
	message: ^Text_Message, field: Protobuf_Field,
) -> Message_Error {
	if field.wire_type != 2 {
		return .Invalid_Protobuf
	}

	if message.has_sender_key_distribution {
		return .Duplicate_Field
	}

	message.has_sender_key_distribution = true
	inner_at := 0
	for inner_at < len(field.data) {
		f, fe := protobuf_field_read(field.data, &inner_at)
		if fe != .None {
			return .Invalid_Protobuf
		}

		if !slice.contains(
			[]type_of(f.number){1, 2},
			f.number,
		) {
			continue
		}

		if f.wire_type != 2 {
			return .Invalid_Protobuf
		}

		s := &message.sender_key_distribution
		if f.number == 1 {
			if s.has_group_id {
				return .Duplicate_Field
			}

			if !utf8.valid_string(cast(string)f.data) {
				return .Invalid_UTF8
			}

			s.group_id, s.has_group_id =
				cast(string)f.data, true
		} else {
			if s.has_distribution {
				return .Duplicate_Field
			}

			s.distribution, s.has_distribution = f.data, true
		}

	}
	return .None
}

message_context_decode :: proc(
	src: []u8,
	depth: int,
) -> (
	c: Message_Context,
	error: Message_Error,
) {
	at := 0
	for at < len(src) {
		f, e := protobuf_field_read(src, &at)
		if e != .None do return {}, .Invalid_Protobuf

		if f.number < 1 || f.number > 4 do continue

		if f.wire_type != 2 do return {}, .Invalid_Protobuf

		if f.number != 3 && !utf8.valid_string(cast(string)f.data) {
			return {}, .Invalid_UTF8
		}

		switch f.number {
		case 1:
			if c.has_stanza_id {
				return {}, .Duplicate_Field
			}

			c.stanza_id, c.has_stanza_id = cast(string)f.data, true
		case 2:
			if c.has_participant {
				return {}, .Duplicate_Field
			}

			c.participant, c.has_participant =
				cast(string)f.data, true
		case 3:
			if c.has_quoted_message {
				return {}, .Duplicate_Field
			}

			_, error = message_decode_inner(f.data, depth + 1)
			if error != .None do return {}, error

			c.quoted_message, c.has_quoted_message = f.data, true
		case 4:
			if c.has_remote_jid {
				return {}, .Duplicate_Field
			}

			c.remote_jid, c.has_remote_jid = cast(string)f.data, true
		}
	}
	return c, .None
}

// Produces a normalized Message (without wrappers). Presence flags preserve
// explicitly empty context/distribution fields. Encoding validates everything,
// including quoted protobufs and source aliasing, before touching dst.
text_message_encode :: proc(
	dst: []u8,
	message: Text_Message,
) -> (
	written: int,
	error: Message_Error,
) {
	m := message
	if validation_error := text_message_encode_validate(m);
	   validation_error != .None do return 0, validation_error
	c, s := m.context_info, m.sender_key_distribution
	context_size, sender_size, required, size_error := text_message_encoded_sizes(m)
	if size_error != .None do return 0, size_error

	if len(dst) < required {
		return 0, .Destination_Undersized
	}

	for v in ([?]string {
			m.text,
			c.stanza_id,
			c.participant,
			c.remote_jid,
			s.group_id,
		}) {
		if bytes.alias(dst[:required], transmute([]u8)v) {
			return 0, .Overlapping_Buffers
		}

	}
	if bytes.alias(dst[:required], c.quoted_message) ||
	   bytes.alias(dst[:required], s.distribution) {
		return 0, .Overlapping_Buffers
	}

	return text_message_fields_write(dst, m, context_size, sender_size), .None
}

text_message_encode_validate :: proc(m: Text_Message) -> Message_Error {
	if !slice.contains(
		[]type_of(m.kind){.None, .Conversation, .Extended_Text},
		m.kind,
	) {
		return .Conflicting_Content
	}

	if m.kind != .Extended_Text && m.has_context {
		return .Conflicting_Content
	}

	if !utf8.valid_string(m.text) do return .Invalid_UTF8

	c, s := m.context_info, m.sender_key_distribution
	for v in ([?]string {
			m.text,
			c.stanza_id,
			c.participant,
			c.remote_jid,
			s.group_id,
		}) {
		if len(v) > MAX_PROTOBUF_MESSAGE_SIZE {
			return .Message_Oversized
		}

	}
	if len(c.quoted_message) > MAX_PROTOBUF_MESSAGE_SIZE ||
	   len(s.distribution) > MAX_PROTOBUF_MESSAGE_SIZE {
		return .Message_Oversized
	}

	return .None
}

text_message_context_size :: proc(m: Text_Message) -> (int, Message_Error) {
	c := m.context_info
	context_size := 0
	if m.has_context {
		values := [?]string{c.stanza_id, c.participant, c.remote_jid}
		present := [?]bool {
			c.has_stanza_id,
			c.has_participant,
			c.has_remote_jid,
		}
		for v, i in values {
			if !present[i] do continue

			if !utf8.valid_string(v) {
				return 0, .Invalid_UTF8
			}

			if len(v) > MAX_PROTOBUF_MESSAGE_SIZE {
				return 0, .Message_Oversized
			}

			context_size += message_field_size(1, len(v))
		}
		if c.has_quoted_message {
			_, e := message_decode_inner(c.quoted_message, 1)
			if e != .None do return 0, e

			context_size += message_field_size(
				3,
				len(c.quoted_message),
			)
		}

	}

	return context_size, .None
}

text_message_encoded_sizes :: proc(m: Text_Message) -> (int, int, int, Message_Error) {
	c, s := m.context_info, m.sender_key_distribution
	context_size, context_error := text_message_context_size(m)
	if context_error != .None do return 0, 0, 0, context_error
	sender_size, content_size := 0, 0

	if m.has_sender_key_distribution {
		if s.has_group_id {
			if !utf8.valid_string(s.group_id) {
				return 0, 0, 0, .Invalid_UTF8
			}

			sender_size += message_field_size(1, len(s.group_id))
		}

		if s.has_distribution {
			sender_size += message_field_size(2, len(s.distribution))
		}

	}

	if len(m.text) > MAX_PROTOBUF_MESSAGE_SIZE ||
	   len(s.group_id) > MAX_PROTOBUF_MESSAGE_SIZE ||
	   len(s.distribution) > MAX_PROTOBUF_MESSAGE_SIZE ||
	   len(c.quoted_message) > MAX_PROTOBUF_MESSAGE_SIZE {
		return 0, 0, 0, .Message_Oversized
	}

	if m.kind == .Conversation {
		content_size = message_field_size(1, len(m.text))
	} else if m.kind == .Extended_Text {
		content_size = message_field_size(1, len(m.text))
		if m.has_context {
			content_size += message_field_size(17, context_size)
		}

		content_size = message_field_size(6, content_size)
	}

	required := content_size
	if m.has_sender_key_distribution {
		required += message_field_size(2, sender_size)
	}

	if required > MAX_PROTOBUF_MESSAGE_SIZE {
		return 0, 0, 0, .Message_Oversized
	}

	return context_size, sender_size, required, .None
}

message_context_fields_write :: proc(dst: []u8, at: ^int, c: Message_Context) {
	if c.has_stanza_id {
		message_field_write(
			dst,
			at,
			1,
			transmute([]u8)c.stanza_id,
		)
	}

	if c.has_participant {
		message_field_write(
			dst,
			at,
			2,
			transmute([]u8)c.participant,
		)
	}

	if c.has_quoted_message {
		message_field_write(
			dst,
			at,
			3,
			c.quoted_message,
		)
	}

	if c.has_remote_jid {
		message_field_write(
			dst,
			at,
			4,
			transmute([]u8)c.remote_jid,
		)
	}

}

text_message_fields_write :: proc(
	dst: []u8, m: Text_Message, context_size, sender_size: int,
) -> int {
	written := 0
	c, s := m.context_info, m.sender_key_distribution
	if m.kind == .Conversation {
		message_field_write(dst, &written, 1, transmute([]u8)m.text)
	}

	if m.has_sender_key_distribution {
		message_field_header(dst, &written, 2, sender_size)
		if s.has_group_id {
			message_field_write(
				dst,
				&written,
				1,
				transmute([]u8)s.group_id,
			)
		}

		if s.has_distribution {
			message_field_write(dst, &written, 2, s.distribution)
		}

	}

	if m.kind == .Extended_Text {
		n := message_field_size(1, len(m.text))
		if m.has_context {
			n += message_field_size(17, context_size)
		}

		message_field_header(dst, &written, 6, n)
		message_field_write(dst, &written, 1, transmute([]u8)m.text)
		if m.has_context {
			message_field_header(dst, &written, 17, context_size)
			message_context_fields_write(dst, &written, c)
		}

	}

	return written
}

message_field_size :: proc(field: u32, size: int) -> int {
	return(
		protobuf_varint_size(cast(u64)field << 3 | 2) +
		protobuf_varint_size(cast(u64)size) +
		size \
	)
}
message_field_header :: proc(
	dst: []u8,
	at: ^int,
	field: u32,
	size: int,
) {
	protobuf_varint_write(dst, at, cast(u64)field << 3 | 2)
	protobuf_varint_write(dst, at, cast(u64)size)
}
message_field_write :: proc(
	dst: []u8,
	at: ^int,
	field: u32,
	value: []u8,
) {
	message_field_header(dst, at, field, len(value))
	at^ += copy(dst[at^:], value)
}

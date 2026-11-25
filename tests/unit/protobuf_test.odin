package whatsapp_test

import "core:encoding/hex"
import "core:testing"
import wa "shared:whatsapp"

writer_golden_config :: proc() -> wa.Payload_Config {
	return {
		version = {2, 3000, 1015901307},
		browser_os = "Mac OS",
		browser_name = "Chrome",
		country_code = "US",
		sync_full_history = true,
	}
}

writer_golden_keys :: proc() -> wa.Registration_Keys {
	keys := wa.Registration_Keys {
		registration_id = 0x1234,
		signed_prekey_id = 0x00ab_cdef,
	}
	for i in 0 ..< 32 {
		keys.identity_public[i] = u8(i)
		keys.signed_prekey_public[i] = u8(0x40 + i)
	}
	for i in 0 ..< 64 {
		keys.signed_prekey_signature[i] = u8(0x80 + i)
	}

	return keys
}

writer_golden_quote := [2]u8{0x08, 0x01}

writer_golden_registration :: "18002a36080e120b080210b81718fbd8b5e4031a0330303022033030302a03302e313a074465736b746f704203302e315000" +
	"5a02656e6202555332022003600168019a01cb010a04000012341201051a20000102030405060708090a0b0c0d0e0f101112" +
	"131415161718191a1b1c1d1e1f2203abcdef2a20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d" +
	"5e5f3240808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacad" +
	"aeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf3a105d4e4496f81e833f9ff45394e5005e6b42230a064d6163204f5318012001" +
	"2a15188050200130003801400148015001580160017001880200"

writer_golden_login :: "08cef6b9f8800118002a36080e120b080210b81718fbd8b5e4031a0330303022033030302a03302e313a074465736b746f70" +
	"4203302e3150005a02656e620255533202200360016801900109880201"

writer_golden_login_bare :: "08cef6b9f8800118002a36080e120b080210b81718fbd8b5e4031a0330303022033030302a03302e313a074465736b746f70" +
	"4203302e3150005a02656e620255533202200360016801880201"

writer_golden_props :: "0a064d6163204f53180120012a15188050200130003801400148015001580160017001"

// Bytes captured from the retired Payload_Writer/Media_Writer pair. The merged
// Protobuf_Writer must keep emitting exactly these.
writer_expect_hex :: proc(t: ^testing.T, out: []u8, want: string, label: string) {
	got := hex.encode(out, context.temp_allocator)
	testing.expectf(t, string(got) == want, "%s: got %s", label, string(got))
}

@(test)
writer_payload_encoders_match_retired_writer :: proc(t: ^testing.T) {
	out: [4096]u8
	config := writer_golden_config()

	n, err := wa.registration_payload_encode(out[:], config, writer_golden_keys())
	testing.expect_value(t, err, wa.Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_registration, "registration")

	n, err = wa.login_payload_encode(out[:], config, "34612345678", 9)
	testing.expect_value(t, err, wa.Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_login, "login")

	n, err = wa.login_payload_encode(out[:], config, "34612345678", 0, false)
	testing.expect_value(t, err, wa.Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_login_bare, "login_bare")

	n, err = wa.device_props_encode(out[:], config)
	testing.expect_value(t, err, wa.Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_props, "props")
}

@(test)
writer_measure_mode_stores_nothing_and_counts_exactly :: proc(t: ^testing.T) {
	data := [?]u8{1, 2, 3, 4, 5}
	measure := wa.Protobuf_Writer {
		measure = true,
	}
	wa.protobuf_write_uint(&measure, 1, 300)
	wa.protobuf_write_bytes(&measure, 2, data[:])
	wa.protobuf_write_string(&measure, 3, "hi")

	fixed_buffer: [32]u8
	fixed := wa.Protobuf_Writer {
		dst = fixed_buffer[:],
	}
	wa.protobuf_write_uint(&fixed, 1, 300)
	wa.protobuf_write_bytes(&fixed, 2, data[:])
	wa.protobuf_write_string(&fixed, 3, "hi")

	testing.expect_value(t, measure.err, wa.Protobuf_Write_Error.None)
	testing.expect_value(t, fixed.err, wa.Protobuf_Write_Error.None)
	testing.expect_value(t, measure.at, fixed.at)
	writer_expect_hex(t, fixed_buffer[:fixed.at], "08ac02" + "1205" + "0102030405" + "1a02" + "6869", "fixed")
}

@(test)
writer_fixed_buffer_overflow_is_sticky_and_leaves_tail_untouched :: proc(t: ^testing.T) {
	buffer: [4]u8
	for &b in buffer {
		b = 0xee
	}
	writer := wa.Protobuf_Writer {
		dst = buffer[:],
	}
	data := [?]u8{9, 9, 9}
	wa.protobuf_write_bytes(&writer, 1, data[:])

	testing.expect_value(t, writer.err, wa.Protobuf_Write_Error.Oversized)
	at := writer.at
	wa.protobuf_write_uint(&writer, 2, 1)
	testing.expect_value(t, writer.at, at)
	testing.expect_value(t, buffer[3], 0xee)
}

@(test)
writer_rejects_invalid_utf8_and_aliasing_target :: proc(t: ^testing.T) {
	bad := [?]u8{0xff, 0xfe}
	writer := wa.Protobuf_Writer {
		measure = true,
	}
	wa.protobuf_write_string(&writer, 1, string(bad[:]))
	testing.expect_value(t, writer.err, wa.Protobuf_Write_Error.Invalid_UTF8)

	target: [8]u8
	aliased := wa.Protobuf_Writer {
		measure = true,
		target = target[:],
	}
	wa.protobuf_write_bytes(&aliased, 1, target[2:4])
	testing.expect_value(t, aliased.err, wa.Protobuf_Write_Error.Overlapping_Buffers)

	media := wa.Media_Message {
		kind = .Image,
		url = "u",
		has_url = true,
	}
	media.caption = string(bad[:])
	media.has_caption = true
	out: [64]u8
	_, err := wa.media_message_encode(out[:], media)
	testing.expect_value(t, err.kind, wa.Media_Error_Kind.Invalid_UTF8)
}

@(test)
writer_payload_error_precedence_is_preserved :: proc(t: ^testing.T) {
	out: [4]u8
	_, err := wa.login_payload_encode(out[:], writer_golden_config(), "1", 1)
	testing.expect_value(t, err, wa.Payload_Error.Destination_Undersized)

	config := writer_golden_config()
	config.country_code = "1"
	_, err = wa.login_payload_encode(out[:], config, "1", 1)
	testing.expect_value(t, err, wa.Payload_Error.Invalid_Country_Code)

	media_out: [4]u8
	_, media_err := wa.media_message_encode(media_out[:], writer_golden_media(.Image, &[4][32]u8{}))
	testing.expect_value(t, media_err.kind, wa.Media_Error_Kind.Destination_Undersized)
}

@(test)
protobuf_varint_preserves_u64_limits_and_cursor :: proc(t: ^testing.T) {
	values := [?]u64{0, 127, 128, max(u64)}
	for value in values {
		buffer: [12]u8
		written := 1
		wa.protobuf_varint_write(buffer[:], &written, value)
		testing.expect_value(t, written - 1, wa.protobuf_varint_size(value))
		read := 1
		got, err := wa.protobuf_varint_read(buffer[:written], &read)
		testing.expect_value(t, err, wa.Protobuf_Error.None)
		testing.expect_value(t, got, value)
		testing.expect_value(t, read, written)
	}

	buffer := [?]u8{0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1}
	for end in 1 ..< 11 {
		read := 1
		_, err := wa.protobuf_varint_read(buffer[:end], &read)
		testing.expect_value(t, err, wa.Protobuf_Error.Truncated_Varint)
		testing.expect_value(t, read, end)
	}
	overflow_bytes := [?]u8{2, 0x80, 0xff}
	for last in overflow_bytes {
		buffer[10] = last
		read := 1
		_, err := wa.protobuf_varint_read(buffer[:], &read)
		testing.expect_value(t, err, wa.Protobuf_Error.Varint_Overflow)
		testing.expect_value(t, read, 11)
	}
}

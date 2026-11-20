package whatsapp

import "core:encoding/hex"
import "core:testing"

writer_golden_config :: proc() -> Payload_Config {
	return {
		version = {2, 3000, 1015901307},
		browser_os = "Mac OS",
		browser_name = "Chrome",
		country_code = "US",
		sync_full_history = true,
	}
}

writer_golden_keys :: proc() -> Registration_Keys {
	keys := Registration_Keys {
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

writer_golden_media :: proc(kind: Media_Kind, buffers: ^[4][32]u8) -> Media_Message {
	for i in 0 ..< 4 {
		for j in 0 ..< 32 {
			buffers[i][j] = u8(i * 32 + j)
		}
	}
	message := Media_Message {
		kind = kind,
		url = "https://mmg.whatsapp.net/o1/v/t62/a.enc",
		has_url = true,
		direct_path = "/o1/v/t62/a.enc",
		has_direct_path = true,
		mime_type = kind == .Image ? "image/jpeg" : "application/pdf",
		has_mime_type = true,
		caption = "caption ✅",
		has_caption = true,
		media_key = buffers[0][:],
		has_media_key = true,
		file_sha256 = buffers[1][:],
		has_file_sha256 = true,
		file_enc_sha256 = buffers[2][:],
		has_file_enc_sha256 = true,
		jpeg_thumbnail = buffers[3][:8],
		has_jpeg_thumbnail = true,
		file_length = 123456,
		has_file_length = true,
		media_key_timestamp = 1700000000,
		has_media_key_timestamp = true,
		height = 480,
		has_height = true,
		width = 640,
		has_width = true,
		page_count = 7,
		has_page_count = true,
		file_name = "doc.pdf",
		has_file_name = true,
		title = "Title",
		has_title = true,
		context_info = {
			stanza_id = "STANZA",
			has_stanza_id = true,
			participant = "1@s.whatsapp.net",
			has_participant = true,
			remote_jid = "2@g.us",
			has_remote_jid = true,
			quoted_message = writer_golden_quote[:],
			has_quoted_message = true,
		},
		has_context = true,
	}

	if kind == .Image {
		message.file_name, message.has_file_name = "", false
		message.title, message.has_title = "", false
		message.page_count, message.has_page_count = 0, false
	} else {
		message.height, message.has_height = 0, false
		message.width, message.has_width = 0, false
	}

	return message
}


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

writer_golden_media_Image :: "1afd010a2768747470733a2f2f6d6d672e77686174736170702e6e65742f6f312f762f7436322f612e656e63120a696d6167" +
	"652f6a7065671a0b63617074696f6e20e29c852220202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c" +
	"3d3e3f28c0c40730e0033880054220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f4a2040" +
	"4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f5a0f2f6f312f762f7436322f612e656e636080" +
	"e2cfaa0682010860616263646566678a01260a065354414e5a4112103140732e77686174736170702e6e65741a0208012206" +
	"3240672e7573"

writer_golden_media_Document :: "3a8f020a2768747470733a2f2f6d6d672e77686174736170702e6e65742f6f312f762f7436322f612e656e63120f6170706c" +
	"69636174696f6e2f7064661a055469746c652220202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d" +
	"3e3f28c0c40730073a20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f4207646f632e7064" +
	"664a20404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f520f2f6f312f762f7436322f612e65" +
	"6e635880e2cfaa0682010860616263646566678a01260a065354414e5a4112103140732e77686174736170702e6e65741a02" +
	"080122063240672e7573a2010b63617074696f6e20e29c85"

writer_golden_reaction :: "f2022f0a210a063240672e757310011a0349443122103340732e77686174736170702e6e65741203e29c8520fbd095ffbc31"

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

	n, err := registration_payload_encode(out[:], config, writer_golden_keys())
	testing.expect_value(t, err, Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_registration, "registration")

	n, err = login_payload_encode(out[:], config, "34612345678", 9)
	testing.expect_value(t, err, Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_login, "login")

	n, err = login_payload_encode(out[:], config, "34612345678", 0, false)
	testing.expect_value(t, err, Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_login_bare, "login_bare")

	n, err = device_props_encode(out[:], config)
	testing.expect_value(t, err, Payload_Error.None)
	writer_expect_hex(t, out[:n], writer_golden_props, "props")
}

@(test)
writer_media_encoders_match_retired_writer :: proc(t: ^testing.T) {
	out: [4096]u8
	buffers: [4][32]u8

	n, err := media_message_encode(out[:], writer_golden_media(.Image, &buffers))
	testing.expect_value(t, err.kind, Media_Error_Kind.None)
	writer_expect_hex(t, out[:n], writer_golden_media_Image, "image")

	n, err = media_message_encode(out[:], writer_golden_media(.Document, &buffers))
	testing.expect_value(t, err.kind, Media_Error_Kind.None)
	writer_expect_hex(t, out[:n], writer_golden_media_Document, "document")

	key := Message_Key {
		remote_jid = "2@g.us",
		has_remote_jid = true,
		id = "ID1",
		has_id = true,
		participant = "3@s.whatsapp.net",
		has_participant = true,
		from_me = true,
		has_from_me = true,
	}
	n, err = reaction_checkmark_encode(out[:], key, 1700000000123)
	testing.expect_value(t, err.kind, Media_Error_Kind.None)
	writer_expect_hex(t, out[:n], writer_golden_reaction, "reaction")
}

@(test)
writer_measure_mode_stores_nothing_and_counts_exactly :: proc(t: ^testing.T) {
	data := [?]u8{1, 2, 3, 4, 5}
	measure := Protobuf_Writer {
		measure = true,
	}
	protobuf_write_uint(&measure, 1, 300)
	protobuf_write_bytes(&measure, 2, data[:])
	protobuf_write_string(&measure, 3, "hi")

	fixed_buffer: [32]u8
	fixed := Protobuf_Writer {
		dst = fixed_buffer[:],
	}
	protobuf_write_uint(&fixed, 1, 300)
	protobuf_write_bytes(&fixed, 2, data[:])
	protobuf_write_string(&fixed, 3, "hi")

	testing.expect_value(t, measure.err, Protobuf_Write_Error.None)
	testing.expect_value(t, fixed.err, Protobuf_Write_Error.None)
	testing.expect_value(t, measure.at, fixed.at)
	writer_expect_hex(t, fixed_buffer[:fixed.at], "08ac02" + "1205" + "0102030405" + "1a02" + "6869", "fixed")
}

@(test)
writer_fixed_buffer_overflow_is_sticky_and_leaves_tail_untouched :: proc(t: ^testing.T) {
	buffer: [4]u8
	for &b in buffer {
		b = 0xee
	}
	writer := Protobuf_Writer {
		dst = buffer[:],
	}
	data := [?]u8{9, 9, 9}
	protobuf_write_bytes(&writer, 1, data[:])

	testing.expect_value(t, writer.err, Protobuf_Write_Error.Oversized)
	at := writer.at
	protobuf_write_uint(&writer, 2, 1)
	testing.expect_value(t, writer.at, at)
	testing.expect_value(t, buffer[3], 0xee)
}

@(test)
writer_rejects_invalid_utf8_and_aliasing_target :: proc(t: ^testing.T) {
	bad := [?]u8{0xff, 0xfe}
	writer := Protobuf_Writer {
		measure = true,
	}
	protobuf_write_string(&writer, 1, string(bad[:]))
	testing.expect_value(t, writer.err, Protobuf_Write_Error.Invalid_UTF8)

	target: [8]u8
	aliased := Protobuf_Writer {
		measure = true,
		target = target[:],
	}
	protobuf_write_bytes(&aliased, 1, target[2:4])
	testing.expect_value(t, aliased.err, Protobuf_Write_Error.Overlapping_Buffers)

	media := Media_Message {
		kind = .Image,
		url = "u",
		has_url = true,
	}
	media.caption = string(bad[:])
	media.has_caption = true
	out: [64]u8
	_, err := media_message_encode(out[:], media)
	testing.expect_value(t, err.kind, Media_Error_Kind.Invalid_UTF8)
}

@(test)
writer_payload_error_precedence_is_preserved :: proc(t: ^testing.T) {
	out: [4]u8
	_, err := login_payload_encode(out[:], writer_golden_config(), "1", 1)
	testing.expect_value(t, err, Payload_Error.Destination_Undersized)

	config := writer_golden_config()
	config.country_code = "1"
	_, err = login_payload_encode(out[:], config, "1", 1)
	testing.expect_value(t, err, Payload_Error.Invalid_Country_Code)

	media_out: [4]u8
	_, media_err := media_message_encode(media_out[:], writer_golden_media(.Image, &[4][32]u8{}))
	testing.expect_value(t, media_err.kind, Media_Error_Kind.Destination_Undersized)
}

@(test)
protobuf_varint_preserves_u64_limits_and_cursor :: proc(t: ^testing.T) {
	values := [?]u64{0, 127, 128, max(u64)}
	for value in values {
		buffer: [12]u8
		written := 1
		protobuf_varint_write(buffer[:], &written, value)
		testing.expect_value(t, written - 1, protobuf_varint_size(value))
		read := 1
		got, err := protobuf_varint_read(buffer[:written], &read)
		testing.expect_value(t, err, Protobuf_Error.None)
		testing.expect_value(t, got, value)
		testing.expect_value(t, read, written)
	}

	buffer := [?]u8{0, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 1}
	for end in 1 ..< 11 {
		read := 1
		_, err := protobuf_varint_read(buffer[:end], &read)
		testing.expect_value(t, err, Protobuf_Error.Truncated_Varint)
		testing.expect_value(t, read, end)
	}
	overflow_bytes := [?]u8{2, 0x80, 0xff}
	for last in overflow_bytes {
		buffer[10] = last
		read := 1
		_, err := protobuf_varint_read(buffer[:], &read)
		testing.expect_value(t, err, Protobuf_Error.Varint_Overflow)
		testing.expect_value(t, read, 11)
	}
}

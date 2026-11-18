package whatsapp

import "core:bytes"
import "core:encoding/hex"
import "core:strings"
import "core:mem"
import "core:testing"
import network_client "shared:surf"

codec_api_hex :: proc(text: string) -> []u8 {
	decoded, ok := hex.decode(transmute([]u8)text, context.temp_allocator)
	assert(ok)

	return decoded
}

// Hand-decoded Message{reactionMessage: {key{remoteJid "2@g.us", fromMe, id
// "ID1", participant "3@s.whatsapp.net"}, text "✅", senderTimestampMs}}.
CODEC_API_REACTION_HEX :: "f2022f0a210a063240672e757310011a0349443122103340732e77686174736170702e6e65741203e29c8520fbd095ffbc31"

codec_api_reaction_key :: proc() -> Message_Key {
	return {
		remote_jid = "2@g.us",
		has_remote_jid = true,
		id = "ID1",
		has_id = true,
		participant = "3@s.whatsapp.net",
		has_participant = true,
		from_me = true,
		has_from_me = true,
	}
}

@(test)
noise_credentials_are_random_nonzero_and_accepted_by_client_init :: proc(t: ^testing.T) {
	first, first_error := noise_credentials_generate()
	second, second_error := noise_credentials_generate()
	testing.expect_value(t, first_error.kind, Client_Error_Kind.None)
	testing.expect_value(t, second_error.kind, Client_Error_Kind.None)

	zero: [32]u8
	testing.expect(t, first.static_private_key != zero)
	testing.expect(t, second.static_private_key != zero)
	testing.expect(t, first.static_private_key != second.static_private_key)

	websocket := network_client.WebSocket_Conn {
		phase = .Open,
		allocator = context.allocator,
		config = {host = "synthetic.invalid", max_message_size = 4096},
		stream = {read = media_retry_test_read, write = media_retry_test_write, close = media_retry_test_close},
	}
	client: Client
	defer noise_clear(&client.noise)
	testing.expect_value(t, client_init(&client, &websocket, first).kind, Client_Error_Kind.None)
	testing.expect_value(t, client.static_private, first.static_private_key)
	testing.expect_value(t, client.static_public, signal_curve_public(first.static_private_key))

	rejected: Client
	testing.expect_value(t, client_init(&rejected, &websocket, {}).kind, Client_Error_Kind.Invalid_Credentials)
}

codec_api_qr_blank :: proc() -> ^QR_Code {
	code := new(QR_Code)
	code.version = 1
	code.size = 21
	code.mask = 0

	return code
}

@(test)
qr_terminal_render_blank_code_is_a_white_quiet_field :: proc(t: ^testing.T) {
	code := codec_api_qr_blank()
	defer free(code)

	text, error := qr_terminal_render(code)
	defer qr_terminal_destroy(text)
	testing.expect_value(t, error, QR_Error.None)

	width := code.size + QR_QUIET_ZONE * 2
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

	text, error := qr_terminal_render(code)
	defer qr_terminal_destroy(text)
	testing.expect_value(t, error, QR_Error.None)

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
	code, encode_error := qr_encode("1@synthetic-reference,AAAA,BBBB,CCCC")
	testing.expect_value(t, encode_error, QR_Error.None)
	text, error := qr_terminal_render(&code)
	defer qr_terminal_destroy(text)
	testing.expect_value(t, error, QR_Error.None)

	width := code.size + QR_QUIET_ZONE * 2
	rows := strings.split(text, "\n", context.temp_allocator)
	testing.expect_value(t, len(rows), (width + 1) / 2 + 1)

	for row, y in rows[:len(rows) - 1] {
		body := row[len("\x1b[30;47m"):len(row) - len("\x1b[0m")]
		x := 0

		for glyph in body {
			top := glyph == '▀' || glyph == '█'
			bottom := glyph == '▄' || glyph == '█'
			testing.expect_value(t, top, qr_module(&code, x - QR_QUIET_ZONE, y * 2 - QR_QUIET_ZONE))
			testing.expect_value(t, bottom, qr_module(&code, x - QR_QUIET_ZONE, y * 2 - QR_QUIET_ZONE + 1))
			x += 1
		}

		testing.expect_value(t, x, width)
	}
}

@(test)
qr_terminal_render_rejects_inconsistent_codes_and_destroy_honours_allocator :: proc(t: ^testing.T) {
	_, nil_error := qr_terminal_render(nil)
	testing.expect_value(t, nil_error, QR_Error.Invalid_Code)

	bad := codec_api_qr_blank()
	defer free(bad)
	bad.size = 25
	_, size_error := qr_terminal_render(bad)
	testing.expect_value(t, size_error, QR_Error.Invalid_Code)

	bad.size, bad.mask = 21, 8
	_, mask_error := qr_terminal_render(bad)
	testing.expect_value(t, mask_error, QR_Error.Invalid_Code)

	bad.mask, bad.version = 0, 41
	_, version_error := qr_terminal_render(bad)
	testing.expect_value(t, version_error, QR_Error.Invalid_Code)

	// The tracking allocator reports a leak if destroy used another allocator.
	track: mem.Tracking_Allocator
	mem.tracking_allocator_init(&track, context.allocator)
	defer mem.tracking_allocator_destroy(&track)
	allocator := mem.tracking_allocator(&track)
	blank := codec_api_qr_blank()
	defer free(blank)
	text, error := qr_terminal_render(blank, allocator)
	testing.expect_value(t, error, QR_Error.None)
	qr_terminal_destroy(text, allocator)
	testing.expect_value(t, len(track.allocation_map), 0)
}

@(test)
reaction_checkmark_encode_matches_reference_bytes_and_decodes_back :: proc(t: ^testing.T) {
	storage: [128]u8
	n, error := reaction_checkmark_encode(storage[:], codec_api_reaction_key(), 1700000000123)
	testing.expect_value(t, error.kind, Media_Error_Kind.None)
	testing.expect(t, bytes.equal(storage[:n], codec_api_hex(CODEC_API_REACTION_HEX)))

	message, decode_error := reaction_message_decode(storage[:n])
	testing.expect_value(t, decode_error.kind, Media_Error_Kind.None)
	testing.expect_value(t, message.text, "✅")
	testing.expect_value(t, message.sender_timestamp_ms, i64(1700000000123))
	testing.expect_value(t, message.key.remote_jid, "2@g.us")
	testing.expect_value(t, message.key.id, "ID1")
	testing.expect_value(t, message.key.participant, "3@s.whatsapp.net")
	testing.expect(t, message.key.from_me && message.key.has_from_me)
	testing.expect(t, message.has_key && message.has_text && message.has_sender_timestamp_ms)
	testing.expect(t, !message.has_grouping_key)
}

@(test)
reaction_checkmark_encode_validates_key_and_destination :: proc(t: ^testing.T) {
	storage: [128]u8
	_, empty := reaction_checkmark_encode(storage[:], {}, 1)
	testing.expect_value(t, empty.kind, Media_Error_Kind.Invalid_Reaction_Key)
	_, no_id := reaction_checkmark_encode(storage[:], {remote_jid = "2@g.us"}, 1)
	testing.expect_value(t, no_id.kind, Media_Error_Kind.Invalid_Reaction_Key)
	_, no_jid := reaction_checkmark_encode(storage[:], {id = "ID1"}, 1)
	testing.expect_value(t, no_jid.kind, Media_Error_Kind.Invalid_Reaction_Key)

	want := len(CODEC_API_REACTION_HEX) / 2
	small: [16]u8
	size, undersized := reaction_checkmark_encode(small[:], codec_api_reaction_key(), 1700000000123)
	testing.expect_value(t, undersized.kind, Media_Error_Kind.Destination_Undersized)
	testing.expect_value(t, size, want)

	// A sparse key omits absent optional fields.
	n, minimal := reaction_checkmark_encode(storage[:], {remote_jid = "2@g.us", id = "ID1"}, 7)
	testing.expect_value(t, minimal.kind, Media_Error_Kind.None)
	decoded, decode_error := reaction_message_decode(storage[:n])
	testing.expect_value(t, decode_error.kind, Media_Error_Kind.None)
	testing.expect(t, !decoded.key.has_participant && !decoded.key.has_from_me)
	testing.expect_value(t, decoded.sender_timestamp_ms, i64(7))
}

@(test)
reaction_message_decode_rejects_malformed_and_ignores_other_messages :: proc(t: ^testing.T) {
	// A text message is not a reaction: empty result, no error.
	text := [?]u8{0x0a, 0x02, 'h', 'i'}
	message, error := reaction_message_decode(text[:])
	testing.expect_value(t, error.kind, Media_Error_Kind.None)
	testing.expect(t, !message.has_key && !message.has_text)

	// Duplicate text field inside the reaction.
	duplicate := codec_api_hex("f2020a" + "1203616161" + "1203626262")
	_, duplicate_error := reaction_message_decode(duplicate)
	testing.expect_value(t, duplicate_error.kind, Media_Error_Kind.Duplicate_Field)

	// Invalid UTF-8 in the text field.
	bad_text := codec_api_hex("f20205" + "1203" + "ff0102")
	_, utf8_error := reaction_message_decode(bad_text)
	testing.expect_value(t, utf8_error.kind, Media_Error_Kind.Invalid_UTF8)

	// Truncated field length.
	valid := codec_api_hex(CODEC_API_REACTION_HEX)
	_, truncated := reaction_message_decode(valid[:len(valid) - 3])
	testing.expect(t, truncated.kind != .None)

	// Wire type mismatch: timestamp must be a varint.
	wrong_wire := codec_api_hex("f20203" + "220100")
	_, wire_error := reaction_message_decode(wrong_wire)
	testing.expect_value(t, wire_error.kind, Media_Error_Kind.Invalid_Protobuf)

	oversized := make([]u8, MAX_PROTOBUF_MESSAGE_SIZE + 1)
	defer delete(oversized)
	_, size_error := reaction_message_decode(oversized)
	testing.expect_value(t, size_error.kind, Media_Error_Kind.Message_Oversized)
}

package whatsapp_test

import wire_frames "../fixtures/message_transport"
import "core:bytes"
import "core:encoding/hex"
import "core:sync"
import "core:testing"
import "core:time"
import test_fixtures "../fixtures/client"
import "shared:async/http"
import "shared:surf"
import wa "shared:whatsapp"

Media_Deadline_Test :: struct {
	t:                ^testing.T,
	calls:            int,
	previous_timeout: time.Duration,
	fail_first_only:  bool,
	uncertain_first:  bool,
}

media_deadline_test_execute :: proc(
	request: http.Request,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	state := cast(^Media_Deadline_Test)context.user_ptr
	state.calls += 1
	if state.uncertain_first {
		if state.calls == 1 {
			return {}, {kind = .IO_Failed, write_effect = .Unknown}
		}

		return {}, {kind = .Dial_Failed, write_effect = .Not_Sent}
	}

	if state.fail_first_only {
		testing.expect(state.t, config.timeout > 0)

		if state.calls == 1 {
			state.previous_timeout = config.timeout
			time.sleep(10 * time.Millisecond)
			return {status = 503}, {}
		}

		testing.expect(state.t, config.timeout < state.previous_timeout)
		body: string = `{"url":"https://mmg.whatsapp.net/media","direct_path":"/media"}`
		return {status = 200, body = transmute([]u8)body}, {}
	}

	testing.expect(state.t, config.timeout > 0 && config.timeout <= 20 * time.Millisecond)
	// An executor may return after its budget. Never start another host then.
	time.sleep(40 * time.Millisecond)
	return {}, {kind = .Deadline_Failed}
}

@(test)
media_upload_later_dial_failure_preserves_earlier_unknown_effect :: proc(t: ^testing.T) {
	state := Media_Deadline_Test {
		t               = t,
		uncertain_first = true,
	}

	previous := context.user_ptr
	context.user_ptr = &state
	defer context.user_ptr = previous

	storage: [64]u8
	n, metadata, encryption := wa.media_encrypt(storage[:], []u8{1, 2, 3}, .Image, {})

	testing.expect_value(t, encryption.kind, .None)
	defer wa.media_metadata_clear(&metadata)

	hosts := []wa.Media_Host{{hostname = "first.invalid"}, {hostname = "second.invalid"}}

	_, error := wa.media_upload(
		storage[:n],
		.Image,
		metadata,
		{auth = "synthetic", hosts = hosts},
		{},
		execute = media_deadline_test_execute,
	)
	testing.expect_value(t, state.calls, 2)
	testing.expect_value(t, error.kind, .HTTP_Failed)
	testing.expect_value(t, error.http.kind, .Dial_Failed)
	testing.expect_value(t, error.http.write_effect, .Unknown)
}

@(test)
media_upload_does_not_restart_budget_on_host_fallback :: proc(t: ^testing.T) {
	state := Media_Deadline_Test {
		t = t,
	}

	previous := context.user_ptr
	context.user_ptr = &state
	defer context.user_ptr = previous

	storage: [64]u8
	n, metadata, encryption := wa.media_encrypt(storage[:], []u8{1, 2, 3}, .Image, {})

	testing.expect_value(t, encryption.kind, .None)
	defer wa.media_metadata_clear(&metadata)

	hosts := []wa.Media_Host{{hostname = "first.invalid"}, {hostname = "second.invalid"}}

	_, error := wa.media_upload(
		storage[:n],
		.Image,
		metadata,
		{auth = "synthetic", hosts = hosts},
		{timeout = 20 * time.Millisecond},
		execute = media_deadline_test_execute,
	)
	testing.expect_value(t, error.kind, .HTTP_Failed)
	testing.expect_value(t, error.http.kind, .Deadline_Failed)
	testing.expect_value(t, error.http.write_effect, .Unknown)
	testing.expect_value(t, state.calls, 1)
}

@(test)
media_upload_fallback_receives_only_remaining_budget :: proc(t: ^testing.T) {
	state := Media_Deadline_Test {
		t               = t,
		fail_first_only = true,
	}

	previous := context.user_ptr
	context.user_ptr = &state
	defer context.user_ptr = previous

	storage: [64]u8
	n, metadata, encryption := wa.media_encrypt(storage[:], []u8{1, 2, 3}, .Image, {})

	testing.expect_value(t, encryption.kind, .None)
	defer wa.media_metadata_clear(&metadata)

	hosts := []wa.Media_Host{{hostname = "first.invalid"}, {hostname = "second.invalid"}}

	result, error := wa.media_upload(
		storage[:n],
		.Image,
		metadata,
		{auth = "synthetic", hosts = hosts},
		{timeout = time.Second},
		execute = media_deadline_test_execute,
	)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, state.calls, 2)
	testing.expect_value(t, string(result.direct_path[:result.direct_path_size]), "/media")
}

Media_Retry_Test_State :: struct {
	t:             ^testing.T,
	calls, writes: int,
}

media_retry_test_http :: proc(
	request: http.Request,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	state := cast(^Media_Retry_Test_State)context.user_ptr
	state.calls += 1
	testing.expect_value(state.t, request.url, "https://mmg.whatsapp.net/new.enc")
	testing.expect_value(state.t, config.max_redirects, 0)
	return {status = 410}, {}
}

media_retry_test_write :: proc(data: rawptr, src: []u8) -> (int, surf.WebSocket_Async_Error) {
	state := cast(^Media_Retry_Test_State)context.user_ptr
	state.writes += 1

	return len(src), {}
}

media_retry_test_read :: proc(data: rawptr, dst: []u8) -> (int, surf.WebSocket_Async_Error) {
	return 0, {kind = .EOF}
}

media_retry_test_close :: proc(data: rawptr, _: u16) -> surf.WebSocket_Async_Error {
	return {}
}

media_retry_test_socket :: proc(t: ^testing.T, socket: ^wa.Socket, auth: ^wa.Auth_State) {
	jid := "123:4@s.whatsapp.net"
	auth.account.jid_size = copy(auth.account.jid[:], transmute([]u8)jid)
	socket.auth = auth
	socket.config.http_execute = media_retry_test_http
	socket.websocket = {
		phase = .Open,
		max_message_size = 4096,
		read = wire_frames.reader(media_retry_test_read), write = wire_frames.writer(media_retry_test_write), close = media_retry_test_close,
	}

	socket.client = {
		phase = .Noise_Ready,
		websocket = &socket.websocket,
		config = {max_frame_payload = 4096},
		noise = {phase = .Transport},
	}

	testing.expect_value(t, wa.frame_transport_init(&socket.client.frames, &socket.websocket, 4096).kind, .None)
}

// Fixed WAProto notification encrypted with Node AES-GCM for
// key bytes 0..31, stanza ABC, nonce bytes 32..43 and direct path /new.enc.
media_retry_test_notification :: proc(t: ^testing.T, ciphertext, nonce: []u8, direct := false, own := false) -> wa.Binary_Document {
	node := wa.Binary_Node {
		tag     = "notification",
		attrs   = []wa.Binary_Node_Attribute{{"id", "ABC"}, {"type", "mediaretry"}, {"from", "123@g.us"}},
		content = []wa.Binary_Node {
			{
				tag = "rmr",
				attrs = []wa.Binary_Node_Attribute {
					{"jid", "123@g.us"},
					{"from_me", "false"},
					{"participant", "321@s.whatsapp.net"},
				},
			},
			{
				tag = "encrypt",
				content = []wa.Binary_Node{{tag = "enc_p", content = ciphertext}, {tag = "enc_iv", content = nonce}},
			},
		},
	}

	if direct {
		rmr := &node.content.([]wa.Binary_Node)[0]
		rmr.attrs = []wa.Binary_Node_Attribute{{"jid", "321@s.whatsapp.net"}, {"from_me", "true" if own else "false"}}
	}

	wire: [1024]u8
	n, encode_error := wa.binary_node_encode(wire[:], node)
	testing.expect_value(t, encode_error.kind, .None)
	document, decode_error := wa.binary_node_decode(wire[:n])
	testing.expect_value(t, decode_error.kind, .None)

	return document
}

// Exercise actual authenticated recovery, including a failed fresh download.
// The retry must use the new route without retaining its soon-zeroed scratch
// storage in the caller's original Media_Message.
@(test)
media_retry_preserves_caller_routing_metadata :: proc(t: ^testing.T) {
	state := Media_Retry_Test_State {
		t = t,
	}

	context.user_ptr = &state
	auth: wa.Auth_State
	socket: wa.Socket
	media_retry_test_socket(t, &socket, &auth)
	defer wa.frame_transport_clear(&socket.client.frames)

	defer delete(socket.pending_media_retry)

	cipher_hex :=
		"a480b04f11ee5fa82b42320a244eff457db59d7239cf27a03dcf5b25925fc805fe" +
		"6962c6769ece6da65780c8c9c3327a81670ea589ec153fdcacab8f06bf93b46e76a0"
	ciphertext, valid := hex.decode(transmute([]u8)cipher_hex)
	testing.expect_value(t, valid, nil)
	defer delete(ciphertext)

	nonce: [12]u8
	for &value, index in nonce {
		value = u8(index + 32)
	}

	document := media_retry_test_notification(t, ciphertext, nonce[:])
	append(&socket.pending_media_retry, document)
	key, hash: [32]u8
	for &value, index in key {
		value = u8(index)
	}

	media := wa.Media_Message {
		kind            = .Image,
		url             = "https://mmg.whatsapp.net/original.enc",
		direct_path     = "/original.enc",
		media_key       = key[:],
		file_sha256     = hash[:],
		file_enc_sha256 = hash[:],
		has_file_length = true,
	}

	original := media
	message := wa.Socket_Message {
		group       = "123@g.us",
		id          = "ABC",
		participant = "321@s.whatsapp.net",
	}

	_, error := wa.socket_media_download_recover(&socket, &message, &media, nil, {})

	testing.expect_value(t, error.kind, .Media_Failed)
	testing.expect_value(t, error.media.kind, .HTTP_Status)
	testing.expect_value(t, error.media.status, 410)
	testing.expect_value(t, state.calls, 1)
	testing.expect(t, state.writes > 0)
	testing.expect_value(t, media.url, original.url)
	testing.expect_value(t, media.direct_path, original.direct_path)
	testing.expect_value(t, raw_data(media.media_key), raw_data(original.media_key))
	testing.expect_value(t, socket.query_depth, 0)
	testing.expect(t, socket.websocket.read_deadline == {})
	testing.expect_value(t, len(socket.pending_media_retry), 0)
	message.group = ""
	message.participant = "321:4@s.whatsapp.net"
	append(&socket.pending_media_retry, media_retry_test_notification(t, ciphertext, nonce[:], direct = true))
	_, dm_error := wa.socket_media_download_recover(&socket, &message, &media, nil, {})

	testing.expect(t, dm_error.kind == .Media_Failed && dm_error.media.status == 410)
	testing.expect_value(t, state.calls, 2)
	testing.expect_value(t, len(socket.pending_media_retry), 0)
	message.from_me = true
	message.recipient, message.participant = message.participant, "123:2@s.whatsapp.net"
	append(&socket.pending_media_retry, media_retry_test_notification(t, ciphertext, nonce[:], direct = true, own = true))
	_, echo_error := wa.socket_media_download_recover(&socket, &message, &media, nil, {})

	testing.expect(t, echo_error.kind == .Media_Failed && echo_error.media.status == 410)
	testing.expect_value(t, state.calls, 3)

}

writer_golden_media :: proc(kind: wa.Media_Kind, buffers: ^[4][32]u8) -> wa.Media_Message {
	for i in 0 ..< 4 {
		for j in 0 ..< 32 {
			buffers[i][j] = u8(i * 32 + j)
		}
	}

	message := wa.Media_Message {
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

@(test)
writer_media_encoders_match_retired_writer :: proc(t: ^testing.T) {
	out: [4096]u8
	buffers: [4][32]u8

	n, err := wa.media_message_encode(out[:], writer_golden_media(.Image, &buffers))
	testing.expect_value(t, err.kind, wa.Media_Error_Kind.None)
	writer_expect_hex(t, out[:n], writer_golden_media_Image, "image")

	n, err = wa.media_message_encode(out[:], writer_golden_media(.Document, &buffers))
	testing.expect_value(t, err.kind, wa.Media_Error_Kind.None)
	writer_expect_hex(t, out[:n], writer_golden_media_Document, "document")

	key := wa.Message_Key {
		remote_jid = "2@g.us",
		has_remote_jid = true,
		id = "ID1",
		has_id = true,
		participant = "3@s.whatsapp.net",
		has_participant = true,
		from_me = true,
		has_from_me = true,
	}

	n, err = wa.reaction_checkmark_encode(out[:], key, 1700000000123)
	testing.expect_value(t, err.kind, wa.Media_Error_Kind.None)
	writer_expect_hex(t, out[:n], writer_golden_reaction, "reaction")
}

// Hand-decoded Message{reactionMessage: {key{remoteJid "2@g.us", fromMe, id
// "ID1", participant "3@s.whatsapp.net"}, text "✅", senderTimestampMs}}.
CODEC_API_REACTION_HEX :: "f2022f0a210a063240672e757310011a0349443122103340732e77686174736170702e6e65741203e29c8520fbd095ffbc31"

codec_api_reaction_key :: proc() -> wa.Message_Key {
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
reaction_checkmark_encode_matches_reference_bytes_and_decodes_back :: proc(t: ^testing.T) {
	storage: [128]u8
	n, error := wa.reaction_checkmark_encode(storage[:], codec_api_reaction_key(), 1700000000123)
	testing.expect_value(t, error.kind, wa.Media_Error_Kind.None)
	testing.expect(t, bytes.equal(storage[:n], test_fixtures.codec_api_hex(CODEC_API_REACTION_HEX)))

	message, decode_error := wa.reaction_message_decode(storage[:n])
	testing.expect_value(t, decode_error.kind, wa.Media_Error_Kind.None)
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
	_, empty := wa.reaction_checkmark_encode(storage[:], {}, 1)
	testing.expect_value(t, empty.kind, wa.Media_Error_Kind.Invalid_Reaction_Key)
	_, no_id := wa.reaction_checkmark_encode(storage[:], {remote_jid = "2@g.us"}, 1)
	testing.expect_value(t, no_id.kind, wa.Media_Error_Kind.Invalid_Reaction_Key)
	_, no_jid := wa.reaction_checkmark_encode(storage[:], {id = "ID1"}, 1)
	testing.expect_value(t, no_jid.kind, wa.Media_Error_Kind.Invalid_Reaction_Key)

	want := len(CODEC_API_REACTION_HEX) / 2
	small: [16]u8
	size, undersized := wa.reaction_checkmark_encode(small[:], codec_api_reaction_key(), 1700000000123)
	testing.expect_value(t, undersized.kind, wa.Media_Error_Kind.Destination_Undersized)
	testing.expect_value(t, size, want)

	// A sparse key omits absent optional fields.
	n, minimal := wa.reaction_checkmark_encode(storage[:], {remote_jid = "2@g.us", id = "ID1"}, 7)
	testing.expect_value(t, minimal.kind, wa.Media_Error_Kind.None)
	decoded, decode_error := wa.reaction_message_decode(storage[:n])
	testing.expect_value(t, decode_error.kind, wa.Media_Error_Kind.None)
	testing.expect(t, !decoded.key.has_participant && !decoded.key.has_from_me)
	testing.expect_value(t, decoded.sender_timestamp_ms, i64(7))
}

@(test)
reaction_message_decode_rejects_malformed_and_ignores_other_messages :: proc(t: ^testing.T) {
	// A text message is not a reaction: empty result, no error.
	text := [?]u8{0x0a, 0x02, 'h', 'i'}

	message, error := wa.reaction_message_decode(text[:])
	testing.expect_value(t, error.kind, wa.Media_Error_Kind.None)
	testing.expect(t, !message.has_key && !message.has_text)

	// Duplicate text field inside the reaction.
	duplicate := test_fixtures.codec_api_hex("f2020a" + "1203616161" + "1203626262")
	_, duplicate_error := wa.reaction_message_decode(duplicate)
	testing.expect_value(t, duplicate_error.kind, wa.Media_Error_Kind.Duplicate_Field)

	// Invalid UTF-8 in the text field.
	bad_text := test_fixtures.codec_api_hex("f20205" + "1203" + "ff0102")
	_, utf8_error := wa.reaction_message_decode(bad_text)
	testing.expect_value(t, utf8_error.kind, wa.Media_Error_Kind.Invalid_UTF8)

	// Truncated field length.
	valid := test_fixtures.codec_api_hex(CODEC_API_REACTION_HEX)
	_, truncated := wa.reaction_message_decode(valid[:len(valid) - 3])
	testing.expect(t, truncated.kind != .None)

	// Wire type mismatch: timestamp must be a varint.
	wrong_wire := test_fixtures.codec_api_hex("f20203" + "220100")
	_, wire_error := wa.reaction_message_decode(wrong_wire)
	testing.expect_value(t, wire_error.kind, wa.Media_Error_Kind.Invalid_Protobuf)

	oversized := make([]u8, wa.MAX_PROTOBUF_MESSAGE_SIZE + 1)
	defer delete(oversized)

	_, size_error := wa.reaction_message_decode(oversized)
	testing.expect_value(t, size_error.kind, wa.Media_Error_Kind.Message_Oversized)
}

@(test)
send_image_rejects_bad_state_and_inputs_before_any_network_work :: proc(t: ^testing.T) {
	_, nil_socket := wa.socket_send_image(nil, "123@g.us", nil)
	testing.expect_value(t, nil_socket.kind, wa.Socket_Error_Kind.Invalid_State)

	auth: wa.Auth_State
	socket := wa.Socket {
		phase = .Online,
		auth = &auth,
	}

	_, not_group := wa.socket_send_image(&socket, "user@s.whatsapp.net", nil)
	testing.expect_value(t, not_group.kind, wa.Socket_Error_Kind.Invalid_Config)
	_, wrong_mime := wa.socket_send_image(&socket, "123@g.us", nil, mime_type = "application/pdf")
	testing.expect_value(t, wrong_mime.kind, wa.Socket_Error_Kind.Invalid_Config)

	socket.phase = .Closed
	_, offline := wa.socket_send_image(&socket, "123@g.us", nil)
	testing.expect_value(t, offline.kind, wa.Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, socket.sequence, u64(0))
}

@(test)
send_reaction_validates_state_key_and_text :: proc(t: ^testing.T) {
	_, nil_socket := wa.socket_send_reaction(nil, {})

	testing.expect_value(t, nil_socket.kind, wa.Socket_Error_Kind.Invalid_State)

	auth: wa.Auth_State
	socket := wa.Socket {
		phase = .Online,
		auth = &auth,
	}

	good := wa.Message_Key {
		remote_jid = "123@g.us",
		id = "ID1",
	}

	_, no_id := wa.socket_send_reaction(&socket, {remote_jid = "123@g.us"})

	testing.expect_value(t, no_id.kind, wa.Socket_Error_Kind.Invalid_Config)
	_, not_group := wa.socket_send_reaction(&socket, {remote_jid = "1@s.whatsapp.net", id = "ID1"})

	testing.expect_value(t, not_group.kind, wa.Socket_Error_Kind.Invalid_Config)
	_, bad_utf8 := wa.socket_send_reaction(&socket, good, "\xff")
	testing.expect_value(t, bad_utf8.kind, wa.Socket_Error_Kind.Invalid_Config)
	long := string(make([]u8, 65, context.temp_allocator))
	_, too_long := wa.socket_send_reaction(&socket, good, long)
	testing.expect_value(t, too_long.kind, wa.Socket_Error_Kind.Invalid_Config)

	socket.phase = .Failed
	_, offline := wa.socket_send_reaction(&socket, good)
	testing.expect_value(t, offline.kind, wa.Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, socket.sequence, u64(0))
}

Download_Fixture :: struct {
	socket:     wa.Socket,
	auth:       wa.Auth_State,
	state:      test_fixtures.Download_State,
	encrypted:  [128]u8,
	protobuf:   [512]u8,
	plain_size: int,
	message:    wa.Socket_Message,
	media_key:  [32]u8,
}

download_fixture_init :: proc(f: ^Download_Fixture, plaintext: string) {
	for &b, i in f.media_key {
		b = u8(i)
	}

	n, metadata, encrypt_error := wa.media_encrypt(f.encrypted[:], transmute([]u8)plaintext, .Image, f.media_key)
	assert(encrypt_error.kind == .None)
	f.state.encrypted = f.encrypted[:n]
	f.plain_size = len(plaintext)
	message := wa.Media_Message {
		kind = .Image,
		direct_path = "/o1/v/t62/file.enc",
		media_key = metadata.media_key[:],
		file_sha256 = metadata.file_sha256[:],
		file_enc_sha256 = metadata.file_enc_sha256[:],
		file_length = metadata.file_length,
		has_file_length = true,
	}

	size, encode_error := wa.media_message_encode(f.protobuf[:], message)
	assert(encode_error.kind == .None)
	f.message = {
		group       = "123@g.us",
		participant = "321@s.whatsapp.net",
		id          = "ABC",
		protobuf    = f.protobuf[:size],
	}

	f.socket = {
		phase = .Online,
		auth = &f.auth,
		config = {query_timeout = time.Second, http_execute = test_fixtures.download_http},
	}
}

@(test)
download_media_fetches_decrypts_and_verifies_over_the_cdn_path :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)

	download_fixture_init(fixture, test_fixtures.SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	destination: [128]u8

	n, error := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, string(destination[:n]), test_fixtures.SEND_IMAGE_PLAINTEXT)
	testing.expect_value(t, fixture.state.calls, 1)
	testing.expect_value(t, fixture.state.url, "https://mmg.whatsapp.net/o1/v/t62/file.enc")
	testing.expect_value(t, fixture.state.redirects_seen, 0)
	fixture.message.group = ""
	dm_n, dm_error := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])
	testing.expect(t, dm_error.kind == .None && string(destination[:dm_n]) == test_fixtures.SEND_IMAGE_PLAINTEXT)
}

@(test)
download_media_corrupt_ciphertext_fails_authentication_and_leaves_destination_untouched :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)

	download_fixture_init(fixture, test_fixtures.SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	fixture.encrypted[3] ~= 1
	destination: [128]u8

	for &b in destination {
		b = 0x55
	}

	_, error := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Media_Failed)
	testing.expect(t, error.media.kind == .Encrypted_Hash_Mismatch || error.media.kind == .MAC_Mismatch)

	for b in destination {
		testing.expect_value(t, b, u8(0x55))
	}

	testing.expect_value(t, fixture.state.calls, 1)
}

@(test)
download_media_surfaces_http_status_without_retrying_other_codes :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)

	download_fixture_init(fixture, test_fixtures.SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	fixture.state.status = 503
	destination: [128]u8

	_, error := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Media_Failed)
	testing.expect_value(t, error.media.kind, wa.Media_Error_Kind.HTTP_Status)
	testing.expect_value(t, error.media.status, 503)
	testing.expect_value(t, fixture.state.calls, 1)
}

// Offline-batch media arrives while the socket is still Provisioning (live staging
// restart after six days offline: each refusal cost the application a reconnect).
// The CDN download runs; an expired one waits for Online, where the phone's
// mediaretry answer is handled.
@(test)
download_media_runs_offline_backlog_while_provisioning :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)

	download_fixture_init(fixture, test_fixtures.SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	fixture.socket.phase = .Provisioning
	destination: [128]u8

	n, error := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, string(destination[:n]), test_fixtures.SEND_IMAGE_PLAINTEXT)
	testing.expect_value(t, fixture.state.calls, 1)
	testing.expect_value(t, fixture.socket.phase, wa.Socket_Phase.Provisioning)
	testing.expect_value(t, fixture.socket.sequence, u64(0))

	fixture.state.status = 404
	for &b in destination {
		b = 0x55
	}

	_, expired := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, expired.kind, wa.Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, fixture.state.calls, 2)
	testing.expect_value(t, fixture.socket.sequence, u64(0))

	for b in destination {
		testing.expect_value(t, b, u8(0x55))
	}

	// Before login there is no session to download for.
	fixture.socket.phase = .Pairing
	_, refused := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])
	testing.expect_value(t, refused.kind, wa.Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, fixture.state.calls, 2)
}

@(test)
download_media_preflights_state_message_and_destination_before_network :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)

	download_fixture_init(fixture, test_fixtures.SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	destination: [128]u8

	_, nil_socket := wa.socket_download_media(nil, &fixture.message, destination[:])
	testing.expect_value(t, nil_socket.kind, wa.Socket_Error_Kind.Invalid_State)
	_, nil_message := wa.socket_download_media(&fixture.socket, nil, destination[:])
	testing.expect_value(t, nil_message.kind, wa.Socket_Error_Kind.Invalid_Config)

	bad_group := fixture.message
	bad_group.group = "user@s.whatsapp.net"
	_, group_error := wa.socket_download_media(&fixture.socket, &bad_group, destination[:])
	testing.expect_value(t, group_error.kind, wa.Socket_Error_Kind.Invalid_Config)

	small: [4]u8
	size, undersized := wa.socket_download_media(&fixture.socket, &fixture.message, small[:])
	testing.expect_value(t, undersized.kind, wa.Socket_Error_Kind.Media_Failed)
	testing.expect_value(t, undersized.media.kind, wa.Media_Error_Kind.Destination_Undersized)
	testing.expect_value(t, size, len(test_fixtures.SEND_IMAGE_PLAINTEXT))

	truncated := [3]u8{26, 5, 10}

	malformed := fixture.message
	malformed.protobuf = truncated[:]
	_, malformed_error := wa.socket_download_media(&fixture.socket, &malformed, destination[:])
	testing.expect_value(t, malformed_error.media.kind, wa.Media_Error_Kind.Invalid_Protobuf)

	text := [3]u8{10, 1, 'x'}

	not_media := fixture.message
	not_media.protobuf = text[:]
	_, text_error := wa.socket_download_media(&fixture.socket, &not_media, destination[:])
	testing.expect_value(t, text_error.media.kind, wa.Media_Error_Kind.Invalid_Kind)

	fixture.socket.phase = .Failed
	_, offline := wa.socket_download_media(&fixture.socket, &fixture.message, destination[:])
	testing.expect_value(t, offline.kind, wa.Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, fixture.state.calls, 0)
}

@(test)
http_execute_requires_an_online_socket_and_never_runs_the_request_otherwise :: proc(t: ^testing.T) {
	marker: test_fixtures.Http_Marker
	_, nil_socket := wa.socket_http_execute(nil, test_fixtures.http_marker_request(&marker), {}, execute = test_fixtures.http_marker_execute)
	testing.expect_value(t, nil_socket.kind, wa.Socket_Error_Kind.Invalid_State)

	socket := wa.Socket {
		phase = .Failed,
	}

	_, offline := wa.socket_http_execute(&socket, test_fixtures.http_marker_request(&marker), {}, execute = test_fixtures.http_marker_execute)
	testing.expect_value(t, offline.kind, wa.Socket_Error_Kind.Invalid_State)
	testing.expect(t, !sync.atomic_load(&marker.started))
}

@(test)
download_private_voice_note_and_audio_attachment :: proc(t: ^testing.T) {
	// Independently generated HKDF-SHA256 / AES-256-CBC / HMAC test vector.
	ciphertext, ok := hex.decode(transmute([]u8)string("d874b3233c0dcef4e9a268bc3b415bd2a7ec798e1433f153fc5499bd4392ef89f01b545fe9a517a297aa"))
	assert(ok == nil)
	defer delete(ciphertext)

	plain_hash, a := hex.decode(transmute([]u8)string("a69b9f40bedbabf3e12dfc7196016db2025b82ab86a6685d3e61fadeb3cbe658"))
	enc_hash, b := hex.decode(transmute([]u8)string("57b9cee7e10ae671167ef34896b1de2854a55defa4df5268c43d6400ca81447d"))
	assert(a == nil && b == nil)
	defer delete(plain_hash)

	defer delete(enc_hash)

	f := new(Download_Fixture)
	defer free(f)

	download_fixture_init(f, "setup")
	f.state.encrypted = ciphertext
	context.user_ptr = &f.state
	for voice_note in ([]bool{true, false}) {
		body: [300]u8
		w := wa.Protobuf_Writer{dst = body[:]}

		wa.protobuf_write_string(&w, 2, "audio/ogg; codecs=opus")
		wa.protobuf_write_bytes(&w, 3, plain_hash)
		wa.protobuf_write_uint(&w, 4, len("OggS audio fixture"))
		wa.protobuf_write_uint(&w, 5, 2)
		if voice_note {wa.protobuf_write_uint(&w, 6, 1)}

		wa.protobuf_write_bytes(&w, 7, f.media_key[:])
		wa.protobuf_write_bytes(&w, 8, enc_hash)
		wa.protobuf_write_string(&w, 9, "/audio/test.enc")
		wa.protobuf_write_bytes(&w, 19, []u8{1, 2, 3}) // Optional waveform.

		outer := wa.Protobuf_Writer{dst = f.protobuf[:]}

		wa.protobuf_write_bytes(&outer, 8, body[:w.at])
		f.message.group = ""
		f.message.protobuf = f.protobuf[:outer.at]
		m, de := wa.media_message_decode(f.message.protobuf)
		testing.expect(t, de.kind == .None && m.kind == .Audio && m.voice_note == voice_note)
		testing.expect(t, m.duration_seconds == 2 && m.mime_type == "audio/ogg; codecs=opus")
		dst: [64]u8
		n, err := wa.socket_download_media(&f.socket, &f.message, dst[:])
		testing.expect(t, err.kind == .None && string(dst[:n]) == "OggS audio fixture")
		testing.expect_value(t, f.state.url, "https://mmg.whatsapp.net/audio/test.enc")
	}

	ciphertext[0] ~= 1
	dst := [3]u8{1, 2, 3}

	output: [64]u8
	copy(output[:], dst[:])
	_, corrupt := wa.socket_download_media(&f.socket, &f.message, output[:])
	testing.expect_value(t, corrupt.media.kind, .Encrypted_Hash_Mismatch)
	testing.expect(t, bytes.equal(output[:3], dst[:]))
}

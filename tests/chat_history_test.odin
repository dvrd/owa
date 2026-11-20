package whatsapp_test

import "core:bytes"
import "core:testing"
import fixtures "fixtures/client"
import wa "shared:whatsapp"

@(test)
chat_history_request_encodes_initial_and_anchored_pages :: proc(t: ^testing.T) {
	buf: [512]u8
	vectors := [2]string {
		"6221101082011c080322180a1232323240732e77686174736170702e6e657440012032",
		"622f101082012a080322260a1232323240732e77686174736170702e6e65741206616e63686f72180128d2ebcfaa062032",
	}
	for anchor, index in ([2]wa.Chat_History_Cursor {
			{},
			{id = "anchor", from_me = true, timestamp = 1700001234},
		}) {
		expected := fixtures.codec_api_hex(vectors[index])
		n, e := wa.chat_history_request_encode(buf[:], "222@s.whatsapp.net", anchor, 50)
		testing.expect(t, e.kind == .None && bytes.equal(expected, buf[:n]))
	}
	for count in ([]int{0, 51}) {
		_, e := wa.chat_history_request_encode(buf[:], "222@s.whatsapp.net", {}, count)
		testing.expect_value(t, e.kind, .Invalid_Config)
	}
	for jid in ([]string{"222@g.us", "222:1@lid"}) {
		_, e := wa.chat_history_request_encode(buf[:], jid, {}, 50)
		testing.expect_value(t, e.kind, .Invalid_Config)
	}
	_, missing := wa.chat_history_request_encode(buf[:], "222@lid", {id = "unknown"}, 1)
	testing.expect_value(t, missing.kind, .Invalid_Config)
}

@(test)
history_pages_match_request_and_chat_and_preserve_original_messages :: proc(t: ^testing.T) {
	request := wa.Pending_Chat_History {
		id = "q",
	}
	defer {for ref in request.notifications {delete(ref)}; delete(request.notifications)}
	for ignored in ([][]u8{{48, 4, 98, 1, 'q'}, {48, 6, 98, 1, 'z'}, {48, 6}}) {
		testing.expect_value(
			t,
			wa.collect_chat_history_notification(&request, ignored).kind,
			.None,
		)
	}
	testing.expect_value(t, len(request.notifications), 0)
	testing.expect_value(
		t,
		wa.collect_chat_history_notification(&request, []u8{48, 6, 98, 1, 'q'}).kind,
		.None,
	)
	testing.expect_value(t, len(request.notifications), 1)
	store: wa.State_Store
	assert(wa.state_store_init(&store, [32]u8{0 = 1}).kind == .None)
	defer wa.state_store_clear(&store)
	assert(wa.socket_lid_mapping_stage(&store, "222@s.whatsapp.net", "777@lid").kind == .None)
	raw: [512]u8
	compressed := fixtures.codec_api_hex(
		"789ce36013aae7123232327228d62bcf482c294e2c28d0cb4b2d11b2e032e392c52623c020c55a969f999c2ac4efc42bc499589a9299af9f9f9e6ec028d1f0e8fc2a36217d2e5d2e19ac3a19a5584a522b4a84d8b95833527372f225be3d046a000043562655",
	)
	page, decompressed := wa.decompress_history_chunk(raw[:], compressed)
	assert(decompressed.kind == .None)
	messages: [dynamic]^wa.Socket_Message
	defer {for msg in messages {wa.socket_message_destroy(msg)}; delete(messages)}
	testing.expect_value(
		t,
		wa.decode_chat_history_chunk(&store, "888@lid", "111@lid", page, 2, &messages).kind,
		.Protocol_Error,
	)
	testing.expect_value(t, len(messages), 0)
	for _ in 0 ..< 2 {
		testing.expect_value(
			t,
			wa.decode_chat_history_chunk(&store, "777@lid", "111@lid", page, 2, &messages).kind,
			.None,
		)
	}
	assert(len(messages) == 2)
	voice, _ := wa.media_message_decode(messages[0].protobuf)
	testing.expect(
		t,
		voice.kind == .Audio &&
		voice.voice_note &&
		messages[0].id == "voice" &&
		!messages[0].from_me,
	)
	text, _ := wa.text_message_decode(messages[1].protobuf)
	testing.expect(
		t,
		text.text == "hello" && messages[1].from_me && messages[1].recipient == "777@lid",
	)
	testing.expect_value(t, messages[0].timestamp, u64(1700000000))
	_, corrupt := wa.decompress_history_chunk(raw[:], compressed[:len(compressed) - 1])
	testing.expect_value(t, corrupt.kind, .Protocol_Error)
}

@(test)
private_chat_history_cursor_survives_older_deliveries_and_accepts_legacy_sent_messages :: proc(
	t: ^testing.T,
) {
	store: wa.State_Store
	assert(wa.state_store_init(&store, [32]u8{0 = 1}).kind == .None)
	defer wa.state_store_clear(&store)
	chat := "111@s.whatsapp.net"
	assert(wa.socket_lid_mapping_stage(&store, chat, "333@lid").kind == .None)
	// The sender's legacy record supplies its original creation time even when
	// the receiving client never had chat history enabled.
	doc := wa.Binary_Node {
		tag     = "saved",
		attrs   = []wa.Binary_Node_Attribute{{"to", chat}, {"t", "90"}},
		content = []u8{10, 1, 'x'},
	}
	wire: [256]u8
	n, e := wa.binary_node_encode(wire[:], doc)
	assert(e.kind == .None)
	assert(wa.state_store_set(&store, .Outbound_Content, "out", wire[:n]).kind == .None)
	before, err := wa.latest_chat_history_cursor(&store, "333@lid")
	testing.expect(
		t,
		err.kind == .None &&
		before == (wa.Chat_History_Cursor{id = "out", timestamp = 90, from_me = true}),
	)
	newer := wa.Socket_Message {
		participant = "333:4@lid",
		id          = "in",
		timestamp   = 95,
	}
	assert(wa.store_chat_history_cursor(&store, &newer).kind == .None)
	newer.timestamp, newer.id = 80, "delayed"
	assert(wa.store_chat_history_cursor(&store, &newer).kind == .None)
	before, err = wa.latest_chat_history_cursor(&store, chat)
	testing.expect(
		t,
		err.kind == .None && before == (wa.Chat_History_Cursor{id = "in", timestamp = 95}),
	)
	unknown, other := wa.latest_chat_history_cursor(&store, "999@lid")
	testing.expect(t, other.kind == .None && unknown.id == "")
}

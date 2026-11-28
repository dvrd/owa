package whatsapp_test

import example "../../../examples/private_audio"
import fixtures "../../fixtures/client"
import "core:bytes"
import "core:testing"
import "core:time"
import wa "shared:whatsapp"

history_test_primary_reply :: proc(peer: ^Send_Peer, request_id: string) {
	history_test_reply_chunk(
		peer,
		request_id,
		fixtures.codec_api_hex(
			"789ce36013aae7123232327228d62bcf482c294e2c28d0cb4b2d11b2e032e392c52623c020c55a969f999c2ac4efc42bc499589a9299af9f9f9e6ec028d1f0e8fc2a36217d2e5d2e19ac3a19a5584a522b4a84d8b95833527372f225be3d046a000043562655",
		),
	)
}

history_test_reply_chunk :: proc(peer: ^Send_Peer, request_id: string, compressed: []u8) {
	ref, control: [2048]u8
	note := wa.Protobuf_Writer {
		dst = ref[:],
	}

	wa.protobuf_write_uint(&note, 6, 6)
	wa.protobuf_write_string(&note, 12, request_id)
	wa.protobuf_write_bytes(&note, 11, compressed)
	pr := wa.Protobuf_Writer {
		dst = control[:],
	}

	wa.protobuf_write_uint(&pr, 2, 5)
	wa.protobuf_write_bytes(&pr, 6, ref[:note.at])
	history_test_send_control(peer, request_id, control[:pr.at])
}

history_test_send_control :: proc(peer: ^Send_Peer, stanza_id: string, control: []u8) {
	msg, encrypted: [2048]u8
	envelope := wa.Protobuf_Writer {
		dst = msg[:],
	}

	wa.protobuf_write_bytes(&envelope, 12, control)
	padded := wa.pad_outbound_message(msg[:envelope.at])
	defer delete(padded)

	_, n, e := wa.signal_session_encrypt(
		&peer.pairwise[0],
		encrypted[:],
		padded,
		peer.store.identity,
	)
	assert(e.kind == .None)
	send_peer_enqueue(
		peer,
		{
			tag = "message",
			attrs = []wa.Binary_Node_Attribute{{"from", "111@s.whatsapp.net"}, {"id", stanza_id}},
			content = []wa.Binary_Node {
				{
					tag = "enc",
					attrs = []wa.Binary_Node_Attribute{{"type", "msg"}, {"v", "2"}},
					content = encrypted[:n],
				},
			},
		},
	)
}

@(test)
fetch_private_chat_history_from_primary_device :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	peer.history_reply = history_test_primary_reply
	page, err := wa.socket_fetch_chat_history(
		&peer.socket,
		"222@s.whatsapp.net",
		{id = "anchor", timestamp = 1700001234, from_me = true},
	)
	defer {for msg in page {wa.socket_message_destroy(msg)}

	delete(page)}

	testing.expect_value(t, err.kind, .None)
	testing.expect(t, len(page) == 2 && peer.durable && !peer.failed)
	testing.expect_value(t, len(peer.socket.queue), 0)
	testing.expect(t, peer.socket.history_request == nil)
}

@(test)
history_timeout_preserves_the_live_socket :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	peer.history_reply = proc(peer: ^Send_Peer, id: string) {send_peer_use_pipe(peer)}

	page, err := wa.socket_fetch_chat_history(
		&peer.socket,
		"222@s.whatsapp.net",
		timeout = 100 * time.Millisecond,
	)
	testing.expect_value(t, err.kind, .Query_Timeout)
	testing.expect(
		t,
		page == nil && peer.socket.phase == .Online && peer.socket.history_request == nil,
	)
	peer.history_reply = proc(peer: ^Send_Peer, id: string) {
		history_test_primary_reply(peer, id)
		send_peer_announce(peer)
	}

	recent, retry := wa.socket_fetch_recent_chat_history(
		&peer.socket,
		"222@s.whatsapp.net",
		"missing",
		timeout = time.Second,
	)
	defer {for m in recent.messages {wa.socket_message_destroy(m)}

	delete(recent.messages)}

	testing.expect(t, retry.kind == .None && len(recent.messages) == 2 && recent.target == nil)
}

@(test)
recent_history_ignores_stale_local_anchor :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	chat := "222@s.whatsapp.net"
	stale := wa.Socket_Message {
		participant = chat,
		id          = "yesterday",
		timestamp   = 90,
	}

	assert(wa.store_chat_history_cursor(&peer.store, &stale).kind == .None)
	peer.history_reply = history_test_primary_reply
	page, err := wa.socket_fetch_recent_chat_history(&peer.socket, chat, "voice")
	defer {for m in page.messages {wa.socket_message_destroy(m)}

	delete(page.messages)}

	assert(err.kind == .None)
	testing.expect(t, page.target != nil && page.target.id == "voice" && page.newest != nil)
	wire: [512]u8
	n, e := wa.chat_history_request_encode(wire[:], chat, {}, 50)
	assert(e.kind == .None)
	testing.expect(t, bytes.equal(wire[:n], peer.last_plain[:peer.last_size]))
}

voice_history_phone :: proc(peer: ^Send_Peer, id: string) {
	control, a := wa.read_unique_protobuf_field(peer.last_plain[:peer.last_size], 12, 2)
	op, b := wa.read_unique_protobuf_field(control.data, 16, 2)
	request, c := wa.read_unique_protobuf_field(op.data, 4, 2)
	mode, d := wa.read_unique_protobuf_field(request.data, 8, 0)
	anchor, e := wa.read_unique_protobuf_field(request.data, 2, 2)
	assert(a && b && c && d && e)
	page: string
	switch string(anchor.data) {
	case "yesterday":
		page = fixtures.VOICE_PAGE_BEFORE_STALE
	case "note-one":
		page = fixtures.VOICE_PAGE_BEFORE_FIRST
	case "note-two":
		page = fixtures.VOICE_PAGE_BEFORE_SECOND
	case "":
		assert(mode.value == 1)
		page = fixtures.VOICE_PAGE_RECENT
	case:
		panic("unexpected synthetic anchor")
	}

	history_test_reply_chunk(peer, id, fixtures.codec_api_hex(page))
}

@(test)
legacy_marker_and_last_voice_note :: proc(t: ^testing.T) {
	chat :: "222@s.whatsapp.net"
	for anchor in ([]string{"yesterday", "note-one", "note-two", ""}) {
		peer := send_peer_new()
		defer send_peer_destroy(peer)

		peer.history_reply = voice_history_phone
		assert(wa.socket_lid_mapping_stage(&peer.store, chat, "777@lid").kind == .None)
		stale := wa.Socket_Message {
			participant = chat,
			id          = "yesterday",
			timestamp   = 90,
		}

		assert(wa.store_chat_history_cursor(&peer.store, &stale).kind == .None)
		key, ke := wa.socket_inbox_key(&peer.socket, "", chat, "note-two")
		assert(ke.kind == .None)
		defer delete(key)

		assert(wa.socket_processed_set(&peer.store, key).kind == .None)
		absent, le := wa.load_private_audio(&peer.store, chat, "note-two")
		assert(absent == nil && le.kind == .None)
		if anchor != "" {
			cursor: wa.Chat_History_Cursor
			if anchor != "yesterday" {
				cursor = {
					id        = anchor,
					timestamp = 103 if anchor == "note-one" else 104,
				}
			}

			page, err := wa.socket_fetch_chat_history(&peer.socket, chat, cursor)
			defer {for m in page {wa.socket_message_destroy(m)}

			delete(page)}

			assert(err.kind == .None)
			switch anchor {
			case "yesterday":
				testing.expect(t, len(page) == 50 && page[0].timestamp == 50)
			case "note-one":
				testing.expect(
					t,
					len(page) == 3 && page[0].id == "text-b" && page[2].id == "question",
				)
			case "note-two":
				testing.expect(
					t,
					len(page) == 4 && page[0].id == "note-one" && page[3].id == "question",
				)
			}

			continue
		}

		page, err := wa.socket_fetch_recent_chat_history(&peer.socket, "777@lid", "note-two")
		defer {for m in page.messages {wa.socket_message_destroy(m)}

		delete(page.messages)}

		assert(err.kind == .None && page.target != nil)
		testing.expect(
			t,
			len(page.messages) == 5 && page.oldest.id == "question" && page.newest == page.target,
		)
		testing.expect(t, page.messages[1].id == "note-one" && page.target.id == "note-two")
		notes, located := example.voices_after_question(page, "Synthetic question?")
		testing.expect(
			t,
			located == .Found && notes[0].id == "note-one" && notes[1] == page.target,
		)
		state := fixtures.Download_State {
			encrypted = fixtures.codec_api_hex(fixtures.VOICE_2_CIPHER),
		}

		context.user_ptr = &state
		peer.socket.config.http_execute = fixtures.download_http
		dst: [64]u8
		n, download := wa.socket_download_media(&peer.socket, page.target, dst[:])
		testing.expect(t, download.kind == .None && string(dst[:n]) == "OggS synthetic voice 2")
	}
}

lookup_phone_reply :: proc(peer: ^Send_Peer, correlation, outer_id, chat, target: string) {
	// A WebMessageInfo with the synthetic second audio from the sender.
	key_buf, info_buf, resend_buf, result_buf, op_buf, control_buf: [1024]u8
	key := wa.Protobuf_Writer {
		dst = key_buf[:],
	}

	wa.protobuf_write_string(&key, 1, chat)
	wa.protobuf_write_uint(&key, 2, 0)
	wa.protobuf_write_string(&key, 3, target)
	info := wa.Protobuf_Writer {
		dst = info_buf[:],
	}

	wa.protobuf_write_bytes(&info, 1, key_buf[:key.at])
	wa.protobuf_write_bytes(&info, 2, fixtures.codec_api_hex(fixtures.VOICE_2_PROTO))
	wa.protobuf_write_uint(&info, 3, 104)
	resend := wa.Protobuf_Writer {
		dst = resend_buf[:],
	}

	wa.protobuf_write_bytes(&resend, 1, info_buf[:info.at])
	result := wa.Protobuf_Writer {
		dst = result_buf[:],
	}

	wa.protobuf_write_bytes(&result, 4, resend_buf[:resend.at])
	op := wa.Protobuf_Writer {
		dst = op_buf[:],
	}

	wa.protobuf_write_uint(&op, 1, 4)
	wa.protobuf_write_string(&op, 2, correlation)
	wa.protobuf_write_bytes(&op, 3, result_buf[:result.at])
	control := wa.Protobuf_Writer {
		dst = control_buf[:],
	}

	wa.protobuf_write_uint(&control, 2, 17)
	wa.protobuf_write_bytes(&control, 17, op_buf[:op.at])
	history_test_send_control(peer, outer_id, control_buf[:control.at])
}

@(test)
exact_key_recovers_synthetic_last_voice_after_processing :: proc(t: ^testing.T) {
	chat :: "222@s.whatsapp.net"
	for attempt in 0 ..< 3 {
		peer := send_peer_new()
		defer send_peer_destroy(peer)

		assert(wa.socket_lid_mapping_stage(&peer.store, chat, "777@lid").kind == .None)
		key, ke := wa.socket_inbox_key(&peer.socket, "", chat, "note-two")
		assert(ke.kind == .None)
		defer delete(key)

		assert(wa.socket_processed_set(&peer.store, key).kind == .None)
		timeout := time.Second
		switch attempt {
		case 0:
			peer.lookup_reply = proc(p: ^Send_Peer, id: string) {
				lookup_phone_reply(
					p,
					"expired-request",
					"stale-response",
					"222@s.whatsapp.net",
					"note-one",
				)
				lookup_phone_reply(p, id, "current-response", "777@lid", "note-two")
			}


		case 1:
			peer.lookup_reply = proc(p: ^Send_Peer, id: string) {
				lookup_phone_reply(p, id, "other-chat-response", "333@s.whatsapp.net", "note-two")
			}


		case 2:
			timeout = 100 * time.Millisecond
			peer.lookup_reply = proc(p: ^Send_Peer, id: string) {send_peer_use_pipe(p)}
		}

		message, e := wa.socket_fetch_private_message_by_id(
			&peer.socket,
			chat,
			"note-two",
			timeout,
		)
		defer wa.socket_message_destroy(message)

		// Message.protocolMessage / type 16 / operation 4 / placeholder key.
		expected := fixtures.codec_api_hex(
			"622b101082012608042a220a200a1232323240732e77686174736170702e6e657410001a086e6f74652d74776f",
		)
		testing.expect(t, bytes.equal(expected, peer.last_plain[:peer.last_size]))
		testing.expect(
			t,
			peer.socket.message_lookup == nil && !peer.failed && len(peer.socket.queue) == 0,
		)
		if attempt == 2 {
			testing.expect(t, e.kind == .Query_Timeout && message == nil); continue
		}

		assert(e.kind == .None)
		if attempt == 1 {
			testing.expect(t, message == nil); continue
		}

		assert(message != nil && message.id == "note-two" && message.timestamp == 104)
		state := fixtures.Download_State {
			encrypted = fixtures.codec_api_hex(fixtures.VOICE_2_CIPHER),
		}

		context.user_ptr = &state
		peer.socket.config.http_execute = fixtures.download_http
		dst: [64]u8
		n, download := wa.socket_download_media(&peer.socket, message, dst[:])
		testing.expect(t, download.kind == .None && string(dst[:n]) == "OggS synthetic voice 2")
	}
}

@(test)
history_budget_includes_the_outbound_write :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	peer.history_reply = proc(p: ^Send_Peer, id: string) {
		assert(p.socket.history_deadline != {})
		assert(p.socket.websocket.write_deadline == p.socket.history_deadline)
		history_test_primary_reply(p, id)
		time.sleep(max(time.Duration(0), time.diff(time.now(), p.socket.history_deadline)))
	}

	page, err := wa.socket_fetch_chat_history(&peer.socket, "222@s.whatsapp.net", timeout = 150 * time.Millisecond)
	testing.expect_value(t, err.kind, .Query_Timeout)
	testing.expect(t, page == nil && peer.socket.phase == .Online && peer.socket.history_deadline == {})
	testing.expect(t, peer.last_size > 0)
}

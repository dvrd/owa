package whatsapp_test

import fixtures "../../fixtures/client"
import "core:testing"
import "core:time"
import wa "shared:whatsapp"

history_test_primary_reply :: proc(peer: ^Send_Peer, request_id: string) {
	ref, control, msg, encrypted: [512]u8
	note := wa.Protobuf_Writer {
		dst = ref[:],
	}
	wa.protobuf_write_uint(&note, 6, 6)
	wa.protobuf_write_string(&note, 12, request_id)
	wa.protobuf_write_bytes(
		&note,
		11,
		fixtures.codec_api_hex(
			"789ce36013aae7123232327228d62bcf482c294e2c28d0cb4b2d11b2e032e392c52623c020c55a969f999c2ac4efc42bc499589a9299af9f9f9e6ec028d1f0e8fc2a36217d2e5d2e19ac3a19a5584a522b4a84d8b95833527372f225be3d046a000043562655",
		),
	)
	pr := wa.Protobuf_Writer {
		dst = control[:],
	}
	wa.protobuf_write_uint(&pr, 2, 5)
	wa.protobuf_write_bytes(&pr, 6, ref[:note.at])
	envelope := wa.Protobuf_Writer {
		dst = msg[:],
	}
	wa.protobuf_write_bytes(&envelope, 12, control[:pr.at])
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
			attrs = []wa.Binary_Node_Attribute {
				{"from", "111@s.whatsapp.net"},
				{"id", "history-reply"},
			},
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
	defer {for msg in page {wa.socket_message_destroy(msg)}; delete(page)}
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
		timeout = time.Millisecond,
	)
	testing.expect_value(t, err.kind, .Query_Timeout)
	testing.expect(
		t,
		page == nil && peer.socket.phase == .Online && peer.socket.history_request == nil,
	)
}

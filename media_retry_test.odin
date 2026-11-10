package whatsapp

import http "../http"
import network_client "../surf"
import "core:encoding/hex"
import "core:testing"

Media_Retry_Test_State :: struct {t: ^testing.T, calls, writes: int}

media_retry_test_http :: proc(
	request: http.Request, config: network_client.Config,
) -> (network_client.Response, network_client.HTTP_Error) {
	state := cast(^Media_Retry_Test_State)context.user_ptr
	state.calls += 1
	testing.expect_value(state.t, request.url, "https://mmg.whatsapp.net/new.enc")
	testing.expect_value(state.t, config.max_redirects, 0)
	return {status = 410}, {}
}

media_retry_test_write :: proc(
	data: rawptr, src: []u8,
) -> (int, network_client.WebSocket_Stream_Error) {
	state := cast(^Media_Retry_Test_State)context.user_ptr
	state.writes += 1
	return len(src), {}
}

media_retry_test_read :: proc(
	data: rawptr, dst: []u8,
) -> (int, network_client.WebSocket_Stream_Error) {return 0, {kind = .EOF}}

media_retry_test_close :: proc(data: rawptr) -> network_client.WebSocket_Stream_Error {
	return {}
}

media_retry_test_socket :: proc(t: ^testing.T, socket: ^Socket, auth: ^Auth_State) {
	jid := "123:4@s.whatsapp.net"
	auth.account.jid_size = copy(auth.account.jid[:], transmute([]u8)jid)
	socket.auth = auth
	socket.config.http_execute = media_retry_test_http
	socket.websocket = {
		phase = .Open, allocator = context.allocator,
		config = {host = "synthetic.invalid", max_message_size = 4096},
		stream = {read = media_retry_test_read, write = media_retry_test_write,
			close = media_retry_test_close},
	}
	socket.client = {
		phase = .Noise_Ready, websocket = &socket.websocket,
		config = {max_frame_payload = 4096}, noise = {phase = .Transport},
	}
	testing.expect_value(t,
		frame_transport_init(&socket.client.frames, &socket.websocket, 4096).kind, .None)
}

// Independently pinned Baileys 6.7.23/WAProto + Node AES-GCM notification for
// key bytes 0..31, stanza ABC, nonce bytes 32..43 and direct path /new.enc.
media_retry_test_notification :: proc(
	t: ^testing.T, ciphertext, nonce: []u8,
) -> Binary_Document {
	node := Binary_Node{
		tag = "notification",
		attrs = []Binary_Node_Attribute{{"id", "ABC"}, {"type", "mediaretry"},
			{"from", "123@g.us"}},
		content = []Binary_Node{
			{tag = "rmr", attrs = []Binary_Node_Attribute{{"jid", "123@g.us"},
				{"from_me", "false"}, {"participant", "321@s.whatsapp.net"}}},
			{tag = "encrypt", content = []Binary_Node{
				{tag = "enc_p", content = ciphertext}, {tag = "enc_iv", content = nonce},
			}},
		},
	}
	wire: [1024]u8
	n, encode_error := binary_node_encode(wire[:], node)
	testing.expect_value(t, encode_error.kind, .None)
	document, decode_error := binary_node_decode(wire[:n])
	testing.expect_value(t, decode_error.kind, .None)
	return document
}

// Exercise actual authenticated recovery, including a failed fresh download.
// The retry must use the new route without retaining its soon-zeroed scratch
// storage in the caller's original Media_Message.
@(test)
media_retry_preserves_caller_routing_metadata :: proc(t: ^testing.T) {
	state := Media_Retry_Test_State{t = t}
	context.user_ptr = &state
	auth: Auth_State
	socket: Socket
	media_retry_test_socket(t, &socket, &auth)
	defer frame_transport_clear(&socket.client.frames)
	defer delete(socket.pending_media_retry)
	cipher_hex := "a480b04f11ee5fa82b42320a244eff457db59d7239cf27a03dcf5b25925fc805fe" +
		"6962c6769ece6da65780c8c9c3327a81670ea589ec153fdcacab8f06bf93b46e76a0"
	ciphertext, valid := hex.decode(transmute([]u8)cipher_hex)
	testing.expect(t, valid)
	defer delete(ciphertext)
	nonce: [12]u8; for &value, index in nonce do value = u8(index + 32)
	document := media_retry_test_notification(t, ciphertext, nonce[:])
	append(&socket.pending_media_retry, document)
	key, hash: [32]u8
	for &value, index in key do value = u8(index)
	media := Media_Message{
		kind = .Image, url = "https://mmg.whatsapp.net/original.enc",
		direct_path = "/original.enc", media_key = key[:], file_sha256 = hash[:],
		file_enc_sha256 = hash[:], has_file_length = true,
	}
	original := media
	message := Socket_Message{group = "123@g.us", id = "ABC",
		participant = "321@s.whatsapp.net"}
	_, error := socket_media_download_recover(&socket, &message, &media, nil, {})
	testing.expect_value(t, error.kind, .Media_Failed)
	testing.expect_value(t, error.media.kind, .HTTP_Status)
	testing.expect_value(t, error.media.status, 410)
	testing.expect_value(t, state.calls, 1)
	testing.expect(t, state.writes > 0)
	testing.expect_value(t, media.url, original.url)
	testing.expect_value(t, media.direct_path, original.direct_path)
	testing.expect_value(t, raw_data(media.media_key), raw_data(original.media_key))
	testing.expect_value(t, socket.query_depth, 0)
	testing.expect_value(t, socket.read_deadline_scopes, 0)
	testing.expect_value(t, len(socket.pending_media_retry), 0)
}

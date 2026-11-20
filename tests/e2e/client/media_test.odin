package whatsapp_test

import test_fixtures "../../fixtures/client"
import "core:bytes"
import "core:sync"
import "core:testing"
import "core:time"
import network_client "shared:surf"
import wa "shared:whatsapp"

@(test)
send_image_encrypts_uploads_and_delivers_to_every_device :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	context.user_ptr = peer
	plaintext := test_fixtures.SEND_IMAGE_PLAINTEXT

	id, error := wa.socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext, "receipt", "image/png")
	defer delete(id)

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)
	testing.expect(t, len(id) > 0)
	testing.expect(t, !peer.failed && peer.durable)
	testing.expect_value(t, string(peer.last_id[:peer.last_id_size]), id)
	testing.expect_value(t, string(peer.media_type[:peer.media_type_size]), "image")
	testing.expect_value(t, peer.upload_requests, 1)
	testing.expect_value(t, peer.metadata_queries, 1)
	testing.expect_value(t, peer.device_queries, 1)
	testing.expect_value(t, peer.key_queries, 2)

	message, decode_error := wa.media_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, decode_error.kind, wa.Media_Error_Kind.None)
	testing.expect_value(t, message.kind, wa.Media_Kind.Image)
	testing.expect_value(t, message.caption, "receipt")
	testing.expect_value(t, message.mime_type, "image/png")
	testing.expect_value(t, message.direct_path, "/synthetic.enc")
	testing.expect_value(t, message.file_length, u64(len(plaintext)))

	// What reached the CDN is only ciphertext that the message's key opens.
	testing.expect(t, !bytes.contains(peer.uploaded[:], transmute([]u8)plaintext))
	metadata, metadata_error := wa.media_metadata_from_message(message)
	defer wa.media_metadata_clear(&metadata)
	testing.expect_value(t, metadata_error.kind, wa.Media_Error_Kind.None)
	plain: [128]u8
	n, decrypt_error := wa.media_decrypt(plain[:], peer.uploaded[:], .Image, metadata)
	testing.expect_value(t, decrypt_error.kind, wa.Media_Error_Kind.None)
	testing.expect_value(t, string(plain[:n]), plaintext)

	// Each send uses a fresh media key and message id.
	first_key := bytes.clone(message.media_key)
	defer delete(first_key)
	second_id, second_error := wa.socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext)
	defer delete(second_id)
	testing.expect_value(t, second_error.kind, wa.Socket_Error_Kind.None)
	testing.expect(t, second_id != id)
	second, _ := wa.media_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, second.mime_type, "image/jpeg")
	testing.expect(t, !bytes.equal(second.media_key, first_key))
	testing.expect_value(t, len(peer.raw), 2)
	testing.expect(t, !peer.failed)
}

@(test)
send_image_upload_rejection_sends_no_message :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	context.user_ptr = peer
	peer.upload_status = 500
	plaintext := test_fixtures.SEND_IMAGE_PLAINTEXT

	id, error := wa.socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext)
	defer delete(id)

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Media_Failed)
	testing.expect(t, peer.upload_requests >= 1)
	testing.expect_value(t, len(peer.raw), 0)
	testing.expect_value(t, len(id), 0)
}

@(test)
send_image_failed_write_keeps_the_durable_outbound_message :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	context.user_ptr = peer
	peer.fail_message = true
	plaintext := test_fixtures.SEND_IMAGE_PLAINTEXT

	id, error := wa.socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext)
	defer delete(id)

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Session_Failed)
	testing.expect(t, len(id) > 0)
	testing.expect(t, peer.durable)
	stored, found := wa.state_store_get(&peer.store, .Outbound_Message, id)
	testing.expect(t, found)
	testing.expect_value(t, len(peer.raw), 1)
	testing.expect(t, bytes.equal(stored, peer.raw[0]))
}

@(test)
send_reaction_delivers_checkmark_by_default_and_custom_text :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	context.user_ptr = peer
	key := wa.Message_Key {
		remote_jid = "123@g.us",
		id = "quoted-original",
		participant = "222@s.whatsapp.net",
	}
	before := time.now()._nsec / i64(time.Millisecond)

	id, error := wa.socket_send_reaction(&peer.socket, key)
	defer delete(id)

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)
	testing.expect(t, !peer.failed && peer.durable)
	reaction, decode_error := wa.reaction_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, decode_error.kind, wa.Media_Error_Kind.None)
	testing.expect_value(t, reaction.text, "✅")
	testing.expect_value(t, reaction.key.id, "quoted-original")
	testing.expect_value(t, reaction.key.remote_jid, "123@g.us")
	testing.expect_value(t, reaction.key.participant, "222@s.whatsapp.net")
	testing.expect(t, reaction.sender_timestamp_ms >= before)
	testing.expect(t, reaction.sender_timestamp_ms <= time.now()._nsec / i64(time.Millisecond))
	testing.expect_value(t, peer.media_type_size, 0)

	other_id, other_error := wa.socket_send_reaction(&peer.socket, key, "👍")
	defer delete(other_id)
	testing.expect_value(t, other_error.kind, wa.Socket_Error_Kind.None)
	other, _ := wa.reaction_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, other.text, "👍")
	testing.expect(t, other_id != id)
	testing.expect_value(t, len(peer.raw), 2)
}

@(test)
http_execute_runs_off_thread_while_the_socket_keeps_serving_the_connection :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	send_peer_use_pipe(peer)
	marker: test_fixtures.Http_Marker
	peer.socket.session.config.keepalive_interval = time.Minute
	// A media-retry notification arrives while the request is in flight.
	send_peer_enqueue(
		peer,
		{
			tag = "notification",
			attrs = []wa.Binary_Node_Attribute{{"id", "preserved-retry"}, {"from", "s.whatsapp.net"}, {"type", "mediaretry"}},
			content = []wa.Binary_Node{{tag = "rmr", attrs = []wa.Binary_Node_Attribute{{"jid", "123@g.us"}, {"from_me", "false"}}}},
		},
	)
	send_peer_announce(peer)

	response, error := wa.socket_http_execute(&peer.socket, test_fixtures.http_marker_request(&marker), {}, execute = test_fixtures.http_marker_execute)
	defer network_client.response_destroy(&response)

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.None)
	testing.expect_value(t, response.status, 200)
	testing.expect_value(t, string(response.body), "finished")
	testing.expect(t, sync.atomic_load(&marker.completed))
	testing.expect(t, marker.worker_id != sync.current_thread_id())
	testing.expect(t, !peer.failed)
	testing.expect_value(t, peer.socket.phase, wa.Socket_Phase.Online)
	testing.expect_value(t, peer.socket.query_depth, 0)
	testing.expect_value(t, len(peer.socket.pending_media_retry), 1)
	id, _ := wa.node_attr(peer.socket.pending_media_retry[0].root, "id")
	testing.expect_value(t, id, "preserved-retry")
}

@(test)
http_execute_reports_executor_failure_as_media_http_failure :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	send_peer_use_pipe(peer)
	marker := test_fixtures.Http_Marker {
		fail = true,
	}

	response, error := wa.socket_http_execute(&peer.socket, test_fixtures.http_marker_request(&marker), {}, execute = test_fixtures.http_marker_execute)
	defer network_client.response_destroy(&response)

	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Media_Failed)
	testing.expect_value(t, error.media.kind, wa.Media_Error_Kind.HTTP_Failed)
	testing.expect(t, error.media.http.kind == .Deadline_Failed)
	testing.expect_value(t, len(response.body), 0)
	testing.expect(t, sync.atomic_load(&marker.completed))
	testing.expect_value(t, peer.socket.query_depth, 0)
}

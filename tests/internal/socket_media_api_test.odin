package whatsapp

import http "../http"
import network_client "../surf"
import "core:bytes"
import "core:sync"
import "core:testing"
import "core:time"

SEND_IMAGE_PLAINTEXT :: "synthetic PNG image bytes"

@(test)
send_image_encrypts_uploads_and_delivers_to_every_device :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	context.user_ptr = peer
	plaintext := SEND_IMAGE_PLAINTEXT

	id, error := socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext, "receipt", "image/png")
	defer delete(id)

	testing.expect_value(t, error.kind, Socket_Error_Kind.None)
	testing.expect(t, len(id) > 0)
	testing.expect(t, !peer.failed && peer.durable)
	testing.expect_value(t, string(peer.last_id[:peer.last_id_size]), id)
	testing.expect_value(t, string(peer.media_type[:peer.media_type_size]), "image")
	testing.expect_value(t, peer.upload_requests, 1)
	testing.expect_value(t, peer.metadata_queries, 1)
	testing.expect_value(t, peer.device_queries, 1)
	testing.expect_value(t, peer.key_queries, 2)

	message, decode_error := media_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, decode_error.kind, Media_Error_Kind.None)
	testing.expect_value(t, message.kind, Media_Kind.Image)
	testing.expect_value(t, message.caption, "receipt")
	testing.expect_value(t, message.mime_type, "image/png")
	testing.expect_value(t, message.direct_path, "/synthetic.enc")
	testing.expect_value(t, message.file_length, u64(len(plaintext)))

	// What reached the CDN is only ciphertext that the message's key opens.
	testing.expect(t, !bytes.contains(peer.uploaded[:], transmute([]u8)plaintext))
	metadata, metadata_error := media_metadata_from_message(message)
	defer media_metadata_clear(&metadata)
	testing.expect_value(t, metadata_error.kind, Media_Error_Kind.None)
	plain: [128]u8
	n, decrypt_error := media_decrypt(plain[:], peer.uploaded[:], .Image, metadata)
	testing.expect_value(t, decrypt_error.kind, Media_Error_Kind.None)
	testing.expect_value(t, string(plain[:n]), plaintext)

	// Each send uses a fresh media key and message id.
	first_key := bytes.clone(message.media_key)
	defer delete(first_key)
	second_id, second_error := socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext)
	defer delete(second_id)
	testing.expect_value(t, second_error.kind, Socket_Error_Kind.None)
	testing.expect(t, second_id != id)
	second, _ := media_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, second.mime_type, "image/jpeg")
	testing.expect(t, !bytes.equal(second.media_key, first_key))
	testing.expect_value(t, len(peer.raw), 2)
	testing.expect(t, !peer.failed)
}

@(test)
send_image_rejects_bad_state_and_inputs_before_any_network_work :: proc(t: ^testing.T) {
	_, nil_socket := socket_send_image(nil, "123@g.us", nil)
	testing.expect_value(t, nil_socket.kind, Socket_Error_Kind.Invalid_State)

	auth: Auth_State
	socket := Socket {
		phase = .Online,
		auth = &auth,
	}
	_, not_group := socket_send_image(&socket, "user@s.whatsapp.net", nil)
	testing.expect_value(t, not_group.kind, Socket_Error_Kind.Invalid_Config)
	_, wrong_mime := socket_send_image(&socket, "123@g.us", nil, mime_type = "application/pdf")
	testing.expect_value(t, wrong_mime.kind, Socket_Error_Kind.Invalid_Config)

	socket.phase = .Closed
	_, offline := socket_send_image(&socket, "123@g.us", nil)
	testing.expect_value(t, offline.kind, Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, socket.sequence, u64(0))
}

@(test)
send_image_upload_rejection_sends_no_message :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	context.user_ptr = peer
	peer.upload_status = 500
	plaintext := SEND_IMAGE_PLAINTEXT

	id, error := socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext)
	defer delete(id)

	testing.expect_value(t, error.kind, Socket_Error_Kind.Media_Failed)
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
	plaintext := SEND_IMAGE_PLAINTEXT

	id, error := socket_send_image(&peer.socket, "123@g.us", transmute([]u8)plaintext)
	defer delete(id)

	testing.expect_value(t, error.kind, Socket_Error_Kind.Session_Failed)
	testing.expect(t, len(id) > 0)
	testing.expect(t, peer.durable)
	stored, found := state_store_get(&peer.store, .Outbound_Message, id)
	testing.expect(t, found)
	testing.expect_value(t, len(peer.raw), 1)
	testing.expect(t, bytes.equal(stored, peer.raw[0]))
}

@(test)
send_reaction_delivers_checkmark_by_default_and_custom_text :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	context.user_ptr = peer
	key := Message_Key {
		remote_jid = "123@g.us",
		id = "quoted-original",
		participant = "222@s.whatsapp.net",
	}
	before := time.now()._nsec / i64(time.Millisecond)

	id, error := socket_send_reaction(&peer.socket, key)
	defer delete(id)

	testing.expect_value(t, error.kind, Socket_Error_Kind.None)
	testing.expect(t, !peer.failed && peer.durable)
	reaction, decode_error := reaction_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, decode_error.kind, Media_Error_Kind.None)
	testing.expect_value(t, reaction.text, "✅")
	testing.expect_value(t, reaction.key.id, "quoted-original")
	testing.expect_value(t, reaction.key.remote_jid, "123@g.us")
	testing.expect_value(t, reaction.key.participant, "222@s.whatsapp.net")
	testing.expect(t, reaction.sender_timestamp_ms >= before)
	testing.expect(t, reaction.sender_timestamp_ms <= time.now()._nsec / i64(time.Millisecond))
	testing.expect_value(t, peer.media_type_size, 0)

	other_id, other_error := socket_send_reaction(&peer.socket, key, "👍")
	defer delete(other_id)
	testing.expect_value(t, other_error.kind, Socket_Error_Kind.None)
	other, _ := reaction_message_decode(peer.last_plain[:peer.last_size])
	testing.expect_value(t, other.text, "👍")
	testing.expect(t, other_id != id)
	testing.expect_value(t, len(peer.raw), 2)
}

@(test)
send_reaction_validates_state_key_and_text :: proc(t: ^testing.T) {
	_, nil_socket := socket_send_reaction(nil, {})
	testing.expect_value(t, nil_socket.kind, Socket_Error_Kind.Invalid_State)

	auth: Auth_State
	socket := Socket {
		phase = .Online,
		auth = &auth,
	}
	good := Message_Key {
		remote_jid = "123@g.us",
		id = "ID1",
	}
	_, no_id := socket_send_reaction(&socket, {remote_jid = "123@g.us"})
	testing.expect_value(t, no_id.kind, Socket_Error_Kind.Invalid_Config)
	_, not_group := socket_send_reaction(&socket, {remote_jid = "1@s.whatsapp.net", id = "ID1"})
	testing.expect_value(t, not_group.kind, Socket_Error_Kind.Invalid_Config)
	_, bad_utf8 := socket_send_reaction(&socket, good, "\xff")
	testing.expect_value(t, bad_utf8.kind, Socket_Error_Kind.Invalid_Config)
	long := string(make([]u8, 65, context.temp_allocator))
	_, too_long := socket_send_reaction(&socket, good, long)
	testing.expect_value(t, too_long.kind, Socket_Error_Kind.Invalid_Config)

	socket.phase = .Failed
	_, offline := socket_send_reaction(&socket, good)
	testing.expect_value(t, offline.kind, Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, socket.sequence, u64(0))
}

Download_State :: struct {
	encrypted:      []u8,
	status:         int,
	calls:          int,
	url:            string,
	redirects_seen: int,
}

download_http :: proc(
	request: http.Request,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	state := cast(^Download_State)context.user_ptr
	state.calls += 1
	state.url = request.url
	state.redirects_seen = config.max_redirects

	if state.status != 0 {
		return {status = state.status}, {}
	}

	return {status = 200, body = state.encrypted}, {}
}

Download_Fixture :: struct {
	socket:     Socket,
	auth:       Auth_State,
	state:      Download_State,
	encrypted:  [128]u8,
	protobuf:   [512]u8,
	plain_size: int,
	message:    Socket_Message,
	media_key:  [32]u8,
}

download_fixture_init :: proc(f: ^Download_Fixture, plaintext: string) {
	for &b, i in f.media_key {
		b = u8(i)
	}

	n, metadata, encrypt_error := media_encrypt(f.encrypted[:], transmute([]u8)plaintext, .Image, f.media_key)
	assert(encrypt_error.kind == .None)
	f.state.encrypted = f.encrypted[:n]
	f.plain_size = len(plaintext)
	message := Media_Message {
		kind = .Image,
		direct_path = "/o1/v/t62/file.enc",
		media_key = metadata.media_key[:],
		file_sha256 = metadata.file_sha256[:],
		file_enc_sha256 = metadata.file_enc_sha256[:],
		file_length = metadata.file_length,
		has_file_length = true,
	}
	size, encode_error := media_message_encode(f.protobuf[:], message)
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
		config = {query_timeout = time.Second, http_execute = download_http},
	}
}

@(test)
download_media_fetches_decrypts_and_verifies_over_the_cdn_path :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)
	download_fixture_init(fixture, SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	destination: [128]u8

	n, error := socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, error.kind, Socket_Error_Kind.None)
	testing.expect_value(t, string(destination[:n]), SEND_IMAGE_PLAINTEXT)
	testing.expect_value(t, fixture.state.calls, 1)
	testing.expect_value(t, fixture.state.url, "https://mmg.whatsapp.net/o1/v/t62/file.enc")
	testing.expect_value(t, fixture.state.redirects_seen, 0)
}

@(test)
download_media_corrupt_ciphertext_fails_authentication_and_leaves_destination_untouched :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)
	download_fixture_init(fixture, SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	fixture.encrypted[3] ~= 1
	destination: [128]u8

	for &b in destination {
		b = 0x55
	}

	_, error := socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, error.kind, Socket_Error_Kind.Media_Failed)
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
	download_fixture_init(fixture, SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	fixture.state.status = 503
	destination: [128]u8

	_, error := socket_download_media(&fixture.socket, &fixture.message, destination[:])

	testing.expect_value(t, error.kind, Socket_Error_Kind.Media_Failed)
	testing.expect_value(t, error.media.kind, Media_Error_Kind.HTTP_Status)
	testing.expect_value(t, error.media.status, 503)
	testing.expect_value(t, fixture.state.calls, 1)
}

@(test)
download_media_preflights_state_message_and_destination_before_network :: proc(t: ^testing.T) {
	fixture := new(Download_Fixture)
	defer free(fixture)
	download_fixture_init(fixture, SEND_IMAGE_PLAINTEXT)
	context.user_ptr = &fixture.state
	destination: [128]u8

	_, nil_socket := socket_download_media(nil, &fixture.message, destination[:])
	testing.expect_value(t, nil_socket.kind, Socket_Error_Kind.Invalid_State)
	_, nil_message := socket_download_media(&fixture.socket, nil, destination[:])
	testing.expect_value(t, nil_message.kind, Socket_Error_Kind.Invalid_Config)

	bad_group := fixture.message
	bad_group.group = "user@s.whatsapp.net"
	_, group_error := socket_download_media(&fixture.socket, &bad_group, destination[:])
	testing.expect_value(t, group_error.kind, Socket_Error_Kind.Invalid_Config)

	small: [4]u8
	size, undersized := socket_download_media(&fixture.socket, &fixture.message, small[:])
	testing.expect_value(t, undersized.kind, Socket_Error_Kind.Media_Failed)
	testing.expect_value(t, undersized.media.kind, Media_Error_Kind.Destination_Undersized)
	testing.expect_value(t, size, len(SEND_IMAGE_PLAINTEXT))

	truncated := [3]u8{26, 5, 10}
	malformed := fixture.message
	malformed.protobuf = truncated[:]
	_, malformed_error := socket_download_media(&fixture.socket, &malformed, destination[:])
	testing.expect_value(t, malformed_error.media.kind, Media_Error_Kind.Invalid_Protobuf)

	text := [3]u8{10, 1, 'x'}
	not_media := fixture.message
	not_media.protobuf = text[:]
	_, text_error := socket_download_media(&fixture.socket, &not_media, destination[:])
	testing.expect_value(t, text_error.media.kind, Media_Error_Kind.Invalid_Kind)

	fixture.socket.phase = .Failed
	_, offline := socket_download_media(&fixture.socket, &fixture.message, destination[:])
	testing.expect_value(t, offline.kind, Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, fixture.state.calls, 0)
}

Http_Marker :: struct {
	started, completed: bool,
	worker_id:          int,
	fail:               bool,
}

http_marker_execute :: proc(
	request: http.Request,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	marker := cast(^Http_Marker)raw_data(request.body)
	marker.worker_id = sync.current_thread_id()
	sync.atomic_store(&marker.started, true)
	time.sleep(150 * time.Millisecond)
	sync.atomic_store(&marker.completed, true)

	if marker.fail {
		return {}, {kind = .Deadline_Failed}
	}

	body := "finished"

	return {status = 200, body = transmute([]u8)body}, {}
}

http_marker_request :: proc(marker: ^Http_Marker) -> http.Request {
	bytes := cast([^]u8)marker

	return {method = .GET, url = "https://synthetic.invalid", body = bytes[:size_of(Http_Marker)]}
}

@(test)
http_execute_runs_off_thread_while_the_socket_keeps_serving_the_connection :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	send_peer_use_pipe(peer)
	marker: Http_Marker
	peer.socket.session.config.keepalive_interval = time.Minute
	// A media-retry notification arrives while the request is in flight.
	send_peer_enqueue(
		peer,
		{
			tag = "notification",
			attrs = []Binary_Node_Attribute{{"id", "preserved-retry"}, {"from", "s.whatsapp.net"}, {"type", "mediaretry"}},
			content = []Binary_Node{{tag = "rmr", attrs = []Binary_Node_Attribute{{"jid", "123@g.us"}, {"from_me", "false"}}}},
		},
	)
	send_peer_announce(peer)

	response, error := socket_http_execute(&peer.socket, http_marker_request(&marker), {}, execute = http_marker_execute)
	defer network_client.response_destroy(&response)

	testing.expect_value(t, error.kind, Socket_Error_Kind.None)
	testing.expect_value(t, response.status, 200)
	testing.expect_value(t, string(response.body), "finished")
	testing.expect(t, sync.atomic_load(&marker.completed))
	testing.expect(t, marker.worker_id != sync.current_thread_id())
	testing.expect(t, !peer.failed)
	testing.expect_value(t, peer.socket.phase, Socket_Phase.Online)
	testing.expect_value(t, peer.socket.query_depth, 0)
	testing.expect_value(t, len(peer.socket.pending_media_retry), 1)
	id, _ := node_attr(peer.socket.pending_media_retry[0].root, "id")
	testing.expect_value(t, id, "preserved-retry")
}

@(test)
http_execute_reports_executor_failure_as_media_http_failure :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)
	send_peer_use_pipe(peer)
	marker := Http_Marker {
		fail = true,
	}

	response, error := socket_http_execute(&peer.socket, http_marker_request(&marker), {}, execute = http_marker_execute)
	defer network_client.response_destroy(&response)

	testing.expect_value(t, error.kind, Socket_Error_Kind.Media_Failed)
	testing.expect_value(t, error.media.kind, Media_Error_Kind.HTTP_Failed)
	testing.expect(t, error.media.http.kind == .Deadline_Failed)
	testing.expect_value(t, len(response.body), 0)
	testing.expect(t, sync.atomic_load(&marker.completed))
	testing.expect_value(t, peer.socket.query_depth, 0)
}

@(test)
http_execute_requires_an_online_socket_and_never_runs_the_request_otherwise :: proc(t: ^testing.T) {
	marker: Http_Marker
	_, nil_socket := socket_http_execute(nil, http_marker_request(&marker), {}, execute = http_marker_execute)
	testing.expect_value(t, nil_socket.kind, Socket_Error_Kind.Invalid_State)

	socket := Socket {
		phase = .Failed,
	}
	_, offline := socket_http_execute(&socket, http_marker_request(&marker), {}, execute = http_marker_execute)
	testing.expect_value(t, offline.kind, Socket_Error_Kind.Invalid_State)
	testing.expect(t, !sync.atomic_load(&marker.started))
}

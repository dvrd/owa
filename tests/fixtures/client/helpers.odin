package client_fixture

import "core:bytes"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:sync"
import "core:testing"
import "core:time"
import "shared:async/http"
import "shared:surf"
import ws "shared:websocket"
import wa "shared:whatsapp"

codec_api_hex :: proc(text: string) -> []u8 {
	decoded, ok := hex.decode(transmute([]u8)text, context.temp_allocator)
	assert(ok == nil)

	return decoded
}

SEND_IMAGE_PLAINTEXT :: "synthetic PNG image bytes"

Download_State :: struct {
	url_storage:    [wa.MAX_MEDIA_URL_SIZE]u8,
	encrypted:      []u8,
	status:         int,
	calls:          int,
	url:            string,
	redirects_seen: int,
}

download_http :: proc(
	request: http.Request,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	state := cast(^Download_State)context.user_ptr
	state.calls += 1
	n := copy(state.url_storage[:], transmute([]u8)request.url)
	state.url = string(state.url_storage[:n])
	state.redirects_seen = config.max_redirects

	if state.status != 0 {
		return {status = state.status}, {}
	}

	return {status = 200, body = state.encrypted}, {}
}

Http_Marker :: struct {
	started, completed: bool,
	worker_id:          int,
	fail:               bool,
}

http_marker_execute :: proc(
	request: http.Request,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
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

ack_routing_call_children := [1]wa.Binary_Node {
	{tag = "offer", attrs = {{"call-id", "synthetic-call-id"}, {"call-creator", "222@s.whatsapp.net"}}},
}

ack_routing_node :: proc(tag, kind: string, attrs: []wa.Binary_Node_Attribute) -> wa.Binary_Node {
	node := wa.Binary_Node {
		tag   = tag,
		attrs = attrs,
	}

	if tag == "call" {
		node.content = ack_routing_call_children[:]
	}

	return node
}

ack_routing_unchanged :: proc(t: ^testing.T, f: ^Negative_Ack_Fixture, before: []u8, revision, durable: u64) {
	testing.expect_value(t, f.store.revision, revision)
	testing.expect_value(t, f.store.durable_revision, durable)
	testing.expect_value(t, len(f.socket.queue), 0)
	testing.expect_value(t, len(f.socket.deferred_retries), 0)
	after := negative_ack_disk(f)
	defer delete(after)

	testing.expect(t, bytes.equal(before, after), "transport ACK cannot commit chat state")
}

Negative_Ack_Fixture :: struct {
	socket:          wa.Socket,
	auth:            wa.Auth_State,
	prekeys:         wa.Prekey_Store,
	store:           wa.State_Store,
	directory, path: string,
}

negative_ack_fixture :: proc() -> ^Negative_Ack_Fixture {
	f := new(Negative_Ack_Fixture)
	directory, error := os.make_directory_temp("", "whatsapp-negative-ack-*", context.allocator)
	assert(error == nil)
	f.directory = directory
	f.path = fmt.aprintf("%s/state", directory)
	identity: [32]u8
	identity[0] = 1
	assert(wa.state_store_init(&f.store, identity).kind == .None)
	f.socket = {
		phase = .Online,
		auth = &f.auth,
		prekeys = &f.prekeys,
		store = &f.store,
		config = {state_path = f.path},
	}

	assert(
		wa.socket_group_outbound_commit(&f.socket, "123@g.us", "", "owned-id", transmute([]u8)string("synthetic content"), transmute([]u8)string("synthetic wire")).kind ==
		.None,
	)

	return f
}

negative_ack_destroy :: proc(f: ^Negative_Ack_Fixture) {
	wa.state_store_clear(&f.store)
	assert(os.remove_all(f.directory) == nil)
	delete(f.path)
	delete(f.directory)
	free(f)
}

negative_ack_disk :: proc(f: ^Negative_Ack_Fixture) -> []u8 {
	data, error := os.read_entire_file(f.path, context.allocator)
	assert(error == nil)

	return data
}

negative_ack_unchanged :: proc(t: ^testing.T, f: ^Negative_Ack_Fixture, before: []u8, revision, durable: u64) {
	testing.expect_value(t, f.store.revision, revision)
	testing.expect_value(t, f.store.durable_revision, durable)
	testing.expect_value(t, f.socket.phase, .Online)
	after := negative_ack_disk(f)
	defer delete(after)

	testing.expect(t, bytes.equal(before, after), "negative/irrelevant ACK must not rewrite disk")
	restored: wa.State_Store
	defer wa.state_store_clear(&restored)

	testing.expect_value(t, wa.state_store_load(&restored, f.path, f.store.identity).kind, .None)
	testing.expect_value(t, restored.revision, revision)

	for kind in ([]wa.State_Record_Kind{.Outbound_Message, .Outbound_Content}) {
		expected, exists := wa.state_store_get(&f.store, kind, "owned-id")
		actual, found := wa.state_store_get(&restored, kind, "owned-id")
		testing.expect(t, exists == found && bytes.equal(expected, actual))
	}
}

Send_Id_Fixture :: struct {
	socket:          wa.Socket,
	auth:            wa.Auth_State,
	store:           wa.State_Store,
	directory, path: string,
}

send_id_fixture :: proc() -> ^Send_Id_Fixture {
	fixture := new(Send_Id_Fixture)
	directory, error := os.make_directory_temp("", "whatsapp-send-id-*", context.allocator)
	assert(error == nil)
	fixture.directory = directory
	fixture.path = fmt.aprintf("%s/state", directory)
	identity: [32]u8
	identity[0] = 1
	assert(wa.state_store_init(&fixture.store, identity).kind == .None)
	fixture.socket = {
		phase = .Online,
		store = &fixture.store,
		auth = &fixture.auth,
		config = {state_path = fixture.path},
	}

	assert(
		wa.socket_group_outbound_commit(&fixture.socket, "123@g.us", "", "stable-id", transmute([]u8)string("original content"), transmute([]u8)string("original wire")).kind ==
		.None,
	)

	return fixture
}

send_id_fixture_destroy :: proc(fixture: ^Send_Id_Fixture) {
	wa.state_store_clear(&fixture.store)
	assert(os.remove_all(fixture.directory) == nil)
	delete(fixture.path)
	delete(fixture.directory)
	free(fixture)
}

Send_Id_Wire :: struct {
	data: [4096]u8,
	used: int,
}

@(thread_local)
send_id_http_calls: int

send_id_http :: proc(
	request: http.Request,
	config: surf.Config,
) -> (
	surf.Response,
	surf.HTTP_Error,
) {
	send_id_http_calls += 1
	return {}, {kind = .IO_Failed}
}

send_id_wire_connect :: proc(socket: ^wa.Socket, wire: ^Send_Id_Wire) {
	socket.websocket = {
		phase = .Open,
		allocator = context.allocator,
		config = {host = "synthetic.invalid", max_message_size = 4096},
		stream = {data = wire, write = send_id_wire_write, read = send_id_wire_read, close = send_id_wire_close},
	}

	socket.client = {
		phase = .Noise_Ready,
		websocket = &socket.websocket,
		config = {max_frame_payload = 4096},
		noise = {phase = .Transport},
	}

	assert(wa.frame_transport_init(&socket.client.frames, &socket.websocket, 4096).kind == .None)
	socket.client.frames.intro_sent = true
	socket.config.http_execute = send_id_http
	send_id_http_calls = 0
}

send_id_wire_write :: proc(data: rawptr, source: []u8) -> (int, surf.WebSocket_Stream_Error) {
	wire := cast(^Send_Id_Wire)data
	assert(len(source) <= len(wire.data) - wire.used)
	wire.used += copy(wire.data[wire.used:], source)

	return len(source), {}
}

send_id_wire_read :: proc(data: rawptr, destination: []u8) -> (int, surf.WebSocket_Stream_Error) {
	return 0, {kind = .EOF}
}

send_id_wire_close :: proc(data: rawptr) -> surf.WebSocket_Stream_Error {
	return {}
}

send_id_wire_plain :: proc(wire: ^Send_Id_Wire, destination: []u8) -> string {
	header, size, decode := ws.frame_header_decode(wire.data[:wire.used], true)
	assert(decode == .None && size + int(header.payload_length) == wire.used)
	payload := wire.data[size:wire.used]
	ws.mask_payload(payload, header.masking_key)
	encrypted, consumed, framed := wa.frame_decode(payload)
	assert(framed == .None && consumed == len(payload))
	peer := wa.Noise_State {
		phase = .Transport,
	}

	count, decrypted := wa.noise_decrypt(&peer, destination, encrypted)
	assert(decrypted == .None)

	return string(destination[:count])
}

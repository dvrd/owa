package main

import peer "../loopback"
import "core:crypto"
import "core:crypto/x25519"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
import "shared:surf"
import ws "shared:websocket"
import wa "shared:whatsapp"

// Match the exact certificate bytes in the fixed loopback transcript.
fixture_verify_certificate :: proc(payload: []u8, _: [32]u8) -> wa.Certificate_Error {
	return string(payload) == "\x12\x04\x0a\x02\x10\x00" ? .None : .Rejected
}

// Fixed synthetic handshake keys for this fixture.
// This explicitly replaces only this test connection's ephemeral before I/O.
fixture_client :: proc(client: ^wa.Client, connection: ^surf.WebSocket_Conn) {
	credentials: wa.Noise_Credentials

	for &byte, index in credentials.static_private_key {
		byte = u8(index + 65)
	}

	assert(
		wa.client_init(client, connection, credentials, {max_frame_payload = 256, handshake_timeout = 200 * time.Millisecond, verify_certificate = fixture_verify_certificate}).kind ==
		.None,
	)
	wa.noise_clear(&client.noise)

	for &byte, index in client.ephemeral_private {
		byte = u8(index + 1)
	}

	x25519.scalarmult_basepoint(client.ephemeral_public[:], client.ephemeral_private[:])
	assert(wa.noise_init(&client.noise, client.ephemeral_public) == .None)
}

fixture_run :: proc(port: int, mode: string) {
	socket, dial_error := net.dial_tcp_from_endpoint({net.IP4_Loopback, port})

	assert(dial_error == nil)
	tcp := net.TCP_Connection {
		socket = socket,
	}

	connection: surf.WebSocket_Conn
	assert(
		surf.websocket_client(
			&connection,
			surf.websocket_tcp_stream(&tcp),
			{
				host = "127.0.0.1",
				target = "/synthetic",
				max_message_size = 1024,
				handshake_timeout = time.Second,
			},
		) ==
		.None,
	)
	defer surf.websocket_close(&connection)

	assert(surf.websocket_upgrade(&connection).kind == .None)
	client: wa.Client
	fixture_client(&client, &connection)

	if mode == "normal" {
		client.config.handshake_timeout = time.Second
	}
	defer wa.client_close(&client)

	payload := [?]u8{0x08, 0x01, 0x12, 0x03, 'b', 'o', 't'}

	started := time.tick_now()
	error := wa.client_handshake(&client, payload[:])

	if mode != "normal" {
		assert(error.kind != .None && client.phase == .Failed)
		elapsed := time.tick_since(started)
		assert(elapsed < time.Second)

		if mode == "eof" {
			assert(error.transport.kind == .Truncated_Envelope)
		}

		if mode == "timeout" {
			assert(elapsed >= 150 * time.Millisecond)
			assert(error.transport.websocket.stream.transport == net.TCP_Recv_Error.Timeout)
		}

		assert(crypto.is_zero_constant_time(client.static_private[:]) == 1)
		assert(crypto.is_zero_constant_time(client.ephemeral_private[:]) == 1)
		assert(crypto.is_zero_constant_time(client.noise.read_key[:]) == 1)
		assert(crypto.is_zero_constant_time(client.noise.write_key[:]) == 1)
		assert(crypto.is_zero_constant_time(client.noise.chaining_key[:]) == 1)
		fmt.printf(
			"WA_LOOPBACK_OK mode=%s error=%v transport=%v\n",
			mode,
			error.kind,
			error.transport.websocket.stream.transport,
		)
		return
	}

	assert(error.kind == .None && client.phase == .Noise_Ready)
	buffer: [64]u8
	count, read_error := wa.client_read(&client, buffer[:])
	assert(read_error.kind == .None && string(buffer[:count]) == "from-server")
	assert(wa.client_write(&client, transmute([]u8)string("from-client")).kind == .None)
	_, closed := wa.client_read(&client, buffer[:])
	assert(closed.kind != .None && client.phase == .Failed)
	assert(crypto.is_zero_constant_time(client.noise.read_key[:]) == 1)
	assert(crypto.is_zero_constant_time(client.noise.write_key[:]) == 1)
	assert(crypto.is_zero_constant_time(client.noise.chaining_key[:]) == 1)
	fmt.println("WA_LOOPBACK_OK mode=normal encrypted_exchange=true peer_close=true")
}

check_client_allocations :: proc(port: int, mode: string) {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)

	context.allocator = mem.tracking_allocator(&tracker)
	context.temp_allocator = context.allocator
	fixture_run(port, mode)
	assert(tracker.current_memory_allocated == 0 && len(tracker.bad_free_array) == 0)
}

// Fixed synthetic handshake transcript from Mesa tests/whatsapp/connection.odin.
HELLO :: "\x12\x22\x0a\x20\x07\xa3\x7c\xbc\x14\x20\x93\xc8\xb7\x55\xdc\x1b\x10\xe8\x6c\xb4\x26\x37\x4a\xd1\x6a\xa8\x53\xed\x0b\xdf\xc0\xb2\xb8\x6d\x1c\x7c"
SERVER :: "\x1a\x6c\x0a\x20\x88\x31\x86\xb8\x00\xb4\x1d\x5c\xf0\x42\x96\x95\xda\x9b\x3c\xc4\xf3\x28\xeb\xcd\x18\x4a\x6e\x48\x2f\xa5\x78\xc1\x03\xf0\x6c\x77\x12\x30\x5c\x99\xcd\x81\x1d\xaa\xd2\xae\x49\x57\x73\x62\xc2\xaf\x50\x3e\xb3\x6b\x54\x71\x6c\x7e\x19\x1e\x19\x6f\x5d\xa9\x74\x16\x3e\x0d\x24\x36\x75\xd8\x4f\x8e\x03\xca\x39\xd1\x32\xd2\x46\x97\x72\x26\x1a\x16\xf2\xad\xf7\xb3\x73\x69\xf1\x9e\x09\x4e\x3d\x12\x42\x27\xe1\xf7\xb4\x67\xfe\x48\x12\xa0"
FINISH :: "\x22\x4b\x0a\x30\xc2\x94\x6d\x59\x86\x9c\xef\x65\x6a\xd4\x91\x44\xb2\x23\x00\x17\x6f\x2a\x8a\xf4\x95\x63\x68\x39\x1c\x7f\xf7\x0e\xa6\x40\x7a\x9b\x1d\xc9\x7a\xbd\xf2\x1e\x78\xb2\xb5\xcd\x28\x07\x97\x35\x94\x66\x12\x17\xed\x5d\x54\x6b\xad\x89\x51\xd6\x94\x0e\x77\x51\x15\x41\x57\xc3\xcd\x46\x2c\xb2\x64\x12\x56"
FROM_SERVER :: "\x3f\xb4\x59\xb2\x95\xaa\xad\x45\xa1\x23\x52\x03\x94\x87\xbf\x81\x2f\x2f\x09\x29\xa5\x47\x98\xf4\x5c\xdb\x9c"
FROM_CLIENT :: "\x82\x49\x0f\x0a\x45\x17\xfe\xdd\x40\xfc\xa7\x29\x8c\x34\x2f\x66\x7e\x38\x82\x0e\xc7\x72\x6c\xcc\xb0\x9f\xe9"

Noise_Server :: struct {
	listener: net.TCP_Socket,
	mode:     string,
}

// All five vectors fit in a short WebSocket frame. The client's mask is random.
expect_client_frame :: proc(socket: net.Connection, opcode: u8, expected: string) {
	header: [2]u8
	peer.read_exact(socket, header[:])
	assert(header[0] == 0x80 | opcode && header[1] == 0x80 | u8(len(expected)))
	mask: [4]u8
	peer.read_exact(socket, mask[:])
	body: [125]u8
	peer.read_exact(socket, body[:len(expected)])
	for &b, i in body[:len(expected)] {b ~= mask[i % 4]}

	assert(string(body[:len(expected)]) == expected)
}

noise_envelope :: proc(payload: string) -> string {
	envelope := make([]u8, 3 + len(payload), context.temp_allocator)
	assert(len(payload) < 256)
	envelope[2] = u8(len(payload))
	copy(envelope[3:], transmute([]u8)payload)
	return string(envelope)
}

serve_noise_transcript :: proc(server: ^Noise_Server) {
	tcp: net.TCP_Connection
	socket := peer.accept(server.listener, &tcp)
	defer socket.close(socket.data)

	buffer: [4096]u8
	headers := peer.read_headers(socket, buffer[:])
	key := peer.header_value(headers, "Sec-WebSocket-Key")
	assert(key != "")
	accept := ws.upgrade_accept_encoded(key)
	response := fmt.tprintf(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		string(accept[:]),
	)
	peer.send_all(socket, transmute([]u8)response)
	expect_client_frame(socket, 2, fmt.tprintf("WA\x06\x03%s", noise_envelope(HELLO)))
	data := noise_envelope(SERVER)
	if server.mode == "eof" {
		data = data[:5]
	}

	frame: [130]u8
	frame[0], frame[1] = 0x82, u8(len(data))
	copy(frame[2:], transmute([]u8)data)
	if server.mode == "timeout" {
		peer.send_all(socket, frame[:5])
		time.sleep(500 * time.Millisecond)
		return
	}

	for offset := 0; offset < len(data) + 2; offset += 5 {
		peer.send_all(socket, frame[offset:min(offset + 5, len(data) + 2)])
		time.sleep(time.Millisecond)
	}

	if server.mode == "eof" {
		return
	}

	expect_client_frame(socket, 2, noise_envelope(FINISH))
	data = noise_envelope(FROM_SERVER)
	frame[1] = u8(len(data))
	copy(frame[2:], transmute([]u8)data)
	peer.send_all(socket, frame[:2 + len(data)])
	expect_client_frame(socket, 2, noise_envelope(FROM_CLIENT))
	peer.send_all(socket, []u8{0x88, 2, 3, 0xe8})

	expect_client_frame(socket, 8, "\x03\xe8")
}

@(test)
noise_handshake_over_local_websocket :: proc(t: ^testing.T) {
	for mode in ([]string{"normal", "eof", "timeout", "normal"}) {
		listener, port := peer.listen()
		defer net.close(listener)

		server := Noise_Server{listener, mode}

		worker := thread.create_and_start_with_poly_data(&server, serve_noise_transcript)
		defer thread.destroy(worker)

		check_client_allocations(port, mode)
		thread.join(worker)
	}
}

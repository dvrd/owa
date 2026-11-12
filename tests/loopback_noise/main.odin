package main

import wa "shared:whatsapp"
import surf "shared:surf"
import "core:crypto"
import "core:crypto/x25519"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"
import "core:strconv"
import "core:time"

// Pinned independent Node/Baileys handshake fixture keys, never account keys.
// This explicitly replaces only this test connection's ephemeral before I/O.
// Issuer-only synthetic certificates use explicit compatibility, never strict trust.
fixture_client :: proc(client: ^wa.Client, connection: ^surf.WebSocket_Conn) {
	credentials: wa.Noise_Credentials
	for &byte, index in credentials.static_private_key {byte = u8(index + 65)}
	assert(wa.client_init(client, connection, credentials,
		{max_frame_payload = 256, handshake_timeout = 200*time.Millisecond,
			verify_certificate = wa.baileys_certificate_policy}).kind == .None)
	wa.noise_clear(&client.noise)
	for &byte, index in client.ephemeral_private {byte = u8(index + 1)}
	x25519.scalarmult_basepoint(client.ephemeral_public[:], client.ephemeral_private[:])
	assert(wa.noise_init(&client.noise, client.ephemeral_public) == .None)
}

fixture_run :: proc() {
	assert(len(os.args) == 3)
	port, valid := strconv.parse_int(os.args[1]); assert(valid && port > 0 && port < 65536)
	mode := os.args[2]
	socket, dial_error := net.dial_tcp_from_endpoint({net.IP4_Loopback, port})
	assert(dial_error == nil)
	tcp := net.TCP_Connection{socket = socket}
	connection: surf.WebSocket_Conn
	assert(surf.websocket_client(&connection, surf.websocket_tcp_stream(&tcp),
		{host = "127.0.0.1", target = "/synthetic", max_message_size = 1024,
			handshake_timeout = time.Second}) == .None)
	defer surf.websocket_close(&connection)
	assert(surf.websocket_upgrade(&connection).kind == .None)
	client: wa.Client
	fixture_client(&client, &connection)
	if mode == "normal" {client.config.handshake_timeout = time.Second}
	defer wa.client_close(&client)
	payload := [?]u8{0x08, 0x01, 0x12, 0x03, 'b', 'o', 't'}
	started := time.tick_now()
	error := wa.client_handshake(&client, payload[:])
	if mode != "normal" {
		assert(error.kind != .None && client.phase == .Failed)
		elapsed := time.tick_since(started)
		assert(elapsed < time.Second)
		if mode == "eof" {assert(error.transport.kind == .Truncated_Envelope)}
		if mode == "timeout" {
			assert(elapsed >= 150*time.Millisecond)
			assert(error.transport.websocket.stream.transport.kind == .Timeout)
		}
		assert(crypto.is_zero_constant_time(client.static_private[:]) == 1)
		assert(crypto.is_zero_constant_time(client.ephemeral_private[:]) == 1)
		assert(crypto.is_zero_constant_time(client.noise.read_key[:]) == 1)
		assert(crypto.is_zero_constant_time(client.noise.write_key[:]) == 1)
		assert(crypto.is_zero_constant_time(client.noise.chaining_key[:]) == 1)
		fmt.printf("WA_LOOPBACK_OK mode=%s error=%v transport=%v\n", mode, error.kind,
			error.transport.websocket.stream.transport.kind)
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

main :: proc() {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	context.allocator = mem.tracking_allocator(&tracker)
	context.temp_allocator = context.allocator
	fixture_run()
	assert(tracker.current_memory_allocated == 0 && len(tracker.bad_free_array) == 0)
	fmt.println("WA_OWNERSHIP retained_bytes=0 bad_frees=0")
}

package main

import peer "../loopback"
import "core:bytes"
import "core:fmt"
import "core:net"
import "core:os"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"
import ws "shared:async/websocket"
import wa "shared:whatsapp"

Wake_Peer :: struct {
	listener:  net.TCP_Socket,
	header_sent: sync.Sema,
	send_body: sync.Sema,
}

WAKE_PAYLOAD_SIZE :: 70 * 1024

serve_partial_message :: proc(state: ^Wake_Peer) {
	tcp: net.TCP_Connection
	socket := peer.accept(state.listener, &tcp)
	defer socket.close(socket.data)

	headers: [4096]u8
	key := peer.header_value(peer.read_headers(socket, headers[:]), "Sec-WebSocket-Key")
	accept := ws.upgrade_accept_encoded(key)
	response := fmt.tprintf(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		string(accept[:]),
	)
	peer.send_all(socket, transmute([]u8)response)
	payload: [WAKE_PAYLOAD_SIZE]u8
	for &b, i in payload {
		b = u8(i % 251)
	}

	frame: [WAKE_PAYLOAD_SIZE + 14]u8
	n, e := ws.frame_encode(frame[:], true, .Binary, payload[:], {}, masked = false)
	assert(e == .None)
	peer.send_all(socket, frame[:1])
	sync.sema_post(&state.header_sent)
	assert(sync.sema_wait_with_timeout(&state.send_body, 3 * time.Second))
	peer.send_all(socket, frame[1:n])
	expect_client_frame(socket, 8, "\x03\xe8")
	peer.send_all(socket, []u8{0x88, 2, 3, 0xe8})
}

@(test)
worker_wake_preserves_pending_large_websocket_message :: proc(t: ^testing.T) {
	listener, port := peer.listen()
	defer net.close(listener)

	state := Wake_Peer {
		listener = listener,
	}

	worker := thread.create_and_start_with_poly_data(&state, serve_partial_message)
	defer thread.destroy(worker)

	conn: wa.Message_Connection
	opened := wa.message_connection_open(
		&conn,
		{host = "localhost", port = port, target = "/", max_message_size = WAKE_PAYLOAD_SIZE},
	)
	assert(opened.kind == .None)
	defer wa.message_connection_close(&conn)

	// A download running during socket teardown retains the same runtime.
	pool, pool_err := wa.media_http_pool_open({}, conn.transport)
	assert(pool_err.kind == .None && pool.transport == conn.transport)
	defer wa.media_http_pool_close(pool)

	reader, writer, pe := os.pipe()
	assert(pe == nil)
	defer os.close(reader)

	// Completion before poll must also wake the owner. The WebSocket is still partial.
	assert(sync.sema_wait_with_timeout(&state.header_sent, 3 * time.Second))
	os.close(writer)
	ready, polled := conn.poll(conn.data, time.Second, reader)
	testing.expect_value(t, polled.kind, .None)
	testing.expect(t, !ready)
	sync.sema_post(&state.send_body)
	ready, polled = conn.poll(conn.data, 2 * time.Second, nil)
	assert(ready && polled.kind == .None)
	dst, expected: [WAKE_PAYLOAD_SIZE]u8
	for &b, i in expected {
		b = u8(i % 251)
	}

	opcode, n, read := conn.read(conn.data, dst[:], time.time_add(time.now(), time.Second))
	testing.expect_value(t, read.kind, .None)
	testing.expect_value(t, opcode, .Binary)
	testing.expect(t, bytes.equal(dst[:n], expected[:]))
	testing.expect_value(t, wa.message_connection_close(&conn).kind, .None)
	thread.join(worker)
	second, reopened := wa.media_http_pool_open({}, pool.transport)
	testing.expect_value(t, reopened.kind, .None)
	if second != nil {
		wa.media_http_pool_close(second)
	}
}

package whatsapp_test

import "core:os"
import "core:sync"
import "core:testing"
import "core:time"
import "shared:surf"
import wa "shared:whatsapp"

// Return immediately at the same seam where the real connection finishes its
// bounded wait. The test controls when another message or terminal error arrives.
loss_peer_poll :: proc(data: rawptr, _: time.Duration, _: ^os.File) -> (bool, surf.WebSocket_Error) {
	peer := cast(^Send_Peer)data
	return peer.read_at < len(peer.input) || peer.terminal_read_error != .None, {}
}

loss_peer_feed :: proc(peer: ^Send_Peer, payload: []u8) {
	frame: [256]u8
	n := send_peer_server_frame(frame[:], payload)
	append(&peer.input, ..frame[:n])
}

@(test)
repeated_deadlines_at_every_envelope_byte_preserve_order_and_nonces :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	peer.socket.websocket.poll = loss_peer_poll
	for id in ([2]string{"first", "second"}) {
		send_peer_enqueue(peer, {tag = "iq", attrs = {{"type", "result"}, {"id", id}}})
	}

	assert(!peer.failed)
	first_size := int(peer.input[1])
	second_at := first_size + 2
	second_size := int(peer.input[second_at + 1])
	assert(first_size < 126 && second_size < 126)
	wire: [252]u8
	copy(wire[:first_size], peer.input[2:second_at])
	copy(wire[first_size:], peer.input[second_at + 2:])
	clear(&peer.input)

	deadline := time.time_add(time.now(), time.Second)
	for at in 0 ..< first_size {
		if at > 0 {
			loss_peer_feed(peer, wire[at - 1:at])
		}

		for _ in 0 ..< 2 {
			_, err := wa.socket_receive_wire(&peer.socket, deadline)
			testing.expect_value(t, err.kind, .Query_Timeout)
			testing.expect_value(t, peer.socket.phase, .Online)
			testing.expect_value(t, peer.socket.client.frames.header_used, min(at, 3))
			testing.expect_value(t, peer.socket.client.frames.payload_used, max(at - 3, 0))
			testing.expect_value(t, peer.socket.client.noise.read_counter, u64(0))
		}
	}

	// Finish the first envelope and coalesce a complete second one in the same WS message.
	loss_peer_feed(peer, wire[first_size - 1:first_size + second_size])
	peer.terminal_read_error = .Peer_Closed
	for expected, i in ([2]string{"first", "second"}) {
		event, err := wa.socket_receive_wire(&peer.socket, deadline)
		testing.expect_value(t, err.kind, .None)
		id, found := wa.node_attr(event.node, "id")
		testing.expect(t, found && id == expected)
		testing.expect_value(t, peer.socket.client.noise.read_counter, u64(i + 1))
	}

	_, eof := wa.socket_receive_wire(&peer.socket, deadline)
	testing.expect_value(t, eof.session.client.transport.kind, .Peer_Closed)
	testing.expect_value(t, peer.socket.phase, .Failed)
}

@(test)
terminal_transport_errors_after_query_timeout_require_fresh_session :: proc(t: ^testing.T) {
	for cause in ([]surf.WebSocket_Error_Kind{.Peer_Closed, .Closed, .Timeout, .IO_Failed}) {
		for prefix in 0 ..= 4 {
			peer := send_peer_new()
			defer send_peer_destroy(peer)

			peer.socket.websocket.poll = loss_peer_poll
			wire := [4]u8{0, 0, 20, 1}
			if prefix > 0 {
				loss_peer_feed(peer, wire[:prefix])
			}

			deadline := time.time_add(time.now(), time.Second)
			_, wait := wa.socket_receive_wire(&peer.socket, deadline)
			testing.expect_value(t, wait.kind, .Query_Timeout)
			peer.terminal_read_error = cause
			_, err := wa.socket_receive_wire(&peer.socket, deadline)
			testing.expect_value(t, err.kind, .Session_Failed)
			failure := err.session.client.transport
			testing.expect_value(t, failure.websocket.kind, cause)
			if prefix > 0 {
				testing.expect_value(t, failure.kind, .Truncated_Envelope)
				testing.expect_value(t, failure.frame, .Header_Incomplete if prefix < 3 else .Payload_Incomplete)
			} else if cause == .Timeout || cause == .IO_Failed {
				testing.expect_value(t, failure.kind, .WebSocket_Read_Failed)
			} else {
				testing.expect_value(t, failure.kind, .Peer_Closed)
			}

			testing.expect_value(t, peer.socket.phase, .Failed)
			testing.expect_value(t, peer.socket.client.noise.read_key, [32]u8{})
			_, retry := wa.socket_read(&peer.socket)
			testing.expect_value(t, retry.kind, .Invalid_State)
		}
	}
}

@(test)
idle_and_provisioning_deadlines_are_independent :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	now := peer.socket.session.last_received
	limit := time.time_add(now, peer.socket.session.config.keepalive_interval + 5 * time.Second)
	peer.socket.session.next_ping = time.time_add(limit, time.Minute)
	_, boundary := wa.socket_tick(&peer.socket, limit)
	testing.expect_value(t, boundary.kind, .None)
	_, expired := wa.socket_tick(&peer.socket, time.time_add(limit, time.Nanosecond))
	testing.expect_value(t, expired.session.kind, .Connection_Lost)
	testing.expect_value(t, peer.socket.phase, .Failed)

	provision := send_peer_new()
	defer send_peer_destroy(provision)

	provision.socket.phase = .Provisioning
	provision.socket.provision_stage = .Active
	provision.socket.provision_deadline = now
	provision.socket.session.last_received = now
	_, timeout := wa.socket_tick(&provision.socket, now)
	testing.expect_value(t, timeout.kind, .Query_Timeout)
	testing.expect_value(t, provision.socket.phase, .Failed)
}

@(test)
server_restart_and_rejection_preserve_distinct_outcomes :: proc(t: ^testing.T) {
	for code in ([2]string{"515", "401"}) {
		peer := send_peer_new()
		defer send_peer_destroy(peer)

		peer.auth.credentials.registered = true
		send_peer_enqueue(peer, {tag = "stream:error", attrs = {{"code", code}}})
		event, err := wa.socket_read(&peer.socket)
		if code == "515" {
			testing.expect_value(t, err.kind, .None)
			testing.expect_value(t, event.kind, .Restart_Required)
			testing.expect_value(t, peer.socket.phase, .Restart_Required)
		} else {
			testing.expect_value(t, err.kind, .Session_Failed)
			testing.expect_value(t, err.session.kind, .Server_Failure)
			testing.expect_value(t, err.session.server_code, u32(401))
			testing.expect_value(t, peer.socket.phase, .Failed)
		}

		_, poll := wa.socket_poll(&peer.socket)
		testing.expect_value(t, poll.kind, .Invalid_State)
		testing.expect_value(t, peer.socket.client.noise.write_key, [32]u8{})
	}
}

HTTP_Loss_Gate :: struct {
	started, release: sync.Sema,
	finished: bool,
}

@(test)
socket_poll_failure_joins_outstanding_http_worker :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	gate: HTTP_Loss_Gate
	previous := context.user_ptr
	context.user_ptr = &gate
	defer context.user_ptr = previous

	peer.socket.websocket.poll = proc(_: rawptr, _: time.Duration, _: ^os.File) -> (bool, surf.WebSocket_Error) {
		gate := cast(^HTTP_Loss_Gate)context.user_ptr
		assert(sync.sema_wait_with_timeout(&gate.started, 3 * time.Second))
		sync.sema_post(&gate.release)
		return false, {kind = .IO_Failed}
	}

	request := surf.Request{
		method = .GET,
		url = "https://synthetic.invalid",
		body = (cast([^]u8)&gate)[:size_of(gate)],
	}

	response, err := wa.socket_http_execute(&peer.socket, request, {}, execute = proc(request: surf.Request, _: surf.Config) -> (surf.Response, surf.HTTP_Error) {
		gate := cast(^HTTP_Loss_Gate)raw_data(request.body)
		sync.sema_post(&gate.started)
		assert(sync.sema_wait_with_timeout(&gate.release, 3 * time.Second))
		sync.atomic_store(&gate.finished, true)
		return {status = 200}, {}
	})

	defer surf.response_destroy(&response)

	testing.expect_value(t, err.kind, .Poll_Failed)
	testing.expect_value(t, err.websocket.kind, .IO_Failed)
	testing.expect_value(t, response.status, 0)
	testing.expect(t, sync.atomic_load(&gate.finished))
	testing.expect_value(t, peer.socket.phase, .Failed)
	testing.expect_value(t, peer.socket.query_depth, 0)
}

@(test)
resumed_read_rejects_wrong_envelope_length_or_authentication_tag :: proc(t: ^testing.T) {
	for oversized in ([2]bool{false, true}) {
		peer := send_peer_new()
		defer send_peer_destroy(peer)

		peer.socket.websocket.poll = loss_peer_poll
		send_peer_enqueue(peer, {tag = "iq", attrs = {{"type", "result"}}})
		assert(!peer.failed && peer.input[1] < 126)
		wire: [128]u8
		n := copy(wire[:], peer.input[2:])
		clear(&peer.input)
		if oversized {
			// The live endpoint returned the bytes of an empty Pong as binary data.
			wire[0], wire[1] = 0x8a, 0
		} else {
			wire[n - 1] ~= 1
		}

		deadline := time.time_add(time.now(), time.Second)
		loss_peer_feed(peer, wire[:2])
		_, wait := wa.socket_receive_wire(&peer.socket, deadline)
		testing.expect_value(t, wait.kind, .Query_Timeout)
		loss_peer_feed(peer, wire[2:n])
		event, err := wa.socket_receive_wire(&peer.socket, deadline)
		testing.expect_value(t, err.kind, .Session_Failed)
		testing.expect(t, event.message == nil && event.node.tag == "")
		if oversized {
			testing.expect_value(t, err.session.client.transport.kind, .Payload_Oversized)
		} else {
			testing.expect_value(t, err.session.client.noise, .Authentication_Failed)
		}

		testing.expect_value(t, peer.socket.phase, .Failed)
	}
}

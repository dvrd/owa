package protocol_watch_test
import w "../../../tools/protocol_watch"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:testing"
import "core:thread"
import "core:time"
Peer :: struct {
	listener: net.TCP_Socket,
	response: string,
	request:  [4096]u8,
	n:        int,
}
serve :: proc(peer: ^Peer) {
	connection, _, error := net.accept_tcp(peer.listener); if error != .None {
		return
	}; defer net.close(connection)
	_ = net.set_option(connection, .Receive_Timeout, 2 * time.Second)
	_ = net.set_option(connection, .Send_Timeout, 2 * time.Second)
	peer.n, _ = net.recv_tcp(connection, peer.request[:]); bytes := transmute([]u8)peer.response
	offset := 0
	for offset < len(bytes) {
		n, write_error := net.send_tcp(connection, bytes[offset:])
		if write_error != .None || n <= 0 {
			break
		}; offset += n
	}
}
fetch_peer :: proc(t: ^testing.T, response: string) -> ([]u8, bool, w.Failure) {
	peer := Peer {
		response = response,
	}; listener, error := net.listen_tcp({net.IP4_Loopback, 0}); assert(error == nil)
	peer.listener = listener; _ = net.set_option(listener, .Receive_Timeout, 3 * time.Second)
	defer net.close(listener)
	endpoint, bound := net.bound_endpoint(listener); assert(bound == .None)
	worker := thread.create_and_start_with_poly_data(&peer, serve); defer thread.destroy(worker)
	network := w.Network {
		allow_loopback = true,
	}
	bytes, present, failure := w.transport(
		&network,
		fmt.aprintf("http://127.0.0.1:%d/path", endpoint.port),
		2 * time.Second,
	); thread.join(worker)
	testing.expect(t, peer.n > 0); return bytes, present, failure
}
@(test)
watch_redirect_never_followed :: proc(t: ^testing.T) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	_, _, failure := fetch_peer(
		t,
		"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
	); testing.expect(t, failure == w.Failure("UPSTREAM_REDIRECT"))
}
@(test)
transport_bounds_missing_http_and_redacted_auth :: proc(t: ^testing.T) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	bytes, present, failure := fetch_peer(
		t,
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
	); testing.expect(t, failure == nil && present && string(bytes) == "ok")
	_, present, failure = fetch_peer(
		t,
		"HTTP/1.1 404 Missing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
	); testing.expect(t, failure == nil && !present)
	_, _, failure = fetch_peer(
		t,
		"HTTP/1.1 500 Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
	); testing.expect(t, failure == w.Failure("UPSTREAM_HTTP_FAILED"))
	_, _, failure = fetch_peer(
		t,
		"HTTP/1.1 200 OK\r\nContent-Length: 5000000\r\nConnection: close\r\n\r\n",
	); testing.expect(t, failure == w.Failure("UPSTREAM_OVERSIZED"))
	network := w.Network {
		linear_key = "private-secret\r\ninjected",
	}; _, failure = w.linear_transport(&network, "query", w.object())
	testing.expect(t, failure == w.Failure("LINEAR_CREDENTIAL_MISSING"))
}
@(test)
linear_owned_http_redacts_and_refuses_redirect :: proc(t: ^testing.T) {
	arena := setup_arena(); defer mem.dynamic_arena_destroy(&arena)
	context.allocator = mem.dynamic_arena_allocator(&arena)
	for mode in 0 ..< 5 {
		body := "{\"data\":{\"safe\":true}}"; status := "200 OK"; extra := ""
		switch mode {case 0:; case 1:
			body = "{\"errors\":[{\"message\":\"private-secret\"}]}"; case 2:
			body = "{\"data\":null}"; case 3:
			body = "private-secret"; status = "503 Error"; case 4:
			body = ""; status = "302 Found"; extra = "Location: http://127.0.0.1:1/private\r\n"
		}
		peer := Peer {
			response = w.cat(
				"HTTP/1.1 ",
				status,
				"\r\n",
				extra,
				"Content-Length: ",
				w.string_number(len(body)),
				"\r\nConnection: close\r\n\r\n",
				body,
			),
		}
		listener, error := net.listen_tcp({net.IP4_Loopback, 0}); assert(error == nil)
		peer.listener = listener; endpoint, bound := net.bound_endpoint(listener)
		assert(bound == .None); worker := thread.create_and_start_with_poly_data(&peer, serve)
		network := w.Network {
			linear_key     = "synthetic-loopback-only",
			linear_url     = fmt.aprintf("http://127.0.0.1:%d/graphql", endpoint.port),
			allow_loopback = true,
		}; value, failure := w.linear_transport(&network, "query Synthetic", w.object())
		thread.join(worker); thread.destroy(worker); net.close(listener)
		if mode == 0 {
			testing.expect(t, failure == nil && w.truth(w.get(value, "safe")))
		} else {
			testing.expect(
				t,
				failure ==
				w.Failure("LINEAR_API_REJECTED" if mode == 1 else "LINEAR_REQUEST_FAILED"),
			)
		}
		testing.expect(t, peer.n > 0)
	}
}

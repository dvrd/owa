package main

import peer "../loopback"
import "core:fmt"
import "core:net"
import "core:strings"
import "core:testing"
import "core:thread"
import "core:time"
import surf "shared:surf"
import wa "shared:whatsapp"

Version_Server :: struct {
	listener: net.TCP_Socket,
	buffer:   [4096]u8,
	headers:  string,
}

serve_version_script :: proc(server: ^Version_Server) {
	tcp: net.TCP_Connection
	socket := peer.accept(server.listener, &tcp)
	defer socket.close(socket.data)
	server.headers = peer.read_headers(socket, server.buffer[:])
	body :: `self.cfg={"client_revision":1234567890};`
	response := fmt.tprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body),
		body,
	)
	peer.send_all(socket, transmute([]u8)response)
}

@(test)
fetch_version_from_local_web_server :: proc(t: ^testing.T) {
	listener, port := peer.listen()
	defer net.close(listener)
	server := Version_Server {
		listener = listener,
	}
	worker := thread.create_and_start_with_poly_data(&server, serve_version_script)
	defer thread.destroy(worker)
	url := fmt.aprintf("http://127.0.0.1:%d/sw.js", port)
	defer delete(url)
	response, error := wa.version_fetch_http(
		nil,
		url,
		{
			allow_http = true,
			timeout = 2 * time.Second,
			setup_timeout = time.Second,
			max_body_size = 4096,
			max_redirects = 0,
		},
	)
	defer surf.response_destroy(&response)
	assert(error.kind == .None && response.status == 200)

	thread.join(worker)
	testing.expect(t, strings.has_prefix(server.headers, "GET /sw.js HTTP/1.1\r\n"))
	testing.expect_value(
		t,
		peer.header_value(server.headers, "User-Agent"),
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	)
	testing.expect_value(t, peer.header_value(server.headers, "Sec-Fetch-Site"), "none")
	revision, decoded := wa.web_version_revision(response.body)
	testing.expect(t, decoded.kind == .None && revision == 1234567890)
}

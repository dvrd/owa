package loopback

import "core:net"
import "core:strings"
import "core:time"

listen :: proc() -> (net.TCP_Socket, int) {
	listener, err := net.listen_tcp({net.IP4_Loopback, 0}, backlog = 1)
	assert(err == nil)
	assert(net.set_option(listener, .Receive_Timeout, 5 * time.Second) == .None)
	endpoint, bound := net.bound_endpoint(listener)
	assert(bound == .None)
	return listener, endpoint.port
}

accept :: proc(listener: net.TCP_Socket, tcp: ^net.TCP_Connection) -> net.Connection {
	socket, source, err := net.accept_tcp(listener)
	assert(err == .None && source.address == net.IP4_Loopback)
	tcp.socket = socket
	conn := net.tcp_connection(tcp)
	assert(net.set_deadline(conn, time.time_add(time.now(), 3*time.Second)) == nil)
	return conn
}

read_exact :: proc(conn: net.Connection, dst: []u8) {
	n, err := net.read_exact(conn, dst)
	assert(err == nil && n == len(dst))
}

send_all :: proc(conn: net.Connection, data: []u8) {
	n, err := net.write_all(conn, data)
	assert(err == nil && n == len(data))
}

read_headers :: proc(socket: net.Connection, buffer: []u8) -> string {
	for i in 0 ..< len(buffer) {
		read_exact(socket, buffer[i:i + 1])
		if i >= 3 && string(buffer[i - 3:i + 1]) == "\r\n\r\n" {
			return string(buffer[:i + 1])
		}
	}
	panic("HTTP headers exceed the test peer's buffer")
}

header_value :: proc(headers, name: string) -> string {
	result: string
	remaining := headers
	for line in strings.split_lines_iterator(&remaining) {
		key, sep, value := strings.partition(line, ":")
		if sep != "" && strings.equal_fold(key, name) {
			assert(result == "", "Duplicate request header")
			result = strings.trim_space(value)
		}
	}
	return result
}

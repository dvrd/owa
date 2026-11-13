package main

import wa "../.."
import surf "../../../surf"
import ws "../../../websocket"
import "core:bytes"
import "core:encoding/hex"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"

socket_tcp_port: int

socket_tcp_close :: proc(data: rawptr) -> surf.WebSocket_Stream_Error {
 peer := cast(^Socket_Recovery)data
 return peer.native_stream.close(peer.native_stream.data)
}

socket_tcp_connect :: proc(peer: ^Socket_Recovery) {
 socket, error := net.dial_tcp_from_endpoint({net.IP4_Loopback, socket_tcp_port})
 assert(error == nil)
 peer.tcp = {socket = socket}
 connection := net.tcp_connection(&peer.tcp)
 assert(net.set_deadline(connection, time.time_add(time.now(), 10*time.Second)).kind == .None)
 peer.native_stream = surf.websocket_tcp_stream(&peer.tcp)
 peer.tcp_enabled = true
 peer.socket.websocket.config.host = "127.0.0.1"
 peer.socket.websocket.stream = {data = peer, read = socket_recovery_read,
  write = socket_recovery_write, close = socket_tcp_close, abort = socket_tcp_close}
}

socket_tcp_wait_replay :: proc(peer: ^Socket_Recovery) {
 path := fmt.aprintf("%s/tcp-replay-received.bin", peer.directory); defer delete(path)
 expected := wa.state_hash(peer.output[:peer.output_size])
 started := time.tick_now()
 for {
  assert(time.tick_since(started) < 5*time.Second)
  if os.exists(path) {
   data, error := os.read_entire_file(path, context.allocator)
   assert(error == nil)
   valid := bytes.equal(data, expected[:]); delete(data)
   if valid {return}
  }
  time.sleep(time.Millisecond)
 }
}

socket_tcp_packet :: proc(connection: net.Connection, buffer: []u8) -> []u8 {
 used := 0
 for used < len(buffer) {
  count, error := connection.read(connection.data, buffer[used:][:min(3, len(buffer)-used)])
  if error.kind == .Peer_Closed && used == 0 {return nil}
  assert(error.kind == .None && count > 0)
  used += count
  header, offset, decoded := ws.frame_header_decode(buffer[:used], true)
  if decoded != .None {continue}
  assert(header.opcode == .Binary && header.fin)
  assert(header.payload_length <= u64(len(buffer)-offset))
  if offset+int(header.payload_length) == used {return buffer[:used]}
 }
 assert(false); return nil
}

// Only the independent receiver creates these files, after real TCP reception
// and real Signal/group authentication. The sender callback cannot fabricate it.
socket_tcp_receive :: proc(directory: string, packet: []u8, replay: bool) {
 f := fixture_open(directory, false); defer fixture_close(f)
 peer := socket_recovery_attach(f, directory, "native-peer", true)
 defer socket_recovery_close(peer)
 snapshot, found := wa.state_store_get(&f.store, .Captured_Message, "socket-peer-session")
 assert(found && wa.signal_session_decode(&f.pair.a, snapshot).kind == .None)
 copy_packet := make([]u8, len(packet)); defer delete(copy_packet)
 copy(copy_packet, packet)
 inner := socket_transport_inner(copy_packet); defer delete(inner)
 socket_peer_decrypt(f, inner)
 name := "replay.bin" if replay else "transport.bin"
 socket_owned_write(directory, name, packet)
 if !replay {
  witness := socket_state_witness(peer)
  socket_owned_write(directory, "transport-state.bin", witness[:])
 }
 marker := "tcp-replay-received.bin" if replay else "tcp-transport-received.bin"
 digest := wa.state_hash(packet)
 socket_owned_write(directory, marker, digest[:])
 encoded, encoding := hex.encode(digest[:]); assert(encoding == nil)
 defer delete(encoded)
 fmt.printf("ENCRYPTED_TCP_HANDOFF hash=%s bytes=%d authenticated=true replay=%t\n",
  string(encoded), len(packet), replay)
}

socket_tcp_peer :: proc(directory, mode: string) {
 replay := strings.has_prefix(mode, "replay:")
 assert(replay || strings.has_prefix(mode, "stage:"))
 stage := mode[7:] if replay else mode[6:]
 assert(strings.has_prefix(stage, "socket-"))
 listener, error := net.listen_tcp({net.IP4_Loopback, 0}, backlog = 1)
 assert(error == nil)
 listener_open := true
 defer if listener_open {net.close(listener)}
 endpoint, endpoint_error := net.bound_endpoint(listener); assert(endpoint_error == .None)
 assert(endpoint.port > 0 && endpoint.port < 65536)
 fmt.printf("ENCRYPTED_TCP_PEER_READY port=%d\n", endpoint.port)
 socket, source, accepted := net.accept_tcp(listener)
 assert(accepted == .None && source.address == net.IP4_Loopback)
 net.close(listener); listener_open = false
 tcp := net.TCP_Connection{socket = socket}
 connection := net.tcp_connection(&tcp)
 defer connection.close(connection.data)
 assert(net.set_deadline(connection, time.time_add(time.now(), 10*time.Second)).kind == .None)
 buffer: [8192]u8
 packet := socket_tcp_packet(connection, buffer[:])
 received, ack := len(packet) > 0, false
 if received {
  socket_tcp_receive(directory, packet, replay)
  if !replay && (stage == "socket-after-positive-ack" || stage == "socket-after-ack-journal") {
   output: [2048]u8
   size := socket_recovery_ack_frame(output[:])
   count, written := net.write_all(connection, output[:size])
   assert(written.kind == .None && count == size)
   ack = true
   fmt.printf("ENCRYPTED_TCP_ACK_SENT bytes=%d\n", count)
  }
  // The owner kills/closes the client; no second application frame is allowed.
  trailing: [1]u8
  count, closed := connection.read(connection.data, trailing[:])
  assert(count == 0 && closed.kind == .Peer_Closed)
 }
 assert(connection.close(connection.data).kind == .None && tcp.closed)
 fmt.printf("ENCRYPTED_TCP_PEER_DONE received=%t ack=%t replay=%t closed=true\n",
  received, ack, replay)
}

package message_transport

import "core:time"
import ws "shared:async/websocket"
import "shared:surf"

Bytes_IO :: #type proc(_: rawptr, _: []u8) -> (int, surf.WebSocket_Error)
Read :: #type proc(
	_: rawptr,
	_: []u8,
	_: time.Time,
) -> (
	surf.WebSocket_Message_Kind,
	int,
	surf.WebSocket_Error,
)
Write :: #type proc(_: rawptr, _: []u8, _: time.Time) -> surf.WebSocket_Error

// The synthetic peers record RFC 6455 frames to check ACKs and crash boundaries.
reader :: proc($receive: Bytes_IO) -> Read {
	return(
		proc(
			data: rawptr,
			dst: []u8,
			_: time.Time,
		) -> (
			surf.WebSocket_Message_Kind,
			int,
			surf.WebSocket_Error,
		) {
			header: [10]u8
			if e := read_exact(data, header[:2], receive); e.kind != .None {
				return {}, 0, e
			}

			n := 2
			switch header[1] {
			case 126:
				n += 2
			case 127:
				n += 8
			}

			if e := read_exact(data, header[2:n], receive); e.kind != .None {
				return {}, 0, e
			}

			h, _, e := ws.frame_header_decode(header[:n], false)
			if e != .None || !h.fin || h.opcode != .Binary || h.payload_length > u64(len(dst)) {
				return {}, 0, {kind = .Protocol_Failed}
			}

			size := int(h.payload_length)
			return .Binary, size, read_exact(data, dst[:size], receive)
		} \
	)
}

read_exact :: proc(data: rawptr, dst: []u8, receive: Bytes_IO) -> surf.WebSocket_Error {
	for at := 0; at < len(dst); {
		n, e := receive(data, dst[at:])
		if e.kind != .None {
			return e
		}

		if n <= 0 || n > len(dst) - at {
			return {kind = .Peer_Closed}
		}

		at += n
	}

	return {}
}

writer :: proc($send: Bytes_IO) -> Write {
	return proc(data: rawptr, payload: []u8, _: time.Time) -> surf.WebSocket_Error {
			wire := make([]u8, len(payload) + 14)
			defer delete(wire)

			n, e := ws.frame_encode(wire, true, .Binary, payload, {1, 2, 3, 4})
			assert(e == .None)
			count, err := send(data, wire[:n])
			if err.kind == .None && count != n {
				return {kind = .IO_Failed}
			}

			return err
		}
}

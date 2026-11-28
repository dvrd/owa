package whatsapp

import "core:mem"
import "core:time"
import "shared:surf"

FRAME_HEADER_SIZE :: 3
MAX_FRAME_PAYLOAD :: 0xff_ffff

Frame_Error :: enum {
	Destination_Undersized,
	Header_Incomplete,
	None,
	Negative_Length,
	Payload_Incomplete,
	Payload_Oversized,
	Invalid_Consume_Count,
	Receive_Buffer_Full,
}

frame_encode_len :: proc(size: int) -> (header: [3]u8, error: Frame_Error) {
	if size < 0 {
		return {}, .Negative_Length
	}

	if size > MAX_FRAME_PAYLOAD {
		return {}, .Payload_Oversized
	}

	header[0] = cast(u8)(size >> 16) & 0xff
	header[1] = cast(u8)(size >> 8) & 0xff
	header[2] = cast(u8)size & 0xff

	return header, .None
}

frame_decode_len :: proc(header: [3]u8) -> int {
	return cast(int)header[0] << 16 | cast(int)header[1] << 8 | cast(int)header[2]
}

frame_encode :: proc(dst: []u8, payload: []u8) -> (written: int, error: Frame_Error) {
	header, len_err := frame_encode_len(len(payload))
	if len_err != .None {
		return 0, len_err
	}

	required := FRAME_HEADER_SIZE + len(payload)

	if len(dst) < required {
		return 0, .Destination_Undersized
	}

	copy(dst[:FRAME_HEADER_SIZE], header[:])
	copy(dst[FRAME_HEADER_SIZE:required], payload)

	return required, .None
}

frame_decode :: proc(src: []u8) -> (payload: []u8, consumed: int, error: Frame_Error) {
	if len(src) < FRAME_HEADER_SIZE {
		return nil, 0, .Header_Incomplete
	}

	header := [3]u8{src[0], src[1], src[2]}

	payload_size := frame_decode_len(header)

	required := FRAME_HEADER_SIZE + payload_size

	if len(src) < required {
		return nil, 0, .Payload_Incomplete
	}

	return src[FRAME_HEADER_SIZE:required], required, .None
}

// Accumulates WhatsApp frames from arbitrary-sized reads in caller storage.
Frame_Reader :: struct {
	storage: []u8,
	used:    int,
}

frame_reader_feed :: proc(reader: ^Frame_Reader, data: []u8) -> Frame_Error {
	available := len(reader.storage) - reader.used

	if len(data) > available {
		return .Receive_Buffer_Full
	}

	copy(reader.storage[reader.used:], data)
	reader.used += len(data)

	return .None
}

// Borrows the first complete frame without consuming it.
frame_reader_peek :: proc(
	reader: ^Frame_Reader,
) -> (
	payload: []u8,
	consumed: int,
	error: Frame_Error,
) {
	return frame_decode(reader.storage[:reader.used])
}

frame_reader_consume :: proc(reader: ^Frame_Reader, count: int) -> Frame_Error {
	if count < 0 || count > reader.used {
		return .Invalid_Consume_Count
	}

	remaining := reader.used - count
	copy(reader.storage[:remaining], reader.storage[count:reader.used])
	reader.used = remaining

	return .None
}

FRAME_INTRO :: [4]u8{87, 65, 6, 3}

DEFAULT_TRANSPORT_MAX_PAYLOAD :: 1 << 20
MAX_EMPTY_WEBSOCKET_MESSAGES :: 128

Frame_Transport_Error_Kind :: enum {
	None,
	Invalid_State,
	Already_Initialized,
	Invalid_Connection,
	Invalid_Payload_Limit,
	Payload_Oversized,
	WebSocket_Message_Oversized,
	WebSocket_Write_Failed,
	WebSocket_Read_Failed,
	Unexpected_Message_Type,
	Destination_Undersized,
	Truncated_Envelope,
	Peer_Closed,
	No_Progress,
	Allocation_Failed,
	Frame_Codec_Failed,
}

Frame_Transport_Error :: struct {
	kind:       Frame_Transport_Error_Kind,
	websocket:  surf.WebSocket_Error,
	frame:      Frame_Error,
	allocation: mem.Allocator_Error,
}

// Borrows an already-open WebSocket. Owns only its receive buffers; clear does
// not close the socket. Payloads are opaque: Noise and message decoding happen
// above this layer. Optional routing-info/ED introduction headers are not used.
// This state must stay at a stable address and be used serially.
Frame_Transport :: struct {
	connection:                      ^Message_Connection,
	max_payload:                     int,
	allocator:                       mem.Allocator,
	initialized, intro_sent, failed: bool,
	failure:                         Frame_Transport_Error,
	// Keep one complete WS message so multiple WA envelopes can be drained
	// without requiring their combined length to fit max_payload.
	ws_message:                      [dynamic]u8,
	ws_at, ws_size:                  int,
	header:                          [FRAME_HEADER_SIZE]u8,
	header_used:                     int,
	payload:                         [dynamic]u8,
	payload_used, payload_size:      int,
	ready:                           bool,
}

frame_transport_init :: proc(
	state: ^Frame_Transport,
	conn: ^Message_Connection,
	max_payload: int = DEFAULT_TRANSPORT_MAX_PAYLOAD,
) -> Frame_Transport_Error {
	if state == nil {
		return {kind = .Invalid_State, frame = .None}
	}

	if state.initialized {
		return {kind = .Already_Initialized, frame = .None}
	}

	if conn == nil || conn.phase != .Open || conn.max_message_size <= 0 || conn.read == nil || conn.write == nil {
		return {kind = .Invalid_Connection, frame = .None}
	}

	if max_payload < 0 || max_payload > MAX_FRAME_PAYLOAD {
		return {kind = .Invalid_Payload_Limit, frame = .None}
	}

	state^ = {
		connection  = conn,
		max_payload = max_payload,
		allocator   = context.allocator,
		initialized = true,
		ws_message  = make([dynamic]u8, context.allocator),
		payload     = make([dynamic]u8, context.allocator),
	}

	return {frame = .None}
}

// Sends one binary WS message. The WA introduction is prepended to the first
// successfully sent envelope only. The WS message limit independently bounds
// the payload plus its three-byte header and first-send four-byte introduction.
// Local size errors consume nothing and can be corrected and retried.
frame_transport_send :: proc(state: ^Frame_Transport, payload: []u8) -> Frame_Transport_Error {
	if err := frame_transport_validate(state); err.kind != .None {
		return err
	}

	if len(payload) > state.max_payload || len(payload) > MAX_FRAME_PAYLOAD {
		return {kind = .Payload_Oversized, frame = .Payload_Oversized}
	}

	intro_size := 0
	if !state.intro_sent {
		intro_size = len(FRAME_INTRO)
	}

	wire_size := intro_size + FRAME_HEADER_SIZE + len(payload)

	if wire_size > state.connection.max_message_size {
		return {
			kind = .WebSocket_Message_Oversized,
			websocket = {kind = .Message_Oversized},
			frame = .None,
		}
	}

	wire, allocation_err := make([]u8, wire_size, state.allocator)

	if allocation_err != nil {
		return frame_transport_fail(
			state,
			{kind = .Allocation_Failed, allocation = allocation_err, frame = .None},
		)
	}
	defer delete(wire, state.allocator)

	if intro_size != 0 {
		intro := FRAME_INTRO
		copy(wire[:intro_size], intro[:])
	}

	_, frame_err := frame_encode(wire[intro_size:], payload)

	if frame_err != .None {
		return frame_transport_fail(state, {kind = .Frame_Codec_Failed, frame = frame_err})
	}

	if err := state.connection.write(state.connection.data, wire, state.connection.write_deadline); err.kind != .None {
		return frame_transport_fail(
			state,
			{kind = .WebSocket_Write_Failed, websocket = err, frame = .None},
		)
	}

	state.intro_sent = true

	return {frame = .None}
}

// Reads one WA envelope across binary WS message boundaries. Complete envelopes
// are retained if dst is undersized: n reports the required size for retry.
// Empty WA envelopes are valid and still consume their three-byte header.
frame_transport_receive :: proc(
	state: ^Frame_Transport,
	dst: []u8,
) -> (
	n: int,
	error: Frame_Transport_Error,
) {
	_, err := frame_transport_prepare(state, {})
	if err.kind != .None {
		return 0, err
	}

	return frame_transport_deliver(state, dst)
}

// A caller's wait can end between WebSocket messages. Keep the partially
// assembled envelope until the next read. Only a transport error ends it.
@(private)
frame_transport_prepare :: proc(state: ^Frame_Transport, deadline: time.Time) -> (bool, Frame_Transport_Error) {
	if err := frame_transport_validate(state); err.kind != .None {
		return false, err
	}

	if state.ready {
		return true, {frame = .None}
	}

	empty_messages := 0

	for {
		if state.ws_at == state.ws_size {
			conn := state.connection
			if deadline != {} && conn.poll != nil {
				remaining := time.diff(time.now(), deadline)
				if remaining <= 0 {
					return false, {frame = .None}
				}

				ready, err := conn.poll(conn.data, remaining, nil)
				if err.kind != .None {
					return false, frame_transport_read_fail(state, err)
				}

				if !ready {
					return false, {frame = .None}
				}
			}

			if err := frame_transport_next_message(state); err.kind != .None {
				return false, err
			}

			if state.ws_size == 0 {
				empty_messages += 1

				if empty_messages > MAX_EMPTY_WEBSOCKET_MESSAGES {
					return false, frame_transport_fail(state, {kind = .No_Progress, frame = .None})
				}

				continue
			}
		}

		if state.header_used < FRAME_HEADER_SIZE {
			complete, header_error := frame_transport_header_receive(state)
			if header_error.kind != .None {
				return false, header_error
			}

			if !complete {
				continue
			}
		}

		count := copy(
			state.payload[state.payload_used:],
			state.ws_message[state.ws_at:state.ws_size],
		)
		state.payload_used += count
		state.ws_at += count

		if state.payload_used == state.payload_size {
			state.ready = true
			return true, {frame = .None}
		}
	}
}

frame_transport_header_receive :: proc(state: ^Frame_Transport) -> (bool, Frame_Transport_Error) {
	count := copy(state.header[state.header_used:], state.ws_message[state.ws_at:state.ws_size])
	state.header_used += count
	state.ws_at += count

	if state.header_used < FRAME_HEADER_SIZE {
		return false, {}
	}

	state.payload_size = frame_decode_len(state.header)

	if state.payload_size > state.max_payload {
		return false, frame_transport_fail(
			state,
			{kind = .Payload_Oversized, frame = .Payload_Oversized},
		)
	}

	// Validate the declared size before allocating payload storage.
	if allocation_err := resize(&state.payload, state.payload_size); allocation_err != nil {
		return false, frame_transport_fail(
			state,
			{kind = .Allocation_Failed, allocation = allocation_err, frame = .None},
		)
	}

	return true, {}
}

// Clears owned buffers and permits reuse with a fresh, already-open WebSocket.
// The borrowed WebSocket is deliberately left under the caller's ownership.
frame_transport_clear :: proc(state: ^Frame_Transport) {
	if state == nil {
		return
	}

	delete(state.ws_message)
	delete(state.payload)
	state^ = {}
}

frame_transport_validate :: proc(state: ^Frame_Transport) -> Frame_Transport_Error {
	if state == nil || !state.initialized {
		return {kind = .Invalid_State, frame = .None}
	}

	if state.failed {
		return state.failure
	}

	if state.connection == nil {
		return {kind = .Invalid_Connection, frame = .None}
	}

	return {frame = .None}
}

frame_transport_next_message :: proc(state: ^Frame_Transport) -> Frame_Transport_Error {
	if len(state.ws_message) == 0 {
		if e := resize(&state.ws_message, state.connection.max_message_size); e != nil {
			return frame_transport_fail(state, {kind = .Allocation_Failed, allocation = e})
		}
	}

	conn := state.connection
	opcode, n, err := conn.read(conn.data, state.ws_message[:], conn.read_deadline)
	if err.kind != .None {
		return frame_transport_read_fail(state, err)
	}

	if opcode != .Binary {
		return frame_transport_fail(state, {kind = .Unexpected_Message_Type})
	}

	if n < 0 || n > len(state.ws_message) {
		return frame_transport_fail(state, {kind = .WebSocket_Message_Oversized})
	}

	state.ws_at, state.ws_size = 0, n
	return {frame = .None}
}

frame_transport_read_fail :: proc(
	state: ^Frame_Transport,
	err: surf.WebSocket_Error,
) -> Frame_Transport_Error {
	kind: Frame_Transport_Error_Kind = .WebSocket_Read_Failed
	frame_err: Frame_Error = .None
	if state.header_used > 0 || state.payload_used > 0 {
		kind = .Truncated_Envelope
		frame_err = .Payload_Incomplete

		if state.header_used < FRAME_HEADER_SIZE {
			frame_err = .Header_Incomplete
		}
	} else if err.kind == .Peer_Closed || err.kind == .Closed {
		kind = .Peer_Closed
	}

	return frame_transport_fail(state, {kind = kind, websocket = err, frame = frame_err})
}

frame_transport_deliver :: proc(
	state: ^Frame_Transport,
	dst: []u8,
) -> (
	int,
	Frame_Transport_Error,
) {
	if len(dst) < state.payload_size {
		return state.payload_size, {
			kind = .Destination_Undersized,
			frame = .Destination_Undersized,
		}
	}

	count := copy(dst, state.payload[:])
	state.ready = false
	state.header_used, state.payload_used, state.payload_size = 0, 0, 0
	clear(&state.payload)

	return count, {frame = .None}
}

frame_transport_fail :: proc(
	state: ^Frame_Transport,
	err: Frame_Transport_Error,
) -> Frame_Transport_Error {
	delete(state.ws_message)
	delete(state.payload)
	state.ws_message, state.payload = nil, nil
	state.failed = true
	state.failure = err
	state.ready = false

	return err
}

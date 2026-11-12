package whatsapp

import network_client "../surf"
import websocket "../websocket"
import "core:crypto"
import "core:crypto/x25519"
import "core:encoding/hex"
import "core:testing"

// Independent pinned Baileys/Node handshake vectors also used by Mesa's consumer
// suite. The second authenticates correctly but carries issuer serial one.
SOCKET_CERT_VALID_HELLO :: "1a6c0a20883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482" +
	"fa578c103f06c7712305c99cd811daad2ae49577362c2af503eb36b54716c7e191e196f5da974163" +
	"e0d243675d84f8e03ca39d132d2469772261a16f2adf7b37369f19e094e3d124227e1f7b467fe4812a0"
SOCKET_CERT_OTHER_HELLO :: "1a6c0a20883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482" +
	"fa578c103f06c7712305c99cd811daad2ae49577362c2af503eb36b54716c7e191e196f5da974163" +
	"e0d243675d84f8e03ca39d132d2469772261a16f2adf7b373687f2065396f7ad0135ac5cf53610b69d3"

Socket_Cert_Test :: struct {
	t: ^testing.T,
	input, output: []u8,
	read_at, written, closed, calls: int,
	reject: bool,
}

socket_cert_test_read :: proc(data: rawptr, dst: []u8) ->
	(int, network_client.WebSocket_Stream_Error) {
	state := cast(^Socket_Cert_Test)data
	n := min(len(dst), len(state.input) - state.read_at, 5)
	copy(dst[:n], state.input[state.read_at:][:n]); state.read_at += n
	if n == 0 {return 0, {kind = .EOF}}
	return n, {}
}

socket_cert_test_write :: proc(data: rawptr, src: []u8) ->
	(int, network_client.WebSocket_Stream_Error) {
	state := cast(^Socket_Cert_Test)data
	n := min(len(src), len(state.output) - state.written)
	copy(state.output[state.written:][:n], src[:n]); state.written += n
	return n, {}
}

socket_cert_test_close :: proc(data: rawptr) -> network_client.WebSocket_Stream_Error {
	state := cast(^Socket_Cert_Test)data
	state.closed += 1
	return {}
}

socket_cert_test_verify :: proc(payload: []u8, server_static: [32]u8) -> Certificate_Error {
	state := cast(^Socket_Cert_Test)context.user_ptr
	state.calls += 1
	chain, error := cert_chain_decode(payload)
	testing.expect_value(state.t, error, .None)
	testing.expect(state.t, chain.has_intermediate && chain.intermediate.has_details)
	key := server_static
	testing.expect_value(state.t, crypto.is_zero_constant_time(key[:]), 0)
	return state.reject ? .Rejected : .None
}

socket_cert_test_init :: proc(socket: ^Socket, auth: ^Auth_State, state: ^Socket_Cert_Test,
	verify: Certificate_Verifier) {
	for &byte, index in auth.credentials.noise_private {byte = u8(index + 65)}
	socket.auth = auth
	socket.websocket = {
		phase = .Open, allocator = context.allocator,
		config = {host = "synthetic.invalid", max_message_size = 1024},
		stream = {data = state, read = socket_cert_test_read,
			write = socket_cert_test_write,
			close = socket_cert_test_close},
	}
	settings := Socket_Config{verify_certificate = verify}
	// This initialized-transport boundary also runs after socket_connect dials.
	testing.expect_value(state.t, socket_client_init(socket, settings).kind, .None)
	// Only test entropy is replaced, before I/O, to match the independent responder.
	noise_clear(&socket.client.noise)
	for &byte, index in socket.client.ephemeral_private {byte = u8(index + 1)}
	x25519.scalarmult_basepoint(socket.client.ephemeral_public[:],
		socket.client.ephemeral_private[:])
	testing.expect_value(state.t, noise_init(&socket.client.noise,
		socket.client.ephemeral_public), .None)
}

socket_cert_test_frames :: proc(output: []u8) -> int {
	count, at := 0, 0
	for _ in 0 ..< 4 {
		if at == len(output) {return count}
		header, used, error := websocket.frame_header_decode(output[at:], true)
		assert(error == .None)
		at += used + int(header.payload_length)
		assert(at <= len(output)); count += 1
	}
	panic("unexpected handshake frame count")
}

socket_cert_test_case :: proc(t: ^testing.T, alternate, custom, reject: bool) {
	encoded := alternate ? SOCKET_CERT_OTHER_HELLO : SOCKET_CERT_VALID_HELLO
	hello, decode_error := hex.decode(transmute([]u8)encoded); assert(decode_error)
	defer delete(hello)
	input, output: [1024]u8
	// One unmasked binary WebSocket message containing one WhatsApp envelope.
	assert(len(hello) + 3 < 126)
	input[0], input[1], input[4] = 0x82, u8(len(hello) + 3), u8(len(hello))
	copy(input[5:], hello)
	state := Socket_Cert_Test{t = t, input = input[:5 + len(hello)], output = output[:],
		reject = reject}
	previous := context.user_ptr
	context.user_ptr = &state
	defer context.user_ptr = previous
	socket: Socket
	auth: Auth_State
	verify: Certificate_Verifier
	if custom {verify = socket_cert_test_verify}
	socket_cert_test_init(&socket, &auth, &state, verify)
	defer {client_close(&socket.client); auth_state_clear(&auth)}
	result := client_handshake(&socket.client, nil)
	failed := custom ? reject : alternate
	testing.expect_value(t, state.calls, custom ? 1 : 0)
	if failed {
		testing.expect_value(t, result.kind, .Certificate_Rejected)
		testing.expect_value(t, result.certificate,
			custom ? .Rejected : .Unexpected_Issuer_Serial)
		testing.expect_value(t, socket.client.phase, .Failed)
		testing.expect_value(t, state.closed, 1)
		testing.expect_value(t, socket_cert_test_frames(output[:state.written]), 1)
		before := state.written
		testing.expect_value(t, client_handshake(&socket.client, nil).kind,
			.Certificate_Rejected)
		testing.expect_value(t, state.written, before)
		testing.expect_value(t, state.calls, custom ? 1 : 0)
	} else {
		testing.expect_value(t, result.kind, .None)
		testing.expect_value(t, socket.client.phase, .Noise_Ready)
		testing.expect_value(t, socket_cert_test_frames(output[:state.written]), 2)
	}
}

@(test)
socket_certificate_verifier_reaches_handshake_and_preserves_default :: proc(t: ^testing.T) {
	socket_cert_test_case(t, false, false, false)
	socket_cert_test_case(t, true, false, false)
	socket_cert_test_case(t, false, true, true)
	socket_cert_test_case(t, true, true, false)
}

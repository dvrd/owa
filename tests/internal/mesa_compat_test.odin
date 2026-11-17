package whatsapp

import "core:os"
import "core:strings"
import "core:testing"

@(test)
frame_reader_reassembles_split_frames_and_bounds_its_storage :: proc(t: ^testing.T) {
	wire: [12]u8
	_, encoded := frame_encode(wire[:], {1, 2, 3, 4, 5})
	testing.expect_value(t, encoded, Frame_Error.None)
	storage: [16]u8
	reader := Frame_Reader {
		storage = storage[:],
	}
	testing.expect_value(t, frame_reader_feed(&reader, wire[:2]), Frame_Error.None)
	_, _, error := frame_reader_peek(&reader)
	testing.expect_value(t, error, Frame_Error.Header_Incomplete)
	testing.expect_value(t, frame_reader_feed(&reader, wire[2:5]), Frame_Error.None)
	_, _, error = frame_reader_peek(&reader)
	testing.expect_value(t, error, Frame_Error.Payload_Incomplete)
	testing.expect_value(t, frame_reader_feed(&reader, wire[5:8]), Frame_Error.None)
	payload, consumed, peek_error := frame_reader_peek(&reader)
	testing.expect_value(t, peek_error, Frame_Error.None)
	testing.expect_value(t, consumed, 8)
	testing.expect_value(t, len(payload), 5)
	testing.expect_value(t, frame_reader_consume(&reader, -1), Frame_Error.Invalid_Consume_Count)
	testing.expect_value(t, frame_reader_consume(&reader, 9), Frame_Error.Invalid_Consume_Count)
	testing.expect_value(t, frame_reader_consume(&reader, consumed), Frame_Error.None)
	testing.expect_value(t, reader.used, 0)
	testing.expect_value(t, frame_reader_feed(&reader, wire[:]), Frame_Error.None)
	testing.expect_value(t, frame_reader_feed(&reader, wire[:6]), Frame_Error.Receive_Buffer_Full)
}

@(test)
group_metadata_query_encode_builds_the_interactive_query_and_validates_input :: proc(t: ^testing.T) {
	buffer: [256]u8
	size, error := group_metadata_query_encode(buffer[:], "120363000000000000@g.us", "req-1")
	testing.expect_value(t, error.kind, Group_Error_Kind.None)
	document, decode_error := binary_node_decode(buffer[:size])
	defer binary_document_destroy(&document)
	testing.expect_value(t, decode_error.kind, Binary_Node_Error_Kind.None)
	xmlns, _ := node_attr(document.root, "xmlns")
	to, _ := node_attr(document.root, "to")
	testing.expect_value(t, xmlns, "w:g2")
	testing.expect_value(t, to, "120363000000000000@g.us")
	testing.expect_value(t, document.root.tag, "iq")
	query := node_child(document.root, "query")
	testing.expect(t, query != nil)
	request, _ := node_attr(query^, "request")
	testing.expect_value(t, request, "interactive")
	_, bad_jid := group_metadata_query_encode(buffer[:], "not-a-group", "req-1")
	testing.expect_value(t, bad_jid.kind, Group_Error_Kind.Invalid_Group_JID)
	_, empty_id := group_metadata_query_encode(buffer[:], "120363000000000000@g.us", "")
	testing.expect_value(t, empty_id.kind, Group_Error_Kind.Invalid_Request_ID)
	_, small := group_metadata_query_encode(buffer[:4], "120363000000000000@g.us", "req-1")
	testing.expect_value(t, small.kind, Group_Error_Kind.Binary_Node_Failed)
}

@(test)
state_atomic_write_replaces_the_file_and_reports_a_missing_directory :: proc(t: ^testing.T) {
	directory, directory_error := os.make_directory_temp("", "wa-atomic-*", context.allocator)
	testing.expect(t, directory_error == nil)
	defer {
		os.remove_all(directory)
		delete(directory)
	}
	path := strings.concatenate({directory, "/state.bin"})
	defer delete(path)
	testing.expect_value(t, state_atomic_write(path, transmute([]u8)string("one")).kind, State_Error_Kind.None)
	testing.expect_value(t, state_atomic_write(path, transmute([]u8)string("two!")).kind, State_Error_Kind.None)
	data, read_error := os.read_entire_file(path, context.allocator)
	testing.expect(t, read_error == nil)
	defer delete(data)
	testing.expect_value(t, string(data), "two!")
	missing := strings.concatenate({directory, "/absent/state.bin"})
	defer delete(missing)
	testing.expect_value(t, state_atomic_write(missing, transmute([]u8)string("x")).kind, State_Error_Kind.Write_Failed)
}

@(test)
signal_group_message_encode_signs_an_envelope_the_decoder_accepts :: proc(t: ^testing.T) {
	ciphertext: [16]u8
	signing_private: [32]u8
	signing_private[0] = 7
	wire: [128]u8
	size, error := signal_group_message_encode(wire[:], 123, 4, ciphertext[:], signing_private)
	testing.expect_value(t, error, Signal_Group_Error.None)
	message, decode_error := signal_group_message_decode(wire[:size])
	testing.expect_value(t, decode_error, Signal_Group_Error.None)
	testing.expect_value(t, message.iteration, u32(4))
	_, unpadded := signal_group_message_encode(wire[:], 123, 4, ciphertext[:5], signing_private)
	testing.expect_value(t, unpadded, Signal_Group_Error.Invalid_Ciphertext)
	_, small := signal_group_message_encode(wire[:10], 123, 4, ciphertext[:], signing_private)
	testing.expect_value(t, small, Signal_Group_Error.Destination_Undersized)
}

@(test)
pairing_observer_receives_application_events :: proc(t: ^testing.T) {
	count: int
	observer: Pairing_Observer = proc(data: rawptr, event: Pairing_Event) {
		(cast(^int)data)^ += 1 if event.kind == .QR && event.qr == "qr" else 0
	}
	observer(&count, {kind = .QR, qr = "qr"})
	observer(&count, {kind = .Online})
	testing.expect_value(t, count, 1)
}

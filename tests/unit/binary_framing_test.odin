package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
frame_reader_reassembles_split_frames_and_bounds_its_storage :: proc(t: ^testing.T) {
	wire: [12]u8
	_, encoded := wa.frame_encode(wire[:], {1, 2, 3, 4, 5})

	testing.expect_value(t, encoded, wa.Frame_Error.None)
	storage: [16]u8
	reader := wa.Frame_Reader {
		storage = storage[:],
	}

	testing.expect_value(t, wa.frame_reader_feed(&reader, wire[:2]), wa.Frame_Error.None)
	_, _, error := wa.frame_reader_peek(&reader)
	testing.expect_value(t, error, wa.Frame_Error.Header_Incomplete)
	testing.expect_value(t, wa.frame_reader_feed(&reader, wire[2:5]), wa.Frame_Error.None)
	_, _, error = wa.frame_reader_peek(&reader)
	testing.expect_value(t, error, wa.Frame_Error.Payload_Incomplete)
	testing.expect_value(t, wa.frame_reader_feed(&reader, wire[5:8]), wa.Frame_Error.None)
	payload, consumed, peek_error := wa.frame_reader_peek(&reader)
	testing.expect_value(t, peek_error, wa.Frame_Error.None)
	testing.expect_value(t, consumed, 8)
	testing.expect_value(t, len(payload), 5)
	testing.expect_value(t, wa.frame_reader_consume(&reader, -1), wa.Frame_Error.Invalid_Consume_Count)
	testing.expect_value(t, wa.frame_reader_consume(&reader, 9), wa.Frame_Error.Invalid_Consume_Count)
	testing.expect_value(t, wa.frame_reader_consume(&reader, consumed), wa.Frame_Error.None)
	testing.expect_value(t, reader.used, 0)
	testing.expect_value(t, wa.frame_reader_feed(&reader, wire[:]), wa.Frame_Error.None)
	testing.expect_value(t, wa.frame_reader_feed(&reader, wire[:6]), wa.Frame_Error.Receive_Buffer_Full)
}

package whatsapp_test

import wire_frames "../fixtures/message_transport"
import "core:testing"
import wa "shared:whatsapp"

@(test)
noise_credentials_are_random_nonzero_and_accepted_by_client_init :: proc(t: ^testing.T) {
	first, first_error := wa.noise_credentials_generate()
	second, second_error := wa.noise_credentials_generate()
	testing.expect_value(t, first_error.kind, wa.Client_Error_Kind.None)
	testing.expect_value(t, second_error.kind, wa.Client_Error_Kind.None)

	zero: [32]u8
	testing.expect(t, first.static_private_key != zero)
	testing.expect(t, second.static_private_key != zero)
	testing.expect(t, first.static_private_key != second.static_private_key)

	websocket := wa.Message_Connection {
		phase = .Open,
		max_message_size = 4096,
		read = wire_frames.reader(media_retry_test_read), write = wire_frames.writer(media_retry_test_write), close = media_retry_test_close,
	}

	client: wa.Client
	defer wa.noise_clear(&client.noise)

	testing.expect_value(t, wa.client_init(&client, &websocket, first).kind, wa.Client_Error_Kind.None)
	testing.expect_value(t, client.static_private, first.static_private_key)
	testing.expect_value(t, client.static_public, wa.signal_curve_public(first.static_private_key))

	rejected: wa.Client
	testing.expect_value(t, wa.client_init(&rejected, &websocket, {}).kind, wa.Client_Error_Kind.Invalid_Credentials)
}

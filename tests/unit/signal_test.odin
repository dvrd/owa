package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
signal_group_message_encode_signs_an_envelope_the_decoder_accepts :: proc(t: ^testing.T) {
	ciphertext: [16]u8
	signing_private: [32]u8
	signing_private[0] = 7
	wire: [128]u8
	size, error := wa.signal_group_message_encode(wire[:], 123, 4, ciphertext[:], signing_private)
	testing.expect_value(t, error, wa.Signal_Group_Error.None)
	message, decode_error := wa.signal_group_message_decode(wire[:size])
	testing.expect_value(t, decode_error, wa.Signal_Group_Error.None)
	testing.expect_value(t, message.iteration, u32(4))
	_, unpadded := wa.signal_group_message_encode(wire[:], 123, 4, ciphertext[:5], signing_private)
	testing.expect_value(t, unpadded, wa.Signal_Group_Error.Invalid_Ciphertext)
	_, small := wa.signal_group_message_encode(wire[:10], 123, 4, ciphertext[:], signing_private)
	testing.expect_value(t, small, wa.Signal_Group_Error.Destination_Undersized)
}

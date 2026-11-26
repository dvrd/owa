package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
signal_curve_signature_binds_the_message :: proc(t: ^testing.T) {
	key: [32]u8
	key[0] = 7

	public := wa.signal_curve_public(key)
	message := [3]u8{1, 2, 3}

	signature, err := wa.signal_curve_sign(key, message[:])
	testing.expect_value(t, err, .None)
	testing.expect_value(t, wa.signal_curve_verify(public, message[:], signature[:]), .None)
	message[0] += 1
	testing.expect_value(t, wa.signal_curve_verify(public, message[:], signature[:]), .Verification_Failed)
}

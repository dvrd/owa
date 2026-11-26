package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
noise_transport_counters_advance_only_on_successful_encryption :: proc(t: ^testing.T) {
	state := wa.Noise_State{phase = .Transport}

	plaintext := [1]u8{42}

	wire: [1 + wa.NOISE_TAG_SIZE]u8
	_, short := wa.noise_encrypt(&state, wire[:1], plaintext[:])
	testing.expect_value(t, short, .Destination_Undersized)
	testing.expect_value(t, state.write_counter, 0)
	n, err := wa.noise_encrypt(&state, wire[:], plaintext[:])
	testing.expect_value(t, err, .None)
	testing.expect_value(t, n, len(wire))
	testing.expect_value(t, state.write_counter, 1)
}

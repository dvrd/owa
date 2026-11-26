package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
binary_token_dictionary_prefixes_select_the_expected_wire_table :: proc(t: ^testing.T) {
	testing.expect_value(t, wa.SINGLE_BYTE_TOKENS[3], "s.whatsapp.net")
	testing.expect_value(t, wa.SINGLE_BYTE_TOKENS[235], "screen_height")

	first_tokens := [4]string{"read-self", "reject", "64", "1724"}

	for expected, index in first_tokens {
		// Uncompressed node, one-element list, dictionary prefix, token index.
		wire := [5]u8{0, 248, 1, u8(236 + index), 0}

		document, err := wa.binary_node_decode(wire[:])
		defer wa.binary_document_destroy(&document)

		testing.expect_value(t, err.kind, wa.Binary_Node_Error_Kind.None)
		testing.expect_value(t, document.root.tag, expected)
	}
}

package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
binary_node_decode_requires_exactly_one_complete_node :: proc(t: ^testing.T) {
	// Flags, LIST_8, list length, receipt tag, trailing byte.
	wire := [5]u8{0, 248, 1, 7, 0}
	document, valid := wa.binary_node_decode(wire[:4])
	defer wa.binary_document_destroy(&document)
	testing.expect_value(t, valid.kind, wa.Binary_Node_Error_Kind.None)
	testing.expect_value(t, document.root.tag, "receipt")
	_, truncated := wa.binary_node_decode(wire[:3])
	testing.expect_value(t, truncated.kind, wa.Binary_Node_Error_Kind.Truncated)
	_, trailing := wa.binary_node_decode(wire[:])
	testing.expect_value(t, trailing.kind, wa.Binary_Node_Error_Kind.Trailing_Data)
}

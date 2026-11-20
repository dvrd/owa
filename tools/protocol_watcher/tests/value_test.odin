package protocol_watch_test

import w "../src"
import "core:testing"

@(test)
integer_preserves_zero_and_rejects_numeric_strings :: proc(t: ^testing.T) {
	zero, found := w.integer(w.number(0))
	testing.expect(t, found && zero == 0)
	_, is_integer := w.integer(w.text("0"))
	testing.expect(t, !is_integer)
}

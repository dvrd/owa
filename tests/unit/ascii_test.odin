package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
ascii_character_classes_preserve_byte_and_rune_boundaries :: proc(t: ^testing.T) {
	testing.expect(t, wa.is_digit(u8('9')) && !wa.is_digit(u8(':')))
	testing.expect(t, wa.is_alpha(rune('Z')) && !wa.is_alpha(rune('[')))
	testing.expect(t, wa.is_alphanumeric(rune('a')) && !wa.is_alphanumeric(rune('_')))
	testing.expect(t, wa.is_lower(u8('z')) && !wa.is_lower(u8('A')))
	testing.expect(t, wa.is_hex_upper(u8('F')) && !wa.is_hex_upper(u8('f')))
	// U+0141 has the same low byte as ASCII 'A'.
	testing.expect(t, !wa.is_alphanumeric(rune('Ł')) && !wa.is_hex_upper(rune('Ł')))
}

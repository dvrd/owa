package whatsapp

// ASCII character classes. Accept bytes and string-loop runes alike, so a
// non-ASCII code point is never narrowed into a byte before classification.

@(private)
is_alpha :: proc(c: $T) -> bool where T == u8 || T == rune {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

@(private)
is_digit :: proc(c: $T) -> bool where T == u8 || T == rune {
	return c >= '0' && c <= '9'
}

@(private)
is_alphanumeric :: proc(c: $T) -> bool where T == u8 || T == rune {
	return is_alpha(c) || is_digit(c)
}

@(private)
is_lower :: proc(c: $T) -> bool where T == u8 || T == rune {
	return c >= 'a' && c <= 'z'
}

@(private)
is_hex_upper :: proc(c: $T) -> bool where T == u8 || T == rune {
	return is_digit(c) || c >= 'A' && c <= 'F'
}

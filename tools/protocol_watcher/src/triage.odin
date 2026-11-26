package protocol_watch

import "core:slice"
import "core:unicode/utf16"
Owner :: struct {
	source, path:    string,
	targets, checks: []string,
	question:        string,
}

OWNERS := [?]Owner {
	{
		"baileys",
		"src/Socket/socket.ts",
		[]string{"socket.odin", "noise_handshake.odin", "auth.odin", "pairing.odin"},
		[]string {
			"tests/e2e/client/socket_test.odin",
			"tests/e2e/loopback_noise",
			"tests/unit/auth_test.odin",
			"tests/unit/pairing_test.odin",
		},
		"Does the changed socket lifecycle require a different admission, shutdown or certificate decision?",
	},
	{
		"baileys",
		"src/Socket/messages-send.ts",
		[]string{"send.odin", "signal.odin"},
		[]string{"tests/unit/send_test.odin", "tests/e2e/encrypted_recovery"},
		"Does the send change alter IDs, encryption envelopes or durable retry ownership?",
	},
	{
		"baileys",
		"src/Socket/messages-recv.ts",
		[]string{"receive.odin", "socket.odin", "addressing.odin"},
		[]string{"tests/unit/receive_test.odin", "tests/unit/pairing_test.odin"},
		"Does the receive change alter ACKs, durable completion, sender alias authority or pinned session selection?",
	},
	{
		"baileys",
		"src/Utils/validate-connection.ts",
		[]string{"pairing.odin", "noise_handshake.odin", "auth.odin", "protobuf.odin"},
		[]string {
			"tests/e2e/client/socket_test.odin",
			"tests/unit/noise_certificate_test.odin",
			"tests/unit/pairing_test.odin",
			"tests/unit/auth_test.odin",
		},
		"Which connection validation predicate changed, and is the same predicate owned locally?",
	},
	{
		"baileys",
		"src/Utils/noise-handler.ts",
		[]string{"noise_handshake.odin", "binary_framing.odin", "noise_cipher.odin", "noise_certificate.odin", "socket.odin"},
		[]string{"tests/e2e/loopback_noise", "tests/unit/noise_certificate_test.odin"},
		"Does the Noise transcript, frame boundary or certificate authentication contract change?",
	},
	{
		"baileys",
		"src/Defaults/baileys-version.json",
		[]string{"pairing.odin", "noise_handshake.odin"},
		[]string{"tests/unit/pairing_test.odin"},
		"Does this advertised version require a payload change, or only a separately qualified version choice?",
	},
	{
		"baileys",
		"src/WABinary/constants.ts",
		[]string{"binary_tokens.odin", "binary_node.odin"},
		[]string {
			"tests/unit/binary_tokens_test.odin",
			"tests/unit/binary_node_test.odin",
			"tests/e2e/encrypted_recovery",
		},
		"Which token positions or binary framing contracts differ from the locally bound dictionary?",
	},
	{
		"baileys",
		"WAProto/WAProto.proto",
		[]string{"protobuf.odin", "receive.odin", "send.odin"},
		[]string{"tests/e2e/encrypted_recovery", "tests/unit/protobuf_test.odin"},
		"Which changed field numbers, wire types or defaults are consumed by the local codec?",
	},
	{
		"whatsmeow",
		"client.go",
		[]string{"socket.odin", "noise_handshake.odin"},
		[]string{"tests/e2e/loopback_noise", "tests/e2e/encrypted_recovery"},
		"Does the client lifecycle change affect locally owned admission or recovery state?",
	},
	{
		"whatsmeow",
		"connectionevents.go",
		[]string{"noise_handshake.odin", "receive.odin"},
		[]string{"tests/unit/receive_test.odin"},
		"Which disconnect, notification or ACK state transition changes locally?",
	},
	{
		"whatsmeow",
		"handshake.go",
		[]string{"noise_handshake.odin", "noise_certificate.odin", "signal_curve25519.odin", "protobuf.odin"},
		[]string{"tests/unit/noise_certificate_test.odin", "tests/e2e/loopback_noise"},
		"Does the authenticated handshake transcript or certificate predicate change?",
	},
	{
		"whatsmeow",
		"pair.go",
		[]string{"pairing.odin", "protobuf.odin", "auth.odin"},
		[]string{"tests/unit/pairing_test.odin", "tests/unit/auth_test.odin"},
		"Which pairing payload or signature predicate changes, and is it used by this implementation?",
	},
	{
		"whatsmeow",
		"send.go",
		[]string{"send.odin", "signal.odin"},
		[]string{"tests/unit/send_test.odin", "tests/e2e/encrypted_recovery"},
		"Does the send envelope or ID ownership differ on an independently reproduced synthetic case?",
	},
	{
		"whatsmeow",
		"retry.go",
		[]string{"receive.odin", "send.odin", "signal.odin"},
		[]string{"tests/unit/receive_test.odin", "tests/e2e/encrypted_recovery"},
		"Does the retry transition change identity reuse, durable completion or the stop-on-negative-ACK policy?",
	},
	{
		"whatsmeow",
		"store/clientpayload.go",
		[]string{"pairing.odin", "protobuf.odin"},
		[]string{"tests/unit/protobuf_test.odin"},
		"Which advertised client payload field changed, and does the local encoder emit it?",
	},
	{
		"whatsmeow",
		"binary/token/token.go",
		[]string{"binary_tokens.odin", "binary_node.odin"},
		[]string {
			"tests/unit/binary_tokens_test.odin",
			"tests/unit/binary_node_test.odin",
			"tests/e2e/encrypted_recovery",
		},
		"Which dictionary index or token-encoding contract changes versus local tables?",
	},
	{
		"whatsmeow",
		"proto/waE2E/WAWebProtobufsE2E.proto",
		[]string{"protobuf.odin", "receive.odin", "send.odin"},
		[]string{"tests/e2e/encrypted_recovery"},
		"Which field number, wire type or default changes a locally consumed message?",
	},
}

import j "core:encoding/json"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"

TABLE_COUNT :: 236
Token :: struct {
	kind, text: string,
}

Comment :: struct {
	index, column: int,
	text:          string,
}

Lexed :: struct {
	tokens:    [dynamic]Token,
	sensitive: [dynamic]Comment,
}

OPERATORS := []string {
	">>>=",
	"===",
	"!==",
	"**=",
	">>>",
	"<<=",
	">>=",
	"&&=",
	"||=",
	"??=",
	"...",
	"=>",
	"++",
	"--",
	"==",
	"!=",
	"<=",
	">=",
	"&&",
	"||",
	"??",
	"?.",
	"**",
	"+=",
	"-=",
	"*=",
	"/=",
	"%=",
	"&=",
	"|=",
	"^=",
	"<<",
	">>",
	"<-",
	":=",
	"::",
	"&^=",
	"&^",
}

owner_for :: proc(source, path: string) -> (Owner, bool) {
	for owner in OWNERS {
		if owner.source == source && owner.path == path {
			return owner, true
		}
	}

	return {}, false
}

repository :: proc(source: string) -> string {
	if source == "baileys" {
		return "WhiskeySockets/Baileys"
	}

	if source == "whatsmeow" {
		return "tulir/whatsmeow"
	}

	return ""
}

reference_commit :: proc(source: string) -> string {
	if source == "baileys" {
		return "e05b16b4aa0d7d3eb2594677e015454af1225b75"
	}

	if source == "whatsmeow" {
		return "c88388f983b4bc43dfd0bcc2b46969fcde82d61f"
	}

	return ""
}

identifier_start :: proc(c: u8) -> bool {
	return strings.index_byte(ASCII_LETTERS + "_$", c) >= 0
}

is_identifier_continuation :: proc(c: u8) -> bool {
	return identifier_start(c) || strings.index_byte(DECIMAL_DIGITS, c) >= 0
}

sensitive_comment :: proc(comment: string) -> bool {
	lower := strings.to_lower(comment)

	for marker in ([]string {
			"copyright",
			"license",
			"spdx",
			"go:",
			"eslint",
			"tslint",
			"prettier",
			"istanbul",
			"coverage",
			"sourcemappingurl",
			"sourceurl",
			"<reference",
			"<amd-",
			"all rights reserved",
		}) {
		if strings.contains(lower, marker) {
			return true
		}
	}

	for c in comment {
		if c == '@' || c == '#' || c == '!' {
			return true
		}
	}

	for word in ([]string{"lint", "c8", "mit", "bsd", "apache", "gpl", "mpl", "isc", "unlicense", "export"}) {
		for start := 0; start < len(lower); start += 1 {
			if !strings.has_prefix(lower[start:], word) {
				continue
			}

			end := start + len(word)
			if (start == 0 || !is_identifier_continuation(lower[start - 1])) &&
			   (end == len(lower) || !is_identifier_continuation(lower[end])) {
				return true
			}
		}
	}

	compact := strings.trim_space(strings.trim_prefix(lower, "//"))

	return(
		strings.has_prefix(compact, "line ") ||
		strings.has_prefix(compact, "line\t") ||
		strings.has_prefix(compact, "+build") ||
		strings.has_prefix(lower, "/*line") \
	)
}

find_numeric_token_end :: proc(s: string, at: int) -> int {
	i := at
	if i + 2 < len(s) &&
	   s[i] == '0' &&
	   (s[i + 1] == 'x' ||
			   s[i + 1] == 'X' ||
			   s[i + 1] == 'b' ||
			   s[i + 1] == 'B' ||
			   s[i + 1] == 'o' ||
			   s[i + 1] == 'O') {
		radix := s[i + 1]
		i += 2
		start := i
		for i < len(s) {
			c := s[i]
			if c == '_' ||
			   c == '0' ||
			   c == '1' ||
			   (radix == 'o' || radix == 'O') && (c >= '0' && c <= '7') ||
			   (radix == 'x' || radix == 'X') && strings.index_byte(LOWER_HEX_DIGITS + "ABCDEF", c) >= 0 {
				i += 1
			} else {
				break
			}
		}

		if i == start {
			return at + 1
		}

		return i
	}

	for i < len(s) && strings.index_byte(DECIMAL_DIGITS + "_", s[i]) >= 0 {
		i += 1
	}

	if i < len(s) && s[i] == '.' {
		i += 1

		for i < len(s) && strings.index_byte(DECIMAL_DIGITS + "_", s[i]) >= 0 {
			i += 1
		}
	}

	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		end := i + 1

		if end < len(s) && (s[end] == '+' || s[end] == '-') {
			end += 1
		}

		start := end
		for end < len(s) && strings.index_byte(DECIMAL_DIGITS + "_", s[end]) >= 0 {
			end += 1
		}

		if end > start {
			i = end
		}
	}

	if i < len(s) && s[i] == 'n' {
		i += 1
	}

	return i
}

lex :: proc(data: []u8, language: string) -> (Lexed, string) {
	result: Lexed
	s := string(data)

	if len(data) > MAX_BYTES || !utf8.valid_string(s) {
		return {}, "INPUT_LIMIT"
	}

	if strings.contains(s, "\u2028") || strings.contains(s, "\u2029") || strings.contains(s, "\x00") {
		return {}, "UNSUPPORTED_LINE_CHARACTER"
	}

	if language == "go" {
		clean := replace(s, "\r\n", "")

		if strings.contains(clean, "\r") || strings.contains(s, "\v") || strings.contains(s, "\f") {
			return {}, "GO_WHITESPACE_AMBIGUITY"
		}
	}

	stack := make([dynamic]u8)
	i := 0

	for i < len(s) {
		if len(result.tokens) >= MAX_TOKENS {
			return {}, "TOKEN_LIMIT"
		}

		c := s[i]

		if c == ' ' || c == '\t' || c == '\v' || c == '\f' {
			i += 1
			continue
		}

		if c == '\r' || c == '\n' {
			i += 2 if strings.has_prefix(s[i:], "\r\n") else 1
			append(&result.tokens, Token{"newline", "\n"})

			continue
		}

		if strings.has_prefix(s[i:], "//") || strings.has_prefix(s[i:], "/*") {
			start := i

			if s[i + 1] == '/' {
				for i < len(s) && s[i] != '\r' && s[i] != '\n' {
					i += 1
				}
			} else {
				at := strings.index(s[i + 2:], "*/")

				if at < 0 {
					return {}, "UNCLOSED_COMMENT"
				}

				i += at + 4
			}

			comment := s[start:i]

			if sensitive_comment(comment) {
				if len(result.sensitive) >= 64 {
					return {}, "DIRECTIVE_LIMIT"
				}

				column := start

				for before := start - 1; before >= 0; before -= 1 {
					if s[before] == '\r' || s[before] == '\n' {
						column = start - before - 1
						break
					}
				}

				append(&result.sensitive, Comment{len(result.tokens), column, comment})
			}

			normalized := replace(replace(comment, "\r\n", "\n"), "\r", "\n")

			for byte in normalized {
				if byte == '\n' {
					append(&result.tokens, Token{"newline", "\n"})
				}
			}

			if len(result.tokens) > MAX_TOKENS {
				return {}, "TOKEN_LIMIT"
			}

			continue
		}

		if c == '\'' || c == '"' || c == '`' {
			start, quote := i, c; i += 1; closed := false

			for i < len(s) {
				if s[i] == quote {
					i += 1; closed = true; break
				}

				if quote != '`' && (s[i] == '\r' || s[i] == '\n') {
					return {}, "STRING_NEWLINE"
				}

				i += 2 if s[i] == '\\' && (quote != '`' || language == "ts") else 1
			}

			if !closed {
				return {}, "UNCLOSED_STRING"
			}

			literal := s[start:i]

			if quote == '`' && language == "ts" && strings.contains(literal, "${") {
				return {}, "TEMPLATE_EXPRESSION"
			}

			append(&result.tokens, Token{"raw" if quote == '`' else "string", literal})

			continue
		}

		if identifier_start(c) {
			start := i; i += 1; for i < len(s) && is_identifier_continuation(s[i]) {i += 1}

			append(&result.tokens, Token{"identifier", s[start:i]})

			continue
		}

		if strings.index_byte(DECIMAL_DIGITS, c) >= 0 ||
		   c == '.' && i + 1 < len(s) && strings.index_byte(DECIMAL_DIGITS, s[i + 1]) >= 0 {
			start := i; i = find_numeric_token_end(s, i)

			if i < len(s) && is_identifier_continuation(s[i]) {
				return {}, "NUMBER_BOUNDARY"
			}

			append(&result.tokens, Token{"number", s[start:i]})

			continue
		}

		if language == "ts" && (c == '/' || strings.has_prefix(s[i:], "<!--") || strings.has_prefix(s[i:], "-->")) {
			return {}, "SLASH_OR_HTML_AMBIGUITY"
		}

		if language == "ts" && strings.has_prefix(s[i:], "?.") &&
		   i + 2 < len(s) && strings.index_byte(DECIMAL_DIGITS, s[i + 2]) >= 0 {
			return {}, "OPTIONAL_CHAIN_DECIMAL_AMBIGUITY"
		}

		matched := false

		for op in OPERATORS {
			if strings.has_prefix(s[i:], op) {
				append(&result.tokens, Token{"operator", op})

				i += len(op); matched = true; break
			}
		}

		if matched {
			continue
		}

		if !strings.contains_rune("{}[]();,.:?~!+-*%&|^<>=/@", rune(c)) {
			return {}, "UNSUPPORTED_CHARACTER"
		}

		if c == '(' || c == '[' || c == '{' {
			append(&stack, c)
		}

		if c == ')' || c == ']' || c == '}' {
			if len(stack) == 0 {
				return {}, "DELIMITER_AMBIGUITY"
			}

			want := u8('(' if c == ')' else '[' if c == ']' else '{')

			if pop(&stack) != want {
				return {}, "DELIMITER_AMBIGUITY"
			}
		}

		append(&result.tokens, Token{"punctuation", s[i:i + 1]})

		i += 1
	}

	if len(stack) != 0 {
		return {}, "UNCLOSED_DELIMITER"
	}

	if language == "go" {
		for token in result.tokens {
			if token == (Token{"raw", "`C`"}) {
				return {}, "CGO_PREAMBLE_AMBIGUITY"
			}

			if token.kind == "string" {
				unquoted, literal_error := literal_string(token)
				if literal_error == "" && unquoted == "C" {
					return {}, "CGO_PREAMBLE_AMBIGUITY"
				}
			}
		}
	}

	return result, ""
}

literal_string :: proc(token: Token) -> (string, string) {
	s := token.text; if token.kind != "string" || len(s) < 2 {
		return "", "STRING_LITERAL_REQUIRED"
	}

	b: strings.Builder; i := 1

	for i < len(s) - 1 {
		c := s[i]; i += 1

		if c < 32 {
			return "", "STRING_CONTROL"
		}

		if c != '\\' {
			strings.write_byte(&b, c); continue
		}

		if i >= len(s) - 1 {
			return "", "STRING_ESCAPE"
		}

		c = s[i]; i += 1

		switch c {
		case 'n':
			strings.write_byte(&b, '\n')
		case 'r':
			strings.write_byte(&b, '\r')
		case 't':
			strings.write_byte(&b, '\t')
		case 'b':
			strings.write_byte(&b, '\b')
		case 'f':
			strings.write_byte(&b, '\f')
		case '\\', '"', '\'', '/':
			strings.write_byte(&b, c)
		case 'u':
			if i + 4 > len(s) - 1 {
				return "", "STRING_ESCAPE"
			}

			n, ok := strconv.parse_u64(s[i:i + 4], 16); if !ok {
				return "", "STRING_ESCAPE"
			}

			i += 4
			if n >= 0xd800 && n <= 0xdbff {
				if i + 6 > len(s) - 1 || s[i:i + 2] != "\\u" {
					return "", "STRING_ESCAPE"
				}

				low, low_ok := strconv.parse_u64(s[i + 2:i + 6], 16)

				if !low_ok || low < 0xdc00 || low > 0xdfff {
					return "", "STRING_ESCAPE"
				}

				i += 6
				n = u64(utf16.decode_surrogate_pair(rune(n), rune(low)))
			} else if n >= 0xdc00 && n <= 0xdfff {
				return "", "STRING_ESCAPE"
			}

			strings.write_rune(&b, rune(n))
		case:
			return "", "STRING_ESCAPE"
		}
	}

	result := strings.to_string(b); if len(result) > 1024 || !utf8.valid_string(result) {
		return "", "TABLE_STRING_LIMIT"
	}

	return result, ""
}

extract_single_byte_token_table :: proc(tokens: []Token, language: string) -> ([]string, []Token, string) {
	significant := make([dynamic]int)

	for t, i in tokens {
		if t.kind != "newline" {
			append(&significant, i)
		}
	}

	values := make([dynamic]string); outside := make([dynamic]Token); found, depth := 0, 0

	for index, at in significant {
		token := tokens[index]

		if token.text == "(" || token.text == "[" || token.text == "{" {
			depth += 1
		}

		if token.text == ")" || token.text == "]" || token.text == "}" {
			depth -= 1
		}

		if token != (Token{"identifier", "SINGLE_BYTE_TOKENS"}) {
			continue
		}

		if language == "ts" && (at < 1 || tokens[significant[at - 1]] != (Token{"identifier", "const"})) {
			continue
		}

		if depth != 0 {
			return nil, nil, "NESTED_TABLE"
		}

		pattern := []string{"=", "["}

		close := "]"

		if language != "ts" {
			pattern = []string{":=", "[", "236", "]", "string", "{"}

			close = "}"
		}

		if at + len(pattern) >= len(significant) {
			return nil, nil, "TABLE_DECLARATION"
		}

		for expected, j in pattern {
			if tokens[significant[at + 1 + j]].text != expected {
				return nil, nil, "TABLE_DECLARATION"
			}
		}

		start := at + len(pattern); cursor := start + 1

		for cursor < len(significant) && tokens[significant[cursor]].text != close {
			element := tokens[significant[cursor]]

			if language == "odin" && !strings.has_prefix(element.text, "\"") {
				return nil, nil, "ODIN_STRING_LITERAL_REQUIRED"
			}

			value, error := literal_string(element); if error != "" {
				return nil, nil, error
			}

			append(&values, value); cursor += 1
			if len(values) > TABLE_COUNT {
				return nil, nil, "TABLE_COUNT"
			}

			if cursor >= len(significant) {
				return nil, nil, "TABLE_END"
			}

			if tokens[significant[cursor]].text == close {
				break
			}

			if tokens[significant[cursor]].text != "," {
				return nil, nil, "TABLE_EXPRESSION"
			}

			cursor += 1
		}

		if cursor >= len(significant) || len(values) != TABLE_COUNT {
			return nil, nil, "TABLE_COUNT"
		}

		append(&outside, ..tokens[:significant[start]])
		append(&outside, Token{"table", "SINGLE_BYTE_TOKENS"})

		append(&outside, ..tokens[significant[cursor] + 1:]); found += 1
	}

	if found != 1 {
		return nil, nil, "TABLE_DECLARATION_COUNT"
	}

	return values[:], outside[:], ""
}

// owner_root is the directory holding a library owner file: the repository's
// src/ in the src/ layout, the root itself for a flat tree (synthetic fixtures).
owner_root :: proc(root, relative: string) -> string {
	direct := strings.concatenate({root, "/", relative}, context.temp_allocator)

	if os.exists(direct) {
		return root
	}

	return strings.concatenate({root, "/src"}, context.temp_allocator)
}

// Existing review records bind hashes to their original repository paths.
contract_directory :: proc(path: string) -> string {
	legacy :: "tools/protocol_watch/contracts/"
	return legacy if strings.has_prefix(path, legacy) else "tools/protocol_watcher/contracts/"
}

owned_bytes :: proc(root, relative, prefix, suffix: string) -> ([]u8, string) {
	if !path_valid(relative) ||
	   !strings.has_prefix(relative, prefix) ||
	   suffix != "" && !strings.has_suffix(relative, suffix) {
		return nil, "CONTRACT_PATH"
	}

	target := root

	for part in strings.split(relative, "/") {
		target = join(target, part)
		info, error := os.lstat(target, context.allocator)

		if error != nil {
			return nil, "CONTRACT_FILE"
		}

		if info.type == .Symlink {
			return nil, "CONTRACT_SYMLINK"
		}
	}

	data, error := read_file(target, 256 * 1024)

	if error != "" {
		return nil, "CONTRACT_FILE"
	}

	return data, ""
}

record_bound :: proc(root: string, record: Value, prefix, suffix: string) -> string {
	if !has_exact_object_fields(record, []string{"path", "sha256"}) || !hex_valid(str(get(record, "sha256")), 64) {
		return "CONTRACT_RECORD"
	}

	data, error := owned_bytes(root, str(get(record, "path")), prefix, suffix)

	if error != "" {
		return error
	}

	if sha256(data) != str(get(record, "sha256")) {
		return "CONTRACT_STALE"
	}

	return ""
}

value_strings :: proc(values: []string) -> Value {return string_array(values)}

finish_change_assessment :: proc(input: Value, kind, reason, summary: string) -> Value {
	result := input
	put(&result, "kind", text(kind)); put(&result, "reason", text(reason))
	put(&result, "summary", text(summary)); return result
}

approved_metadata :: proc(assessment: Value, root, path: string) -> (Value, string) {
	raw, error := owned_bytes(root, path, contract_directory(path), ".json")

	if error != "" {
		return null(), error
	}

	contract, parse_error := decode(raw); if parse_error != "" {
		return null(), parse_error
	}

	if !has_required_and_allowed_fields(
		contract,
		[]string{"schema", "source", "path", "target_table_sha256", "requirement"},
		[]string{"fixture"},
	) {
		return null(), "CONTRACT_BINDING"
	}

	schema, ok := integer(get(contract, "schema"))
	if !ok ||
	   schema != 1 ||
	   str(get(contract, "source")) != "baileys" ||
	   str(get(contract, "path")) != "src/WABinary/constants.ts" ||
	   str(get(assessment, "source")) != "baileys" ||
	   str(get(assessment, "path")) != "src/WABinary/constants.ts" {
		return null(), "CONTRACT_BINDING"
	}

	evidence := get(assessment, "evidence"); expected := str(get(contract, "target_table_sha256"))
	count, _ := integer(get(evidence, "table_count"))
	if !hex_valid(expected, 64) ||
	   expected != str(get(evidence, "target_table_sha256")) ||
	   expected == str(get(evidence, "reference_table_sha256")) ||
	   str(get(evidence, "static_regression")) != "indexed_table_comparison" ||
	   str(get(evidence, "local_table_sha256")) != str(get(evidence, "reference_table_sha256")) ||
	   str(get(evidence, "local_table_matches")) != "reference" ||
	   count != 236 ||
	   !json_boolean_equals(get(evidence, "outside_tokens_equal")) {
		return null(), "CONTRACT_COUNTEREXAMPLE"
	}

	indices := items(get(evidence, "changed_indices"))
	changed, _ := integer(get(evidence, "changed_count"))

	if len(indices) == 0 || i64(len(indices)) != changed {
		return null(), "CONTRACT_INDICES"
	}

	last: i64 = -1

	for index in indices {
		n, index_ok := integer(index); if !index_ok || n < 0 || n >= 236 || n <= last {
			return null(), "CONTRACT_INDICES"
		}

		last = n
	}

	owner, _ := owner_for("baileys", "src/WABinary/constants.ts")
	targets := items(get(assessment, "local_targets"))

	if len(targets) != len(owner.targets) {
		return null(), "CONTRACT_OWNERS"
	}

	for target, i in targets {
		owner_path := str(get(target, "path")); if owner_path != owner.targets[i] {
			return null(), "CONTRACT_OWNERS"
		}

		bytes, owner_error := owned_bytes(owner_root(root, owner_path), owner_path, "", ".odin"); if owner_error != "" {
			return null(), owner_error
		}

		if sha256(bytes) != str(get(target, "sha256")) {
			return null(), "CONTRACT_OWNER_STALE"
		}

		if owner_path == "binary_tokens.odin" {
			local, lex_error := lex(bytes, "odin"); if lex_error != "" {
				return null(), lex_error
			}

			values, _, table_error := extract_single_byte_token_table(local.tokens[:], "odin")
			if table_error != "" ||
			   sha256(transmute([]u8)encode(value_strings(values))) != str(get(evidence, "reference_table_sha256")) {
				return null(), "CONTRACT_LOCAL_TABLE"
			}
		}
	}

	requirement := get(contract, "requirement")
	error = record_bound(root, requirement, contract_directory(str(get(requirement, "path"))), ".md")

	if error != "" {
		return null(), error
	}

	result := object(
		{"path", text(path)},
		{"sha256", text(sha256(raw))},
		{"target_table_sha256", text(expected)},
		{"requirement", requirement},
		{"basis", text("explicit_reviewed_requirement_and_owned_indexed_comparison")},
		{
			"trust_limit",
			text(
				"Requirement review authority/independence is trusted local policy, not authenticated by this verifier.",
			),
		},
	)

	if fixture, has_fixture := get(contract, "fixture").(j.Object); has_fixture {
		error = record_bound(root, fixture, "tests/", ""); if error != "" {
			return null(), error
		}

		put(&result, "fixture", fixture)
	} else if object_contract, has_contract := contract.(j.Object); has_contract {
		if "fixture" in object_contract {
			return null(), "CONTRACT_RECORD"
		}
	}

	return result, ""
}

validate_approved_contract :: proc(assessment: Value, root: string) -> bool {
	schema, ok := integer(get(assessment, "schema"))
	if !ok ||
	   schema != 1 ||
	   str(get(assessment, "kind")) != "FIX" ||
	   str(get(assessment, "reason")) != "APPROVED_DICTIONARY_CONTRACT_GAP" {
		return false
	}

	actual := get(get(assessment, "evidence"), "approved_contract")
	expected, error := approved_metadata(assessment, root, str(get(actual, "path")))

	return error == "" && equal(actual, expected)
}

assess_upstream_file_change :: proc(
	source: Value,
	path: string,
	before, after: []u8,
	before_present, after_present: bool,
	root: string,
	approved_contract := "",
) -> Value {
	name := str(source)
	if _, ok := source.(j.Object); ok {
		name = str(get(source, "name"))
	}

	owner, bound := owner_for(name, path)
	if _, ok := source.(j.Object); ok {
		provided := str(get(source, "reference_commit"))
		bound =
			bound &&
			str(get(source, "repository")) == repository(name) &&
			(!slice.contains(keys(source), "reference_commit") || provided == reference_commit(name))
	}

	evidence := object(
		{"reference", digest(before, before_present)},
		{"current", digest(after, after_present)},
		{"server_compatibility_proven", boolean(false)},
	)
	result := object(
		{"schema", number(1)},
		{"kind", text("SPIKE")},
		{"reason", text("SOURCE_BINDING_UNKNOWN")},
		{"summary", text("The supplied source/path cannot be bound to a monitored local owner.")},
		{"source", text(name if bound else "unknown")},
		{"path", text(path if bound else "unknown")},
		{"local_targets", array()},
		{"checks", array()},
		{"acceptance", array()},
		{"evidence", evidence},
	)
	if !bound {
		put(&evidence, "question", text("Which allowlisted source and monitored path does this observation describe?"))
		return result
	}

	put(&evidence, "question", text(owner.question))
	put(&result, "checks", value_strings(owner.checks))
	put(
		&result,
		"acceptance",
		value_strings(
			[]string {
				owner.question,
				"Reproduce the changed contract in owned synthetic fixtures before editing Odin.",
				"Preserve durable completion, negative-ACK stop, original identities and no replay.",
				"Run focused native/ASan and recovery/consumer checks; no live-account compatibility claim.",
			},
		),
	)
	targets := make(j.Array)
	for owner_path in owner.targets {
		bytes, error := read_file(join(owner_root(root, owner_path), owner_path))

		if error != "" {
			put(&result, "local_targets", targets)
			return finish_change_assessment(
				result,
				"SPIKE",
				"LOCAL_OWNER_UNAVAILABLE",
				"The local Odin owner cannot be safely read and source-bound.",
			)
		}

		append(&targets, object({"path", text(owner_path)}, {"sha256", text(sha256(bytes))}))
	}

	put(&result, "local_targets", targets)
	if !before_present || !after_present || len(before) > MAX_BYTES || len(after) > MAX_BYTES {
		return finish_change_assessment(
			result,
			"SPIKE",
			"INPUT_UNAVAILABLE",
			"A missing, unsupported or oversized file prevents bounded comparison.",
		)
	}

	if string(before) == string(after) {
		return finish_change_assessment(
			result,
			"NO_ACTION",
			"BYTE_IDENTICAL",
			"The monitored file bytes are unchanged; compatibility is not inferred.",
		)
	}

	if strings.has_suffix(path, ".json") {
		a, ae := decode(before, MAX_BYTES); b, be := decode(after, MAX_BYTES)

		if ae != "" || be != "" {
			return finish_change_assessment(
				result,
				"SPIKE",
				"LEXICAL_PROOF_UNAVAILABLE",
				"JSON normalization failed; duplicate keys and unsupported values require investigation.",
			)
		}

		if equal(a, b) {
			return finish_change_assessment(
				result,
				"NO_ACTION",
				"JSON_NORMALIZED_EQUIVALENT",
				"Unique-key finite JSON values are unchanged after normalization.",
			)
		}

		return finish_change_assessment(
			result,
			"SPIKE",
			"BEHAVIOR_CHANGE_UNRESOLVED",
			"The advertised JSON value changed; qualify the specific local payload decision.",
		)
	}

	language := "ts" if strings.has_suffix(path, ".ts") else "go" if strings.has_suffix(path, ".go") else "proto"
	old, old_error := lex(before, language); next, next_error := lex(after, language)
	if old_error != "" || next_error != "" {
		return finish_change_assessment(
			result,
			"SPIKE",
			"LEXICAL_PROOF_UNAVAILABLE",
			"Syntax, slash or literal ambiguity prevents a safe lexical equivalence proof.",
		)
	}

	if !slice.equal(old.sensitive[:], next.sensitive[:]) {
		return finish_change_assessment(
			result,
			"SPIKE",
			"DIRECTIVE_OR_LICENSE_CHANGED",
			"A directive or license-bearing comment changed and must not be stripped as formatting.",
		)
	}

	if slice.equal(old.tokens[:], next.tokens[:]) {
		return finish_change_assessment(
			result,
			"NO_ACTION",
			"LEXICALLY_EQUIVALENT",
			"Exact tokens, newlines and literals are unchanged; only safely ignored formatting/comments differ.",
		)
	}

	if name != "baileys" || path != "src/WABinary/constants.ts" {
		return finish_change_assessment(
			result,
			"SPIKE",
			"BEHAVIOR_CHANGE_UNRESOLVED",
			"Tokens changed; resolve the named local contract question with a synthetic regression.",
		)
	}

	reference, outside_old, re := extract_single_byte_token_table(old.tokens[:], "ts")
	current, outside_new, ce := extract_single_byte_token_table(next.tokens[:], "ts")
	local_bytes, le := read_file(join(owner_root(root, "binary_tokens.odin"), "binary_tokens.odin"))
	local_lex, lxe := lex(local_bytes, "odin")
	local_values, _, lte := extract_single_byte_token_table(local_lex.tokens[:], "odin")
	if re != "" ||
	   ce != "" ||
	   le != "" ||
	   lxe != "" ||
	   lte != "" ||
	   sha256(local_bytes) != str(get(targets[0], "sha256")) {
		return finish_change_assessment(
			result,
			"SPIKE",
			"TABLE_PROOF_UNAVAILABLE",
			"Only one strict 236-string constant array per source and a bound local array can prove this edit.",
		)
	}

	if !slice.equal(outside_old, outside_new) {
		return finish_change_assessment(
			result,
			"SPIKE",
			"TABLE_OUTSIDE_CHANGE",
			"Tokens outside the dictionary changed; table drift alone cannot classify this observation.",
		)
	}

	if slice.equal(reference, current) {
		return finish_change_assessment(
			result,
			"NO_ACTION",
			"LEXICALLY_EQUIVALENT",
			"The strict table values and outside tokens are unchanged.",
		)
	}

	if slice.equal(local_values, current) {
		put(&evidence, "local_table_matches", text("current"))
		return finish_change_assessment(
			result,
			"NO_ACTION",
			"ALREADY_IMPLEMENTED",
			"The local 236-entry dictionary already matches the supplied current table.",
		)
	}

	if !slice.equal(local_values, reference) {
		return finish_change_assessment(
			result,
			"SPIKE",
			"LOCAL_BASELINE_UNKNOWN",
			"The local table matches neither supplied reference nor current; establish its source before a fix.",
		)
	}

	changes, indices := make(j.Array), make(j.Array)
	for value, i in reference {
		if value == current[i] {
			continue
		}

		append(&indices, number(i64(i)))

		if len(changes) < 32 {
			old_excerpt, new_excerpt := excerpt(value), excerpt(current[i])
			append(
				&changes,
				object(
					{"index", number(i64(i))},
					{"old", text(old_excerpt)},
					{"new", text(new_excerpt)},
					{"old_sha256", text(sha256(transmute([]u8)value))},
					{"new_sha256", text(sha256(transmute([]u8)current[i]))},
				),
			)
		}
	}

	put(&evidence, "static_regression", text("indexed_table_comparison"))
	put(&evidence, "reference_table_sha256", text(sha256(transmute([]u8)encode(value_strings(reference)))))
	put(&evidence, "target_table_sha256", text(sha256(transmute([]u8)encode(value_strings(current)))))
	put(&evidence, "local_table_sha256", text(sha256(transmute([]u8)encode(value_strings(local_values)))))
	put(&evidence, "table_count", number(TABLE_COUNT))
	put(&evidence, "outside_tokens_equal", boolean(true))
	put(&evidence, "local_table_matches", text("reference"))
	put(&evidence, "changed_count", number(i64(len(indices))))
	put(&evidence, "changed_indices", indices); put(&evidence, "changes", changes)
	put(&evidence, "changes_truncated", boolean(len(indices) > 32))
	plan := value_strings(
		[]string {
			"Implement every index in evidence.changed_indices (not only sampled excerpts) in binary_tokens.odin; preserve all 236 positions.",
			"Preserve the approved legacy/default-version behavior; do not blindly replace a pinned dictionary.",
			"Add per-changed-index encoder/decoder roundtrip and exact byte-index regression fixtures.",
			"Verify unchanged token indices, unknown-token behavior and binary framing with owned synthetic tests.",
			"Run focused native/ASan plus encrypted recovery/consumer checks without altering durable ACK/replay policy.",
			"A matching public dictionary is not server compatibility proof; keep that qualification explicitly separate.",
		},
	)
	put(&evidence, "proposed_fix_plan", plan)
	put(
		&result,
		"acceptance",
		value_strings(
			[]string {
				"Determine whether the pinned legacy/default-version contract intentionally requires the existing table.",
				"Obtain an independently reviewed requirement naming the exact target table hash, or record why no update is required.",
				"Only after that requirement demonstrates a local gap, execute the conditional proposed_fix_plan with owned regressions.",
			},
		),
	)
	if approved_contract == "" {
		return finish_change_assessment(
			result,
			"SPIKE",
			"LOCAL_DICTIONARY_CONTRACT_DRIFT",
			"Exact dictionary drift is relevant, but updateworthiness is unproven; obtain an independently reviewed target requirement before implementation.",
		)
	}

	approval, error := approved_metadata(result, root, approved_contract)
	if error != "" {
		return finish_change_assessment(
			result,
			"SPIKE",
			"APPROVED_CONTRACT_UNAVAILABLE",
			"The explicit reviewed target contract could not be bound to this static counterexample and current local owners.",
		)
	}

	put(&evidence, "approved_contract", approval); put(&result, "acceptance", plan)
	return finish_change_assessment(
		result,
		"FIX",
		"APPROVED_DICTIONARY_CONTRACT_GAP",
		"An explicit reviewed requirement names this exact target table; the owned indexed comparison demonstrates a local contract gap, not server compatibility.",
	)
}

excerpt :: proc(value: string) -> string {
	out: strings.Builder; n := 0

	for c in value {
		if n == 128 {
			break
		}

		strings.write_rune(&out, c if c >= 32 && c < 127 else '?'); n += 1
	}

	return strings.to_string(out)
}

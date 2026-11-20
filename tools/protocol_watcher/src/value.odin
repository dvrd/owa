package protocol_watch

import "core:unicode/utf16"
import "core:crypto/hash"
import "core:encoding/hex"
import j "core:encoding/json"
import "core:fmt"
import "core:math"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"

ASCII_LETTERS :: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
DECIMAL_DIGITS :: "0123456789"
LOWER_HEX_DIGITS :: DECIMAL_DIGITS + "abcdef"

MAX_BYTES :: 4 * 1024 * 1024
MAX_REPORT :: 256 * 1024
MAX_TOKENS :: 100000
PROJECT :: "b16b3039-a8cd-4080-adc2-d032669d0365"
TEAM :: "f8cf5dbc-16dd-445e-ba0c-b3950e31f13b"
BACKLOG :: "dd80a97e-0581-4d76-b659-83b1ec927019"
READY :: "d47c0045-e2ba-4bd5-a22b-d047f9cbb6a6"
BEGIN :: "owa-protocol-review:v2:begin"
END :: "owa-protocol-review:v2:end"
SCOPE_PREFIX :: "owa-protocol-review-scope:v1:"
Value :: j.Value
Pair :: struct {
	key:   string,
	value: Value,
}

text :: proc(s: string) -> Value {
	return j.String(s)
}
number :: proc(n: i64) -> Value {
	return j.Integer(n)
}
boolean :: proc(b: bool) -> Value {
	return j.Boolean(b)
}
null :: proc() -> Value {
	return j.Null(nil)
}
object :: proc(pairs: ..Pair) -> Value {
	result := make(j.Object, 64)

	for pair in pairs {
		result[pair.key] = pair.value
	}

	return result
}
array :: proc(values: ..Value) -> Value {
	result := make(j.Array)
	append(&result, ..values)
	return result
}
string_array :: proc(values: []string) -> Value {
	result := make(j.Array)

	for value in values {
		append(&result, text(value))
	}

	return result
}
get :: proc(value: Value, key: string) -> Value {
	if obj, ok := value.(j.Object); ok {
		if found, present := obj[key]; present {
			return found
		}
	}

	return null()
}
put :: proc(value: ^Value, key: string, next: Value) {
	if obj, ok := value^.(j.Object); ok {
		obj[key] = next
		value^ = obj
	}
}
str :: proc(value: Value) -> string {
	if s, ok := value.(j.String); ok {
		return string(s)
	}; return ""
}
integer :: proc(value: Value) -> (i64, bool) {
	if n, ok := value.(j.Integer); ok {
		return i64(n), true
	}; return 0, false
}
json_boolean_equals :: proc(value: Value, expected := true) -> bool {
	if b, ok := value.(j.Boolean); ok {
		return bool(b) == expected
	}; return false
}
items :: proc(value: Value) -> j.Array {
	if a, ok := value.(j.Array); ok {
		return a
	}; return nil
}
keys :: proc(value: Value) -> []string {
	obj, ok := value.(j.Object)
	if !ok {
		return nil
	}
	// Callers can hold an older copy of a JSON object while adding fields.
	// Collect the keys visited by the iterator, which can exceed the length in that copy.
	result := make([dynamic]string, 0, len(obj))
	for key in obj {
		append(&result, key)
	}
	slice.sort(result[:])
	return result[:]
}
has_exact_object_fields :: proc(value: Value, wanted: []string) -> bool {
	actual := keys(value)

	if len(actual) != len(wanted) {
		return false
	}

	for key in wanted {
		if !slice.contains(actual, key) {
			return false
		}
	}

	return true
}
hex_valid :: proc(s: string, n: int) -> bool {
	if len(s) != n {
		return false
	}

	return strings.trim_left(s, LOWER_HEX_DIGITS) == ""
}
path_valid :: proc(path: string) -> bool {
	if len(path) == 0 || len(path) > 200 {
		return false
	}

	for part in strings.split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}

		if strings.trim_left(part, ASCII_LETTERS + DECIMAL_DIGITS + "_.-") != "" {
			return false
		}
	}

	return true
}
sha256 :: proc(data: []u8) -> string {
	digest: [32]u8
	hash.hash_bytes_to_buffer(.SHA256, data, digest[:])
	return string(hex.encode(digest[:]))
}
digest :: proc(data: []u8, present: bool) -> Value {
	return object(
		{"present", boolean(present)},
		{"bytes", number(i64(len(data)))},
		{"sha256", text(sha256(data)) if present && len(data) <= MAX_BYTES else null()},
	)
}
quote :: proc(builder: ^strings.Builder, s: string) {
	strings.write_byte(builder, '"')

	for c in s {
		switch c {
		case '"':
			strings.write_string(builder, `\"`)
		case '\\':
			strings.write_string(builder, `\\`)
		case '\n':
			strings.write_string(builder, `\n`)
		case '\r':
			strings.write_string(builder, `\r`)
		case '\t':
			strings.write_string(builder, `\t`)
		case '\b':
			strings.write_string(builder, `\b`)
		case '\f':
			strings.write_string(builder, `\f`)
		case:
			if c < 32 || c > 126 {
				if c <= 0xffff {
					fmt.sbprintf(builder, "\\u%04x", u32(c))
				} else {
					high, low := utf16.encode_surrogate_pair(c)
					fmt.sbprintf(builder, "\\u%04x\\u%04x", u32(high), u32(low))
				}
			} else {
				strings.write_rune(builder, c)
			}
		}
	}

	strings.write_byte(builder, '"')
}
encode_value :: proc(builder: ^strings.Builder, value: Value, spaced: bool, depth: int) -> bool {
	if depth > 64 {
		return false
	}

	comma := ", " if spaced else ","
	colon := ": " if spaced else ":"

	switch v in value {
	case j.Null:
		strings.write_string(builder, "null")
	case j.String:
		quote(builder, string(v))
	case j.Boolean:
		strings.write_string(builder, "true" if bool(v) else "false")
	case j.Integer:
		fmt.sbprintf(builder, "%d", i64(v))
	case j.Float:
		if math.is_nan(f64(v)) || math.is_inf(f64(v)) {
			return false
		}; fmt.sbprintf(builder, "%v", f64(v))
	case j.Array:
		strings.write_byte(builder, '[')

		for item, i in v {
			if i > 0 {
				strings.write_string(builder, comma)
			}; if !encode_value(builder, item, spaced, depth + 1) {
				return false
			}
		}

		strings.write_byte(builder, ']')
	case j.Object:
		strings.write_byte(builder, '{')

		for key, i in keys(value) {
			if i > 0 {
				strings.write_string(builder, comma)
			}; quote(builder, key); strings.write_string(builder, colon)
			if !encode_value(builder, v[key], spaced, depth + 1) {
				return false
			}
		}

		strings.write_byte(builder, '}')
	case:
		return false
	}

	return true
}
encode :: proc(value: Value, spaced := false) -> string {
	builder: strings.Builder

	if !encode_value(&builder, value, spaced, 0) {
		return ""
	}

	return strings.to_string(builder)
}
equal :: proc(a, b: Value) -> bool {
	return encode(a) == encode(b)
}
decode :: proc(data: []u8, maximum := MAX_REPORT) -> (Value, string) {
	if len(data) > maximum || !utf8.valid_string(string(data)) || !j.is_valid(data, .JSON, true) {
		return null(), "JSON_INVALID"
	}

	tokenizer := j.make_tokenizer(string(data), .JSON, true)
	previous: j.Token_Kind
	depth, count := 0, 0
	all := make([dynamic]j.Token)

	for {
		token, error := j.get_token(&tokenizer)

		if token.kind == .EOF && (error == .None || error == .EOF) {
			break
		}

		if error != .None {
			return null(), "JSON_INVALID"
		}

		count += 1

		if count > MAX_TOKENS {
			return null(), "JSON_INVALID"
		}

		if token.kind == .Open_Brace || token.kind == .Open_Bracket {
			depth += 1

			if depth > 64 {
				return null(), "JSON_INVALID"
			}
		}

		if token.kind == .Close_Brace || token.kind == .Close_Bracket {
			if previous == .Comma {
				return null(), "JSON_INVALID"
			}; depth -= 1
		}

		previous = token.kind
		append(&all, token)
	}

	index := 0
	value, ok := parse_tokens(all[:], &index, 0)

	if !ok || index != len(all) {
		return null(), "JSON_INVALID"
	}

	return value, ""
}
read_file :: proc(path: string, maximum := MAX_BYTES) -> ([]u8, string) {
	info, error := os.lstat(path, context.allocator)

	if error != nil || info.type != .Regular || info.size > i64(maximum) {
		return nil, "LOCAL_FILE_INVALID"
	}

	file, open_error := os.open(path, {.Read, .Non_Blocking})

	if open_error != nil {
		return nil, "LOCAL_FILE_INVALID"
	}; defer os.close(file)
	data := make([]u8, int(info.size) + 1)
	used := 0

	for used < len(data) {
		n, e := os.read(file, data[used:])
		used += n

		if n == 0 {
			break
		}; if e != nil {
			return nil, "LOCAL_FILE_INVALID"
		}
	}

	if used > maximum || used != int(info.size) {
		return nil, "LOCAL_FILE_INVALID"
	}

	return data[:used], ""
}
replace :: proc(s, from, to: string) -> string {
	value, _ := strings.replace_all(s, from, to)

	return value
}
has_required_and_allowed_fields :: proc(value: Value, required, optional: []string) -> bool {
	if _, ok := value.(j.Object); !ok {
		return false
	}

	actual := keys(value)

	for key in required {
		if !slice.contains(actual, key) {
			return false
		}
	}

	for key in actual {
		if !slice.contains(required, key) && !slice.contains(optional, key) {
			return false
		}
	}

	return true
}

join :: proc(a, b: string) -> string {
	return fmt.aprintf("%s/%s", strings.trim_suffix(a, "/"), b)
}
Failure :: union {
	string,
}
text_limit :: proc(value: Value, minimum, maximum: int) -> bool {
	s, ok := value.(j.String)

	if !ok {
		return false
	}

	length := utf8.rune_count_in_string(string(s))

	return length >= minimum && length <= maximum
}
is_project_actions_run_url :: proc(run: string) -> bool {
	prefix := "https://github.com/dvrd/owa/actions/runs/"

	if !strings.has_prefix(run, prefix) || len(run) == len(prefix) {
		return false
	}

	return strings.trim_left(run[len(prefix):], DECIMAL_DIGITS) == ""
}
stable_uuid :: proc(seed: string) -> string {
	bytes := (transmute([]u8)sha256(transmute([]u8)seed))[:32]
	bytes[12] = '4'
	variant, _ := strconv.parse_u64(string(bytes[16:17]), 16)
	alphabet: string = "0123456789abcdef"
	bytes[16] = alphabet[(variant & 3) | 8]

	return fmt.aprintf(
		"%s-%s-%s-%s-%s",
		string(bytes[:8]),
		string(bytes[8:12]),
		string(bytes[12:16]),
		string(bytes[16:20]),
		string(bytes[20:]),
	)
}
stable_id :: proc(namespace: string, values: Value) -> string {
	return stable_uuid(fmt.aprintf("%s/%s/%s", PROJECT, namespace, encode(values)))
}
change_identity :: proc(repo, path: string, reference, current: Value) -> string {
	value := array(
		text(repo),
		text(path),
		get(reference, "present"),
		get(reference, "sha256"),
		get(current, "present"),
		get(current, "sha256"),
	)

	return sha256(transmute([]u8)encode(value))
}

coverage_object :: proc() -> Value {
	return make(j.Object, MAX_REPORT / 64)
}
parse_tokens :: proc(tokens: []j.Token, index: ^int, depth: int) -> (Value, bool) {
	if depth > 64 || index^ >= len(tokens) {
		return null(), false
	}

	token := tokens[index^]
	index^ += 1
	#partial switch token.kind {
	case .Null:
		return null(), true
	case .True:
		return boolean(true), true
	case .False:
		return boolean(false), true
	case .Integer:
		n, ok := strconv.parse_i64(token.text)
		return number(n), ok
	case .Float:
		n, ok := strconv.parse_f64(token.text)
		return j.Float(n), ok && !math.is_nan(n) && !math.is_inf(n)
	case .String:
		value, error := j.parse(token.text, .JSON, true)
		return value, error == .None
	case .Open_Bracket:
		values := make(j.Array)
		for index^ < len(tokens) && tokens[index^].kind != .Close_Bracket {
			value, ok := parse_tokens(tokens, index, depth + 1)

			if !ok {
				return null(), false
			}; append(&values, value)
			if index^ < len(tokens) && tokens[index^].kind == .Comma {
				index^ += 1
			} else {
				break
			}
		}
		if index^ >= len(tokens) || tokens[index^].kind != .Close_Bracket {
			return null(), false
		}; index^ += 1; return values, true
	case .Open_Brace:
		values := make(j.Object, 64)
		for index^ < len(tokens) && tokens[index^].kind != .Close_Brace {
			if tokens[index^].kind != .String {
				return null(), false
			}

			key, key_ok := parse_tokens(tokens, index, depth + 1)

			if !key_ok {
				return null(), false
			}

			if index^ >= len(tokens) || tokens[index^].kind != .Colon {
				return null(), false
			}; index^ += 1
			value, ok := parse_tokens(tokens, index, depth + 1)

			if !ok {
				return null(), false
			}

			name := str(key)

			if name in values {
				return null(), false
			}; values[name] = value
			if index^ < len(tokens) && tokens[index^].kind == .Comma {
				index^ += 1
			} else {
				break
			}
		}
		if index^ >= len(tokens) || tokens[index^].kind != .Close_Brace {
			return null(), false
		}; index^ += 1; return values, true
	case:
		return null(), false
	}
}
unicode_prefix :: proc(s: string, count: int) -> string {
	end := utf8.rune_offset(s, count)
	return s[:end] if end >= 0 else s
}

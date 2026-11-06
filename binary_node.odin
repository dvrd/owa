package whatsapp

import ascii "../ascii"

import "core:bytes"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:sort"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"
import zlib "vendor:zlib"

MAX_BINARY_NODE_PAYLOAD :: 1 << 20
MAX_BINARY_NODE_DEPTH :: 64
MAX_BINARY_NODE_COUNT :: 4096
MAX_BINARY_NODE_ATTRIBUTES :: 16384
MAX_BINARY_DOCUMENT_STORAGE :: 8 << 20

Binary_Node_Attribute :: struct {
	key, value: string,
}
Binary_Node_Content :: union {
	[]u8,
	[]Binary_Node,
}
Binary_Node :: struct {
	tag:     string,
	attrs:   []Binary_Node_Attribute,
	content: Binary_Node_Content,
}

Binary_Node_Error_Kind :: enum {
	None,
	Invalid_Limit,
	Payload_Oversized,
	Destination_Undersized,
	Overlapping_Buffers,
	Allocation_Failed,
	Document_Storage_Exhausted,
	Truncated,
	Unsupported_Flags,
	Decompression_Failed,
	Decompressed_Payload_Oversized,
	Compressed_Trailing_Data,
	Trailing_Data,
	Invalid_List,
	Invalid_Node,
	Depth_Limit,
	Node_Limit,
	Attribute_Limit,
	Duplicate_Attribute,
	Invalid_UTF8,
	Invalid_Token,
	Unsupported_Token,
	Invalid_Packed_String,
	Invalid_JID,
}

Binary_Node_Error :: struct {
	kind:        Binary_Node_Error_Kind,
	offset:      int,
	token:       u8,
	zlib_status: i32,
	allocation:  mem.Allocator_Error,
}

// All returned slices and generated strings borrow this document. Destroy
// exactly once; do not independently free attributes/children/content. The
// input is cloned, so the caller can reuse its receive buffer after decoding.
Binary_Document :: struct {
	root:            Binary_Node,
	data:            []u8,
	data_allocation: []u8,
	storage:         []u8,
	allocator:       mem.Allocator,
}

binary_document_destroy :: proc(document: ^Binary_Document) {
	if document == nil do return

	if document.allocator.procedure != nil {
		delete(document.storage, document.allocator)
		delete(document.data_allocation, document.allocator)
	}

	document^ = {}
}

// Canonical uncompressed encoding matching Baileys 6.7.23's dictionary,
// nibble/hex, JID, attribute order, and content list decisions. Validation and
// sizing happen before touching dst. dst must not alias node strings/content.
// Optional max_payload remains <=24 bits.
binary_node_encode :: proc(
	dst: []u8,
	node: Binary_Node,
	max_payload: int = MAX_BINARY_NODE_PAYLOAD,
) -> (
	n: int,
	err: Binary_Node_Error,
) {
	if max_payload < 1 || max_payload > MAX_FRAME_PAYLOAD {
		return 0, {kind = .Invalid_Limit}
	}

	measure := Binary_Writer {
		limit  = max_payload,
		target = dst,
	}
	binary_write_byte(&measure, 0)
	binary_write_node(&measure, node, 0)
	if measure.err.kind != .None do return 0, measure.err

	if len(dst) < measure.used {
		return measure.used, {kind = .Destination_Undersized}
	}

	writer := Binary_Writer {
		dst   = dst,
		limit = max_payload,
	}
	binary_write_byte(&writer, 0)
	binary_write_node(&writer, node, 0)
	return writer.used, writer.err
}

// Supports the pinned codec's uncompressed flag0 and zlib flag2. Native libz
// (vendor:zlib) inflates into a fixed bounded output; bombs cannot grow it.
// FB_JID/INTEROP_JID are constants in 6.7.23 but its decoder has no branches
// for them; these tags return Unsupported_Token rather than guessing a format.
binary_node_decode :: proc(
	src: []u8,
	allocator := context.allocator,
	max_payload: int = MAX_BINARY_NODE_PAYLOAD,
) -> (
	document: Binary_Document,
	err: Binary_Node_Error,
) {
	if max_payload < 1 || max_payload > MAX_FRAME_PAYLOAD {
		return {}, {kind = .Invalid_Limit}
	}

	if len(src) > max_payload {
		return {}, {kind = .Payload_Oversized}
	}

	if len(src) < 1 do return {}, {kind = .Truncated}

	if !slice.contains([]type_of(src[0]){0, 2}, src[0]) {
		return {}, {kind = .Unsupported_Flags}
	}

	document.allocator = allocator
	if payload_error := binary_document_payload_copy(&document, src, allocator, max_payload);
	   payload_error.kind != .None do return {}, payload_error
	if tree_error := binary_document_tree_decode(&document, allocator); tree_error.kind != .None {
		binary_document_destroy(&document)
		return {}, tree_error
	}
	return document, {}
}

binary_document_decompress :: proc(
	document: ^Binary_Document, src: []u8, allocator: mem.Allocator, max_payload: int,
) -> Binary_Node_Error {
	data, allocation_err := make(
		[]u8,
		max_payload + 1,
		allocator,
	)
	if allocation_err != nil {
		return {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
	}

	output_size := zlib.uLongf(len(data))
	input_size := zlib.uLong(len(src) - 1)
	status := zlib.uncompress2(
		raw_data(data),
		&output_size,
		raw_data(src[1:]),
		&input_size,
	)
	if output_size > zlib.uLongf(max_payload) {
		delete(data, allocator)
		return {
			kind = .Decompressed_Payload_Oversized,
			zlib_status = status,
		}
	}

	if status != zlib.OK {
		delete(data, allocator)
		return {
			kind = .Decompression_Failed,
			zlib_status = status,
		}
	}

	if input_size != zlib.uLong(len(src) - 1) {
		delete(data, allocator)
		return {kind = .Compressed_Trailing_Data}
	}

	document.data = data[:cast(int)output_size]
	document.data_allocation = data
	return {}
}

binary_document_payload_copy :: proc(
	document: ^Binary_Document, src: []u8, allocator: mem.Allocator, max_payload: int,
) -> Binary_Node_Error {
	if src[0] == 2 {
		return binary_document_decompress(document, src, allocator, max_payload)
	} else {
		data, allocation_err := make([]u8, len(src) - 1, allocator)
		if allocation_err != nil {
			return {
				kind = .Allocation_Failed,
				allocation = allocation_err,
			}
		}

		copy(data, src[1:])
		document.data = data
		document.data_allocation = data
	}

	return {}
}

binary_document_tree_decode :: proc(
	document: ^Binary_Document, allocator: mem.Allocator,
) -> Binary_Node_Error {
	// Metadata/string expansion is bounded separately from the wire length.
	// The arena is needed only during decoding; returned nodes hold plain
	// slices, never an allocator pointing at this stack-local arena value.
	storage_size := min(
		MAX_BINARY_DOCUMENT_STORAGE,
		max(4096, len(document.data) * 32),
	)
	storage, allocation_err := make([]u8, storage_size, allocator)
	if allocation_err != nil {
		return {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
	}

	document.storage = storage
	arena: mem.Arena
	mem.arena_init(&arena, storage)
	reader := Binary_Reader {
		src       = document.data,
		allocator = mem.arena_allocator(&arena),
	}
	document.root = binary_read_node(&reader, 0)
	if reader.err.kind == .None && reader.at != len(reader.src) {
		reader.err = {
			kind   = .Trailing_Data,
			offset = reader.at,
		}
	}

	if reader.err.kind != .None {
		return reader.err
	}

	return {}
}

node_attr :: proc(
	node: Binary_Node,
	key: string,
) -> (
	value: string,
	found: bool,
) {
	for attr in node.attrs {
		if attr.key == key do return attr.value, true

	}
	return "", false
}

node_child :: proc(node: Binary_Node, tag: string) -> ^Binary_Node {
	#partial switch children in node.content {
	case []Binary_Node:
		for &child in children {
			if child.tag == tag do return &child

		}
	}
	return nil
}

Binary_Writer :: struct {
	dst:                       []u8,
	target:                    []u8,
	used, limit, nodes, attrs: int,
	err:                       Binary_Node_Error,
}

binary_write_byte :: proc(writer: ^Binary_Writer, value: u8) {
	if writer.err.kind != .None do return

	if writer.used >= writer.limit {
		writer.err = {
			kind = .Payload_Oversized,
		}
		return
	}

	if writer.dst != nil do writer.dst[writer.used] = value

	writer.used += 1
}

binary_write_bytes :: proc(writer: ^Binary_Writer, data: []u8) {
	if writer.err.kind != .None do return

	if bytes.alias(writer.target, data) {
		writer.err = {
			kind = .Overlapping_Buffers,
		}
		return
	}

	if len(data) > writer.limit - writer.used {
		writer.err = {
			kind = .Payload_Oversized,
		}
		return
	}

	if writer.dst != nil {
		copy(writer.dst[writer.used:], data)
	}

	writer.used += len(data)
}

binary_write_integer :: proc(
	writer: ^Binary_Writer,
	value: u32,
	bytes: int,
) {
	for i := bytes - 1; i >= 0; i -= 1 {
		binary_write_byte(writer, cast(u8)(value >> cast(uint)(i * 8)))
	}
}

binary_write_list :: proc(writer: ^Binary_Writer, size: int) {
	if size == 0 {
		binary_write_byte(writer, cast(u8)Binary_Tag.LIST_EMPTY)
	} else if size < 256 {
		binary_write_byte(writer, cast(u8)Binary_Tag.LIST_8)
		binary_write_byte(writer, cast(u8)size)
	} else if size <= 65535 {
		binary_write_byte(writer, cast(u8)Binary_Tag.LIST_16)
		binary_write_integer(writer, cast(u32)size, 2)
	} else {
		writer.err = {
			kind = .Invalid_List,
		}
	}

}

binary_write_length :: proc(writer: ^Binary_Writer, size: int) {
	if size < 256 {
		binary_write_byte(writer, cast(u8)Binary_Tag.BINARY_8)
		binary_write_byte(writer, cast(u8)size)
	} else if size < 1 << 20 {
		binary_write_byte(writer, cast(u8)Binary_Tag.BINARY_20)
		binary_write_integer(writer, cast(u32)size, 3)
	} else {
		binary_write_byte(writer, cast(u8)Binary_Tag.BINARY_32)
		binary_write_integer(writer, cast(u32)size, 4)
	}

}

binary_write_node :: proc(
	writer: ^Binary_Writer,
	node: Binary_Node,
	depth: int,
) {
	if !binary_write_node_validate(writer, node, depth) do return

	has_content := node.content != nil
	list_size := 1 + 2 * len(node.attrs)
	if has_content do list_size += 1

	binary_write_list(writer, list_size)
	binary_write_string(writer, node.tag, 0)
	for attr in node.attrs {
		binary_write_string(writer, attr.key, 0)
		binary_write_string(writer, attr.value, 0)
	}
	switch content in node.content {
	case []u8:
		binary_write_length(writer, len(content))
		binary_write_bytes(writer, content)
	case []Binary_Node:
		if len(content) > MAX_BINARY_NODE_COUNT - writer.nodes {
			writer.err = {
				kind = .Node_Limit,
			}
			return
		}

		binary_write_list(writer, len(content))
		for child in content do binary_write_node(writer, child, depth + 1)
	}
}

binary_write_node_validate :: proc(
	writer: ^Binary_Writer, node: Binary_Node, depth: int,
) -> bool {
	if writer.err.kind != .None do return false

	if depth >= MAX_BINARY_NODE_DEPTH {
		writer.err = {
			kind = .Depth_Limit,
		}
		return false
	}

	writer.nodes += 1
	writer.attrs += len(node.attrs)
	if writer.nodes > MAX_BINARY_NODE_COUNT {
		writer.err = {
			kind = .Node_Limit,
		}
		return false
	}

	if writer.attrs > MAX_BINARY_NODE_ATTRIBUTES {
		writer.err = {
			kind = .Attribute_Limit,
		}
		return false
	}

	if len(node.tag) == 0 {
		writer.err = {
			kind = .Invalid_Node,
		}
		return false
	}

	for attr, i in node.attrs {
		for j in 0 ..< i {
			if node.attrs[j].key == attr.key {
				writer.err = {
					kind = .Duplicate_Attribute,
				}
				return false
			}

		}
	}
	return true
}

binary_write_string :: proc(
	writer: ^Binary_Writer,
	value: string,
	depth: int,
) {
	if writer.err.kind != .None do return

	if bytes.alias(writer.target, transmute([]u8)value) {
		writer.err = {
			kind = .Overlapping_Buffers,
		}
		return
	}

	if depth >= MAX_BINARY_NODE_DEPTH {
		writer.err = {
			kind = .Depth_Limit,
		}
		return
	}

	if !utf8.valid_string(value) {
		writer.err = {
			kind = .Invalid_UTF8,
		}
		return
	}

	if binary_write_token(writer, value) do return
	if binary_write_packed_string(writer, value) do return
	if at := strings.index_byte(value, '@'); at >= 0 {
		binary_write_jid(writer, value, at, depth)
		return
	}

	binary_write_length(writer, len(value))
	binary_write_bytes(writer, transmute([]u8)value)
}

binary_write_token :: proc(writer: ^Binary_Writer, value: string) -> bool {
	// TOKEN_MAP in Baileys is last-write-wins: doubles override singles and
	// later duplicate dictionary slots override earlier ones.
	for dictionary := 3; dictionary >= 0; dictionary -= 1 {
		for index := 255; index >= 0; index -= 1 {
			if DOUBLE_BYTE_TOKENS[dictionary][index] == value {
				binary_write_byte(
					writer,
					cast(u8)Binary_Tag.DICTIONARY_0 +
					cast(u8)dictionary,
				)
				binary_write_byte(writer, cast(u8)index)
				return true
			}

		}
	}
	for index := len(SINGLE_BYTE_TOKENS) - 1;
	    index >= 0;
	    index -= 1 {
		if SINGLE_BYTE_TOKENS[index] == value {
			binary_write_byte(writer, cast(u8)index)
			return true
		}

	}
	return false
}

binary_write_packed_string :: proc(writer: ^Binary_Writer, value: string) -> bool {
	packed_type: Binary_Tag
	if len(value) > 0 && len(value) <= BINARY_PACKED_MAX {
		nibble, hex := true, true
		for c in value {
			if !(ascii.is_digit(c) ||
				   slice.contains([]type_of(c){'-', '.'}, c)) {
				nibble = false
			}

			if !(ascii.is_digit(c) || c >= 'A' && c <= 'F') {
				hex = false
			}

		}
		if nibble do packed_type = .NIBBLE_8

		if !nibble && hex do packed_type = .HEX_8

	}

	if packed_type != .LIST_EMPTY {
		binary_write_byte(writer, cast(u8)packed_type)
		length := cast(u8)((len(value) + 1) / 2)
		if len(value) % 2 != 0 do length |= 128

		binary_write_byte(writer, length)
		for i := 0; i < len(value); i += 2 {
			high := binary_pack_char(value[i])
			low := cast(u8)15
			if i + 1 < len(value) {
				low = binary_pack_char(value[i + 1])
			}

			binary_write_byte(writer, high << 4 | low)
		}
		return true
	}

	return false
}

binary_write_jid :: proc(writer: ^Binary_Writer, value: string, at, depth: int) {
	user, server := value[:at], value[at + 1:]
	device_present := false
	device: u8
	if colon := strings.index_byte(user, ':'); colon >= 0 {
		device_text := user[colon + 1:]
		if extra := strings.index_byte(device_text, ':');
		   extra >= 0 {
			device_text = device_text[:extra]
		}

		if len(device_text) != 0 {
			parsed, valid := strconv.parse_uint(device_text, 10)
			if !valid || parsed > 255 {
				writer.err = {
					kind = .Invalid_JID,
				}
				return
			}

			device, device_present = cast(u8)parsed, true
		}

		user = user[:colon]
	}

	if underscore := strings.index_byte(user, '_');
	   underscore >= 0 {
		user = user[:underscore]
	}

	if device_present {
		binary_write_byte(writer, cast(u8)Binary_Tag.AD_JID)
		domain := cast(u8)0
		if server == "lid" do domain = 1

		binary_write_byte(writer, domain)
		binary_write_byte(writer, device)
		binary_write_string(writer, user, depth + 1)
	} else {
		binary_write_byte(writer, cast(u8)Binary_Tag.JID_PAIR)
		binary_write_string(writer, user, depth + 1)
		binary_write_string(writer, server, depth + 1)
	}

	return
}

binary_pack_char :: proc(c: u8) -> u8 {
	if ascii.is_digit(c) do return c - '0'

	if c == '-' do return 10

	if c == '.' do return 11

	return c - 'A' + 10
}

Binary_Reader :: struct {
	src:              []u8,
	at, nodes, attrs: int,
	allocator:        mem.Allocator,
	err:              Binary_Node_Error,
}

binary_read_bytes :: proc(
	reader: ^Binary_Reader,
	size: int,
) -> []u8 {
	if reader.err.kind != .None do return nil

	if size < 0 || size > len(reader.src) - reader.at {
		reader.err = {
			kind   = .Truncated,
			offset = reader.at,
		}
		return nil
	}

	data := reader.src[reader.at:][:size]
	reader.at += size
	return data
}

binary_read_byte :: proc(reader: ^Binary_Reader) -> u8 {
	data := binary_read_bytes(reader, 1)
	if reader.err.kind != .None do return 0

	return data[0]
}

binary_read_integer :: proc(
	reader: ^Binary_Reader,
	count: int,
) -> u32 {
	data := binary_read_bytes(reader, count)
	value: u32
	for b in data do value = value << 8 | cast(u32)b
	return value
}

binary_read_length :: proc(reader: ^Binary_Reader, tag: u8) -> int {
	#partial switch cast(Binary_Tag)tag {
	case .BINARY_8:
		return cast(int)binary_read_byte(reader)
	case .BINARY_20:
		return cast(int)(binary_read_integer(reader, 3) & 0xfffff)
	case .BINARY_32:
		return cast(int)binary_read_integer(reader, 4)
	case:
		reader.err = {
			kind   = .Invalid_Token,
			offset = reader.at,
			token  = tag,
		}
	}
	return 0
}

binary_read_list_size :: proc(
	reader: ^Binary_Reader,
	tag: u8,
) -> int {
	#partial switch cast(Binary_Tag)tag {
	case .LIST_EMPTY:
		return 0
	case .LIST_8:
		return cast(int)binary_read_byte(reader)
	case .LIST_16:
		return cast(int)binary_read_integer(reader, 2)
	case:
		reader.err = {
			kind   = .Invalid_List,
			offset = reader.at,
			token  = tag,
		}
	}
	return 0
}

binary_read_node :: proc(
	reader: ^Binary_Reader,
	depth: int,
) -> (
	node: Binary_Node,
) {
	if reader.err.kind != .None do return

	if depth >= MAX_BINARY_NODE_DEPTH {
		reader.err = {
			kind   = .Depth_Limit,
			offset = reader.at,
		}
		return
	}

	reader.nodes += 1
	if reader.nodes > MAX_BINARY_NODE_COUNT {
		reader.err = {
			kind   = .Node_Limit,
			offset = reader.at,
		}
		return
	}

	size := binary_read_list_size(reader, binary_read_byte(reader))
	if reader.err.kind != .None do return

	if size < 1 {
		reader.err = {
			kind   = .Invalid_Node,
			offset = reader.at,
		}
		return
	}

	node.tag = binary_read_string(
		reader,
		binary_read_byte(reader),
		0,
	)
	if reader.err.kind != .None do return

	if len(node.tag) == 0 {
		reader.err = {
			kind   = .Invalid_Node,
			offset = reader.at,
		}
		return
	}

	binary_read_attributes(reader, &node, size)
	if reader.err.kind != .None do return
	if size % 2 == 0 do binary_read_content(reader, &node, depth)
	return
}

binary_read_attribute_keys_validate :: proc(
	reader: ^Binary_Reader, node: ^Binary_Node, attrs: int,
) {
	if attrs > 1 {
		keys, keys_err := make([]string, attrs, reader.allocator)
		if keys_err != nil {
			reader.err = {
				kind       = .Document_Storage_Exhausted,
				offset     = reader.at,
				allocation = keys_err,
			}
			return
		}

		for attr, i in node.attrs do keys[i] = attr.key
		sort.quick_sort(keys)
		for i in 1 ..< len(keys) {
			if keys[i] == keys[i - 1] {
				reader.err = {
					kind   = .Duplicate_Attribute,
					offset = reader.at,
				}
				return
			}

		}
	}

}

binary_read_attributes :: proc(reader: ^Binary_Reader, node: ^Binary_Node, size: int) {
	attrs := (size - 1) / 2
	if attrs > MAX_BINARY_NODE_ATTRIBUTES - reader.attrs {
		reader.err = {
			kind   = .Attribute_Limit,
			offset = reader.at,
		}
		return
	}

	reader.attrs += attrs
	attributes, allocation_err := make(
		[]Binary_Node_Attribute,
		attrs,
		reader.allocator,
	)
	if allocation_err != nil {
		reader.err = {
			kind       = .Document_Storage_Exhausted,
			offset     = reader.at,
			allocation = allocation_err,
		}
		return
	}

	node.attrs = attributes
	for &attr in node.attrs {
		attr.key = binary_read_string(
			reader,
			binary_read_byte(reader),
			0,
		)
		attr.value = binary_read_string(
			reader,
			binary_read_byte(reader),
			0,
		)
		if reader.err.kind != .None do return

	}
	binary_read_attribute_keys_validate(reader, node, attrs)
}

binary_read_content :: proc(reader: ^Binary_Reader, node: ^Binary_Node, depth: int) {
	tag := binary_read_byte(reader)
	if reader.err.kind != .None do return

	if tag == cast(u8)Binary_Tag.LIST_EMPTY ||
	   tag == cast(u8)Binary_Tag.LIST_8 ||
	   tag == cast(u8)Binary_Tag.LIST_16 {
		count := binary_read_list_size(reader, tag)
		if count > MAX_BINARY_NODE_COUNT - reader.nodes {
			reader.err = {
				kind   = .Node_Limit,
				offset = reader.at,
			}
			return
		}

		children, child_err := make(
			[]Binary_Node,
			count,
			reader.allocator,
		)
		if child_err != nil {
			reader.err = {
				kind       = .Document_Storage_Exhausted,
				offset     = reader.at,
				allocation = child_err,
			}
			return
		}

		for &child in children {
			child = binary_read_node(reader, depth + 1)
			if reader.err.kind != .None do return

		}
		node.content = children
	} else if tag == cast(u8)Binary_Tag.BINARY_8 ||
	   tag == cast(u8)Binary_Tag.BINARY_20 ||
	   tag == cast(u8)Binary_Tag.BINARY_32 {
		count := binary_read_length(reader, tag)
		node.content = binary_read_bytes(reader, count)
	} else {
		value := binary_read_string(reader, tag, 0)
		if reader.err.kind != .None do return

		content, content_err := make(
			[]u8,
			len(value),
			reader.allocator,
		)
		if content_err != nil {
			reader.err = {
				kind       = .Document_Storage_Exhausted,
				offset     = reader.at,
				allocation = content_err,
			}
			return
		}

		copy(content, transmute([]u8)value)
		node.content = content
	}

}

binary_read_string :: proc(
	reader: ^Binary_Reader,
	tag: u8,
	depth: int,
) -> string {
	if reader.err.kind != .None do return ""

	if depth >= MAX_BINARY_NODE_DEPTH {
		reader.err = {
			kind   = .Depth_Limit,
			offset = reader.at,
		}
		return ""
	}

	if tag > 0 && cast(int)tag < len(SINGLE_BYTE_TOKENS) {
		return SINGLE_BYTE_TOKENS[tag]
	}

	#partial switch cast(Binary_Tag)tag {
	case .LIST_EMPTY:
		return ""
	case .DICTIONARY_0, .DICTIONARY_1, .DICTIONARY_2, .DICTIONARY_3:
		index := binary_read_byte(reader)
		return(
			DOUBLE_BYTE_TOKENS[cast(int)tag - cast(int)Binary_Tag.DICTIONARY_0][index] \
		)
	case .BINARY_8, .BINARY_20, .BINARY_32:
		value := cast(string)binary_read_bytes(
			reader,
			binary_read_length(reader, tag),
		)
		if !utf8.valid_string(value) {
			reader.err = {
				kind   = .Invalid_UTF8,
				offset = reader.at,
			}
		}

		return value
	case .HEX_8, .NIBBLE_8:
		return binary_read_packed_string(reader, tag)
	case .JID_PAIR:
		return binary_read_jid_pair(reader, depth)
	case .AD_JID:
		return binary_read_device_jid(reader, depth)
	case .FB_JID, .INTEROP_JID:
		reader.err = {
			kind   = .Unsupported_Token,
			offset = reader.at,
			token  = tag,
		}
	case:
		reader.err = {
			kind   = .Invalid_Token,
			offset = reader.at,
			token  = tag,
		}
	}
	return ""
}

binary_read_device_jid :: proc(reader: ^Binary_Reader, depth: int) -> string {
	domain, device :=
		binary_read_byte(reader), binary_read_byte(reader)
	user := binary_read_string(
		reader,
		binary_read_byte(reader),
		depth + 1,
	)
	server := "lid"
	if slice.contains([]type_of(domain){0, 128}, domain) {
		server = "s.whatsapp.net"
	}

	return binary_reader_join_jid(reader, user, server, device)
}

binary_unpack_bytes :: proc(reader: ^Binary_Reader, tag: u8, packed, data: []u8) -> bool {
	for value, i in packed {
		for half in 0 ..< 2 {
			nibble := value >> cast(uint)((1 - half) * 4) & 15
			c: u8
			if tag == cast(u8)Binary_Tag.HEX_8 {
				c = '0' + nibble
				if nibble >= 10 do c = 'A' + nibble - 10

			} else if nibble <= 9 {
				c = '0' + nibble
			} else {
				switch nibble {
				case 10:
					c = '-'
				case 11:
					c = '.'
				case 15:
					c = 0
				case:
					reader.err = {
						kind   = .Invalid_Packed_String,
						offset = reader.at,
					}
					return false
				}
			}

			data[i * 2 + half] = c
		}
	}
	return true
}

binary_read_packed_string :: proc(reader: ^Binary_Reader, tag: u8) -> string {
	length := binary_read_byte(reader)
	packed := binary_read_bytes(reader, cast(int)(length & 127))
	if reader.err.kind != .None do return ""

	if len(packed) == 0 && length & 128 != 0 {
		reader.err = {
			kind   = .Invalid_Packed_String,
			offset = reader.at,
		}
		return ""
	}

	count := len(packed) * 2
	if length & 128 != 0 do count -= 1

	data, allocation_err := make(
		[]u8,
		len(packed) * 2,
		reader.allocator,
	)
	if allocation_err != nil {
		reader.err = {
			kind       = .Document_Storage_Exhausted,
			offset     = reader.at,
			allocation = allocation_err,
		}
		return ""
	}

	if !binary_unpack_bytes(reader, tag, packed, data) do return ""
	return cast(string)data[:count]
}

binary_read_jid_pair :: proc(reader: ^Binary_Reader, depth: int) -> string {
	user := binary_read_string(
		reader,
		binary_read_byte(reader),
		depth + 1,
	)
	server := binary_read_string(
		reader,
		binary_read_byte(reader),
		depth + 1,
	)
	if reader.err.kind != .None do return ""

	if len(server) == 0 {
		reader.err = {
			kind   = .Invalid_JID,
			offset = reader.at,
		}
		return ""
	}

	return binary_reader_join_jid(reader, user, server, 0)
}

binary_reader_join_jid :: proc(
	reader: ^Binary_Reader,
	user, server: string,
	device: u8,
) -> string {
	if reader.err.kind != .None do return ""

	suffix: [4]u8
	device_suffix := ""
	if device != 0 {
		device_suffix = fmt.bprintf(suffix[:], ":%d", device)
	}

	data, allocation_err := make(
		[]u8,
		len(user) + len(device_suffix) + 1 + len(server),
		reader.allocator,
	)
	if allocation_err != nil {
		reader.err = {
			kind       = .Document_Storage_Exhausted,
			offset     = reader.at,
			allocation = allocation_err,
		}
		return ""
	}

	at := copy(data, transmute([]u8)user)
	at += copy(data[at:], transmute([]u8)device_suffix)
	data[at] = '@'
	copy(data[at + 1:], transmute([]u8)server)
	return cast(string)data
}

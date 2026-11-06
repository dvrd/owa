package whatsapp

import ascii "../ascii"
import http "../http"
import network_client "../surf"
import "core:bytes"
import "core:crypto"
import "core:crypto/aes"
import "core:crypto/hkdf"
import "core:crypto/hmac"
import "core:crypto/sha2"
import "core:encoding/base64"
import "core:encoding/json"
import "core:mem"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:unicode/utf8"
import "core:sync"
import "core:thread"
import "core:time"

// Baileys6.7.23 messages-media.js: full-file image/document encryption.
// Audio/video and ranged downloads are outside this module's scope.
DEFAULT_MAX_MEDIA_SIZE :: 16 << 20
MAX_MEDIA_SIZE_LIMIT :: 64 << 20
MEDIA_MAC_SIZE :: 10

Media_Kind :: enum {
	None,
	Image,
	Document,
}
Media_Keys :: struct {
	iv:                                 [16]u8,
	cipher_key, mac_key, reference_key: [32]u8,
}
Media_Metadata :: struct {
	media_key, file_sha256, file_enc_sha256: [32]u8,
	file_length:                             u64,
}
Media_Error_Kind :: enum {
	None,
	Invalid_Kind,
	Invalid_Limit,
	Media_Oversized,
	Destination_Undersized,
	Overlapping_Buffers,
	Allocation_Failed,
	Entropy_Unavailable,
	Invalid_Encrypted_Length,
	Encrypted_Hash_Mismatch,
	MAC_Mismatch,
	Invalid_Padding,
	File_Length_Mismatch,
	File_Hash_Mismatch,
	Invalid_Protobuf,
	Duplicate_Field,
	Conflicting_Content,
	Invalid_UTF8,
	Nesting_Limit,
	Message_Oversized,
	Invalid_Metadata,
	Invalid_Reaction_Key,
	Invalid_Download_Path,
	Invalid_Request_ID,
	Unexpected_Response,
	Server_Error,
	Invalid_Connection,
	Invalid_Upload_Response,
	HTTP_Failed,
	HTTP_Status,
	Binary_Node_Failed,
	Authentication_Failed,
	Invalid_Retry,
}
Media_Error :: struct {
	kind:       Media_Error_Kind,
	protobuf:   Protobuf_Error,
	allocation: mem.Allocator_Error,
	http:       network_client.HTTP_Error,
	status:     int,
	binary:     Binary_Node_Error,
}

media_keys_clear :: proc(keys: ^Media_Keys) {
	if keys != nil {
		crypto.zero_explicit(keys, size_of(Media_Keys))
	}

}
media_metadata_clear :: proc(metadata: ^Media_Metadata) {
	if metadata != nil {
		crypto.zero_explicit(metadata, size_of(Media_Metadata))
	}

}

media_key_generate :: proc() -> (key: [32]u8, err: Media_Error) {
	when !crypto.HAS_RAND_BYTES do return {}, {kind = .Entropy_Unavailable}
	crypto.rand_bytes(key[:])
	return key, {}
}

media_keys_derive :: proc(
	kind: Media_Kind,
	media_key: [32]u8,
) -> (
	keys: Media_Keys,
	err: Media_Error,
) {
	info: string
	#partial switch kind {
	case .Image:
		info = "WhatsApp Image Keys"
	case .Document:
		info = "WhatsApp Document Keys"
	case:
		return {}, {kind = .Invalid_Kind}
	}
	key := media_key
	defer crypto.zero_explicit(&key, 32)
	expanded: [112]u8
	defer crypto.zero_explicit(&expanded, 112)
	salt: [32]u8
	hkdf.extract_and_expand(
		.SHA256,
		salt[:],
		key[:],
		transmute([]u8)info,
		expanded[:],
	)
	copy(keys.iv[:], expanded[:16])
	copy(keys.cipher_key[:], expanded[16:48])
	copy(keys.mac_key[:], expanded[48:80])
	copy(keys.reference_key[:], expanded[80:])
	return keys, {}
}

// dst and plaintext must not overlap. All possible validation failures precede
// output writes. The returned metadata owns its secret media_key; clear it
// after storing/encoding the authenticated message that carries it.
media_encrypt :: proc(
	dst, plaintext: []u8,
	kind: Media_Kind,
	media_key: [32]u8,
	max_size: int = DEFAULT_MAX_MEDIA_SIZE,
) -> (
	n: int,
	metadata: Media_Metadata,
	err: Media_Error,
) {
	if max_size < 0 || max_size > MAX_MEDIA_SIZE_LIMIT {
		return 0, {}, {kind = .Invalid_Limit}
	}

	if len(plaintext) > max_size {
		return 0, {}, {kind = .Media_Oversized}
	}

	keys, key_err := media_keys_derive(kind, media_key)
	if key_err.kind != .None do return 0, {}, key_err

	defer media_keys_clear(&keys)
	cipher_size := (len(plaintext) / 16 + 1) * 16
	required := cipher_size + MEDIA_MAC_SIZE
	if len(dst) < required {
		return required, {}, {kind = .Destination_Undersized}
	}

	if bytes.alias(dst[:required], plaintext) {
		return 0, {}, {kind = .Overlapping_Buffers}
	}

	ctx: aes.Context_ECB
	aes.init_ecb(&ctx, keys.cipher_key[:])
	defer aes.reset_ecb(&ctx)
	previous := keys.iv
	defer crypto.zero_explicit(&previous, 16)
	block: [16]u8
	defer crypto.zero_explicit(&block, 16)
	padding := cast(u8)(cipher_size - len(plaintext))
	for at := 0; at < cipher_size; at += 16 {
		for i in 0 ..< 16 {
			value := padding
			if at + i < len(plaintext) {
				value = plaintext[at + i]
			}

			block[i] = value ~ previous[i]
		}
		aes.encrypt_ecb(&ctx, dst[at:at + 16], block[:])
		copy(previous[:], dst[at:at + 16])
	}
	mac := media_mac(keys, dst[:cipher_size])
	defer crypto.zero_explicit(&mac, 32)
	copy(dst[cipher_size:required], mac[:MEDIA_MAC_SIZE])
	metadata.media_key = media_key
	metadata.file_sha256 = media_hash(plaintext)
	metadata.file_enc_sha256 = media_hash(dst[:required])
	metadata.file_length = cast(u64)len(plaintext)
	return required, metadata, {}
}

// Verifies the complete encrypted-file hash and MAC before decrypting. CBC
// padding, exact file length and plaintext hash are checked in bounded scratch
// storage before copying anything to dst. Every failure leaves dst unchanged.
media_decrypt :: proc(
	dst, encrypted: []u8,
	kind: Media_Kind,
	metadata: Media_Metadata,
	max_size: int = DEFAULT_MAX_MEDIA_SIZE,
) -> (
	n: int,
	err: Media_Error,
) {
	details := metadata
	defer media_metadata_clear(&details)
	if max_size < 0 || max_size > MAX_MEDIA_SIZE_LIMIT {
		return 0, {kind = .Invalid_Limit}
	}

	if details.file_length > cast(u64)max_size {
		return 0, {kind = .Media_Oversized}
	}

	plain_size := cast(int)details.file_length
	expected_size := (plain_size / 16 + 1) * 16 + MEDIA_MAC_SIZE
	if len(encrypted) != expected_size {
		return 0, {kind = .Invalid_Encrypted_Length}
	}

	if len(dst) < plain_size {
		return plain_size, {kind = .Destination_Undersized}
	}

	if bytes.alias(dst[:plain_size], encrypted) {
		return 0, {kind = .Overlapping_Buffers}
	}

	keys, key_err := media_keys_derive(kind, details.media_key)
	if key_err.kind != .None do return 0, key_err

	defer media_keys_clear(&keys)
	if authentication_error := media_ciphertext_authenticate(encrypted, &details, &keys);
	   authentication_error.kind != .None do return 0, authentication_error
	cipher_size := len(encrypted) - MEDIA_MAC_SIZE
	plaintext, allocation_err := make([]u8, cipher_size)
	if allocation_err != nil {
		return 0, {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
	}

	defer delete(plaintext)
	defer crypto.zero_explicit(raw_data(plaintext), len(plaintext))
	media_cbc_decrypt_blocks(plaintext, encrypted, cipher_size, &keys)
	if plaintext_error := media_plaintext_validate(plaintext, cipher_size, plain_size, &details);
	   plaintext_error.kind != .None do return 0, plaintext_error
	copy(dst, plaintext[:plain_size])
	return plain_size, {}
}

media_ciphertext_authenticate :: proc(
	encrypted: []u8, details: ^Media_Metadata, keys: ^Media_Keys,
) -> Media_Error {
	hash := media_hash(encrypted)
	if crypto.compare_constant_time(
		   hash[:],
		   details.file_enc_sha256[:],
	   ) !=
	   1 {
		return {kind = .Encrypted_Hash_Mismatch}
	}

	cipher_size := len(encrypted) - MEDIA_MAC_SIZE
	mac := media_mac(keys^, encrypted[:cipher_size])
	defer crypto.zero_explicit(&mac, 32)
	if crypto.compare_constant_time(
		   mac[:MEDIA_MAC_SIZE],
		   encrypted[cipher_size:],
	   ) !=
	   1 {
		return {kind = .MAC_Mismatch}
	}

	return {}
}

media_cbc_decrypt_blocks :: proc(
	plaintext, encrypted: []u8, cipher_size: int, keys: ^Media_Keys,
) {
	ctx: aes.Context_ECB
	aes.init_ecb(&ctx, keys.cipher_key[:])
	defer aes.reset_ecb(&ctx)
	previous := keys.iv
	defer crypto.zero_explicit(&previous, 16)
	block: [16]u8
	defer crypto.zero_explicit(&block, 16)
	for at := 0; at < cipher_size; at += 16 {
		aes.decrypt_ecb(&ctx, block[:], encrypted[at:at + 16])
		for i in 0 ..< 16 do plaintext[at + i] = block[i] ~ previous[i]
		copy(previous[:], encrypted[at:at + 16])
	}
}

media_plaintext_validate :: proc(
	plaintext: []u8, cipher_size, plain_size: int, details: ^Media_Metadata,
) -> Media_Error {
	padding := cast(int)plaintext[cipher_size - 1]
	if padding < 1 || padding > 16 {
		return {kind = .Invalid_Padding}
	}

	difference: u8
	for i in 0 ..< 16 {
		if i < padding {
			difference |=
				plaintext[cipher_size - 1 - i] ~ cast(u8)padding
		}

	}
	if difference != 0 {
		return {kind = .Invalid_Padding}
	}

	if cipher_size - padding != plain_size {
		return {kind = .File_Length_Mismatch}
	}

	hash := media_hash(plaintext[:plain_size])
	if crypto.compare_constant_time(
		   hash[:],
		   details.file_sha256[:],
	   ) !=
	   1 {
		return {kind = .File_Hash_Mismatch}
	}

	return {}
}

media_hash :: proc(data: []u8) -> [32]u8 {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, data)
	hash: [32]u8
	sha2.final(&ctx, hash[:])
	return hash
}

media_mac :: proc(keys: Media_Keys, ciphertext: []u8) -> [32]u8 {
	key := keys
	defer media_keys_clear(&key)
	ctx: hmac.Context
	hmac.init(&ctx, .SHA256, key.mac_key[:])
	hmac.update(&ctx, key.iv[:])
	hmac.update(&ctx, ciphertext)
	mac: [32]u8
	hmac.final(&ctx, mac[:])
	return mac
}

// Full WAProto.Message imageMessage3/documentMessage7. Strings and slices
// borrow the decoded protobuf. Presence flags preserve explicitly empty fields;
// nonempty fields are also emitted when constructed without presence flags.
Media_Message :: struct {
	kind: Media_Kind,
	url,
	direct_path,
	mime_type,
	caption,
	file_name,
	title:                                       string,
	media_key,
	file_sha256,
	file_enc_sha256,
	jpeg_thumbnail:                                      []u8,
	file_length: u64,
	media_key_timestamp: i64,
	height,
	width,
	page_count:                                                                    u32,
	context_info: Message_Context,
	has_url,
	has_direct_path,
	has_mime_type,
	has_caption,
	has_file_name,
	has_title:               bool,
	has_media_key,
	has_file_sha256,
	has_file_enc_sha256,
	has_jpeg_thumbnail:                      bool,
	has_file_length,
	has_media_key_timestamp,
	has_height,
	has_width,
	has_page_count,
	has_context: bool,
}

Message_Key :: struct {
	remote_jid, id, participant:                          string,
	from_me:                                              bool,
	has_remote_jid, has_id, has_participant, has_from_me: bool,
}
Reaction_Message :: struct {
	key:                                                          Message_Key,
	text,
	grouping_key:                                           string,
	sender_timestamp_ms:                                          i64,
	has_key,
	has_text,
	has_grouping_key,
	has_sender_timestamp_ms: bool,
}

media_metadata_from_message :: proc(
	message: Media_Message,
) -> (
	metadata: Media_Metadata,
	err: Media_Error,
) {
	if !slice.contains(
		[]type_of(message.kind){.Image, .Document},
		message.kind,
	) {
		return {}, {kind = .Invalid_Kind}
	}

	if len(message.media_key) != 32 ||
	   len(message.file_sha256) != 32 ||
	   len(message.file_enc_sha256) != 32 ||
	   (!message.has_file_length && message.file_length == 0) {
		return {}, {kind = .Invalid_Metadata}
	}

	copy(metadata.media_key[:], message.media_key)
	copy(metadata.file_sha256[:], message.file_sha256)
	copy(metadata.file_enc_sha256[:], message.file_enc_sha256)
	metadata.file_length = message.file_length
	return metadata, {}
}

// Match Baileys' download routing: only the canonical CDN URL is accepted;
// otherwise a valid directPath is attached to mmg.whatsapp.net. No arbitrary
// sender-selected host is returned for the caller's HTTP downloader.
media_download_url :: proc(
	dst: []u8,
	message: Media_Message,
) -> (
	url: string,
	err: Media_Error,
) {
	if bytes.alias(dst, transmute([]u8)message.url) ||
	   bytes.alias(dst, transmute([]u8)message.direct_path) {
		return "", {kind = .Overlapping_Buffers}
	}

	url = message.url
	if strings.has_prefix(url, "https://mmg.whatsapp.net/") {
		for c in url {
			if c <= 32 || c >= 127 {
				return "", {kind = .Invalid_Download_Path}
			}

		}
		if strings.contains(url, "#") ||
		   strings.contains(url, "\\") {
			return "", {kind = .Invalid_Download_Path}
		}

	} else {
		if len(message.direct_path) == 0 ||
		   message.direct_path[0] != '/' ||
		   strings.has_prefix(message.direct_path, "//") {
			return "", {kind = .Invalid_Download_Path}
		}

		for c in message.direct_path {
			if c <= 32 ||
			   c >= 127 ||
			   slice.contains([]type_of(c){'#', '\\'}, c) {
				return "", {kind = .Invalid_Download_Path}
			}

		}
		prefix := "https://mmg.whatsapp.net"
		if len(dst) < len(prefix) + len(message.direct_path) {
			return "", {kind = .Destination_Undersized}
		}

		at := copy(dst, transmute([]u8)prefix)
		at += copy(dst[at:], transmute([]u8)message.direct_path)
		return cast(string)dst[:at], {}
	}

	if len(dst) < len(url) {
		return "", {kind = .Destination_Undersized}
	}

	copy(dst, transmute([]u8)url)
	return cast(string)dst[:len(url)], {}
}

media_message_encode :: proc(
	dst: []u8,
	message: Media_Message,
) -> (
	int,
	Media_Error,
) {
	if !slice.contains(
		[]type_of(message.kind){.Image, .Document},
		message.kind,
	) {
		return 0, {kind = .Invalid_Kind}
	}

	measure := Media_Writer {
		target = dst,
	}
	media_emit_envelope(&measure, message)
	if measure.err.kind != .None do return 0, measure.err

	if len(dst) < measure.at {
		return measure.at, {kind = .Destination_Undersized}
	}

	writer := Media_Writer {
		dst = dst,
	}
	media_emit_envelope(&writer, message)
	return writer.at, writer.err
}

media_message_decode :: proc(
	src: []u8,
) -> (
	message: Media_Message,
	err: Media_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, {kind = .Message_Oversized}
	}

	payload, number, extract_err := media_extract_content(src, 0)
	if extract_err.kind != .None do return {}, extract_err

	if !slice.contains([]type_of(number){3, 7}, number) {
		return {}, {}
	}

	message.kind = .Image
	if number == 7 do message.kind = .Document

	key_field, path_field, timestamp_field :=
		cast(u32)8, cast(u32)11, cast(u32)12
	if message.kind == .Document {
		key_field, path_field, timestamp_field = 7, 10, 11
	}

	at := 0
	seen: u64
	for at < len(payload) {
		field, protobuf_err := protobuf_field_read(payload, &at)
		if protobuf_err != .None {
			return {}, {
				kind = .Invalid_Protobuf,
				protobuf = protobuf_err,
			}
		}

		known := media_message_field_known(&message, field, key_field, path_field, timestamp_field)
		if !known do continue

		bit := cast(u64)1 << field.number
		if seen & bit != 0 {
			return {}, {kind = .Duplicate_Field}
		}

		seen |= bit
		integer :=
			slice.contains(
				[]type_of(field.number){5, 6, timestamp_field},
				field.number,
			) ||
			message.kind == .Image && field.number == 7
		if integer {
			if integer_error := media_message_integer_decode(&message, field, timestamp_field);
			   integer_error.kind != .None do return {}, integer_error
			continue
		}

		if bytes_error := media_message_bytes_decode(&message, field, key_field);
		   bytes_error.kind != .None do return {}, bytes_error
	}
	return message, {}
}

media_message_field_known :: proc(
	message: ^Media_Message, field: Protobuf_Field, key_field, path_field, timestamp_field: u32,
) -> bool {
	known := slice.contains(
		[]type_of(field.number) {
			1,
			2,
			3,
			4,
			5,
			6,
			9,
			key_field,
			path_field,
			timestamp_field,
			16,
			17,
		},
		field.number,
	)
	if message.kind == .Image && field.number == 7 {
		known = true
	}

	if message.kind == .Document &&
	   (slice.contains(
				   []type_of(field.number){8, 20},
				   field.number,
			   )) {
		known = true
	}

	return known
}

media_message_integer_decode :: proc(
	message: ^Media_Message, field: Protobuf_Field, timestamp_field: u32,
) -> Media_Error {
	if field.wire_type != 0 {
		return {kind = .Invalid_Protobuf}
	}

	if field.number == 5 {
		message.file_length, message.has_file_length =
			field.value, true
	} else if field.number == timestamp_field {
		message.media_key_timestamp, message.has_media_key_timestamp =
			cast(i64)field.value, true
	} else {
		if field.value > cast(u64)max(u32) {
			return {
				kind = .Invalid_Protobuf,
				protobuf = .Integer_Overflow,
			}
		}

		if message.kind == .Document {
			message.page_count, message.has_page_count =
				cast(u32)field.value, true
		} else if field.number == 6 {
			message.height, message.has_height =
				cast(u32)field.value, true
		} else {
			message.width, message.has_width =
				cast(u32)field.value, true
		}

	}

	return {}
}

media_message_bytes_decode :: proc(
	message: ^Media_Message, field: Protobuf_Field, key_field: u32,
) -> (err: Media_Error) {
	if field.wire_type != 2 {
		return {kind = .Invalid_Protobuf}
	}

	if slice.contains(
		[]type_of(field.number){4, 9, key_field},
		field.number,
	) {
		if len(field.data) != 32 {
			return {kind = .Invalid_Metadata}
		}

		if field.number == 4 {
			message.file_sha256, message.has_file_sha256 =
				field.data, true
		} else if field.number == 9 {
			message.file_enc_sha256, message.has_file_enc_sha256 =
				field.data, true
		} else {
			message.media_key, message.has_media_key =
				field.data, true
		}

		return {}
	}

	if field.number == 16 {
		message.jpeg_thumbnail, message.has_jpeg_thumbnail =
			field.data, true
		return {}
	}

	if field.number == 17 {
		message.context_info, err = media_context_decode(
			field.data,
		)
		if err.kind != .None do return err

		message.has_context = true
		return {}
	}

	return media_message_string_decode(message, field)
}

media_message_string_decode :: proc(
	message: ^Media_Message, field: Protobuf_Field,
) -> Media_Error {
	value := cast(string)field.data
	if !utf8.valid_string(value) {
		return {kind = .Invalid_UTF8}
	}

	switch field.number {
	case 1:
		message.url, message.has_url = value, true
	case 2:
		message.mime_type, message.has_mime_type = value, true
	case 3:
		if message.kind == .Image {
			message.caption, message.has_caption = value, true
		} else {
			message.title, message.has_title = value, true
		}

	case 8:
		message.file_name, message.has_file_name = value, true
	case 20:
		message.caption, message.has_caption = value, true
	case:
		message.direct_path, message.has_direct_path =
			value, true
	}
	return {}
}

reaction_message_encode :: proc(
	dst: []u8,
	message: Reaction_Message,
) -> (
	int,
	Media_Error,
) {
	measure := Media_Writer {
		target = dst,
	}
	reaction_emit_envelope(&measure, message)
	if measure.err.kind != .None do return 0, measure.err

	if len(dst) < measure.at {
		return measure.at, {kind = .Destination_Undersized}
	}

	writer := Media_Writer {
		dst = dst,
	}
	reaction_emit_envelope(&writer, message)
	return writer.at, writer.err
}

reaction_message_decode :: proc(
	src: []u8,
) -> (
	message: Reaction_Message,
	err: Media_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, {kind = .Message_Oversized}
	}

	payload, number, extract_err := media_extract_content(src, 0)
	if extract_err.kind != .None do return {}, extract_err

	if number != 46 do return {}, {}

	at := 0
	seen: u8
	for at < len(payload) {
		field, protobuf_err := protobuf_field_read(payload, &at)
		if protobuf_err != .None {
			return {}, {
				kind = .Invalid_Protobuf,
				protobuf = protobuf_err,
			}
		}

		if field.number < 1 || field.number > 4 do continue

		bit := cast(u8)1 << field.number
		if seen & bit != 0 {
			return {}, {kind = .Duplicate_Field}
		}

		seen |= bit
		if field_error := reaction_message_field_decode(&message, field);
		   field_error.kind != .None do return {}, field_error
	}
	return message, {}
}

reaction_message_field_decode :: proc(
	message: ^Reaction_Message, field: Protobuf_Field,
) -> (err: Media_Error) {
	if field.number == 4 {
		if field.wire_type != 0 {
			return {kind = .Invalid_Protobuf}
		}

		message.sender_timestamp_ms, message.has_sender_timestamp_ms =
			cast(i64)field.value, true
		return {}
	}

	if field.wire_type != 2 {
		return {kind = .Invalid_Protobuf}
	}

	if field.number == 1 {
		message.key, err = media_key_decode(field.data)
		if err.kind != .None do return err

		message.has_key = true
	} else {
		value := cast(string)field.data
		if !utf8.valid_string(value) {
			return {kind = .Invalid_UTF8}
		}

		if field.number == 2 {
			message.text, message.has_text = value, true
		} else {
			message.grouping_key, message.has_grouping_key =
				value, true
		}

	}

	return {}
}

reaction_checkmark_encode :: proc(
	dst: []u8,
	key: Message_Key,
	sender_timestamp_ms: i64,
) -> (
	int,
	Media_Error,
) {
	if len(key.remote_jid) == 0 || len(key.id) == 0 {
		return 0, {kind = .Invalid_Reaction_Key}
	}

	return reaction_message_encode(
		dst,
		{
			key = key,
			has_key = true,
			text = "✅",
			has_text = true,
			sender_timestamp_ms = sender_timestamp_ms,
			has_sender_timestamp_ms = true,
		},
	)
}

Media_Writer :: struct {
	dst, target: []u8,
	at:          int,
	err:         Media_Error,
}

media_write_varint :: proc(writer: ^Media_Writer, value: u64) {
	if writer.err.kind != .None do return

	v := value
	for {
		if writer.at >= MAX_PROTOBUF_MESSAGE_SIZE {
			writer.err = {
				kind = .Message_Oversized,
			}
			return
		}

		b := cast(u8)(v & 127)
		v >>= 7
		if v != 0 do b |= 128

		if writer.dst != nil do writer.dst[writer.at] = b

		writer.at += 1
		if v == 0 do break

	}
}

media_write_header :: proc(
	writer: ^Media_Writer,
	number: u32,
	size: int,
) {
	media_write_varint(writer, cast(u64)number << 3 | 2)
	media_write_varint(writer, cast(u64)size)
}

media_write_bytes :: proc(
	writer: ^Media_Writer,
	number: u32,
	data: []u8,
) {
	if writer.err.kind != .None do return

	if bytes.alias(writer.target, data) {
		writer.err = {
			kind = .Overlapping_Buffers,
		}
		return
	}

	if len(data) > MAX_PROTOBUF_MESSAGE_SIZE {
		writer.err = {
			kind = .Message_Oversized,
		}
		return
	}

	media_write_header(writer, number, len(data))
	if writer.err.kind != .None do return

	if len(data) > MAX_PROTOBUF_MESSAGE_SIZE - writer.at {
		writer.err = {
			kind = .Message_Oversized,
		}
		return
	}

	if writer.dst != nil {
		copy(writer.dst[writer.at:], data)
	}

	writer.at += len(data)
}

media_write_string :: proc(
	writer: ^Media_Writer,
	number: u32,
	value: string,
) {
	if !utf8.valid_string(value) {
		writer.err = {
			kind = .Invalid_UTF8,
		}
		return
	}

	media_write_bytes(writer, number, transmute([]u8)value)
}

media_write_integer :: proc(
	writer: ^Media_Writer,
	number: u32,
	value: u64,
) {
	media_write_varint(writer, cast(u64)number << 3)
	media_write_varint(writer, value)
}

media_emit_envelope :: proc(
	writer: ^Media_Writer,
	message: Media_Message,
) {
	measure := Media_Writer {
		target = writer.target,
	}
	media_emit_body(&measure, message)
	if measure.err.kind != .None {
		writer.err = measure.err
		return
	}

	field := cast(u32)3
	if message.kind == .Document do field = 7

	media_write_header(writer, field, measure.at)
	media_emit_body(writer, message)
}

media_emit_body :: proc(
	writer: ^Media_Writer,
	message: Media_Message,
) {
	m := message
	if !media_emit_kind_validate(writer, m) do return

	caption, key, path, timestamp :=
		cast(u32)3, cast(u32)8, cast(u32)11, cast(u32)12
	if m.kind == .Document {
		caption, key, path, timestamp = 20, 7, 10, 11
	}

	strings_to_write := [?]struct {
		number:  u32,
		value:   string,
		present: bool,
	} {
		{1, m.url, m.has_url || len(m.url) > 0},
		{2, m.mime_type, m.has_mime_type || len(m.mime_type) > 0},
		{caption, m.caption, m.has_caption || len(m.caption) > 0},
		{
			path,
			m.direct_path,
			m.has_direct_path || len(m.direct_path) > 0,
		},
		{8, m.file_name, m.has_file_name || len(m.file_name) > 0},
		{3, m.title, m.has_title || len(m.title) > 0},
	}
	// Emit field-number order, as protobufjs's pinned encoder does.
	for number in 1 ..= 20 {
		for field in strings_to_write {
			if field.number == cast(u32)number && field.present {
				media_write_string(writer, field.number, field.value)
			}

		}
		if !media_emit_bytes_fields(writer, m, number, key) do return
		if !media_emit_integer_context_fields(writer, m, number, timestamp) do return
	}
}

media_emit_kind_validate :: proc(writer: ^Media_Writer, m: Media_Message) -> bool {
	if m.kind == .Image &&
	   (m.has_file_name ||
			   m.file_name != "" ||
			   m.has_title ||
			   m.title != "" ||
			   m.has_page_count ||
			   m.page_count != 0) {
		writer.err = {
			kind = .Invalid_Metadata,
		}
		return false
	}

	if m.kind == .Document &&
	   (m.has_height ||
			   m.height != 0 ||
			   m.has_width ||
			   m.width != 0) {
		writer.err = {
			kind = .Invalid_Metadata,
		}
		return false
	}

	return true
}

media_emit_bytes_fields :: proc(
	writer: ^Media_Writer, m: Media_Message, number: int, key: u32,
) -> bool {
	for field in ([?]struct {
			number:  u32,
			data:    []u8,
			present: bool,
		} {
			{
				4,
				m.file_sha256,
				m.has_file_sha256 || len(m.file_sha256) > 0,
			},
			{
				9,
				m.file_enc_sha256,
				m.has_file_enc_sha256 ||
				len(m.file_enc_sha256) > 0,
			},
			{
				key,
				m.media_key,
				m.has_media_key || len(m.media_key) > 0,
			},
			{
				16,
				m.jpeg_thumbnail,
				m.has_jpeg_thumbnail ||
				len(m.jpeg_thumbnail) > 0,
			},
		}) {
		if field.number != cast(u32)number || !field.present {
			continue
		}

		if field.number != 16 && len(field.data) != 32 {
			writer.err = {
				kind = .Invalid_Metadata,
			}
			return false
		}

		media_write_bytes(writer, field.number, field.data)
	}
	return true
}

media_emit_integer_context_fields :: proc(
	writer: ^Media_Writer, m: Media_Message, number: int, timestamp: u32,
) -> bool {
	if number == 5 && (m.has_file_length || m.file_length != 0) {
		media_write_integer(writer, 5, m.file_length)
	}

	if number == cast(int)timestamp &&
	   (m.has_media_key_timestamp ||
			   m.media_key_timestamp != 0) {
		media_write_integer(
			writer,
			timestamp,
			cast(u64)m.media_key_timestamp,
		)
	}

	if m.kind == .Image {
		if number == 6 && (m.has_height || m.height != 0) {
			media_write_integer(writer, 6, cast(u64)m.height)
		}

		if number == 7 && (m.has_width || m.width != 0) {
			media_write_integer(writer, 7, cast(u64)m.width)
		}

	} else if number == 6 &&
	   (m.has_page_count || m.page_count != 0) {
		media_write_integer(writer, 6, cast(u64)m.page_count)
	}

	if number == 17 && m.has_context {
		measure := Media_Writer {
			target = writer.target,
		}
		media_emit_context(&measure, m.context_info)
		if measure.err.kind != .None {
			writer.err = measure.err
			return false
		}

		media_write_header(writer, 17, measure.at)
		media_emit_context(writer, m.context_info)
	}

	return true
}

media_emit_context :: proc(
	writer: ^Media_Writer,
	context_info: Message_Context,
) {
	c := context_info
	if c.has_stanza_id {
		media_write_string(writer, 1, c.stanza_id)
	}

	if c.has_participant {
		media_write_string(writer, 2, c.participant)
	}

	if c.has_quoted_message {
		if err := media_validate_protobuf(c.quoted_message);
		   err.kind != .None {
			writer.err = err
			return
		}

		media_write_bytes(writer, 3, c.quoted_message)
	}

	if c.has_remote_jid {
		media_write_string(writer, 4, c.remote_jid)
	}

}

reaction_emit_envelope :: proc(
	writer: ^Media_Writer,
	message: Reaction_Message,
) {
	measure := Media_Writer {
		target = writer.target,
	}
	reaction_emit_body(&measure, message)
	if measure.err.kind != .None {
		writer.err = measure.err
		return
	}

	media_write_header(writer, 46, measure.at)
	reaction_emit_body(writer, message)
}

reaction_emit_body :: proc(
	writer: ^Media_Writer,
	message: Reaction_Message,
) {
	m := message
	if m.has_key || m.key.remote_jid != "" || m.key.id != "" {
		measure := Media_Writer {
			target = writer.target,
		}
		media_emit_message_key(&measure, m.key)
		if measure.err.kind != .None {
			writer.err = measure.err
			return
		}

		media_write_header(writer, 1, measure.at)
		media_emit_message_key(writer, m.key)
	}

	if m.has_text || m.text != "" {
		media_write_string(writer, 2, m.text)
	}

	if m.has_grouping_key || m.grouping_key != "" {
		media_write_string(writer, 3, m.grouping_key)
	}

	if m.has_sender_timestamp_ms || m.sender_timestamp_ms != 0 {
		media_write_integer(
			writer,
			4,
			cast(u64)m.sender_timestamp_ms,
		)
	}

}

media_emit_message_key :: proc(
	writer: ^Media_Writer,
	key: Message_Key,
) {
	if key.has_remote_jid || key.remote_jid != "" {
		media_write_string(writer, 1, key.remote_jid)
	}

	if key.has_from_me || key.from_me {
		media_write_integer(writer, 2, key.from_me ? 1 : 0)
	}

	if key.has_id || key.id != "" {
		media_write_string(writer, 3, key.id)
	}

	if key.has_participant || key.participant != "" {
		media_write_string(writer, 4, key.participant)
	}

}

media_extract_content :: proc(
	src: []u8,
	depth: int,
) -> (
	payload: []u8,
	number: u32,
	err: Media_Error,
) {
	if depth > MAX_MESSAGE_NESTING {
		return nil, 0, {kind = .Nesting_Limit}
	}

	at := 0
	seen: bool
	outer_number: u32
	for at < len(src) {
		field, protobuf_err := protobuf_field_read(src, &at)
		if protobuf_err != .None {
			return nil, 0, {
				kind = .Invalid_Protobuf,
				protobuf = protobuf_err,
			}
		}

		switch field.number {
		case 1, 3, 6, 7, 37, 40, 46, 53, 55, 59:
			if field.wire_type != 2 {
				return nil, 0, {kind = .Invalid_Protobuf}
			}

			if seen {
				kind: Media_Error_Kind = .Conflicting_Content
				if outer_number == field.number {
					kind = .Duplicate_Field
				}

				return nil, 0, {kind = kind}
			}

			seen = true
			outer_number = field.number
			if slice.contains(
				[]type_of(field.number){37, 40, 53, 55, 59},
				field.number,
			) {
				payload, number, err = media_extract_wrapper(field.data, depth)
				if err.kind != .None do return nil, 0, err
			} else {
				payload, number = field.data, field.number
			}

		}
	}
	return payload, number, {}
}

media_extract_wrapper :: proc(
	src: []u8, depth: int,
) -> (payload: []u8, number: u32, err: Media_Error) {
	inner_at := 0
	inner_seen := false
	for inner_at < len(src) {
		inner, inner_err := protobuf_field_read(
			src,
			&inner_at,
		)
		if inner_err != .None {
			return nil, 0, {
				kind = .Invalid_Protobuf,
				protobuf = inner_err,
			}
		}

		if inner.number != 1 do continue

		if inner_seen {
			return nil, 0, {kind = .Duplicate_Field}
		}

		if inner.wire_type != 2 {
			return nil, 0, {kind = .Invalid_Protobuf}
		}

		inner_seen = true
		payload, number, err = media_extract_content(
			inner.data,
			depth + 1,
		)
		if err.kind != .None {
			return nil, 0, err
		}

	}
	if !inner_seen {
		return nil, 0, {kind = .Invalid_Protobuf}
	}

	return payload, number, {}
}

media_context_decode :: proc(
	src: []u8,
) -> (
	context_info: Message_Context,
	err: Media_Error,
) {
	at := 0
	seen: u8
	for at < len(src) {
		field, protobuf_err := protobuf_field_read(src, &at)
		if protobuf_err != .None {
			return {}, {
				kind = .Invalid_Protobuf,
				protobuf = protobuf_err,
			}
		}

		if field.number < 1 || field.number > 4 do continue

		if field.wire_type != 2 {
			return {}, {kind = .Invalid_Protobuf}
		}

		bit := cast(u8)1 << field.number
		if seen & bit != 0 {
			return {}, {kind = .Duplicate_Field}
		}

		seen |= bit
		if field.number == 3 {
			if quoted_err := media_validate_protobuf(field.data);
			   quoted_err.kind != .None {
				return {}, quoted_err
			}

			context_info.quoted_message, context_info.has_quoted_message =
				field.data, true
			continue
		}

		value := cast(string)field.data
		if !utf8.valid_string(value) {
			return {}, {kind = .Invalid_UTF8}
		}

		switch field.number {
		case 1:
			context_info.stanza_id, context_info.has_stanza_id =
				value, true
		case 2:
			context_info.participant, context_info.has_participant =
				value, true
		case 4:
			context_info.remote_jid, context_info.has_remote_jid =
				value, true
		}
	}
	return context_info, {}
}

media_key_decode :: proc(
	src: []u8,
) -> (
	key: Message_Key,
	err: Media_Error,
) {
	at := 0
	seen: u8
	for at < len(src) {
		field, protobuf_err := protobuf_field_read(src, &at)
		if protobuf_err != .None {
			return {}, {
				kind = .Invalid_Protobuf,
				protobuf = protobuf_err,
			}
		}

		if field.number < 1 || field.number > 4 do continue

		bit := cast(u8)1 << field.number
		if seen & bit != 0 {
			return {}, {kind = .Duplicate_Field}
		}

		seen |= bit
		if field.number == 2 {
			if field.wire_type != 0 || field.value > 1 {
				return {}, {kind = .Invalid_Protobuf}
			}

			key.from_me, key.has_from_me = field.value != 0, true
			continue
		}

		if field.wire_type != 2 {
			return {}, {kind = .Invalid_Protobuf}
		}

		value := cast(string)field.data
		if !utf8.valid_string(value) {
			return {}, {kind = .Invalid_UTF8}
		}

		switch field.number {
		case 1:
			key.remote_jid, key.has_remote_jid = value, true
		case 3:
			key.id, key.has_id = value, true
		case 4:
			key.participant, key.has_participant = value, true
		}
	}
	return key, {}
}

media_validate_protobuf :: proc(src: []u8) -> Media_Error {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {kind = .Message_Oversized}
	}

	at := 0
	for at < len(src) {
		_, err := protobuf_field_read(src, &at)
		if err != .None {
			return {kind = .Invalid_Protobuf, protobuf = err}
		}

	}
	return {}
}

MAX_MEDIA_HOSTS :: 16
MAX_MEDIA_URL_SIZE :: 4096
// Nil selects the native authenticated HTTP client. An explicit executor is
// trusted application code and must uphold the supplied TLS/bounds settings.
Media_HTTP_Execute :: #type proc(
	request: http.Request,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
)

media_http_native :: proc(
	request: http.Request,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	return network_client.execute(request, config)
}
Media_Host :: struct {
	hostname:           string,
	// Zero means the server did not advertise a per-host limit. Local media
	// and HTTP limits still apply to every upload.
	max_content_length: u64,
}
// Strings borrow the decoded Binary_Document; host storage belongs to caller.
Media_Connection :: struct {
	auth:        string,
	ttl_seconds: u32,
	hosts:       []Media_Host,
}
Media_Upload_Result :: struct {
	url:              [MAX_MEDIA_URL_SIZE]u8,
	url_size:         int,
	direct_path:      [2048]u8,
	direct_path_size: int,
}

media_connection_query_encode :: proc(
	dst: []u8,
	request_id: string,
) -> (
	int,
	Media_Error,
) {
	if !media_request_id_valid(request_id) {
		return 0, {kind = .Invalid_Request_ID}
	}

	node := Binary_Node {
		tag     = "iq",
		attrs   = []Binary_Node_Attribute {
			{"type", "set"},
			{"xmlns", "w:m"},
			{"to", "@s.whatsapp.net"},
			{"id", request_id},
		},
		content = []Binary_Node{{tag = "media_conn"}},
	}
	n, e := binary_node_encode(dst, node)
	if e.kind != .None {
		return n, {kind = .Binary_Node_Failed, binary = e}
	}

	return n, {}
}

// A connection's TTL is measured by the caller from the successful response.
// Expired credentials must be refreshed before initiating a new upload.
media_connection_decode :: proc(
	node: Binary_Node,
	request_id: string,
	storage: []Media_Host,
) -> (
	Media_Connection,
	Media_Error,
) {
	target, node_error := media_connection_node_decode(node, request_id)
	if node_error.kind != .None do return {}, node_error

	auth, _ := node_attr(target^, "auth")
	ttl_text, _ := node_attr(target^, "ttl")
	ttl, valid := strconv.parse_uint(ttl_text, 10)
	if len(auth) == 0 ||
	   len(auth) > 4096 ||
	   !utf8.valid_string(auth) ||
	   !valid ||
	   ttl == 0 ||
	   ttl > cast(uint)max(u32) {
		return {}, {kind = .Invalid_Connection}
	}

	hosts, _ := target.content.([]Binary_Node)
	count, host_error := media_connection_hosts_validate(hosts)
	if host_error.kind != .None do return {}, host_error

	if len(storage) < count {
		return {}, {kind = .Destination_Undersized}
	}

	at := 0
	for host in hosts {
		if host.tag != "host" do continue

		hostname, _ := node_attr(host, "hostname")
		length, _ := media_host_limit(host)
		storage[at] = {hostname, length}; at += 1
	}
	return {
		auth = auth,
		ttl_seconds = cast(u32)ttl,
		hosts = storage[:count],
	}, {}
}

media_connection_node_decode :: proc(
	node: Binary_Node, request_id: string,
) -> (^Binary_Node, Media_Error) {
	if !media_request_id_valid(request_id) {
		return nil, {kind = .Invalid_Request_ID}
	}

	id, _ := node_attr(node, "id")
	kind, _ := node_attr(node, "type")
	from, present := node_attr(node, "from")
	if node.tag != "iq" ||
	   id != request_id ||
	   present &&
		   !slice.contains(
				   []string{"s.whatsapp.net", "@s.whatsapp.net"},
				   from,
			   ) {
		return nil, {kind = .Unexpected_Response}
	}

	if kind == "error" || node_child(node, "error") != nil {
		return nil, {kind = .Server_Error}
	}

	if kind != "result" {
		return nil, {kind = .Unexpected_Response}
	}

	children, _ := node.content.([]Binary_Node)
	target: ^Binary_Node
	for &child in children {
		if child.tag != "media_conn" do continue

		if target != nil {
			return nil, {kind = .Invalid_Connection}
		}

		target = &child
	}
	if target == nil {
		return nil, {kind = .Invalid_Connection}
	}

	return target, {}
}

media_connection_hosts_validate :: proc(hosts: []Binary_Node) -> (int, Media_Error) {
	count := 0
	for host in hosts {
		if host.tag != "host" do continue

		hostname, _ := node_attr(host, "hostname")
		_, valid_limit := media_host_limit(host)
		if !media_hostname_valid(hostname) ||
		   !valid_limit ||
		   count >= MAX_MEDIA_HOSTS {
			return 0, {kind = .Invalid_Connection}
		}

		// This is an ordered failover list, not a hostname-keyed map. Live
		// responses can advertise the same host more than once.
		count += 1
	}
	if count == 0 do return 0, {kind = .Invalid_Connection}

	return count, {}
}

media_host_limit :: proc(host: Binary_Node) -> (u64, bool) {
	text, present := node_attr(host, "maxContentLengthBytes")
	if !present do return 0, true

	length, valid := strconv.parse_u64(text, 10)
	return length, valid && length > 0
}

media_upload_url :: proc(
	dst: []u8,
	hostname, auth: string,
	kind: Media_Kind,
	encrypted_hash: [32]u8,
) -> (
	string,
	Media_Error,
) {
	if !media_hostname_valid(hostname) ||
	   len(auth) == 0 ||
	   len(auth) > 4096 ||
	   !utf8.valid_string(auth) {
		return "", {kind = .Invalid_Connection}
	}

	path: string
	#partial switch kind {case .Image:
		path = "/mms/image/"; case .Document:
		path = "/mms/document/"; case:
		return "", {kind = .Invalid_Kind}
	}
	hash := encrypted_hash
	token: [44]u8
	base64.encode_into_buf(token[:], hash[:])
	for &c in token[:43] {
		if c == '+' do c = '-'

		if c == '/' do c = '_'

	}
	// encodeURIComponent's exact unescaped alphabet, as used by pinned Baileys.
	scratch: [MAX_MEDIA_URL_SIZE]u8
	at := 0
	pieces := []string {
		"https://",
		hostname,
		path,
		cast(string)token[:43],
		"?auth=",
	}
	for piece in pieces {
		if len(piece) > len(scratch) - at {
			return "", {kind = .Invalid_Connection}
		}

		at += copy(scratch[at:], transmute([]u8)piece)
	}
	if auth_error := media_upload_auth_encode(scratch[:], &at, auth);
	   auth_error.kind != .None do return "", auth_error
	if 7 + 43 > len(scratch) - at {
		return "", {kind = .Invalid_Connection}
	}

	at += copy(scratch[at:], []u8{38, 116, 111, 107, 101, 110, 61})
	at += copy(scratch[at:], token[:43])
	if len(dst) < at {
		return "", {kind = .Destination_Undersized}
	}

	copy(dst, scratch[:at]); return cast(string)dst[:at], {}
}

media_upload_auth_encode :: proc(scratch: []u8, at: ^int, auth: string) -> Media_Error {
	hex_digits := "0123456789ABCDEF"
	for c in transmute([]u8)auth {
		unescaped :=
			ascii.is_alphanumeric(c) ||
			strings.contains_rune("-_.!~*'()", cast(rune)c)
		required := 3; if unescaped do required = 1

		if required > len(scratch) - at^ {
			return {kind = .Invalid_Connection}
		}

		if unescaped {
			scratch[at^] = c; at^ += 1
		} else {
			scratch[at^] = '%'; scratch[at^ + 1] = hex_digits[c >> 4]
			scratch[at^ + 2] = hex_digits[c & 15]; at^ += 3
		}

	}
	return {}
}

// Strict bounded JSON. Returned strings are copied into fixed owned storage.
media_upload_response_decode :: proc(
	src: []u8,
) -> (
	result: Media_Upload_Result,
	err: Media_Error,
) {
	if len(src) > 16384 {
		return {}, {kind = .Invalid_Upload_Response}
	}

	if depth_error := media_upload_json_depth_validate(src);
	   depth_error.kind != .None do return {}, depth_error
	parser := json.make_parser(src, spec = .JSON)
	value, e := json.parse_value(&parser)
	if e != .None {
		return {}, {kind = .Invalid_Upload_Response}
	}

	defer json.destroy_value(value)
	if parser.curr_token.kind != .EOF {
		return {}, {kind = .Invalid_Upload_Response}
	}

	object, ok := value.(json.Object)
	if !ok do return {}, {kind = .Invalid_Upload_Response}

	url, url_ok := object["url"].(string)
	path, path_ok := object["direct_path"].(string)
	if !url_ok ||
	   !path_ok ||
	   len(url) == 0 ||
	   len(url) > len(result.url) ||
	   len(path) == 0 ||
	   len(path) > len(result.direct_path) {
		return {}, {kind = .Invalid_Upload_Response}
	}

	url_buffer: [MAX_MEDIA_URL_SIZE]u8
	normalized, validation := media_download_url(
		url_buffer[:],
		{url = url, direct_path = path},
	)
	if validation.kind != .None || normalized != url {
		return {}, {kind = .Invalid_Upload_Response}
	}

	_, validation = media_download_url(
		url_buffer[:],
		{direct_path = path},
	)
	if validation.kind != .None {
		return {}, {kind = .Invalid_Upload_Response}
	}

	result.url_size = copy(result.url[:], transmute([]u8)url)
	result.direct_path_size = copy(
		result.direct_path[:],
		transmute([]u8)path,
	)
	return result, {}
}

media_upload_json_depth_validate :: proc(src: []u8) -> Media_Error {
	// Bound parser recursion before handing nested data to core:encoding/json.
	depth := 0; quoted, escaped := false, false
	for c in src {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}

			continue
		}

		if c == '"' {
			quoted = true; continue
		}

		if slice.contains([]type_of(c){'{', '['}, c) {
			depth += 1
			if depth > 16 {
				return {kind = .Invalid_Upload_Response}
			}

		}

		if slice.contains([]type_of(c){'}', ']'}, c) {
			depth -= 1
			if depth < 0 {
				return {kind = .Invalid_Upload_Response}
			}

		}

	}
	return {}
}

// Tries at most16 advertised hosts. No redirects: media authentication tokens
// and encrypted uploads must stay on the selected server. Refreshing expired
// media_conn authentication is explicit in the caller's IQ orchestration.
media_upload :: proc(
	encrypted: []u8,
	kind: Media_Kind,
	metadata: Media_Metadata,
	connection: Media_Connection,
	config: network_client.Config,
	execute: Media_HTTP_Execute = nil,
) -> (
	Media_Upload_Result,
	Media_Error,
) {
	exchange := execute
	if exchange == nil do exchange = media_http_native

	if len(connection.hosts) == 0 ||
	   len(connection.hosts) > MAX_MEDIA_HOSTS {
		return {}, {kind = .Invalid_Connection}
	}

	if len(encrypted) < 26 ||
	   len(encrypted) > MAX_MEDIA_SIZE_LIMIT + 26 {
		return {}, {kind = .Invalid_Encrypted_Length}
	}

	if len(encrypted) > http.MAX_BODY_SIZE {
		return {}, {kind = .Media_Oversized}
	}

	if metadata.file_length > cast(u64)MAX_MEDIA_SIZE_LIMIT ||
	   cast(u64)len(encrypted) !=
		   (metadata.file_length / 16 + 1) * 16 + 10 {
		return {}, {kind = .Invalid_Encrypted_Length}
	}

	if media_hash(encrypted) != metadata.file_enc_sha256 {
		return {}, {kind = .Encrypted_Hash_Mismatch}
	}

	settings := config; settings.max_redirects = 0
	settings.max_body_size = 16384; settings.allow_http = false
	last := Media_Error {
		kind = .Invalid_Connection,
	}
	for host in connection.hosts {
		if host.max_content_length != 0 &&
		   cast(u64)len(encrypted) > host.max_content_length {
			last = {
				kind = .Media_Oversized,
			}; continue
		}

		url_buffer: [MAX_MEDIA_URL_SIZE]u8
		url, e := media_upload_url(
			url_buffer[:],
			host.hostname,
			connection.auth,
			kind,
			metadata.file_enc_sha256,
		)
		if e.kind != .None do return {}, e

		result, exchange_error := media_upload_exchange(exchange, url, encrypted, settings)
		if exchange_error.kind == .None do return result, {}
		last = exchange_error
	}
	return {}, last
}

media_upload_exchange :: proc(
	exchange: Media_HTTP_Execute, url: string, encrypted: []u8, settings: network_client.Config,
) -> (Media_Upload_Result, Media_Error) {
	response, he := exchange(
		{
			method = .POST,
			url = url,
			body = encrypted,
			headers = []http.Header {
				{"Content-Type", "application/octet-stream"},
				{"Origin", "https://web.whatsapp.com"},
			},
		},
		settings,
	)
	if he.kind != .None {
		return {}, {
			kind = .HTTP_Failed,
			http = he,
		}
	}

	if response.status < 200 || response.status >= 300 {
		status := response.status
		network_client.response_destroy(&response)
		return {}, {kind = .HTTP_Status, status = status}
	}

	result, parse_err := media_upload_response_decode(
		response.body,
	)
	network_client.response_destroy(&response)
	if parse_err.kind == .None do return result, {}

	return {}, parse_err
}

// Downloads the complete bounded ciphertext and verifies encrypted hash, MAC,
// CBC padding, plaintext length and plaintext hash before touching caller dst.
media_download :: proc(
	dst: []u8,
	message: Media_Message,
	config: network_client.Config,
	max_size: int = DEFAULT_MAX_MEDIA_SIZE,
	execute: Media_HTTP_Execute = nil,
) -> (
	int,
	Media_Error,
) {
	exchange := execute
	if exchange == nil do exchange = media_http_native

	if max_size < 0 || max_size > MAX_MEDIA_SIZE_LIMIT {
		return 0, {kind = .Invalid_Limit}
	}

	metadata, e := media_metadata_from_message(message)
	defer media_metadata_clear(&metadata)
	if e.kind != .None do return 0, e

	if metadata.file_length > cast(u64)max_size {
		return 0, {kind = .Media_Oversized}
	}

	if cast(u64)len(dst) < metadata.file_length {
		return cast(int)metadata.file_length, {
			kind = .Destination_Undersized,
		}
	}

	url_buffer: [MAX_MEDIA_URL_SIZE]u8
	url, validation := media_download_url(url_buffer[:], message)
	if validation.kind != .None do return 0, validation

	settings, settings_error := media_download_settings(config, &metadata)
	if settings_error.kind != .None do return 0, settings_error

	response, he := exchange(
		{
			method = .GET,
			url = url,
			headers = []http.Header {
				{"Origin", "https://web.whatsapp.com"},
			},
		},
		settings,
	)
	if he.kind != .None {
		return 0, {kind = .HTTP_Failed, http = he}
	}

	defer network_client.response_destroy(&response)
	if response.status != 200 {
		return 0, {kind = .HTTP_Status, status = response.status}
	}

	return media_decrypt(
		dst,
		response.body,
		message.kind,
		metadata,
		max_size,
	)
}

media_download_settings :: proc(
	config: network_client.Config, metadata: ^Media_Metadata,
) -> (network_client.Config, Media_Error) {
	settings := config; settings.max_redirects = 0
	settings.allow_http = false
	// An empty file is still a complete CBC block and ten-byte MAC.
	settings.max_body_size =
		(cast(int)metadata.file_length / 16 + 1) * 16 + 10
	// HTTP's body bound includes padding/MAC, unlike the crypto size bound.
	if settings.max_body_size > http.MAX_BODY_SIZE {
		return {}, {kind = .Media_Oversized}
	}

	return settings, {}
}

media_request_id_valid :: proc(id: string) -> bool {
	return len(id) > 0 && len(id) <= 128 && utf8.valid_string(id)
}
media_hostname_valid :: proc(host: string) -> bool {
	if len(host) == 0 ||
	   len(host) > 253 ||
	   host[0] == '.' ||
	   host[len(host) - 1] == '.' {
		return false
	}

	label := 0
	for c in transmute([]u8)host {
		if c == '.' {
			if label == 0 || label > 63 {
				return false
			}

			label = 0
			continue
		}

		if !(ascii.is_alphanumeric(c) ||
			   c == '-') {
			return false
		}

		label += 1
	}
	return label > 0 && label <= 63
}

Media_Retry_Result :: enum {
	General_Error    = 0,
	Success          = 1,
	Not_Found        = 2,
	Decryption_Error = 3,
}
// Decoded strings and message_secret borrow the authenticated caller buffer.
Media_Retry_Notification :: struct {
	stanza_id,
	direct_path:                                         string,
	result:                                                         Media_Retry_Result,
	message_secret:                                                 []u8,
	has_stanza_id,
	has_direct_path,
	has_result,
	has_message_secret: bool,
}
Media_Retry_Event :: struct {
	key:            Message_Key,
	ciphertext, iv: []u8,
	server_error:   u32,
}

// Fresh cryptographic nonce for each request, including retries. The recipient
// is the caller's normalized PN JID (without its device suffix).
media_retry_request_encode :: proc(
	dst: []u8,
	key: Message_Key,
	media_key: [32]u8,
	me_jid: string,
) -> (
	int,
	Media_Error,
) {
	when !crypto.HAS_RAND_BYTES do return 0, {kind = .Entropy_Unavailable}
	nonce: [12]u8; crypto.rand_bytes(nonce[:])
	return media_retry_request_with_nonce(
		dst,
		key,
		media_key,
		me_jid,
		nonce,
	)
}

// Explicit nonce entry point supports persisted uniqueness/deterministic tests.
// Never reuse a nonce with the same media key, even for the same stanza ID.
media_retry_request_with_nonce :: proc(
	dst: []u8,
	key: Message_Key,
	media_key: [32]u8,
	me_jid: string,
	nonce: [12]u8,
) -> (
	int,
	Media_Error,
) {
	if validation_error := media_retry_request_validate(key, me_jid);
	   validation_error.kind != .None do return 0, validation_error

	receipt: [256]u8
	writer := Media_Writer {
		dst = receipt[:],
	}; media_write_string(&writer, 1, key.id)
	if writer.err.kind != .None do return 0, writer.err

	retry_key := media_retry_key(media_key)
	defer crypto.zero_explicit(&retry_key, 32)
	ctx: aes.Context_GCM; aes.init_gcm(&ctx, retry_key[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	ciphertext: [272]u8
	defer crypto.zero_explicit(&ciphertext, size_of(ciphertext))
	iv := nonce
	aes.seal_gcm(
		&ctx,
		ciphertext[:writer.at],
		ciphertext[writer.at:writer.at + 16],
		iv[:],
		transmute([]u8)key.id,
		receipt[:writer.at],
	)
	return media_retry_receipt_encode(dst, key, me_jid, ciphertext[:writer.at + 16], iv[:])
}

media_retry_receipt_encode :: proc(
	dst: []u8, key: Message_Key, me_jid: string, ciphertext, iv: []u8,
) -> (int, Media_Error) {
	from_me := "false"; if key.from_me do from_me = "true"

	attrs := []Binary_Node_Attribute {
		{"jid", key.remote_jid},
		{"from_me", from_me},
		{"participant", key.participant},
	}
	if len(key.participant) == 0 do attrs = attrs[:2]

	node := Binary_Node {
		tag     = "receipt",
		attrs   = []Binary_Node_Attribute {
			{"id", key.id},
			{"to", me_jid},
			{"type", "server-error"},
		},
		content = []Binary_Node {
			{
				tag = "encrypt",
				content = []Binary_Node {
					{
						tag = "enc_p",
						content = ciphertext,
					},
					{tag = "enc_iv", content = iv},
				},
			},
			{tag = "rmr", attrs = attrs},
		},
	}
	n, e := binary_node_encode(dst, node)
	if e.kind != .None {
		return n, {kind = .Binary_Node_Failed, binary = e}
	}

	return n, {}
}

media_retry_request_validate :: proc(key: Message_Key, me_jid: string) -> Media_Error {
	if !media_request_id_valid(key.id) ||
	   len(key.remote_jid) == 0 ||
	   !utf8.valid_string(key.remote_jid) ||
	   !utf8.valid_string(key.participant) ||
	   len(me_jid) == 0 ||
	   !utf8.valid_string(me_jid) ||
	   strings.contains_rune(me_jid, ':') {
		return {kind = .Invalid_Retry}
	}

	if !strings.has_suffix(me_jid, "@s.whatsapp.net") {
		return {kind = .Invalid_Retry}
	}

	return {}
}

// Validate routing against the exact pending message key before accepting the
// encrypted response. Node/document storage must outlive the returned slices.
media_retry_event_decode :: proc(
	node: Binary_Node,
	expected: Message_Key,
) -> (
	Media_Retry_Event,
	Media_Error,
) {
	error_count, route_error := media_retry_event_route_validate(node, expected)
	if route_error.kind != .None do return {}, route_error

	event := Media_Retry_Event {
		key = expected,
	}
	if error_count == 1 {
		child := node_child(node, "error")
		text, _ := node_attr(child^, "code")
		code, valid := strconv.parse_uint(text, 10)
		if !valid || code > cast(uint)max(u32) {
			return {}, {kind = .Invalid_Retry}
		}

		event.server_error = cast(u32)code
		return event, {kind = .Server_Error, status = cast(int)code}
	}

	encrypted := node_child(node, "encrypt")
	parts, _ := encrypted.content.([]Binary_Node)
	for part in parts {
		if part.tag == "enc_p" {
			if event.ciphertext != nil {
				return {}, {kind = .Invalid_Retry}
			}

			event.ciphertext, _ = part.content.([]u8)
		}

		if part.tag == "enc_iv" {
			if event.iv != nil {
				return {}, {kind = .Invalid_Retry}
			}

			event.iv, _ = part.content.([]u8)
		}

	}
	if len(event.iv) != 12 ||
	   len(event.ciphertext) < 16 ||
	   len(event.ciphertext) > 8192 {
		return {}, {kind = .Invalid_Retry}
	}

	return event, {}
}

media_retry_event_route_validate :: proc(
	node: Binary_Node, expected: Message_Key,
) -> (int, Media_Error) {
	if !media_request_id_valid(expected.id) {
		return 0, {kind = .Invalid_Retry}
	}

	id, _ := node_attr(node, "id")
	kind, _ := node_attr(node, "type")
	if node.tag != "notification" ||
	   kind != "mediaretry" ||
	   id != expected.id {
		return 0, {kind = .Unexpected_Response}
	}

	rmr := node_child(node, "rmr")
	if rmr == nil do return 0, {kind = .Invalid_Retry}

	jid, _ := node_attr(rmr^, "jid")
	from_me, _ := node_attr(rmr^, "from_me")
	participant, _ := node_attr(rmr^, "participant")
	if jid != expected.remote_jid ||
	   participant != expected.participant ||
	   (!slice.contains([]string{"true", "false"}, from_me)) ||
	   (from_me == "true") != expected.from_me {
		return 0, {kind = .Unexpected_Response}
	}

	children, _ := node.content.([]Binary_Node)
	rmr_count, encrypt_count, error_count := 0, 0, 0
	for child in children {
		if child.tag == "rmr" do rmr_count += 1

		if child.tag == "encrypt" do encrypt_count += 1

		if child.tag == "error" do error_count += 1

	}
	if rmr_count != 1 ||
	   encrypt_count > 1 ||
	   error_count > 1 ||
	   encrypt_count + error_count != 1 {
		return 0, {kind = .Invalid_Retry}
	}

	return error_count, {}
}

// Authenticates in scratch storage; no plaintext or decoded fields become
// visible until both AES-GCM and all protobuf/routing validation succeed.
media_retry_decrypt :: proc(
	dst, ciphertext, nonce: []u8,
	media_key: [32]u8,
	expected_id: string,
) -> (
	Media_Retry_Notification,
	Media_Error,
) {
	if !media_request_id_valid(expected_id) ||
	   len(nonce) != 12 ||
	   len(ciphertext) < 16 ||
	   len(ciphertext) > 8192 {
		return {}, {kind = .Invalid_Retry}
	}

	n := len(ciphertext) - 16
	if len(dst) < n {
		return {}, {kind = .Destination_Undersized}
	}

	if bytes.alias(dst[:n], ciphertext) ||
	   bytes.alias(dst[:n], nonce) ||
	   bytes.alias(dst[:n], transmute([]u8)expected_id) {
		return {}, {kind = .Overlapping_Buffers}
	}

	scratch: [8192]u8
	defer crypto.zero_explicit(&scratch, size_of(scratch))
	retry_key := media_retry_key(media_key)
	defer crypto.zero_explicit(&retry_key, 32)
	ctx: aes.Context_GCM; aes.init_gcm(&ctx, retry_key[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	valid := aes.open_gcm(
		&ctx,
		scratch[:n],
		nonce,
		transmute([]u8)expected_id,
		ciphertext[:n],
		ciphertext[n:],
	)
	if !valid do return {}, {kind = .Authentication_Failed}

	notification, e := media_retry_notification_decode(scratch[:n])
	if e.kind != .None do return {}, e

	if notification.stanza_id != expected_id {
		return {}, {kind = .Unexpected_Response}
	}

	if notification.result == .Success {
		buffer: [MAX_MEDIA_URL_SIZE]u8
		_, validation := media_download_url(
			buffer[:],
			{direct_path = notification.direct_path},
		)
		if !notification.has_direct_path ||
		   validation.kind != .None {
			return {}, {kind = .Invalid_Retry}
		}

	}

	copy(dst, scratch[:n])
	return media_retry_notification_decode(dst[:n])
}

media_retry_key :: proc(media_key: [32]u8) -> [32]u8 {
	key := media_key; defer crypto.zero_explicit(&key, 32)
	result: [32]u8; salt: [32]u8
	info := "WhatsApp Media Retry Notification"
	hkdf.extract_and_expand(
		.SHA256,
		salt[:],
		key[:],
		transmute([]u8)info,
		result[:],
	)
	return result
}
media_retry_notification_decode :: proc(
	src: []u8,
) -> (
	notification: Media_Retry_Notification,
	err: Media_Error,
) {
	at := 0; seen: u8
	for at < len(src) {
		field, e := protobuf_field_read(src, &at)
		if e != .None {
			return {}, {kind = .Invalid_Protobuf, protobuf = e}
		}

		if field.number < 1 || field.number > 4 do continue

		bit := cast(u8)1 << field.number
		if seen & bit != 0 {
			return {}, {kind = .Duplicate_Field}
		}

		seen |= bit
		if field.number == 3 {
			if field.wire_type != 0 || field.value > 3 {
				return {}, {kind = .Invalid_Retry}
			}

			notification.result = cast(Media_Retry_Result)field.value
			notification.has_result = true; continue
		}

		if field.wire_type != 2 {
			return {}, {kind = .Invalid_Protobuf}
		}

		if field.number == 4 {
			if len(field.data) != 32 {
				return {}, {kind = .Invalid_Retry}
			}

			notification.message_secret = field.data
			notification.has_message_secret = true; continue
		}

		text := cast(string)field.data
		if !utf8.valid_string(text) {
			return {}, {kind = .Invalid_UTF8}
		}

		if field.number == 1 {
			notification.stanza_id = text
			notification.has_stanza_id = true
		} else {
			notification.direct_path = text
			notification.has_direct_path = true
		}

	}
	if !notification.has_stanza_id || !notification.has_result {
		return {}, {kind = .Invalid_Retry}
	}

	return notification, {}
}

// HTTP workers and WhatsApp event pumping.

// An HTTP worker never accesses Socket, its stores or its WebSocket. Borrowed
// request bytes, media metadata, connection strings and TLS roots remain alive
// until join. Its default thread allocator owns/frees all HTTP scratch state.
Socket_HTTP_Job :: struct {
	kind:                   enum {
		HTTP,
		Upload,
		Download,
	},
	done, cancel:           bool,
	request:                http.Request,
	config:                 network_client.Config,
	execute:                Media_HTTP_Execute,
	response:               network_client.Response,
	http_error:             network_client.HTTP_Error,
	encrypted, destination: []u8,
	media_kind:             Media_Kind,
	metadata:               Media_Metadata,
	connection:             Media_Connection,
	message:                Media_Message,
	result:                 Media_Upload_Result,
	n:                      int,
	media_error:            Media_Error,
}
@(thread_local)
socket_http_current_job: ^Socket_HTTP_Job

// Generic HTTP alongside the serialized WhatsApp event pump. An optional
// executor runs on the WORKER (unlike Socket_Config.http_execute, whose
// existing synchronous injection contract is retained for media helpers).
// Caller destroys a successful Response with network_client.response_destroy.
socket_http_execute :: proc(
	socket: ^Socket,
	request: http.Request,
	config: network_client.Config,
	execute: Media_HTTP_Execute = nil,
) -> (
	network_client.Response,
	Socket_Error,
) {
	job := Socket_HTTP_Job {
		kind    = .HTTP,
		request = request,
		config  = config,
		execute = execute,
	}
	defer crypto.zero_explicit(&job, size_of(job))
	e := socket_http_run(socket, &job)
	if e.kind != .None {
		network_client.response_destroy(&job.response); return {}, e
	}

	if job.http_error.kind != .None {
		return {}, {
			kind = .Media_Failed,
			media = {kind = .HTTP_Failed, http = job.http_error},
		}
	}

	return job.response, {}
}

socket_media_upload_http :: proc(
	socket: ^Socket,
	encrypted: []u8,
	kind: Media_Kind,
	metadata: Media_Metadata,
	connection: Media_Connection,
	config: network_client.Config,
) -> (
	Media_Upload_Result,
	Media_Error,
	Socket_Error,
) {
	if socket.config.http_execute != nil {
		result, e := media_upload(
			encrypted,
			kind,
			metadata,
			connection,
			config,
			execute = socket.config.http_execute,
		)
		return result, e, {}
	}

	job := Socket_HTTP_Job {
		kind       = .Upload,
		config     = config,
		encrypted  = encrypted,
		media_kind = kind,
		metadata   = metadata,
		connection = connection,
	}
	defer crypto.zero_explicit(&job, size_of(job))
	if e := socket_http_run(socket, &job); e.kind != .None {
		return {}, {}, e
	}

	return job.result, job.media_error, {}
}

socket_media_download_http :: proc(
	socket: ^Socket,
	dst: []u8,
	message: Media_Message,
	config: network_client.Config,
) -> (
	int,
	Media_Error,
	Socket_Error,
) {
	if socket.config.http_execute != nil {
		n, e := media_download(
			dst,
			message,
			config,
			execute = socket.config.http_execute,
		)
		return n, e, {}
	}

	// Reject local metadata/buffer failures before starting an event pump.
	metadata, validation := media_metadata_from_message(message)
	defer media_metadata_clear(&metadata)
	if validation.kind != .None do return 0, validation, {}

	if metadata.file_length > cast(u64)DEFAULT_MAX_MEDIA_SIZE {
		return 0, {kind = .Media_Oversized}, {}
	}

	if metadata.file_length > cast(u64)len(dst) {
		return cast(int)metadata.file_length, {
			kind = .Destination_Undersized,
		}, {}
	}

	url_storage: [MAX_MEDIA_URL_SIZE]u8
	_, url_error := media_download_url(url_storage[:], message)
	if url_error.kind != .None do return 0, url_error, {}

	// Keep failed Socket operations from exposing a completed worker's bytes.
	scratch, ae := make([]u8, cast(int)metadata.file_length)
	if ae != nil {
		return 0, {}, {kind = .Allocation_Failed, allocation = ae}
	}

	defer {
		crypto.zero_explicit(raw_data(scratch), len(scratch))
		delete(scratch)
	}
	job := Socket_HTTP_Job {
		kind        = .Download,
		config      = config,
		destination = scratch,
		message     = message,
	}
	defer crypto.zero_explicit(&job, size_of(job))
	if e := socket_http_run(socket, &job); e.kind != .None {
		return 0, {}, e
	}

	if job.media_error.kind == .None {
		copy(dst, job.destination[:job.n])
	}

	return job.n, job.media_error, {}
}

socket_http_worker :: proc(data: rawptr) {
	job := cast(^Socket_HTTP_Job)data
	socket_http_current_job = job
	defer {
		socket_http_current_job = nil
		sync.atomic_store(&job.done, true)
	}
	// A canceled multi-host upload does not begin another request. The active
	// request retains a bounded I/O deadline; DNS/TCP connection setup retains
	// the native HTTP client's platform resolver/dial limits.
	config := job.config
	if config.timeout == 0 || config.timeout > 30 * time.Second {
		config.timeout = 30 * time.Second
	}

	switch job.kind {
	case .HTTP:
		job.response, job.http_error = socket_http_worker_execute(
			job.request,
			config,
		)
	case .Upload:
		job.result, job.media_error = media_upload(
			job.encrypted,
			job.media_kind,
			job.metadata,
			job.connection,
			config,
			execute = socket_http_worker_execute,
		)
	case .Download:
		job.n, job.media_error = media_download(
			job.destination,
			job.message,
			config,
			execute = socket_http_worker_execute,
		)
	}
}

socket_http_worker_execute :: proc(
	request: http.Request,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	job := socket_http_current_job
	if sync.atomic_load(&job.cancel) {
		return {}, {kind = .Deadline_Failed}
	}

	response: network_client.Response
	e: network_client.HTTP_Error
	if job.execute != nil {
		response, e = job.execute(request, config)
	} else {
		response, e = network_client.execute(request, config)
	}

	if sync.atomic_load(&job.cancel) {
		network_client.response_destroy(&response)
		return {}, {kind = .Deadline_Failed}
	}

	return response, e
}

socket_http_run :: proc(
	socket: ^Socket,
	job: ^Socket_HTTP_Job,
) -> Socket_Error {
	if socket == nil || socket.phase != .Online {
		return {kind = .Invalid_State}
	}

	socket.query_depth += 1
	defer socket.query_depth -= 1
	worker := thread.create_and_start_with_data(
		job,
		socket_http_worker,
	)
	if worker == nil do return {kind = .Allocation_Failed}

	defer {
		sync.atomic_store(&job.cancel, true); thread.join(worker)
		thread.destroy(worker)
	}
	for !sync.atomic_load(&job.done) {
		if _, e := socket_tick(socket, time.now()); e.kind != .None {
			return e
		}

		ready, poll_error := socket_network_poll(
			socket,
			100 * time.Millisecond,
		)
		if poll_error.kind != .None do return poll_error

		if sync.atomic_load(&job.done) do break

		if !ready do continue

		event, e := socket_receive(socket)
		if e.kind != .None do return e

		if event.kind == .Restart_Required {
			return {kind = .Invalid_State}
		}

		if event_error := socket_http_event_process(socket, event);
		   event_error.kind != .None do return event_error
	}
	return {}
}

socket_media_retry_enqueue :: proc(socket: ^Socket, event: Socket_Event) -> Socket_Error {
	if len(socket.pending_media_retry) >= 16 {
		return socket_fail(socket, {kind = .Queue_Full})
	}

	size, measure := binary_node_encode(nil, event.node)
	if measure.kind != .Destination_Undersized ||
	   size > 16384 {
		return socket_fail(
			socket,
			{
				kind = .Media_Failed,
				media = {kind = .Invalid_Retry},
			},
		)
	}

	storage, ae := make([]u8, size)
	if ae != nil {
		return socket_fail(
			socket,
			{kind = .Allocation_Failed, allocation = ae},
		)
	}

	_, encoded := binary_node_encode(storage, event.node)
	if encoded.kind != .None {
		delete(storage)
		return socket_fail(
			socket,
			{kind = .Binary_Failed, binary = encoded},
		)
	}

	document, decoded := binary_node_decode(storage)
	delete(storage)
	if decoded.kind != .None {
		return socket_fail(
			socket,
			{kind = .Binary_Failed, binary = decoded},
		)
	}

	if _, append_err := append(
		&socket.pending_media_retry,
		document,
	); append_err != nil {
		binary_document_destroy(&document)
		return socket_fail(
			socket,
			{kind = .Allocation_Failed, allocation = append_err},
		)
	}

	return {}
}

socket_http_event_process :: proc(socket: ^Socket, event: Socket_Event) -> Socket_Error {
	if event.kind == .Message do return socket_query_message_enqueue(socket, event)
	if event.kind == .Node {
		kind, _ := node_attr(event.node, "type")
		if event.node.tag == "notification" && kind == "mediaretry" {
			return socket_media_retry_enqueue(socket, event)
		}
	}
	return {}
}

// Socket media send, download and retry operations.

// Returns an owned message ID, destroyed with delete(id) by the caller. Media
// is encrypted locally before upload; only its encrypted bytes reach HTTP.
socket_send_image :: proc(
	socket: ^Socket,
	group: string,
	plaintext: []u8,
	caption: string = "",
	mime_type: string = "image/jpeg",
) -> (
	string,
	Socket_Error,
) {
	return socket_send_media(
		socket,
		group,
		plaintext,
		.Image,
		caption,
		mime_type,
		"",
	)
}
socket_send_document :: proc(
	socket: ^Socket,
	group: string,
	plaintext: []u8,
	file_name: string,
	caption: string = "",
	mime_type: string = "application/pdf",
) -> (
	string,
	Socket_Error,
) {
	return socket_send_media(
		socket,
		group,
		plaintext,
		.Document,
		caption,
		mime_type,
		file_name,
	)
}

socket_send_reaction :: proc(
	socket: ^Socket,
	key: Message_Key,
	text: string = "✅",
) -> (
	string,
	Socket_Error,
) {
	if socket == nil || socket.phase != .Online {
		return "", {kind = .Invalid_State}
	}

	if !group_jid_valid(key.remote_jid) ||
	   !device_request_valid(key.id) ||
	   len(text) > 64 ||
	   !utf8.valid_string(text) {
		return "", {kind = .Invalid_Config}
	}

	buffer: [1024]u8
	n, e := reaction_message_encode(
		buffer[:],
		{
			key = key,
			has_key = true,
			text = text,
			has_text = true,
			sender_timestamp_ms = time.now()._nsec /
			cast(i64)time.Millisecond,
			has_sender_timestamp_ms = true,
		},
	)
	if e.kind != .None {
		return "", {kind = .Media_Failed, media = e}
	}

	return socket_send_group(socket, key.remote_jid, buffer[:n])
}

socket_send_media :: proc(
	socket: ^Socket,
	group: string,
	plaintext: []u8,
	kind: Media_Kind,
	caption, mime_type, file_name: string,
) -> (
	string,
	Socket_Error,
) {
	if validation_error := socket_media_send_validate(
		socket, group, plaintext, kind, caption, mime_type, file_name,
	); validation_error.kind != .None do return "", validation_error

	key, ke := media_key_generate()
	defer crypto.zero_explicit(&key, size_of(key))
	if ke.kind != .None {
		return "", {kind = .Media_Failed, media = ke}
	}

	ciphertext, ae := make([]u8, (len(plaintext) / 16 + 1) * 16 + 10)
	if ae != nil {
		return "", {kind = .Allocation_Failed, allocation = ae}
	}

	defer {
		crypto.zero_explicit(raw_data(ciphertext), len(ciphertext))
		delete(ciphertext)
	}
	n, metadata, e := media_encrypt(ciphertext, plaintext, kind, key)
	defer media_metadata_clear(&metadata)
	if e.kind != .None {
		return "", {kind = .Media_Failed, media = e}
	}

	uploaded, upload_error := socket_media_upload(socket, ciphertext[:n], kind, &metadata)
	if upload_error.kind != .None do return "", upload_error
	return socket_media_message_send(
		socket, group, kind, caption, mime_type, file_name, &uploaded, &metadata,
	)
}

socket_media_send_validate :: proc(
	socket: ^Socket, group: string, plaintext: []u8, kind: Media_Kind,
	caption, mime_type, file_name: string,
) -> Socket_Error {
	if socket == nil ||
	   socket.phase != .Online ||
	   socket.auth == nil {
		return {kind = .Invalid_State}
	}

	if !group_jid_valid(group) ||
	   len(caption) > 4096 ||
	   !utf8.valid_string(caption) ||
	   len(file_name) > 256 ||
	   !utf8.valid_string(file_name) {
		return {kind = .Invalid_Config}
	}

	if kind == .Image {
		if !slice.contains(
			[]string {
				"image/jpeg",
				"image/png",
				"image/webp",
				"image/gif",
			},
			mime_type,
		) {
			return {kind = .Invalid_Config}
		}

	} else if kind == .Document {
		if mime_type != "application/pdf" || len(file_name) == 0 {
			return {kind = .Invalid_Config}
		}

	} else {
		return {kind = .Invalid_Config}
	}

	if len(plaintext) > DEFAULT_MAX_MEDIA_SIZE {
		return {
			kind = .Media_Failed,
			media = {kind = .Media_Oversized},
		}
	}

	return {}
}

socket_media_upload :: proc(
	socket: ^Socket, ciphertext: []u8, kind: Media_Kind, metadata: ^Media_Metadata,
) -> (Media_Upload_Result, Socket_Error) {
	id_buffer: [128]u8; id := socket_next_id(socket, id_buffer[:])
	query_buffer: [512]u8
	qn, qe := media_connection_query_encode(query_buffer[:], id)
	if qe.kind != .None {
		return {}, {kind = .Media_Failed, media = qe}
	}

	query, de := binary_node_decode(query_buffer[:qn])
	if de.kind != .None {
		return {}, {kind = .Binary_Failed, binary = de}
	}

	defer binary_document_destroy(&query)
	response, re := socket_query(socket, query.root)
	if re.kind != .None do return {}, re

	defer binary_document_destroy(&response)
	hosts: [MAX_MEDIA_HOSTS]Media_Host
	connection, ce := media_connection_decode(
		response.root,
		id,
		hosts[:],
	)
	if ce.kind != .None {
		return {}, {kind = .Media_Failed, media = ce}
	}

	uploaded, ue, pump_error := socket_media_upload_http(
		socket,
		ciphertext,
		kind,
		metadata^,
		connection,
		{
			tls = socket.config.tls,
			timeout = socket.config.query_timeout,
		},
	)
	if pump_error.kind != .None do return {}, pump_error

	if ue.kind != .None {
		return {}, {kind = .Media_Failed, media = ue}
	}

	return uploaded, {}
}

socket_media_message_send :: proc(
	socket: ^Socket, group: string, kind: Media_Kind, caption, mime_type, file_name: string,
	uploaded: ^Media_Upload_Result, metadata: ^Media_Metadata,
) -> (string, Socket_Error) {
	message := Media_Message {
		kind                    = kind,
		url                     = cast(string)uploaded.url[:uploaded.url_size],
		direct_path             = cast(string)uploaded.direct_path[:uploaded.direct_path_size],
		mime_type               = mime_type,
		caption                 = caption,
		file_name               = file_name,
		media_key               = metadata.media_key[:],
		file_sha256             = metadata.file_sha256[:],
		file_enc_sha256         = metadata.file_enc_sha256[:],
		file_length             = metadata.file_length,
		has_file_length         = true,
		media_key_timestamp     = time.now()._nsec / cast(i64)time.Second,
		has_media_key_timestamp = true,
	}
	required, measure := media_message_encode(nil, message)
	if measure.kind != .Destination_Undersized {
		return "", {kind = .Media_Failed, media = measure}
	}

	protobuf, pe := make([]u8, required)
	if pe != nil {
		return "", {kind = .Allocation_Failed, allocation = pe}
	}

	defer {
		crypto.zero_explicit(raw_data(protobuf), len(protobuf))
		delete(protobuf)
	}
	_, encode_err := media_message_encode(protobuf, message)
	if encode_err.kind != .None {
		return "", {kind = .Media_Failed, media = encode_err}
	}

	media_type := "image"
	if kind == .Document do media_type = "document"

	return socket_send_group(socket, group, protobuf, media_type)
}

// Caller owns message/protobuf and destination. A404/410 CDN response triggers
// one authenticated request to the primary phone and one fresh download. No
// fallback removes integrity checks, changes the media key, or follows redirects.
socket_download_media :: proc(
	socket: ^Socket,
	message: ^Socket_Message,
	dst: []u8,
) -> (
	int,
	Socket_Error,
) {
	if socket == nil ||
	   socket.phase != .Online ||
	   socket.auth == nil {
		return 0, {kind = .Invalid_State}
	}

	if message == nil ||
	   !group_jid_valid(message.group) ||
	   !device_request_valid(message.id) {
		return 0, {kind = .Invalid_Config}
	}

	media, e := media_message_decode(message.protobuf)
	if e.kind != .None {
		return 0, {kind = .Media_Failed, media = e}
	}

	if media.kind == .None {
		return 0, {
			kind = .Media_Failed,
			media = {kind = .Invalid_Kind},
		}
	}

	config := network_client.Config {
		tls     = socket.config.tls,
		timeout = socket.config.query_timeout,
	}
	n, download_err, pump_error := socket_media_download_http(
		socket,
		dst,
		media,
		config,
	)
	if pump_error.kind != .None do return 0, pump_error

	if download_err.kind == .None do return n, {}

	if download_err.kind != .HTTP_Status ||
	   (!slice.contains(
				   []type_of(download_err.status){404, 410},
				   download_err.status,
			   )) {
		return n, {kind = .Media_Failed, media = download_err}
	}

	return socket_media_download_recover(socket, message, &media, dst, config)
}

socket_media_retry_send :: proc(
	socket: ^Socket, key: Message_Key, metadata: ^Media_Metadata,
) -> Socket_Error {
	owner_buffer: [256]u8
	owner, oe := socket_media_owner_jid(owner_buffer[:], socket.auth)
	if oe.kind != .None do return oe

	request: [2048]u8
	rn, request_err := media_retry_request_encode(
		request[:],
		key,
		metadata.media_key,
		owner,
	)
	if request_err.kind != .None {
		return {kind = .Media_Failed, media = request_err}
	}

	if se := socket_write(socket, request[:rn]); se.kind != .None {
		return se
	}

	return {}
}

socket_media_download_recover :: proc(
	socket: ^Socket, message: ^Socket_Message, media: ^Media_Message,
	dst: []u8, config: network_client.Config,
) -> (int, Socket_Error) {
	metadata, me := media_metadata_from_message(media^)
	defer media_metadata_clear(&metadata)
	if me.kind != .None {
		return 0, {kind = .Media_Failed, media = me}
	}

	key := Message_Key {
		remote_jid  = message.group,
		id          = message.id,
		participant = message.participant,
		from_me     = message.from_me,
	}
	if request_error := socket_media_retry_send(socket, key, &metadata);
	   request_error.kind != .None do return 0, request_error
	retry_buffer: [8192]u8
	defer crypto.zero_explicit(&retry_buffer, size_of(retry_buffer))
	notification, retry_err := socket_media_wait_retry(
		socket,
		key,
		metadata.media_key,
		retry_buffer[:],
	)
	if retry_err.kind != .None do return 0, retry_err

	if notification.result != .Success {
		return 0, {
			kind = .Media_Failed,
			media = {
				kind = .Server_Error,
				status = cast(int)notification.result,
			},
		}
	}

	media.url = ""; media.direct_path = notification.direct_path
	final_n, final_err, final_pump_error :=
		socket_media_download_http(socket, dst, media^, config)
	if final_pump_error.kind != .None {
		return 0, final_pump_error
	}

	if final_err.kind != .None {
		return final_n, {kind = .Media_Failed, media = final_err}
	}

	return final_n, {}
}

socket_media_owner_jid :: proc(
	dst: []u8,
	auth: ^Auth_State,
) -> (
	string,
	Socket_Error,
) {
	if auth == nil ||
	   auth.account.jid_size <= 0 ||
	   auth.account.jid_size > len(auth.account.jid) {
		return "", {kind = .Invalid_State}
	}

	jid := cast(string)auth.account.jid[:auth.account.jid_size]
	at := strings.index_byte(jid, '@')
	if at <= 0 || jid[at:] != "@s.whatsapp.net" {
		return "", {kind = .Invalid_Config}
	}

	local := jid[:at]
	if colon := strings.index_byte(local, ':'); colon >= 0 {
		local = local[:colon]
	}

	if agent := strings.index_byte(local, '_'); agent >= 0 {
		local = local[:agent]
	}

	if len(local) == 0 || len(local) + 15 > len(dst) {
		return "", {kind = .Invalid_Config}
	}

	n := copy(dst, transmute([]u8)local); suffix := "@s.whatsapp.net"
	n += copy(dst[n:], transmute([]u8)suffix)
	owner := cast(string)dst[:n]
	if !device_user_valid(owner, false) {
		return "", {kind = .Invalid_Config}
	}

	return owner, {}
}

socket_media_wait_retry :: proc(
	socket: ^Socket,
	key: Message_Key,
	media_key: [32]u8,
	plaintext: []u8,
) -> (
	Media_Retry_Notification,
	Socket_Error,
) {
	socket.query_depth += 1
	socket.read_deadline_scopes += 1
	defer {socket.query_depth -= 1; socket.read_deadline_scopes -= 1}
	timeout := socket.config.query_timeout
	if timeout == 0 do timeout = 30 * time.Second

	deadline := time.time_add(time.now(), timeout)
	for {
		for document, index in socket.pending_media_retry {
			id, _ := node_attr(document.root, "id")
			if id != key.id do continue

			owned := document
			ordered_remove(&socket.pending_media_retry, index)
			defer binary_document_destroy(&owned)
			return socket_media_notification_open(
				owned.root,
				key,
				media_key,
				plaintext,
			)
		}
		event, ready, read_error := socket_media_retry_event_read(socket, deadline)
		if read_error.kind != .None do return {}, read_error
		if !ready do continue
		if event.kind == .Restart_Required {
			return {}, {kind = .Invalid_State}
		}

		if event.kind == .Message {
			if queue_error := socket_query_message_enqueue(socket, event);
			   queue_error.kind != .None do return {}, queue_error
			continue
		}

		if event.kind != .Node || event.node.tag != "notification" {
			continue
		}

		kind, _ := node_attr(event.node, "type")
		id, _ := node_attr(event.node, "id")
		if kind != "mediaretry" || id != key.id do continue

		return socket_media_notification_open(
			event.node,
			key,
			media_key,
			plaintext,
		)
	}
}

socket_media_retry_event_read :: proc(
	socket: ^Socket, deadline: time.Time,
) -> (Socket_Event, bool, Socket_Error) {
	if time.now()._nsec >= deadline._nsec {
		return {}, false, socket_fail(socket, {kind = .Query_Timeout})
	}

	if _, e := socket_tick(socket, time.now()); e.kind != .None {
		return {}, false, e
	}

	ready, poll_err := socket_network_poll(
		socket,
		100 * time.Millisecond,
	)
	if poll_err.kind != .None do return {}, false, poll_err

	if !ready do return {}, false, {}

	if e := socket_read_deadline(socket, deadline);
	   e.kind != .None {
		return {}, false, e
	}

	event, e := socket_receive(socket)
	if e.kind != .None do return {}, false, e

	if reset := socket_read_deadline(socket, {});
	   reset.kind != .None {
		if event.message != nil {
			socket_message_destroy(event.message)
		}

		return {}, false, reset
	}

	return event, true, {}
}

socket_media_notification_open :: proc(
	node: Binary_Node,
	key: Message_Key,
	media_key: [32]u8,
	plaintext: []u8,
) -> (
	Media_Retry_Notification,
	Socket_Error,
) {
	retry, decode_err := media_retry_event_decode(node, key)
	if decode_err.kind != .None {
		return {}, {kind = .Media_Failed, media = decode_err}
	}

	notification, decrypt_err := media_retry_decrypt(
		plaintext,
		retry.ciphertext,
		retry.iv,
		media_key,
		key.id,
	)
	if decrypt_err.kind != .None {
		return {}, {kind = .Media_Failed, media = decrypt_err}
	}

	return notification, {}
}

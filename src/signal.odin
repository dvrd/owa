package whatsapp

import "core:bytes"
import "core:crypto"
import field "core:crypto/_fiat/field_curve25519"
import subtle "core:crypto/_subtle"
import "core:crypto/aes"
import "core:crypto/hkdf"
import "core:crypto/hmac"
import "core:crypto/x25519"
import endian "core:encoding/endian"
import "core:mem"
import "core:slice"

// Each record belongs to ONE (group JID, sender device) tuple. The caller must
// authenticate that tuple before processing a distribution (normally pairwise
// Signal). Distribution messages themselves carry no signature or identity.
MAX_GROUP_KEY_STATES :: 5
MAX_GROUP_SKIPPED_KEYS :: 2000
MAX_GROUP_FUTURE_MESSAGES :: 2000
MAX_GROUP_KEY_SNAPSHOT_SIZE :: 11 + MAX_GROUP_KEY_STATES * (111 + MAX_GROUP_SKIPPED_KEYS * 36) + 32
SIGNAL_GROUP_VERSION :: cast(u8)0x33

Signal_Group_Error :: enum {
	None,
	Invalid_State,
	Invalid_Protobuf,
	Invalid_Version,
	Missing_Field,
	Duplicate_Field,
	Invalid_Key,
	Invalid_Ciphertext,
	Unknown_Key,
	Conflicting_Key,
	Replay,
	Future_Limit,
	Counter_Exhausted,
	Destination_Undersized,
	Payload_Oversized,
	Overlapping_Buffers,
	Signature_Failed,
	Cipher_Failed,
	Entropy_Unavailable,
	Invalid_Snapshot,
	Checksum_Mismatch,
	Allocation_Failed,
}
Signal_Group_Distribution :: struct {
	id, iteration:              u32,
	chain_seed, signing_public: [32]u8,
}
// These slices borrow the wire buffer; retain it unchanged until verification
// and decryption finish. Distribution decode instead returns owned fixed arrays.
Signal_Group_Message :: struct {
	id, iteration:                       u32,
	ciphertext, signed_bytes, signature: []u8,
}
Signal_Group_Skipped_Key :: struct {
	iteration: u32,
	seed:      [32]u8,
}
Signal_Group_State :: struct {
	id:                                          u32,
	// u64 represents the exhausted sentinel max(u32)+1 without wrapping.
	next_iteration:                              u64,
	chain_seed, signing_public, signing_private: [32]u8,
	has_private:                                 bool,
	skipped:                                     [MAX_GROUP_SKIPPED_KEYS]Signal_Group_Skipped_Key,
	skipped_count:                               int,
}
// Oldest state first; rotation retains at most five states for delayed traffic.
// No allocation. All fields own their bytes. Never share a record between
// senders, and serialize callers. Clear records and snapshots after use.
Signal_Group_Record :: struct {
	states: [MAX_GROUP_KEY_STATES]Signal_Group_State,
	count:  int,
}

signal_group_record_clear :: proc(record: ^Signal_Group_Record) {
	if record != nil {
		crypto.zero_explicit(record, size_of(Signal_Group_Record))
	}
}

// Initial sender creation and explicit rotation use caller-provided entropy.
// A key ID must be fresh within this record. Persist the new record and deliver
// its distribution to recipients before sending messages using the new key.
signal_group_init_sender :: proc(
	record: ^Signal_Group_Record,
	id: u32,
	chain_seed, signing_private: [32]u8,
	iteration: u32 = 0,
) -> Signal_Group_Error {
	if e := group_record_validate(record); e != .None {
		return e
	}

	for s in record.states[:record.count] {
		if s.id == id {
			return .Conflicting_Key
		}
	}

	state := Signal_Group_State {
		id              = id,
		next_iteration  = cast(u64)iteration,
		chain_seed      = chain_seed,
		has_private     = true,
		signing_private = signing_private,
	}
	defer crypto.zero_explicit(&state, size_of(state))
	state.signing_private[0] &= 248
	state.signing_private[31] = state.signing_private[31] & 127 | 64
	state.signing_public = signal_curve_public(state.signing_private)
	group_state_append(record, &state)
	return .None
}

signal_group_distribution_encode :: proc(
	dst: []u8,
	record: ^Signal_Group_Record,
) -> (
	written: int,
	err: Signal_Group_Error,
) {
	if e := group_record_validate(record); e != .None {
		return 0, e
	}

	if record.count == 0 {
		return 0, .Unknown_Key
	}

	s := &record.states[record.count - 1]
	if s.next_iteration > cast(u64)max(u32) {
		return 0, .Counter_Exhausted
	}

	required :=
		1 +
		1 +
		protobuf_varint_size(cast(u64)s.id) +
		1 +
		protobuf_varint_size(s.next_iteration) +
		34 +
		35
	if len(dst) < required {
		return 0, .Destination_Undersized
	}

	if group_record_overlaps_buffer(record, dst[:required]) {
		return 0, .Overlapping_Buffers
	}

	dst[0] = SIGNAL_GROUP_VERSION
	written = 1
	group_uint_write(dst, &written, 1, cast(u64)s.id)
	group_uint_write(dst, &written, 2, s.next_iteration)
	group_bytes_write(dst, &written, 3, s.chain_seed[:])
	public: [33]u8
	public[0] = 5
	copy(public[1:], s.signing_public[:])
	group_bytes_write(dst, &written, 4, public[:])
	return written, .None
}

signal_group_distribution_decode :: proc(
	src: []u8,
) -> (
	d: Signal_Group_Distribution,
	err: Signal_Group_Error,
) {
	if len(src) > MAX_PROTOBUF_MESSAGE_SIZE {
		return {}, .Payload_Oversized
	}

	if len(src) < 1 {
		return {}, .Invalid_Protobuf
	}

	if src[0] != SIGNAL_GROUP_VERSION {
		return {}, .Invalid_Version
	}

	at, seen := 1, cast(u8)0

	for at < len(src) {
		f, e := protobuf_field_read(src, &at)
		if e != .None {
			return {}, .Invalid_Protobuf
		}

		if f.number < 1 || f.number > 4 {
			continue
		}

		mask := cast(u8)1 << f.number
		if seen & mask != 0 {
			return {}, .Duplicate_Field
		}

		seen |= mask

		if f.number <= 2 {
			if f.wire_type != 0 || f.value > cast(u64)max(u32) {
				return {}, .Invalid_Protobuf
			}

			if f.number == 1 {
				d.id = cast(u32)f.value
			} else {
				d.iteration = cast(u32)f.value
			}
		} else {
			if f.wire_type != 2 {
				return {}, .Invalid_Protobuf
			}

			if f.number == 3 {
				if len(f.data) != 32 {
					return {}, .Invalid_Key
				}

				copy(d.chain_seed[:], f.data)
			} else {
				if len(f.data) != 33 || f.data[0] != 5 {
					return {}, .Invalid_Key
				}

				copy(d.signing_public[:], f.data[1:])

				if !group_signing_public_key_valid(d.signing_public) {
					return {}, .Invalid_Key
				}
			}
		}
	}

	if seen != 30 {
		return {}, .Missing_Field
	}

	return d, .None
}

// Existing IDs never roll counters back or clear cached keys. A repeated
// distribution is idempotent; an authenticated newer distribution can advance
// the chain for recovery after a long gap. Changing signing identity is rejected.
// Sender rotation must allocate a new ID. This intentionally avoids the pinned
// JS implementation's duplicate-state behavior, which can resurrect old keys.
signal_group_distribution_process :: proc(
	record: ^Signal_Group_Record,
	wire: []u8,
) -> Signal_Group_Error {
	if e := group_record_validate(record); e != .None {
		return e
	}

	d, e := signal_group_distribution_decode(wire)
	defer crypto.zero_explicit(&d, size_of(d))
	if e != .None {
		return e
	}

	for &s in record.states[:record.count] {
		if s.id != d.id {
			continue
		}

		if crypto.compare_constant_time(s.signing_public[:], d.signing_public[:]) != 1 {
			return .Conflicting_Key
		}

		if cast(u64)d.iteration == s.next_iteration &&
		   crypto.compare_constant_time(s.chain_seed[:], d.chain_seed[:]) != 1 {
			return .Conflicting_Key
		}

		if cast(u64)d.iteration > s.next_iteration {
			// Authentication is provided by the pairwise distribution channel.
			// Keep already cached old keys, but do not restore consumed ones.
			s.next_iteration, s.chain_seed = cast(u64)d.iteration, d.chain_seed
		}

		return .None
	}

	state := Signal_Group_State {
		id             = d.id,
		next_iteration = cast(u64)d.iteration,
		chain_seed     = d.chain_seed,
		signing_public = d.signing_public,
	}

	defer crypto.zero_explicit(&state, size_of(state))
	group_state_append(record, &state)

	return .None
}

signal_group_message_decode :: proc(
	src: []u8,
) -> (
	m: Signal_Group_Message,
	err: Signal_Group_Error,
) {
	if len(src) > MAX_SIGNAL_CIPHERTEXT_SIZE + 128 {
		return {}, .Payload_Oversized
	}

	if len(src) < 65 {
		return {}, .Invalid_Protobuf
	}

	if src[0] != SIGNAL_GROUP_VERSION {
		return {}, .Invalid_Version
	}

	m.signed_bytes, m.signature = src[:len(src) - 64], src[len(src) - 64:]
	at, seen := 1, cast(u8)0

	for at < len(m.signed_bytes) {
		f, e := protobuf_field_read(m.signed_bytes, &at)
		if e != .None {
			return {}, .Invalid_Protobuf
		}

		if f.number < 1 || f.number > 3 {
			continue
		}

		mask := cast(u8)1 << f.number
		if seen & mask != 0 {
			return {}, .Duplicate_Field
		}

		seen |= mask

		if f.number <= 2 {
			if f.wire_type != 0 || f.value > cast(u64)max(u32) {
				return {}, .Invalid_Protobuf
			}

			if f.number == 1 {
				m.id = cast(u32)f.value
			} else {
				m.iteration = cast(u32)f.value
			}
		} else {
			if f.wire_type != 2 {
				return {}, .Invalid_Protobuf
			}

			m.ciphertext = f.data
		}
	}

	if seen != 14 {
		return {}, .Missing_Field
	}

	if len(m.ciphertext) == 0 || len(m.ciphertext) % 16 != 0 {
		return {}, .Invalid_Ciphertext
	}

	if len(m.ciphertext) > MAX_SIGNAL_CIPHERTEXT_SIZE {
		return {}, .Payload_Oversized
	}

	return m, .None
}

// Low-level signed envelope encoder. Ciphertext must already be CBC padded.
signal_group_message_encode :: proc(
	dst: []u8,
	id, iteration: u32,
	ciphertext: []u8,
	signing_private: [32]u8,
) -> (
	written: int,
	err: Signal_Group_Error,
) {
	if len(ciphertext) == 0 || len(ciphertext) % 16 != 0 {
		return 0, .Invalid_Ciphertext
	}

	if len(ciphertext) > MAX_SIGNAL_CIPHERTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	size := group_message_header_size(id, iteration, len(ciphertext)) + len(ciphertext) + 64

	if len(dst) < size {
		return 0, .Destination_Undersized
	}

	if bytes.alias(dst[:size], ciphertext) {
		return 0, .Overlapping_Buffers
	}

	when !crypto.HAS_RAND_BYTES {
		return 0, .Entropy_Unavailable
	}

	written = write_group_message_header(dst, id, iteration, len(ciphertext))
	written += copy(dst[written:], ciphertext)
	signature, e := signal_curve_sign(signing_private, dst[:written])

	if e != .None {
		return 0, .Signature_Failed
	}

	written += copy(dst[written:], signature[:])

	return written, .None
}

// Caller transaction rule: operate on a candidate record, persist it durably,
// then transmit ciphertext/expose plaintext and replace the live record. A
// crash must not reuse a sender counter or resurrect consumed receiver keys.
// Every failure leaves the record unchanged; no failed decrypt writes dst.
// Pinned encrypt() intentionally uses 0,2,4,... counters after starting at0.
signal_group_encrypt :: proc(
	dst: []u8,
	record: ^Signal_Group_Record,
	plaintext: []u8,
) -> (
	written: int,
	err: Signal_Group_Error,
) {
	if e := group_record_validate(record); e != .None {
		return 0, e
	}

	if record.count == 0 {
		return 0, .Unknown_Key
	}

	s := &record.states[record.count - 1]
	if !s.has_private {
		return 0, .Invalid_Key
	}

	iteration := s.next_iteration
	if iteration != 0 {
		iteration += 1
	}

	if iteration > cast(u64)max(u32) {
		return 0, .Counter_Exhausted
	}

	if len(plaintext) > MAX_SIGNAL_PLAINTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	cipher_size := (len(plaintext) / 16 + 1) * 16
	header_size := group_message_header_size(s.id, cast(u32)iteration, cipher_size)
	size := header_size + cipher_size + 64
	if len(dst) < size {
		return 0, .Destination_Undersized
	}

	if bytes.alias(dst[:size], plaintext) ||
	   group_record_overlaps_buffer(record, dst[:size]) ||
	   group_record_overlaps_buffer(record, plaintext) {
		return 0, .Overlapping_Buffers
	}

	when !crypto.HAS_RAND_BYTES {
		return 0, .Entropy_Unavailable
	}
	candidate := s^
	defer crypto.zero_explicit(&candidate, size_of(candidate))
	seed, e := group_message_seed(&candidate, cast(u32)iteration)
	defer crypto.zero_explicit(&seed, size_of(seed))
	if e != .None {
		return 0, e
	}

	keys := signal_group_message_keys(seed)
	defer crypto.zero_explicit(&keys, size_of(keys))
	_, ce := signal_cbc_encrypt(
		dst[header_size:][:cipher_size],
		keys.cipher_key,
		keys.iv,
		plaintext,
	)
	if ce != .None {
		return 0, .Cipher_Failed
	}

	signed_size, sign_error := group_message_sign(dst, s, iteration, cipher_size)
	if sign_error != .None {
		return 0, sign_error
	}

	s^ = candidate
	return signed_size, .None
}

group_message_sign :: proc(
	dst: []u8,
	s: ^Signal_Group_State,
	iteration: u64,
	cipher_size: int,
) -> (
	written: int,
	error: Signal_Group_Error,
) {
	written = write_group_message_header(dst, s.id, cast(u32)iteration, cipher_size) + cipher_size
	signature, se := signal_curve_sign(s.signing_private, dst[:written])
	if se != .None {
		return 0, .Signature_Failed
	}

	written += copy(dst[written:], signature[:])
	return written, .None
}

signal_group_decrypt :: proc(
	dst: []u8,
	record: ^Signal_Group_Record,
	wire: []u8,
) -> (
	written: int,
	err: Signal_Group_Error,
) {
	if e := group_record_validate(record); e != .None {
		return 0, e
	}

	m, e := signal_group_message_decode(wire)
	if e != .None {
		return 0, e
	}

	if bytes.alias(dst, wire) ||
	   group_record_overlaps_buffer(record, dst) ||
	   group_record_overlaps_buffer(record, wire) {
		return 0, .Overlapping_Buffers
	}

	index := -1
	for s, i in record.states[:record.count] {
		if s.id == m.id {
			index = i
		}
	}

	if index < 0 {
		return 0, .Unknown_Key
	}

	s := &record.states[index]
	if signal_curve_verify(s.signing_public, m.signed_bytes, m.signature) != .None {
		return 0, .Signature_Failed
	}

	candidate := s^
	defer crypto.zero_explicit(&candidate, size_of(candidate))
	seed, ke := group_message_seed(&candidate, m.iteration)
	defer crypto.zero_explicit(&seed, size_of(seed))
	if ke != .None {
		return 0, ke
	}

	keys := signal_group_message_keys(seed)
	defer crypto.zero_explicit(&keys, size_of(keys))
	count, ce := signal_cbc_decrypt(dst, keys.cipher_key, keys.iv, m.ciphertext)
	if ce != .None {
		if ce == .Destination_Undersized {
			return 0, .Destination_Undersized
		}

		return 0, .Cipher_Failed
	}

	s^ = candidate
	return count, .None
}

group_message_seed :: proc(
	state: ^Signal_Group_State,
	iteration: u32,
) -> (
	seed: [32]u8,
	err: Signal_Group_Error,
) {
	if state.next_iteration > cast(u64)iteration {
		for key, i in state.skipped[:state.skipped_count] {
			if key.iteration != iteration {
				continue
			}

			seed = key.seed
			for j in i ..< state.skipped_count - 1 {
				state.skipped[j] = state.skipped[j + 1]
			}
			state.skipped_count -= 1
			crypto.zero_explicit(
				&state.skipped[state.skipped_count],
				size_of(Signal_Group_Skipped_Key),
			)
			return seed, .None
		}

		return {}, .Replay
	}

	if cast(u64)iteration - state.next_iteration > MAX_GROUP_FUTURE_MESSAGES {
		return {}, .Future_Limit
	}

	for state.next_iteration <= cast(u64)iteration {
		keys := signal_chain_keys(state.chain_seed)
		state.chain_seed = keys.next_chain_key
		current := cast(u32)state.next_iteration
		state.next_iteration += 1

		if current == iteration {
			seed = keys.message_seed
			crypto.zero_explicit(&keys, size_of(keys))
			return seed, .None
		}

		if state.skipped_count == MAX_GROUP_SKIPPED_KEYS {
			for i in 0 ..< state.skipped_count - 1 {
				state.skipped[i] = state.skipped[i + 1]
			}
			state.skipped_count -= 1
		}

		state.skipped[state.skipped_count] = {
			iteration = current,
			seed      = keys.message_seed,
		}

		state.skipped_count += 1
		crypto.zero_explicit(&keys, size_of(keys))
	}

	return {}, .Counter_Exhausted
}

group_state_append :: proc(record: ^Signal_Group_Record, state: ^Signal_Group_State) {
	if record.count == MAX_GROUP_KEY_STATES {
		for i in 0 ..< record.count - 1 {
			record.states[i] = record.states[i + 1]
		}
		record.count -= 1
	}

	record.states[record.count] = state^
	record.count += 1
}
group_signing_public_key_valid :: proc(public: [32]u8) -> bool {
	// Strict verifier validates the public point before reading R/S. Deliberately
	// invalid R makes this a public-point check without duplicating curve code.
	zero: [64]u8

	return signal_curve_verify(public, nil, zero[:]) != .Invalid_Public_Key
}
group_record_validate :: proc(record: ^Signal_Group_Record) -> Signal_Group_Error {
	if record == nil || record.count < 0 || record.count > MAX_GROUP_KEY_STATES {
		return .Invalid_State
	}

	for &s, i in record.states[:record.count] {
		if s.next_iteration > cast(u64)max(u32) + 1 ||
		   s.skipped_count < 0 ||
		   s.skipped_count > MAX_GROUP_SKIPPED_KEYS ||
		   !group_signing_public_key_valid(s.signing_public) {
			return .Invalid_State
		}

		for previous in record.states[:i] {
			if previous.id == s.id {
				return .Invalid_State
			}
		}

		if s.has_private {
			public := signal_curve_public(s.signing_private)

			if crypto.compare_constant_time(public[:], s.signing_public[:]) != 1 {
				return .Invalid_Key
			}
		} else if crypto.is_zero_constant_time(s.signing_private[:]) != 1 {
			return .Invalid_Key
		}

		previous: u64

		for key, j in s.skipped[:s.skipped_count] {
			if cast(u64)key.iteration >= s.next_iteration ||
			   (j > 0 && cast(u64)key.iteration <= previous) {
				return .Invalid_State
			}

			previous = cast(u64)key.iteration
		}
	}

	return .None
}
group_record_overlaps_buffer :: proc(record: ^Signal_Group_Record, src: []u8) -> bool {
	return bytes.alias((cast(^[size_of(Signal_Group_Record)]u8)record)[:], src)
}
group_uint_write :: proc(dst: []u8, at: ^int, field: u32, value: u64) {
	protobuf_varint_write(dst, at, cast(u64)field << 3)
	protobuf_varint_write(dst, at, value)
}
group_message_header_size :: proc(id, iteration: u32, size: int) -> int {
	return(
		1 +
		1 +
		protobuf_varint_size(cast(u64)id) +
		1 +
		protobuf_varint_size(cast(u64)iteration) +
		1 +
		protobuf_varint_size(cast(u64)size) \
	)
}
write_group_message_header :: proc(dst: []u8, id, iteration: u32, size: int) -> int {
	dst[0] = SIGNAL_GROUP_VERSION
	at := 1
	group_uint_write(dst, &at, 1, cast(u64)id)
	group_uint_write(dst, &at, 2, cast(u64)iteration)
	protobuf_varint_write(dst, &at, 26)
	protobuf_varint_write(dst, &at, cast(u64)size)

	return at
}

// Versioned private snapshot. SHA256 detects corruption, not malicious edits;
// confidentiality, storage identity binding and atomic durable commits belong
// to the caller's store. Never load an older snapshot after a successful commit.
signal_group_record_encode :: proc(
	dst: []u8,
	record: ^Signal_Group_Record,
) -> (
	int,
	Signal_Group_Error,
) {
	if e := group_record_validate(record); e != .None {
		return 0, e
	}

	size := 11 + 32
	for s in record.states[:record.count] {
		size += 111 + s.skipped_count * 36
	}
	if len(dst) < size {
		return 0, .Destination_Undersized
	}

	if group_record_overlaps_buffer(record, dst[:size]) {
		return 0, .Overlapping_Buffers
	}

	copy(dst, []u8{'O', 'D', 'G', 'R', 'O', 'U', 'P', 0})
	at := 8
	endian.unchecked_put_u16be(dst[at:][:2], 1)
	at += 2
	dst[at] = u8(record.count)
	at += 1

	for &s in record.states[:record.count] {
		endian.unchecked_put_u32be(dst[at:][:4], s.id)
		at += 4
		endian.unchecked_put_u64be(dst[at:][:8], s.next_iteration)
		at += 8
		at += copy(dst[at:], s.chain_seed[:])
		at += copy(dst[at:], s.signing_public[:])
		at += copy(dst[at:], s.signing_private[:])
		dst[at] = s.has_private ? 1 : 0
		at += 1
		endian.unchecked_put_u16be(dst[at:][:2], u16(s.skipped_count))
		at += 2

		for &key in s.skipped[:s.skipped_count] {
			endian.unchecked_put_u32be(dst[at:][:4], key.iteration)
			at += 4
			at += copy(dst[at:], key.seed[:])
		}
	}

	digest := sha256(dst[:at])
	copy(dst[at:], digest[:])

	return size, .None
}

signal_group_record_decode :: proc(record: ^Signal_Group_Record, src: []u8) -> Signal_Group_Error {
	if record == nil {
		return .Invalid_State
	}

	if len(src) > MAX_GROUP_KEY_SNAPSHOT_SIZE {
		return .Payload_Oversized
	}

	if len(src) < 43 || !bytes.equal(src[:8], []u8{'O', 'D', 'G', 'R', 'O', 'U', 'P', 0}) {
		return .Invalid_Snapshot
	}

	if group_record_overlaps_buffer(record, src) {
		return .Overlapping_Buffers
	}

	end := len(src) - 32
	digest := sha256(src[:end])

	if crypto.compare_constant_time(digest[:], src[end:]) != 1 {
		return .Checksum_Mismatch
	}

	at := 8

	version := endian.unchecked_get_u16be(src[at:][:2])
	at += 2
	if version != 1 {
		return .Invalid_Snapshot
	}

	allocator := context.allocator
	next, allocation_err := new(Signal_Group_Record, allocator)
	if allocation_err != nil {
		return .Allocation_Failed
	}

	defer {
		signal_group_record_clear(next)
		free(next, allocator)
	}

	next.count = cast(int)src[at]
	at += 1

	if next.count > MAX_GROUP_KEY_STATES {
		return .Invalid_Snapshot
	}

	if state_error := group_snapshot_states_decode(next, src, &at, end); state_error != .None {
		return state_error
	}
	if at != end {
		return .Invalid_Snapshot
	}

	if e := group_record_validate(next); e != .None {
		return e
	}

	signal_group_record_clear(record)
	record^ = next^

	return .None
}

group_snapshot_states_decode :: proc(
	next: ^Signal_Group_Record,
	src: []u8,
	at: ^int,
	end: int,
) -> Signal_Group_Error {
	for &s in next.states[:next.count] {
		if end - at^ < 111 {
			return .Invalid_Snapshot
		}

		s.id = endian.unchecked_get_u32be(src[at^:][:4])
		at^ += 4
		s.next_iteration = endian.unchecked_get_u64be(src[at^:][:8])
		at^ += 8
		at^ += copy(s.chain_seed[:], src[at^:][:32])
		at^ += copy(s.signing_public[:], src[at^:][:32])
		at^ += copy(s.signing_private[:], src[at^:][:32])
		flag := src[at^]
		at^ += 1
		if flag > 1 {
			return .Invalid_Snapshot
		}

		s.has_private = flag == 1
		s.skipped_count = cast(int)endian.unchecked_get_u16be(src[at^:][:2])
		at^ += 2

		if s.skipped_count > MAX_GROUP_SKIPPED_KEYS || s.skipped_count * 36 > end - at^ {
			return .Invalid_Snapshot
		}

		for &key in s.skipped[:s.skipped_count] {
			key.iteration = endian.unchecked_get_u32be(src[at^:][:4])
			at^ += 4
			at^ += copy(key.seed[:], src[at^:][:32])
		}
	}

	return .None
}

group_bytes_write :: proc(dst: []u8, at: ^int, field: u32, value: []u8) {
	protobuf_varint_write(dst, at, cast(u64)field << 3 | 2)
	protobuf_varint_write(dst, at, cast(u64)len(value))
	at^ += copy(dst[at^:], value)
}

// Wire-compatible crypto labels/layouts from libsignal-node
// bcea72df9ec34d9d9140ab30619cf479c7c144c7.
// This module is stateless: callers commit chain/counter changes only after
// authenticating/decrypting successfully, and must erase returned key structs.
MAX_SIGNAL_PLAINTEXT_SIZE :: 1 << 20
MAX_SIGNAL_CIPHERTEXT_SIZE :: MAX_SIGNAL_PLAINTEXT_SIZE + aes.BLOCK_SIZE
SIGNAL_MESSAGE_MAC_SIZE :: 8

Signal_Key_Error :: enum {
	None,
	Payload_Oversized,
	Destination_Undersized,
	Overlapping_Buffers,
	Invalid_Ciphertext_Length,
	Invalid_Padding,
	Invalid_MAC_Length,
	Authentication_Failed,
}

Signal_Chain_Keys :: struct {
	message_seed, next_chain_key: [32]u8,
}

Signal_Message_Keys :: struct {
	cipher_key, mac_key: [32]u8,
	iv:                  [16]u8,
}

Signal_Ratchet_Keys :: struct {
	root_key, chain_key: [32]u8,
}

Signal_Group_Message_Keys :: struct {
	cipher_key: [32]u8,
	iv:         [16]u8,
}

signal_chain_keys :: proc(chain_key: [32]u8) -> (keys: Signal_Chain_Keys) {
	secret := chain_key
	defer crypto.zero_explicit(&secret, size_of(secret))
	hmac.sum(.SHA256, keys.message_seed[:], []u8{1}, secret[:])
	hmac.sum(.SHA256, keys.next_chain_key[:], []u8{2}, secret[:])

	return keys
}

signal_message_keys :: proc(message_seed: [32]u8) -> (keys: Signal_Message_Keys) {
	seed := message_seed
	defer crypto.zero_explicit(&seed, size_of(seed))
	salt: [32]u8
	derived: [96]u8
	defer crypto.zero_explicit(&derived, size_of(derived))
	label := "WhisperMessageKeys"
	hkdf.extract_and_expand(.SHA256, salt[:], seed[:], transmute([]u8)label, derived[:])
	copy(keys.cipher_key[:], derived[:32])
	copy(keys.mac_key[:], derived[32:64])
	copy(keys.iv[:], derived[64:80])

	return keys
}

// shared is an already-validated DH result, not a peer public key. The DH
// layer must reject invalid/low-order points before calling this KDF.
signal_ratchet_keys :: proc(root_key, shared: [32]u8) -> (keys: Signal_Ratchet_Keys) {
	root, dh := root_key, shared
	defer crypto.zero_explicit(&root, size_of(root))
	defer crypto.zero_explicit(&dh, size_of(dh))
	derived: [64]u8
	defer crypto.zero_explicit(&derived, size_of(derived))
	label := "WhisperRatchet"
	hkdf.extract_and_expand(.SHA256, root[:], dh[:], transmute([]u8)label, derived[:])
	copy(keys.root_key[:], derived[:32])
	copy(keys.chain_key[:], derived[32:])

	return keys
}

signal_group_message_keys :: proc(message_seed: [32]u8) -> (keys: Signal_Group_Message_Keys) {
	seed := message_seed
	defer crypto.zero_explicit(&seed, size_of(seed))
	salt: [32]u8
	derived: [48]u8
	defer crypto.zero_explicit(&derived, size_of(derived))
	label := "WhisperGroup"
	hkdf.extract_and_expand(.SHA256, salt[:], seed[:], transmute([]u8)label, derived[:])
	copy(keys.iv[:], derived[:16])
	copy(keys.cipher_key[:], derived[16:48])

	return keys
}

// AES-256-CBC with PKCS#7 padding, including a full padding block for aligned
// input. This is not authenticated encryption: message MAC/signature verification
// belongs above CBC. No allocation; plaintext and written dst must not overlap.
signal_cbc_encrypt :: proc(
	dst: []u8,
	key: [32]u8,
	iv: [16]u8,
	plaintext: []u8,
) -> (
	written: int,
	error: Signal_Key_Error,
) {
	if len(plaintext) > MAX_SIGNAL_PLAINTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	required := (len(plaintext) / aes.BLOCK_SIZE + 1) * aes.BLOCK_SIZE
	if len(dst) < required {
		return 0, .Destination_Undersized
	}

	if bytes.alias(dst[:required], plaintext) {
		return 0, .Overlapping_Buffers
	}

	secret := key
	defer crypto.zero_explicit(&secret, size_of(secret))
	ctx: aes.Context_ECB
	aes.init_ecb(&ctx, secret[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	chain := iv
	block: [16]u8
	defer crypto.zero_explicit(&chain, size_of(chain))
	defer crypto.zero_explicit(&block, size_of(block))
	padding := cast(u8)(required - len(plaintext))
	for at := 0; at < required; at += aes.BLOCK_SIZE {
		for i in 0 ..< aes.BLOCK_SIZE {
			value := padding

			if at + i < len(plaintext) {
				value = plaintext[at + i]
			}

			block[i] = value ~ chain[i]
		}

		aes.encrypt_ecb(&ctx, dst[at:][:aes.BLOCK_SIZE], block[:])
		copy(chain[:], dst[at:][:aes.BLOCK_SIZE])
	}
	return required, .None
}

// Call only after verifying the message MAC (pairwise) or signature (group).
// Padding is checked from a local last-block copy before touching dst, so any
// failure leaves both the ciphertext and the destination unchanged. IV/key are
// passed by value; the caller's chain/counter state is never modified here.
signal_cbc_decrypt :: proc(
	dst: []u8,
	key: [32]u8,
	iv: [16]u8,
	ciphertext: []u8,
) -> (
	written: int,
	error: Signal_Key_Error,
) {
	if len(ciphertext) > MAX_SIGNAL_CIPHERTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	if len(ciphertext) == 0 || len(ciphertext) % aes.BLOCK_SIZE != 0 {
		return 0, .Invalid_Ciphertext_Length
	}

	if bytes.alias(dst, ciphertext) {
		return 0, .Overlapping_Buffers
	}

	secret := key
	defer crypto.zero_explicit(&secret, size_of(secret))
	ctx: aes.Context_ECB
	aes.init_ecb(&ctx, secret[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	last: [16]u8
	defer crypto.zero_explicit(&last, size_of(last))
	final_at := len(ciphertext) - aes.BLOCK_SIZE
	aes.decrypt_ecb(&ctx, last[:], ciphertext[final_at:])
	previous := iv
	if final_at > 0 {
		copy(previous[:], ciphertext[final_at - aes.BLOCK_SIZE:final_at])
	}

	for &value, i in last {
		value ~= previous[i]
	}
	padding, padding_error := signal_cbc_padding_size(last[:])
	if padding_error != .None {
		return 0, padding_error
	}

	written = len(ciphertext) - cast(int)padding
	if written > MAX_SIGNAL_PLAINTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	if len(dst) < written {
		return 0, .Destination_Undersized
	}

	signal_cbc_blocks_decrypt(&ctx, dst, ciphertext, iv, final_at)
	copy(dst[final_at:written], last[:aes.BLOCK_SIZE - cast(int)padding])
	return written, .None
}

signal_cbc_blocks_decrypt :: proc(
	ctx: ^aes.Context_ECB,
	dst, ciphertext: []u8,
	iv: [16]u8,
	final_at: int,
) {
	chain := iv
	block: [16]u8
	defer crypto.zero_explicit(&chain, size_of(chain))
	defer crypto.zero_explicit(&block, size_of(block))

	for at := 0; at < final_at; at += aes.BLOCK_SIZE {
		aes.decrypt_ecb(ctx, block[:], ciphertext[at:][:aes.BLOCK_SIZE])
		for &value, i in block {
			value ~= chain[i]
		}
		copy(dst[at:][:aes.BLOCK_SIZE], block[:])
		copy(chain[:], ciphertext[at:][:aes.BLOCK_SIZE])
	}
}

signal_cbc_padding_size :: proc(last: []u8) -> (u32, Signal_Key_Error) {
	padding := cast(u32)last[15]
	valid_length := subtle.le(cast(u32)1, padding) & subtle.le(padding, cast(u32)16)
	bad := valid_length ~ 1

	for i in 0 ..< 16 {
		selected := subtle.lt(cast(u32)i, padding)
		bad |= (cast(u32)last[15 - i] ~ padding) & (0 - selected)
	}

	if bad != 0 {
		return 0, .Invalid_Padding
	}

	return padding, .None
}

// serialized_message includes its version byte (normally 0x33), followed by
// WhisperMessage protobuf bytes. Both identity prefixes 0x05 are part of the
// MAC input, in sender then receiver order; identity arguments are raw32.
signal_message_mac :: proc(
	mac_key, sender_identity, receiver_identity: [32]u8,
	serialized_message: []u8,
) -> (
	mac: [SIGNAL_MESSAGE_MAC_SIZE]u8,
	error: Signal_Key_Error,
) {
	if len(serialized_message) > MAX_SIGNAL_CIPHERTEXT_SIZE + 1024 {
		return {}, .Payload_Oversized
	}

	secret := mac_key
	defer crypto.zero_explicit(&secret, size_of(secret))
	sender, receiver := sender_identity, receiver_identity
	ctx: hmac.Context
	defer crypto.zero_explicit(&ctx, size_of(ctx))
	digest: [32]u8
	defer crypto.zero_explicit(&digest, size_of(digest))
	hmac.init(&ctx, .SHA256, secret[:])
	hmac.update(&ctx, []u8{5})
	hmac.update(&ctx, sender[:])
	hmac.update(&ctx, []u8{5})
	hmac.update(&ctx, receiver[:])
	hmac.update(&ctx, serialized_message)
	hmac.final(&ctx, digest[:])
	copy(mac[:], digest[:SIGNAL_MESSAGE_MAC_SIZE])
	return mac, .None
}

signal_message_mac_verify :: proc(
	mac_key, sender_identity, receiver_identity: [32]u8,
	serialized_message, mac: []u8,
) -> Signal_Key_Error {
	if len(mac) != SIGNAL_MESSAGE_MAC_SIZE {
		return .Invalid_MAC_Length
	}

	expected, err := signal_message_mac(
		mac_key,
		sender_identity,
		receiver_identity,
		serialized_message,
	)
	if err != .None {
		return err
	}

	defer crypto.zero_explicit(&expected, size_of(expected))
	if crypto.compare_constant_time(expected[:], mac) != 1 {
		return .Authentication_Failed
	}

	return .None
}

SIGNAL_SESSION_WIRE_VERSION :: cast(u8)0x33
MAX_SIGNAL_SKIPPED_KEYS :: 2000
MAX_SIGNAL_RECEIVING_CHAINS :: 32
MAX_SIGNAL_PACKET_SIZE :: MAX_SIGNAL_CIPHERTEXT_SIZE + 256
MAX_SIGNAL_SESSION_STORE_SIZE ::
	330 + MAX_SIGNAL_RECEIVING_CHAINS * 74 + MAX_SIGNAL_SKIPPED_KEYS * 39
SIGNAL_SESSION_STORE_MAGIC :: "ODWSIGS\x00"

Signal_Prekey_Bundle :: struct {
	registration_id:         u32,
	identity_public:         [32]u8,
	signed_prekey_id:        u32,
	signed_prekey_public:    [32]u8,
	signed_prekey_signature: [64]u8,
	has_prekey:              bool,
	prekey_id:               u32,
	prekey_public:           [32]u8,
}

Signal_Recipient_Keys :: struct {
	identity_private:      [32]u8,
	registration_id:       u32,
	signed_prekey_private: [32]u8,
	signed_prekey_id:      u32,
	has_prekey:            bool,
	prekey_private:        [32]u8,
	prekey_id:             u32,
}

Signal_Message_Type :: enum u8 {
	Whisper = 1,
	Prekey  = 3,
}

Signal_Session_Error_Kind :: enum {
	None,
	Invalid_State,
	Already_Initialized,
	Untrusted_Identity,
	Invalid_Key,
	Invalid_Prekey,
	Invalid_Prekey_Signature,
	Session_Mismatch,
	Missing_Prekey,
	Entropy_Unavailable,
	Invalid_Message,
	Unsupported_Version,
	Protobuf_Failed,
	Payload_Oversized,
	Destination_Undersized,
	Overlapping_Buffers,
	Counter_Exhausted,
	Counter_Gap_Exceeded,
	Skipped_Key_Limit,
	Receiving_Chain_Limit,
	Replay,
	Chain_Closed,
	Authentication_Failed,
	Encryption_Failed,
	Decryption_Failed,
	Invalid_Format,
	Unsupported_Store_Version,
	Checksum_Mismatch,
}

Signal_Session_Error :: struct {
	kind:     Signal_Session_Error_Kind,
	crypto:   Signal_Key_Error,
	signal:   Signal_Error,
	protobuf: Protobuf_Error,
}

Signal_Receiving_Chain :: struct {
	in_use, closed:            bool,
	ratchet_public, chain_key: [32]u8,
	counter:                   i64,
}

Signal_Skipped_Key :: struct {
	in_use:      bool,
	chain_index: u16,
	counter:     u32,
	seed:        [32]u8,
}

// One X3DH generation for a remote device, with bounded historical DH chains.
// The caller supplies an explicitly trusted identity on every operation and
// durably commits the session and consumed one-time prekey together. Do not
// copy live secrets except for such transactions; erase discarded snapshots.
Signal_Session :: struct {
	initialized, initiator, pending_prekey, has_pending_prekey:         bool,
	local_registration_id, remote_registration_id:                      u32,
	local_identity_public, remote_identity_public:                      [32]u8,
	base_public:                                                        [32]u8,
	pending_signed_prekey_id, pending_prekey_id:                        u32,
	root_key:                                                           [32]u8,
	local_ratchet_private, local_ratchet_public, remote_ratchet_public: [32]u8,
	sending:                                                            bool,
	send_chain_key:                                                     [32]u8,
	send_counter:                                                       i64,
	previous_counter:                                                   u32,
	receiving:                                                          [MAX_SIGNAL_RECEIVING_CHAINS]Signal_Receiving_Chain,
	skipped:                                                            [MAX_SIGNAL_SKIPPED_KEYS]Signal_Skipped_Key,
	skipped_count:                                                      int,
}

signal_session_clear :: proc(session: ^Signal_Session) {
	if session != nil {
		crypto.zero_explicit(session, size_of(Signal_Session))
	}
}

// Builds a new initiator generation. Explicit trust is required even for the
// first bundle; silently accepting a new identity is not a storage policy.
signal_session_init_initiator :: proc(
	session: ^Signal_Session,
	identity_private: [32]u8,
	registration_id: u32,
	bundle: Signal_Prekey_Bundle,
	trusted_identity: [32]u8,
) -> Signal_Session_Error {
	if session == nil {
		return {kind = .Invalid_State}
	}

	if session.initialized {
		return {kind = .Already_Initialized}
	}

	if !signal_identity_equal(bundle.identity_public, trusted_identity) {
		return {kind = .Untrusted_Identity}
	}

	identity := identity_private
	defer crypto.zero_explicit(&identity, size_of(identity))
	if !signal_private_valid(identity) || registration_id > 0x3fff {
		return {kind = .Invalid_Key}
	}

	if bundle_error := signal_initiator_bundle_validate(bundle); bundle_error.kind != .None {
		return bundle_error
	}

	when !crypto.HAS_RAND_BYTES {
		return {kind = .Entropy_Unavailable}
	}
	next: Signal_Session
	defer signal_session_clear(&next)
	base_private: [32]u8
	defer crypto.zero_explicit(&base_private, size_of(base_private))
	signal_private_generate(&base_private)
	signal_private_generate(&next.local_ratchet_private)
	next.local_ratchet_public = signal_curve_public(next.local_ratchet_private)
	next.base_public = signal_curve_public(base_private)
	next.local_identity_public = signal_curve_public(identity)
	next.remote_identity_public = bundle.identity_public
	next.remote_ratchet_public = bundle.signed_prekey_public
	next.local_registration_id, next.remote_registration_id =
		registration_id, bundle.registration_id
	next.pending_signed_prekey_id = bundle.signed_prekey_id
	next.has_pending_prekey, next.pending_prekey_id = bundle.has_prekey, bundle.prekey_id
	next.pending_prekey, next.initiator = true, true
	if root_error := signal_initiator_root_derive(&next, identity, base_private, bundle);
	   root_error.kind != .None {
		return root_error
	}
	dh: [32]u8
	defer crypto.zero_explicit(&dh, size_of(dh))
	if err := signal_agreement(dh[:], next.local_ratchet_private, bundle.signed_prekey_public);
	   err.kind != .None {
		return err
	}

	ratchet := signal_ratchet_keys(next.root_key, dh)
	defer crypto.zero_explicit(&ratchet, size_of(ratchet))
	next.root_key, next.send_chain_key = ratchet.root_key, ratchet.chain_key
	next.send_counter, next.sending, next.initialized = -1, true, true
	session^ = next
	return {}
}

signal_initiator_bundle_validate :: proc(bundle: Signal_Prekey_Bundle) -> Signal_Session_Error {
	if bundle.signed_prekey_id > MAX_DEVICE_PREKEY_ID ||
	   bundle.has_prekey && bundle.prekey_id > MAX_DEVICE_PREKEY_ID {
		return {kind = .Invalid_Prekey}
	}

	signed: [33]u8
	signed[0] = 5
	public := bundle.signed_prekey_public
	copy(signed[1:], public[:])
	prekey_signature := bundle.signed_prekey_signature

	if err := signal_curve_verify(bundle.identity_public, signed[:], prekey_signature[:]);
	   err != .None {
		return {kind = .Invalid_Prekey_Signature, signal = err}
	}

	return {}
}

signal_initiator_root_derive :: proc(
	next: ^Signal_Session,
	identity, base_private: [32]u8,
	bundle: Signal_Prekey_Bundle,
) -> Signal_Session_Error {
	material: [160]u8
	defer crypto.zero_explicit(&material, size_of(material))
	slice.fill(material[:32], 0xff)
	if err := signal_agreement(material[32:64], identity, bundle.signed_prekey_public);
	   err.kind != .None {
		return err
	}

	if err := signal_agreement(material[64:96], base_private, bundle.identity_public);
	   err.kind != .None {
		return err
	}

	if err := signal_agreement(material[96:128], base_private, bundle.signed_prekey_public);
	   err.kind != .None {
		return err
	}

	length := 128
	if bundle.has_prekey {
		if err := signal_agreement(material[128:160], base_private, bundle.prekey_public);
		   err.kind != .None {
			return err
		}

		length = 160
	}

	next.root_key = signal_x3dh_root(material[:length])
	return {}
}

signal_identity_equal :: proc(a, b: [32]u8) -> bool {
	a_copy, b_copy := a, b

	return crypto.compare_constant_time(a_copy[:], b_copy[:]) == 1
}

signal_private_valid :: proc(private: [32]u8) -> bool {
	return private[0] & 7 == 0 && private[31] & 0xc0 == 0x40
}

signal_private_generate :: proc(private: ^[32]u8) {
	crypto.rand_bytes(private[:])
	private[0] &= 248
	private[31] = private[31] & 127 | 64
}

signal_public_valid :: proc(public: [32]u8) -> bool {
	value := public
	u: field.Tight_Field_Element
	field.fe_from_bytes(&u, &value)

	return field.fe_equal_bytes(&u, &value) == 1 && crypto.is_zero_constant_time(value[:]) == 0
}

signal_agreement :: proc(dst: []u8, private, public: [32]u8) -> Signal_Session_Error {
	if !signal_public_valid(public) {
		return {kind = .Invalid_Key}
	}

	secret, peer := private, public
	defer crypto.zero_explicit(&secret, size_of(secret))
	x25519.scalarmult(dst, secret[:], peer[:])

	if crypto.is_zero_constant_time(dst) == 1 {
		return {kind = .Invalid_Key}
	}

	return {}
}

signal_x3dh_root :: proc(material: []u8) -> (root: [32]u8) {
	salt: [32]u8
	label := "WhisperText"
	hkdf.extract_and_expand(.SHA256, salt[:], material, transmute([]u8)label, root[:])

	return root
}

Signal_Whisper :: struct {
	ratchet_public:                 [32]u8,
	counter, previous_counter:      u32,
	ciphertext, authenticated, mac: []u8,
}

Signal_Prekey_Message :: struct {
	registration_id, signed_prekey_id, prekey_id: u32,
	has_prekey:                                   bool,
	base_public, identity_public:                 [32]u8,
	message:                                      []u8,
}

signal_whisper_decode :: proc(
	wire: []u8,
) -> (
	message: Signal_Whisper,
	error: Signal_Session_Error,
) {
	if len(wire) > MAX_SIGNAL_PACKET_SIZE {
		return {}, {kind = .Payload_Oversized}
	}

	if len(wire) < 10 {
		return {}, {kind = .Invalid_Message}
	}

	if wire[0] != SIGNAL_SESSION_WIRE_VERSION {
		return {}, {kind = .Unsupported_Version}
	}

	message.authenticated, message.mac = wire[:len(wire) - 8], wire[len(wire) - 8:]
	encoded := wire[1:len(wire) - 8]
	at := 0
	seen: [4]bool

	for at < len(encoded) {
		part, part_err := protobuf_field_read(encoded, &at)

		if part_err != .None {
			return {}, {kind = .Protobuf_Failed, protobuf = part_err}
		}

		if part.number < 1 || part.number > 4 {
			continue
		}

		if seen[part.number - 1] {
			return {}, {kind = .Invalid_Message}
		}

		seen[part.number - 1] = true
		if field_error := signal_whisper_decode_field(&message, part); field_error.kind != .None {
			return {}, field_error
		}
	}

	for present in seen {
		if !present {
			return {}, {kind = .Invalid_Message}
		}
	}

	if !signal_public_valid(message.ratchet_public) {
		return {}, {kind = .Invalid_Key}
	}

	return message, {}
}

signal_whisper_decode_field :: proc(
	message: ^Signal_Whisper,
	part: Protobuf_Field,
) -> Signal_Session_Error {
	switch part.number {
	case 1:
		if part.wire_type != 2 || len(part.data) != 33 || part.data[0] != 5 {
			return {kind = .Invalid_Key}
		}

		copy(message.ratchet_public[:], part.data[1:])
	case 2, 3:
		if part.wire_type != 0 || part.value > cast(u64)max(u32) {
			return {kind = .Invalid_Message}
		}

		if part.number == 2 {
			message.counter = cast(u32)part.value
		}

		if part.number == 3 {
			message.previous_counter = cast(u32)part.value
		}

	case 4:
		if part.wire_type != 2 ||
		   len(part.data) == 0 ||
		   len(part.data) % 16 != 0 ||
		   len(part.data) > MAX_SIGNAL_CIPHERTEXT_SIZE {
			return {kind = .Invalid_Message}
		}

		message.ciphertext = part.data
	}

	return {}
}

// Header inspection does not authenticate the identity or consume a prekey.
// message.message borrows wire; use the matching trusted identity explicitly
// when processing this envelope through signal_session_decrypt_prekey.
signal_prekey_message_decode :: proc(
	wire: []u8,
) -> (
	message: Signal_Prekey_Message,
	error: Signal_Session_Error,
) {
	if len(wire) > MAX_SIGNAL_PACKET_SIZE {
		return {}, {kind = .Payload_Oversized}
	}

	if len(wire) < 2 {
		return {}, {kind = .Invalid_Message}
	}

	if wire[0] != SIGNAL_SESSION_WIRE_VERSION {
		return {}, {kind = .Unsupported_Version}
	}

	at := 0
	encoded := wire[1:]
	seen: [6]bool

	for at < len(encoded) {
		part, part_err := protobuf_field_read(encoded, &at)

		if part_err != .None {
			return {}, {kind = .Protobuf_Failed, protobuf = part_err}
		}

		if part.number < 1 || part.number > 6 {
			continue
		}

		if seen[part.number - 1] {
			return {}, {kind = .Invalid_Message}
		}

		seen[part.number - 1] = true
		if field_error := signal_prekey_message_decode_field(&message, part);
		   field_error.kind != .None {
			return {}, field_error
		}
	}

	for i in 1 ..< 6 {
		if !seen[i] {
			return {}, {kind = .Invalid_Message}
		}
	}

	if message.signed_prekey_id > MAX_DEVICE_PREKEY_ID ||
	   message.has_prekey && message.prekey_id > MAX_DEVICE_PREKEY_ID {
		return {}, {kind = .Invalid_Prekey}
	}

	return message, {}
}

signal_prekey_message_decode_field :: proc(
	message: ^Signal_Prekey_Message,
	part: Protobuf_Field,
) -> Signal_Session_Error {
	switch part.number {
	case 1, 5, 6:
		if part.wire_type != 0 || part.value > cast(u64)max(u32) {
			return {kind = .Invalid_Message}
		}

		if part.number == 1 {
			message.prekey_id, message.has_prekey = cast(u32)part.value, true
		}

		if part.number == 5 {
			message.registration_id = cast(u32)part.value
		}

		if part.number == 6 {
			message.signed_prekey_id = cast(u32)part.value
		}

	case 2, 3:
		if part.wire_type != 2 || len(part.data) != 33 || part.data[0] != 5 {
			return {kind = .Invalid_Key}
		}

		if part.number == 2 {
			copy(message.base_public[:], part.data[1:])
		}

		if part.number == 3 {
			copy(message.identity_public[:], part.data[1:])
		}

	case 4:
		if part.wire_type != 2 {
			return {kind = .Invalid_Message}
		}

		message.message = part.data
	}
	return {}
}

// Commits the sending chain only after the complete packet fits and has been
// encoded. Persist the resulting state before exposing/sending the packet.
signal_session_encrypt :: proc(
	session: ^Signal_Session,
	dst, plaintext: []u8,
	trusted_identity: [32]u8,
) -> (
	kind: Signal_Message_Type,
	written: int,
	error: Signal_Session_Error,
) {
	if err := signal_session_ready(session, trusted_identity); err.kind != .None {
		return {}, 0, err
	}

	if !session.sending {
		return {}, 0, {kind = .Invalid_State}
	}

	if len(plaintext) > MAX_SIGNAL_PLAINTEXT_SIZE {
		return {}, 0, {kind = .Payload_Oversized}
	}

	if session.send_counter >= cast(i64)max(u32) {
		return {}, 0, {kind = .Counter_Exhausted}
	}

	counter := cast(u32)(session.send_counter + 1)
	cipher_size := (len(plaintext) / 16 + 1) * 16
	packet_kind, prefix_size, whisper_size, suffix_size := signal_session_encrypt_sizes(
		session,
		counter,
		cipher_size,
	)
	required := prefix_size + whisper_size + suffix_size
	if len(dst) < required {
		return {}, required, {kind = .Destination_Undersized}
	}

	if bytes.alias(dst[:required], plaintext) ||
	   signal_session_overlaps_buffer(session, dst[:required]) {
		return {}, 0, {kind = .Overlapping_Buffers}
	}

	step := signal_chain_keys(session.send_chain_key)
	defer crypto.zero_explicit(&step, size_of(step))
	keys := signal_message_keys(step.message_seed)
	defer crypto.zero_explicit(&keys, size_of(keys))
	whisper := dst[prefix_size:][:whisper_size]
	if encryption_error := signal_session_whisper_encrypt(
		session,
		whisper,
		plaintext,
		&keys,
		counter,
		cipher_size,
	); encryption_error.kind != .None {
		return {}, 0, encryption_error
	}
	if session.pending_prekey {
		signal_session_prekey_wrap(session, dst, prefix_size, whisper_size, required)
	}

	session.send_chain_key = step.next_chain_key
	session.send_counter += 1
	return packet_kind, required, {}
}

signal_session_encrypt_sizes :: proc(
	session: ^Signal_Session,
	counter: u32,
	cipher_size: int,
) -> (
	Signal_Message_Type,
	int,
	int,
	int,
) {
	whisper_size :=
		1 +
		35 +
		1 +
		protobuf_varint_size(cast(u64)counter) +
		1 +
		protobuf_varint_size(cast(u64)session.previous_counter) +
		1 +
		protobuf_varint_size(cast(u64)cipher_size) +
		cipher_size +
		8
	prefix_size, suffix_size: int
	kind := Signal_Message_Type.Whisper
	if session.pending_prekey {
		kind = .Prekey
		prefix_size = 1 + 35 + 35 + 1 + protobuf_varint_size(cast(u64)whisper_size)

		if session.has_pending_prekey {
			prefix_size += 1 + protobuf_varint_size(cast(u64)session.pending_prekey_id)
		}

		suffix_size =
			1 +
			protobuf_varint_size(cast(u64)session.local_registration_id) +
			1 +
			protobuf_varint_size(cast(u64)session.pending_signed_prekey_id)
	}

	return kind, prefix_size, whisper_size, suffix_size
}

signal_session_whisper_encrypt :: proc(
	session: ^Signal_Session,
	whisper, plaintext: []u8,
	keys: ^Signal_Message_Keys,
	counter: u32,
	cipher_size: int,
) -> Signal_Session_Error {
	whisper[0] = SIGNAL_SESSION_WIRE_VERSION
	at := 1
	signal_session_put_public(whisper, &at, 1, session.local_ratchet_public)
	signal_session_put_uint(whisper, &at, 2, counter)
	signal_session_put_uint(whisper, &at, 3, session.previous_counter)
	whisper[at] = 34
	at += 1
	protobuf_varint_write(whisper, &at, cast(u64)cipher_size)
	_, crypto_err := signal_cbc_encrypt(
		whisper[at:][:cipher_size],
		keys.cipher_key,
		keys.iv,
		plaintext,
	)
	if crypto_err != .None {
		return {kind = .Encryption_Failed, crypto = crypto_err}
	}

	at += cipher_size
	mac, mac_err := signal_message_mac(
		keys.mac_key,
		session.local_identity_public,
		session.remote_identity_public,
		whisper[:at],
	)
	if mac_err != .None {
		return {kind = .Encryption_Failed, crypto = mac_err}
	}

	copy(whisper[at:], mac[:])
	return {}
}

signal_session_prekey_wrap :: proc(
	session: ^Signal_Session,
	dst: []u8,
	prefix_size, whisper_size, required: int,
) {
	dst[0] = SIGNAL_SESSION_WIRE_VERSION
	at := 1

	if session.has_pending_prekey {
		signal_session_put_uint(dst, &at, 1, session.pending_prekey_id)
	}

	signal_session_put_public(dst, &at, 2, session.base_public)
	signal_session_put_public(dst, &at, 3, session.local_identity_public)
	dst[at] = 34
	at += 1
	protobuf_varint_write(dst, &at, cast(u64)whisper_size)
	assert(at == prefix_size)
	at += whisper_size
	signal_session_put_uint(dst, &at, 5, session.local_registration_id)
	signal_session_put_uint(dst, &at, 6, session.pending_signed_prekey_id)
	assert(at == required)
}

// Normal Whisper messages authenticate the cached peer identity and commit
// ratchet/skipped-key changes only after MAC, padding, and destination checks.
signal_session_decrypt :: proc(
	session: ^Signal_Session,
	dst, wire: []u8,
	trusted_identity: [32]u8,
) -> (
	written: int,
	error: Signal_Session_Error,
) {
	if err := signal_session_ready(session, trusted_identity); err.kind != .None {
		return 0, err
	}

	if bytes.alias(dst, wire) || signal_session_overlaps_buffer(session, dst) {
		return 0, {kind = .Overlapping_Buffers}
	}

	message, decode_err := signal_whisper_decode(wire)
	if decode_err.kind != .None {
		return 0, decode_err
	}

	next := session^
	defer signal_session_clear(&next)
	written, error = signal_session_decrypt_next(&next, dst, message)
	if error.kind != .None {
		return 0, error
	}

	session^ = next
	return written, {}
}

// A new authenticated recipient generation consumes its optional prekey.
// Because ID zero is valid, callers distinguish no-consumption by inspecting
// whether the session was already initialized and the decoded has_prekey flag.
// Commit removal together with the snapshot; no prekey store is mutated here.
signal_session_decrypt_prekey :: proc(
	session: ^Signal_Session,
	dst, wire: []u8,
	local: Signal_Recipient_Keys,
	trusted_identity: [32]u8,
) -> (
	written: int,
	consumed_prekey_id: u32,
	error: Signal_Session_Error,
) {
	if session == nil {
		return 0, 0, {kind = .Invalid_State}
	}

	if bytes.alias(dst, wire) || signal_session_overlaps_buffer(session, dst) {
		return 0, 0, {kind = .Overlapping_Buffers}
	}

	prekey, prekey_err := signal_prekey_message_decode(wire)
	if prekey_err.kind != .None {
		return 0, 0, prekey_err
	}

	if !signal_identity_equal(prekey.identity_public, trusted_identity) {
		return 0, 0, {kind = .Untrusted_Identity}
	}

	message, message_err := signal_whisper_decode(prekey.message)
	if message_err.kind != .None {
		return 0, 0, message_err
	}

	next: Signal_Session
	defer signal_session_clear(&next)
	if session.initialized {
		if session_error := signal_prekey_existing_session_validate(
			session,
			trusted_identity,
			prekey,
			local,
		); session_error.kind != .None {
			return 0, 0, session_error
		}

		next = session^
	} else {
		if err := signal_session_init_recipient(&next, local, prekey); err.kind != .None {
			return 0, 0, err
		}

		if prekey.has_prekey {
			consumed_prekey_id = prekey.prekey_id
		}
	}

	written, error = signal_session_decrypt_next(&next, dst, message)
	if error.kind != .None {
		return 0, 0, error
	}

	session^ = next
	return written, consumed_prekey_id, {}
}

signal_prekey_existing_session_validate :: proc(
	session: ^Signal_Session,
	trusted_identity: [32]u8,
	prekey: Signal_Prekey_Message,
	local: Signal_Recipient_Keys,
) -> Signal_Session_Error {
	if err := signal_session_ready(session, trusted_identity); err.kind != .None {
		return err
	}

	if !signal_identity_equal(session.base_public, prekey.base_public) {
		return {kind = .Session_Mismatch}
	}

	if !signal_identity_equal(
		session.local_identity_public,
		signal_curve_public(local.identity_private),
	) {
		return {kind = .Invalid_Key}
	}

	return {}
}

signal_session_init_recipient :: proc(
	next: ^Signal_Session,
	local: Signal_Recipient_Keys,
	message: Signal_Prekey_Message,
) -> Signal_Session_Error {
	if key_error := signal_recipient_keys_validate(local, message); key_error.kind != .None {
		return key_error
	}

	material: [160]u8
	defer crypto.zero_explicit(&material, size_of(material))
	slice.fill(material[:32], 0xff)
	if err := signal_agreement(
		material[32:64],
		local.signed_prekey_private,
		message.identity_public,
	); err.kind != .None {
		return err
	}

	if err := signal_agreement(material[64:96], local.identity_private, message.base_public);
	   err.kind != .None {
		return err
	}

	if err := signal_agreement(material[96:128], local.signed_prekey_private, message.base_public);
	   err.kind != .None {
		return err
	}

	length := 128
	if message.has_prekey {
		if err := signal_agreement(material[128:160], local.prekey_private, message.base_public);
		   err.kind != .None {
			return err
		}

		length = 160
	}

	next^ = {
		initialized            = true,
		local_registration_id  = local.registration_id,
		remote_registration_id = message.registration_id,
		local_identity_public  = signal_curve_public(local.identity_private),
		remote_identity_public = message.identity_public,
		base_public            = message.base_public,
		root_key               = signal_x3dh_root(material[:length]),
		local_ratchet_private  = local.signed_prekey_private,
		local_ratchet_public   = signal_curve_public(local.signed_prekey_private),
		remote_ratchet_public  = message.base_public,
		send_counter           = -1,
	}
	return {}
}

signal_recipient_keys_validate :: proc(
	local: Signal_Recipient_Keys,
	message: Signal_Prekey_Message,
) -> Signal_Session_Error {
	if !signal_private_valid(local.identity_private) ||
	   !signal_private_valid(local.signed_prekey_private) ||
	   local.registration_id > 0x3fff {
		return {kind = .Invalid_Key}
	}

	if message.signed_prekey_id != local.signed_prekey_id {
		return {kind = .Missing_Prekey}
	}

	if message.has_prekey &&
	   (!local.has_prekey ||
			   local.prekey_id != message.prekey_id ||
			   !signal_private_valid(local.prekey_private)) {
		return {kind = .Missing_Prekey}
	}

	return {}
}

signal_session_decrypt_next :: proc(
	next: ^Signal_Session,
	dst: []u8,
	message: Signal_Whisper,
) -> (
	written: int,
	error: Signal_Session_Error,
) {
	index := signal_receiving_chain_find(next, message.ratchet_public)
	if index < 0 {
		if err := signal_session_ratchet(next, message.ratchet_public, message.previous_counter);
		   err.kind != .None {
			return 0, err
		}

		index = signal_receiving_chain_find(next, message.ratchet_public)
		assert(index >= 0)
	}

	seed, seed_err := signal_session_message_seed(next, index, message.counter)
	defer crypto.zero_explicit(&seed, size_of(seed))
	if seed_err.kind != .None {
		return 0, seed_err
	}

	keys := signal_message_keys(seed)
	defer crypto.zero_explicit(&keys, size_of(keys))
	if mac_err := signal_message_mac_verify(
		keys.mac_key,
		next.remote_identity_public,
		next.local_identity_public,
		message.authenticated,
		message.mac,
	); mac_err != .None {
		return 0, {kind = .Authentication_Failed, crypto = mac_err}
	}

	body_size, crypto_err := signal_cbc_decrypt(dst, keys.cipher_key, keys.iv, message.ciphertext)
	if crypto_err == .Destination_Undersized {
		return 0, {kind = .Destination_Undersized}
	}

	if crypto_err != .None {
		return 0, {kind = .Decryption_Failed, crypto = crypto_err}
	}

	next.pending_prekey = false
	return body_size, {}
}

signal_session_ratchet :: proc(
	next: ^Signal_Session,
	remote: [32]u8,
	previous_counter: u32,
) -> Signal_Session_Error {
	old := signal_receiving_chain_find(next, next.remote_ratchet_public)

	if old >= 0 && !next.receiving[old].closed {
		if err := signal_session_skip_through(next, old, previous_counter); err.kind != .None {
			return err
		}

		next.receiving[old].closed = true
		crypto.zero_explicit(&next.receiving[old].chain_key, 32)
	}

	index := signal_receiving_chain_slot(next)
	if index < 0 {
		return {kind = .Receiving_Chain_Limit}
	}

	dh: [32]u8
	defer crypto.zero_explicit(&dh, size_of(dh))

	if err := signal_agreement(dh[:], next.local_ratchet_private, remote); err.kind != .None {
		return err
	}

	receiving := signal_ratchet_keys(next.root_key, dh)
	defer crypto.zero_explicit(&receiving, size_of(receiving))
	next.root_key = receiving.root_key
	next.receiving[index] = {
		in_use         = true,
		ratchet_public = remote,
		chain_key      = receiving.chain_key,
		counter        = -1,
	}

	if next.sending {
		next.previous_counter = cast(u32)next.send_counter
	}

	when !crypto.HAS_RAND_BYTES {
		return {kind = .Entropy_Unavailable}
	}
	signal_private_generate(&next.local_ratchet_private)
	next.local_ratchet_public = signal_curve_public(next.local_ratchet_private)

	if err := signal_agreement(dh[:], next.local_ratchet_private, remote); err.kind != .None {
		return err
	}

	sending := signal_ratchet_keys(next.root_key, dh)
	defer crypto.zero_explicit(&sending, size_of(sending))
	next.root_key, next.send_chain_key = sending.root_key, sending.chain_key
	next.send_counter, next.sending = -1, true
	next.remote_ratchet_public = remote

	return {}
}

signal_session_message_seed :: proc(
	next: ^Signal_Session,
	index: int,
	counter: u32,
) -> (
	seed: [32]u8,
	error: Signal_Session_Error,
) {
	chain := &next.receiving[index]
	if cast(i64)counter <= chain.counter {
		for &skipped in next.skipped {
			if skipped.in_use &&
			   skipped.chain_index == cast(u16)index &&
			   skipped.counter == counter {
				seed = skipped.seed
				crypto.zero_explicit(&skipped, size_of(Signal_Skipped_Key))
				next.skipped_count -= 1
				return seed, {}
			}
		}

		return {}, {kind = .Replay}
	}

	if chain.closed {
		return {}, {kind = .Chain_Closed}
	}

	if cast(i64)counter - chain.counter > MAX_SIGNAL_SKIPPED_KEYS {
		return {}, {kind = .Counter_Gap_Exceeded}
	}

	for chain.counter < cast(i64)counter {
		step := signal_chain_keys(chain.chain_key)
		chain.chain_key = step.next_chain_key
		chain.counter += 1

		if chain.counter == cast(i64)counter {
			seed = step.message_seed
			crypto.zero_explicit(&step, size_of(step))
			return seed, {}
		}

		err := signal_session_save_skipped(next, index, cast(u32)chain.counter, step.message_seed)
		crypto.zero_explicit(&step, size_of(step))
		if err.kind != .None {
			return {}, err
		}
	}
	unreachable()
}

signal_session_skip_through :: proc(
	next: ^Signal_Session,
	index: int,
	counter: u32,
) -> Signal_Session_Error {
	chain := &next.receiving[index]
	if chain.counter >= cast(i64)counter {
		return {}
	}

	if chain.closed {
		return {kind = .Chain_Closed}
	}

	if cast(i64)counter - chain.counter > MAX_SIGNAL_SKIPPED_KEYS {
		return {kind = .Counter_Gap_Exceeded}
	}

	for chain.counter < cast(i64)counter {
		step := signal_chain_keys(chain.chain_key)
		chain.chain_key = step.next_chain_key
		chain.counter += 1
		err := signal_session_save_skipped(next, index, cast(u32)chain.counter, step.message_seed)
		crypto.zero_explicit(&step, size_of(step))
		if err.kind != .None {
			return err
		}
	}

	return {}
}

signal_session_save_skipped :: proc(
	next: ^Signal_Session,
	index: int,
	counter: u32,
	seed: [32]u8,
) -> Signal_Session_Error {
	if next.skipped_count >= MAX_SIGNAL_SKIPPED_KEYS {
		return {kind = .Skipped_Key_Limit}
	}

	for &skipped in next.skipped {
		if !skipped.in_use {
			skipped = {
				in_use      = true,
				chain_index = cast(u16)index,
				counter     = counter,
				seed        = seed,
			}

			next.skipped_count += 1
			return {}
		}
	}
	return {kind = .Skipped_Key_Limit}
}

signal_receiving_chain_find :: proc(session: ^Signal_Session, public: [32]u8) -> int {
	for chain, i in session.receiving {
		if chain.in_use && signal_identity_equal(chain.ratchet_public, public) {
			return i
		}
	}

	return -1
}

signal_receiving_chain_slot :: proc(session: ^Signal_Session) -> int {
	for &chain, i in session.receiving {
		if !chain.in_use {
			return i
		}
	}

	for &chain, i in session.receiving {
		if !chain.closed {
			continue
		}

		cached := false

		for key in session.skipped {
			if key.in_use && key.chain_index == cast(u16)i {
				cached = true
			}
		}

		if !cached {
			crypto.zero_explicit(&chain, size_of(chain))
			return i
		}
	}

	return -1
}

signal_session_ready :: proc(session: ^Signal_Session, trusted: [32]u8) -> Signal_Session_Error {
	if session == nil ||
	   !session.initialized ||
	   session.skipped_count < 0 ||
	   session.skipped_count > MAX_SIGNAL_SKIPPED_KEYS ||
	   session.send_counter < -1 ||
	   session.send_counter > cast(i64)max(u32) {
		return {kind = .Invalid_State}
	}

	if !signal_identity_equal(session.remote_identity_public, trusted) {
		return {kind = .Untrusted_Identity}
	}

	return {}
}

signal_session_overlaps_buffer :: proc(session: ^Signal_Session, data: []u8) -> bool {
	return bytes.alias(data, mem.ptr_to_bytes(session))
}

signal_session_put_uint :: proc(dst: []u8, at: ^int, field: u8, value: u32) {
	dst[at^] = field << 3
	at^ += 1
	protobuf_varint_write(dst, at, cast(u64)value)
}

signal_session_put_public :: proc(dst: []u8, at: ^int, field: u8, public: [32]u8) {
	dst[at^], dst[at^ + 1], dst[at^ + 2] = field << 3 | 2, 33, 5
	public_bytes := public
	copy(dst[at^ + 3:][:32], public_bytes[:])
	at^ += 35
}

// Structural validation for durable snapshots. A checksum is not an identity
// trust decision; the caller still supplies trusted_identity on every use.
signal_session_validate :: proc(session: ^Signal_Session) -> Signal_Session_Error {
	if session == nil ||
	   !session.initialized ||
	   !session.sending ||
	   session.local_registration_id > 0x3fff ||
	   session.send_counter < -1 ||
	   session.send_counter > cast(i64)max(u32) ||
	   session.skipped_count < 0 ||
	   session.skipped_count > MAX_SIGNAL_SKIPPED_KEYS {
		return {kind = .Invalid_State}
	}

	if !signal_private_valid(session.local_ratchet_private) ||
	   !signal_identity_equal(
			   signal_curve_public(session.local_ratchet_private),
			   session.local_ratchet_public,
		   ) ||
	   !signal_public_valid(session.local_identity_public) ||
	   !signal_public_valid(session.remote_identity_public) ||
	   !signal_public_valid(session.base_public) ||
	   !signal_public_valid(session.remote_ratchet_public) {
		return {kind = .Invalid_Key}
	}

	if session.pending_prekey &&
	   (!session.initiator || session.pending_signed_prekey_id > MAX_DEVICE_PREKEY_ID) {
		return {kind = .Invalid_Prekey}
	}

	if session.has_pending_prekey && session.pending_prekey_id > MAX_DEVICE_PREKEY_ID {
		return {kind = .Invalid_Prekey}
	}

	return signal_session_chains_validate(session)
}

signal_session_chains_validate :: proc(session: ^Signal_Session) -> Signal_Session_Error {
	active := 0

	for &chain, i in session.receiving {
		if !chain.in_use {
			continue
		}

		if !signal_public_valid(chain.ratchet_public) ||
		   chain.counter < -1 ||
		   chain.counter > cast(i64)max(u32) {
			return {kind = .Invalid_State}
		}

		for other in session.receiving[:i] {
			if other.in_use && other.ratchet_public == chain.ratchet_public {
				return {kind = .Invalid_State}
			}
		}

		if !chain.closed {
			active += 1

			if chain.ratchet_public != session.remote_ratchet_public {
				return {kind = .Invalid_State}
			}
		}
	}

	if active > 1 {
		return {kind = .Invalid_State}
	}

	count := 0

	for &key, i in session.skipped {
		if !key.in_use {
			continue
		}

		count += 1

		if cast(int)key.chain_index >= MAX_SIGNAL_RECEIVING_CHAINS {
			return {kind = .Invalid_State}
		}

		chain := &session.receiving[key.chain_index]

		if !chain.in_use || cast(i64)key.counter > chain.counter {
			return {kind = .Invalid_State}
		}

		for other in session.skipped[:i] {
			if other.in_use &&
			   other.chain_index == key.chain_index &&
			   other.counter == key.counter {
				return {kind = .Invalid_State}
			}
		}
	}

	if count != session.skipped_count {
		return {kind = .Invalid_State}
	}

	return {}
}

// Bounded versioned snapshot; contains private keys and skipped message seeds.
// The caller's atomic state store must protect these bytes and commit consumed
// one-time-key markers alongside them before releasing plaintext/ciphertext.
signal_session_encode :: proc(
	dst: []u8,
	session: ^Signal_Session,
) -> (
	written: int,
	error: Signal_Session_Error,
) {
	if err := signal_session_validate(session); err.kind != .None {
		return 0, err
	}

	chains := 0

	for chain in session.receiving {
		if chain.in_use {
			chains += 1
		}
	}

	required := 330 + chains * 74 + session.skipped_count * 39

	if len(dst) < required {
		return required, {kind = .Destination_Undersized}
	}

	if signal_session_overlaps_buffer(session, dst[:required]) {
		return 0, {kind = .Overlapping_Buffers}
	}

	copy(dst[:8], SIGNAL_SESSION_STORE_MAGIC)
	dst[8], dst[9] = 0, 1
	dst[10] = 0
	if session.initiator {
		dst[10] |= 1
	}

	if session.pending_prekey {
		dst[10] |= 2
	}

	if session.has_pending_prekey {
		dst[10] |= 4
	}

	if session.sending {
		dst[10] |= 8
	}

	written = 11
	signal_session_keys_encode(dst, session, &written)
	endian.unchecked_put_u64be(dst[written:][:8], u64(session.send_counter + 1))
	written += 8
	dst[written] = u8(chains)
	written += 1
	endian.unchecked_put_u16be(dst[written:][:2], u16(session.skipped_count))
	written += 2
	signal_session_chains_encode(dst, session, &written)
	assert(written + 32 == required)
	checksum := sha256(dst[:written])
	written += copy(dst[written:], checksum[:])

	return written, {}
}

signal_session_keys_encode :: proc(dst: []u8, session: ^Signal_Session, at: ^int) {
	metadata := [?]u32 {
		session.local_registration_id,
		session.remote_registration_id,
		session.pending_signed_prekey_id,
		session.pending_prekey_id,
		session.previous_counter,
	}

	for value in metadata {
		endian.unchecked_put_u32be(dst[at^:][:4], value)
		at^ += 4
	}
	parts := [?][]u8 {
		session.local_identity_public[:],
		session.remote_identity_public[:],
		session.base_public[:],
		session.root_key[:],
		session.local_ratchet_private[:],
		session.local_ratchet_public[:],
		session.remote_ratchet_public[:],
		session.send_chain_key[:],
	}

	for part in parts {
		at^ += copy(dst[at^:], part)
	}
}

signal_session_chains_encode :: proc(dst: []u8, session: ^Signal_Session, at: ^int) {
	for &chain, i in session.receiving {
		if !chain.in_use {
			continue
		}

		dst[at^], dst[at^ + 1] = cast(u8)i, chain.closed ? 1 : 0
		at^ += 2

		at^ += copy(dst[at^:][:32], chain.ratchet_public[:])

		at^ += copy(dst[at^:][:32], chain.chain_key[:])

		endian.unchecked_put_u64be(dst[at^:][:8], u64(chain.counter + 1))
		at^ += 8
	}

	for &key, i in session.skipped {
		if !key.in_use {
			continue
		}

		endian.unchecked_put_u16be(dst[at^:][:2], u16(i))
		at^ += 2
		dst[at^] = cast(u8)key.chain_index
		at^ += 1
		endian.unchecked_put_u32be(dst[at^:][:4], key.counter)
		at^ += 4

		at^ += copy(dst[at^:][:32], key.seed[:])
	}
}

signal_session_decode :: proc(session: ^Signal_Session, src: []u8) -> Signal_Session_Error {
	if session == nil {
		return {kind = .Invalid_State}
	}

	if header_error := signal_session_snapshot_validate(src); header_error.kind != .None {
		return header_error
	}

	next := Signal_Session {
		initialized        = true,
		initiator          = src[10] & 1 != 0,
		pending_prekey     = src[10] & 2 != 0,
		has_pending_prekey = src[10] & 4 != 0,
		sending            = src[10] & 8 != 0,
	}

	defer signal_session_clear(&next)
	at := 11
	signal_session_keys_decode(&next, src, &at)
	counter := endian.unchecked_get_u64be(src[at:][:8])
	at += 8

	if counter > cast(u64)max(u32) + 1 {
		return {kind = .Invalid_Format}
	}

	next.send_counter = cast(i64)counter - 1
	chains := cast(int)src[at]
	at += 1
	skipped := cast(int)endian.unchecked_get_u16be(src[at:][:2])
	at += 2
	if chains > MAX_SIGNAL_RECEIVING_CHAINS ||
	   skipped > MAX_SIGNAL_SKIPPED_KEYS ||
	   len(src) != 330 + chains * 74 + skipped * 39 {
		return {kind = .Invalid_Format}
	}

	if chains_error := signal_session_chains_decode(&next, src, &at, chains, skipped);
	   chains_error.kind != .None {
		return chains_error
	}

	if err := signal_session_validate(&next); err.kind != .None {
		return err
	}

	signal_session_clear(session)
	session^ = next

	return {}
}

signal_session_keys_decode :: proc(next: ^Signal_Session, src: []u8, at: ^int) {
	next.local_registration_id = endian.unchecked_get_u32be(src[at^:][:4])
	at^ += 4
	next.remote_registration_id = endian.unchecked_get_u32be(src[at^:][:4])
	at^ += 4
	next.pending_signed_prekey_id = endian.unchecked_get_u32be(src[at^:][:4])
	at^ += 4
	next.pending_prekey_id = endian.unchecked_get_u32be(src[at^:][:4])
	at^ += 4
	next.previous_counter = endian.unchecked_get_u32be(src[at^:][:4])
	at^ += 4
	parts := [?][]u8 {
		next.local_identity_public[:],
		next.remote_identity_public[:],
		next.base_public[:],
		next.root_key[:],
		next.local_ratchet_private[:],
		next.local_ratchet_public[:],
		next.remote_ratchet_public[:],
		next.send_chain_key[:],
	}

	for part in parts {
		copy(part, src[at^:][:len(part)])
		at^ += len(part)
	}
}

signal_session_snapshot_validate :: proc(src: []u8) -> Signal_Session_Error {
	if len(src) > MAX_SIGNAL_SESSION_STORE_SIZE {
		return {kind = .Payload_Oversized}
	}

	if len(src) < 330 || cast(string)src[:8] != SIGNAL_SESSION_STORE_MAGIC {
		return {kind = .Invalid_Format}
	}

	if src[8] != 0 || src[9] != 1 {
		return {kind = .Unsupported_Store_Version}
	}

	if src[10] & 0xf0 != 0 {
		return {kind = .Invalid_Format}
	}

	checksum := sha256(src[:len(src) - 32])

	if crypto.compare_constant_time(checksum[:], src[len(src) - 32:]) != 1 {
		return {kind = .Checksum_Mismatch}
	}

	return {}
}

signal_session_chains_decode :: proc(
	next: ^Signal_Session,
	src: []u8,
	at: ^int,
	chains, skipped: int,
) -> Signal_Session_Error {
	for _ in 0 ..< chains {
		index, flags := cast(int)src[at^], src[at^ + 1]
		at^ += 2

		if index >= MAX_SIGNAL_RECEIVING_CHAINS || next.receiving[index].in_use || flags > 1 {
			return {kind = .Invalid_Format}
		}

		chain := &next.receiving[index]
		chain.in_use, chain.closed = true, flags == 1
		copy(chain.ratchet_public[:], src[at^:at^ + 32])
		at^ += 32
		copy(chain.chain_key[:], src[at^:at^ + 32])
		at^ += 32
		stored_counter := endian.unchecked_get_u64be(src[at^:][:8])
		at^ += 8

		if stored_counter > cast(u64)max(u32) + 1 {
			return {kind = .Invalid_Format}
		}

		chain.counter = cast(i64)stored_counter - 1
	}
	for _ in 0 ..< skipped {
		index := cast(int)endian.unchecked_get_u16be(src[at^:][:2])
		at^ += 2
		chain_index := cast(u16)src[at^]
		at^ += 1

		if index >= MAX_SIGNAL_SKIPPED_KEYS || next.skipped[index].in_use {
			return {kind = .Invalid_Format}
		}

		key := &next.skipped[index]
		key.in_use, key.chain_index = true, chain_index
		key.counter = endian.unchecked_get_u32be(src[at^:][:4])
		at^ += 4
		copy(key.seed[:], src[at^:at^ + 32])
		at^ += 32
	}
	next.skipped_count = skipped
	return {}
}

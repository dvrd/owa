package whatsapp

import "core:bytes"
import "core:crypto"
import "core:crypto/sha2"

// Pinned Baileys 6.7.23 lib/Signal/Group and WAProto SenderKey* messages.
// Each record belongs to ONE (group JID, sender device) tuple. The caller must
// authenticate that tuple before processing a distribution (normally pairwise
// Signal). Distribution messages themselves carry no signature or identity.
MAX_GROUP_KEY_STATES :: 5
MAX_GROUP_SKIPPED_KEYS :: 2000
MAX_GROUP_FUTURE_MESSAGES :: 2000
MAX_GROUP_KEY_SNAPSHOT_SIZE ::
	11 +
	MAX_GROUP_KEY_STATES * (111 + MAX_GROUP_SKIPPED_KEYS * 36) +
	32
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

	for s in record.states[:record.count] do if s.id == id {
		return .Conflicting_Key
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

	if record.count == 0 do return 0, .Unknown_Key

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

	if group_record_alias(record, dst[:required]) {
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

	if len(src) < 1 do return {}, .Invalid_Protobuf

	if src[0] != SIGNAL_GROUP_VERSION {
		return {}, .Invalid_Version
	}

	at, seen := 1, cast(u8)0
	for at < len(src) {
		f, e := protobuf_field_read(src, &at)
		if e != .None do return {}, .Invalid_Protobuf

		if f.number < 1 || f.number > 4 do continue

		mask := cast(u8)1 << f.number
		if seen & mask != 0 do return {}, .Duplicate_Field

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
				if !group_public_valid(d.signing_public) {
					return {}, .Invalid_Key
				}

			}

		}

	}
	if seen != 30 do return {}, .Missing_Field

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
	if e != .None do return e

	for &s in record.states[:record.count] {
		if s.id != d.id do continue

		if crypto.compare_constant_time(
			   s.signing_public[:],
			   d.signing_public[:],
		   ) !=
		   1 {
			return .Conflicting_Key
		}

		if cast(u64)d.iteration == s.next_iteration &&
		   crypto.compare_constant_time(
			   s.chain_seed[:],
			   d.chain_seed[:],
		   ) !=
			   1 {
			return .Conflicting_Key
		}

		if cast(u64)d.iteration > s.next_iteration {
			// Authentication is provided by the pairwise distribution channel.
			// Keep already cached old keys, but do not restore consumed ones.
			s.next_iteration, s.chain_seed =
				cast(u64)d.iteration, d.chain_seed
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

	if len(src) < 65 do return {}, .Invalid_Protobuf

	if src[0] != SIGNAL_GROUP_VERSION {
		return {}, .Invalid_Version
	}

	m.signed_bytes, m.signature =
		src[:len(src) - 64], src[len(src) - 64:]
	at, seen := 1, cast(u8)0
	for at < len(m.signed_bytes) {
		f, e := protobuf_field_read(m.signed_bytes, &at)
		if e != .None do return {}, .Invalid_Protobuf

		if f.number < 1 || f.number > 3 do continue

		mask := cast(u8)1 << f.number
		if seen & mask != 0 do return {}, .Duplicate_Field

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
	if seen != 14 do return {}, .Missing_Field

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

	size :=
		group_message_header_size(id, iteration, len(ciphertext)) +
		len(ciphertext) +
		64
	if len(dst) < size do return 0, .Destination_Undersized

	if bytes.alias(dst[:size], ciphertext) {
		return 0, .Overlapping_Buffers
	}

	when !crypto.HAS_RAND_BYTES do return 0, .Entropy_Unavailable
	written = group_message_header(
		dst,
		id,
		iteration,
		len(ciphertext),
	)
	written += copy(dst[written:], ciphertext)
	signature, e := signal_curve_sign(signing_private, dst[:written])
	if e != .None do return 0, .Signature_Failed

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

	if record.count == 0 do return 0, .Unknown_Key

	s := &record.states[record.count - 1]
	if !s.has_private do return 0, .Invalid_Key

	iteration := s.next_iteration
	if iteration != 0 do iteration += 1

	if iteration > cast(u64)max(u32) {
		return 0, .Counter_Exhausted
	}

	if len(plaintext) > MAX_SIGNAL_PLAINTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	cipher_size := (len(plaintext) / 16 + 1) * 16
	header_size := group_message_header_size(
		s.id,
		cast(u32)iteration,
		cipher_size,
	)
	size := header_size + cipher_size + 64
	if len(dst) < size do return 0, .Destination_Undersized

	if bytes.alias(dst[:size], plaintext) ||
	   group_record_alias(record, dst[:size]) ||
	   group_record_alias(record, plaintext) {
		return 0, .Overlapping_Buffers
	}

	when !crypto.HAS_RAND_BYTES do return 0, .Entropy_Unavailable
	candidate := s^
	defer crypto.zero_explicit(&candidate, size_of(candidate))
	seed, e := group_message_seed(&candidate, cast(u32)iteration)
	defer crypto.zero_explicit(&seed, size_of(seed))
	if e != .None do return 0, e

	keys := signal_group_message_keys(seed)
	defer crypto.zero_explicit(&keys, size_of(keys))
	_, ce := signal_cbc_encrypt(
		dst[header_size:][:cipher_size],
		keys.cipher_key,
		keys.iv,
		plaintext,
	)
	if ce != .None do return 0, .Cipher_Failed

	signed_size, sign_error := group_message_sign(dst, s, iteration, cipher_size)
	if sign_error != .None do return 0, sign_error

	s^ = candidate
	return signed_size, .None
}

group_message_sign :: proc(
	dst: []u8, s: ^Signal_Group_State, iteration: u64, cipher_size: int,
) -> (written: int, error: Signal_Group_Error) {
	written =
		group_message_header(
			dst,
			s.id,
			cast(u32)iteration,
			cipher_size,
		) +
		cipher_size
	signature, se := signal_curve_sign(
		s.signing_private,
		dst[:written],
	)
	if se != .None do return 0, .Signature_Failed

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
	if e != .None do return 0, e

	if bytes.alias(dst, wire) ||
	   group_record_alias(record, dst) ||
	   group_record_alias(record, wire) {
		return 0, .Overlapping_Buffers
	}

	index := -1
	for s, i in record.states[:record.count] do if s.id == m.id {
		index = i
	}

	if index < 0 do return 0, .Unknown_Key

	s := &record.states[index]
	if signal_curve_verify(
		   s.signing_public,
		   m.signed_bytes,
		   m.signature,
	   ) !=
	   .None {
		return 0, .Signature_Failed
	}

	candidate := s^
	defer crypto.zero_explicit(&candidate, size_of(candidate))
	seed, ke := group_message_seed(&candidate, m.iteration)
	defer crypto.zero_explicit(&seed, size_of(seed))
	if ke != .None do return 0, ke

	keys := signal_group_message_keys(seed)
	defer crypto.zero_explicit(&keys, size_of(keys))
	count, ce := signal_cbc_decrypt(
		dst,
		keys.cipher_key,
		keys.iv,
		m.ciphertext,
	)
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
			if key.iteration != iteration do continue

			seed = key.seed
			for j in i ..< state.skipped_count - 1 do state.skipped[j] = state.skipped[j + 1]
			state.skipped_count -= 1
			crypto.zero_explicit(
				&state.skipped[state.skipped_count],
				size_of(Signal_Group_Skipped_Key),
			)
			return seed, .None
		}
		return {}, .Replay
	}

	if cast(u64)iteration - state.next_iteration >
	   MAX_GROUP_FUTURE_MESSAGES {
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
			for i in 0 ..< state.skipped_count - 1 do state.skipped[i] = state.skipped[i + 1]
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

group_state_append :: proc(
	record: ^Signal_Group_Record,
	state: ^Signal_Group_State,
) {
	if record.count == MAX_GROUP_KEY_STATES {
		for i in 0 ..< record.count - 1 do record.states[i] = record.states[i + 1]
		record.count -= 1
	}

	record.states[record.count] = state^
	record.count += 1
}
group_public_valid :: proc(public: [32]u8) -> bool {
	// Strict verifier validates the public point before reading R/S. Deliberately
	// invalid R makes this a public-point check without duplicating curve code.
	zero: [64]u8
	return(
		signal_curve_verify(public, nil, zero[:]) !=
		.Invalid_Public_Key \
	)
}
group_record_validate :: proc(
	record: ^Signal_Group_Record,
) -> Signal_Group_Error {
	if record == nil ||
	   record.count < 0 ||
	   record.count > MAX_GROUP_KEY_STATES {
		return .Invalid_State
	}

	for &s, i in record.states[:record.count] {
		if s.next_iteration > cast(u64)max(u32) + 1 ||
		   s.skipped_count < 0 ||
		   s.skipped_count > MAX_GROUP_SKIPPED_KEYS ||
		   !group_public_valid(s.signing_public) {
			return .Invalid_State
		}

		for previous in record.states[:i] do if previous.id == s.id {
			return .Invalid_State
		}

		if s.has_private {
			public := signal_curve_public(s.signing_private)
			if crypto.compare_constant_time(
				   public[:],
				   s.signing_public[:],
			   ) !=
			   1 {
				return .Invalid_Key
			}

		} else if crypto.is_zero_constant_time(
			   s.signing_private[:],
		   ) !=
		   1 {
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
group_record_alias :: proc(
	record: ^Signal_Group_Record,
	src: []u8,
) -> bool {
	return bytes.alias(
		(cast(^[size_of(Signal_Group_Record)]u8)record)[:],
		src,
	)
}
group_uint_write :: proc(
	dst: []u8,
	at: ^int,
	field: u32,
	value: u64,
) {
	protobuf_varint_write(dst, at, cast(u64)field << 3)
	protobuf_varint_write(dst, at, value)
}
group_message_header_size :: proc(
	id, iteration: u32,
	size: int,
) -> int {
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
group_message_header :: proc(
	dst: []u8,
	id, iteration: u32,
	size: int,
) -> int {
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
	for s in record.states[:record.count] do size += 111 + s.skipped_count * 36
	if len(dst) < size do return 0, .Destination_Undersized

	if group_record_alias(record, dst[:size]) {
		return 0, .Overlapping_Buffers
	}

	copy(dst, []u8{'O', 'D', 'G', 'R', 'O', 'U', 'P', 0})
	at := 8
	group_put(dst, &at, 1, 2)
	group_put(dst, &at, cast(u64)record.count, 1)
	for &s in record.states[:record.count] {
		group_put(dst, &at, cast(u64)s.id, 4)
		group_put(dst, &at, s.next_iteration, 8)
		at += copy(dst[at:], s.chain_seed[:])
		at += copy(dst[at:], s.signing_public[:])
		at += copy(dst[at:], s.signing_private[:])
		group_put(dst, &at, (s.has_private ? 1 : 0), 1)
		group_put(dst, &at, cast(u64)s.skipped_count, 2)
		for &key in s.skipped[:s.skipped_count] {
			group_put(dst, &at, cast(u64)key.iteration, 4)
			at += copy(dst[at:], key.seed[:])
		}
	}
	digest := group_snapshot_hash(dst[:at])
	copy(dst[at:], digest[:])
	return size, .None
}

signal_group_record_decode :: proc(
	record: ^Signal_Group_Record,
	src: []u8,
) -> Signal_Group_Error {
	if record == nil do return .Invalid_State

	if len(src) > MAX_GROUP_KEY_SNAPSHOT_SIZE {
		return .Payload_Oversized
	}

	if len(src) < 43 ||
	   !bytes.equal(
			   src[:8],
			   []u8{'O', 'D', 'G', 'R', 'O', 'U', 'P', 0},
		   ) {
		return .Invalid_Snapshot
	}

	if group_record_alias(record, src) {
		return .Overlapping_Buffers
	}

	end := len(src) - 32
	digest := group_snapshot_hash(src[:end])
	if crypto.compare_constant_time(digest[:], src[end:]) != 1 {
		return .Checksum_Mismatch
	}

	at := 8
	if group_get(src, &at, 2) != 1 {
		return .Invalid_Snapshot
	}

	allocator := context.allocator
	next, allocation_err := new(Signal_Group_Record, allocator)
	if allocation_err != nil do return .Allocation_Failed

	defer {
		signal_group_record_clear(next)
		free(next, allocator)
	}
	next.count = cast(int)group_get(src, &at, 1)
	if next.count > MAX_GROUP_KEY_STATES {
		return .Invalid_Snapshot
	}

	if state_error := group_snapshot_states_decode(next, src, &at, end);
	   state_error != .None do return state_error
	if at != end do return .Invalid_Snapshot

	if e := group_record_validate(next); e != .None {
		return e
	}

	signal_group_record_clear(record)
	record^ = next^
	return .None
}

group_snapshot_states_decode :: proc(
	next: ^Signal_Group_Record, src: []u8, at: ^int, end: int,
) -> Signal_Group_Error {
	for &s in next.states[:next.count] {
		if end - at^ < 111 do return .Invalid_Snapshot

		s.id = cast(u32)group_get(src, at, 4)
		s.next_iteration = group_get(src, at, 8)
		at^ += copy(s.chain_seed[:], src[at^:][:32])
		at^ += copy(s.signing_public[:], src[at^:][:32])
		at^ += copy(s.signing_private[:], src[at^:][:32])
		flag := group_get(src, at, 1)
		if flag > 1 do return .Invalid_Snapshot

		s.has_private = flag == 1
		s.skipped_count = cast(int)group_get(src, at, 2)
		if s.skipped_count > MAX_GROUP_SKIPPED_KEYS ||
		   s.skipped_count * 36 > end - at^ {
			return .Invalid_Snapshot
		}

		for &key in s.skipped[:s.skipped_count] {
			key.iteration = cast(u32)group_get(src, at, 4)
			at^ += copy(key.seed[:], src[at^:][:32])
		}
	}
	return .None
}
group_snapshot_hash :: proc(src: []u8) -> [32]u8 {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, src)
	digest: [32]u8
	sha2.final(&ctx, digest[:])
	return digest
}
group_put :: proc(dst: []u8, at: ^int, value: u64, size: int) {
	for i in 0 ..< size do dst[at^ + i] = cast(u8)(value >> cast(uint)((size - 1 - i) * 8))
	at^ += size
}
group_get :: proc(src: []u8, at: ^int, size: int) -> u64 {
	value: u64
	for i in 0 ..< size do value = value << 8 | cast(u64)src[at^ + i]
	at^ += size
	return value
}

group_bytes_write :: proc(
	dst: []u8,
	at: ^int,
	field: u32,
	value: []u8,
) {
	protobuf_varint_write(dst, at, cast(u64)field << 3 | 2)
	protobuf_varint_write(dst, at, cast(u64)len(value))
	at^ += copy(dst[at^:], value)
}

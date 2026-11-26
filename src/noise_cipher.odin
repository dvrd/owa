package whatsapp

import "core:bytes"
import "core:crypto"
import "core:crypto/aes"
import "core:crypto/hkdf"
import "core:crypto/sha2"
import "core:encoding/endian"

NOISE_HEADER :: [4]u8{87, 65, 6, 3}

NOISE_MODE :: "Noise_XX_25519_AESGCM_SHA256\x00\x00\x00\x00"
NOISE_TAG_SIZE :: 16
MAX_NOISE_PLAINTEXT_SIZE :: MAX_FRAME_PAYLOAD - NOISE_TAG_SIZE
NOISE_COUNTER_LIMIT :: cast(u64)1 << 32

Noise_Phase :: enum {
	Uninitialized,
	Handshake,
	Transport,
	Failed,
}

Noise_Error :: enum {
	None,
	Invalid_State,
	Destination_Undersized,
	Overlapping_Buffers,
	Ciphertext_Too_Short,
	Payload_Oversized,
	Counter_Exhausted,
	Authentication_Failed,
}

// Internal, caller-owned state; keep at a stable address and do not copy or
// mutate it while live. DH and certificate authentication live above this
// symmetric layer. Counters are u64 only to represent the exhausted 2^32 state.
Noise_State :: struct {
	hash:                        [32]u8,
	chaining_key:                [32]u8,
	write_key:                   [32]u8,
	read_key:                    [32]u8,
	write_counter, read_counter: u64,
	phase:                       Noise_Phase,
	failure:                     Noise_Error,
}

// Initialization skips the empty-payload hash. The 32-byte protocol name
// includes four trailing NULs.
// The initial ck/keys remain the protocol name while h mixes header then e.
noise_init :: proc(state: ^Noise_State, ephemeral_public: [32]u8) -> Noise_Error {
	if state == nil || state.phase != .Uninitialized {
		return .Invalid_State
	}

	mode := NOISE_MODE
	copy(state.hash[:], transmute([]u8)mode)
	state.chaining_key = state.hash
	state.write_key, state.read_key = state.hash, state.hash
	state.write_counter, state.read_counter = 0, 0
	state.failure = .None
	state.phase = .Handshake
	header := NOISE_HEADER
	ephemeral := ephemeral_public
	noise_mix_hash(state, header[:])
	noise_mix_hash(state, ephemeral[:])

	return .None
}

// Stop updating the handshake hash once the transport keys are installed.
noise_mix_hash :: proc(state: ^Noise_State, data: []u8) -> Noise_Error {
	if err := noise_state_validate(state); err != .None {
		return err
	}

	if state.phase == .Transport {
		return .None
	}

	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, state.hash[:])
	sha2.update(&ctx, data)
	sha2.final(&ctx, state.hash[:])

	return .None
}

// HKDF-SHA256(IKM=DH, salt=ck, info="", length=64). Both handshake
// directions use the second half, and share a single counter until split.
noise_mix_key :: proc(state: ^Noise_State, shared: [32]u8) -> Noise_Error {
	if err := noise_state_validate(state); err != .None {
		return err
	}

	if state.phase != .Handshake {
		return .Invalid_State
	}

	secret := shared
	defer crypto.zero_explicit(&secret, size_of(secret))

	derived: [64]u8
	defer crypto.zero_explicit(&derived, size_of(derived))

	hkdf.extract_and_expand(.SHA256, state.chaining_key[:], secret[:], nil, derived[:])
	copy(state.chaining_key[:], derived[:32])
	copy(state.write_key[:], derived[32:])
	state.read_key = state.write_key
	state.write_counter, state.read_counter = 0, 0

	return .None
}

// Initiator split: first HKDF half writes, second reads. There is no AAD in
// transport mode, and send/receive nonces advance independently from zero.
// A second split is rejected so traffic nonces can never be reset accidentally.
noise_split :: proc(state: ^Noise_State) -> Noise_Error {
	if err := noise_state_validate(state); err != .None {
		return err
	}

	if state.phase != .Handshake {
		return .Invalid_State
	}

	derived: [64]u8
	defer crypto.zero_explicit(&derived, size_of(derived))

	hkdf.extract_and_expand(.SHA256, state.chaining_key[:], nil, nil, derived[:])
	copy(state.write_key[:], derived[:32])
	copy(state.read_key[:], derived[32:])
	crypto.zero_explicit(&state.chaining_key, size_of(state.chaining_key))
	crypto.zero_explicit(&state.hash, size_of(state.hash))
	state.write_counter, state.read_counter = 0, 0
	state.phase = .Transport

	return .None
}

// Appends a 16-byte GCM tag. Invalid local buffer arguments do not advance
// counters, update h, or write dst. Source and destination must not overlap.
noise_encrypt :: proc(
	state: ^Noise_State,
	dst, plaintext: []u8,
) -> (
	written: int,
	error: Noise_Error,
) {
	if err := noise_state_validate(state); err != .None {
		return 0, err
	}

	if len(plaintext) > MAX_NOISE_PLAINTEXT_SIZE {
		return 0, .Payload_Oversized
	}

	if len(dst) < NOISE_TAG_SIZE || len(plaintext) > len(dst) - NOISE_TAG_SIZE {
		return 0, .Destination_Undersized
	}

	written = len(plaintext) + NOISE_TAG_SIZE

	if bytes.alias(dst[:written], plaintext) {
		return 0, .Overlapping_Buffers
	}

	if state.write_counter >= NOISE_COUNTER_LIMIT {
		return 0, noise_fail(state, .Counter_Exhausted)
	}

	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, state.write_key[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))

	nonce := noise_nonce(state.write_counter)
	aad: []u8
	if state.phase == .Handshake {
		aad = state.hash[:]
	}

	aes.seal_gcm(&ctx, dst[:len(plaintext)], dst[len(plaintext):written], nonce[:], aad, plaintext)
	state.write_counter += 1
	noise_mix_hash(state, dst[:written])

	return written, .None
}

// During the handshake decryption advances the same counter as encryption.
// Authentication failure clears dst and permanently destroys this state.
noise_decrypt :: proc(
	state: ^Noise_State,
	dst, ciphertext: []u8,
) -> (
	written: int,
	error: Noise_Error,
) {
	if err := noise_state_validate(state); err != .None {
		return 0, err
	}

	if len(ciphertext) < NOISE_TAG_SIZE {
		return 0, .Ciphertext_Too_Short
	}

	if len(ciphertext) > MAX_FRAME_PAYLOAD {
		return 0, .Payload_Oversized
	}

	written = len(ciphertext) - NOISE_TAG_SIZE

	if len(dst) < written {
		return 0, .Destination_Undersized
	}

	if bytes.alias(dst[:written], ciphertext) {
		return 0, .Overlapping_Buffers
	}

	counter := state.write_counter

	if state.phase == .Transport {
		counter = state.read_counter
	}

	if counter >= NOISE_COUNTER_LIMIT {
		return 0, noise_fail(state, .Counter_Exhausted)
	}

	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, state.read_key[:])
	defer crypto.zero_explicit(&ctx, size_of(ctx))

	nonce := noise_nonce(counter)
	aad: []u8
	if state.phase == .Handshake {
		aad = state.hash[:]
	}

	valid := aes.open_gcm(
		&ctx,
		dst[:written],
		nonce[:],
		aad,
		ciphertext[:written],
		ciphertext[written:],
	)

	if !valid {
		crypto.zero_explicit(raw_data(dst), written)
		return 0, noise_fail(state, .Authentication_Failed)
	}

	if state.phase == .Transport {
		state.read_counter += 1
	} else {
		state.write_counter += 1
	}

	noise_mix_hash(state, ciphertext)

	return written, .None
}

noise_clear :: proc(state: ^Noise_State) {
	if state != nil {
		crypto.zero_explicit(state, size_of(Noise_State))
	}
}

noise_nonce :: proc(counter: u64) -> [12]u8 {
	nonce: [12]u8
	endian.unchecked_put_u32be(nonce[8:], u32(counter))
	return nonce
}

noise_state_validate :: proc(state: ^Noise_State) -> Noise_Error {
	if state == nil || state.phase == .Uninitialized {
		return .Invalid_State
	}

	if state.phase == .Failed {
		return state.failure
	}

	return .None
}

noise_fail :: proc(state: ^Noise_State, err: Noise_Error) -> Noise_Error {
	noise_clear(state)
	state.phase, state.failure = .Failed, err

	return err
}

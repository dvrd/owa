package whatsapp

import "core:crypto"
import grp "core:crypto/_edwards25519"
import field "core:crypto/_fiat/field_curve25519"
import "core:crypto/sha2"
import "core:crypto/x25519"

/*
Signal's Curve25519 signature construction follows curve25519-js 0.0.4:
https://github.com/harveyconnor/curve25519-js (lib/index.js).
The pinned libsignal wrapper is bcea72df9ec34d9d9140ab30619cf479c7c144c7.
Scalar/group arithmetic is provided by Odin's core crypto packages.

Copyright (c) 2019 Smart Guide Pty Ltd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

Signal_Error :: enum {
	None,
	Entropy_Unavailable,
	Nonce_Generation_Failed,
	Invalid_Public_Key,
	Invalid_Signature_Length,
	Invalid_Signature_Encoding,
	Verification_Failed,
}

// Raw 32-byte Montgomery public key, without Signal's key-type prefix 0x05.
signal_curve_public :: proc(private: [32]u8) -> [32]u8 {
	secret := private
	defer crypto.zero_explicit(&secret, size_of(secret))

	public: [32]u8
	x25519.scalarmult_basepoint(public[:], secret[:])

	return public
}

// This is Signal's direct/clamped-scalar signature variant, not Ed25519 seed
// signing. Randomized nonces use curve25519-js's domain-separated 64-byte
// random-suffix construction. Its verifier also accepts deterministic legacy
// signatures. The Edwards public-key sign bit is carried in signature[63].
signal_curve_sign :: proc(
	private: [32]u8,
	message: []u8,
) -> (
	signature: [64]u8,
	error: Signal_Error,
) {
	when !crypto.HAS_RAND_BYTES {
		return {}, .Entropy_Unavailable
	}

	secret := private
	defer crypto.zero_explicit(&secret, size_of(secret))

	secret[0] &= 248
	secret[31] = (secret[31] & 127) | 64
	a, nonce, challenge, s: grp.Scalar
	defer grp.sc_clear(&a)

	defer grp.sc_clear(&nonce)

	defer grp.sc_clear(&challenge)

	defer grp.sc_clear(&s)

	grp.sc_set_bytes_rfc8032(&a, secret[:])
	A, R: grp.Group_Element
	defer grp.ge_clear(&A)

	defer grp.ge_clear(&R)

	grp.ge_scalarmult_basepoint(&A, &a)
	public: [32]u8
	grp.ge_bytes(&A, public[:])
	random, digest: [64]u8
	defer crypto.zero_explicit(&random, size_of(random))

	defer crypto.zero_explicit(&digest, size_of(digest))

	domain: [32]u8
	for &value in domain {
		value = 0xff
	}

	domain[0] = 0xfe
	ctx: sha2.Context_512
	defer crypto.zero_explicit(&ctx, size_of(ctx))

	// Avoid the negligible zero-nonce case because verification rejects all
	// low-order R points. Independent randomness is sampled on each attempt.
	zero: grp.Scalar
	generated := false

	for _ in 0 ..< 8 {
		crypto.rand_bytes(random[:])
		sha2.init_512(&ctx)
		sha2.update(&ctx, domain[:])
		sha2.update(&ctx, secret[:])
		sha2.update(&ctx, message)
		sha2.update(&ctx, random[:])
		sha2.final(&ctx, digest[:])
		grp.sc_set_bytes_wide(&nonce, &digest)

		if grp.sc_equal(&nonce, &zero) != 1 {
			generated = true
			break
		}
	}

	if !generated {
		return {}, .Nonce_Generation_Failed
	}

	grp.ge_scalarmult_basepoint(&R, &nonce)
	grp.ge_bytes(&R, signature[:32])
	sha2.init_512(&ctx)
	sha2.update(&ctx, signature[:32])
	sha2.update(&ctx, public[:])
	sha2.update(&ctx, message)
	sha2.final(&ctx, digest[:])
	grp.sc_set_bytes_wide(&challenge, &digest)
	grp.sc_mul(&s, &challenge, &a)
	grp.sc_add(&s, &s, &nonce)
	grp.sc_bytes(signature[32:], &s)
	signature[63] |= public[31] & 0x80

	return signature, .None
}

// Strict verification: canonical Montgomery key, canonical R/S encodings,
// and prime-order A/R. This intentionally rejects malformed/malleable encodings
// tolerated by older JS verifiers; correctly generated signatures interoperate.
signal_curve_verify :: proc(public: [32]u8, message, signature: []u8) -> Signal_Error {
	if len(signature) != 64 {
		return .Invalid_Signature_Length
	}

	ed_public, public_error := signal_curve_edwards_public(public, signature)
	if public_error != .None {
		return public_error
	}

	A, R, neg_A, calculated: grp.Group_Element
	if !grp.ge_set_bytes(&A, ed_public[:]) ||
	   grp.ge_is_small_order(&A) ||
	   !grp.ge_in_prime_order_subgroup_vartime(&A) {
		return .Invalid_Public_Key
	}

	if !grp.ge_set_bytes(&R, signature[:32]) ||
	   grp.ge_is_small_order(&R) ||
	   !grp.ge_in_prime_order_subgroup_vartime(&R) {
		return .Invalid_Signature_Encoding
	}

	s_bytes: [32]u8
	copy(s_bytes[:], signature[32:])
	s_bytes[31] &= 127
	s, challenge: grp.Scalar

	if !grp.sc_set_bytes(&s, s_bytes[:]) {
		return .Invalid_Signature_Encoding
	}

	ctx: sha2.Context_512
	digest: [64]u8
	sha2.init_512(&ctx)
	sha2.update(&ctx, signature[:32])
	sha2.update(&ctx, ed_public[:])
	sha2.update(&ctx, message)
	sha2.final(&ctx, digest[:])
	grp.sc_set_bytes_wide(&challenge, &digest)
	grp.ge_negate(&neg_A, &A)
	grp.ge_double_scalarmult_basepoint_vartime(&calculated, &challenge, &neg_A, &s)

	if grp.ge_equal(&calculated, &R) != 1 {
		return .Verification_Failed
	}

	return .None
}

signal_curve_edwards_public :: proc(public: [32]u8, signature: []u8) -> ([32]u8, Signal_Error) {
	public_copy := public
	u, one, numerator, denominator, inverse, y, zero: field.Tight_Field_Element
	field.fe_from_bytes(&u, &public_copy)

	if field.fe_equal_bytes(&u, &public_copy) != 1 {
		return {}, .Invalid_Public_Key
	}

	field.fe_one(&one)
	field.fe_carry_add(&denominator, &u, &one)

	if field.fe_equal(&denominator, &zero) == 1 {
		return {}, .Invalid_Public_Key
	}

	field.fe_carry_sub(&numerator, &u, &one)
	field.fe_carry_inv(&inverse, field.fe_relax_cast(&denominator))
	field.fe_carry_mul(&y, field.fe_relax_cast(&numerator), field.fe_relax_cast(&inverse))
	ed_public: [32]u8
	field.fe_to_bytes(&ed_public, &y)
	ed_public[31] |= signature[63] & 0x80

	return ed_public, .None
}

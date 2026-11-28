package whatsapp

import "core:crypto"
import "core:time"

Certificate_Error :: enum {
	None,
	Invalid_Certificate_Chain,
	Missing_Intermediate,
	Invalid_Intermediate_Details,
	Missing_Leaf,
	Invalid_Leaf_Details,
	Invalid_Key_Length,
	Invalid_Signature_Length,
	Invalid_Intermediate_Signature,
	Invalid_Leaf_Signature,
	Invalid_Validity,
	Certificate_Not_Yet_Valid,
	Certificate_Expired,
	Static_Key_Mismatch,
	Unexpected_Issuer_Serial,
	Rejected,
}

Certificate_Verifier :: #type proc(payload: []u8, server_static: [32]u8) -> Certificate_Error

// Trust anchor matches pinned Whatsmeow c88388f983b4bc43.
// SHA256: 8f5c9b62980545504f24221417a5ebd8
// 0fafd0c4f85f0b33e3aed78445a0cd7d. These are Signal Curve25519 signing keys.
NOISE_CERTIFICATE_ROOT := [32]u8 {
	0x14,
	0x23,
	0x75,
	0x57,
	0x4d,
	0x0a,
	0x58,
	0x71,
	0x66,
	0xaa,
	0xe7,
	0x1e,
	0xbe,
	0x51,
	0x64,
	0x37,
	0xc4,
	0xa2,
	0x8b,
	0x73,
	0xe3,
	0x69,
	0x5c,
	0x6c,
	0xe1,
	0xf7,
	0xf9,
	0x54,
	0x5d,
	0xa8,
	0xee,
	0x6b,
}

verify_whatsapp_server_certificate :: proc(
	payload: []u8,
	server_static: [32]u8,
) -> Certificate_Error {
	return verify_whatsapp_server_certificate_at(payload, server_static, time.now())
}

// The controlled clock permits deterministic qualification of genuine captures.
// The only production root is pinned above; a custom verifier remains explicit.
verify_whatsapp_server_certificate_at :: proc(
	payload: []u8,
	server_static: [32]u8,
	now: time.Time,
) -> Certificate_Error {
	return verify_certificate_chain_against_root(
		payload,
		server_static,
		now,
		NOISE_CERTIFICATE_ROOT,
	)
}

verify_certificate_chain_against_root :: proc(
	payload: []u8,
	server_static: [32]u8,
	now: time.Time,
	root: [32]u8,
) -> Certificate_Error {
	chain, decoded := cert_chain_decode(payload)
	if decoded != .None {
		return .Invalid_Certificate_Chain
	}

	if !chain.has_intermediate {
		return .Missing_Intermediate
	}

	if !chain.has_leaf {
		return .Missing_Leaf
	}

	intermediate, intermediate_error := decode_and_validate_certificate_details(
		chain.intermediate,
		true,
	)
	if intermediate_error != .None {
		return intermediate_error
	}

	leaf, leaf_error := decode_and_validate_certificate_details(chain.leaf, false)
	if leaf_error != .None {
		return leaf_error
	}

	if intermediate.issuer_serial != 0 || leaf.issuer_serial != intermediate.serial {
		return .Unexpected_Issuer_Serial
	}

	if signal_curve_verify(root, chain.intermediate.details, chain.intermediate.signature) !=
	   .None {
		return .Invalid_Intermediate_Signature
	}

	intermediate_key: [32]u8
	copy(intermediate_key[:], intermediate.key)
	if signal_curve_verify(intermediate_key, chain.leaf.details, chain.leaf.signature) != .None {
		return .Invalid_Leaf_Signature
	}

	observed_static := server_static
	if crypto.compare_constant_time(leaf.key, observed_static[:]) != 1 {
		return .Static_Key_Mismatch
	}

	if error := check_certificate_validity_at(intermediate, now); error != .None {
		return error
	}

	return check_certificate_validity_at(leaf, now)
}

decode_and_validate_certificate_details :: proc(
	certificate: Noise_Certificate,
	intermediate: bool,
) -> (
	Certificate_Details,
	Certificate_Error,
) {
	detail_error := Certificate_Error.Invalid_Leaf_Details
	if intermediate {
		detail_error = .Invalid_Intermediate_Details
	}

	if !certificate.has_details {
		return {}, detail_error
	}

	if !certificate.has_signature || len(certificate.signature) != 64 {
		return {}, .Invalid_Signature_Length
	}

	details, decoded := certificate_details_decode(certificate.details)
	if decoded != .None {
		return {}, detail_error
	}

	if !details.has_issuer_serial || intermediate && !details.has_serial {
		return {}, .Unexpected_Issuer_Serial
	}

	if !details.has_key || len(details.key) != 32 {
		return {}, .Invalid_Key_Length
	}

	if !details.has_not_before ||
	   !details.has_not_after ||
	   details.not_before > details.not_after ||
	   details.not_after > u64(max(i64)) {
		return {}, .Invalid_Validity
	}

	return details, .None
}

check_certificate_validity_at :: proc(
	details: Certificate_Details,
	now: time.Time,
) -> Certificate_Error {
	if now._nsec < 0 {
		return .Invalid_Validity
	}

	seconds := u64(time.to_unix_seconds(now))

	if seconds < details.not_before {
		return .Certificate_Not_Yet_Valid
	}

	// Compare seconds directly: untrusted u64 epochs never become nanoseconds.
	// As in the pinned primary policy, the exact end instant itself is valid.
	if seconds > details.not_after ||
	   seconds == details.not_after && now._nsec % i64(time.Second) != 0 {
		return .Certificate_Expired
	}

	return .None
}

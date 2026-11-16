package whatsapp

import "core:testing"
import "core:time"

Policy_Test_Details :: struct {
 serial, issuer: u32,
 key: [32]u8,
 before, after: u64,
 present: u8,
 key_size: int,
 extra: u8,
}
Policy_Test_Options :: struct {
 intermediate, leaf: Policy_Test_Details,
 intermediate_signature_size, leaf_signature_size: int,
}
Policy_Test_Fixture :: struct {
 payload: [1024]u8,
 size: int,
 root, server_static: [32]u8,
}

policy_test_options :: proc() -> Policy_Test_Options {
 return {intermediate = {serial = 7, issuer = 0, before = 100, after = 200,
   present = 31, key_size = 32},
  leaf = {serial = 11, issuer = 7, before = 100, after = 200, present = 31, key_size = 32},
  intermediate_signature_size = 64, leaf_signature_size = 64}
}

policy_test_bytes :: proc(dst: []u8, at: ^int, number: u64, value: []u8) {
 assert(len(value) + 20 <= len(dst) - at^)
 protobuf_varint_write(dst, at, number << 3 | 2)
 protobuf_varint_write(dst, at, u64(len(value)))
 at^ += copy(dst[at^:], value)
}

policy_test_scalar :: proc(dst: []u8, at: ^int, number, value: u64) {
 assert(len(dst) - at^ >= 20)
 protobuf_varint_write(dst, at, number << 3)
 protobuf_varint_write(dst, at, value)
}

policy_test_details :: proc(dst: []u8, fields: Policy_Test_Details) -> int {
 at := 0
 if fields.present & 1 != 0 {policy_test_scalar(dst, &at, 1, u64(fields.serial))}
 if fields.present & 2 != 0 {policy_test_scalar(dst, &at, 2, u64(fields.issuer))}
 key := fields.key
 if fields.present & 4 != 0 {policy_test_bytes(dst, &at, 3, key[:fields.key_size])}
 if fields.present & 8 != 0 {policy_test_scalar(dst, &at, 4, fields.before)}
 if fields.present & 16 != 0 {policy_test_scalar(dst, &at, 5, fields.after)}
 if fields.extra == 1 {policy_test_scalar(dst, &at, 99, 42)}
 if fields.extra == 2 {policy_test_scalar(dst, &at, 1, u64(fields.serial))}
 return at
}

policy_test_certificate :: proc(dst: []u8, certificate: Noise_Certificate) -> int {
 at := 0
 if certificate.has_details {policy_test_bytes(dst, &at, 1, certificate.details)}
 if certificate.has_signature {policy_test_bytes(dst, &at, 2, certificate.signature)}
 return at
}

policy_test_chain :: proc(dst: []u8, chain: Cert_Chain) -> int {
 at := 0
 encoded: [512]u8
 if chain.has_leaf {
  size := policy_test_certificate(encoded[:], chain.leaf)
  policy_test_bytes(dst, &at, 1, encoded[:size])
 }
 if chain.has_intermediate {
  size := policy_test_certificate(encoded[:], chain.intermediate)
  policy_test_bytes(dst, &at, 2, encoded[:size])
 }
 return at
}

policy_test_fixture :: proc(options: Policy_Test_Options) -> Policy_Test_Fixture {
 root_private, intermediate_private, leaf_private: [32]u8
 for index in 0..<32 {
  root_private[index] = u8(index + 1)
  intermediate_private[index] = u8(index + 41)
  leaf_private[index] = u8(index + 81)
 }
 fixture := Policy_Test_Fixture{root = signal_curve_public(root_private),
  server_static = signal_curve_public(leaf_private)}
 intermediate, leaf := options.intermediate, options.leaf
 intermediate.key = signal_curve_public(intermediate_private)
 leaf.key = fixture.server_static
 intermediate_wire, leaf_wire: [256]u8
 intermediate_size := policy_test_details(intermediate_wire[:], intermediate)
 leaf_size := policy_test_details(leaf_wire[:], leaf)
 intermediate_signature, first := signal_curve_sign(root_private,
  intermediate_wire[:intermediate_size])
 leaf_signature, second := signal_curve_sign(intermediate_private, leaf_wire[:leaf_size])
 assert(first == .None && second == .None)
 chain := Cert_Chain{has_leaf = true, has_intermediate = true,
  intermediate = {has_details = true, has_signature = true,
   details = intermediate_wire[:intermediate_size],
   signature = intermediate_signature[:options.intermediate_signature_size]},
  leaf = {has_details = true, has_signature = true, details = leaf_wire[:leaf_size],
   signature = leaf_signature[:options.leaf_signature_size]}}
 fixture.size = policy_test_chain(fixture.payload[:], chain)
 return fixture
}

policy_test_verify :: proc(fixture: ^Policy_Test_Fixture,
 now: time.Time = time.Time{_nsec = 150_000_000_000}) -> Certificate_Error {
 return strict_certificate_chain_verify(fixture.payload[:fixture.size],
  fixture.server_static, now, fixture.root)
}

@(test)
certificate_policy_valid_synthetic_chain_does_not_replace_pinned_root :: proc(t: ^testing.T) {
 fixture := policy_test_fixture(policy_test_options())
 testing.expect_value(t, policy_test_verify(&fixture), .None)
 testing.expect_value(t, strict_certificate_policy_at(fixture.payload[:fixture.size],
  fixture.server_static, time.unix(150, 0)), .Invalid_Intermediate_Signature)
 fixture.root[0] ~= 1
 testing.expect_value(t, policy_test_verify(&fixture), .Invalid_Intermediate_Signature)
 options := policy_test_options(); options.leaf.present &= ~u8(1)
 serial_optional := policy_test_fixture(options)
 testing.expect_value(t, policy_test_verify(&serial_optional), .None)
}

@(test)
certificate_policy_checks_both_raw_signatures_and_server_static :: proc(t: ^testing.T) {
 for index in 0..<5 {
  fixture := policy_test_fixture(policy_test_options())
  chain, decoded := cert_chain_decode(fixture.payload[:fixture.size]); assert(decoded == .None)
  expected := Certificate_Error.Invalid_Intermediate_Signature
  if index == 0 {chain.intermediate.signature[0] ~= 1}
  if index == 1 {chain.leaf.signature[0] ~= 1; expected = .Invalid_Leaf_Signature}
  if index == 2 {
   details, error := certificate_details_decode(chain.intermediate.details); assert(error == .None)
   details.key[0] ~= 1
  }
  if index == 3 {
   details, error := certificate_details_decode(chain.leaf.details); assert(error == .None)
   details.key[0] ~= 1
   expected = .Invalid_Leaf_Signature
  }
  if index == 4 {fixture.server_static[0] ~= 1; expected = .Static_Key_Mismatch}
  testing.expect_value(t, policy_test_verify(&fixture), expected)
 }
 options := policy_test_options(); options.leaf.extra = 1
 fixture := policy_test_fixture(options)
 testing.expect_value(t, policy_test_verify(&fixture), .None)
 fixture.payload[fixture.size - 1] ~= 1
 testing.expect(t, policy_test_verify(&fixture) != .None)
}

@(test)
certificate_policy_enforces_presence_lengths_and_issuer_linkage :: proc(t: ^testing.T) {
 for index in 0..<10 {
  options := policy_test_options()
  expected := Certificate_Error.Unexpected_Issuer_Serial
  switch index {
  case 0: options.intermediate.issuer = 1
  case 1: options.leaf.issuer = 8
  case 2: options.intermediate.present &= ~u8(1)
  case 3: options.leaf.present &= ~u8(2)
  case 4: options.intermediate.key_size = 31; expected = .Invalid_Key_Length
  case 5: options.leaf.key_size = 31; expected = .Invalid_Key_Length
  case 6: options.intermediate_signature_size = 63; expected = .Invalid_Signature_Length
  case 7: options.leaf_signature_size = 63; expected = .Invalid_Signature_Length
  case 8: options.leaf.extra = 2; expected = .Invalid_Leaf_Details
  case 9: options.intermediate.extra = 2; expected = .Invalid_Intermediate_Details
  }
  fixture := policy_test_fixture(options)
  testing.expect_value(t, policy_test_verify(&fixture), expected)
 }
}

@(test)
certificate_policy_checks_exact_time_boundaries_without_epoch_overflow :: proc(t: ^testing.T) {
 fixture := policy_test_fixture(policy_test_options())
 for row in ([]struct {now: time.Time, expected: Certificate_Error}{
  {time.unix(99, 999999999), .Certificate_Not_Yet_Valid},
  {time.unix(100, 0), .None}, {time.unix(200, 0), .None},
  {time.unix(200, 1), .Certificate_Expired}, {time.unix(-1, 0), .Invalid_Validity},
 }) {testing.expect_value(t, policy_test_verify(&fixture, row.now), row.expected)}
 for index in 0..<5 {
  options := policy_test_options()
  switch index {
  case 0: options.intermediate.before = 201
  case 1: options.leaf.before = 201
  case 2: options.intermediate.after = max(u64)
  case 3: options.leaf.after = max(u64)
  case 4: options.leaf.present &= ~u8(8)
  }
  malformed := policy_test_fixture(options)
  testing.expect_value(t, policy_test_verify(&malformed), .Invalid_Validity)
 }
}

@(test)
certificate_policy_malformed_or_incomplete_chain_fails_closed :: proc(t: ^testing.T) {
 fixture := policy_test_fixture(policy_test_options())
 malformed := [?]u8{0xff}
 testing.expect_value(t, strict_certificate_policy(malformed[:], fixture.server_static),
  .Invalid_Certificate_Chain)
 chain, decoded := cert_chain_decode(fixture.payload[:fixture.size]); assert(decoded == .None)
 for index in 0..<4 {
  copy := chain
  expected := Certificate_Error.Missing_Intermediate
  if index == 0 {copy.has_intermediate = false}
  if index == 1 {copy.has_leaf = false; expected = .Missing_Leaf}
  if index == 2 {copy.leaf.has_signature = false; expected = .Invalid_Signature_Length}
  if index == 3 {copy.intermediate.has_signature = false; expected = .Invalid_Signature_Length}
  payload: [1024]u8
  size := policy_test_chain(payload[:], copy)
  testing.expect_value(t, strict_certificate_chain_verify(payload[:size],
   fixture.server_static, time.unix(150, 0), fixture.root), expected)
 }
}

// Public server data only. Independent exact Whatsmeow/libsignal verification
// and the authenticated capture provenance accompany these two binary files.
PUBLIC_CERTIFICATE :: #load("tests/certificate_policy/certificate.bin")
PUBLIC_SERVER_STATIC :: #load("tests/certificate_policy/server-static.bin")
PUBLIC_CAPTURE_TIME_MS :: 1794504045498

@(test)
certificate_policy_genuine_public_chain_matches_pinned_signal_root :: proc(t: ^testing.T) {
 assert(len(PUBLIC_SERVER_STATIC) == 32)
 server_static: [32]u8
 copy(server_static[:], transmute([]u8)PUBLIC_SERVER_STATIC)
 captured := time.Time{_nsec = PUBLIC_CAPTURE_TIME_MS * i64(time.Millisecond)}
 testing.expect_value(t, strict_certificate_policy_at(transmute([]u8)PUBLIC_CERTIFICATE,
  server_static, captured), .None)
}

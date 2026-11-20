package whatsapp

import endian "core:encoding/endian"
import "core:bytes"
import "core:crypto"
import "core:crypto/hmac"
import "core:crypto/hash"
import "core:testing"
import "core:os"
import "core:fmt"

// Owned synthetic identities only. The signing and HMAC domains here are
// independent literal expectations from the immutable upstream declaration.
Pairing_Domain_Fixture :: struct {
	credentials:            Device_Credentials,
	account_private:        [32]u8,
	details:                [64]u8,
	details_size:           int,
	identity:               [512]u8,
	identity_size:          int,
	wrapper:                [1024]u8,
	wrapper_size:           int,
	iq_attrs, device_attrs: [1]Binary_Node_Attribute,
	iq_children:            [1]Binary_Node,
	pair_children:          [2]Binary_Node,
}

pairing_domain_field :: proc(dst: []u8, at: ^int, number: u64, value: []u8) {
	protobuf_varint_write(dst, at, number << 3 | 2)
	protobuf_varint_write(dst, at, u64(len(value)))
	at^ += copy(dst[at^:], value)
}

pairing_domain_fixture :: proc(
	wrapper_type: u32,
	device_type: int,
	account_domain: u8 = 255,
) -> ^Pairing_Domain_Fixture {
	f := new(Pairing_Domain_Fixture)
	error: Credentials_Error
	f.credentials, error = device_credentials_generate()
	assert(error == .None)
	for &b, i in f.account_private {
		b = u8(i + 129)
	}
	f.account_private[0] &= 248
	f.account_private[31] = f.account_private[31] & 127 | 64
	// rawId=42, timestamp=1, keyIndex=7; deviceType absent is ordinary default.
	copy(f.details[:], []u8{8, 42, 16, 1, 24, 7})
	f.details_size = 6
	if device_type >= 0 {
		f.details[6], f.details[7] = 40, u8(device_type)
		f.details_size = 8
	}
	prefix := account_domain
	if prefix == 255 {
		prefix = device_type == 1 ? 5 : 0
	}
	account_key := signal_curve_public(f.account_private)
	identity_key := signal_curve_public(f.credentials.identity_private)
	signed: [128]u8
	signed[0], signed[1] = 6, prefix
	copy(signed[2:], f.details[:f.details_size])
	copy(signed[2 + f.details_size:], identity_key[:])
	signature, sign_error := signal_curve_sign(f.account_private, signed[:2 + f.details_size + 32])
	assert(sign_error == .None)
	at := 0
	pairing_domain_field(f.identity[:], &at, 1, f.details[:f.details_size])
	pairing_domain_field(f.identity[:], &at, 2, account_key[:])
	pairing_domain_field(f.identity[:], &at, 3, signature[:])
	f.identity_size = at
	mac: [32]u8
	mac_context: hmac.Context
	hmac.init(&mac_context, .SHA256, f.credentials.adv_secret[:])
	if wrapper_type == 1 {
		hmac.update(&mac_context, []u8{6, 5})
	}
	hmac.update(&mac_context, f.identity[:f.identity_size])
	hmac.final(&mac_context, mac[:])
	crypto.zero_explicit(&mac_context, size_of(mac_context))
	at = 0
	pairing_domain_field(f.wrapper[:], &at, 1, f.identity[:f.identity_size])
	pairing_domain_field(f.wrapper[:], &at, 2, mac[:])
	protobuf_varint_write(f.wrapper[:], &at, 3 << 3)
	protobuf_varint_write(f.wrapper[:], &at, u64(wrapper_type))
	f.wrapper_size = at
	f.device_attrs = {{"jid", "123:4@s.whatsapp.net"}}
	f.iq_attrs = {{"id", "synthetic-pair"}}
	f.pair_children = {
		{tag = "device-identity", content = f.wrapper[:f.wrapper_size]},
		{tag = "device", attrs = f.device_attrs[:]},
	}
	f.iq_children = {{tag = "pair-success", content = f.pair_children[:]}}
	return f
}

pairing_domain_iq :: proc(f: ^Pairing_Domain_Fixture) -> Binary_Node {
	return {tag = "iq", attrs = f.iq_attrs[:], content = f.iq_children[:]}
}

pairing_domain_free :: proc(f: ^Pairing_Domain_Fixture) {
	crypto.zero_explicit(f, size_of(Pairing_Domain_Fixture))
	free(f)
}

pairing_domain_companion_verify :: proc(
	account: ^Paired_Account,
	credentials: ^Device_Credentials,
	domain: u8,
) -> Signal_Error {
	public := signal_curve_public(credentials.identity_private)
	message: [2 + MAX_PAIRING_DETAILS_SIZE + 64]u8
	message[0], message[1] = 6, domain
	copy(message[2:], account.details[:account.details_size])
	copy(message[2 + account.details_size:], public[:])
	copy(message[2 + account.details_size + 32:], account.account_signature_key[:])
	return signal_curve_verify(public, message[:2 + account.details_size + 64], account.device_signature[:])
}

@(test)
pairing_current_domains_follow_signed_device_type_independent_of_wrapper :: proc(t: ^testing.T) {
	for wrapper in 0 ..< 2 {
		for device in ([]int{-1, 0, 1}) {
			f := pairing_domain_fixture(u32(wrapper), device)
			defer pairing_domain_free(f)
			account: Paired_Account
			reply: [2048]u8
			_, error := pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
			testing.expect_value(t, error.kind, .None)

			if error.kind != .None {
				continue
			}

			testing.expect_value(t, pairing_domain_companion_verify(&account, &f.credentials, 1), .None)
			testing.expect(t, pairing_domain_companion_verify(&account, &f.credentials, 6) != .None)
			testing.expect_value(t, paired_account_validate(&account, &f.credentials).kind, .None)
		}
	}
}

pairing_domain_legacy_account :: proc(f: ^Pairing_Domain_Fixture, hosted: bool) -> Paired_Account {
	identity, error := pairing_signed_identity_decode(f.identity[:f.identity_size])
	assert(error == .None)
	account := Paired_Account {
		valid            = true,
		hosted           = hosted,
		key_index        = 7,
		signature_policy = .Legacy,
		jid_size         = len("123:4@s.whatsapp.net"),
		details_size     = f.details_size,
	}

	copy(account.jid[:], "123:4@s.whatsapp.net")
	copy(account.details[:], f.details[:f.details_size])
	copy(account.account_signature_key[:], identity.account_signature_key)
	copy(account.account_signature[:], identity.account_signature)
	public := signal_curve_public(f.credentials.identity_private)
	message: [128]u8
	message[0], message[1] = 6, hosted ? 6 : 1
	copy(message[2:], f.details[:f.details_size])
	copy(message[2 + f.details_size:], public[:])
	copy(message[2 + f.details_size + 32:], account.account_signature_key[:])
	sign_error: Signal_Error
	account.device_signature, sign_error = signal_curve_sign(
		f.credentials.identity_private,
		message[:2 + f.details_size + 64],
	); assert(sign_error == .None)

	return account
}

pairing_domain_auth :: proc(f: ^Pairing_Domain_Fixture, account: Paired_Account) -> Auth_State {
	state := Auth_State {
		credentials = f.credentials,
		account     = account,
	}

	state.credentials.registered = true

	return state
}

pairing_domain_checksum :: proc(data: []u8) {
	// Independent fixture envelope repair, not production state mutation.
	length := u32(len(data) - 46)
	endian.unchecked_put_u32be(data[10:14], length)
	hash.hash_bytes_to_buffer(.SHA256, data[:len(data) - 32], data[len(data) - 32:])
}

pairing_domain_v1 :: proc(dst, current: []u8) -> int {
	// Existing v1 account header ends at offset293. v2 inserts only policy there.
	assert(len(current) > 294 && current[9] == 2 && current[287] == 1)
	count := len(current) - 1
	copy(dst[:293], current[:293])
	copy(dst[293:count], current[294:])
	dst[9] = 1
	pairing_domain_checksum(dst[:count])

	return count
}

@(test)
pairing_current_rejects_wrong_domains_unknown_types_and_tampered_identity :: proc(t: ^testing.T) {
	for scenario in 0 ..< 6 {
		// Domain0 over hosted-declared details is valid under the legacy policy,
		// never an alternate acceptance path for new pairing.
		f := pairing_domain_fixture(0, 1, scenario == 0 ? 0 : 5)
		defer pairing_domain_free(f)

		if scenario == 1 {
			f.wrapper[f.wrapper_size - 1] = 2 // wrapper accountType checked before HMAC.
		}

		if scenario == 2 {
			bad := pairing_domain_fixture(0, 2)
			defer pairing_domain_free(bad)
			account: Paired_Account
			reply: [2048]u8
			_, error := pairing_success_handle(&account, pairing_domain_iq(bad), &bad.credentials, reply[:])
			testing.expect_value(t, error.kind, .Invalid_Account_Type)
			testing.expect(t, !account.valid)
			continue
		}

		if scenario == 3 {
			f.wrapper[f.wrapper_size - 4] ~= 1
		} // HMAC bytes.
		if scenario == 4 {
			f.wrapper[5] ~= 1
		} // Signed details without matching HMAC.
		if scenario == 5 {
			f.credentials.adv_secret[0] ~= 1
		}

		target: Paired_Account
		target.jid[0] = 0xa5
		reply: [2048]u8

		for &b in reply {
			b = 0xa5
		}

		_, error := pairing_success_handle(&target, pairing_domain_iq(f), &f.credentials, reply[:])
		testing.expect(t, error.kind != .None)
		testing.expect(t, !target.valid && target.jid[0] == 0xa5)

		for b in reply {
			testing.expect_value(t, b, u8(0xa5))
		}
	}
}

@(test)
pairing_auth_current_roundtrip_retains_policy_and_rejects_legacy_domain :: proc(t: ^testing.T) {
	for wrapper in 0 ..< 2 {
		for device in 0 ..< 2 {
			f := pairing_domain_fixture(u32(wrapper), device)
			defer pairing_domain_free(f)
			account: Paired_Account
			reply: [2048]u8
			_, error := pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
			assert(error.kind == .None)
			state := pairing_domain_auth(f, account)
			defer auth_state_clear(&state)
			encoded: [MAX_AUTH_STATE_SIZE]u8
			count, encode_error := auth_state_encode(encoded[:], &state)
			testing.expect_value(t, encode_error.kind, .None)
			testing.expect_value(t, encoded[9], u8(2))
			testing.expect_value(t, encoded[293], u8(1))
			restored: Auth_State
			defer auth_state_clear(&restored)
			testing.expect_value(t, auth_state_decode(&restored, encoded[:count]).kind, .None)
			testing.expect_value(t, restored.account.signature_policy, .Current)
			testing.expect_value(t, paired_account_validate(&restored.account, &restored.credentials).kind, .None)
			// Policy is not inferred by trying signatures. A current hosted-declared
			// account relabeled Legacy has the wrong account domain and must fail.
			if device == 1 {
				restored.account.signature_policy = .Legacy
				testing.expect_value(t, auth_state_validate(&restored).kind, .Invalid_Account)
			}
		}
	}
}

@(test)
pairing_auth_reads_historical_v1_and_rewrites_without_resigning_or_domain_guessing :: proc(t: ^testing.T) {
	for hosted in ([]bool{false, true}) {
		for device in 0 ..< 2 {
			f := pairing_domain_fixture(hosted ? 1 : 0, device, 0)
			defer pairing_domain_free(f)
			original := pairing_domain_auth(f, pairing_domain_legacy_account(f, hosted))
			defer auth_state_clear(&original)
			testing.expect_value(t, auth_state_validate(&original).kind, .None)
			current, old: [MAX_AUTH_STATE_SIZE]u8
			count, encoded := auth_state_encode(current[:], &original)
			assert(encoded.kind == .None)
			old_count := pairing_domain_v1(old[:], current[:count])
			restored: Auth_State
			defer auth_state_clear(&restored)
			testing.expect_value(t, auth_state_decode(&restored, old[:old_count]).kind, .None)
			testing.expect_value(t, restored.account.signature_policy, .Legacy)
			testing.expect(
				t,
				bytes.equal(restored.account.account_signature[:], original.account.account_signature[:]),
			)
			testing.expect(t, bytes.equal(restored.account.device_signature[:], original.account.device_signature[:]))
			rewritten: [MAX_AUTH_STATE_SIZE]u8
			rewritten_count, rewrite_error := auth_state_encode(rewritten[:], &restored)
			testing.expect_value(t, rewrite_error.kind, .None)
			testing.expect_value(t, rewritten[9], u8(2))
			testing.expect_value(t, rewritten[293], u8(0))
			testing.expect_value(t, rewritten_count, count)
			again: Auth_State
			defer auth_state_clear(&again)
			testing.expect_value(t, auth_state_decode(&again, rewritten[:rewritten_count]).kind, .None)
			testing.expect_value(t, again.account.signature_policy, .Legacy)
			testing.expect_value(t, auth_state_validate(&again).kind, .None)
			again.account.signature_policy = .Current

			if device == 1 || hosted {
				testing.expect_value(t, auth_state_validate(&again).kind, .Invalid_Account)
			} else {
				// Ordinary historical and current domains coincide, with no fallback needed.
				testing.expect_value(t, auth_state_validate(&again).kind, .None)
			}
		}
	}
}

@(test)
pairing_auth_invalid_policy_version_and_truncation_preserve_destination :: proc(t: ^testing.T) {
	f := pairing_domain_fixture(1, 1, 0)
	defer pairing_domain_free(f)
	state := pairing_domain_auth(f, pairing_domain_legacy_account(f, true))
	defer auth_state_clear(&state)
	encoded: [MAX_AUTH_STATE_SIZE]u8
	count, error := auth_state_encode(encoded[:], &state)
	assert(error.kind == .None)

	for scenario in 0 ..< 4 {
		copy_buffer := encoded
		candidate := copy_buffer[:count]

		switch scenario {
		case 0:
			candidate[293] = 2
		case 1:
			candidate[9] = 3
		case 2:
			candidate = copy_buffer[:293 + 32] // Truncated before v2 policy/account body.
		case 3:
			candidate[292] = 2 // Hosted flag is not a multi-policy bitmask.
		}

		pairing_domain_checksum(candidate)
		destination: Auth_State
		destination.account.jid[0] = 0xa5
		result := auth_state_decode(&destination, candidate)
		testing.expect(t, result.kind != .None)
		testing.expect(t, !destination.account.valid && destination.account.jid[0] == 0xa5)
	}

	state.account.signature_policy = Pairing_Signature_Policy(2)
	testing.expect_value(t, auth_state_validate(&state).kind, .Invalid_Account)
}

@(test)
pairing_auth_unpaired_v1_remains_readable :: proc(t: ^testing.T) {
	f := pairing_domain_fixture(0, 0)
	defer pairing_domain_free(f)
	state := Auth_State {
		credentials = f.credentials,
	}

	defer auth_state_clear(&state)
	data: [MAX_AUTH_STATE_SIZE]u8
	count, error := auth_state_encode(data[:], &state)
	assert(error.kind == .None)
	testing.expect_value(t, count, 320)
	data[9] = 1
	pairing_domain_checksum(data[:count])
	restored: Auth_State
	defer auth_state_clear(&restored)
	testing.expect_value(t, auth_state_decode(&restored, data[:count]).kind, .None)
	testing.expect(t, !restored.account.valid && !restored.credentials.registered)
}

@(test)
pairing_current_persisted_identity_rejects_tampering_and_legacy_companion_domain :: proc(t: ^testing.T) {
	f := pairing_domain_fixture(1, 1)
	defer pairing_domain_free(f)
	account: Paired_Account
	reply: [2048]u8
	_, error := pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
	assert(error.kind == .None)

	for scenario in 0 ..< 5 {
		changed := account

		switch scenario {
		case 0:
			changed.account_signature[0] ~= 1
		case 1:
			changed.account_signature_key[0] ~= 1
		case 2:
			changed.device_signature[0] ~= 1
		case 3:
			changed.details[1] ~= 1
		case 4:
			public := signal_curve_public(f.credentials.identity_private)
			message: [128]u8
			message[0], message[1] = 6, 6
			copy(message[2:], changed.details[:changed.details_size])
			copy(message[2 + changed.details_size:], public[:])
			copy(message[2 + changed.details_size + 32:], changed.account_signature_key[:])
			sign_error: Signal_Error
			changed.device_signature, sign_error = signal_curve_sign(
				f.credentials.identity_private,
				message[:2 + changed.details_size + 64],
			); assert(sign_error == .None)
		}

		testing.expect(t, paired_account_validate(&changed, &f.credentials).kind != .None)
	}
}

@(test)
pairing_auth_disk_save_load_preserves_current_and_historical_policy :: proc(t: ^testing.T) {
	directory, directory_error := os.make_directory_temp("", "owa-pairing-domains-*", context.allocator)
	assert(directory_error == nil)
	defer {
		assert(os.remove_all(directory) == nil)
		delete(directory)
	}

	path := fmt.aprintf("%s/auth", directory)
	defer delete(path)
	f := pairing_domain_fixture(1, 1)
	defer pairing_domain_free(f)
	account: Paired_Account
	reply: [2048]u8
	_, error := pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
	assert(error.kind == .None)
	current := pairing_domain_auth(f, account)
	defer auth_state_clear(&current)
	testing.expect_value(t, auth_state_save(path, &current).kind, .None)
	restored: Auth_State
	defer auth_state_clear(&restored)
	testing.expect_value(t, auth_state_load(path, &restored).kind, .None)
	testing.expect_value(t, restored.account.signature_policy, .Current)
	old_fixture := pairing_domain_fixture(1, 1, 0)
	defer pairing_domain_free(old_fixture)
	legacy := pairing_domain_auth(old_fixture, pairing_domain_legacy_account(old_fixture, true))
	defer auth_state_clear(&legacy)
	encoded, old: [MAX_AUTH_STATE_SIZE]u8
	size, encoded_error := auth_state_encode(encoded[:], &legacy)
	assert(encoded_error.kind == .None)
	old_size := pairing_domain_v1(old[:], encoded[:size])
	file, open_error := os.open(path, {.Write, .Trunc})
	assert(open_error == nil)
	written, write_error := os.write(file, old[:old_size])
	assert(write_error == nil && written == old_size)
	assert(os.close(file) == nil)
	testing.expect_value(t, auth_state_load(path, &restored).kind, .None)
	testing.expect_value(t, restored.account.signature_policy, .Legacy)
	testing.expect_value(t, auth_state_save(path, &restored).kind, .None)
	auth_state_clear(&restored)
	testing.expect_value(t, auth_state_load(path, &restored).kind, .None)
	testing.expect_value(t, restored.account.signature_policy, .Legacy)
	testing.expect_value(t, auth_state_validate(&restored).kind, .None)
}

package whatsapp_test

import "core:bytes"
import "core:crypto"
import "core:crypto/hash"
import "core:encoding/endian"
import "core:fmt"
import "core:os"
import "core:testing"
import wa "shared:whatsapp"

pairing_domain_auth :: proc(f: ^Pairing_Domain_Fixture, account: wa.Paired_Account) -> wa.Auth_State {
	state := wa.Auth_State {
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
pairing_auth_current_roundtrip_retains_policy_and_rejects_legacy_domain :: proc(t: ^testing.T) {
	for wrapper in 0 ..< 2 {
		for device in 0 ..< 2 {
			f := pairing_domain_fixture(u32(wrapper), device)
			defer pairing_domain_free(f)
			account: wa.Paired_Account
			reply: [2048]u8
			_, error := wa.pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
			assert(error.kind == .None)
			state := pairing_domain_auth(f, account)
			defer wa.auth_state_clear(&state)
			encoded: [wa.MAX_AUTH_STATE_SIZE]u8
			count, encode_error := wa.auth_state_encode(encoded[:], &state)
			testing.expect_value(t, encode_error.kind, .None)
			testing.expect_value(t, encoded[9], u8(2))
			testing.expect_value(t, encoded[293], u8(1))
			restored: wa.Auth_State
			defer wa.auth_state_clear(&restored)
			testing.expect_value(t, wa.auth_state_decode(&restored, encoded[:count]).kind, .None)
			testing.expect_value(t, restored.account.signature_policy, .Current)
			testing.expect_value(t, wa.paired_account_validate(&restored.account, &restored.credentials).kind, .None)
			// Policy is not inferred by trying signatures. A current hosted-declared
			// account relabeled Legacy has the wrong account domain and must fail.
			if device == 1 {
				restored.account.signature_policy = .Legacy
				testing.expect_value(t, wa.auth_state_validate(&restored).kind, .Invalid_Account)
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
			defer wa.auth_state_clear(&original)
			testing.expect_value(t, wa.auth_state_validate(&original).kind, .None)
			current, old: [wa.MAX_AUTH_STATE_SIZE]u8
			count, encoded := wa.auth_state_encode(current[:], &original)
			assert(encoded.kind == .None)
			old_count := pairing_domain_v1(old[:], current[:count])
			restored: wa.Auth_State
			defer wa.auth_state_clear(&restored)
			testing.expect_value(t, wa.auth_state_decode(&restored, old[:old_count]).kind, .None)
			testing.expect_value(t, restored.account.signature_policy, .Legacy)
			testing.expect(
				t,
				bytes.equal(restored.account.account_signature[:], original.account.account_signature[:]),
			)
			testing.expect(t, bytes.equal(restored.account.device_signature[:], original.account.device_signature[:]))
			rewritten: [wa.MAX_AUTH_STATE_SIZE]u8
			rewritten_count, rewrite_error := wa.auth_state_encode(rewritten[:], &restored)
			testing.expect_value(t, rewrite_error.kind, .None)
			testing.expect_value(t, rewritten[9], u8(2))
			testing.expect_value(t, rewritten[293], u8(0))
			testing.expect_value(t, rewritten_count, count)
			again: wa.Auth_State
			defer wa.auth_state_clear(&again)
			testing.expect_value(t, wa.auth_state_decode(&again, rewritten[:rewritten_count]).kind, .None)
			testing.expect_value(t, again.account.signature_policy, .Legacy)
			testing.expect_value(t, wa.auth_state_validate(&again).kind, .None)
			again.account.signature_policy = .Current

			if device == 1 || hosted {
				testing.expect_value(t, wa.auth_state_validate(&again).kind, .Invalid_Account)
			} else {
				// Ordinary historical and current domains coincide, with no fallback needed.
				testing.expect_value(t, wa.auth_state_validate(&again).kind, .None)
			}
		}
	}
}

@(test)
pairing_auth_invalid_policy_version_and_truncation_preserve_destination :: proc(t: ^testing.T) {
	f := pairing_domain_fixture(1, 1, 0)
	defer pairing_domain_free(f)
	state := pairing_domain_auth(f, pairing_domain_legacy_account(f, true))
	defer wa.auth_state_clear(&state)
	encoded: [wa.MAX_AUTH_STATE_SIZE]u8
	count, error := wa.auth_state_encode(encoded[:], &state)
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
		destination: wa.Auth_State
		destination.account.jid[0] = 0xa5
		result := wa.auth_state_decode(&destination, candidate)
		testing.expect(t, result.kind != .None)
		testing.expect(t, !destination.account.valid && destination.account.jid[0] == 0xa5)
	}

	state.account.signature_policy = wa.Pairing_Signature_Policy(2)
	testing.expect_value(t, wa.auth_state_validate(&state).kind, .Invalid_Account)
}

@(test)
pairing_auth_unpaired_v1_remains_readable :: proc(t: ^testing.T) {
	f := pairing_domain_fixture(0, 0)
	defer pairing_domain_free(f)
	state := wa.Auth_State {
		credentials = f.credentials,
	}

	defer wa.auth_state_clear(&state)
	data: [wa.MAX_AUTH_STATE_SIZE]u8
	count, error := wa.auth_state_encode(data[:], &state)
	assert(error.kind == .None)
	testing.expect_value(t, count, 320)
	data[9] = 1
	pairing_domain_checksum(data[:count])
	restored: wa.Auth_State
	defer wa.auth_state_clear(&restored)
	testing.expect_value(t, wa.auth_state_decode(&restored, data[:count]).kind, .None)
	testing.expect(t, !restored.account.valid && !restored.credentials.registered)
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
	account: wa.Paired_Account
	reply: [2048]u8
	_, error := wa.pairing_success_handle(&account, pairing_domain_iq(f), &f.credentials, reply[:])
	assert(error.kind == .None)
	current := pairing_domain_auth(f, account)
	defer wa.auth_state_clear(&current)
	testing.expect_value(t, wa.auth_state_save(path, &current).kind, .None)
	restored: wa.Auth_State
	defer wa.auth_state_clear(&restored)
	testing.expect_value(t, wa.auth_state_load(path, &restored).kind, .None)
	testing.expect_value(t, restored.account.signature_policy, .Current)
	old_fixture := pairing_domain_fixture(1, 1, 0)
	defer pairing_domain_free(old_fixture)
	legacy := pairing_domain_auth(old_fixture, pairing_domain_legacy_account(old_fixture, true))
	defer wa.auth_state_clear(&legacy)
	encoded, old: [wa.MAX_AUTH_STATE_SIZE]u8
	size, encoded_error := wa.auth_state_encode(encoded[:], &legacy)
	assert(encoded_error.kind == .None)
	old_size := pairing_domain_v1(old[:], encoded[:size])
	file, open_error := os.open(path, {.Write, .Trunc})
	assert(open_error == nil)
	written, write_error := os.write(file, old[:old_size])
	assert(write_error == nil && written == old_size)
	assert(os.close(file) == nil)
	testing.expect_value(t, wa.auth_state_load(path, &restored).kind, .None)
	testing.expect_value(t, restored.account.signature_policy, .Legacy)
	testing.expect_value(t, wa.auth_state_save(path, &restored).kind, .None)
	wa.auth_state_clear(&restored)
	testing.expect_value(t, wa.auth_state_load(path, &restored).kind, .None)
	testing.expect_value(t, restored.account.signature_policy, .Legacy)
	testing.expect_value(t, wa.auth_state_validate(&restored).kind, .None)
}

Prekey_Lifecycle_Fixture :: struct {
	credentials:     wa.Device_Credentials,
	store:           wa.Prekey_Store,
	directory, path: string,
}

prekey_lifecycle_fixture :: proc() -> ^Prekey_Lifecycle_Fixture {
	f := new(Prekey_Lifecycle_Fixture)
	credentials, generated := wa.device_credentials_generate()
	assert(generated == .None)
	f.credentials = credentials
	assert(wa.prekey_store_init(&f.store, &f.credentials).kind == .None)
	directory, created := os.make_directory_temp("", "owa-prekey-lifecycle-*", context.allocator)
	assert(created == nil)
	f.directory = directory
	f.path = fmt.aprintf("%s/prekeys", directory)

	return f
}

prekey_lifecycle_destroy :: proc(f: ^Prekey_Lifecycle_Fixture) {
	assert(os.remove_all(f.directory) == nil)
	delete(f.directory)
	delete(f.path)
	wa.device_credentials_clear(&f.credentials)
	wa.prekey_store_clear(&f.store)
	free(f)
}

prekey_lifecycle_ack :: proc(store: ^wa.Prekey_Store, id: string) -> wa.Prekey_Error {
	attrs := [3]wa.Binary_Node_Attribute{{"id", id}, {"type", "result"}, {"from", "s.whatsapp.net"}}

	return wa.prekey_upload_handle_response(store, {tag = "iq", attrs = attrs[:]})
}

@(test)
prekey_lifecycle_capacity_and_id_exhaustion_are_explicit_and_unchanged :: proc(t: ^testing.T) {
	f := prekey_lifecycle_fixture()
	defer prekey_lifecycle_destroy(f)

	for _ in 0 ..< wa.MAX_STORED_PREKEYS / wa.MAX_PREKEY_UPLOAD_COUNT {
		assert(wa.prekey_store_generate(&f.store, wa.MAX_PREKEY_UPLOAD_COUNT).kind == .None)
	}

	testing.expect_value(t, f.store.count, wa.MAX_STORED_PREKEYS)
	before := new(wa.Prekey_Store)
	defer {
		wa.prekey_store_clear(before)
		free(before)
	}

	before^ = f.store
	testing.expect_value(t, wa.prekey_store_generate(&f.store, 1).kind, .Store_Full)
	testing.expect(t, f.store == before^, "capacity refusal must not discard or overwrite private keys")
	wa.prekey_store_clear(&f.store)
	assert(wa.prekey_store_init(&f.store, &f.credentials).kind == .None)
	f.store.next_id = wa.MAX_DEVICE_PREKEY_ID + 1
	before^ = f.store
	testing.expect_value(t, wa.prekey_store_generate(&f.store, 1).kind, .ID_Exhausted)
	testing.expect(t, f.store == before^, "ID exhaustion must not wrap or reuse an ID")
}

@(test)
prekey_lifecycle_lost_response_reloads_and_reuses_pending_keys_until_matching_iq :: proc(t: ^testing.T) {
	f := prekey_lifecycle_fixture()
	defer prekey_lifecycle_destroy(f)
	assert(wa.prekey_upload_prepare(&f.store, "upload-first", 3).kind == .None)
	wire: [4096]u8
	_, unsaved := wa.prekey_upload_encode(wire[:], &f.store, &f.credentials)
	testing.expect_value(t, unsaved.kind, .Persistence_Required)
	assert(wa.prekey_store_save(f.path, &f.store).kind == .None)
	_, encoded := wa.prekey_upload_encode(wire[:], &f.store, &f.credentials)
	assert(encoded.kind == .None)
	original := [3]wa.One_Time_Prekey{f.store.keys[0], f.store.keys[1], f.store.keys[2]}
	defer crypto.zero_explicit(&original, size_of(original))
	next_id := f.store.next_id
	// No reply: reconnect must recover the identical pending private material.
	restored := new(wa.Prekey_Store)
	defer {
		wa.prekey_store_clear(restored)
		free(restored)
	}

	assert(wa.prekey_store_load(f.path, restored, &f.credentials).kind == .None)
	wa.prekey_store_clear(&f.store)
	f.store = restored^
	assert(wa.prekey_upload_retry(&f.store, "upload-retry").kind == .None)
	testing.expect_value(t, f.store.next_id, next_id)
	testing.expect_value(t, f.store.pending_count, 3)

	for key, i in original {
		testing.expect(t, f.store.keys[i] == key, "retry must reuse exact pending IDs, public and private keys")
	}

	_, unpersisted_retry := wa.prekey_upload_encode(wire[:], &f.store, &f.credentials)
	testing.expect_value(t, unpersisted_retry.kind, .Persistence_Required)
	assert(wa.prekey_store_save(f.path, &f.store).kind == .None)
	_, retried := wa.prekey_upload_encode(wire[:], &f.store, &f.credentials)
	assert(retried.kind == .None)
	revision := f.store.revision
	stale := prekey_lifecycle_ack(&f.store, "upload-first")
	testing.expect_value(t, stale.kind, .Response_Mismatch)
	testing.expect_value(t, f.store.pending_count, 3)
	testing.expect_value(t, f.store.revision, revision)
	assert(prekey_lifecycle_ack(&f.store, "upload-retry").kind == .None)
	testing.expect_value(t, f.store.pending_count, 0)

	for key, i in original {
		testing.expect_value(t, f.store.keys[i].status, .Published)
		testing.expect_value(t, f.store.keys[i].id, key.id)
		testing.expect(t, f.store.keys[i].private == key.private && f.store.keys[i].public == key.public)
	}

	assert(wa.prekey_store_save(f.path, &f.store).kind == .None)
}

@(test)
prekey_lifecycle_consumed_highest_id_may_be_absent_without_reuse :: proc(t: ^testing.T) {
	f := prekey_lifecycle_fixture()
	defer prekey_lifecycle_destroy(f)
	assert(wa.prekey_upload_prepare(&f.store, "initial-batch", 3).kind == .None)
	assert(wa.prekey_store_save(f.path, &f.store).kind == .None)
	// Reclamation must not break a still-pending contiguous upload batch.
	testing.expect_value(t, wa.prekey_store_remove_consumed(&f.store, 3).kind, .Pending_Upload_Exists)
	assert(prekey_lifecycle_ack(&f.store, "initial-batch").kind == .None)
	// Model the caller's independently durable consumption transaction. This API
	// is deliberately lower-level than the socket's authority check.
	assert(wa.prekey_store_remove_consumed(&f.store, 3).kind == .None)
	testing.expect(t, wa.prekey_store_get(&f.store, f.store.next_id - 1) == nil)
	testing.expect_value(t, f.store.next_id, u32(4))
	testing.expect_value(t, wa.prekey_store_validate(&f.store).kind, .None)
	assert(wa.prekey_store_save(f.path, &f.store).kind == .None)
	restored := new(wa.Prekey_Store)
	defer {
		wa.prekey_store_clear(restored)
		free(restored)
	}

	assert(wa.prekey_store_load(f.path, restored, &f.credentials).kind == .None)
	testing.expect(t, wa.prekey_store_get(restored, 3) == nil)
	assert(wa.prekey_store_generate(restored, 1).kind == .None)
	testing.expect(t, wa.prekey_store_get(restored, 3) == nil)
	testing.expect(t, wa.prekey_store_get(restored, 4) != nil)
	testing.expect_value(t, restored.next_id, u32(5))
}

package main

import wa "../.."
import "core:bytes"
import "core:fmt"
import "core:os"

// Same-format cross-commit compatibility only. Both roles are generated test
// identities. This path calls no Socket/HTTP/network API and injects no faults.
compat_credentials :: proc() -> wa.Device_Credentials {
	local := fixture_local(96, 200); bundle := fixture_bundle(local)
	credentials := wa.Device_Credentials {
		noise_private              = fixture_private(10),
		pairing_ephemeral_private  = fixture_private(20),
		identity_private           = local.identity_private,
		signed_prekey_private      = local.signed_prekey_private,
		signed_prekey_public       = bundle.signed_prekey_public,
		signed_prekey_signature    = bundle.signed_prekey_signature,
		signed_prekey_id           = local.signed_prekey_id,
		registration_id            = local.registration_id,
		next_prekey_id             = 10,
		first_unuploaded_prekey_id = 10,
	}
	credentials.adv_secret[0] = 1
	assert(wa.device_credentials_validate(&credentials) == .None)
	return credentials
}

compat_produce :: proc(directory: string) {
	f := fixture_open(directory, true); defer fixture_close(f)
	fixture_established(f)
	fixture_encrypt(f)
	prekey_path := fmt.aprintf("%s/prekeys.bin", directory); defer delete(prekey_path)
	assert(wa.prekey_store_save(prekey_path, &f.prekeys).kind == .None)
	prekeys_set(f)
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
	fmt.println("COMPAT_PRODUCED same_format=true stable_intent=true normal_exit=true")
}

compat_verify :: proc(directory: string) {
	f := fixture_open(directory, false); defer fixture_close(f)
	fixture_load_pair(f)
	before, io_error := os.read_entire_file(f.path, context.allocator); assert(io_error == nil)
	defer delete(before)
	size, measured := wa.state_store_encode(nil, &f.store)
	assert(measured.kind == .Destination_Undersized)
	encoded := make([]u8, size); defer delete(encoded)
	_, encode_error := wa.state_store_encode(encoded, &f.store)
	assert(encode_error.kind == .None && bytes.equal(before, encoded))
	for entry in ([]struct {
			name:    string,
			session: ^wa.Signal_Session,
		}{{"device-a", &f.pair.a}, {"device-b", &f.pair.b}}) {
		saved, found := wa.state_store_get(&f.store, .Session, entry.name); assert(found)
		canonical := session_bytes(entry.session); defer delete(canonical)
		assert(bytes.equal(saved, canonical))
	}
	assert(f.pair.a.local_registration_id == 100 && f.pair.a.remote_registration_id == 200)
	assert(f.pair.b.local_registration_id == 200 && f.pair.b.remote_registration_id == 100)
	assert(f.pair.a.send_counter == 0)
	content, content_found := wa.state_store_get(&f.store, .Outbound_Content, INTENT_ID)
	pending, pending_found := wa.state_store_get(&f.store, .Outbound_Message, INTENT_ID)
	assert(content_found && string(content) == BODY && pending_found && len(pending) > 0)
	prekey_path := fmt.aprintf("%s/prekeys.bin", directory); defer delete(prekey_path)
	prekey_bytes, prekey_io := os.read_entire_file(prekey_path, context.allocator)
	assert(prekey_io == nil)
	defer delete(prekey_bytes)
	snapshot, snapshot_found := wa.state_store_get(&f.store, .Captured_Message, "prekeys-b")
	assert(snapshot_found && bytes.equal(snapshot, prekey_bytes))
	credentials := compat_credentials(); defer wa.device_credentials_clear(&credentials)
	loaded := new(wa.Prekey_Store); defer {wa.prekey_store_clear(loaded); free(loaded)}
	assert(wa.prekey_store_load(prekey_path, loaded, &credentials).kind == .None)
	assert(
		loaded.count == 0 &&
		loaded.next_id == 10 &&
		loaded.revision == 2 &&
		loaded.durable_revision == loaded.revision &&
		wa.prekey_store_get(loaded, 9) == nil,
	)
	assert(loaded.identity_public == wa.signal_curve_public(fixture_private(96)))
	// Authenticate/decrypt the actual prior runtime's pending ciphertext in memory.
	// Do not publish a new ratchet or rewrite the old state/prekey files.
	plaintext: [1024]u8
	count, decrypted := wa.signal_session_decrypt(
		&f.pair.b,
		plaintext[:],
		pending,
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(decrypted.kind == .None && string(plaintext[:count]) == BODY)
	after, after_error := os.read_entire_file(f.path, context.allocator)
	assert(after_error == nil)
	defer delete(after)
	prekey_after, prekey_after_error := os.read_entire_file(prekey_path, context.allocator)
	assert(prekey_after_error == nil); defer delete(prekey_after)
	assert(bytes.equal(before, after) && bytes.equal(prekey_bytes, prekey_after))
	fmt.println(
		"COMPAT_VERIFIED same_format=true stable_intent=true exact_store_and_session_bytes=true prekey_metadata=true pending_authenticated=true readonly=true",
	)
}

package main

import wa "../.."
import "core:bytes"
import "core:fmt"
import "core:os"
import "core:testing"

unit_fixture :: proc() -> (^Fixture, string) {
	directory, error := os.make_directory_temp("/tmp", "wa-encrypted-*", context.allocator)
	assert(error == nil)
	owner := fmt.aprintf("%s/owner", directory); defer delete(owner)
	assert(os.write_entire_file(owner, OWNER, {.Read_User, .Write_User}) == nil)
	return fixture_open(directory, true), directory
}

unit_cleanup :: proc(f: ^Fixture, directory: string) {
	fixture_close(f); assert(os.remove_all(directory) == nil); delete(directory)
}

unit_reload :: proc(f: ^Fixture) {
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
	wa.signal_session_clear(&f.pair.a); wa.signal_session_clear(&f.pair.b)
	wa.prekey_store_clear(&f.prekeys); wa.state_store_clear(&f.store)
	assert(wa.state_store_load(&f.store, f.path, fixture_identity()).kind == .None)
	fixture_load_pair(f)
}

unit_whisper :: proc(sender: ^wa.Signal_Session, identity: [32]u8, body: []u8) -> []u8 {
	wire := make([]u8, 1024)
	kind, size, error := wa.signal_session_encrypt(sender, wire, body, identity)
	assert(error.kind == .None && kind == .Whisper)
	resize := make([]u8, size); copy(resize, wire[:size]); delete(wire)
	return resize
}

@(test)
recovery_delayed_packet_survives_dh_ratchet_and_disk_restart :: proc(t: ^testing.T) {
	f, directory := unit_fixture(); defer unit_cleanup(f, directory)
	fixture_established(f)
	a_identity := wa.signal_curve_public(fixture_private(0))
	b_identity := wa.signal_curve_public(fixture_private(96))
	first := unit_whisper(&f.pair.a, b_identity, []u8{11}); defer delete(first)
	delayed := unit_whisper(&f.pair.a, b_identity, []u8{22}); defer delete(delayed)
	plaintext: [1024]u8
	_, error := wa.signal_session_decrypt(&f.pair.b, plaintext[:], first, a_identity)
	assert(error.kind == .None)
	reply := unit_whisper(&f.pair.b, a_identity, []u8{33}); defer delete(reply)
	_, error = wa.signal_session_decrypt(&f.pair.a, plaintext[:], reply, b_identity)
	assert(error.kind == .None)
	rotated := unit_whisper(&f.pair.a, b_identity, []u8{44}); defer delete(rotated)
	_, error = wa.signal_session_decrypt(&f.pair.b, plaintext[:], rotated, a_identity)
	assert(error.kind == .None && f.pair.b.skipped_count == 1)
	session_set(&f.store, "device-a", &f.pair.a); session_set(&f.store, "device-b", &f.pair.b)
	assert(
		wa.state_store_set(&f.store, .Inbox_Message, "delayed-stable-id", delayed).kind == .None,
	)
	unit_reload(f)
	saved, found := wa.state_store_get(&f.store, .Inbox_Message, "delayed-stable-id")
	assert(found)
	count: int
	count, error = wa.signal_session_decrypt(&f.pair.b, plaintext[:], saved, a_identity)
	assert(error.kind == .None && count == 1 && plaintext[0] == 22 && f.pair.b.skipped_count == 0)
	session_set(&f.store, "device-b", &f.pair.b)
	assert(
		wa.state_store_set(&f.store, .Processed_Message, "delayed-stable-id", []u8{1}).kind ==
		.None,
	)
	unit_reload(f)
	saved, found = wa.state_store_get(&f.store, .Inbox_Message, "delayed-stable-id"); assert(found)
	before := session_bytes(&f.pair.b); defer delete(before)
	_, error = wa.signal_session_decrypt(&f.pair.b, plaintext[:], saved, a_identity)
	after := session_bytes(&f.pair.b); defer delete(after)
	testing.expect(t, error.kind == .Replay && bytes.equal(before, after))
}

@(test)
recovery_untrusted_new_device_requires_explicit_identity :: proc(t: ^testing.T) {
	f, directory := unit_fixture(); defer unit_cleanup(f, directory)
	fixture_established(f)
	original := session_bytes(&f.pair.a); defer delete(original)
	local := fixture_local(192, 300, false); bundle := fixture_bundle(local)
	wire, plaintext: [1024]u8
	_, _, error := wa.signal_session_encrypt(&f.pair.a, wire[:], []u8{1}, bundle.identity_public)
	assert(error.kind == .Untrusted_Identity)
	unchanged := session_bytes(&f.pair.a); defer delete(unchanged)
	assert(bytes.equal(original, unchanged))
	next := new(Pair)
	defer {wa.signal_session_clear(&next.a); wa.signal_session_clear(&next.b); free(next)}
	error = wa.signal_session_init_initiator(
		&next.a,
		fixture_private(0),
		100,
		bundle,
		wa.signal_curve_public(fixture_private(96)),
	)
	assert(error.kind == .Untrusted_Identity && !next.a.initialized)
	assert(
		wa.signal_session_init_initiator(&next.a, fixture_private(0), 100, bundle, bundle.identity_public).kind ==
		.None,
	)
	size: int
	message_kind, wire_size, encrypt_error := wa.signal_session_encrypt(
		&next.a,
		wire[:],
		[]u8{77},
		bundle.identity_public,
	)
	assert(encrypt_error.kind == .None && message_kind == .Prekey)
	consumed: u32
	size, consumed, error = wa.signal_session_decrypt_prekey(
		&next.b,
		plaintext[:],
		wire[:wire_size],
		local,
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(error.kind == .None && consumed == 0 && size == 1 && plaintext[0] == 77)
	session_set(&f.store, "device-a/new-peer", &next.a)
	session_set(&f.store, "device-new", &next.b)
	assert(
		wa.state_store_set(&f.store, .Identity, "device-new", bundle.identity_public[:]).kind ==
		.None,
	)
	unit_reload(f)
	session_get(&f.store, "device-a/new-peer", &next.a)
	session_get(&f.store, "device-new", &next.b)
	identity, found := wa.state_store_get(&f.store, .Identity, "device-new")
	assert(found && bytes.equal(identity, bundle.identity_public[:]))
	old := session_bytes(&f.pair.a); defer delete(old)
	assert(bytes.equal(old, original))
	reply := unit_whisper(&next.b, wa.signal_curve_public(fixture_private(0)), []u8{88})
	defer delete(reply)
	size, error = wa.signal_session_decrypt(&next.a, plaintext[:], reply, bundle.identity_public)
	testing.expect(t, error.kind == .None && size == 1 && plaintext[0] == 88)
	fixture_encrypt(f); fixture_decrypt(f)
}

@(test)
recovery_rotated_signed_prekey_keeps_existing_session_generation :: proc(t: ^testing.T) {
	f, directory := unit_fixture(); defer unit_cleanup(f, directory)
	fixture_established(f)
	original := session_bytes(&f.pair.b); defer delete(original)
	local := fixture_local(96, 200)
	local.signed_prekey_private = fixture_private(192); local.signed_prekey_id = 8
	local.prekey_private = fixture_private(224); local.prekey_id = 10
	f.prekeys.count = 1; f.prekeys.next_id = 11; f.prekeys.revision += 1
	f.prekeys.keys[0] = {
		id      = 10,
		private = local.prekey_private,
		public  = wa.signal_curve_public(local.prekey_private),
		status  = .Published,
	}
	prekeys_set(f)
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
	bundle := fixture_bundle(local)
	next := new(Pair)
	defer {wa.signal_session_clear(&next.a); wa.signal_session_clear(&next.b); free(next)}
	assert(
		wa.signal_session_init_initiator(&next.a, fixture_private(0), 100, bundle, wa.signal_curve_public(fixture_private(96))).kind ==
		.None,
	)
	wire, plaintext: [1024]u8
	kind, size, error := wa.signal_session_encrypt(
		&next.a,
		wire[:],
		[]u8{55},
		bundle.identity_public,
	)
	assert(error.kind == .None && kind == .Prekey)
	count, consumed, decrypt_error := wa.signal_session_decrypt_prekey(
		&next.b,
		plaintext[:],
		wire[:size],
		local,
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(decrypt_error.kind == .None && consumed == 10 && count == 1 && plaintext[0] == 55)
	assert(wa.prekey_store_remove_consumed(&f.prekeys, consumed).kind == .None)
	prekeys_set(f)
	session_set(&f.store, "device-a/generation-2", &next.a)
	session_set(&f.store, "device-b/generation-2", &next.b)
	assert(wa.state_store_set(&f.store, .Consumed_Prekey, "device-b/10", []u8{10}).kind == .None)
	unit_reload(f)
	session_get(&f.store, "device-a/generation-2", &next.a)
	session_get(&f.store, "device-b/generation-2", &next.b)
	old := session_bytes(&f.pair.b); defer delete(old)
	assert(bytes.equal(old, original) && wa.prekey_store_get(&f.prekeys, 10) == nil)
	reply := unit_whisper(&next.b, wa.signal_curve_public(fixture_private(0)), []u8{66})
	defer delete(reply)
	count, error = wa.signal_session_decrypt(&next.a, plaintext[:], reply, bundle.identity_public)
	testing.expect(t, error.kind == .None && count == 1 && plaintext[0] == 66)
	fixture_encrypt(f); fixture_decrypt(f)
}

@(test)
recovery_bad_prekey_mac_does_not_consume_key_or_initialize_session :: proc(t: ^testing.T) {
	f, directory := unit_fixture(); defer unit_cleanup(f, directory)
	fixture_first(f)
	wire, found := wa.state_store_get(&f.store, .Outbound_Message, INITIAL_ID); assert(found)
	corrupt := make([]u8, len(wire)); copy(corrupt, wire); defer delete(corrupt)
	prekey, decoded := wa.signal_prekey_message_decode(corrupt); assert(decoded.kind == .None)
	whisper, message_error := wa.signal_whisper_decode(prekey.message)
	assert(message_error.kind == .None)
	whisper.mac[0] ~= 1
	plaintext: [1024]u8
	_, consumed, error := wa.signal_session_decrypt_prekey(
		&f.pair.b,
		plaintext[:],
		corrupt,
		fixture_local(96, 200),
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(error.kind == .Authentication_Failed && consumed == 0 && !f.pair.b.initialized)
	assert(wa.prekey_store_get(&f.prekeys, 9) != nil)
	// A valid retry still consumes exactly the original one-time prekey.
	fixture_receive_first(f)
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
	wa.state_store_clear(&f.store); wa.prekey_store_clear(&f.prekeys)
	assert(wa.state_store_load(&f.store, f.path, fixture_identity()).kind == .None)
	prekeys_get(f)
	marker, marker_found := wa.state_store_get(&f.store, .Consumed_Prekey, "device-b/9")
	testing.expect(
		t,
		marker_found && bytes.equal(marker, []u8{9}) && wa.prekey_store_get(&f.prekeys, 9) == nil,
	)
}

@(test)
recovery_corrupt_inner_session_preserves_live_ratchet :: proc(t: ^testing.T) {
	f, directory := unit_fixture(); defer unit_cleanup(f, directory)
	fixture_established(f)
	before := session_bytes(&f.pair.b); defer delete(before)
	corrupt := make([]u8, len(before)); copy(corrupt, before); defer delete(corrupt)
	corrupt[len(corrupt) - 1] ~= 1
	error := wa.signal_session_decode(&f.pair.b, corrupt)
	assert(error.kind != .None)
	after := session_bytes(&f.pair.b); defer delete(after)
	testing.expect(t, bytes.equal(before, after))
	fixture_encrypt(f); fixture_decrypt(f)
}

@(test)
recovery_socket_encrypted_send_and_inbound_positive_ack_control :: proc(_: ^testing.T) {
	f, directory := unit_fixture()
	fixture_close(f)
	defer {assert(os.remove_all(directory) == nil); delete(directory)}
	socket_stage_run(directory, "control")
	socket_verify_run(directory, "control")
}

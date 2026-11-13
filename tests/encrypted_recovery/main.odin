package main

import wa "../.."
import "core:bytes"
import "core:fmt"
import "core:os"
import "core:time"


boundary :: proc(stage: string) {
	fmt.printf("ENCRYPTED_BOUNDARY_READY %s\n", stage)
	for {time.sleep(time.Second)}
}

stage_run :: proc(directory, stage: string) {
	f := fixture_open(directory, true); defer fixture_close(f)
	switch stage {
	case "receiver-before-commit", "receiver-after-commit":
		fixture_first(f); fixture_receive_first(f)
		if stage == "receiver-after-commit" {
			assert(wa.state_store_save(&f.store, f.path).kind == .None)
		}
	case "sender-before-commit", "sender-after-commit", "receiver-after-message-commit":
		fixture_established(f); fixture_encrypt(f)
		if stage != "sender-before-commit" {
			assert(wa.state_store_save(&f.store, f.path).kind == .None)
		}
		if stage == "receiver-after-message-commit" {
			fixture_decrypt(f)
			assert(wa.state_store_save(&f.store, f.path).kind == .None)
		}
	case:
		assert(false)
	}
	boundary(stage)
}

verify_prekey :: proc(f: ^Fixture, committed: bool) {
	_, session_found := wa.state_store_get(&f.store, .Session, "device-b")
	_, marker_found := wa.state_store_get(&f.store, .Consumed_Prekey, "device-b/9")
	_, inbox_found := wa.state_store_get(&f.store, .Inbox_Message, INITIAL_ID)
	prekeys_get(f)
	prekey_found := wa.prekey_store_get(&f.prekeys, 9) != nil
	assert(session_found == committed && marker_found == committed && inbox_found == committed)
	assert(prekey_found != committed)
	if !committed {
		fixture_receive_first(f); return
	}
	session_get(&f.store, "device-b", &f.pair.b)
	before := session_bytes(&f.pair.b); defer delete(before)
	wire, found := wa.state_store_get(&f.store, .Outbound_Message, INITIAL_ID); assert(found)
	local := fixture_local(96, 200, false); local.prekey_private = {}
	plaintext: [1024]u8
	_, consumed, error := wa.signal_session_decrypt_prekey(
		&f.pair.b,
		plaintext[:],
		wire,
		local,
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(error.kind == .Replay && consumed == 0)
	after := session_bytes(&f.pair.b); defer delete(after)
	assert(bytes.equal(before, after))
}

verify_sender :: proc(f: ^Fixture, committed, received: bool) {
	fixture_load_pair(f)
	content, content_found := wa.state_store_get(&f.store, .Outbound_Content, INTENT_ID)
	assert(content_found && string(content) == BODY)
	wire, wire_found := wa.state_store_get(&f.store, .Outbound_Message, INTENT_ID)
	assert(wire_found == committed && f.pair.a.send_counter == (0 if committed else -1))
	if !committed {
		// Recover the same durable intent, not a newly allocated application ID.
		fixture_encrypt(f); fixture_decrypt(f); return
	}
	if !received {
		fixture_decrypt(f); return
	}
	_, processed := wa.state_store_get(&f.store, .Processed_Message, INTENT_ID); assert(processed)
	before := session_bytes(&f.pair.b); defer delete(before)
	plaintext: [1024]u8
	_, error := wa.signal_session_decrypt(
		&f.pair.b,
		plaintext[:],
		wire,
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(error.kind == .Replay)
	after := session_bytes(&f.pair.b); defer delete(after)
	assert(bytes.equal(before, after))
}

verify_run :: proc(directory, stage: string) {
	f := fixture_open(directory, false); defer fixture_close(f)
	before, io_error := os.read_entire_file(f.path, context.allocator); assert(io_error == nil)
	defer delete(before)
	switch stage {
	case "receiver-before-commit":
		verify_prekey(f, false)
	case "receiver-after-commit":
		verify_prekey(f, true)
	case "sender-before-commit", "file-limit":
		verify_sender(f, false, false)
	case "sender-after-commit":
		verify_sender(f, true, false)
	case "receiver-after-message-commit":
		verify_sender(f, true, true)
	case:
		assert(false)
	}
	after, after_error := os.read_entire_file(f.path, context.allocator)
	assert(after_error == nil); defer delete(after)
	assert(bytes.equal(before, after))
	fmt.println("ENCRYPTED_REOPEN_PASS stable_intent_id=true recipient_delivery=false")
}

limited_write :: proc(directory: string) {
	f := fixture_open(directory, false); defer fixture_close(f)
	fixture_load_pair(f)
	before, io_error := os.read_entire_file(f.path, context.allocator); assert(io_error == nil)
	defer delete(before)
	durable := f.store.durable_revision
	fixture_encrypt(f)
	error := wa.state_store_save(&f.store, f.path)
	observed_efbig := write_error_is_efbig(error.io)
	assert(error.kind == .Write_Failed && observed_efbig)
	assert(f.store.durable_revision == durable && f.store.revision > durable)
	after, after_error := os.read_entire_file(f.path, context.allocator)
	assert(after_error == nil); defer delete(after)
	assert(bytes.equal(before, after))
	fmt.printf(
		"ENCRYPTED_WRITE_LIMIT_PASS error=Write_Failed errno=EFBIG original_unchanged=true core_io=%v\n",
		error.io,
	)
}

corrupt_load :: proc(directory, kind: string) {
	f := fixture_open(directory, false); defer fixture_close(f)
	fixture_load_pair(f)
	size, measured := wa.state_store_encode(nil, &f.store)
	assert(measured.kind == .Destination_Undersized)
	before := make([]u8, size); defer delete(before)
	_, encoded := wa.state_store_encode(before, &f.store); assert(encoded.kind == .None)
	path := fmt.aprintf("%s/%s.bin", directory, kind); defer delete(path)
	error := wa.state_store_load(&f.store, path, fixture_identity())
	assert(error.kind == .Checksum_Mismatch || error.kind == .Invalid_Format)
	after := make([]u8, size); defer delete(after)
	_, encoded = wa.state_store_encode(after, &f.store)
	assert(encoded.kind == .None && bytes.equal(before, after))
	session_get(&f.store, "device-a", &f.pair.a); session_get(&f.store, "device-b", &f.pair.b)
	fixture_encrypt(f); fixture_decrypt(f)
	fmt.println("ENCRYPTED_CORRUPTION_PASS live_sessions_preserved=true")
}

main :: proc() {
	assert(len(os.args) == 4)
	command, directory, argument := os.args[1], os.args[2], os.args[3]
	switch command {
	case "stage":
		stage_run(directory, argument)
	case "verify":
		verify_run(directory, argument)
	case "prepare":
		f := fixture_open(directory, true); defer fixture_close(f)
		fixture_established(f); fmt.println("ENCRYPTED_BASELINE_READY")
	case "limited-write":
		limited_write(directory)
	case "corrupt-load":
		assert(argument == "corrupt" || argument == "truncated")
		corrupt_load(directory, argument)
	case:
		assert(false)
	}
}

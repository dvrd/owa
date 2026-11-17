package whatsapp

import "core:crypto"
import "core:fmt"
import "core:os"
import "core:testing"

Prekey_Lifecycle_Fixture :: struct {
	credentials:     Device_Credentials,
	store:           Prekey_Store,
	directory, path: string,
}
prekey_lifecycle_fixture :: proc() -> ^Prekey_Lifecycle_Fixture {
	f := new(Prekey_Lifecycle_Fixture)
	credentials, generated := device_credentials_generate()
	assert(generated == .None)
	f.credentials = credentials
	assert(prekey_store_init(&f.store, &f.credentials).kind == .None)
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
	device_credentials_clear(&f.credentials)
	prekey_store_clear(&f.store)
	free(f)
}
prekey_lifecycle_ack :: proc(store: ^Prekey_Store, id: string) -> Prekey_Error {
	attrs := [3]Binary_Node_Attribute{{"id", id}, {"type", "result"}, {"from", "s.whatsapp.net"}}

	return prekey_upload_handle_response(store, {tag = "iq", attrs = attrs[:]})
}

@(test)
prekey_lifecycle_capacity_and_id_exhaustion_are_explicit_and_unchanged :: proc(t: ^testing.T) {
	f := prekey_lifecycle_fixture()
	defer prekey_lifecycle_destroy(f)

	for _ in 0 ..< MAX_STORED_PREKEYS / MAX_PREKEY_UPLOAD_COUNT {
		assert(prekey_store_generate(&f.store, MAX_PREKEY_UPLOAD_COUNT).kind == .None)
	}

	testing.expect_value(t, f.store.count, MAX_STORED_PREKEYS)
	before := new(Prekey_Store)
	defer {
		prekey_store_clear(before)
		free(before)
	}

	before^ = f.store
	testing.expect_value(t, prekey_store_generate(&f.store, 1).kind, .Store_Full)
	testing.expect(t, f.store == before^, "capacity refusal must not discard or overwrite private keys")
	prekey_store_clear(&f.store)
	assert(prekey_store_init(&f.store, &f.credentials).kind == .None)
	f.store.next_id = MAX_DEVICE_PREKEY_ID + 1
	before^ = f.store
	testing.expect_value(t, prekey_store_generate(&f.store, 1).kind, .ID_Exhausted)
	testing.expect(t, f.store == before^, "ID exhaustion must not wrap or reuse an ID")
}

@(test)
prekey_lifecycle_lost_response_reloads_and_reuses_pending_keys_until_matching_iq :: proc(t: ^testing.T) {
	f := prekey_lifecycle_fixture()
	defer prekey_lifecycle_destroy(f)
	assert(prekey_upload_prepare(&f.store, "upload-first", 3).kind == .None)
	wire: [4096]u8
	_, unsaved := prekey_upload_encode(wire[:], &f.store, &f.credentials)
	testing.expect_value(t, unsaved.kind, .Persistence_Required)
	assert(prekey_store_save(f.path, &f.store).kind == .None)
	_, encoded := prekey_upload_encode(wire[:], &f.store, &f.credentials)
	assert(encoded.kind == .None)
	original := [3]One_Time_Prekey{f.store.keys[0], f.store.keys[1], f.store.keys[2]}
	defer crypto.zero_explicit(&original, size_of(original))
	next_id := f.store.next_id
	// No reply: reconnect must recover the identical pending private material.
	restored := new(Prekey_Store)
	defer {
		prekey_store_clear(restored)
		free(restored)
	}

	assert(prekey_store_load(f.path, restored, &f.credentials).kind == .None)
	prekey_store_clear(&f.store)
	f.store = restored^
	assert(prekey_upload_retry(&f.store, "upload-retry").kind == .None)
	testing.expect_value(t, f.store.next_id, next_id)
	testing.expect_value(t, f.store.pending_count, 3)

	for key, i in original {
		testing.expect(t, f.store.keys[i] == key, "retry must reuse exact pending IDs, public and private keys")
	}

	_, unpersisted_retry := prekey_upload_encode(wire[:], &f.store, &f.credentials)
	testing.expect_value(t, unpersisted_retry.kind, .Persistence_Required)
	assert(prekey_store_save(f.path, &f.store).kind == .None)
	_, retried := prekey_upload_encode(wire[:], &f.store, &f.credentials)
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

	assert(prekey_store_save(f.path, &f.store).kind == .None)
}

@(test)
prekey_lifecycle_consumed_highest_id_may_be_absent_without_reuse :: proc(t: ^testing.T) {
	f := prekey_lifecycle_fixture()
	defer prekey_lifecycle_destroy(f)
	assert(prekey_upload_prepare(&f.store, "initial-batch", 3).kind == .None)
	assert(prekey_store_save(f.path, &f.store).kind == .None)
	// Reclamation must not break a still-pending contiguous upload batch.
	testing.expect_value(t, prekey_store_remove_consumed(&f.store, 3).kind, .Pending_Upload_Exists)
	assert(prekey_lifecycle_ack(&f.store, "initial-batch").kind == .None)
	// Model the caller's independently durable consumption transaction. This API
	// is deliberately lower-level than the socket's authority check.
	assert(prekey_store_remove_consumed(&f.store, 3).kind == .None)
	testing.expect(t, prekey_store_get(&f.store, f.store.next_id - 1) == nil)
	testing.expect_value(t, f.store.next_id, u32(4))
	testing.expect_value(t, prekey_store_validate(&f.store).kind, .None)
	assert(prekey_store_save(f.path, &f.store).kind == .None)
	restored := new(Prekey_Store)
	defer {
		prekey_store_clear(restored)
		free(restored)
	}

	assert(prekey_store_load(f.path, restored, &f.credentials).kind == .None)
	testing.expect(t, prekey_store_get(restored, 3) == nil)
	assert(prekey_store_generate(restored, 1).kind == .None)
	testing.expect(t, prekey_store_get(restored, 3) == nil)
	testing.expect(t, prekey_store_get(restored, 4) != nil)
	testing.expect_value(t, restored.next_id, u32(5))
}

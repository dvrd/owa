package main

import wa "../.."
import "core:bytes"
import "core:crypto"
import "core:fmt"
import "core:os"
import "core:strings"

// Deterministic synthetic key helpers adapted from Mesa tests/whatsapp/signal.odin
// signal_session_test_private/local/bundle (lines906–965). No account material.
fixture_private :: proc(start: int) -> [32]u8 {
	value: [32]u8
	for &b, i in value {b = u8(start + i)}
	value[0] &= 248; value[31] = value[31] & 127 | 64
	return value
}

fixture_local :: proc(start: int, registration: u32, prekey := true) -> wa.Signal_Recipient_Keys {
	return {
		identity_private = fixture_private(start),
		registration_id = registration,
		signed_prekey_private = fixture_private(start + 32),
		signed_prekey_id = 7,
		has_prekey = prekey,
		prekey_private = fixture_private(start + 64),
		prekey_id = 9,
	}
}

fixture_bundle :: proc(local: wa.Signal_Recipient_Keys) -> wa.Signal_Prekey_Bundle {
	bundle := wa.Signal_Prekey_Bundle {
		registration_id      = local.registration_id,
		identity_public      = wa.signal_curve_public(local.identity_private),
		signed_prekey_id     = local.signed_prekey_id,
		signed_prekey_public = wa.signal_curve_public(local.signed_prekey_private),
		has_prekey           = local.has_prekey,
		prekey_id            = local.prekey_id,
		prekey_public        = wa.signal_curve_public(local.prekey_private),
	}
	signed: [33]u8; signed[0] = 5; copy(signed[1:], bundle.signed_prekey_public[:])
	error: wa.Signal_Error
	bundle.signed_prekey_signature, error = wa.signal_curve_sign(local.identity_private, signed[:])
	assert(error == .None)
	return bundle
}

INITIAL_ID :: "encrypted-recovery-prekey-1"
INTENT_ID :: "encrypted-recovery-intent-1"
FIRST_BODY :: string("synthetic authenticated prekey")
BODY :: string("synthetic durable encrypted intent")
OWNER :: "OWA-ENCRYPTED-RECOVERY-V1"

Pair :: struct {
	a, b: wa.Signal_Session,
}
Fixture :: struct {
	pair:    Pair,
	prekeys: wa.Prekey_Store,
	store:   wa.State_Store,
	path:    string,
}

fixture_identity :: proc() -> [32]u8 {
	value: [32]u8; value[0], value[31] = 0x41, 0x14
	return value
}

fixture_close :: proc(f: ^Fixture) {
	wa.signal_session_clear(&f.pair.a); wa.signal_session_clear(&f.pair.b)
	wa.prekey_store_clear(&f.prekeys)
	wa.state_store_clear(&f.store); delete(f.path); free(f)
}

session_bytes :: proc(session: ^wa.Signal_Session) -> []u8 {
	size, error := wa.signal_session_encode(nil, session)
	assert(error.kind == .Destination_Undersized)
	data := make([]u8, size)
	_, error = wa.signal_session_encode(data, session)
	assert(error.kind == .None)
	return data
}

session_set :: proc(store: ^wa.State_Store, name: string, session: ^wa.Signal_Session) {
	data := session_bytes(session)
	defer {crypto.zero_explicit(raw_data(data), len(data)); delete(data)}
	assert(wa.state_store_set(store, .Session, name, data).kind == .None)
}

session_get :: proc(store: ^wa.State_Store, name: string, session: ^wa.Signal_Session) {
	data, found := wa.state_store_get(store, .Session, name)
	assert(found && wa.signal_session_decode(session, data).kind == .None)
}

prekeys_set :: proc(f: ^Fixture) {
	size, error := wa.prekey_store_encode(nil, &f.prekeys)
	assert(error.kind == .Destination_Undersized)
	data := make([]u8, size)
	defer {crypto.zero_explicit(raw_data(data), len(data)); delete(data)}
	_, error = wa.prekey_store_encode(data, &f.prekeys); assert(error.kind == .None)
	assert(wa.state_store_set(&f.store, .Captured_Message, "prekeys-b", data).kind == .None)
}

prekeys_get :: proc(f: ^Fixture) {
	data, found := wa.state_store_get(&f.store, .Captured_Message, "prekeys-b")
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
	defer wa.device_credentials_clear(&credentials)
	assert(found && wa.prekey_store_decode(&f.prekeys, data, &credentials).kind == .None)
}

fixture_open :: proc(directory: string, initialize: bool) -> ^Fixture {
	prefix := "/tmp/wa-encrypted-"
	if strings.has_prefix(directory, "/private/tmp/wa-encrypted-") {
		prefix = "/private/tmp/wa-encrypted-"
	}
	assert(strings.has_prefix(directory, prefix) && len(directory) > len(prefix))
	assert(!strings.contains(directory[len(prefix):], "/"))
	owner_path := fmt.aprintf("%s/owner", directory); defer delete(owner_path)
	owner, owner_error := os.read_entire_file(owner_path, context.allocator)
	assert(owner_error == nil); defer delete(owner)
	assert(string(owner) == OWNER)
	f := new(Fixture); f.path = fmt.aprintf("%s/state.bin", directory)
	if initialize {
		assert(!os.exists(f.path))
		assert(wa.state_store_init(&f.store, fixture_identity()).kind == .None)
	} else {
		assert(wa.state_store_load(&f.store, f.path, fixture_identity()).kind == .None)
	}
	return f
}

fixture_first :: proc(f: ^Fixture) {
	a, b := fixture_local(0, 100), fixture_local(96, 200)
	bundle := fixture_bundle(b)
	assert(
		wa.signal_session_init_initiator(&f.pair.a, a.identity_private, a.registration_id, bundle, bundle.identity_public).kind ==
		.None,
	)
	wire: [1024]u8
	kind, size, error := wa.signal_session_encrypt(
		&f.pair.a,
		wire[:],
		transmute([]u8)FIRST_BODY,
		bundle.identity_public,
	)
	assert(error.kind == .None && kind == .Prekey)
	session_set(&f.store, "device-a", &f.pair.a)
	public_a := wa.signal_curve_public(a.identity_private)
	assert(wa.state_store_set(&f.store, .Outbound_Message, INITIAL_ID, wire[:size]).kind == .None)
	assert(wa.state_store_set(&f.store, .Identity, "device-a", public_a[:]).kind == .None)
	assert(
		wa.state_store_set(&f.store, .Identity, "device-b", bundle.identity_public[:]).kind ==
		.None,
	)
	f.prekeys = {
		initialized      = true,
		identity_public  = bundle.identity_public,
		count            = 1,
		next_id          = 10,
		revision         = 1,
		durable_revision = 1,
	}
	f.prekeys.keys[0] = {
		id      = 9,
		private = b.prekey_private,
		public  = wa.signal_curve_public(b.prekey_private),
		status  = .Published,
	}
	prekeys_set(f)
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
}

fixture_receive_first :: proc(f: ^Fixture) {
	wire, found := wa.state_store_get(&f.store, .Outbound_Message, INITIAL_ID); assert(found)
	plaintext: [1024]u8
	size, consumed, error := wa.signal_session_decrypt_prekey(
		&f.pair.b,
		plaintext[:],
		wire,
		fixture_local(96, 200),
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(error.kind == .None && consumed == 9 && string(plaintext[:size]) == FIRST_BODY)
	assert(wa.prekey_store_remove_consumed(&f.prekeys, consumed).kind == .None)
	prekeys_set(f)
	session_set(&f.store, "device-b", &f.pair.b)
	assert(wa.state_store_set(&f.store, .Consumed_Prekey, "device-b/9", []u8{9}).kind == .None)
	assert(
		wa.state_store_set(&f.store, .Inbox_Message, INITIAL_ID, plaintext[:size]).kind == .None,
	)
}

fixture_established :: proc(f: ^Fixture) {
	fixture_first(f); fixture_receive_first(f)
	wire, plaintext: [1024]u8
	kind, size, error := wa.signal_session_encrypt(
		&f.pair.b,
		wire[:],
		[]u8{1},
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(error.kind == .None && kind == .Whisper)
	_, error = wa.signal_session_decrypt(
		&f.pair.a,
		plaintext[:],
		wire[:size],
		wa.signal_curve_public(fixture_private(96)),
	)
	assert(error.kind == .None && !f.pair.a.pending_prekey && f.pair.a.send_counter == -1)
	session_set(&f.store, "device-a", &f.pair.a); session_set(&f.store, "device-b", &f.pair.b)
	// Durable caller intent precedes encryption. Never mint a replacement ID.
	assert(
		wa.state_store_set(&f.store, .Outbound_Content, INTENT_ID, transmute([]u8)BODY).kind ==
		.None,
	)
	assert(wa.state_store_save(&f.store, f.path).kind == .None)
}

fixture_load_pair :: proc(f: ^Fixture) {
	session_get(&f.store, "device-a", &f.pair.a); session_get(&f.store, "device-b", &f.pair.b)
	marker, found := wa.state_store_get(&f.store, .Consumed_Prekey, "device-b/9")
	assert(found && bytes.equal(marker, []u8{9}))
	prekeys_get(f)
	assert(wa.prekey_store_get(&f.prekeys, 9) == nil)
}

fixture_encrypt :: proc(f: ^Fixture) {
	wire: [1024]u8
	kind, size, error := wa.signal_session_encrypt(
		&f.pair.a,
		wire[:],
		transmute([]u8)BODY,
		wa.signal_curve_public(fixture_private(96)),
	)
	assert(kind == .Whisper && error.kind == .None)
	session_set(&f.store, "device-a", &f.pair.a)
	assert(wa.state_store_set(&f.store, .Outbound_Message, INTENT_ID, wire[:size]).kind == .None)
}

fixture_decrypt :: proc(f: ^Fixture) {
	wire, found := wa.state_store_get(&f.store, .Outbound_Message, INTENT_ID); assert(found)
	plaintext: [1024]u8
	count, error := wa.signal_session_decrypt(
		&f.pair.b,
		plaintext[:],
		wire,
		wa.signal_curve_public(fixture_private(0)),
	)
	assert(error.kind == .None && string(plaintext[:count]) == BODY)
	session_set(&f.store, "device-b", &f.pair.b)
	assert(wa.state_store_set(&f.store, .Processed_Message, INTENT_ID, []u8{1}).kind == .None)
}

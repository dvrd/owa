package whatsapp

import "core:bytes"
import "core:crypto"
import "core:crypto/sha2"
import "core:fmt"
import "core:io"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:slice"
import ascii "../ascii"
import "core:strconv"

// Device credentials and authentication persistence.

// Device credentials

MAX_DEVICE_PREKEY_ID :: cast(u32)0xff_ffff

// Initial device key material only. The caller owns these secrets and must
// persist them securely; account/pairing data is managed separately.
Device_Credentials :: struct {
	noise_private:              [32]u8,
	pairing_ephemeral_private:  [32]u8,
	identity_private:           [32]u8,
	signed_prekey_private:      [32]u8,
	signed_prekey_public:       [32]u8,
	signed_prekey_signature:    [64]u8,
	signed_prekey_id:           u32,
	registration_id:            u32,
	adv_secret:                 [32]u8,
	next_prekey_id:             u32,
	first_unuploaded_prekey_id: u32,
	registered:                 bool,
}

Credentials_Error :: enum {
	None,
	Entropy_Unavailable,
	Signing_Failed,
	Nil_Credentials,
	Invalid_Noise_Key,
	Invalid_Pairing_Ephemeral_Key,
	Invalid_Identity_Key,
	Invalid_Signed_Prekey,
	Invalid_Signed_Prekey_Signature,
	Invalid_Signed_Prekey_ID,
	Invalid_Registration_ID,
	Invalid_Prekey_ID,
	Invalid_Adv_Secret,
}

device_credentials_generate :: proc(
) -> (
	credentials: Device_Credentials,
	error: Credentials_Error,
) {
	when !crypto.HAS_RAND_BYTES do return {}, .Entropy_Unavailable
	device_private_generate(&credentials.noise_private)
	device_private_generate(&credentials.pairing_ephemeral_private)
	device_private_generate(&credentials.identity_private)
	device_private_generate(&credentials.signed_prekey_private)
	credentials.signed_prekey_public = signal_curve_public(
		credentials.signed_prekey_private,
	)
	message: [33]u8
	message[0] = 5 // Signal public-key type prefix is part of the signed data.
	copy(message[1:], credentials.signed_prekey_public[:])
	signature, sign_err := signal_curve_sign(
		credentials.identity_private,
		message[:],
	)
	if sign_err != .None {
		device_credentials_clear(&credentials)
		return {}, .Signing_Failed
	}

	credentials.signed_prekey_signature = signature
	registration: [2]u8
	crypto.rand_bytes(registration[:])
	credentials.registration_id =
		(cast(u32)registration[0] << 8 | cast(u32)registration[1]) &
		0x3fff
	crypto.rand_bytes(credentials.adv_secret[:])
	credentials.signed_prekey_id = 1
	credentials.next_prekey_id = 1
	credentials.first_unuploaded_prekey_id = 1
	return credentials, .None
}

device_credentials_validate :: proc(
	credentials: ^Device_Credentials,
) -> Credentials_Error {
	if credentials == nil do return .Nil_Credentials

	if !device_private_valid(&credentials.noise_private) {
		return .Invalid_Noise_Key
	}

	if !device_private_valid(
		&credentials.pairing_ephemeral_private,
	) {
		return .Invalid_Pairing_Ephemeral_Key
	}

	if !device_private_valid(&credentials.identity_private) {
		return .Invalid_Identity_Key
	}

	if !device_private_valid(&credentials.signed_prekey_private) {
		return .Invalid_Signed_Prekey
	}

	public := signal_curve_public(credentials.signed_prekey_private)
	if crypto.compare_constant_time(
		   public[:],
		   credentials.signed_prekey_public[:],
	   ) !=
	   1 {
		return .Invalid_Signed_Prekey
	}

	if credentials.signed_prekey_id == 0 ||
	   credentials.signed_prekey_id > MAX_DEVICE_PREKEY_ID {
		return .Invalid_Signed_Prekey_ID
	}

	if credentials.registration_id > 0x3fff {
		return .Invalid_Registration_ID
	}

	if credentials.next_prekey_id == 0 ||
	   credentials.next_prekey_id > MAX_DEVICE_PREKEY_ID ||
	   credentials.first_unuploaded_prekey_id == 0 ||
	   credentials.first_unuploaded_prekey_id >
		   credentials.next_prekey_id {
		return .Invalid_Prekey_ID
	}

	if crypto.is_zero_constant_time(credentials.adv_secret[:]) == 1 {
		return .Invalid_Adv_Secret
	}

	message: [33]u8
	message[0] = 5
	copy(message[1:], credentials.signed_prekey_public[:])
	identity_public := signal_curve_public(
		credentials.identity_private,
	)
	if signal_curve_verify(
		   identity_public,
		   message[:],
		   credentials.signed_prekey_signature[:],
	   ) !=
	   .None {
		return .Invalid_Signed_Prekey_Signature
	}

	return .None
}

device_credentials_clear :: proc(credentials: ^Device_Credentials) {
	if credentials != nil {
		crypto.zero_explicit(
			credentials,
			size_of(Device_Credentials),
		)
	}

}

device_private_generate :: proc(private: ^[32]u8) {
	crypto.rand_bytes(private[:])
	private[0] &= 248
	private[31] = (private[31] & 127) | 64
}

device_private_valid :: proc(private: ^[32]u8) -> bool {
	return(
		private[0] & 7 == 0 &&
		private[31] & 0xc0 == 0x40 &&
		crypto.is_zero_constant_time(private[:]) != 1 \
	)
}

// Authentication state persistence

MAX_AUTH_STATE_SIZE :: 8192
AUTH_STATE_VERSION :: 1
AUTH_STATE_MAGIC :: "ODWAUTH\x00"

Auth_State :: struct {
	credentials: Device_Credentials,
	account:     Paired_Account,
}

Auth_Store_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Credentials,
	Invalid_Account,
	Destination_Undersized,
	Overlapping_Buffers,
	State_Oversized,
	Invalid_Format,
	Unsupported_Version,
	Checksum_Mismatch,
	Read_Failed,
	Write_Failed,
	Flush_Failed,
	Close_Failed,
	Rename_Failed,
	Entropy_Unavailable,
}

Auth_Store_Error :: struct {
	kind:        Auth_Store_Error_Kind,
	credentials: Credentials_Error,
	pairing:     Pairing_Error,
	io:          os.Error,
}

auth_state_clear :: proc(state: ^Auth_State) {
	if state != nil {
		crypto.zero_explicit(state, size_of(Auth_State))
	}

}

auth_state_validate :: proc(state: ^Auth_State) -> Auth_Store_Error {
	if state == nil do return {kind = .Invalid_State}

	if err := device_credentials_validate(&state.credentials);
	   err != .None {
		return {kind = .Invalid_Credentials, credentials = err}
	}

	if state.credentials.registered != state.account.valid {
		return {kind = .Invalid_Account}
	}

	if state.account.valid {
		if err := paired_account_validate(
			&state.account,
			&state.credentials,
		); err.kind != .None {
			return {kind = .Invalid_Account, pairing = err}
		}

	}

	return {}
}

// Versioned native state. The checksum detects corruption, not malicious
// modification. Secret bytes are stored unencrypted, matching the old auth
// directory's persistence model; the file writer restricts mode to 0600.
auth_state_encode :: proc(
	dst: []u8,
	state: ^Auth_State,
) -> (
	n: int,
	error: Auth_Store_Error,
) {
	if err := auth_state_validate(state); err.kind != .None {
		return 0, err
	}

	required := 320
	if state.account.valid {
		required +=
			173 +
			state.account.jid_size +
			state.account.name_size +
			state.account.platform_size +
			state.account.details_size
	}

	if len(dst) < required {
		return required, {kind = .Destination_Undersized}
	}

	if bytes.alias(
		dst[:required],
		mem.slice_ptr(cast([^]u8)state, size_of(Auth_State)),
	) {
		return 0, {kind = .Overlapping_Buffers}
	}

	copy(dst[:8], AUTH_STATE_MAGIC)
	dst[8], dst[9] = 0, AUTH_STATE_VERSION
	n = 10
	auth_put_u32(dst, &n, cast(u32)(required - 46))
	auth_put_u32(dst, &n, state.credentials.registration_id)
	auth_put_u32(dst, &n, state.credentials.signed_prekey_id)
	auth_put_u32(dst, &n, state.credentials.next_prekey_id)
	auth_put_u32(
		dst,
		&n,
		state.credentials.first_unuploaded_prekey_id,
	)
	dst[n] = state.credentials.registered ? 1 : 0
	n += 1
	secrets := [7][]u8 {
		state.credentials.noise_private[:],
		state.credentials.pairing_ephemeral_private[:],
		state.credentials.identity_private[:],
		state.credentials.signed_prekey_private[:],
		state.credentials.signed_prekey_public[:],
		state.credentials.signed_prekey_signature[:],
		state.credentials.adv_secret[:],
	}
	for secret in secrets do n += copy(dst[n:], secret)
	dst[n] = state.account.valid ? 1 : 0
	n += 1
	auth_account_encode(dst, state, &n)

	assert(n + 32 == required)
	checksum: sha2.Context_256
	sha2.init_256(&checksum)
	sha2.update(&checksum, dst[:n])
	sha2.final(&checksum, dst[n:n + 32])
	n += 32
	return n, {}
}

auth_account_encode :: proc(dst: []u8, state: ^Auth_State, at: ^int) {
	if state.account.valid {
		auth_put_u32(dst, at, state.account.key_index)
		dst[at^] = state.account.hosted ? 1 : 0
		at^ += 1
		parts := [?][]u8 {
			state.account.jid[:state.account.jid_size],
			state.account.name[:state.account.name_size],
			state.account.platform[:state.account.platform_size],
			state.account.details[:state.account.details_size],
		}
		for part in parts {
			dst[at^], dst[at^ + 1] =
				cast(u8)(len(part) >> 8), cast(u8)len(part)
			at^ += 2
			at^ += copy(dst[at^:], part)
		}
		at^ += copy(dst[at^:], state.account.account_signature_key[:])
		at^ += copy(dst[at^:], state.account.account_signature[:])
		at^ += copy(dst[at^:], state.account.device_signature[:])
	}

}

auth_state_decode :: proc(
	dst: ^Auth_State,
	src: []u8,
) -> Auth_Store_Error {
	if dst == nil do return {kind = .Invalid_State}

	at, header_error := auth_state_header_validate(src)
	if header_error.kind != .None do return header_error

	next: Auth_State
	defer auth_state_clear(&next)
	next.credentials.registration_id = auth_get_u32(src, &at)
	next.credentials.signed_prekey_id = auth_get_u32(src, &at)
	next.credentials.next_prekey_id = auth_get_u32(src, &at)
	next.credentials.first_unuploaded_prekey_id = auth_get_u32(
		src,
		&at,
	)
	if src[at] > 1 do return {kind = .Invalid_Format}

	next.credentials.registered = src[at] == 1
	at += 1
	keys := [?][]u8 {
		next.credentials.noise_private[:],
		next.credentials.pairing_ephemeral_private[:],
		next.credentials.identity_private[:],
		next.credentials.signed_prekey_private[:],
		next.credentials.signed_prekey_public[:],
		next.credentials.signed_prekey_signature[:],
		next.credentials.adv_secret[:],
	}
	for key in keys {copy(key, src[at:][:len(key)]); at += len(key)}
	end := len(src) - 32
	if src[at] > 1 do return {kind = .Invalid_Format}

	next.account.valid = src[at] == 1
	at += 1
	if account_error := auth_account_decode(&next, src, &at, end);
	   account_error.kind != .None do return account_error

	if at != end do return {kind = .Invalid_Format}

	if err := auth_state_validate(&next); err.kind != .None {
		return err
	}

	auth_state_clear(dst)
	dst^ = next
	return {}
}

auth_state_header_validate :: proc(src: []u8) -> (int, Auth_Store_Error) {
	if len(src) > MAX_AUTH_STATE_SIZE {
		return 0, {kind = .State_Oversized}
	}

	if len(src) < 320 || cast(string)src[:8] != AUTH_STATE_MAGIC {
		return 0, {kind = .Invalid_Format}
	}

	if src[8] != 0 || src[9] != AUTH_STATE_VERSION {
		return 0, {kind = .Unsupported_Version}
	}

	at := 10
	if cast(int)auth_get_u32(src, &at) != len(src) - 46 {
		return 0, {kind = .Invalid_Format}
	}

	hash: [32]u8
	checksum: sha2.Context_256
	sha2.init_256(&checksum)
	sha2.update(&checksum, src[:len(src) - 32])
	sha2.final(&checksum, hash[:])
	if crypto.compare_constant_time(hash[:], src[len(src) - 32:]) !=
	   1 {
		return 0, {kind = .Checksum_Mismatch}
	}

	return at, {}
}

auth_account_decode :: proc(
	next: ^Auth_State, src: []u8, at: ^int, end: int,
) -> Auth_Store_Error {
	if next.account.valid {
		if end - at^ < 5 do return {kind = .Invalid_Format}

		next.account.key_index = auth_get_u32(src, at)
		if src[at^] > 1 do return {kind = .Invalid_Format}

		next.account.hosted = src[at^] == 1
		at^ += 1
		slots := [?][]u8 {
			next.account.jid[:],
			next.account.name[:],
			next.account.platform[:],
			next.account.details[:],
		}
		sizes := [?]^int {
			&next.account.jid_size,
			&next.account.name_size,
			&next.account.platform_size,
			&next.account.details_size,
		}
		for slot, i in slots {
			if end - at^ < 2 {
				return {kind = .Invalid_Format}
			}

			size := cast(int)src[at^] << 8 | cast(int)src[at^ + 1]
			at^ += 2
			if size > len(slot) || size > end - at^ {
				return {kind = .Invalid_Format}
			}

			copy(slot, src[at^:at^ + size])
			sizes[i]^ = size
			at^ += size
		}
		if end - at^ != 160 {
			return {kind = .Invalid_Format}
		}

		copy(next.account.account_signature_key[:], src[at^:at^ + 32])
		at^ += 32
		copy(next.account.account_signature[:], src[at^:at^ + 64])
		at^ += 64
		copy(next.account.device_signature[:], src[at^:at^ + 64])
		at^ += 64
	}

	return {}
}

auth_state_save :: proc(
	path: string,
	state: ^Auth_State,
) -> Auth_Store_Error {
	buffer: [MAX_AUTH_STATE_SIZE]u8
	defer crypto.zero_explicit(&buffer, size_of(buffer))
	size, encode_err := auth_state_encode(buffer[:], state)
	if encode_err.kind != .None do return encode_err

	when !crypto.HAS_RAND_BYTES do return {kind = .Entropy_Unavailable}
	random: [8]u8
	crypto.rand_bytes(random[:])
	temporary := fmt.aprintf(
		"%s.tmp-%016x",
		path,
		transmute(u64)random,
	)
	defer delete(temporary)
	file, open_err := os.open(
		temporary,
		{.Write, .Create, .Excl},
		{.Read_User, .Write_User},
	)
	if open_err != nil {
		return {kind = .Write_Failed, io = open_err}
	}

	closed, renamed: bool
	defer {
		if !closed do os.close(file)

		if !renamed do os.remove(temporary)

	}
	n, write_err := os.write(file, buffer[:size])
	if write_err != nil || n != size {
		return {kind = .Write_Failed, io = write_err}
	}

	if err := os.flush(file); err != nil {
		return {kind = .Flush_Failed, io = err}
	}

	close_err := os.close(file)
	closed = true
	if close_err != nil {
		return {kind = .Close_Failed, io = close_err}
	}

	if err := os.rename(temporary, path); err != nil {
		return {kind = .Rename_Failed, io = err}
	}

	renamed = true
	// Flushing the file protects its contents, but the directory entry must
	// also be durable before session_checkpoint permits a pairing reply.
	parent, parent_err := os.open(filepath.dir(path))
	if parent_err != nil {
		return {kind = .Flush_Failed, io = parent_err}
	}

	defer os.close(parent)
	if err := os.flush(parent); err != nil {
		return {kind = .Flush_Failed, io = err}
	}

	return {}
}

auth_state_load :: proc(
	path: string,
	state: ^Auth_State,
) -> Auth_Store_Error {
	if state == nil do return {kind = .Invalid_State}

	file, open_err := os.open(path)
	if open_err != nil {
		return {kind = .Read_Failed, io = open_err}
	}

	defer os.close(file)
	buffer: [MAX_AUTH_STATE_SIZE + 1]u8
	defer crypto.zero_explicit(&buffer, size_of(buffer))
	used := 0
	for used < len(buffer) {
		count, err := os.read(file, buffer[used:])
		used += count
		if !slice.contains([]type_of(err){nil, io.Error.EOF}, err) {
			return {kind = .Read_Failed, io = err}
		}

		if count == 0 || err == io.Error.EOF do break

	}
	if used > MAX_AUTH_STATE_SIZE {
		return {kind = .State_Oversized}
	}

	return auth_state_decode(state, buffer[:used])
}

auth_put_u32 :: proc(dst: []u8, at: ^int, value: u32) {
	for i in 0 ..< 4 do dst[at^ + i] = cast(u8)(value >> cast(uint)(24 - i * 8))
	at^ += 4
}

auth_get_u32 :: proc(src: []u8, at: ^int) -> u32 {
	value :=
		cast(u32)src[at^] << 24 |
		cast(u32)src[at^ + 1] << 16 |
		cast(u32)src[at^ + 2] << 8 |
		cast(u32)src[at^ + 3]
	at^ += 4
	return value
}

// One-time prekey provisioning and persistence.

MAX_STORED_PREKEYS :: 1024
MAX_PREKEY_UPLOAD_COUNT :: 256
PREKEY_DEFAULT_UPLOAD_COUNT :: 30
PREKEY_SERVER_MIN_COUNT :: 5
PREKEY_SERVER_JID :: "@s.whatsapp.net"
MAX_PREKEY_REQUEST_ID_SIZE :: 128
PREKEY_STORE_VERSION :: 1
PREKEY_STORE_MAGIC :: cast(string)"ODWPREK\x00"
MAX_PREKEY_STORE_SIZE ::
	8 +
	2 +
	32 +
	4 +
	8 +
	2 +
	4 +
	2 +
	2 +
	MAX_PREKEY_REQUEST_ID_SIZE +
	MAX_STORED_PREKEYS * 69 +
	32

Prekey_Status :: enum u8 {
	Unpublished,
	Pending,
	Published,
}
One_Time_Prekey :: struct {
	id:              u32,
	private, public: [32]u8,
	status:          Prekey_Status,
}

// Single-writer, connection-independent storage. Published private keys remain
// here until a future Signal-session transaction safely consumes them. Nothing
// in this provisioning module deletes published keys or writes Device_Credentials.
// A registered account must reload its existing store, never recreate one after
// a load failure. The store, not auth metadata, owns its monotonically rising ID.
Prekey_Store :: struct {
	initialized:                bool,
	identity_public:            [32]u8,
	keys:                       [MAX_STORED_PREKEYS]One_Time_Prekey,
	count:                      int,
	next_id:                    u32,
	revision, durable_revision: u64,
	pending_first_id:           u32,
	pending_count:              int,
	pending_request_id:         [MAX_PREKEY_REQUEST_ID_SIZE]u8,
	pending_request_id_size:    int,
}

Prekey_Error_Kind :: enum {
	None,
	Invalid_State,
	Already_Initialized,
	Invalid_Credentials,
	Identity_Mismatch,
	Invalid_Count,
	Store_Full,
	ID_Exhausted,
	Revision_Exhausted,
	Entropy_Unavailable,
	Invalid_Key,
	Invalid_Status,
	Invalid_Request_ID,
	Pending_Upload_Exists,
	No_Pending_Upload,
	Persistence_Required,
	Destination_Undersized,
	Invalid_Format,
	Unsupported_Version,
	Checksum_Mismatch,
	State_Oversized,
	Read_Failed,
	Write_Failed,
	Flush_Failed,
	Close_Failed,
	Rename_Failed,
	Directory_Sync_Failed,
	Binary_Node_Failed,
	Response_Mismatch,
	Invalid_Response,
	Server_Rejected,
}

Prekey_Error :: struct {
	kind:        Prekey_Error_Kind,
	credentials: Credentials_Error,
	binary:      Binary_Node_Error,
	io:          os.Error,
	server_code: u32,
}

prekey_store_init :: proc(
	store: ^Prekey_Store,
	credentials: ^Device_Credentials,
) -> Prekey_Error {
	if store == nil do return {kind = .Invalid_State}

	if store.initialized {
		return {kind = .Already_Initialized}
	}

	if err := device_credentials_validate(credentials);
	   err != .None {
		return {kind = .Invalid_Credentials, credentials = err}
	}

	// An auth counter describing generated but missing private keys cannot be
	// repaired by silently regenerating a different key under the same ID.
	if credentials.first_unuploaded_prekey_id !=
	   credentials.next_prekey_id {
		return {
			kind = .Invalid_Credentials,
			credentials = .Invalid_Prekey_ID,
		}
	}

	store^ = {
		initialized     = true,
		identity_public = signal_curve_public(
			credentials.identity_private,
		),
		next_id         = credentials.next_prekey_id,
		revision        = 1,
	}
	return {}
}

prekey_store_clear :: proc(store: ^Prekey_Store) {
	if store != nil {
		crypto.zero_explicit(store, size_of(Prekey_Store))
	}

}

prekey_store_get :: proc(
	store: ^Prekey_Store,
	id: u32,
) -> ^One_Time_Prekey {
	if store == nil ||
	   !store.initialized ||
	   store.count < 0 ||
	   store.count > MAX_STORED_PREKEYS {
		return nil
	}

	for &key in store.keys[:store.count] {
		if key.id == id do return &key

	}
	return nil
}

prekey_store_generate :: proc(
	store: ^Prekey_Store,
	count: int,
) -> Prekey_Error {
	if err := prekey_store_validate(store); err.kind != .None {
		return err
	}

	if err := prekey_generation_validate(store, count);
	   err.kind != .None {
		return err
	}

	prekey_generate_append(store, count)
	store.revision += 1
	return {}
}

// Select the oldest unpublished keys, generating only any missing suffix.
// Persist this Pending batch before calling prekey_upload_encode or sending.
prekey_upload_prepare :: proc(
	store: ^Prekey_Store,
	request_id: string,
	count: int = PREKEY_DEFAULT_UPLOAD_COUNT,
) -> Prekey_Error {
	if err := prekey_store_validate(store); err.kind != .None {
		return err
	}

	if !prekey_request_id_valid(request_id) {
		return {kind = .Invalid_Request_ID}
	}

	if count < 1 || count > MAX_PREKEY_UPLOAD_COUNT {
		return {kind = .Invalid_Count}
	}

	if store.pending_count != 0 {
		return {kind = .Pending_Upload_Exists}
	}

	if store.revision == max(u64) {
		return {kind = .Revision_Exhausted}
	}

	unpublished := 0
	for key in store.keys[:store.count] {
		if key.status == .Unpublished do unpublished += 1

	}
	needed := max(0, count - unpublished)
	if needed > 0 {
		if err := prekey_generation_validate(store, needed);
		   err.kind != .None {
			return err
		}

		prekey_generate_append(store, needed)
	}

	for &key in store.keys[:store.count] {
		if key.status == .Unpublished {
			if store.pending_count == 0 {
				store.pending_first_id = key.id
			}

			key.status = .Pending
			store.pending_count += 1
			if store.pending_count == count do break

		}

	}
	prekey_set_request_id(store, request_id)
	store.revision += 1
	return {}
}

// Lost responses/reconnections reuse the same private keys and IDs. Only the
// IQ correlation ID changes; persist it before resending the upload.
prekey_upload_retry :: proc(
	store: ^Prekey_Store,
	request_id: string,
) -> Prekey_Error {
	if err := prekey_store_validate(store); err.kind != .None {
		return err
	}

	if store.pending_count == 0 {
		return {kind = .No_Pending_Upload}
	}

	if !prekey_request_id_valid(request_id) {
		return {kind = .Invalid_Request_ID}
	}

	if store.revision == max(u64) {
		return {kind = .Revision_Exhausted}
	}

	prekey_set_request_id(store, request_id)
	store.revision += 1
	return {}
}

// Pinned Baileys Utils/signal.js getNextPreKeysNode, with the request ID
// appended by Socket/socket.js query. Only public material is serialized.
prekey_upload_encode :: proc(
	dst: []u8,
	store: ^Prekey_Store,
	credentials: ^Device_Credentials,
) -> (
	n: int,
	error: Prekey_Error,
) {
	if validation_error := prekey_upload_validate(store, credentials);
	   validation_error.kind != .None do return 0, validation_error

	registration: [4]u8
	for i in 0 ..< 4 {
		registration[i] = cast(u8)(credentials.registration_id >> cast(uint)(24 - i * 8))
	}
	bundle_type := [?]u8{5}
	identity := store.identity_public
	ids: [MAX_PREKEY_UPLOAD_COUNT][3]u8
	key_fields: [MAX_PREKEY_UPLOAD_COUNT][2]Binary_Node
	key_nodes: [MAX_PREKEY_UPLOAD_COUNT]Binary_Node
	at := prekey_upload_nodes_prepare(store, ids[:], key_fields[:], key_nodes[:])
	signed_id := prekey_id_bytes(credentials.signed_prekey_id)
	signed_fields := [?]Binary_Node {
		{tag = "id", content = signed_id[:]},
		{
			tag = "value",
			content = credentials.signed_prekey_public[:],
		},
		{
			tag = "signature",
			content = credentials.signed_prekey_signature[:],
		},
	}
	content := [?]Binary_Node {
		{tag = "registration", content = registration[:]},
		{tag = "type", content = bundle_type[:]},
		{tag = "identity", content = identity[:]},
		{tag = "list", content = key_nodes[:at]},
		{tag = "skey", content = signed_fields[:]},
	}
	attrs := [?]Binary_Node_Attribute {
		{"xmlns", "encrypt"},
		{"type", "set"},
		{"to", PREKEY_SERVER_JID},
		{
			"id",
			cast(string)store.pending_request_id[:store.pending_request_id_size],
		},
	}
	size, binary_err := binary_node_encode(
		dst,
		{tag = "iq", attrs = attrs[:], content = content[:]},
	)
	if binary_err.kind != .None {
		kind: Prekey_Error_Kind = .Binary_Node_Failed
		if binary_err.kind == .Destination_Undersized {
			kind = .Destination_Undersized
		}

		return size, {kind = kind, binary = binary_err}
	}

	return size, {}
}

prekey_upload_nodes_prepare :: proc(
	store: ^Prekey_Store, ids: [][3]u8,
	key_fields: [][2]Binary_Node, key_nodes: []Binary_Node,
) -> int {
	at := 0
	for &key in store.keys[:store.count] {
		if key.status != .Pending do continue

		ids[at] = prekey_id_bytes(key.id)
		key_fields[at] = {
			Binary_Node{tag = "id", content = ids[at][:]},
			Binary_Node{tag = "value", content = key.public[:]},
		}
		key_nodes[at] = {
			tag     = "key",
			content = key_fields[at][:],
		}
		at += 1
	}
	return at
}

prekey_upload_validate :: proc(
	store: ^Prekey_Store, credentials: ^Device_Credentials,
) -> Prekey_Error {
	if err := prekey_store_validate(store); err.kind != .None {
		return err
	}

	if err := prekey_owner_validate(store, credentials);
	   err.kind != .None {
		return err
	}

	if store.pending_count == 0 {
		return {kind = .No_Pending_Upload}
	}

	if store.durable_revision != store.revision {
		return {kind = .Persistence_Required}
	}

	return {}
}

// A matching successful IQ, not a socket send, confirms publication. All
// private keys are retained. Save this revision before preparing another batch.
// If the process dies before saving, the old Pending snapshot is safe to retry.
prekey_upload_handle_response :: proc(
	store: ^Prekey_Store,
	response: Binary_Node,
) -> Prekey_Error {
	if err := prekey_store_validate(store); err.kind != .None {
		return err
	}

	if store.pending_count == 0 {
		return {kind = .No_Pending_Upload}
	}

	if store.durable_revision != store.revision {
		return {kind = .Persistence_Required}
	}

	request_id := cast(string)store.pending_request_id[:store.pending_request_id_size]
	if err := prekey_response_validate(response, request_id);
	   err.kind != .None {
		return err
	}

	if store.revision == max(u64) {
		return {kind = .Revision_Exhausted}
	}

	for &key in store.keys[:store.count] {
		if key.status == .Pending do key.status = .Published

	}
	store.pending_first_id, store.pending_count = 0, 0
	crypto.zero_explicit(
		&store.pending_request_id,
		size_of(store.pending_request_id),
	)
	store.pending_request_id_size = 0
	store.revision += 1
	return {}
}

prekey_count_query_encode :: proc(
	dst: []u8,
	request_id: string,
) -> (
	int,
	Prekey_Error,
) {
	if !prekey_request_id_valid(request_id) {
		return 0, {kind = .Invalid_Request_ID}
	}

	attrs := [?]Binary_Node_Attribute {
		{"id", request_id},
		{"xmlns", "encrypt"},
		{"type", "get"},
		{"to", PREKEY_SERVER_JID},
	}
	content := [?]Binary_Node{{tag = "count"}}
	size, err := binary_node_encode(
		dst,
		{tag = "iq", attrs = attrs[:], content = content[:]},
	)
	if err.kind != .None {
		return size, {kind = .Binary_Node_Failed, binary = err}
	}

	return size, {}
}

prekey_count_response :: proc(
	response: Binary_Node,
	request_id: string,
) -> (
	int,
	Prekey_Error,
) {
	if err := prekey_response_validate(response, request_id);
	   err.kind != .None {
		return 0, err
	}

	count: ^Binary_Node
	#partial switch children in response.content {
	case []Binary_Node:
		for &child in children {
			if child.tag == "count" {
				if count != nil {
					return 0, {kind = .Invalid_Response}
				}

				count = &child
			}

		}
	}
	if count == nil do return 0, {kind = .Invalid_Response}

	value, found := node_attr(count^, "value")
	if !found || len(value) == 0 {
		return 0, {kind = .Invalid_Response}
	}

	for c in value {
		if !ascii.is_digit(c) {
			return 0, {kind = .Invalid_Response}
		}

	}
	parsed, valid := strconv.parse_uint(value, 10)
	if !valid || parsed > cast(uint)MAX_DEVICE_PREKEY_ID {
		return 0, {kind = .Invalid_Response}
	}

	return cast(int)parsed, {}
}

// Versioned checksum-protected plaintext snapshot (not encryption). Callers
// must keep this private, as with auth state. Encoding alone does not satisfy
// the durable-before-upload gate; only a successful save/load does.
prekey_store_encode :: proc(
	dst: []u8,
	store: ^Prekey_Store,
) -> (
	int,
	Prekey_Error,
) {
	if err := prekey_store_validate(store); err.kind != .None {
		return 0, err
	}

	size :=
		8 +
		2 +
		32 +
		4 +
		8 +
		2 +
		4 +
		2 +
		2 +
		store.pending_request_id_size +
		store.count * 69 +
		32
	if len(dst) < size {
		return size, {kind = .Destination_Undersized}
	}

	at := copy(dst, transmute([]u8)PREKEY_STORE_MAGIC)
	prekey_put_uint(dst, &at, PREKEY_STORE_VERSION, 2)
	at += copy(dst[at:], store.identity_public[:])
	prekey_put_uint(dst, &at, cast(u64)store.next_id, 4)
	prekey_put_uint(dst, &at, store.revision, 8)
	prekey_put_uint(dst, &at, cast(u64)store.count, 2)
	prekey_put_uint(dst, &at, cast(u64)store.pending_first_id, 4)
	prekey_put_uint(dst, &at, cast(u64)store.pending_count, 2)
	prekey_put_uint(
		dst,
		&at,
		cast(u64)store.pending_request_id_size,
		2,
	)
	at += copy(
		dst[at:],
		store.pending_request_id[:store.pending_request_id_size],
	)
	for key in store.keys[:store.count] {
		prekey_put_uint(dst, &at, cast(u64)key.id, 4)
		dst[at] = cast(u8)key.status
		at += 1
		for value, i in key.private do dst[at + i] = value
		at += 32
		for value, i in key.public do dst[at + i] = value
		at += 32
	}
	hash := prekey_hash(dst[:at])
	copy(dst[at:], hash[:])
	return size, {}
}

prekey_store_decode :: proc(
	store: ^Prekey_Store,
	src: []u8,
	credentials: ^Device_Credentials,
) -> Prekey_Error {
	if store == nil do return {kind = .Invalid_State}

	if header_error := prekey_store_header_validate(src);
	   header_error.kind != .None do return header_error

	at := 8
	if prekey_get_uint(src, &at, 2) != PREKEY_STORE_VERSION {
		return {kind = .Unsupported_Version}
	}

	next: Prekey_Store
	defer prekey_store_clear(&next)
	next.initialized = true
	at += copy(next.identity_public[:], src[at:][:32])
	next.next_id = cast(u32)prekey_get_uint(src, &at, 4)
	next.revision = prekey_get_uint(src, &at, 8)
	next.count = cast(int)prekey_get_uint(src, &at, 2)
	next.pending_first_id = cast(u32)prekey_get_uint(src, &at, 4)
	next.pending_count = cast(int)prekey_get_uint(src, &at, 2)
	next.pending_request_id_size = cast(int)prekey_get_uint(
		src,
		&at,
		2,
	)
	if next.count > MAX_STORED_PREKEYS ||
	   next.pending_count > MAX_PREKEY_UPLOAD_COUNT ||
	   next.pending_request_id_size > MAX_PREKEY_REQUEST_ID_SIZE {
		return {kind = .Invalid_Format}
	}

	if at + next.pending_request_id_size + next.count * 69 + 32 !=
	   len(src) {
		return {kind = .Invalid_Format}
	}

	at += copy(
		next.pending_request_id[:next.pending_request_id_size],
		src[at:][:next.pending_request_id_size],
	)
	for &key in next.keys[:next.count] {
		key.id = cast(u32)prekey_get_uint(src, &at, 4)
		key.status = cast(Prekey_Status)src[at]
		at += 1
		at += copy(key.private[:], src[at:][:32])
		at += copy(key.public[:], src[at:][:32])
	}
	if err := prekey_store_validate(&next); err.kind != .None {
		return err
	}

	if err := prekey_owner_validate(&next, credentials);
	   err.kind != .None {
		return err
	}

	prekey_store_clear(store)
	store^ = next
	return {}
}

prekey_store_header_validate :: proc(src: []u8) -> Prekey_Error {
	if len(src) > MAX_PREKEY_STORE_SIZE {
		return {kind = .State_Oversized}
	}

	if len(src) < 8 + 2 + 32 + 4 + 8 + 2 + 4 + 2 + 2 + 32 {
		return {kind = .Invalid_Format}
	}

	if !bytes.equal(src[:8], transmute([]u8)PREKEY_STORE_MAGIC) {
		return {kind = .Invalid_Format}
	}

	hash := prekey_hash(src[:len(src) - 32])
	if crypto.compare_constant_time(hash[:], src[len(src) - 32:]) !=
	   1 {
		return {kind = .Checksum_Mismatch}
	}

	return {}
}

// Exclusive temporary file, mode0600, full write+fsync, atomic rename, then
// directory fsync. A failed durability step never permits upload. Serialize
// writers; this is a local single-process store, not a multi-writer database.
prekey_store_save :: proc(
	path: string,
	store: ^Prekey_Store,
) -> Prekey_Error {
	buffer: [MAX_PREKEY_STORE_SIZE]u8
	defer crypto.zero_explicit(&buffer, size_of(buffer))
	size, encode_err := prekey_store_encode(buffer[:], store)
	if encode_err.kind != .None do return encode_err

	when !crypto.HAS_RAND_BYTES do return {kind = .Entropy_Unavailable}
	random: [8]u8
	crypto.rand_bytes(random[:])
	temporary := fmt.aprintf(
		"%s.tmp-%016x",
		path,
		transmute(u64)random,
	)
	defer delete(temporary)
	file, open_err := os.open(
		temporary,
		{.Write, .Create, .Excl},
		{.Read_User, .Write_User},
	)
	if open_err != nil {
		return {kind = .Write_Failed, io = open_err}
	}

	closed, renamed: bool
	defer {
		if !closed do os.close(file)

		if !renamed do os.remove(temporary)

	}
	if write_error := prekey_store_write_flush(file, buffer[:size]);
	   write_error.kind != .None do return write_error

	close_err := os.close(file)
	closed = true
	if close_err != nil {
		return {kind = .Close_Failed, io = close_err}
	}

	if err := os.rename(temporary, path); err != nil {
		return {kind = .Rename_Failed, io = err}
	}

	renamed = true
	parent := filepath.dir(path)
	directory, directory_err := os.open(parent)
	if directory_err != nil {
		return {kind = .Directory_Sync_Failed, io = directory_err}
	}

	defer os.close(directory)
	if err := os.flush(directory); err != nil {
		return {kind = .Directory_Sync_Failed, io = err}
	}

	store.durable_revision = store.revision
	return {}
}

prekey_store_write_flush :: proc(file: ^os.File, buffer: []u8) -> Prekey_Error {
	written := 0
	for written < len(buffer) {
		count, err := os.write(file, buffer[written:])
		written += count
		if err != nil || count == 0 {
			return {kind = .Write_Failed, io = err}
		}

	}
	if err := os.flush(file); err != nil {
		return {kind = .Flush_Failed, io = err}
	}

	return {}
}

prekey_store_load :: proc(
	path: string,
	store: ^Prekey_Store,
	credentials: ^Device_Credentials,
) -> Prekey_Error {
	if store == nil do return {kind = .Invalid_State}

	file, open_err := os.open(path)
	if open_err != nil {
		return {kind = .Read_Failed, io = open_err}
	}

	defer os.close(file)
	buffer: [MAX_PREKEY_STORE_SIZE + 1]u8
	defer crypto.zero_explicit(&buffer, size_of(buffer))
	used := 0
	for used < len(buffer) {
		count, err := os.read(file, buffer[used:])
		used += count
		if !slice.contains([]type_of(err){nil, io.Error.EOF}, err) {
			return {kind = .Read_Failed, io = err}
		}

		if count == 0 || err == io.Error.EOF do break

	}
	if used > MAX_PREKEY_STORE_SIZE {
		return {kind = .State_Oversized}
	}

	if err := prekey_store_decode(store, buffer[:used], credentials);
	   err.kind != .None {
		return err
	}

	store.durable_revision = store.revision
	return {}
}

prekey_store_validate :: proc(store: ^Prekey_Store) -> Prekey_Error {
	if store == nil || !store.initialized {
		return {kind = .Invalid_State}
	}

	if store.count < 0 ||
	   store.count > MAX_STORED_PREKEYS ||
	   store.next_id == 0 ||
	   store.next_id > MAX_DEVICE_PREKEY_ID + 1 ||
	   store.revision == 0 ||
	   store.durable_revision > store.revision {
		return {kind = .Invalid_State}
	}

	if crypto.is_zero_constant_time(store.identity_public[:]) == 1 {
		return {kind = .Identity_Mismatch}
	}

	if store.pending_count < 0 ||
	   store.pending_count > MAX_PREKEY_UPLOAD_COUNT ||
	   store.pending_request_id_size < 0 ||
	   store.pending_request_id_size > MAX_PREKEY_REQUEST_ID_SIZE {
		return {kind = .Invalid_State}
	}

	if store.pending_count == 0 {
		if store.pending_first_id != 0 ||
		   store.pending_request_id_size != 0 {
			return {kind = .Invalid_State}
		}

	} else {
		if store.pending_first_id == 0 ||
		   store.pending_first_id > MAX_DEVICE_PREKEY_ID ||
		   cast(u32)store.pending_count >
			   MAX_DEVICE_PREKEY_ID - store.pending_first_id + 1 {
			return {kind = .Invalid_State}
		}

		if !prekey_request_id_valid(
			cast(string)store.pending_request_id[:store.pending_request_id_size],
		) {
			return {kind = .Invalid_Request_ID}
		}

	}

	return prekey_store_keys_validate(store)
}

prekey_store_keys_validate :: proc(store: ^Prekey_Store) -> Prekey_Error {
	previous: u32
	pending := 0
	phase: Prekey_Status = .Published
	for &key in store.keys[:store.count] {
		if key.id == 0 ||
		   key.id > MAX_DEVICE_PREKEY_ID ||
		   key.id <= previous ||
		   key.id >= store.next_id {
			return {kind = .Invalid_Key}
		}

		previous = key.id
		if key.private[0] & 7 != 0 ||
		   key.private[31] & 0xc0 != 0x40 {
			return {kind = .Invalid_Key}
		}

		public := signal_curve_public(key.private)
		if crypto.compare_constant_time(public[:], key.public[:]) !=
		   1 {
			return {kind = .Invalid_Key}
		}

		#partial switch key.status {
		case .Published:
			if phase != .Published {
				return {kind = .Invalid_Status}
			}

		case .Pending:
			if phase == .Unpublished {
				return {kind = .Invalid_Status}
			}

			phase = .Pending
			if key.id != store.pending_first_id + cast(u32)pending {
				return {kind = .Invalid_Status}
			}

			pending += 1
		case .Unpublished:
			phase = .Unpublished
		case:
			return {kind = .Invalid_Status}
		}
	}
	if pending != store.pending_count {
		return {kind = .Invalid_Status}
	}

	return {}
}

prekey_owner_validate :: proc(
	store: ^Prekey_Store,
	credentials: ^Device_Credentials,
) -> Prekey_Error {
	if err := device_credentials_validate(credentials);
	   err != .None {
		return {kind = .Invalid_Credentials, credentials = err}
	}

	identity := signal_curve_public(credentials.identity_private)
	if crypto.compare_constant_time(
		   identity[:],
		   store.identity_public[:],
	   ) !=
	   1 {
		return {kind = .Identity_Mismatch}
	}

	return {}
}

prekey_generation_validate :: proc(
	store: ^Prekey_Store,
	count: int,
) -> Prekey_Error {
	if count < 1 || count > MAX_PREKEY_UPLOAD_COUNT {
		return {kind = .Invalid_Count}
	}

	if count > MAX_STORED_PREKEYS - store.count {
		return {kind = .Store_Full}
	}

	if cast(u32)count > MAX_DEVICE_PREKEY_ID + 1 - store.next_id {
		return {kind = .ID_Exhausted}
	}

	if store.revision == max(u64) {
		return {kind = .Revision_Exhausted}
	}

	when !crypto.HAS_RAND_BYTES do return {kind = .Entropy_Unavailable}
	return {}
}

prekey_generate_append :: proc(store: ^Prekey_Store, count: int) {
	for _ in 0 ..< count {
		key := &store.keys[store.count]
		key.id = store.next_id
		crypto.rand_bytes(key.private[:])
		key.private[0] &= 248
		key.private[31] = key.private[31] & 127 | 64
		key.public = signal_curve_public(key.private)
		key.status = .Unpublished
		store.count += 1
		store.next_id += 1
	}
}

prekey_request_id_valid :: proc(id: string) -> bool {
	if len(id) < 1 || len(id) > MAX_PREKEY_REQUEST_ID_SIZE {
		return false
	}

	for c in id {
		if c < 33 || c > 126 || c == '@' do return false

	}
	return true
}

prekey_set_request_id :: proc(
	store: ^Prekey_Store,
	request_id: string,
) {
	// Retry callers may borrow the current request ID directly from this store.
	copy_of_id: [MAX_PREKEY_REQUEST_ID_SIZE]u8
	size := copy(copy_of_id[:], transmute([]u8)request_id)
	crypto.zero_explicit(
		&store.pending_request_id,
		size_of(store.pending_request_id),
	)
	store.pending_request_id_size = copy(
		store.pending_request_id[:],
		copy_of_id[:size],
	)
}

prekey_response_validate :: proc(
	response: Binary_Node,
	request_id: string,
) -> Prekey_Error {
	if !prekey_request_id_valid(request_id) {
		return {kind = .Invalid_Request_ID}
	}

	id, has_id := node_attr(response, "id")
	if response.tag != "iq" || !has_id || id != request_id {
		return {kind = .Response_Mismatch}
	}

	from, has_from := node_attr(response, "from")
	if has_from &&
	   !slice.contains(
			   []type_of(from){"s.whatsapp.net", PREKEY_SERVER_JID},
			   from,
		   ) {
		return {kind = .Response_Mismatch}
	}

	type, has_type := node_attr(response, "type")
	error_child := node_child(response, "error")
	if type == "error" || error_child != nil {
		code: u32
		if error_child != nil {
			text, found := node_attr(error_child^, "code")
			if found {
				parsed, valid := strconv.parse_uint(text, 10)
				if valid && parsed <= cast(uint)max(u32) {
					code = cast(u32)parsed
				}

			}

		}

		return {kind = .Server_Rejected, server_code = code}
	}

	if !has_type || type != "result" {
		return {kind = .Invalid_Response}
	}

	return {}
}

prekey_id_bytes :: proc(id: u32) -> [3]u8 {
	return {cast(u8)(id >> 16), cast(u8)(id >> 8), cast(u8)id}
}

prekey_put_uint :: proc(dst: []u8, at: ^int, value: u64, size: int) {
	for i in 0 ..< size do dst[at^ + i] = cast(u8)(value >> cast(uint)((size - 1 - i) * 8))
	at^ += size
}

prekey_get_uint :: proc(src: []u8, at: ^int, size: int) -> u64 {
	value: u64
	for i in 0 ..< size do value = value << 8 | cast(u64)src[at^ + i]
	at^ += size
	return value
}

prekey_hash :: proc(src: []u8) -> [32]u8 {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, src)
	hash: [32]u8
	sha2.final(&ctx, hash[:])
	return hash
}

// Invoke only after an independently durable Signal-session/consumption
// transaction. Pending upload batches retain their contiguous IDs until ACK.
prekey_store_remove_consumed :: proc(
	store: ^Prekey_Store,
	id: u32,
) -> Prekey_Error {
	if e := prekey_store_validate(store); e.kind != .None {
		return e
	}

	for key, i in store.keys[:store.count] {
		if key.id != id do continue

		if key.status == .Pending {
			return {kind = .Pending_Upload_Exists}
		}

		if store.revision == max(u64) {
			return {kind = .Revision_Exhausted}
		}

		crypto.zero_explicit(
			&store.keys[i],
			size_of(One_Time_Prekey),
		)
		for j in i ..< store.count - 1 do store.keys[j] = store.keys[j + 1]
		store.count -= 1
		crypto.zero_explicit(
			&store.keys[store.count],
			size_of(One_Time_Prekey),
		)
		store.revision += 1
		return {}
	}
	return {}
}

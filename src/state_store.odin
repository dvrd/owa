package whatsapp

import "core:bytes"
import "core:crypto"
import "core:crypto/hash"
import "core:fmt"
import "core:io"
import endian "core:encoding/endian"
import "core:mem"
import "core:os"
import "core:path/filepath"

MAX_STATE_RECORDS :: 65536
MAX_STATE_RECORD_SIZE :: 1 << 20
MAX_STATE_STORE_SIZE :: 64 << 20
STATE_STORE_MAGIC :: cast(string)"ODWSTATE"

State_Record_Kind :: enum u8 {
	Session,
	Sender_Key,
	Identity,
	LID_Mapping,
	Consumed_Prekey,
	Outbound_Message,
	Processed_Message,
	Inbox_Message,
	Sender_Key_Membership,
	Outbound_Content,
	Retry_Count,
	Captured_Message,
	Contact_Name,
	Contact_Profile,
	Contact_Sync_Key,
	Contact_Index_MAC,
	Contact_Sync_State,
	Pending_Profile_History,
}
State_Record :: struct {
	kind: State_Record_Kind,
	name: string,
	data: []u8,
}
State_Store :: struct {
	initialized:                bool,
	requires_reload:            bool,
	identity:                   [32]u8,
	records:                    [dynamic]State_Record,
	revision, durable_revision: u64,
	allocator:                  mem.Allocator,
}
State_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Record,
	Identity_Mismatch,
	Revision_Exhausted,
	Limit_Exceeded,
	Allocation_Failed,
	Destination_Undersized,
	Invalid_Format,
	Checksum_Mismatch,
	Read_Failed,
	Write_Failed,
	Flush_Failed,
	Rename_Failed,
	Directory_Flush_Failed,
}
State_Error :: struct {
	kind:       State_Error_Kind,
	io:         os.Error,
	allocation: mem.Allocator_Error,
}

state_store_init :: proc(store: ^State_Store, identity: [32]u8, allocator := context.allocator) -> State_Error {
	if store == nil || store.initialized {
		return {kind = .Invalid_State}
	}

	local_identity := identity

	if crypto.is_zero_constant_time(local_identity[:]) == 1 {
		return {kind = .Identity_Mismatch}
	}

	store^ = {
		initialized = true,
		identity    = identity,
		revision    = 1,
		allocator   = allocator,
	}

	store.records = make([dynamic]State_Record, allocator)

	return {}
}
state_store_clear :: proc(store: ^State_Store) {
	if store == nil {
		return
	}

	if store.initialized {
		for record in store.records {
			crypto.zero_explicit(raw_data(record.data), len(record.data))
			delete(record.data, store.allocator)
			delete(record.name, store.allocator)
		}

		delete(store.records)
	}

	crypto.zero_explicit(store, size_of(State_Store))
}

// Returned bytes borrow the store until its next mutation/clear. Never mutate
// them: stage changes in a candidate, then set and save before exposing effects.
state_store_get :: proc(store: ^State_Store, kind: State_Record_Kind, name: string) -> ([]u8, bool) {
	record, found := state_store_find_record(store, kind, name)
	return record.data, found
}

state_store_find_record :: proc(store: ^State_Store, kind: State_Record_Kind, name: string) -> (State_Record, bool) {
	if store == nil || !store.initialized {
		return {}, false
	}

	for record in store.records {
		if record.kind == kind && record.name == name {
			return record, true
		}
	}

	return {}, false
}

state_store_delete :: proc(store: ^State_Store, kind: State_Record_Kind, name: string) -> State_Error {
	if store == nil || !store.initialized || store.requires_reload {
		return {kind = .Invalid_State}
	}

	if store.revision == max(u64) {
		return {kind = .Revision_Exhausted}
	}

	for record, i in store.records {
		if record.kind != kind || record.name != name {
			continue
		}

		crypto.zero_explicit(raw_data(record.data), len(record.data))
		delete(record.data, store.allocator)
		delete(record.name, store.allocator)
		ordered_remove(&store.records, i)
		store.revision += 1
		break
	}

	return {}
}

// Multiple set operations form one transaction when followed by save. A
// session snapshot and its consumed-prekey marker must be saved together.
// Until then, runtime code must neither ack plaintext nor send ciphertext.
state_store_set :: proc(store: ^State_Store, kind: State_Record_Kind, name: string, data: []u8) -> State_Error {
	if store == nil || !store.initialized || store.requires_reload {
		return {kind = .Invalid_State}
	}

	if !state_record_valid(kind, name, data) {
		return {kind = .Invalid_Record}
	}

	if store.revision == max(u64) {
		return {kind = .Revision_Exhausted}
	}

	index, index_error := state_store_find_upsert_index(store, kind, name, data)
	if index_error.kind != .None {
		return index_error
	}

	value, alloc_err := make([]u8, len(data), store.allocator)

	if alloc_err != nil {
		return {kind = .Allocation_Failed, allocation = alloc_err}
	}

	copy(value, data)

	if index >= 0 {
		old := store.records[index].data
		store.records[index].data = value
		crypto.zero_explicit(raw_data(old), len(old))
		delete(old, store.allocator)
	} else {
		key, key_err := make([]u8, len(name), store.allocator)

		if key_err != nil {
			crypto.zero_explicit(raw_data(value), len(value))
			delete(value, store.allocator)
			return {kind = .Allocation_Failed, allocation = key_err}
		}

		copy(key, transmute([]u8)name)
		_, append_err := append(&store.records, State_Record{kind, cast(string)key, value})

		if append_err != nil {
			crypto.zero_explicit(raw_data(value), len(value))
			delete(value, store.allocator)
			delete(key, store.allocator)
			return {kind = .Allocation_Failed, allocation = append_err}
		}
	}

	store.revision += 1

	return {}
}

state_store_find_upsert_index :: proc(
	store: ^State_Store,
	kind: State_Record_Kind,
	name: string,
	data: []u8,
) -> (
	int,
	State_Error,
) {
	index := -1
	total := 8 + 2 + 32 + 8 + 4 + 32
	for record, i in store.records {
		if record.kind == kind && record.name == name {
			index = i
		}

		total += 1 + 2 + 4 + len(record.name) + len(record.data)
	}
	if index < 0 && len(store.records) == MAX_STATE_RECORDS {
		return -1, {kind = .Limit_Exceeded}
	}

	if index >= 0 {
		total -= 1 + 2 + 4 + len(store.records[index].name) + len(store.records[index].data)
	}

	total += 1 + 2 + 4 + len(name) + len(data)
	if total > MAX_STATE_STORE_SIZE {
		return -1, {kind = .Limit_Exceeded}
	}

	return index, {}
}

state_store_encode :: proc(dst: []u8, store: ^State_Store) -> (int, State_Error) {
	if store == nil || !store.initialized || store.revision == 0 {
		return 0, {kind = .Invalid_State}
	}

	size := 8 + 2 + 32 + 8 + 4 + 32
	for record in store.records {
		size += 1 + 2 + 4 + len(record.name) + len(record.data)
	}

	if size > MAX_STATE_STORE_SIZE {
		return 0, {kind = .Limit_Exceeded}
	}

	if len(dst) < size {
		return size, {kind = .Destination_Undersized}
	}

	for record in store.records {
		if bytes.alias(dst[:size], record.data) || bytes.alias(dst[:size], transmute([]u8)record.name) {
			return 0, {kind = .Invalid_Record}
		}
	}

	at := copy(dst, transmute([]u8)STATE_STORE_MAGIC)
	endian.unchecked_put_u16be(dst[at:][:2], 1)
	at += 2
	at += copy(dst[at:], store.identity[:])
	endian.unchecked_put_u64be(dst[at:][:8], store.revision)
	at += 8
	endian.unchecked_put_u32be(dst[at:][:4], u32(len(store.records)))
	at += 4

	for record in store.records {
		dst[at] = u8(record.kind)
		at += 1
		endian.unchecked_put_u16be(dst[at:][:2], u16(len(record.name)))
		at += 2
		endian.unchecked_put_u32be(dst[at:][:4], u32(len(record.data)))
		at += 4
		at += copy(dst[at:], transmute([]u8)record.name)
		at += copy(dst[at:], record.data)
	}

	hash := sha256(dst[:at])
	copy(dst[at:], hash[:])

	return size, {}
}

// Copy records directly rather than encoding and reparsing the whole store.
// The source owns all borrowed inputs until the complete replacement succeeds.
state_store_clone :: proc(destination, source: ^State_Store, allocator := context.allocator) -> State_Error {
	if destination == nil ||
	   source == nil ||
	   !source.initialized || source.requires_reload ||
	   source.revision == 0 ||
	   source.durable_revision > source.revision {
		return {kind = .Invalid_State}
	}

	if destination == source {
		return {}
	}

	if len(source.records) > MAX_STATE_RECORDS {
		return {kind = .Limit_Exceeded}
	}

	next: State_Store
	defer state_store_clear(&next)

	if error := state_store_init(&next, source.identity, allocator); error.kind != .None {
		return error
	}

	seen, allocation := make(map[State_Record_Key]bool, len(source.records), allocator)

	if allocation != nil {
		return {kind = .Allocation_Failed, allocation = allocation}
	}

	defer delete(seen)
	encoded_size := STATE_STORE_HEADER_SIZE + 32

	for record in source.records {
		if !state_record_valid(record.kind, record.name, record.data) {
			return {kind = .Invalid_Record}
		}

		key := State_Record_Key{record.kind, record.name}

		if seen[key] {
			return {kind = .Invalid_Record}
		}

		seen[key] = true
		record_size := 7 + len(record.name) + len(record.data)

		if record_size > MAX_STATE_STORE_SIZE - encoded_size {
			return {kind = .Limit_Exceeded}
		}

		encoded_size += record_size

		if error := state_store_append_owned(&next, record); error.kind != .None {
			return error
		}
	}

	next.revision, next.durable_revision = source.revision, source.durable_revision
	state_store_clear(destination)
	destination^ = next
	next = {}

	return {}
}

STATE_STORE_HEADER_SIZE :: 8 + 2 + 32 + 8 + 4
State_Record_Key :: struct {
	kind: State_Record_Kind,
	name: string,
}

// Caller has validated uniqueness and aggregate bounds. Each append owns its
// name/data, and partial allocation failures leave the candidate unchanged.
state_store_append_owned :: proc(store: ^State_Store, source: State_Record) -> State_Error {
	assert(store != nil)
	assert(store.initialized)
	data, allocation := make([]u8, len(source.data), store.allocator)

	if allocation != nil {
		return {kind = .Allocation_Failed, allocation = allocation}
	}

	copy(data, source.data)
	name, name_error := make([]u8, len(source.name), store.allocator)

	if name_error != nil {
		crypto.zero_explicit(raw_data(data), len(data))
		delete(data, store.allocator)
		return {kind = .Allocation_Failed, allocation = name_error}
	}

	copy(name, transmute([]u8)source.name)
	if _, append_error := append(&store.records, State_Record{source.kind, cast(string)name, data});
	   append_error != nil {
		crypto.zero_explicit(raw_data(data), len(data))
		delete(data, store.allocator)
		delete(name, store.allocator)
		return {kind = .Allocation_Failed, allocation = append_error}
	}

	return {}
}

// Validate framing/checksum before any record allocations or live replacement.
state_store_decode_header :: proc(source: []u8, identity: [32]u8) -> (revision: u64, count: int, error: State_Error) {
	if len(source) < STATE_STORE_HEADER_SIZE + 32 || len(source) > MAX_STATE_STORE_SIZE {
		return 0, 0, {kind = .Invalid_Format}
	}

	if !bytes.equal(source[:8], transmute([]u8)STATE_STORE_MAGIC) {
		return 0, 0, {kind = .Invalid_Format}
	}

	digest := sha256(source[:len(source) - 32])

	if crypto.compare_constant_time(digest[:], source[len(source) - 32:]) != 1 {
		return 0, 0, {kind = .Checksum_Mismatch}
	}

	position := 8

	version := endian.unchecked_get_u16be(source[position:][:2])
	position += 2
	if version != 1 {
		return 0, 0, {kind = .Invalid_Format}
	}

	local_identity := identity

	if crypto.compare_constant_time(source[position:][:32], local_identity[:]) != 1 {
		return 0, 0, {kind = .Identity_Mismatch}
	}

	position += 32
	revision = endian.unchecked_get_u64be(source[position:][:8])
	position += 8
	record_count := endian.unchecked_get_u32be(source[position:][:4])
	position += 4

	if revision == 0 || record_count > MAX_STATE_RECORDS {
		return 0, 0, {kind = .Invalid_Format}
	}

	assert(position == STATE_STORE_HEADER_SIZE)

	return revision, cast(int)record_count, {}
}

state_store_decode_records :: proc(store: ^State_Store, source: []u8, count: int) -> State_Error {
	assert(count >= 0)
	assert(count <= MAX_STATE_RECORDS)
	seen, allocation := make(map[State_Record_Key]bool, count, store.allocator)

	if allocation != nil {
		return {kind = .Allocation_Failed, allocation = allocation}
	}

	defer delete(seen)
	position, end := STATE_STORE_HEADER_SIZE, len(source) - 32

	for _ in 0 ..< count {
		if end - position < 7 {
			return {kind = .Invalid_Format}
		}

		kind := cast(State_Record_Kind)source[position]
		position += 1
		name_size := cast(int)endian.unchecked_get_u16be(source[position:][:2])
		position += 2
		data_size := cast(int)endian.unchecked_get_u32be(source[position:][:4])
		position += 4

		if name_size > 512 || data_size > MAX_STATE_RECORD_SIZE || name_size + data_size > end - position {
			return {kind = .Invalid_Format}
		}

		name := cast(string)source[position:][:name_size]
		position += name_size
		data := source[position:][:data_size]
		position += data_size

		if !state_record_valid(kind, name, data) {
			return {kind = .Invalid_Record}
		}

		key := State_Record_Key{kind, name}

		if seen[key] {
			return {kind = .Invalid_Format}
		}

		seen[key] = true

		if error := state_store_append_owned(store, {kind, name, data}); error.kind != .None {
			return error
		}
	}

	if position != end {
		return {kind = .Invalid_Format}
	}

	return {}
}

// Replace the live store only after the entire bounded snapshot validates.
// Disk checksums detect damage; they do not authenticate or encrypt the file.
state_store_decode :: proc(
	store: ^State_Store,
	source: []u8,
	identity: [32]u8,
	allocator := context.allocator,
) -> State_Error {
	if store == nil {
		return {kind = .Invalid_State}
	}
	revision, count, error := state_store_decode_header(source, identity)
	if error.kind != .None {
		return error
	}
	next: State_Store
	defer state_store_clear(&next)
	if init_error := state_store_init(&next, identity, allocator); init_error.kind != .None {
		return init_error
	}
	if record_error := state_store_decode_records(&next, source, count); record_error.kind != .None {
		return record_error
	}
	next.revision = revision
	state_store_clear(store)
	store^ = next
	next = {}
	return {}
}

state_store_save :: proc(store: ^State_Store, path: string, create_only := false) -> State_Error {
	if store != nil && store.requires_reload { return {kind = .Directory_Flush_Failed} }
	size, measured := state_store_encode(nil, store)

	if measured.kind != .Destination_Undersized {
		return measured
	}

	buffer, allocation_err := make([]u8, size)

	if allocation_err != nil {
		return {kind = .Allocation_Failed, allocation = allocation_err}
	}

	defer {
		crypto.zero_explicit(raw_data(buffer), len(buffer))
		delete(buffer)
	}

	_, encoded := state_store_encode(buffer, store)
	if encoded.kind != .None {
		return encoded
	}

	if write_error := state_atomic_write(path, buffer, create_only); write_error.kind != .None {
		store.requires_reload = write_error.kind == .Directory_Flush_Failed
		return write_error
	}

	store.durable_revision = store.revision

	return {}
}

// Replace the file using a synced temporary file and sync its directory.
// Report the failing step as a State_Error.
state_atomic_write :: proc(path: string, data: []u8, create_only := false) -> State_Error {
	step, io_error := replace_file_durably(path, data, create_only)

	if step == .None {
		return {}
	}

	kinds := [Durable_Write_Step]State_Error_Kind {
		.None      = .None,
		.Write     = .Write_Failed,
		.Flush     = .Flush_Failed,
		.Close     = .Write_Failed,
		.Rename    = .Rename_Failed,
		.Directory = .Directory_Flush_Failed,
	}

	return {kind = kinds[step], io = io_error}
}

state_store_load :: proc(store: ^State_Store, path: string, identity: [32]u8) -> State_Error {
	file, err := os.open(path)
	if err != nil {
		return {kind = .Read_Failed, io = err}
	}

	defer os.close(file)
	size, stat_err := os.file_size(file)

	if stat_err != nil {
		return {kind = .Read_Failed, io = stat_err}
	}

	if size < 0 || size > MAX_STATE_STORE_SIZE {
		return {kind = .Limit_Exceeded}
	}

	buffer, alloc_err := make([]u8, cast(int)size + 1)

	if alloc_err != nil {
		return {kind = .Allocation_Failed, allocation = alloc_err}
	}

	defer {
		crypto.zero_explicit(raw_data(buffer), len(buffer))
		delete(buffer)
	}

	used, read_err := read_file_into_bounded_buffer(file, buffer)

	if read_err != nil {
		return {kind = .Read_Failed, io = read_err}
	}

	// A previous rename succeeded but the directory entry was not confirmed.
	// Establish durability before adopting the visible file as the new baseline.
	if store != nil && store.requires_reload {
		parent, open_error := os.open(filepath.dir(path))
		if open_error != nil { return {kind = .Directory_Flush_Failed, io = open_error} }
		defer os.close(parent)
		if flush_error := os.flush(parent); flush_error != nil {
			return {kind = .Directory_Flush_Failed, io = flush_error}
		}
	}
	if err := state_store_decode(store, buffer[:used], identity); err.kind != .None {
		return err
	}

	store.durable_revision = store.revision

	return {}
}

state_record_valid :: proc(kind: State_Record_Kind, name: string, data: []u8) -> bool {
	if cast(u8)kind > cast(u8)State_Record_Kind.Pending_Profile_History ||
	   len(name) == 0 ||
	   len(name) > 512 ||
	   len(data) > MAX_STATE_RECORD_SIZE {
		return false
	}

	for c in name {
		if c < 33 || c > 126 {
			return false
		}
	}

	#partial switch kind {
	case .Contact_Name:
		contact, ok := decode_saved_contact(name, data)
		return ok && device_user_jid_valid(name, false) && contact_name_valid(contact.full_name) &&
			contact_name_valid(contact.first_name) && (contact.alternate_jid == "" || device_user_jid_valid(contact.alternate_jid, false))
	case .Contact_Profile:
		return device_user_jid_valid(name, false) && contact_name_valid(string(data))
	case .Contact_Index_MAC, .Contact_Sync_Key:
		if len(data) != 32 || len(name) > 256 || len(name) % 2 != 0 ||
		   (kind == .Contact_Index_MAC && len(name) != 64) { return false }
		for c in name {
			if !is_digit(c) && (c < 'a' || c > 'f') { return false }
		}
	case .Contact_Sync_State:
		switch name {
		case "contacts-key-id": return len(data) > 0 && len(data) <= 128
		case "ready": return len(data) == 1 && data[0] == 1
		case "cursor", "contacts-cursor": return len(data) == 136
		case "required-version", "server-version": return len(data) == 8
		case: return false
		}
	}

	return true
}
Durable_Write_Step :: enum {
	None,
	Write,
	Flush,
	Close,
	Rename,
	Directory,
}

// Exclusive temporary file, mode 0600, full write+fsync, atomic rename, then
// directory fsync: flushing the file protects its contents, but the directory
// entry must be durable too. Reports the step that failed. Serialize writers;
// this is a local single-process store, not a multi-writer database.
replace_file_durably :: proc(path: string, data: []u8, create_only := false) -> (Durable_Write_Step, os.Error) {
	random: [8]u8
	crypto.rand_bytes(random[:])
	tmp := fmt.aprintf("%s.tmp-%016x", path, transmute(u64)random)
	defer delete(tmp)
	file, open_err := os.open(tmp, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
	if open_err != nil {
		return .Write, open_err
	}

	closed, renamed := false, false
	defer {
		if !closed {
			os.close(file)
		}

		if !renamed {
			os.remove(tmp)
		}
	}

	at := 0

	for at < len(data) {
		n, err := os.write(file, data[at:])
		at += n
		if err != nil || n == 0 {
			return .Write, err
		}
	}

	if err := os.flush(file); err != nil {
		return .Flush, err
	}

	close_err := os.close(file)
	closed = true
	if close_err != nil {
		return .Close, close_err
	}

	if create_only {
		// Publish the flushed inode only if the destination is still absent.
		if err := os.link(tmp, path); err != nil {return .Rename, err}
		if err := os.remove(tmp); err != nil {return .Directory, err}
	} else if err := os.rename(tmp, path); err != nil {
		return .Rename, err
	}
	renamed = true
	parent, parent_err := os.open(filepath.dir(path))
	if parent_err != nil {
		return .Directory, parent_err
	}

	defer os.close(parent)
	if err := os.flush(parent); err != nil {
		return .Directory, err
	}

	return .None, nil
}

// Reads until EOF or a full buffer. Callers size the buffer one byte past
// their limit so an oversized file is detected instead of truncated.
read_file_into_bounded_buffer :: proc(file: ^os.File, buffer: []u8) -> (used: int, err: os.Error) {
	for used < len(buffer) {
		n, read_err := os.read(file, buffer[used:])
		used += n
		if read_err == io.Error.EOF {
			break
		}

		if read_err != nil {
			return used, read_err
		}

		if n == 0 {
			break
		}
	}

	return used, nil
}

sha256 :: proc(src: []u8) -> [32]u8 {
	digest: [32]u8
	hash.hash_bytes_to_buffer(.SHA256, src, digest[:])
	return digest
}

// Build a v0.2.0–v0.2.2 snapshot for an offline handoff. The source remains
// authoritative until the caller transfers ownership to the older process.
state_store_export_v0_2 :: proc(source: ^State_Store, path: string) -> (deferred_profiles: int, error: State_Error) {
	if source == nil || !source.initialized || source.revision != source.durable_revision {
		return 0, {kind = .Invalid_State}
	}
	exported: State_Store
	defer state_store_clear(&exported)
	if e := state_store_clone(&exported, source); e.kind != .None {return 0, e}
	for record in source.records {
		#partial switch record.kind {
		case .Contact_Sync_State:
			legacy_name: string
			switch record.name {
			case "contacts-cursor": legacy_name = "cursor"
			case "server-version": legacy_name = "required-version"
			case "contacts-key-id": // This transient key hint has no v0.2 representation.
			case "ready", "cursor", "required-version": continue
			case: return 0, {kind = .Invalid_Record}
			}
			if e := state_store_delete(&exported, record.kind, record.name); e.kind != .None {return 0, e}
			if legacy_name != "" {
				if e := state_store_set(&exported, record.kind, legacy_name, record.data); e.kind != .None {return 0, e}
			}
		case .Pending_Profile_History:
			// Older clients cannot import deferred profile names. The original
			// snapshot retains the references and all previously imported names.
			if e := state_store_delete(&exported, record.kind, record.name); e.kind != .None {return 0, e}
			deferred_profiles += 1
		case .Processed_Message:
			if processed_history_receipt(record.data) {
				if e := state_store_set(&exported, record.kind, record.name, record.data[:8]); e.kind != .None {return 0, e}
			}
		}
		if record.kind > .Pending_Profile_History {return 0, {kind = .Invalid_Record}}
	}
	return deferred_profiles, state_store_save(&exported, path, create_only = true)
}

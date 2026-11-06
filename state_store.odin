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
}
State_Record :: struct {
	kind: State_Record_Kind,
	name: string,
	data: []u8,
}
State_Store :: struct {
	initialized:                bool,
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
}
State_Error :: struct {
	kind:       State_Error_Kind,
	io:         os.Error,
	allocation: mem.Allocator_Error,
}

state_store_init :: proc(
	store: ^State_Store,
	identity: [32]u8,
	allocator := context.allocator,
) -> State_Error {
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
	if store == nil do return

	if store.initialized {
		for record in store.records {
			crypto.zero_explicit(
				raw_data(record.data),
				len(record.data),
			)
			delete(record.data, store.allocator)
			delete(record.name, store.allocator)
		}
		delete(store.records)
	}

	crypto.zero_explicit(store, size_of(State_Store))
}

// Returned bytes borrow the store until its next mutation/clear. Never mutate
// them: stage changes in a candidate, then set and save before exposing effects.
state_store_get :: proc(
	store: ^State_Store,
	kind: State_Record_Kind,
	name: string,
) -> (
	[]u8,
	bool,
) {
	if store == nil || !store.initialized {
		return nil, false
	}

	for record in store.records do if record.kind == kind && record.name == name {
		return record.data, true
	}

	return nil, false
}

state_store_delete :: proc(
	store: ^State_Store,
	kind: State_Record_Kind,
	name: string,
) -> State_Error {
	if store == nil || !store.initialized {
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
state_store_set :: proc(
	store: ^State_Store,
	kind: State_Record_Kind,
	name: string,
	data: []u8,
) -> State_Error {
	if store == nil || !store.initialized {
		return {kind = .Invalid_State}
	}

	if !state_record_valid(kind, name, data) {
		return {kind = .Invalid_Record}
	}

	if store.revision == max(u64) {
		return {kind = .Revision_Exhausted}
	}

	index, index_error := state_store_set_index(store, kind, name, data)
	if index_error.kind != .None do return index_error

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
		_, append_err := append(
			&store.records,
			State_Record{kind, cast(string)key, value},
		)
		if append_err != nil {
			crypto.zero_explicit(raw_data(value), len(value))
			delete(value, store.allocator)
			delete(key, store.allocator)
			return {
				kind = .Allocation_Failed,
				allocation = append_err,
			}
		}

	}

	store.revision += 1
	return {}
}

state_store_set_index :: proc(
	store: ^State_Store, kind: State_Record_Kind, name: string, data: []u8,
) -> (int, State_Error) {
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
		total -=
			1 +
			2 +
			4 +
			len(store.records[index].name) +
			len(store.records[index].data)
	}

	total += 1 + 2 + 4 + len(name) + len(data)
	if total > MAX_STATE_STORE_SIZE {
		return -1, {kind = .Limit_Exceeded}
	}

	return index, {}
}

state_store_encode :: proc(
	dst: []u8,
	store: ^State_Store,
) -> (
	int,
	State_Error,
) {
	if store == nil || !store.initialized || store.revision == 0 {
		return 0, {kind = .Invalid_State}
	}

	size := 8 + 2 + 32 + 8 + 4 + 32
	for record in store.records do size += 1 + 2 + 4 + len(record.name) + len(record.data)
	if size > MAX_STATE_STORE_SIZE {
		return 0, {kind = .Limit_Exceeded}
	}

	if len(dst) < size {
		return size, {kind = .Destination_Undersized}
	}

	for record in store.records {
		if bytes.alias(dst[:size], record.data) ||
		   bytes.alias(dst[:size], transmute([]u8)record.name) {
			return 0, {kind = .Invalid_Record}
		}

	}
	at := copy(dst, transmute([]u8)STATE_STORE_MAGIC)
	state_put(dst, &at, 1, 2)
	at += copy(dst[at:], store.identity[:])
	state_put(dst, &at, store.revision, 8)
	state_put(dst, &at, cast(u64)len(store.records), 4)
	for record in store.records {
		state_put(dst, &at, cast(u64)record.kind, 1)
		state_put(dst, &at, cast(u64)len(record.name), 2)
		state_put(dst, &at, cast(u64)len(record.data), 4)
		at += copy(dst[at:], transmute([]u8)record.name)
		at += copy(dst[at:], record.data)
	}
	hash := state_hash(dst[:at])
	copy(dst[at:], hash[:])
	return size, {}
}

// Copy records directly rather than encoding and reparsing the whole store.
// The source owns all borrowed inputs until the complete replacement succeeds.
state_store_clone :: proc(
	destination, source: ^State_Store,
	allocator := context.allocator,
) -> State_Error {
	if destination == nil || source == nil || !source.initialized ||
	   source.revision == 0 || source.durable_revision > source.revision {
		return {kind = .Invalid_State}
	}
	if destination == source {return {}}
	if len(source.records) > MAX_STATE_RECORDS {return {kind = .Limit_Exceeded}}
	next: State_Store
	defer state_store_clear(&next)
	if error := state_store_init(&next, source.identity, allocator); error.kind != .None {
		return error
	}
	seen, allocation := make(map[State_Record_Key]bool, len(source.records), allocator)
	if allocation != nil {return {kind = .Allocation_Failed, allocation = allocation}}
	defer delete(seen)
	encoded_size := STATE_STORE_HEADER_SIZE + 32
	for record in source.records {
		if !state_record_valid(record.kind, record.name, record.data) {
			return {kind = .Invalid_Record}
		}
		key := State_Record_Key{record.kind, record.name}
		if seen[key] {return {kind = .Invalid_Record}}
		seen[key] = true
		record_size := 7 + len(record.name) + len(record.data)
		if record_size > MAX_STATE_STORE_SIZE - encoded_size {
			return {kind = .Limit_Exceeded}
		}
		encoded_size += record_size
		if error := state_store_append_owned(&next, record); error.kind != .None {return error}
	}
	next.revision, next.durable_revision = source.revision, source.durable_revision
	state_store_clear(destination)
	destination^ = next
	next = {}
	return {}
}

STATE_STORE_HEADER_SIZE :: 8 + 2 + 32 + 8 + 4
State_Record_Key :: struct {kind: State_Record_Kind, name: string}

// Caller has validated uniqueness and aggregate bounds. Each append owns its
// name/data, and partial allocation failures leave the candidate unchanged.
state_store_append_owned :: proc(store: ^State_Store, source: State_Record) -> State_Error {
	assert(store != nil)
	assert(store.initialized)
	data, allocation := make([]u8, len(source.data), store.allocator)
	if allocation != nil {return {kind = .Allocation_Failed, allocation = allocation}}
	copy(data, source.data)
	name, name_error := make([]u8, len(source.name), store.allocator)
	if name_error != nil {
		crypto.zero_explicit(raw_data(data), len(data)); delete(data, store.allocator)
		return {kind = .Allocation_Failed, allocation = name_error}
	}
	copy(name, transmute([]u8)source.name)
	if _, append_error := append(&store.records, State_Record{source.kind, cast(string)name, data});
	   append_error != nil {
		crypto.zero_explicit(raw_data(data), len(data)); delete(data, store.allocator)
		delete(name, store.allocator)
		return {kind = .Allocation_Failed, allocation = append_error}
	}
	return {}
}

// Validate framing/checksum before any record allocations or live replacement.
state_store_decode_header :: proc(
	source: []u8,
	identity: [32]u8,
) -> (revision: u64, count: int, error: State_Error) {
	if len(source) < STATE_STORE_HEADER_SIZE + 32 || len(source) > MAX_STATE_STORE_SIZE {
		return 0, 0, {kind = .Invalid_Format}
	}
	if !bytes.equal(source[:8], transmute([]u8)STATE_STORE_MAGIC) {
		return 0, 0, {kind = .Invalid_Format}
	}
	digest := state_hash(source[:len(source) - 32])
	if crypto.compare_constant_time(digest[:], source[len(source) - 32:]) != 1 {
		return 0, 0, {kind = .Checksum_Mismatch}
	}
	position := 8
	if state_get(source, &position, 2) != 1 {return 0, 0, {kind = .Invalid_Format}}
	local_identity := identity
	if crypto.compare_constant_time(source[position:][:32], local_identity[:]) != 1 {
		return 0, 0, {kind = .Identity_Mismatch}
	}
	position += 32
	revision = state_get(source, &position, 8)
	record_count := state_get(source, &position, 4)
	if revision == 0 || record_count > MAX_STATE_RECORDS {
		return 0, 0, {kind = .Invalid_Format}
	}
	assert(position == STATE_STORE_HEADER_SIZE)
	return revision, cast(int)record_count, {}
}

state_store_decode_records :: proc(
	store: ^State_Store,
	source: []u8,
	count: int,
) -> State_Error {
	assert(count >= 0)
	assert(count <= MAX_STATE_RECORDS)
	seen, allocation := make(map[State_Record_Key]bool, count, store.allocator)
	if allocation != nil {return {kind = .Allocation_Failed, allocation = allocation}}
	defer delete(seen)
	position, end := STATE_STORE_HEADER_SIZE, len(source) - 32
	for _ in 0..<count {
		if end - position < 7 {return {kind = .Invalid_Format}}
		kind := cast(State_Record_Kind)state_get(source, &position, 1)
		name_size := cast(int)state_get(source, &position, 2)
		data_size := cast(int)state_get(source, &position, 4)
		if name_size > 512 || data_size > MAX_STATE_RECORD_SIZE ||
		   name_size + data_size > end - position {
			return {kind = .Invalid_Format}
		}
		name := cast(string)source[position:][:name_size]
		position += name_size
		data := source[position:][:data_size]
		position += data_size
		if !state_record_valid(kind, name, data) {return {kind = .Invalid_Record}}
		key := State_Record_Key{kind, name}
		if seen[key] {return {kind = .Invalid_Format}}
		seen[key] = true
		if error := state_store_append_owned(store, {kind, name, data});
		   error.kind != .None {return error}
	}
	if position != end {return {kind = .Invalid_Format}}
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
	if store == nil {return {kind = .Invalid_State}}
	revision, count, error := state_store_decode_header(source, identity)
	if error.kind != .None {return error}
	next: State_Store
	defer state_store_clear(&next)
	if init_error := state_store_init(&next, identity, allocator);
	   init_error.kind != .None {return init_error}
	if record_error := state_store_decode_records(&next, source, count);
	   record_error.kind != .None {return record_error}
	next.revision = revision
	state_store_clear(store)
	store^ = next
	next = {}
	return {}
}

state_store_save :: proc(
	store: ^State_Store,
	path: string,
) -> State_Error {
	size, measured := state_store_encode(nil, store)
	if measured.kind != .Destination_Undersized {
		return measured
	}

	buffer, allocation_err := make([]u8, size)
	if allocation_err != nil {
		return {
			kind = .Allocation_Failed,
			allocation = allocation_err,
		}
	}

	defer {
		crypto.zero_explicit(raw_data(buffer), len(buffer))
		delete(buffer)
	}
	_, encoded := state_store_encode(buffer, store)
	if encoded.kind != .None do return encoded

	if err := state_atomic_write(path, buffer); err.kind != .None {
		return err
	}

	store.durable_revision = store.revision
	return {}
}
state_store_load :: proc(
	store: ^State_Store,
	path: string,
	identity: [32]u8,
) -> State_Error {
	file, err := os.open(path)
	if err != nil do return {kind = .Read_Failed, io = err}

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
	used := 0
	for used < len(buffer) {
		n, read_err := os.read(file, buffer[used:])
		used += n
		if !slice.contains(
			[]type_of(read_err){nil, io.Error.EOF},
			read_err,
		) {
			return {kind = .Read_Failed, io = read_err}
		}

		if n == 0 || read_err == io.Error.EOF do break

	}
	if err := state_store_decode(store, buffer[:used], identity);
	   err.kind != .None {
		return err
	}

	store.durable_revision = store.revision
	return {}
}

state_record_valid :: proc(
	kind: State_Record_Kind,
	name: string,
	data: []u8,
) -> bool {
	if cast(u8)kind > cast(u8)State_Record_Kind.Captured_Message ||
	   len(name) == 0 ||
	   len(name) > 512 ||
	   len(data) > MAX_STATE_RECORD_SIZE {
		return false
	}

	for c in name do if c < 33 || c > 126 do return false

	return true
}
state_atomic_write :: proc(path: string, data: []u8) -> State_Error {
	random: [8]u8
	crypto.rand_bytes(random[:])
	tmp := fmt.aprintf("%s.tmp-%016x", path, transmute(u64)random)
	defer delete(tmp)
	file, open_err := os.open(
		tmp,
		{.Write, .Create, .Excl},
		{.Read_User, .Write_User},
	)
	if open_err != nil {
		return {kind = .Write_Failed, io = open_err}
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
			return {kind = .Write_Failed, io = err}
		}

	}
	if err := os.flush(file); err != nil {
		return {kind = .Flush_Failed, io = err}
	}

	close_err := os.close(file)
	closed = true
	if close_err != nil {
		return {kind = .Write_Failed, io = close_err}
	}

	if err := os.rename(tmp, path); err != nil {
		return {kind = .Rename_Failed, io = err}
	}

	renamed = true
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
state_hash :: proc(src: []u8) -> [32]u8 {
	ctx: sha2.Context_256
	sha2.init_256(&ctx)
	sha2.update(&ctx, src)
	digest: [32]u8
	sha2.final(&ctx, digest[:])
	return digest
}
state_put :: proc(dst: []u8, at: ^int, value: u64, size: int) {
	for i in 0 ..< size do dst[at^ + i] = cast(u8)(value >> cast(uint)((size - 1 - i) * 8))
	at^ += size
}
state_get :: proc(src: []u8, at: ^int, size: int) -> u64 {
	value: u64
	for i in 0 ..< size do value = value << 8 | cast(u64)src[at^ + i]
	at^ += size
	return value
}

package main

import wa "../.."
import "core:crypto"
import "core:crypto/sha2"
import "core:encoding/hex"
import "core:fmt"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sync"
import "core:sys/posix"

Storage_Mode :: enum {Pair_New, Qualify_Resume}
Storage_Error :: enum {
 None, Invalid_Path, Already_Open, Directory_Unsafe, Ownership, Locked,
 Incomplete, Marker_Invalid, Store_Invalid, Scope_Mismatch, Outbox_Unsafe,
 Journal_Invalid, Intent_Mismatch, Limit, IO, Entropy, Allocation,
}
Storage_Marker :: struct {
 magic: [16]u8,
 identity, nonce: [32]u8,
 device, inode, owner: u64,
 complete: u64,
 checksum: [32]u8,
}
Journal_Status :: enum u8 {Prepared, Queued, Acknowledged}
Storage_Intent :: struct {
 status: Journal_Status,
 kind: [32]u8,
 fingerprint: [128]u8,
 id: [64]u8,
 kind_size, fingerprint_size, id_size: u32,
}
Storage_Journal :: struct {
 magic: [16]u8,
 nonce: [32]u8,
 subject: [512]u8,
 target: [128]u8,
 subject_size, target_size, count: u32,
 intents: [8]Storage_Intent,
 checksum: [32]u8,
}
Storage :: struct {
 auth: wa.Auth_State,
 prekeys: wa.Prekey_Store,
 state: wa.State_Store,
 directory, auth_path, prekey_path, state_path: string,
 target_subject, target_jid: string,
 marker: Storage_Marker,
 journal: Storage_Journal,
 directory_fd, lock_fd: posix.FD,
 opened: bool,
}
// lockf is process-owned; this tool also refuses a second in-process owner.
storage_mutex: sync.Mutex
storage_owner: ^Storage
STORAGE_MARKER_MAGIC :: "ODWA-LIVE-406-v1"
STORAGE_JOURNAL_MAGIC :: "ODWA-SCOPE406-v1"

storage_path :: proc(directory, name: string) -> string {
 return fmt.aprintf("%s/%s", directory, name)
}

storage_safe_stat :: proc(info: posix.stat_t, directory: bool) -> bool {
 expected := directory ? posix.S_IFDIR : posix.S_IFREG
 permissions := directory ? posix.mode_t{.IRUSR, .IWUSR, .IXUSR} :
  posix.mode_t{.IRUSR, .IWUSR}
 return info.st_mode & posix.S_IFMT == expected &&
  info.st_mode & transmute(posix.mode_t)posix._mode_t(0o7777) == permissions && info.st_uid == posix.geteuid()
}

storage_cpath :: proc(path: string) -> cstring {
 return strings.clone_to_cstring(path)
}

storage_directory_path :: proc(input: string) -> (string, Storage_Error) {
 if !filepath.is_abs(input) || strings.contains(input, "\x00") {return "", .Invalid_Path}
 // Darwin abs resolves the full path, but fresh session leaves do not exist.
 // Clean lexically and resolve only the existing parent before creating a leaf.
 absolute, error := filepath.clean(input)
 if error != nil {return "", .Invalid_Path}
 defer delete(absolute)
 parent := storage_cpath(filepath.dir(absolute)); defer delete(parent)
 resolved: [4096]u8
 if posix.realpath(parent, raw_data(resolved[:])) == nil {return "", .Invalid_Path}
 canonical := fmt.aprintf("%s/%s", string(cstring(raw_data(resolved[:]))), filepath.base(absolute))
 // Never place private generated sessions beneath any Git checkout/worktree.
 ancestor := canonical
 for depth := 0; depth < 128; depth += 1 {
  git := storage_path(ancestor, ".git")
  exists := os.exists(git); delete(git)
  if exists {delete(canonical); return "", .Directory_Unsafe}
  if ancestor == "/" || ancestor == "." {return canonical, .None}
  ancestor = filepath.dir(ancestor)
 }
 delete(canonical); return "", .Invalid_Path
}

storage_file_check :: proc(s: ^Storage, name: string) -> Storage_Error {
 info: posix.stat_t
 path := storage_cpath(name); defer delete(path)
 if posix.fstatat(s.directory_fd, path, &info, {.SYMLINK_NOFOLLOW}) != .OK {return .Incomplete}
 if !storage_safe_stat(info, false) || info.st_nlink != 1 {return .Ownership}
 return .None
}

storage_read :: proc(s: ^Storage, name: string, destination: []u8) -> Storage_Error {
 if e := storage_file_check(s, name); e != .None {return e}
 path := storage_cpath(name); defer delete(path)
 fd := posix.openat(s.directory_fd, path, {.NOFOLLOW, .CLOEXEC})
 if fd == -1 {return .IO}; defer posix.close(fd)
 used := 0
 for used < len(destination) {
  n := posix.read(fd, raw_data(destination[used:]), uint(len(destination)) - uint(used))
  if n <= 0 {return .Incomplete}; used += int(n)
 }
 extra: u8
 if posix.read(fd, &extra, 1) != 0 {return .Journal_Invalid}
 return .None
}

storage_write :: proc(s: ^Storage, name: string, data: []u8) -> Storage_Error {
 temporary_name := fmt.aprintf("%s.next", name); defer delete(temporary_name)
 temporary := storage_cpath(temporary_name); defer delete(temporary)
 target := storage_cpath(name); defer delete(target)
 fd := posix.openat(s.directory_fd, temporary, {.WRONLY, .CREAT, .EXCL, .NOFOLLOW, .CLOEXEC},
  {.IRUSR, .IWUSR})
 if fd == -1 {return .IO}
 closed, renamed := false, false
 defer {
  if !closed {posix.close(fd)}
  if !renamed {posix.unlinkat(s.directory_fd, temporary, {})}
 }
 used := 0
 for used < len(data) {
  n := posix.write(fd, raw_data(data[used:]), uint(len(data)) - uint(used))
  if n <= 0 {return .IO}; used += int(n)
 }
 if posix.fsync(fd) != .OK {return .IO}
 if posix.close(fd) != .OK {closed = true; return .IO}; closed = true
 if posix.renameat(s.directory_fd, temporary, s.directory_fd, target) != .OK {return .IO}
 renamed = true
 if posix.fsync(s.directory_fd) != .OK {return .IO}
 return .None
}

storage_lock :: proc(s: ^Storage) -> Storage_Error {
 s.lock_fd = posix.openat(s.directory_fd, "owner.lock", {.RDWR, .CREAT, .NOFOLLOW, .CLOEXEC},
  {.IRUSR, .IWUSR})
 if s.lock_fd == -1 {return .IO}
 if e := storage_file_check(s, "owner.lock"); e != .None {return e}
 if posix.lockf(s.lock_fd, .TLOCK, 0) != .OK {return .Locked}
 return .None
}

storage_open :: proc(s: ^Storage, directory: string, mode: Storage_Mode,
 subject: string) -> Storage_Error {
 sync.mutex_lock(&storage_mutex); defer sync.mutex_unlock(&storage_mutex)
 if s == nil {return .Invalid_Path}
 if storage_owner != nil || s.opened {return .Already_Open}
 if len(subject) == 0 || len(subject) > 512 {return .Limit}
 s.directory_fd, s.lock_fd = -1, -1
 resolved, path_error := storage_directory_path(directory)
 if path_error != .None {return path_error}
 s.directory = resolved
 successful := false
 defer {if !successful {storage_release(s)}}
 path := storage_cpath(resolved); defer delete(path)
 info: posix.stat_t
 fresh := posix.lstat(path, &info) != .OK
 if fresh {
  if mode != .Pair_New {return .Incomplete}
  if posix.mkdir(path, {.IRUSR, .IWUSR, .IXUSR}) != .OK {return .IO}
 } else if !storage_safe_stat(info, true) {return .Directory_Unsafe}
 s.directory_fd = posix.open(path, {.DIRECTORY, .NOFOLLOW, .CLOEXEC})
 if s.directory_fd == -1 {return .Directory_Unsafe}
 if posix.fstat(s.directory_fd, &info) != .OK || !storage_safe_stat(info, true) {return .Directory_Unsafe}
 // Existing unmarked directories are rejected without creating even a lockfile.
 if !fresh {if e := storage_marker_check(s); e != .None {return e}}
 if e := storage_lock(s); e != .None {return e}
 s.auth_path = storage_path(resolved, "auth.bin")
 s.prekey_path = storage_path(resolved, "prekeys.bin")
 s.state_path = storage_path(resolved, "state.bin")
 if fresh {
  if e := storage_create(s, subject); e != .None {return e}
 } else if e := storage_resume(s); e != .None {return e}
 if mode == .Pair_New && s.auth.credentials.registered {return .Scope_Mismatch}
 if mode == .Qualify_Resume && !s.auth.credentials.registered {return .Scope_Mismatch}
 if e := storage_scope_guard_offline(s, mode == .Pair_New, subject); e != .None {return e}
 s.opened = true; storage_owner = s; successful = true
 return .None
}

storage_create :: proc(s: ^Storage, subject: string) -> Storage_Error {
 if len(subject) == 0 || len(subject) > len(s.journal.subject) {return .Limit}
 credentials, generated := wa.device_credentials_generate()
 if generated != .None {return .Entropy}
 s.auth.credentials = credentials
 crypto.zero_explicit(&credentials, size_of(credentials))
 s.marker.identity = wa.signal_curve_public(s.auth.credentials.identity_private)
 copy(s.marker.magic[:], STORAGE_MARKER_MAGIC)
 crypto.rand_bytes(s.marker.nonce[:])
 info: posix.stat_t
 if posix.fstat(s.directory_fd, &info) != .OK {return .IO}
 s.marker.device, s.marker.inode, s.marker.owner = u64(info.st_dev), u64(info.st_ino), u64(info.st_uid)
 if e := storage_record_write(s, "generated-session.marker", &s.marker); e != .None {return e}
 if wa.prekey_store_init(&s.prekeys, &s.auth.credentials).kind != .None {return .Store_Invalid}
 if wa.state_store_init(&s.state, s.marker.identity).kind != .None {return .Store_Invalid}
 // Stores precede auth, and the complete marker is the final creation commit.
 if wa.prekey_store_save(s.prekey_path, &s.prekeys).kind != .None {return .IO}
 if wa.state_store_save(&s.state, s.state_path).kind != .None {return .IO}
 if wa.auth_state_save(s.auth_path, &s.auth).kind != .None {return .IO}
 copy(s.journal.magic[:], STORAGE_JOURNAL_MAGIC)
 s.journal.nonce = s.marker.nonce
 s.journal.subject_size = u32(copy(s.journal.subject[:], subject))
 if e := storage_record_write(s, "scope.journal", &s.journal); e != .None {return e}
 s.marker.complete = 1
 return storage_record_write(s, "generated-session.marker", &s.marker)
}

storage_marker_check :: proc(s: ^Storage) -> Storage_Error {
 if e := storage_read(s, "generated-session.marker", storage_bytes(&s.marker)); e != .None {return e}
 if string(s.marker.magic[:len(STORAGE_MARKER_MAGIC)]) != STORAGE_MARKER_MAGIC ||
  s.marker.complete != 1 || !storage_record_valid(&s.marker) {return .Marker_Invalid}
 info: posix.stat_t
 if posix.fstat(s.directory_fd, &info) != .OK {return .IO}
 if s.marker.device != u64(info.st_dev) || s.marker.inode != u64(info.st_ino) ||
  s.marker.owner != u64(posix.geteuid()) {return .Ownership}
 return .None
}

storage_resume :: proc(s: ^Storage) -> Storage_Error {
 if e := storage_marker_check(s); e != .None {return e}
 for name in ([]string{"auth.bin", "prekeys.bin", "state.bin"}) {
  if e := storage_file_check(s, name); e != .None {return e}
 }
 if wa.auth_state_load(s.auth_path, &s.auth).kind != .None {return .Store_Invalid}
 if wa.signal_curve_public(s.auth.credentials.identity_private) != s.marker.identity {return .Ownership}
 if wa.prekey_store_load(s.prekey_path, &s.prekeys, &s.auth.credentials).kind != .None {return .Store_Invalid}
 if wa.state_store_load(&s.state, s.state_path, s.marker.identity).kind != .None {return .Store_Invalid}
 if e := storage_read(s, "scope.journal", storage_bytes(&s.journal)); e != .None {return e}
 if !storage_record_valid(&s.journal) {return .Journal_Invalid}
 return storage_journal_validate(s)
}

storage_journal_validate :: proc(s: ^Storage) -> Storage_Error {
 j := &s.journal
 if string(j.magic[:len(STORAGE_JOURNAL_MAGIC)]) != STORAGE_JOURNAL_MAGIC ||
  j.nonce != s.marker.nonce || j.subject_size == 0 || j.subject_size > 512 ||
  j.target_size > 128 || j.count > 8 {return .Journal_Invalid}
 for index in 0..<int(j.count) {
  entry := &j.intents[index]
  if entry.kind_size == 0 || entry.kind_size > 32 || entry.fingerprint_size == 0 ||
   entry.fingerprint_size > 128 || entry.id_size != 32 ||
   u8(entry.status) > u8(Journal_Status.Acknowledged) {return .Journal_Invalid}
  for previous in 0..<index {
   if entry.kind == j.intents[previous].kind || entry.id == j.intents[previous].id {return .Journal_Invalid}
  }
 }
 s.target_subject = string(j.subject[:j.subject_size])
 s.target_jid = string(j.target[:j.target_size])
 return .None
}

storage_scope_guard_offline :: proc(s: ^Storage, pair: bool, subject: string) -> Storage_Error {
 if e := storage_journal_validate(s); e != .None {return e}
 if subject != s.target_subject {return .Scope_Mismatch}
 for record in s.state.records {
  if record.kind != .Outbound_Message && record.kind != .Outbound_Content {continue}
  if pair || s.target_jid == "" {return .Outbox_Unsafe}
  known := false
  for index in 0..<int(s.journal.count) {
   entry := &s.journal.intents[index]
   if record.name == string(entry.id[:entry.id_size]) {known = true; break}
  }
  if !known {return .Outbox_Unsafe}
  document, decoded := wa.binary_node_decode(record.data)
  if decoded.kind != .None {return .Outbox_Unsafe}
  matches, id_matches := false, record.kind == .Outbound_Content
  target_count := 0
  for attribute in document.root.attrs {
   if attribute.key == "to" {
    target_count += 1; matches = attribute.value == s.target_jid
   }
   if attribute.key == "id" && attribute.value == record.name {id_matches = true}
  }
  valid_tag := record.kind == .Outbound_Content ? document.root.tag == "saved" :
   document.root.tag == "message"
  wa.binary_document_destroy(&document)
  if !matches || target_count != 1 || !id_matches || !valid_tag {return .Outbox_Unsafe}
  if record.kind == .Outbound_Message {
   if _, found := wa.state_store_get(&s.state, .Outbound_Content, record.name); !found {return .Outbox_Unsafe}
  }
 }
 return .None
}

storage_scope_target :: proc(s: ^Storage, target_jid: string) -> Storage_Error {
 if !s.opened || target_jid == "" || len(target_jid) > 128 ||
  !strings.has_suffix(target_jid, "@g.us") {return .Scope_Mismatch}
 if s.target_jid != "" {return s.target_jid == target_jid ? .None : .Scope_Mismatch}
 candidate := s.journal
 candidate.target_size = u32(copy(candidate.target[:], target_jid))
 if e := storage_record_write(s, "scope.journal", &candidate); e != .None {return e}
 s.journal = candidate
 return storage_journal_validate(s)
}

storage_journal_prepare :: proc(s: ^Storage, kind, fingerprint: string) -> (string, Storage_Error) {
 if !s.opened || s.target_jid == "" {return "", .Scope_Mismatch}
 if len(kind) == 0 || len(kind) > 32 || len(fingerprint) == 0 || len(fingerprint) > 128 {
  return "", .Limit
 }
 for index in 0..<int(s.journal.count) {
  entry := &s.journal.intents[index]
  if string(entry.kind[:entry.kind_size]) != kind {continue}
  if string(entry.fingerprint[:entry.fingerprint_size]) != fingerprint {return "", .Intent_Mismatch}
  id, error := strings.clone(string(entry.id[:entry.id_size]))
  return id, error == nil ? .None : .Allocation
 }
 if s.journal.count == 8 {return "", .Limit}
 candidate := s.journal
 entry := &candidate.intents[candidate.count]
 entry.kind_size = u32(copy(entry.kind[:], kind))
 entry.fingerprint_size = u32(copy(entry.fingerprint[:], fingerprint))
 random: [16]u8; crypto.rand_bytes(random[:])
 encoded, allocation := hex.encode(random[:]);
 if allocation != nil {return "", .Allocation}
 defer delete(encoded)
 copy(entry.id[:32], encoded); entry.id_size = 32
 candidate.count += 1
 if e := storage_record_write(s, "scope.journal", &candidate); e != .None {return "", e}
 s.journal = candidate
 if e := storage_journal_validate(s); e != .None {return "", e}
 id, error := strings.clone(string(s.journal.intents[s.journal.count - 1].id[:32]))
 return id, error == nil ? .None : .Allocation
}

storage_release :: proc(s: ^Storage) {
 wa.state_store_clear(&s.state)
 wa.prekey_store_clear(&s.prekeys)
 wa.auth_state_clear(&s.auth)
 // Caller must have closed the socket: stores remain alive until that point.
 if s.lock_fd != -1 {posix.close(s.lock_fd)}
 if s.directory_fd != -1 {posix.close(s.directory_fd)}
 for path in ([]string{s.directory, s.auth_path, s.prekey_path, s.state_path}) {delete(path)}
 crypto.zero_explicit(s, size_of(Storage))
}

storage_close :: proc(s: ^Storage) {
 if s == nil {return}
 sync.mutex_lock(&storage_mutex); defer sync.mutex_unlock(&storage_mutex)
 if storage_owner != s {return}
 storage_owner = nil
 storage_release(s)
}

// Fixed-size versioned private records contain no pointers.
storage_bytes :: proc(value: ^$T) -> []u8 {
 return mem.slice_ptr(cast(^u8)value, size_of(T))
}

// Status reflects explicit observed actions, never an inference from absent wire.
storage_journal_status :: proc(s: ^Storage, kind, id: string) -> (Journal_Status, Storage_Error) {
 if !s.opened {return .Prepared, .Scope_Mismatch}
 for index in 0..<int(s.journal.count) {
  entry := &s.journal.intents[index]
  if string(entry.kind[:entry.kind_size]) != kind {continue}
  if string(entry.id[:entry.id_size]) != id {return .Prepared, .Intent_Mismatch}
  return entry.status, .None
 }
 return .Prepared, .Intent_Mismatch
}

// The runner may mark Acknowledged only after observing present→absent wire
// while pumping an authenticated ACK in this process. Resume absence proves none.
storage_journal_mark :: proc(s: ^Storage, kind, id: string, status: Journal_Status) -> Storage_Error {
 current, error := storage_journal_status(s, kind, id)
 if error != .None {return error}
 if u8(status) > u8(Journal_Status.Acknowledged) || status < current ||
  current == .Prepared && status == .Acknowledged {return .Intent_Mismatch}
 if current == status {return .None}
 candidate := s.journal
 for index in 0..<int(candidate.count) {
  entry := &candidate.intents[index]
  if string(entry.kind[:entry.kind_size]) == kind {entry.status = status; break}
 }
 if e := storage_record_write(s, "scope.journal", &candidate); e != .None {return e}
 s.journal = candidate
 return storage_journal_validate(s)
}

// Like native store checksums, these detect damage without claiming secrecy or
// authentication. Owner-only directory/files and the process lock govern access.
storage_digest :: proc(data: []u8) -> [32]u8 {
 ctx: sha2.Context_256
 sha2.init_256(&ctx); sha2.update(&ctx, data)
 result: [32]u8; sha2.final(&ctx, result[:]); return result
}

storage_record_valid :: proc(record: ^$T) -> bool {
 candidate := record^
 expected := candidate.checksum; candidate.checksum = {}
 return expected == storage_digest(storage_bytes(&candidate))
}

storage_record_write :: proc(s: ^Storage, name: string, record: ^$T) -> Storage_Error {
 record.checksum = {}
 record.checksum = storage_digest(storage_bytes(record))
 return storage_write(s, name, storage_bytes(record))
}

// Correct an unused test scope without replacing any generated session keys.
// Explicit old-subject opening has already proved ownership before this call.
storage_scope_retarget :: proc(s: ^Storage, new_subject: string) -> Storage_Error {
 sync.mutex_lock(&storage_mutex); defer sync.mutex_unlock(&storage_mutex)
 if s == nil || !s.opened || storage_owner != s {return .Ownership}
 if !subject_valid(new_subject) {return .Scope_Mismatch}
 if !storage_record_valid(&s.journal) {return .Journal_Invalid}
 if e := storage_journal_validate(s); e != .None {return e}
 if s.journal.count != 0 || s.journal.target_size != 0 {return .Scope_Mismatch}
 for record in s.state.records {
  if record.kind == .Outbound_Message || record.kind == .Outbound_Content {
   return .Outbox_Unsafe
  }
 }
 candidate := s.journal
 candidate.subject = {}
 candidate.subject_size = u32(copy(candidate.subject[:], new_subject))
 if e := storage_record_write(s, "scope.journal", &candidate); e != .None {return e}
 s.journal = candidate
 return storage_journal_validate(s)
}

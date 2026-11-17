package main

import wa "../.."
import "core:time"
import "core:bytes"
import "core:sys/posix"
import "core:fmt"
import "core:os"
import "core:crypto"
import "core:encoding/hex"

canary_enabled :: proc(options: Options) -> bool {
	return(
		options.command == .Watch &&
		options.send &&
		options.allow_scoped_retries &&
		options.canary_interval_seconds >= 3600 \
	)
}

canary_pending_authorized :: proc(s: ^Storage, id: string, options: Options) -> bool {
	if !canary_enabled(options) {
		return false
	}

	index, found := canary_find(s, id)

	return found && index >= int(s.canary.count) - 2 && s.canary.entries[index].intent.status == .Queued
}

canary_admission :: proc(options: Options, s: ^Storage) -> Tool_Error {
	if error := canary_ledger_validate(s); error != .None {
		return {kind = .Journal, storage = error}
	}

	if s.canary == nil {
		return {}
	}

	if canary_enabled(options) && s.canary.interval_seconds != i64(options.canary_interval_seconds) {
		return {kind = .Journal, storage = .Intent_Mismatch}
	}

	for index in 0 ..< int(s.canary.count) {
		entry := &s.canary.entries[index].intent
		expected := action_fingerprint_parts(
			action_metadata(index % 2 == 1),
			transmute([]u8)(index % 2 == 1 ? qualification_pdf : qualification_text),
		)

		if expected == "" {
			return {kind = .Allocation}
		}

		matches := expected == string(entry.fingerprint[:entry.fingerprint_size])
		delete(expected)

		if !matches {
			return {kind = .Journal, storage = .Intent_Mismatch}
		}

		id := string(entry.id[:32])
		_, pending := wa.state_store_get(&s.state, .Outbound_Message, id)
		_, retained := wa.state_store_get(&s.state, .Outbound_Content, id)

		if entry.status == .Prepared && (pending || retained) {
			return {kind = .Scope}
		}

		if entry.status != .Acknowledged && !canary_enabled(options) {
			return {kind = .Scope}
		}

		if entry.status == .Queued && !pending && !options.retry_unknown_canary {
			return {kind = .Canary_Unknown}
		}
	}

	return {}
}

canary_observe :: proc(runner: ^Runner) -> [2]bool {
	result: [2]bool
	ledger := runner.storage.canary

	if ledger == nil || ledger.count == 0 {
		return result
	}

	first := int(ledger.count) - 2

	for offset in 0 ..< 2 {
		entry := &ledger.entries[first + offset].intent

		if entry.status != .Queued {
			continue
		}

		_, result[offset] = wa.state_store_get(&runner.storage.state, .Outbound_Message, string(entry.id[:32]))
	}

	return result
}

// A successful native operation can consume a positive ACK while doing an IQ.
// Only a wire observed present BEFORE that operation can establish this witness.
canary_reconcile :: proc(runner: ^Runner, observed: [2]bool, now: i64) -> Tool_Error {
	ledger := runner.storage.canary

	if ledger == nil || ledger.count == 0 {
		return {}
	}

	first := int(ledger.count) - 2

	for offset in 0 ..< 2 {
		entry := &ledger.entries[first + offset].intent

		if !observed[offset] || entry.status != .Queued {
			continue
		}

		if _, pending := wa.state_store_get(&runner.storage.state, .Outbound_Message, string(entry.id[:32])); pending {
			continue
		}

		if error := canary_mark(&runner.storage, first + offset, .Acknowledged, now); error != .None {
			return {kind = .Journal, storage = error}
		}

		phase_print(offset == 0 ? .CANARY_TEXT_ACKED : .CANARY_PDF_ACKED)

		if offset == 1 {
			runner.canary_due_tick = time.tick_add(
				time.tick_now(),
				time.Duration(ledger.interval_seconds) * time.Second,
			)
			runner.canary_due_set = true
			runner.canary_completed += 1
			phase_print(.CANARY_COMPLETE)
			canary_status(runner)
		}
	}

	return {}
}

canary_has_unknown :: proc(s: ^Storage) -> bool {
	if s.canary == nil || s.canary.count < 2 {
		return false
	}

	for index in int(s.canary.count) - 2 ..< int(s.canary.count) {
		entry := &s.canary.entries[index].intent

		if entry.status != .Queued {
			continue
		}

		if _, pending := wa.state_store_get(&s.state, .Outbound_Message, string(entry.id[:32])); !pending {
			return true
		}
	}

	return false
}

canary_content_matches :: proc(s: ^Storage, index: int, node: wa.Binary_Node) -> bool {
	protobuf, valid := node.content.([]u8)

	if !valid || node.tag != "saved" {
		return false
	}

	media_type, _ := wa.node_attr(node, "mediatype")

	if index % 2 == 0 {
		if media_type != "" {
			return false
		}

		expected: [512]u8
		count, error := wa.text_message_encode(expected[:], {kind = .Conversation, text = qualification_text})
		return error == .None && bytes.equal(expected[:count], protobuf)
	}

	if media_type != "document" {
		return false
	}

	message, error := wa.media_message_decode(protobuf)

	if error.kind != .None || message.kind != .Document {
		return false
	}

	metadata, decoded := wa.media_metadata_from_message(message)
	defer wa.media_metadata_clear(&metadata)

	return(
		decoded.kind == .None &&
		message.caption == "Synthetic PDF transport check." &&
		message.mime_type == "application/pdf" &&
		message.file_name == "mesa-qualification.pdf" &&
		metadata.file_length == u64(len(qualification_pdf)) &&
		metadata.file_sha256 == storage_digest(transmute([]u8)qualification_pdf) \
	)
}

CANARY_MAGIC :: "ODWA-CANARY-v1"
CANARY_FILE :: "canary.ledger"
CANARY_CAPACITY :: 512
Canary_Entry :: struct {
	cycle:  u64,
	intent: Storage_Intent,
}
Canary_Ledger :: struct {
	magic:                                      [16]u8,
	identity, nonce:                            [32]u8,
	subject:                                    [512]u8,
	target:                                     [128]u8,
	subject_size, target_size, count:           u32,
	cycle:                                      u64,
	interval_seconds:                           i64,
	next_due, completed_at, first_completed_at: i64,
	entries:                                    [CANARY_CAPACITY]Canary_Entry,
	checksum:                                   [32]u8,
}

canary_ledger_load :: proc(s: ^Storage) -> Storage_Error {
	if error := canary_discard_temporary(s); error != .None {
		return error
	}

	path := storage_cpath(CANARY_FILE)
	defer delete(path)
	info: posix.stat_t

	if posix.fstatat(s.directory_fd, path, &info, {.SYMLINK_NOFOLLOW}) != .OK {
		return posix.errno() == .ENOENT ? .None : .IO
	}

	if !storage_safe_stat(info, false) {
		return .Directory_Unsafe
	}

	ledger, allocation := new(Canary_Ledger)

	if allocation != nil {
		return .Allocation
	}

	s.canary = ledger

	if error := storage_read(s, CANARY_FILE, storage_bytes(ledger)); error != .None {
		return error
	}

	return canary_ledger_validate(s)
}

canary_ledger_validate :: proc(s: ^Storage) -> Storage_Error {
	ledger := s.canary

	if ledger == nil {
		return .None
	}

	if !storage_record_valid(ledger) ||
	   string(ledger.magic[:len(CANARY_MAGIC)]) != CANARY_MAGIC ||
	   ledger.identity != s.marker.identity ||
	   ledger.nonce != s.marker.nonce ||
	   ledger.subject_size > 512 ||
	   ledger.target_size > 128 ||
	   ledger.count > CANARY_CAPACITY ||
	   ledger.count % 2 != 0 ||
	   ledger.interval_seconds < 3600 ||
	   ledger.interval_seconds > 86400 ||
	   ledger.completed_at < 0 ||
	   ledger.first_completed_at < 0 ||
	   ledger.next_due < 0 ||
	   ledger.first_completed_at > ledger.completed_at ||
	   ledger.completed_at > max(i64) - ledger.interval_seconds {
		return .Journal_Invalid
	}

	if string(ledger.subject[:ledger.subject_size]) != s.target_subject ||
	   string(ledger.target[:ledger.target_size]) != s.target_jid ||
	   s.target_jid == "" {
		return .Scope_Mismatch
	}

	if ledger.count == 0 {
		valid :=
			ledger.cycle == 0 && ledger.completed_at == 0 && ledger.next_due == 0 && ledger.first_completed_at == 0
		return valid ? .None : .Journal_Invalid
	}

	previous: u64

	for index in 0 ..< int(ledger.count) {
		record := &ledger.entries[index]
		entry := &record.intent
		kind := index % 2 == 0 ? "text" : "pdf"
		if entry.kind_size != u32(len(kind)) ||
		   string(entry.kind[:entry.kind_size]) != kind ||
		   entry.id_size != 32 ||
		   entry.fingerprint_size != 64 ||
		   u8(entry.status) > u8(Journal_Status.Acknowledged) ||
		   record.cycle == 0 ||
		   record.cycle > ledger.cycle {
			return .Journal_Invalid
		}

		if index % 2 == 0 {
			if record.cycle <= previous {
				return .Journal_Invalid
			}; previous = record.cycle
		} else if record.cycle != previous {
			return .Journal_Invalid
		}

		if record.cycle < ledger.cycle && entry.status != .Acknowledged {
			return .Journal_Invalid
		}

		id := string(entry.id[:entry.id_size])

		for old in 0 ..< index {
			if id == string(ledger.entries[old].intent.id[:32]) {
				return .Journal_Invalid
			}
		}

		for old in 0 ..< int(s.journal.count) {
			if id == string(s.journal.intents[old].id[:s.journal.intents[old].id_size]) {
				return .Journal_Invalid
			}
		}
	}

	first := int(ledger.count) - 2
	text_status := ledger.entries[first].intent.status
	pdf_status := ledger.entries[first + 1].intent.status

	if pdf_status != .Prepared && text_status != .Acknowledged {
		return .Journal_Invalid
	}

	complete := text_status == .Acknowledged && pdf_status == .Acknowledged
	if complete &&
	   (ledger.completed_at == 0 ||
			   ledger.first_completed_at == 0 ||
			   ledger.next_due != ledger.completed_at + ledger.interval_seconds) {
		return .Journal_Invalid
	}

	if !complete && ledger.next_due != 0 {
		return .Journal_Invalid
	}

	if ledger.cycle > 1 && ledger.first_completed_at == 0 {
		return .Journal_Invalid
	}

	return previous == ledger.cycle ? .None : .Journal_Invalid
}

canary_find :: proc(s: ^Storage, id: string) -> (int, bool) {
	if s.canary == nil {
		return 0, false
	}

	for index in 0 ..< int(s.canary.count) {
		if string(s.canary.entries[index].intent.id[:32]) == id {
			return index, true
		}
	}

	return 0, false
}

canary_commit :: proc(s: ^Storage, candidate: ^Canary_Ledger) -> Storage_Error {
	if s == nil || !s.opened || storage_owner != s || s.canary == nil {
		return .Ownership
	}

	candidate.checksum = {}
	candidate.checksum = storage_digest(storage_bytes(candidate))
	old := s.canary
	s.canary = candidate
	validated := canary_ledger_validate(s)
	s.canary = old

	if validated != .None {
		return validated
	}

	if error := storage_record_write(s, CANARY_FILE, candidate); error != .None {
		return error
	}

	s.canary^ = candidate^

	return canary_ledger_validate(s)
}

canary_clone :: proc(s: ^Storage) -> ^Canary_Ledger {
	candidate, allocation := new(Canary_Ledger)

	if allocation != nil {
		return nil
	}

	if s.canary != nil {
		candidate^ = s.canary^
	}

	return candidate
}

// A .next file was never the committed sidecar. It cannot authorize a send or ACK.
// Discard only this private, bounded regular temporary under the held owner lock.
canary_discard_temporary :: proc(s: ^Storage) -> Storage_Error {
	path := storage_cpath(CANARY_FILE + ".next")
	defer delete(path)
	info: posix.stat_t

	if posix.fstatat(s.directory_fd, path, &info, {.SYMLINK_NOFOLLOW}) != .OK {
		return posix.errno() == .ENOENT ? .None : .IO
	}

	if !storage_safe_stat(info, false) || info.st_size < 0 || info.st_size > size_of(Canary_Ledger) {
		return .Directory_Unsafe
	}

	if posix.unlinkat(s.directory_fd, path, {}) != .OK {
		return .IO
	}

	return posix.fsync(s.directory_fd) == .OK ? .None : .IO
}

canary_now :: proc() -> i64 {
	return time.now()._nsec / 1_000_000_000
}

canary_schedule :: proc(runner: ^Runner) -> Tool_Error {
	if !canary_enabled(runner.options) {
		return {}
	}

	s := &runner.storage

	if error := canary_ledger_create(s, runner.options.canary_interval_seconds); error != .None {
		return {kind = .Journal, storage = error}
	}

	now := canary_now()

	if now < s.canary.completed_at {
		return {kind = .Journal, storage = .Scope_Mismatch}
	}

	count := int(s.canary.count)
	complete :=
		count == 0 ||
		(s.canary.entries[count - 2].intent.status == .Acknowledged &&
				s.canary.entries[count - 1].intent.status == .Acknowledged)

	if complete {
		if runner.canary_due_set && time.tick_diff(time.tick_now(), runner.canary_due_tick) > 0 {
			return {}
		}

		if runner.canary_completed >= 48 {
			return {kind = .Storage, storage = .Limit}
		}

		if now < s.canary.next_due || canary_pending(s) || remaining(runner) < 90 * time.Second {
			return {}
		}
	}

	if remaining(runner) < 90 * time.Second {
		return {}
	}

	observed := canary_observe(runner)
	refreshed := runner_target(runner)

	if refreshed.kind != .None {
		return refreshed
	}

	reconciled := canary_reconcile(runner, observed, canary_now())

	if reconciled.kind != .None {
		return reconciled
	}

	if complete {
		if canary_pending(s) || remaining(runner) < 60 * time.Second {
			return {}
		}

		if error := canary_prepare_cycle(s, canary_now()); error != .None {
			return {kind = .Journal, storage = error}
		}

		phase_print(.CANARY_PREPARED)
	}

	for offset in 0 ..< 2 {
		if error := canary_send(runner, offset); error.kind != .None {
			return error
		}
	}

	return {}
}

canary_send :: proc(runner: ^Runner, offset: int) -> Tool_Error {
	s := &runner.storage
	index := int(s.canary.count) - 2 + offset
	entry := &s.canary.entries[index].intent

	if entry.status == .Acknowledged {
		return {}
	}

	id := string(entry.id[:32])

	if entry.status == .Queued {
		if _, pending := wa.state_store_get(&s.state, .Outbound_Message, id); !pending {
			if !runner.options.retry_unknown_canary {
				phase_print(.CANARY_UNKNOWN)
				return {kind = .Canary_Unknown}
			}

			// Explicit recovery applies only to the already-loaded unknown item.
			runner.options.retry_unknown_canary = false
		}
	}

	if error := canary_mark(s, index, .Queued, canary_now()); error != .None {
		return {kind = .Journal, storage = error}
	}

	if error := runner_query_budget(runner); error.kind != .None {
		return error
	}

	sent: string
	error: wa.Socket_Error

	if offset == 0 {
		sent, error = wa.socket_send_text(&runner.socket, runner.target_jid, qualification_text, message_id = id)
	} else {
		sent, error = wa.socket_send_document(
			&runner.socket,
			runner.target_jid,
			transmute([]u8)qualification_pdf,
			"mesa-qualification.pdf",
			"Synthetic PDF transport check.",
			"application/pdf",
			id,
		)
	}

	defer delete(sent)

	if error.kind != .None {
		return {kind = .Send, socket = error}
	}

	if sent != id {
		return {kind = .Protocol}
	}

	return canary_ack_wait(runner, index)
}

canary_ack_wait :: proc(runner: ^Runner, index: int) -> Tool_Error {
	s := &runner.storage
	id := string(s.canary.entries[index].intent.id[:32])

	if _, pending := wa.state_store_get(&s.state, .Outbound_Message, id); !pending {
		return {kind = .Canary_Unknown}
	}

	deadline := time.tick_add(time.tick_now(), min(remaining(runner), 15 * time.Second))

	for time.tick_diff(time.tick_now(), deadline) > 0 {
		observed := canary_observe(runner)
		restart, error := runner_pump(runner)

		if error.kind != .None {
			return error
		}

		if restart {
			return {kind = .Protocol}
		}

		reconciled := canary_reconcile(runner, observed, canary_now())

		if reconciled.kind != .None {
			return reconciled
		}

		if s.canary.entries[index].intent.status == .Acknowledged {
			return {}
		}
	}

	return {kind = .Timeout}
}

canary_durable_completed :: proc(s: ^Storage) -> u64 {
	ledger := s.canary

	if ledger == nil || ledger.count == 0 {
		return 0
	}

	first := int(ledger.count) - 2
	completed :=
		ledger.entries[first].intent.status == .Acknowledged &&
		ledger.entries[first + 1].intent.status == .Acknowledged

	return completed ? ledger.cycle : ledger.cycle - 1
}

canary_status :: proc(runner: ^Runner) {
	first, last: i64

	if runner.storage.canary != nil {
		first = runner.storage.canary.first_completed_at
		last = runner.storage.canary.completed_at
	}

	fmt.printf(
		"CANARY_STATUS completed_cycles=%d durable_completed_cycles=%d " +
		"first_ack_unix_seconds=%d last_ack_unix_seconds=%d\n",
		runner.canary_completed,
		canary_durable_completed(&runner.storage),
		first,
		last,
	)
	os.flush(os.stdout)
}

canary_ledger_create :: proc(s: ^Storage, interval: int) -> Storage_Error {
	if s == nil || !s.opened || storage_owner != s {
		return .Ownership
	}

	if interval < 3600 || interval > 86400 || s.target_jid == "" {
		return .Scope_Mismatch
	}

	if s.canary != nil {
		return s.canary.interval_seconds == i64(interval) ? .None : .Intent_Mismatch
	}

	ledger := canary_clone(s)

	if ledger == nil {
		return .Allocation
	}

	defer free(ledger)
	copy(ledger.magic[:], CANARY_MAGIC)
	ledger.identity, ledger.nonce = s.marker.identity, s.marker.nonce
	ledger.subject_size = u32(copy(ledger.subject[:], s.target_subject))
	ledger.target_size = u32(copy(ledger.target[:], s.target_jid))
	ledger.interval_seconds = i64(interval)
	stored, allocation := new(Canary_Ledger)

	if allocation != nil {
		return .Allocation
	}

	s.canary = stored
	error := canary_commit(s, ledger)

	if error != .None {
		free(s.canary)
		s.canary = nil
	}

	return error
}

canary_pending :: proc(s: ^Storage) -> bool {
	for record in s.state.records {
		if record.kind == .Outbound_Message {
			return true
		}
	}

	return false
}

canary_pair_retained :: proc(s: ^Storage, pair: []Canary_Entry) -> bool {
	for index in 0 ..< 2 {
		entry := pair[index].intent
		id := string(entry.id[:32])

		if _, exists := wa.state_store_get(&s.state, .Outbound_Content, id); exists {
			return true
		}

		if _, exists := wa.state_store_get(&s.state, .Outbound_Message, id); exists {
			return true
		}
	}

	return false
}

// Metadata-only compaction; native seven-day pruning alone owns content lifetime.
canary_compact :: proc(s: ^Storage, candidate: ^Canary_Ledger) {
	if s.state.revision != s.state.durable_revision {
		return
	}

	kept := 0

	for index := 0; index < int(candidate.count); index += 2 {
		pair := &candidate.entries[index]
		remove :=
			pair.cycle < candidate.cycle &&
			pair.intent.status == .Acknowledged &&
			candidate.entries[index + 1].intent.status == .Acknowledged &&
			!canary_pair_retained(s, candidate.entries[index:index + 2])

		if remove {
			continue
		}

		if kept != index {
			candidate.entries[kept] = candidate.entries[index]
			candidate.entries[kept + 1] = candidate.entries[index + 1]
		}

		kept += 2
	}

	for index in kept ..< int(candidate.count) {
		candidate.entries[index] = {}
	}

	candidate.count = u32(kept)
}

canary_entry_create :: proc(
	s: ^Storage,
	entry: ^Canary_Entry,
	cycle: u64,
	document: bool,
	other_id: string,
) -> Storage_Error {
	kind := document ? "pdf" : "text"
	fingerprint := action_fingerprint_parts(
		action_metadata(document),
		transmute([]u8)(document ? qualification_pdf : qualification_text),
	)
	if fingerprint == "" {
		return .Allocation
	}; defer delete(fingerprint)
	entry.cycle = cycle
	entry.intent.kind_size = u32(copy(entry.intent.kind[:], kind))
	entry.intent.fingerprint_size = u32(copy(entry.intent.fingerprint[:], fingerprint))
	for _ in 0 ..< 4 {
		random: [16]u8
		crypto.rand_bytes(random[:])
		encoded, error := hex.encode(random[:])

		if error != nil {
			return .Allocation
		}

		id := string(encoded)
		_, known := canary_find(s, id)

		for index in 0 ..< int(s.journal.count) {
			known = known || id == string(s.journal.intents[index].id[:s.journal.intents[index].id_size])
		}

		if !known && id != other_id {
			copy(entry.intent.id[:32], encoded)
			entry.intent.id_size = 32
			delete(encoded)
			return .None
		}

		delete(encoded)
	}
	return .Entropy
}

canary_prepare_cycle :: proc(s: ^Storage, now: i64) -> Storage_Error {
	ledger := s.canary

	if ledger == nil || now < ledger.completed_at || now < 0 || now > max(i64) - ledger.interval_seconds {
		return .Scope_Mismatch
	}

	if canary_pending(s) {
		return .Outbox_Unsafe
	}

	if ledger.count > 0 {
		for index in int(ledger.count) - 2 ..< int(ledger.count) {
			if ledger.entries[index].intent.status != .Acknowledged {
				return .Outbox_Unsafe
			}
		}

		if now < ledger.next_due {
			return .Scope_Mismatch
		}
	}

	if ledger.cycle == max(u64) {
		return .Limit
	}

	candidate := canary_clone(s)

	if candidate == nil {
		return .Allocation
	}

	defer free(candidate)
	canary_compact(s, candidate)

	if candidate.count > CANARY_CAPACITY - 2 {
		return .Limit
	}

	candidate.cycle += 1
	candidate.next_due = 0
	first := int(candidate.count)

	for offset in 0 ..< 2 {
		other := offset == 0 ? "" : string(candidate.entries[first].intent.id[:32])
		if error := canary_entry_create(s, &candidate.entries[first + offset], candidate.cycle, offset == 1, other);
		   error != .None {
			return error
		}
	}

	candidate.count += 2

	return canary_commit(s, candidate)
}

canary_mark :: proc(s: ^Storage, index: int, status: Journal_Status, now: i64) -> Storage_Error {
	if s.canary == nil || index < int(s.canary.count) - 2 || index >= int(s.canary.count) {
		return .Intent_Mismatch
	}

	old := s.canary.entries[index].intent.status

	if status < old || u8(status) > u8(Journal_Status.Acknowledged) || old == .Prepared && status == .Acknowledged {
		return .Intent_Mismatch
	}

	if status == old {
		return .None
	}

	if now < s.canary.completed_at || now < 0 || now > max(i64) - s.canary.interval_seconds {
		return .Scope_Mismatch
	}

	candidate := canary_clone(s)

	if candidate == nil {
		return .Allocation
	}

	defer free(candidate)
	candidate.entries[index].intent.status = status
	first := int(candidate.count) - 2
	if candidate.entries[first].intent.status == .Acknowledged &&
	   candidate.entries[first + 1].intent.status == .Acknowledged {
		if candidate.first_completed_at == 0 {
			candidate.first_completed_at = now
		}
		candidate.completed_at = now
		candidate.next_due = now + candidate.interval_seconds
	}

	return canary_commit(s, candidate)
}

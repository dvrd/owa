package whatsapp

import "base:runtime"
import "core:os"
import "core:sync"
import "core:sys/posix"
import "core:time"
import "shared:async"
import "shared:surf"

// The protocol owner calls these operations serially. Poll may wake for an HTTP
// worker while the same whole-message read remains pending on Surf's runtime.
Message_Connection :: struct {
	transport:                     ^Transport_Runtime,
	phase:                         enum {
		Uninitialized,
		Open,
		Failed,
		Closed,
	},
	max_message_size:              int,
	read_deadline, write_deadline: time.Time,
	data:                          rawptr,
	read:                          proc(
		data: rawptr,
		dst: []u8,
		deadline: time.Time,
	) -> (
		async.WS_Message_Kind,
		int,
		surf.WebSocket_Async_Error,
	),
	write:                         proc(
		data: rawptr,
		payload: []u8,
		deadline: time.Time,
	) -> surf.WebSocket_Async_Error,
	close:                         proc(data: rawptr, code: u16) -> surf.WebSocket_Async_Error,
	poll:                          proc(
		data: rawptr,
		timeout: time.Duration,
		wakeup: ^os.File,
	) -> (
		bool,
		surf.WebSocket_Async_Error,
	),
}

// References are acquired and released by the serialized socket owner. An
// active HTTP worker can outlive WebSocket teardown until the pump joins it.
Transport_Runtime :: struct {
	runtime: async.Runtime,
	owners:  int,
}

transport_runtime_acquire :: proc(
	existing: ^Transport_Runtime = nil,
) -> (
	^Transport_Runtime,
	surf.WebSocket_Async_Error,
) {
	if existing != nil {
		existing.owners += 1
		return existing, {}
	}

	a := runtime.heap_allocator()
	owner, ae := new(Transport_Runtime, a)
	if ae != nil {
		return nil, {kind = .Allocation_Failed}
	}

	if async.init(&owner.runtime, {workers = 1, task_capacity = 16, io_capacity = 32, allocator = a}).kind !=
	   .None {
		free(owner, a)
		return nil, {kind = .IO_Failed}
	}

	if async.start(&owner.runtime).kind != .None {
		async.destroy(&owner.runtime)
		free(owner, a)
		return nil, {kind = .IO_Failed}
	}

	owner.owners = 1
	return owner, {}
}

transport_runtime_release :: proc(owner: ^Transport_Runtime) {
	owner.owners -= 1
	if owner.owners == 0 {
		async.destroy(&owner.runtime)
		free(owner, runtime.heap_allocator())
	}
}

Surf_Connection :: struct {
	transport:      ^Transport_Runtime,
	finished:       sync.Sema,
	session:        surf.WebSocket_Async,
	input:          []u8,
	reader, writer: ^os.File,
	read, write:    surf.WebSocket_Async_Op,
	write_done:     sync.Sema,
	reading:        bool,
	read_done:      sync.Sema,
}

message_connection_open :: proc(
	conn: ^Message_Connection,
	config: surf.WebSocket_Async_Config,
) -> surf.WebSocket_Async_Error {
	if conn == nil ||
	   conn.phase != .Uninitialized ||
	   config.max_message_size <= 0 ||
	   config.max_message_size > async.WS_MAX_MESSAGE_BYTES {
		return {kind = .Invalid_Config}
	}

	allocator := runtime.heap_allocator()
	state, ae := new(Surf_Connection, allocator)
	if ae != nil {
		return {kind = .Allocation_Failed}
	}
	defer if conn.phase != .Open {
		free(state, allocator)
	}

	state.input, ae = make([]u8, config.max_message_size, allocator)
	if ae != nil {
		return {kind = .Allocation_Failed}
	}
	defer if conn.phase != .Open {
		delete(state.input, allocator)
	}

	reader, writer, pipe_error := os.pipe()
	if pipe_error != nil {
		return {kind = .IO_Failed}
	}

	state.reader, state.writer = reader, writer
	defer if conn.phase != .Open {
		os.close(reader)
		os.close(writer)
	}

	transport, runtime_error := transport_runtime_acquire()
	if runtime_error.kind != .None {
		return runtime_error
	}
	defer if conn.phase != .Open {
		transport_runtime_release(transport)
	}

	state.transport = transport
	state.session.user = state
	// All asynchronous allocations must outlive the thread and context that dialed.
	context.allocator = allocator
	settings := config
	if settings.max_frame_payload == 0 {
		settings.max_frame_payload = settings.max_message_size
	}

	if settings.max_queued_bytes == 0 {
		settings.max_queued_bytes = settings.max_message_size
	}

	if e := surf.websocket_async_bind(
		&state.session,
		&transport.runtime,
		settings,
		surf_message_finished,
	); e.kind != .None {
		return e
	}

	done: sync.Sema
	op := surf.WebSocket_Async_Op {
		callback  = message_op_complete,
		user_data = &done,
	}

	if e := surf.websocket_async_upgrade(&state.session, &op); e.kind != .None {
		return e
	}

	if async.spawn(&transport.runtime, &state.session.task).kind != .None {
		return {kind = .IO_Failed}
	}

	sync.sema_wait(&done)
	if op.error.kind != .None {
		return op.error
	}

	conn^ = {
		phase            = .Open,
		transport        = transport,
		max_message_size = config.max_message_size,
		data             = state,
		read             = surf_message_read,
		write            = surf_message_write,
		close            = surf_message_close,
		poll             = surf_message_poll,
	}

	return {}
}

message_op_complete :: proc(op: ^surf.WebSocket_Async_Op) {
	sync.sema_post(cast(^sync.Sema)op.user_data)
}

message_connection_close :: proc(
	conn: ^Message_Connection,
	code: u16 = 1000,
) -> surf.WebSocket_Async_Error {
	if conn == nil || conn.phase == .Closed || conn.phase == .Uninitialized {
		return {}
	}

	conn.phase = .Closed
	conn.transport = nil
	if conn.close != nil {
		return conn.close(conn.data, code)
	}

	return {}
}

surf_message_finished :: proc(session_ptr: rawptr) {
	session := cast(^surf.WebSocket_Async)session_ptr
	state := cast(^Surf_Connection)session.user
	sync.sema_post(&state.finished)
}

surf_message_close :: proc(data: rawptr, code: u16) -> surf.WebSocket_Async_Error {
	state := cast(^Surf_Connection)data
	done: sync.Sema
	op := surf.WebSocket_Async_Op {
		callback  = message_op_complete,
		user_data = &done,
	}

	err := surf.websocket_async_close(&state.session, &op, code)
	if err.kind == .None {
		sync.sema_wait(&done)
		err = op.error
	} else {
		async.cancel(&state.transport.runtime, &state.session.task)
	}

	// Surf invokes on_done after all read, write and close callbacks.
	sync.sema_wait(&state.finished)
	transport_runtime_release(state.transport)
	os.close(state.reader)
	os.close(state.writer)
	delete(state.input, runtime.heap_allocator())
	free(state, runtime.heap_allocator())
	return err
}

surf_message_write :: proc(
	data: rawptr,
	payload: []u8,
	deadline: time.Time,
) -> surf.WebSocket_Async_Error {
	state := cast(^Surf_Connection)data
	done := &state.write_done
	op := &state.write
	op^ = {
		callback  = message_op_complete,
		user_data = done,
	}

	if deadline != {} && time.diff(time.now(), deadline) <= 0 {
		return {kind = .Timeout}
	}

	if err := surf.websocket_async_write(&state.session, op, .Binary, payload); err.kind != .None {
		return err
	}

	if deadline == {} {
		sync.sema_wait(done)
	} else if remaining := time.diff(time.now(), deadline);
	   remaining <= 0 || !sync.sema_wait_with_timeout(done, remaining) {
		surf.websocket_async_cancel(&state.session, op)
		sync.sema_wait(done)
		return {kind = .Timeout}
	}

	return op.error
}

surf_message_arrived :: proc(op: ^surf.WebSocket_Async_Op) {
	state := cast(^Surf_Connection)op.user_data
	sync.sema_post(&state.read_done)
	// Exactly one byte per pending read. The owner drains it before rearming.
	byte := [1]u8{1}

	for {
		if posix.write(posix.FD(os.fd(state.writer)), &byte[0], 1) >= 0 ||
		   posix.errno() != .EINTR {
			return
		}
	}
}

surf_message_poll :: proc(
	data: rawptr,
	timeout: time.Duration,
	wakeup: ^os.File,
) -> (
	bool,
	surf.WebSocket_Async_Error,
) {
	state := cast(^Surf_Connection)data
	if !state.reading {
		state.read = {
			callback  = surf_message_arrived,
			user_data = state,
		}

		if e := surf.websocket_async_read(&state.session, &state.read, state.input);
		   e.kind != .None {
			return false, e
		}

		state.reading = true
	}

	return message_poll_fd(posix.FD(os.fd(state.reader)), timeout, wakeup)
}

message_poll_fd :: proc(
	fd: posix.FD,
	timeout: time.Duration,
	wakeup: ^os.File,
) -> (
	bool,
	surf.WebSocket_Async_Error,
) {
	fds := [2]posix.pollfd{{fd = fd, events = {.IN}}, {fd = -1, events = {.IN}}}

	if wakeup != nil {
		fds[1].fd = posix.FD(os.fd(wakeup))
	}

	start := time.tick_now()
	for {
		ms: i32 = -1
		if timeout >= 0 {
			left := max(time.Duration(0), timeout - time.tick_since(start))
			millis := left / time.Millisecond
			if left % time.Millisecond != 0 {
				millis += 1
			}

			ms = i32(min(millis, time.Duration(max(i32))))
		}

		if posix.poll(&fds[0], len(fds), ms) >= 0 {
			return fds[0].revents != {}, {}
		}

		if posix.errno() != .EINTR {
			return false, {kind = .IO_Failed}
		}
	}
}

surf_message_read :: proc(
	data: rawptr,
	dst: []u8,
	deadline: time.Time,
) -> (
	async.WS_Message_Kind,
	int,
	surf.WebSocket_Async_Error,
) {
	state := cast(^Surf_Connection)data
	timeout: time.Duration = -1
	if deadline != {} {
		timeout = max(time.Duration(0), time.diff(time.now(), deadline))
	}

	ready, e := surf_message_poll(data, timeout, nil)
	if e.kind != .None {
		return {}, 0, e
	}

	if !ready {
		return {}, 0, {kind = .Timeout}
	}

	byte: [1]u8
	if n, err := os.read(state.reader, byte[:]); n != 1 || err != nil {
		return {}, 0, {kind = .IO_Failed}
	}

	sync.sema_wait(&state.read_done)
	state.reading = false
	op := &state.read
	if op.error.kind != .None {
		return op.opcode, 0, op.error
	}

	if op.n > len(dst) {
		return op.opcode, op.n, {kind = .Destination_Undersized}
	}

	copy(dst, state.input[:op.n])
	return op.opcode, op.n, {}
}

package whatsapp

import "core:sync"
import "core:testing"
import "core:time"

Query_Observer_Record :: struct {
	calls, failures: int,
}

// Other tests may query concurrently: only queries made with the observing
// test's record in context are counted, on that test's thread.
query_observer_test_record: rawptr

query_observer_test_observe :: proc(started: time.Tick, ok: bool) {
	record := cast(^Query_Observer_Record)context.user_ptr
	if record == nil || rawptr(record) != sync.atomic_load(&query_observer_test_record) {
		return
	}

	assert(time.tick_since(started) >= 0)
	record.calls += 1
	if !ok {
		record.failures += 1
	}
}

@(test)
whatsapp_query_observer_reports_sent_queries_only :: proc(t: ^testing.T) {
	record: Query_Observer_Record
	previous := context.user_ptr
	context.user_ptr = &record
	defer context.user_ptr = previous
	sync.atomic_store(&query_observer_test_record, rawptr(&record))
	defer sync.atomic_store(&query_observer_test_record, nil)
	query_observer_set(query_observer_test_observe)
	defer query_observer_set(nil)

	query := Binary_Node{tag = "iq"}
	socket: Socket
	document, error := socket_query(&socket, query)
	binary_document_destroy(&document)
	testing.expect_value(t, error.kind, Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, record, Query_Observer_Record{})

	// Online without a connection: the query is attempted and its send fails.
	socket.phase = .Online
	document, error = socket_query(&socket, query)
	binary_document_destroy(&document)
	testing.expect(t, error.kind != .None)
	testing.expect_value(t, record, Query_Observer_Record{calls = 1, failures = 1})
	socket_close(&socket)
}

package whatsapp_test

import "core:crypto/x509"
import "core:sync"
import "core:testing"
import "core:time"
import wa "shared:whatsapp"

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
	wa.query_observer_set(query_observer_test_observe)
	defer wa.query_observer_set(nil)

	query := wa.Binary_Node{tag = "iq"}
	socket: wa.Socket
	document, error := wa.socket_query(&socket, query)
	wa.binary_document_destroy(&document)
	testing.expect_value(t, error.kind, wa.Socket_Error_Kind.Invalid_State)
	testing.expect_value(t, record, Query_Observer_Record{})

	// Online without a connection: the query is attempted and its send fails.
	socket.phase = .Online
	document, error = wa.socket_query(&socket, query)
	wa.binary_document_destroy(&document)
	testing.expect(t, error.kind != .None)
	testing.expect_value(t, record, Query_Observer_Record{calls = 1, failures = 1})
	wa.socket_close(&socket)
}

@(test)
official_version_explicit_payload_is_preserved_by_socket_settings :: proc(t: ^testing.T) {
	explicit := [3]u32{2, 3000, 1234567890}
	root: x509.Certificate
	roots := [1]^x509.Certificate{&root}
	// Settings-only fixture; no TLS handshake or external request.
	settings, error := wa.socket_connect_settings({payload = {version = explicit}, tls = {root_cas = roots[:]}})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, settings.payload.version, explicit)
}

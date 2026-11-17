package whatsapp

import http "../http"
import network_client "../surf"
import "core:mem"
import "core:crypto/x509"
import "core:testing"

@(test)
whatsapp_version_worker_revision_requires_an_exact_unsigned_integer :: proc(t: ^testing.T) {
	for fixture in ([?]struct {
			body:     string,
			revision: u32,
		} {
			{`self.cfg={"client_revision":1234567890};`, 1234567890},
			{`"{\"client_revision\":4294967295}"`, max(u32)},
			{`{"client_revision": 1234 }`, 1234},
		}) {
		revision, error := web_version_revision(transmute([]u8)fixture.body)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, revision, fixture.revision)
	}

	for body in ([?]string {
			`{"client_revision":0}`,
			`{"client_revision":-1}`,
			`{"client_revision":4294967296}`,
			`{"client_revision":12345678901}`,
			`{"client_revision":"1234"}`,
			`{"client_revision":1234.5}`,
			`{"client_revision":1234e2}`,
			`{"client_revision":1234abc}`,
			`{"other_revision":1234}`,
			`{"xclient_revision":1234}`,
			``,
		}) {
		_, error := web_version_revision(transmute([]u8)body)
		testing.expect(t, error.kind != .None, body)
	}
}

Version_Test_Fetch :: struct {
	calls:         int,
	body:          string,
	status:        int,
	failure:       http.Error_Kind,
	url:           string,
	max_body_size: int,
}

version_test_fetch :: proc(
	data: rawptr,
	url: string,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	peer := cast(^Version_Test_Fetch)data
	peer.calls += 1
	peer.url, peer.max_body_size = url, config.max_body_size
	if peer.calls > 1 {
		return {}, {kind = .Invalid_Config}
	}
	if peer.failure != .None {
		return {}, {kind = peer.failure}
	}
	// Static fixture bytes have no owned allocator; discovery still destroys the response.
	return {status = peer.status, body = transmute([]u8)peer.body}, {}
}

@(test)
whatsapp_version_discovery_uses_official_worker_or_pinned_default :: proc(t: ^testing.T) {
	peer := Version_Test_Fetch {
		body   = `{"client_revision":1234567890}`,
		status = 200,
	}

	result := web_version_discover({}, {data = &peer, get = version_test_fetch})
	testing.expect_value(t, result.source, .WhatsApp)
	testing.expect_value(t, result.version, [3]u32{2, 3000, 1234567890})
	testing.expect_value(t, peer.calls, 1)
	testing.expect_value(t, peer.url, WA_WEB_VERSION_URL)
	testing.expect_value(t, peer.max_body_size, WA_WEB_VERSION_BODY_MAX)

	for sample in ([?]struct {
			body:     string,
			status:   int,
			failure:  http.Error_Kind,
			expected: Version_Error_Kind,
		} {
			{`{"client_revision":1}`, 503, .None, .HTTP_Status},
			{``, 200, .TLS_Failed, .HTTP_Failed},
			{`{"client_revision":0}`, 200, .None, .Invalid_Version},
			{`{"other":1234}`, 200, .None, .Missing_Version},
		}) {
		peer = {
			body    = sample.body,
			status  = sample.status,
			failure = sample.failure,
		}
		result = web_version_discover({}, {data = &peer, get = version_test_fetch})
		testing.expect_value(t, result.source, .Pinned)
		testing.expect_value(t, result.version, default_payload_config().version)
		testing.expect_value(t, result.fetch_error.kind, sample.expected)
		testing.expect_value(t, peer.calls, 1)
		if sample.status == 503 {
			testing.expect_value(t, result.fetch_error.status, 503)
		}
	}
}

@(test)
whatsapp_version_discovery_prefers_a_caller_fallback_to_the_pin :: proc(t: ^testing.T) {
	testing.expect_value(t, default_payload_config().version, WA_WEB_VERSION_PINNED)
	fallback := [3]u32{2, 3000, 1000000001}
	peer := Version_Test_Fetch{failure = .TLS_Failed}
	result := web_version_discover({}, {data = &peer, get = version_test_fetch}, fallback)
	testing.expect_value(t, result.source, Web_Version_Source.Configured)
	testing.expect_value(t, result.version, fallback)
	testing.expect_value(t, result.fetch_error.kind, Version_Error_Kind.HTTP_Failed)

	peer = {body = `{"client_revision":1234567890}`, status = 200}
	result = web_version_discover({}, {data = &peer, get = version_test_fetch}, fallback)
	testing.expect_value(t, result.source, Web_Version_Source.WhatsApp)
	testing.expect_value(t, result.version, [3]u32{2, 3000, 1234567890})

	peer = {status = 503}
	result = web_version_discover({}, {data = &peer, get = version_test_fetch})
	testing.expect_value(t, result.source, Web_Version_Source.Pinned)
	testing.expect_value(t, result.version, WA_WEB_VERSION_PINNED)
}

@(test)
whatsapp_version_preserves_body_and_explicit_triplet_bounds :: proc(t: ^testing.T) {
	body := make([]u8, WA_WEB_VERSION_BODY_MAX + 1)
	defer delete(body)
	_, oversized := web_version_revision(body)
	testing.expect_value(t, oversized.kind, .Body_Oversized)

	for text in ([?]string{"2.3000.1234567890", "2.3000.4294967295"}) {
		_, error := web_version_parse(text)
		testing.expect_value(t, error, .None)
	}

	for text in ([?]string {
			"",
			"2.3",
			"2.3.4.5",
			"v2.3.4",
			"2.-3.4",
			"2.3.4294967296",
			"2.3.4-beta",
			"2.3.4 ",
			"2..4",
			"0.0.0",
		}) {
		_, error := web_version_parse(text)
		testing.expect_value(t, error, .Invalid_Version)
	}
}

version_test_failed_allocator :: proc(
	_: rawptr,
	mode: mem.Allocator_Mode,
	size, alignment: int,
	old: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]u8,
	mem.Allocator_Error,
) {
	if mode == .Alloc || mode == .Alloc_Non_Zeroed || mode == .Resize || mode == .Resize_Non_Zeroed {
		return nil, .Out_Of_Memory
	}
	return nil, nil
}

@(test)
whatsapp_version_revision_needs_no_heap_allocation :: proc(t: ^testing.T) {
	context.allocator = {
		procedure = version_test_failed_allocator,
	}

	input := `{"client_revision":1234567890}`
	revision, error := web_version_revision(transmute([]u8)input)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, revision, u32(1234567890))
}

@(test)
official_version_literal_boundaries_and_conflicts_fail_closed :: proc(t: ^testing.T) {
	for fixture in ([?]struct {
			body:  string,
			value: u32,
		} {
			{`{"client_revision" : 1234}`, 1234},
			{`{"client_revision":1234,"client_revision":1234}`, 1234},
			{`{"client_revision":1234,"other":"x"}`, 1234},
			{`{"client_revision_extra":99,"client_revision":1234}`, 1234},
		}) {
		value, error := web_version_revision(transmute([]u8)fixture.body)
		testing.expect_value(t, error.kind, .None)
		testing.expect_value(t, value, fixture.value)
	}

	for body in ([?]string {
			`{"client_revision":1234,"client_revision":5678}`,
			`{"client_revision":1234 x}`,
			`{"client_revision":1234 e2}`,
			`{"client_revision":1234`,
			`{"client_revision\":1234}`,
			`{"client_revision":1234,"client_revision":0}`,
		}) {
		_, error := web_version_revision(transmute([]u8)body)
		testing.expect_value(t, error.kind, .Invalid_Version)
	}
}

@(test)
official_version_discovery_preserves_tighter_body_budget :: proc(t: ^testing.T) {
	peer := Version_Test_Fetch {
		body   = `{"client_revision":1234567890}`,
		status = 200,
	}

	result := web_version_discover({max_body_size = 8}, {data = &peer, get = version_test_fetch})
	testing.expect_value(t, peer.max_body_size, 8)
	testing.expect_value(t, result.source, .Pinned)
	testing.expect_value(t, result.fetch_error.kind, .Body_Oversized)
	testing.expect_value(t, peer.calls, 1)
}

@(test)
official_version_explicit_payload_is_preserved_by_socket_settings :: proc(t: ^testing.T) {
	explicit := [3]u32{2, 3000, 1234567890}
	root: x509.Certificate
	roots := [1]^x509.Certificate{&root}
	// Settings-only fixture; no TLS handshake or external request.
	settings, error := socket_connect_settings({payload = {version = explicit}, tls = {root_cas = roots[:]}})
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, settings.payload.version, explicit)
}

Owned_Version_Peer :: struct {
	status: int,
	body:   string,
	fail:   bool,
}

owned_version_fetch :: proc(
	data: rawptr,
	url: string,
	config: network_client.Config,
) -> (
	network_client.Response,
	network_client.HTTP_Error,
) {
	peer := cast(^Owned_Version_Peer)data
	storage := make([dynamic]u8, 0, len(peer.body))
	append(&storage, peer.body)
	response := network_client.Response {
		status       = peer.status,
		body         = storage[:],
		body_storage = storage,
		allocator    = context.allocator,
	}
	if peer.fail {
		return response, {kind = .IO_Failed}
	}
	return response, {}
}

@(test)
official_version_discovery_releases_owned_response_on_every_outcome :: proc(t: ^testing.T) {
	// The test runner's allocator tracking verifies response ownership is released
	// for success, rejected status, parse failure and transport failure.
	for peer in ([]Owned_Version_Peer {
			{200, `{"client_revision":1234}`, false},
			{503, `temporary failure`, false},
			{200, `{"client_revision":0}`, false},
			{200, `{"client_revision":1234}`, true},
		}) {
		actual := peer
		result := web_version_discover({}, {data = &actual, get = owned_version_fetch})
		expected := Web_Version_Source.Pinned
		if peer.status == 200 && !peer.fail && peer.body == `{"client_revision":1234}` {
			expected = .WhatsApp
		}
		testing.expect_value(t, result.source, expected)
	}
}

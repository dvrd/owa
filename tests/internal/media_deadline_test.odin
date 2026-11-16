package whatsapp

import http "../http"
import network_client "../surf"
import "core:testing"
import "core:time"

Media_Deadline_Test :: struct {
	t: ^testing.T,
	calls: int,
	previous_timeout: time.Duration,
	fail_first_only: bool,
	uncertain_first: bool,
}

media_deadline_test_execute :: proc(
	request: http.Request, config: network_client.Config,
) -> (network_client.Response, network_client.HTTP_Error) {
	state := cast(^Media_Deadline_Test)context.user_ptr
	state.calls += 1
	if state.uncertain_first {
		if state.calls == 1 {
			return {}, {kind = .IO_Failed, write_effect = .Unknown}
		}
		return {}, {kind = .Dial_Failed, write_effect = .Not_Sent}
	}
	if state.fail_first_only {
		testing.expect(state.t, config.timeout > 0)
		if state.calls == 1 {
			state.previous_timeout = config.timeout
			time.sleep(10 * time.Millisecond)
			return {status = 503}, {}
		}
		testing.expect(state.t, config.timeout < state.previous_timeout)
		body: string = `{"url":"https://mmg.whatsapp.net/media","direct_path":"/media"}`
		return {status = 200, body = transmute([]u8)body}, {}
	}
	testing.expect(state.t, config.timeout > 0 && config.timeout <= 20 * time.Millisecond)
	// An executor may return after its budget. Never start another host then.
	time.sleep(40 * time.Millisecond)
	return {}, {kind = .Deadline_Failed}
}

@(test)
media_upload_later_dial_failure_preserves_earlier_unknown_effect :: proc(t: ^testing.T) {
	state := Media_Deadline_Test{t = t, uncertain_first = true}
	previous := context.user_ptr
	context.user_ptr = &state
	defer context.user_ptr = previous
	storage: [64]u8
	n, metadata, encryption := media_encrypt(storage[:], []u8{1, 2, 3}, .Image, {})
	testing.expect_value(t, encryption.kind, .None)
	defer media_metadata_clear(&metadata)
	hosts := []Media_Host{{hostname = "first.invalid"}, {hostname = "second.invalid"}}
	_, error := media_upload(storage[:n], .Image, metadata,
		{auth = "synthetic", hosts = hosts}, {}, execute = media_deadline_test_execute)
	testing.expect_value(t, state.calls, 2)
	testing.expect_value(t, error.kind, .HTTP_Failed)
	testing.expect_value(t, error.http.kind, .Dial_Failed)
	testing.expect_value(t, error.http.write_effect, .Unknown)
}

@(test)
media_upload_does_not_restart_budget_on_host_fallback :: proc(t: ^testing.T) {
	state := Media_Deadline_Test{t = t}
	previous := context.user_ptr
	context.user_ptr = &state
	defer context.user_ptr = previous
	storage: [64]u8
	n, metadata, encryption := media_encrypt(storage[:], []u8{1, 2, 3}, .Image, {})
	testing.expect_value(t, encryption.kind, .None)
	defer media_metadata_clear(&metadata)
	hosts := []Media_Host{{hostname = "first.invalid"}, {hostname = "second.invalid"}}
	_, error := media_upload(storage[:n], .Image, metadata,
		{auth = "synthetic", hosts = hosts},
		{timeout = 20 * time.Millisecond}, execute = media_deadline_test_execute)
	testing.expect_value(t, error.kind, .HTTP_Failed)
	testing.expect_value(t, error.http.kind, .Deadline_Failed)
	testing.expect_value(t, error.http.write_effect, .Unknown)
	testing.expect_value(t, state.calls, 1)
}

@(test)
media_upload_fallback_receives_only_remaining_budget :: proc(t: ^testing.T) {
	state := Media_Deadline_Test{t = t, fail_first_only = true}
	previous := context.user_ptr
	context.user_ptr = &state
	defer context.user_ptr = previous
	storage: [64]u8
	n, metadata, encryption := media_encrypt(storage[:], []u8{1, 2, 3}, .Image, {})
	testing.expect_value(t, encryption.kind, .None)
	defer media_metadata_clear(&metadata)
	hosts := []Media_Host{{hostname = "first.invalid"}, {hostname = "second.invalid"}}
	result, error := media_upload(storage[:n], .Image, metadata,
		{auth = "synthetic", hosts = hosts},
		{timeout = time.Second}, execute = media_deadline_test_execute)
	testing.expect_value(t, error.kind, .None)
	testing.expect_value(t, state.calls, 2)
	testing.expect_value(t, string(result.direct_path[:result.direct_path_size]), "/media")
}

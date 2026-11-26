package whatsapp_test

import "core:fmt"
import "core:slice"
import "core:testing"
import "core:time"
import "shared:async/http"
import "shared:surf"
import wa "shared:whatsapp"

// task test:odin -- --package tests/e2e/client -- -define:OWA_BENCH_HTTP_WAKEUP=true -define:ODIN_TEST_NAMES=whatsapp_test.quiet_socket_http_wakeup
Wakeup_Sample :: struct {
	delay:    time.Duration,
	finished: time.Tick,
}

wakeup_execute :: proc(request: http.Request, _: surf.Config) -> (surf.Response, surf.HTTP_Error) {
	sample := cast(^Wakeup_Sample)raw_data(request.body)
	time.sleep(sample.delay)
	sample.finished = time.tick_now()
	return {status = 200}, {}
}

measure_quiet_socket_http_wakeup :: proc(t: ^testing.T) {
	peer := send_peer_new()
	defer send_peer_destroy(peer)

	send_peer_use_pipe(peer)
	delays := [?]int{5, 25, 50, 75, 95, 105}

	REPEATS :: 10
	lag: [len(delays)][REPEATS]f64
	// Discard one warm-up, then rotate the delay order on each pass.
	for i in -1 ..< len(delays) * REPEATS {
		round := max(0, i) / len(delays)
		index := (max(0, i) + round) % len(delays)
		sample := Wakeup_Sample {
			delay = time.Duration(delays[index]) * time.Millisecond,
		}

		request := http.Request {
			method = .GET,
			url    = "https://synthetic.invalid",
			body   = (cast([^]u8)&sample)[:size_of(sample)],
		}

		response, err := wa.socket_http_execute(
			&peer.socket,
			request,
			{},
			execute = wakeup_execute,
		)
		returned := time.tick_now()
		defer surf.response_destroy(&response)

		if !testing.expect_value(t, err.kind, wa.Socket_Error_Kind.None) ||
		   !testing.expect_value(t, response.status, 200) ||
		   !testing.expect(t, sample.finished != {}) {
			return
		}

		if i >= 0 {
			// socket_http_execute joins the worker before the owner reads finished.
			lag[index][round] = time.duration_milliseconds(
				time.tick_diff(sample.finished, returned),
			)
		}
	}

	for &samples, index in lag {
		slice.sort(samples[:])
		fmt.printf(
			"worker delay %3d ms | completion to return (ms), n=%d: median %.2f, range %.2f..%.2f\n",
			delays[index],
			REPEATS,
			(samples[4] + samples[5]) / 2,
			samples[0],
			samples[REPEATS - 1],
		)
	}
}

when #config(OWA_BENCH_HTTP_WAKEUP, false) {
	@(test)
	quiet_socket_http_wakeup :: proc(t: ^testing.T) {
		measure_quiet_socket_http_wakeup(t)
	}
}

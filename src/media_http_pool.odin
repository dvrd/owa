package whatsapp

import "base:runtime"
import "core:sync"
import "core:time"
import "shared:async/http"
import "shared:surf"

// A Socket lends this pool exclusively to one download until its worker joins.
Media_HTTP_Pool :: struct {
	transport: ^Transport_Runtime,
	client:  surf.Client,
}

media_http_pool_open :: proc(settings: surf.Config, transport: ^Transport_Runtime = nil) -> (^Media_HTTP_Pool, surf.HTTP_Error) {
	a := runtime.heap_allocator()
	pool, allocation := new(Media_HTTP_Pool, a)
	if allocation != nil {
		return nil, {kind = .Allocation_Failed, allocation = allocation}
	}

	owner, runtime_error := transport_runtime_acquire(transport)
	if runtime_error.kind != .None {
		free(pool, a)
		return nil, {kind = .Allocation_Failed if runtime_error.kind == .Allocation_Failed else .IO_Failed}
	}

	pool.transport = owner
	config := surf.Client_Config {
		http = settings,
		capacities = surf.Capacities {
			requests = 1,
			origins = 1,
			connections_per_origin = 1,
			response_chunks = 2,
			upload_chunks = 1,
		},
	}

	config.http.timeout = 30 * time.Second
	config.http.max_body_size = http.MAX_BODY_SIZE
	config.http.allow_http = false
	config.http.max_redirects = 0
	if err := surf.client_init(&pool.client, &pool.transport.runtime, config, a); err.kind != .None {
		transport_runtime_release(pool.transport)
		free(pool, a)
		return nil, media_http_pool_error(err)
	}

	return pool, {}
}

media_http_pool_close :: proc(pool: ^Media_HTTP_Pool) {
	if pool == nil {
		return
	}

	surf.client_close(&pool.client)
	for !surf.client_quiescent(&pool.client) {
		time.sleep(time.Millisecond)
	}

	surf.client_destroy(&pool.client)
	transport_runtime_release(pool.transport)
	free(pool, runtime.heap_allocator())
}

media_http_pool_error :: proc(error: surf.Client_Error) -> surf.HTTP_Error {
	if error.http.kind != .None {
		return error.http
	}

	#partial switch error.kind {
	case .Allocation_Failed: return {kind = .Allocation_Failed}
	case .Invalid_Config: return {kind = .Invalid_Config}
	case: return {kind = .IO_Failed}
	}
}

media_http_pool_download :: proc(
	pool: ^Media_HTTP_Pool,
	request: surf.Request,
	limit: int,
	timeout: time.Duration,
	cancel: ^bool,
) -> (surf.Response, surf.HTTP_Error) {
	if pool == nil || limit <= 0 || limit > http.MAX_BODY_SIZE || timeout <= 0 || request.method != .GET {
		return {}, {kind = .Invalid_Config}
	}

	deadline := time.tick_add(time.tick_now(), timeout)
	handle, submit := surf.client_submit_stream(
		&pool.client, request, {max_decoded_bytes = u64(limit)}, deadline,
	)
	if submit.kind != .None {
		return {}, media_http_pool_error(submit)
	}

	response := surf.Response{allocator = context.allocator}

	head: surf.Stream_Head
	defer surf.stream_head_destroy(&head)

	complete, ended := false, false
	failure: surf.HTTP_Error
	for !complete || !ended {
		if !complete {
			if result, ok := surf.client_poll(&pool.client); ok {
				complete = true
				failure = result.error
			}
		}

		if failure.kind != .None {
			break
		}

		if cancel != nil && sync.atomic_load(cancel) {
			failure.kind = .Deadline_Failed
			break
		}

		if response.status == 0 {
			e := surf.client_stream_take_head(&pool.client, handle, &head)
			if e.kind == .None {
				response.status = head.response.status
			} else if e.kind != .Pending {
				failure = media_http_pool_error(e)
				break
			}
		}

		if response.status != 0 && !ended {
			chunk: surf.Body_Chunk
			state, e := surf.client_stream_next(&pool.client, handle, &chunk)
			if e.kind != .None {
				failure = media_http_pool_error(e)
				break
			}

			if state == .Chunk {
				_, ae := append(&response.body_storage, ..chunk.data)
				surf.body_chunk_release(&chunk)
				if ae != nil {
					failure = {kind = .Allocation_Failed, allocation = ae}

					break
				}

				continue
			}

			ended = state == .End
		}

		if !complete || !ended {
			time.sleep(time.Millisecond)
		}
	}

	if !complete {
		surf.client_cancel(&pool.client, handle)
		for {
			if result, ok := surf.client_poll(&pool.client); ok {
				if result.error.kind != .None && failure.kind == .IO_Failed {
					failure = result.error
				}

				break
			}

			time.sleep(time.Millisecond)
		}
	}

	surf.client_release(&pool.client, handle)
	if failure.kind != .None {
		surf.response_destroy(&response)
		return {}, failure
	}

	response.body = response.body_storage[:]
	return response, {}
}

package whatsapp

import "base:runtime"
import "core:sync"
import "core:time"
import "shared:async"
import "shared:async/http"
import "shared:async/mem/owned"
import "shared:surf"
import surf_async "shared:surf/async"

// A Socket lends this pool exclusively to one download until its worker joins.
Media_HTTP_Pool :: struct {
	runtime: async.Runtime,
	client:  surf_async.Client,
}

media_http_pool_supports :: proc(protocols: []string) -> bool {
	for protocol in protocols {
		if protocol == "http/1.1" {
			return true
		}
	}

	return len(protocols) == 0
}

media_http_pool_open :: proc(settings: surf.Config) -> (^Media_HTTP_Pool, surf.HTTP_Error) {
	a := runtime.heap_allocator()
	pool, allocation := new(Media_HTTP_Pool, a)
	if allocation != nil {
		return nil, {kind = .Allocation_Failed, allocation = allocation}
	}

	if async.init(&pool.runtime, {workers = 1, task_capacity = 4, io_capacity = 4, allocator = a}).kind != .None {
		free(pool, a)
		return nil, {kind = .IO_Failed}
	}

	protocols := [1]string{"http/1.1"}

	config := surf_async.Client_Config {
		http = settings,
		capacities = surf_async.Capacities {
			requests = 1, origins = 1, connections = 1, connections_per_origin = 1,
			waiters_per_origin = 1, dns_ids = surf_async.DNS_IDS_PER_QUERY, work_per_resume = 64,
		},
		streaming = surf_async.Stream_Client_Limits {
			streams = 1, response_chunks = 2, upload_chunks = 1,
			max_chunk_bytes = 16384, max_retained_bytes_per_stream = 65536,
		},
	}

	config.http.tls.alpn_protocols = protocols[:]
	config.http.timeout = 30 * time.Second
	config.http.max_body_size = http.MAX_BODY_SIZE
	config.http.allow_http = false
	config.http.max_redirects = 0
	if async.start(&pool.runtime).kind != .None {
		async.destroy(&pool.runtime)
		free(pool, a)
		return nil, {kind = .IO_Failed}
	}

	if err := surf_async.client_init(&pool.client, &pool.runtime, config, a); err.kind != .None {
		async.destroy(&pool.runtime)
		free(pool, a)
		return nil, media_http_pool_error(err)
	}

	return pool, {}
}

media_http_pool_close :: proc(pool: ^Media_HTTP_Pool) {
	if pool == nil {
		return
	}

	surf_async.client_close(&pool.client)
	for !surf_async.client_quiescent(&pool.client) {
		time.sleep(time.Millisecond)
	}

	surf_async.client_destroy(&pool.client)
	async.destroy(&pool.runtime)
	free(pool, runtime.heap_allocator())
}

media_http_pool_error :: proc(error: surf_async.Client_Error) -> surf.HTTP_Error {
	if error.http.kind != .None {
		return error.http
	}

	#partial switch error.kind {
	case .Allocation_Failed, .Budget_Rejected: return {kind = .Allocation_Failed}
	case .Invalid_Config: return {kind = .Invalid_Config}
	case: return {kind = .IO_Failed}
	}
}

media_http_pool_download :: proc(
	pool: ^Media_HTTP_Pool,
	request: http.Request,
	limit: int,
	timeout: time.Duration,
	cancel: ^bool,
) -> (surf.Response, surf.HTTP_Error) {
	if pool == nil || limit <= 0 || limit > http.MAX_BODY_SIZE || timeout <= 0 || request.method != .GET {
		return {}, {kind = .Invalid_Config}
	}

	deadline := async.deadline_after(&pool.runtime, timeout)
	handle, submit := surf_async.client_submit_stream(
		&pool.client, request, {max_encoded_bytes = u64(limit), max_decoded_bytes = u64(limit)}, deadline,
	)
	if submit.kind != .None {
		return {}, media_http_pool_error(submit)
	}

	response := surf.Response{allocator = context.allocator}

	head: surf_async.Stream_Head
	defer surf_async.stream_head_destroy(&head)

	complete, ended := false, false
	failure: surf.HTTP_Error
	for !complete || !ended {
		if !complete {
			if result, ok := surf_async.client_poll(&pool.client); ok {
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
			e := surf_async.client_stream_take_head(&pool.client, handle, &head)
			if e.kind == .None {
				response.status = head.response.status
			} else if e.kind != .Pending {
				failure = media_http_pool_error(e)
				break
			}
		}

		if response.status != 0 && !ended {
			chunk: owned.Chunk
			state, e := surf_async.client_stream_next(&pool.client, handle, &chunk)
			if e.kind != .None {
				failure = media_http_pool_error(e)
				break
			}

			if state == .Chunk {
				_, ae := append(&response.body_storage, ..chunk.data)
				owned.destroy(&chunk)
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
		surf_async.client_cancel(&pool.client, handle)
		for {
			if result, ok := surf_async.client_poll(&pool.client); ok {
				if result.error.kind != .None && failure.kind == .IO_Failed {
					failure = result.error
				}

				break
			}

			time.sleep(time.Millisecond)
		}
	}

	surf_async.client_release(&pool.client, handle)
	if failure.kind != .None {
		surf.response_destroy(&response)
		return {}, failure
	}

	response.body = response.body_storage[:]
	return response, {}
}

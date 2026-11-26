package whatsapp_test

import "core:testing"
import "core:time"
import "shared:async/http"
import wa "shared:whatsapp"

@(test)
media_pool_respects_existing_protocol_offers :: proc(t: ^testing.T) {
	testing.expect(t, wa.media_http_pool_supports(nil))
	testing.expect(t, wa.media_http_pool_supports([]string{"h2", "http/1.1"}))
	testing.expect(t, !wa.media_http_pool_supports([]string{"h2"}))
}

@(test)
media_pool_rejects_cleartext_on_each_request :: proc(t: ^testing.T) {
	pool, open_error := wa.media_http_pool_open({})
	if !testing.expect_value(t, open_error.kind, http.Error_Kind.None) {
		return
	}
	defer wa.media_http_pool_close(pool)

	cancel := false
	limits := [?]int{26, 74}

	for limit in limits {
		response, e := wa.media_http_pool_download(pool, {method = .GET, url = "http://127.0.0.1/"}, limit, time.Second, &cancel)
		testing.expect(t, e.kind != .None)
		testing.expect_value(t, len(response.body), 0)
	}
}

package main

import wa "shared:whatsapp"
import surf "shared:surf"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:time"

main :: proc() {
 assert(len(os.args) == 2)
 port, valid := strconv.parse_u64(os.args[1], 10)
 assert(valid && port > 0 && port <= 65535)
 url := fmt.aprintf("http://127.0.0.1:%d/sw.js", port)
 defer delete(url)
 response, error := wa.version_fetch_http(nil, url,
  {allow_http = true, timeout = 2 * time.Second,
   setup_timeout = time.Second, max_body_size = 4096, max_redirects = 0})
 defer surf.response_destroy(&response)
 assert(error.kind == .None && response.status == 200)
 when !#config(VERSION_HTTP_LEGACY, false) {
  revision, decoded := wa.web_version_revision(response.body)
  assert(decoded.kind == .None && revision == 1234567890)
 }
 fmt.println("OWA_VERSION_HTTP_RESPONSE_PASS")
}

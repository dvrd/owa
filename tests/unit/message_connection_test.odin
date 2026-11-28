package whatsapp_test

import "core:testing"
import "shared:surf"
import wa "shared:whatsapp"

@(test)
message_connection_closes_the_owner_once :: proc(t: ^testing.T) {
	state: u16
	conn := wa.Message_Connection {
		phase = .Open,
		data = &state,
		close = proc(data: rawptr, code: u16) -> surf.WebSocket_Error {
			value := cast(^u16)data
			assert(value^ == 0)
			value^ = code
			return {}
		},
	}

	testing.expect_value(t, wa.message_connection_close(&conn, 1008).kind, .None)
	testing.expect_value(t, wa.message_connection_close(&conn).kind, .None)
	testing.expect_value(t, state, u16(1008))
}

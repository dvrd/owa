package main

import "core:os"

write_error_is_efbig :: proc(error: os.Error) -> bool {
	errno, ok := error.(os.Platform_Error)
	return ok && errno == .EFBIG
}

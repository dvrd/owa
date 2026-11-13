package main

import "core:io"
import "core:os"
import "core:sys/posix"

write_error_is_efbig :: proc(error: os.Error) -> bool {
	// Darwin Core os.stream maps failed writes to io.Unknown, retaining libc errno.
	// Read errno immediately after save, before further I/O; cleanup success does not reset it.
	if error == io.Error.Unknown {
		return posix.errno() == .EFBIG
	}
	errno, ok := error.(os.Platform_Error)
	return ok && errno == .EFBIG
}

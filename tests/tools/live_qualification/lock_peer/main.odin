#+build darwin, linux, freebsd, openbsd, netbsd
package main

import "core:os"
import "core:strings"
import "core:sys/posix"

check :: proc() -> int {
	if len(os.args) != 2 {return 2}
	path := strings.clone_to_cstring(os.args[1]); defer delete(path)
	file := posix.open(path, {.RDWR})
	if file < 0 {return 2}
	defer posix.close(file)
	result := posix.lockf(file, .TLOCK, 0)
	if result != .OK {
		error := posix.errno()
		if error == .EACCES || error == .EAGAIN {return 0}
		return 2
	}
	return 1
}

main :: proc() {os.exit(check())}

package main

import wa "../.."
import "core:crypto"
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:time"

qr_write :: proc(runner: ^Runner, token: string) -> Tool_Error {
 code, encode_error := wa.qr_encode(token)
 if encode_error != .None {return {kind = .QR}}
 defer crypto.zero_explicit(&code, size_of(code))
 qr_modules: [wa.QR_MAX_SIZE * wa.QR_MAX_SIZE]bool
 defer crypto.zero_explicit(&qr_modules, size_of(qr_modules))
 for y in 0..<code.size {
  for x in 0..<code.size {qr_modules[y * code.size + x] = wa.qr_module(&code, x, y)}
 }
 body, json_error := json.marshal(struct {size: int, modules: []bool}{
  code.size, qr_modules[:code.size * code.size]})
 if json_error != nil {return {kind = .Allocation}}
 defer {crypto.zero_explicit(raw_data(body), len(body)); delete(body)}
 path := fmt.aprintf("%s/qr.json", runner.storage.directory); defer delete(path)
 if error := qr_private_write(path, body); error.kind != .None {return error}
 fmt.println("QR_READY qr.json"); os.flush(os.stdout)
 return {}
}

qr_private_write :: proc(path: string, data: []u8) -> Tool_Error {
 temporary := fmt.aprintf("%s.next-%d", path, time.now()._nsec); defer delete(temporary)
 file, open_error := os.open(temporary, {.Write, .Create, .Excl}, os.perm_number(0o600))
 if open_error != nil {return {kind = .IO}}
 closed, renamed := false, false
 defer {
  if !closed {os.close(file)}
  if !renamed {os.remove(temporary)}
 }
 offset := 0
 for offset < len(data) {
  count, error := os.write(file, data[offset:])
  if error != nil || count <= 0 {return {kind = .IO}}
  offset += count
 }
 if os.flush(file) != nil {return {kind = .IO}}
 close_error := os.close(file); closed = true
 if close_error != nil {return {kind = .IO}}
 if os.rename(temporary, path) != nil {return {kind = .IO}}
 renamed = true
 return {}
}

qr_remove :: proc(runner: ^Runner) {
 if runner.storage.directory == "" {return}
 path := fmt.aprintf("%s/qr.json", runner.storage.directory); defer delete(path)
 // A cleanup failure leaves an expiring rendering inside the private0600 file.
 _ = os.remove(path)
}

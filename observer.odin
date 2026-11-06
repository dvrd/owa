package whatsapp

import "core:time"

Pairing_Event_Kind :: enum {Connecting, QR, Paired, Online, Disconnected, Failed}
Pairing_Event :: struct {
	kind: Pairing_Event_Kind,
	qr: string,
	expires_at: time.Time,
}
Pairing_Observer :: #type proc(data: rawptr, event: Pairing_Event)

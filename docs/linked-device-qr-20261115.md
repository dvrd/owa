# Opt-in current linked-device QR format

Keep zero/default `.Legacy` for the existing four-field QR. Select `.Linked_Device` in `Socket_Config.qr_format` or `Session_Config.qr_format` to emit the current linked-device URL and companion web-client field. Browser mapping comes from the existing payload browser strings; login payloads, profile defaults and app versions are unchanged.

Direct callers may use `pairing_qr_encode(dst, ref, noise_public, identity_public, adv_secret, .Linked_Device, "Ubuntu", "Chrome")`; the old call signature remains valid and preserves legacy output. `pairing_qr_next` accepts the same optional format/browser arguments. Required-size errors and invalid format/reference errors leave the destination and QR reference position unchanged.

Source-byte parity is not a successful live phone scan. No pairing, session or messaging operation occurred during qualification.

## Validation

The old encoder fails the expected current-format byte regression. Review also reproduced the borrowed-profile overwrite (Other9 instead of Windows Desktop8), fixed by classifying the companion before writing. The final candidate passes56 ASan tests; integrated with pairing/receive fixes it passes75 ASan tests with vet/warnings-as-errors and memory tracking. Four owned localhost Noise modes and native ASan consumer pass. Independent review found no blocker.

[Receipt and retained logs](evidence/linked-device-qr-20261115/receipt.json). Exact mapping includes11 profile cases, legacy output, bounds/unchanged errors, initial/timer QR events, invalid session/socket configuration and aliased inputs. No global login/profile/version/capability defaults were changed. This is encoder/session qualification, not a phone scan or live-account result.

# Offline native TCP, WebSocket and Noise lifecycle evidence

This fixture contacts only a fresh localhost listener. It never loads an account,
contacts WhatsApp, pairs a device or sends an external message. The Python peer
uses only the standard library; the Odin client uses the real native Surf TCP
WebSocket transport and WhatsApp Noise implementation.

```sh
python3 shared/whatsapp/tests/loopback_noise/run.py \
  --odin /absolute/path/to/matching/odin \
  --shared-root /absolute/path/to/shared \
  --report /tmp/whatsapp-loopback-address.json
```

`--sanitize thread` selects TSan. To exercise an installed Mesa copy, use its
physical `src` directory as `--shared-root`; no source is copied or modified.
Reports retain exact commands, compiler/root identity, binary hash, imported
source hashes, source-unchanged checks, peer errors and all four client results.

The peer checks RFC6455 client masking, the expected ClientHello and ClientFinish,
and encrypted application payload bytes against pinned independent Node/Baileys
6.7.23 test vectors. It sends the ServerHello in five-byte TCP writes. Four fresh
connections cover successful encrypted exchange and clean peer close, truncated
Noise envelope inside a complete WebSocket message followed by EOF, partial-WebSocket-frame timeout with a 200 ms handshake deadline, and a fresh
successful exchange after both failures. Failed clients must erase private and
Noise read keys. The client allocation tracker must return to zero retained bytes
and zero invalid frees after each connection closes.

This closes a real-stream regression gap around the deterministic in-memory
handshake tests. The peer replays a synthetic cryptographic transcript; it is not
a dynamically authenticated independent Noise server or evidence of current
WhatsApp account interoperability. It does not exercise TLS, full socket pairing,
Signal ratchets, live media providers, receipt ordering or account reconnection.
Those require their separately owned fixtures and explicit account qualification.

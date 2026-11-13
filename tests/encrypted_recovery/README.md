# Offline encrypted recovery qualification

This fixture uses the public WhatsApp library's actual Signal initiator,
prekey decrypt, authenticated Whisper encrypt/decrypt, session codec,
Prekey_Store codec/removal, and StateStore encode/save/load APIs. Both protocol
roles have disposable synthetic keys. The small deterministic key/bundle helpers
come from Mesa `tests/whatsapp/signal.odin` lines 906–965
(`signal_session_test_private/local/bundle`); no account material or application
state is copied.

Run with the compiler/Core pairing from `ci/WEBTOOLS_TOOLCHAIN.md` and a compatible
native sanitizer linker/runtime. On macOS the LLVM 22 runtime used by the pinned
compiler has been qualified; Apple clang's sanitizer ABI differs.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s whatsapp/tests/encrypted_recovery -p 'test_*.py'
PATH=/opt/homebrew/opt/llvm@22/bin:$PATH \
  python3 whatsapp/tests/encrypted_recovery/run.py --odin ../odin \
  --sanitize address --report /tmp/owa-encrypted-recovery-address.json
# Repeat with --sanitize thread and a distinct report.
```

The runner builds and runs five native tests with leak tracking, then builds an
instrumented child executable. It owns every temporary directory, process and
kill target. A child prints an exact readiness marker after staging or committing
real cryptographic transitions; the parent kills that unreaped child with
SIGKILL. A new process reloads the saved file and verifies the same stable intent
ID and coupled session/prekey/message records. It never resends a persisted raw
Signal packet by re-encrypting its intent.

The five crash boundaries cover prekey consumption before/after commit, outbound
ratchet/ciphertext persistence before/after commit, and receiver ratchet plus
processed-ID persistence after commit. The native tests also cover signed-prekey
rotation while retaining an older session generation, explicit trust for a new
device identity, delayed old-chain delivery across DH ratchets and disk reload,
an invalid prekey MAC without one-time-key consumption, and transactional rejection
of an inner session checksum failure. Corrupted/truncated outer StateStore files
must leave the old live store and usable sessions intact.

The file-failure case sets `RLIMIT_FSIZE=512` and ignores SIGXFSZ **only in an
owned child**. The actual StateStore temporary-file write must return
`Write_Failed` with an observed EFBIG cause, leave the old committed file byte-identical, keep the old
durable revision, and remove its temporary file. The parent's limit is unchanged.
Linux Core returns the platform errno directly. Darwin Core maps stream write
errors to `io.Unknown`; the fixture captures the retained libc EFBIG errno
immediately after save, before further I/O. This is a bounded file-write failure,
not an ENOSPC or physical power-loss test.

The evidence report records each command, binary/compiler hashes, compiler root,
clang identity, source hashes before/after, crash receipts and exact failure
classification. Source guards include the fixture, its runtime sibling libraries
and the compiler's actual Core/base/zlib source closure. Output and execution
budgets fail closed. The runner receives no account/provider configuration and
makes no provider or network calls.

## Evidence limits

This tests caller-managed atomic snapshots containing real encoded Signal sessions,
real encoded prekey state, consumed-key markers, stable content IDs and raw Signal
packets in one StateStore. It does not prove the production Socket's full stanza
routing or multi-file persistence integration. `Captured_Message/prekeys-b` is a
fixture-owned snapshot record; no new application record convention is introduced.
The second role uses the same library, so this is not an independent libsignal
interoperability oracle. There is no linked device, WhatsApp service, recipient
delivery, full-stack certification, disk-full/ENOSPC or power-loss claim. The older
`tests/recovery_campaign` fixture remains separate. No runtime code is changed.

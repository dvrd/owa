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

The runner builds and runs six native tests with leak tracking, then builds an
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
budgets fail closed. The runner receives no account/provider configuration and makes no provider or
external network calls. The optional native mode uses only owned127.0.0.1 TCP.

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

## Production Socket send/ACK crash composition

Six additional owned crash stages now use the public
`socket_group_send_prepared` implementation with supplied synthetic group/device
metadata and a real established pairwise session. The production code generates
and signs a sender key, encrypts its distribution with Signal, encrypts the group
message, stages both ratchets, commits the exact stanza, and writes its actual
Noise/WebSocket framing. The fixture uses production canonical session addresses,
numeric consumed-prekey markers and a separate real `prekey_store_save/load`
file. The sender is the synthetic participant whose one-time key9 was consumed
during the established-session setup; that key must stay absent throughout.
The older standalone fixture's record conventions remain confined to its stages.

The new stages are before send, after production commit/before any transport
write, after a complete transport handoff/before its callback returns, after send
returns/before ACK, after positive ACK/before caller journal, and after caller ACK
journal. A durable file owned by the synthetic stream peer witnesses the actual
outbound bytes before the handoff crash. A second owned witness binds the exact
session, sender key, recipient membership, immutable content and prekey-file
hashes to that handoff; they must remain identical after ACK and restart.
It is not a server-delivery receipt.
The positive ACK is itself encrypted and framed by the synthetic peer and travels
through `socket_read` and the production ACK commit path.

Fresh verifier processes decrypt the actual outgoing pairwise distribution and
signed group payload using the real peer session. They check the stable message
ID, plaintext, sender chain counter, group iteration, consumed-key marker,
prekey snapshot/file consistency and replay rejection. If a pending stanza
remains, ordinary `socket_send_group` must replay its exact ciphertext without
new discovery/encryption or a state-file change. After an ACK with no durable
caller journal, the fixture retains the caller intent as unknown and performs no
automatic send. Pending absence alone still is not proof of delivery; this is the
fixture caller's explicit recovery policy, not a new guarantee for every caller.

These stages prove the prepared production Socket send/ACK subset. They do not
exercise metadata discovery, live service delivery, a complete Noise login,
concurrent writers, an upgrade/migration or all multi-file crash transitions.
They add evidence to the earlier standalone snapshots rather than substituting a
processed-ID marker for a server ACK. The wider OKAMI-414 acceptance criteria
still require separate upgrade and any explicitly requested ENOSPC qualification.

## Same-format cross-commit compatibility (offline)

`compatibility.py` prepares two isolated runtime owners from exact local Git
commits: the earlier published OWA
`fa2734f60b60cc9770809bb1be873cea60fe3c12` and the explicit committed consumer
`1d5160f384d3055eef314557c31c912bea5ce557`. Uncommitted runtime changes are excluded. Each exported public
root runtime source is checked against its Git blob identity and SHA256. The
identical current synthetic fixture is overlaid onto both owners. Both binaries
use the same hashlocked released compiler/Core and five sibling dependency bundle;
`--assets-dir` is mandatory and no download occurs.

The earlier runtime generates real Signal sessions and pending ciphertext plus
StateStore and prekey files, then exits normally. Two fresh current-runtime
processes load those prior-produced files, verify stable intent IDs, exact
StateStore and session re-encoding, registration/counter metadata, consumed-key
absence and prekey-file/snapshot consistency, and authenticate/decrypt the pending
ciphertext in memory. Original state/prekey file bytes must remain identical.
This path calls no Socket, HTTP or external network API and injects no failures.

```sh
python3 whatsapp/tests/encrypted_recovery/compatibility.py \
  --assets-dir /tmp/owa-native-sdk-20261112-413 \
  --clang /opt/homebrew/opt/llvm@22/bin/clang \
  --current-revision 1d5160f384d3055eef314557c31c912bea5ce557 \
  --sanitize address --work /tmp/owa-format-compat-address \
  --report /tmp/owa-format-compat-address.json
# Repeat with --sanitize thread and new work/report paths.
```

Work directories must be new direct children of `/tmp` with the shown prefix;
they retain exported public sources and binaries for review. Generated synthetic
state is disposable and removed after verification. Evidence records exact owner
commits, Git blobs, source/binary/compiler hashes, normal exits and guards.
This is **same-format cross-commit compatibility**, not historical schema migration,
a full application/Socket upgrade, a compiler upgrade or a crash-recovery claim.

When executing from an exported owner with no `.git`, pass `--repository` pointing
to the original local Git repository. It is read-only and must contain both exact
commits with the pinned producer as an ancestor. Moving refs and a different
repository lacking that history are refused. Native CI passes the captured actual
checkout SHA explicitly; the manual consumer default above remains unchanged.


## Coupled native TCP Socket recovery

Select `--socket-transport native-tcp` to run the same six prepared Socket crash
boundaries and fresh verifier processes through real Core TCP sockets. The
native CI gate selects this mode explicitly under both sanitizers; memory mode
remains the manual default and its existing fixtures are preserved.

```sh
PATH=/opt/homebrew/opt/llvm@22/bin:$PATH \
  python3 whatsapp/tests/encrypted_recovery/run.py --odin ../odin \
  --sanitize address --socket-transport native-tcp \
  --report /tmp/owa-encrypted-native-tcp-address.json
# Repeat with --sanitize thread and a distinct report.
```

A separate owned native peer binds127.0.0.1 on an ephemeral port and accepts one
connection. The prepared Socket writes its actual masked WebSocket/Noise frame
through Surf's native Core TCP stream. Only the independent receiver writes the
handoff files, after reading the complete kernel-delivered frame and verifying
its real pairwise Signal distribution and signed group payload. Witness fsync
precedes the peer's handoff marker and positive ACK. The parent waits for actual
peer handoff evidence before killing the sender at the callback-return boundary.

For ACK stages, only that native peer builds and writes the encrypted positive
ACK over TCP; the sender consumes it through public `socket_read`. Pending replay
uses a fresh native peer/process and checks the exact persisted inner ciphertext,
ratchet/key/content/membership/prekey hashes and unchanged store files. ACK without
a caller journal remains unknown and produces no automatic resend.

Every campaign observes twelve accepted native connections: six crash children
and six verifier children. Seven frames are authenticated (four initial sends,
three pending replays), and two peer ACKs are sent/processed. Empty connections
prove that before-send and acknowledged-unknown verifier cases send nothing.
Listener lifetime ends immediately after accept; connection I/O has an absolute
ten-second budget. Readiness/handoff output, packet size and parent deadlines are
bounded. Every native peer reports its explicit socket close, exits normally and
is reaped, with exact child/group cleanup on failures. Negative controls reject
premature ACK claims, bad/blocked peers, missing or duplicated stages, false
handoff/authentication metadata and incomplete cleanup.

This is coupled native-loopback recovery of the prepared Socket subset, not a
standalone TCP smoke relabelled as recovery. Both roles use the same SDK with
synthetic metadata and pre-established WebSocket/Noise transport keys; no full
HTTP upgrade, Noise login, external server ACK, recipient delivery, independent
Signal interoperability, ENOSPC or power-loss qualification is claimed. Local
Darwin execution and future hosted execution must retain their separate receipts.

# Normal message ACK contract review

A1 is an unresolved interoperability question, not a demonstrated runtime defect.
The two current independent implementations disagree. OWA's ordinary successful
message policy matches Whatsmeow's omission of message type/local sender; copying
the Baileys builder would change that policy without proving a server requirement.
No production code or transport/application completion policy changes here.

## Immutable primary evidence

| Implementation | Commit | File and Git blob |
| --- | --- | --- |
| Baileys | `81345beb67ca3fb0eb79a2c20cd4ac24da517929` | `src/Utils/stanza-ack.ts`, `5e2e478fa6548383aef8e7516e9b0345b4f86751` |
| Baileys call sites | same | `src/Socket/messages-recv.ts`, `02d0a584091fc89648eb5869e58b40affb7c99dd` |
| Whatsmeow | `fcb7bdeb35921905b60984025945a571eb8f39b6` | `receipt.go`, `5bba2fe19ef132758c46c7c723a1718e440ef81c` |

The [Baileys builder](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/stanza-ack.ts)
keeps nonempty type and includes the supplied local identity for message ACKs.
Its [caller](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Socket/messages-recv.ts)
supplies the local identity. The independently implemented
[Whatsmeow ACK path](https://github.com/tulir/whatsmeow/blob/fcb7bdeb35921905b60984025945a571eb8f39b6/receipt.go)
omits type for message-class ACKs and supplies no local sender attribute.
Both omit the outbound error attribute for numeric zero. Neither source is a
normative Meta Web protocol contract; Baileys' Web-mirroring comment is its
maintainer's assertion, not independent service acceptance evidence.

Forty-six synthetic vectors execute the unchanged TypeScript builder through
Node's type stripping and the byte-identical extracted Go method through bounded
type/log/transport doubles. This proves attribute-builder behavior only, not the
full upstream parser/encoder, bot-recipient remapping or server interoperability.
Go numeric error versus TypeScript decimal string is recorded separately from
attribute presence. Missing mandatory attributes in these builders do not prove
that the upstream receive parsers accept them. Current omitted and explicit-zero
JavaScript arguments produce equivalent maps; the older baseline optional-argument
caveat does not establish a current discrepancy.

## Tested OWA policy

| Input | Existing output / rejection |
| --- | --- |
| Ordinary message, type absent/empty/nonempty | Exact class/id/to; no type or local from |
| Participant/recipient absent | Omitted |
| Participant/recipient present, including empty | Preserved as present |
| Unavailable message | Preserves present type; adds local from |
| Nonzero outbound error | Decimal error; preserves present type; no local from unless unavailable |
| Numeric zero outbound error | Omitted error |
| Missing or empty id/from | Protocol error before any write |
| ACK transport failure | Terminal Socket error; durable intent/inbox retained; no automatic replay |

The unavailable private-helper fixture with no local identity records an existing
empty sender attribute. It is outside a valid paired-connection setup and is not
claimed interoperable. Empty optional attributes and unavailable/error branches
remain policy questions where references differ. Attribute order is not asserted.
A1 must remain open for a reviewed authoritative policy or separately authorized
service evidence; no speculative RED or protocol fix is fabricated.

The new native tests capture and decode actual masked WebSocket/Noise ACK output,
assert one exact ACK, release/overwrite the input document before inspecting it,
and check unchanged durable state, queues and HTTP-call counts. Separate tests
exercise the maintained receive commit/receipt seam: the inbox is loaded from disk
at each receipt/ACK write, an ACK-specific write failure retains it, destroying the
event leaves it recoverable, and restart returns it until durable caller completion.
Failed inbox save exposes no event/wire; failed caller completion preserves disk
and sends no extra ACK. Completion then suppresses further inbox replay. Transport
ACK, application completion, delivery receipt and read/view/call effects remain
distinct. These seam tests do not claim a complete inbound Signal decrypt oracle.

All 45 package tests pass without sanitizer and with ASan/TSan. Existing negative
ACK/routing cases, disposable recovery campaign (including owned Noise TCP), native
TCP encrypted recovery and public consumer also pass under both sanitizers. An
owned candidate export uses the exact released frontend/Core SDK and pinned
dependency bundle for every primary check. Earlier local-root checks with newer
Core are retained separately and do not substitute for that qualification. Local
Darwin execution is not hosted Linux qualification,
current WhatsApp interoperability or full-stack readiness. No live account,
private session, provider request or external message was used.

The primary SDK is the declared c826 frontend/Core2e8 pairing: 1,100 SDK files
and 280 dependency files are verified before and after execution. The initial
direct cached-SDK recovery setup lacked its declared shared collection and failed
before runtime; that failure is retained. The corrected owned layout uses the
maintained asset installer, changes no SDK/cache source, and passes all checks.

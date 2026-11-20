# Function catalog

This catalog covers **1,284 named functions and bound callbacks** in the WhatsApp repository. Entries follow declaration order within each file. Each links to the implementation and describes its behavior.

| Area | Entries | What it covers |
|---|---:|---|
| [Client library](library.md) | 617 | WhatsApp connection, pairing, addressing, messages, Signal encryption, media, codecs and persistent state. |
| [Tools](tools.md) | 131 | Release checks and upstream protocol review. |
| [Tests and harnesses](tests.md) | 536 | Test assertions, fixtures, synthetic peers, recovery campaigns, subprocess controls and test runners. |

## Running checks

Run `task hooks:install` once per clone to enable the pre-push hook. The hook runs `task check` on each distinct commit at the tip of a ref being pushed. A failing test blocks the push. Run `task check` directly to test uncommitted edits. Both use the local Odin compiler and shared packages. Set `ODIN` and `WEBTOOLS_SHARED` to override their locations.

Each `src/<module>.odin` has one unit test file at `tests/<module>_test.odin`. The protocol watcher pairs each `tools/protocol_watcher/src/<module>.odin` with `tools/protocol_watcher/tests/<module>_test.odin`. `task check` verifies both sets of filenames. End-to-end suites live in `tests/e2e/`. Shared test data and helpers live in `tests/fixtures/`.

- `task test:odin -- --package .` runs the client unit tests against this checkout.
- `task test:odin -- --package e2e` runs all end-to-end suites. Use `--package e2e/encrypted_recovery` to run only the subprocess recovery tests.
- `task test:protocol` runs the watcher's unit and end-to-end suites.
- `task check -- -sanitize:address` and `task check -- -sanitize:thread` run the full suite with instrumentation.

## Publishing the protocol watcher

Run `task protocol:publish` from the checkout after changing the watcher. It uses local Odin and shared packages, Zig to link for Linux x86-64, and an authenticated GitHub CLI with release access to `dvrd/owa`. It publishes the binary, verifies the downloaded copy, and writes the release checksum to `tools/protocol_watcher/linux-amd64.sha256`. Include that file with the source changes in the next push. The daily workflow uses the checksum to select and verify the binary before running the upstream scan and Linear tracking.

## Naming review

The review changed **78 current declarations** where the previous name obscured the subject, the data representation, or an observable action. The [rename table](renames.md) gives each former name and its replacement. Other entries retain their existing names, including framework entry points and methods such as `main`, `setUp` and `__exit__`.

- `verify_whatsapp_server_certificate` authenticates the WhatsApp server during its Noise handshake by checking the pinned trust chain, validity times and the server’s handshake key.
- `socket_request_activation` sends the activation IQ. `socket_handle_activation_response` handles the reply and transitions the socket online.

## Standard library review

The review screened all 1,855 entries present at its start across 111 files. That included 1,397 Odin procedures and callbacks, 440 Python functions and callbacks, and 18 shell functions and jq filters. It removed 15 redundant declarations and added one regression test.

| Area | Changes |
|---|---|
| Client library | Fixed-width fields use `core:encoding/endian`. Decimal login IDs and version components use `core:strconv`. Hashes use `core:crypto/hash` with caller-provided buffers. Device-list searches and key serialization use slice operations and built-in copies. |
| Tools | The review tool uses `slice.equal`, `slice.contains`, stable sorting, JSON value cloning, UTF-8 rune counting and UTF-16 surrogate conversion. |
| Tests and harnesses | Fixtures use standard hashing, integer encoding and slice operations. The protobuf regression test checks cursor position on success, truncation and overflow, including values at the ten-byte limit. |

| Removed declarations | Replacement |
|---|---|
| `write_decimal_u32` | `strconv.write_uint` writes into the existing version buffer. |
| `storage_cpath`, `storage_bytes` | `strings.clone_to_cstring` and `mem.ptr_to_bytes`. |
| `storage_digest` | The shared `sha256` function returns a fixed-size digest from `hash.hash_bytes_to_buffer`. |
| `make_strings`, `string_number` | Built-in `make` and `fmt.aprint`. |
| `strings_equal`, `tokens_equal`, `comments_equal` | `slice.equal` compares the original element types in order. |
| `contains_string`, `sort_strings`, `append_clone` | `slice.contains`, `slice.sort` and `slice.clone`. |
| `clone` in the JSON review tool | `json.clone_value` recursively copies the value. |
| `child_exit`, `native_rename` | `posix._exit` and `posix.rename`. |

Three cases illustrate why the SDK version and the callers matter.

- The protobuf reader and writer implement unsigned LEB128 locally so they also work with Odin distributions that omit `core:encoding/varint`. Size calculation uses `bits.len_u64`.
- The JSON parser used during the review dropped an object member with an empty key. Protocol review reports must preserve that member and reject a repeated empty key. The token parser retains those checks along with the project’s byte, depth and token limits.
- A copied Odin map header can retain an old length when another copy inserts a key. The review tool enumerates and sorts the keys it actually visits. The SDK’s `slice.map_keys` is used for maps whose length is current.

## Coverage

The inventory includes Odin procedures, named local callbacks, native bindings, shell functions and named jq filters embedded in shell scripts. Inline expressions passed as arguments belong to the enclosing entry. The catalog describes the repository’s source files. Token tables, workflow configuration, serialized fixtures and dependencies have no separate entries unless they define executable functions.

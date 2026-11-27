# WhatsApp client library

[Catalog index](README.md) · [Name changes](renames.md)

641 entries across 21 source files. Select a function to open its declaration.

Owa runs Surf’s asynchronous WebSocket session behind its synchronous socket API. Surf resolves the hostname, verifies TLS, upgrades the connection and reassembles WebSocket messages. Owa owns the WhatsApp frame envelope, Noise handshake, certificate pin and transport encryption. One pending read can survive a poll timeout or an HTTP worker wakeup. WhatsApp queries retain their original deadline across unrelated messages.

Use `Socket_Config.tls.roots` to supply a borrowed `^async.Root_Pool`. The default uses platform trust. Keep explicit roots alive through `socket_close`. Set `pool_media_downloads = true` before connecting to reuse a Surf HTTP client on the socket’s async runtime for online media downloads. Each descriptor sets its own ciphertext limit and owa verifies the ciphertext hash, MAC and plaintext hash. Provisioning downloads and custom executors keep their existing paths.

| Source file | Functions |
|---|---:|
| [src/addressing.odin](#file-src-addressing-odin) | 33 |
| [src/ascii.odin](#file-src-ascii-odin) | 5 |
| [src/auth.odin](#file-src-auth-odin) | 41 |
| [src/binary_node.odin](#file-src-binary-node-odin) | 35 |
| [src/chat_history.odin](#file-src-chat-history-odin) | 9 |
| [src/binary_framing.odin](#file-src-binary-framing-odin) | 17 |
| [src/message_connection.odin](#file-src-message-connection-odin) | 2 |
| [src/noise_certificate.odin](#file-src-noise-certificate-odin) | 5 |
| [src/noise_cipher.odin](#file-src-noise-cipher-odin) | 10 |
| [src/noise_handshake.odin](#file-src-noise-handshake-odin) | 19 |
| [src/signal_curve25519.odin](#file-src-signal-curve25519-odin) | 4 |
| [src/contact_sync.odin](#file-src-contact-sync-odin) | 24 |
| [src/contacts.odin](#file-src-contacts-odin) | 5 |
| [src/media.odin](#file-src-media-odin) | 89 |
| [src/pairing.odin](#file-src-pairing-odin) | 64 |
| [src/protobuf.odin](#file-src-protobuf-odin) | 47 |
| [src/receive.odin](#file-src-receive-odin) | 65 |
| [src/send.odin](#file-src-send-odin) | 39 |
| [src/signal.odin](#file-src-signal-odin) | 75 |
| [src/socket.odin](#file-src-socket-odin) | 32 |
| [src/state_store.odin](#file-src-state-store-odin) | 21 |

<a id="file-src-addressing-odin"></a>

## src/addressing.odin

| Function | Behavior |
|---|---|
| [`device_keys_response_decode`](../../src/addressing.odin#L52) | Decode the requested device bundles and verify their signed prekey signatures before returning any bundle. |
| [`device_query_response_validate`](../../src/addressing.odin#L125) | Check the requested users and correlate the reply with the original IQ. |
| [`device_bundle_decode`](../../src/addressing.odin#L148) | Extract the identity and prekeys and verify the signed prekey signature. |
| [`device_bundle_prekey_decode`](../../src/addressing.odin#L206) | Read an optional one-time prekey from a device bundle. |
| [`device_read_fixed_child_bytes`](../../src/addressing.odin#L236) | Read a uniquely named child and require its bytes to have the expected length. |
| [`devices_query_encode`](../../src/addressing.odin#L260) | Encode a user-device lookup as a usync IQ. |
| [`devices_query_nodes_prepare`](../../src/addressing.odin#L324) | Build one usync user node for each requested JID. |
| [`devices_response_decode`](../../src/addressing.odin#L350) | Decode a correlated usync result into remote device entries. |
| [`devices_response_user_validate`](../../src/addressing.odin#L416) | Validate and count one user's device list. |
| [`devices_response_children_validate`](../../src/addressing.odin#L468) | Validate all returned users and count their device entries. |
| [`remote_device_jid`](../../src/addressing.odin#L506) | Format the addressed device's JID in the supplied buffer. |
| [`stanza_id_valid`](../../src/addressing.odin#L539) | Check that a stanza ID contains 1–128 printable, non-space ASCII bytes. |
| [`device_user_jid_valid`](../../src/addressing.odin#L552) | Check the user JID against the supported addressing domains. |
| [`device_response_validate`](../../src/addressing.odin#L570) | Check the IQ sender, request ID, result type and error response. |
| [`device_unique_child`](../../src/addressing.odin#L591) | Find a single matching child and reject duplicate matches. |
| [`device_entry_decode`](../../src/addressing.odin#L614) | Read a device ID, key index and hosted flag from a device node. |
| [`group_metadata_query_encode`](../../src/addressing.odin#L681) | Encode a group metadata IQ with the supplied request ID. |
| [`group_metadata_decode`](../../src/addressing.odin#L714) | Decode group metadata and participants from the matching response. |
| [`group_metadata_participants_copy`](../../src/addressing.odin#L788) | Copy decoded group participants into the caller's output. |
| [`group_metadata_response_group`](../../src/addressing.odin#L801) | Validate the metadata response and select its group node. |
| [`group_metadata_description_decode`](../../src/addressing.odin#L868) | Extract the group's description text and description ID. |
| [`group_jid_valid`](../../src/addressing.odin#L903) | Recognize a supported group JID. |
| [`group_participant_decode`](../../src/addressing.odin#L923) | Read the participant JID, alternate address and role. |
| [`socket_signal_address`](../../src/addressing.odin#L978) | Resolve a JID to its Signal session address using the socket's store. |
| [`socket_record_lid_mapping`](../../src/addressing.odin#L986) | Persist one phone-to-LID mapping and migrate affected records atomically. |
| [`socket_record_group_lid_mappings`](../../src/addressing.odin#L1015) | Persist mappings learned from group participants in one store commit. |
| [`socket_signal_address_store`](../../src/addressing.odin#L1062) | Resolve a Signal address against a specified store, preserving the device ID. |
| [`socket_lid_mapping_stage`](../../src/addressing.odin#L1110) | Stage a phone-to-LID mapping in a candidate store. |
| [`socket_lid_migrate`](../../src/addressing.odin#L1156) | Rekey affected LID records under the resolved phone address and reconcile collisions. |
| [`socket_lid_session_pin_validate`](../../src/addressing.odin#L1204) | Check a migrated session against the pinned remote identity. |
| [`socket_lid_session_archive`](../../src/addressing.odin#L1235) | Decode and archive a displaced session during LID migration. |
| [`socket_lid_record_merge`](../../src/addressing.odin#L1278) | Merge records that resolve to the same address, archiving a displaced session when necessary. |
| [`socket_lid_record_name`](../../src/addressing.odin#L1326) | Construct the destination record name for an address migration. |

<a id="file-src-ascii-odin"></a>

## src/ascii.odin

| Function | Behavior |
|---|---|
| [`is_alpha`](../../src/ascii.odin#L6) | Recognize ASCII letters. |
| [`is_digit`](../../src/ascii.odin#L10) | Recognize ASCII decimal digits. |
| [`is_alphanumeric`](../../src/ascii.odin#L14) | Recognize ASCII letters and decimal digits. |
| [`is_lower`](../../src/ascii.odin#L18) | Recognize lowercase ASCII letters. |
| [`is_hex_upper`](../../src/ascii.odin#L22) | Recognize digits and uppercase A–F. |

<a id="file-src-auth-odin"></a>

## src/auth.odin

| Function | Behavior |
|---|---|
| [`device_credentials_generate`](../../src/auth.odin#L47) | Generate the device identity, Noise credentials and signed prekey. |
| [`device_credentials_validate`](../../src/auth.odin#L78) | Validate the device key pairs and signed prekey signature. |
| [`device_credentials_clear`](../../src/auth.odin#L136) | Erase device credentials from memory. |
| [`device_private_generate`](../../src/auth.odin#L142) | Generate and clamp a private device scalar. |
| [`device_private_valid`](../../src/auth.odin#L148) | Check that the private scalar is nonzero and correctly clamped. |
| [`auth_state_clear`](../../src/auth.odin#L187) | Erase the authentication state. |
| [`auth_state_validate`](../../src/auth.odin#L193) | Validate device credentials and any paired account. |
| [`auth_state_encode`](../../src/auth.odin#L220) | Serialize validated authentication state with its integrity digest. |
| [`auth_account_encode`](../../src/auth.odin#L283) | Write paired-account fields to the authentication snapshot. |
| [`auth_state_decode`](../../src/auth.odin#L310) | Decode and validate credentials and account data before installing them. |
| [`auth_state_header_validate`](../../src/auth.odin#L376) | Check the authentication snapshot header, length and digest. |
| [`auth_account_decode`](../../src/auth.odin#L402) | Read the paired-account portion of an authentication snapshot. |
| [`auth_state_save`](../../src/auth.odin#L468) | Persist encoded authentication state with a durable write. |
| [`auth_state_load`](../../src/auth.odin#L493) | Read a bounded authentication file and decode its state. |
| [`prekey_store_init`](../../src/auth.odin#L601) | Initialize the prekey store for a validated device identity. |
| [`prekey_store_clear`](../../src/auth.odin#L630) | Erase stored prekeys and their metadata. |
| [`prekey_store_get`](../../src/auth.odin#L636) | Look up a stored one-time prekey by ID. |
| [`prekey_store_generate`](../../src/auth.odin#L650) | Check capacity and append newly generated prekeys. |
| [`prekey_upload_prepare`](../../src/auth.odin#L667) | Prepare a batch of prekeys and bind it to an upload request. |
| [`prekey_upload_retry`](../../src/auth.odin#L727) | Bind the pending prekey batch to a new request for retry. |
| [`prekey_upload_encode`](../../src/auth.odin#L751) | Encode the pending public prekeys in an upload IQ. |
| [`prekey_upload_nodes_prepare`](../../src/auth.odin#L804) | Build the per-key child nodes for a prekey upload. |
| [`prekey_upload_validate`](../../src/auth.odin#L832) | Check the pending batch and verify its owner before encoding. |
| [`prekey_upload_handle_response`](../../src/auth.odin#L855) | Apply the matching upload response to the pending batch. |
| [`prekey_count_query_encode`](../../src/auth.odin#L892) | Encode an IQ asking how many prekeys remain on the server. |
| [`decode_prekey_count_response`](../../src/auth.odin#L914) | Parse the prekey count from a matching server response. |
| [`prekey_store_encode`](../../src/auth.odin#L961) | Serialize the prekey store and append its integrity digest. |
| [`prekey_store_decode`](../../src/auth.odin#L1005) | Decode a prekey snapshot and verify its keys and owner. |
| [`prekey_store_header_validate`](../../src/auth.odin#L1073) | Check a serialized prekey store's header and digest. |
| [`prekey_store_save`](../../src/auth.odin#L1096) | Serialize and durably persist the prekey store. |
| [`prekey_store_load`](../../src/auth.odin#L1127) | Read and validate a bounded prekey snapshot for this device. |
| [`prekey_store_validate`](../../src/auth.odin#L1160) | Validate the store's counters, pending request and key records. |
| [`prekey_store_keys_validate`](../../src/auth.odin#L1204) | Check each stored prekey and its derived public key. |
| [`prekey_owner_validate`](../../src/auth.odin#L1257) | Check that device credentials match the store's recorded owner. |
| [`prekey_generation_validate`](../../src/auth.odin#L1271) | Check the requested batch size, ID range and available space. |
| [`prekey_generate_append`](../../src/auth.odin#L1295) | Generate key pairs and append them with sequential IDs. |
| [`prekey_request_id_valid`](../../src/auth.odin#L1309) | Check the permitted length and bytes of a prekey request ID. |
| [`prekey_set_request_id`](../../src/auth.odin#L1323) | Replace the pending request ID, clearing the previous bytes. |
| [`prekey_response_validate`](../../src/auth.odin#L1331) | Validate the ID, sender and outcome of a prekey IQ response. |
| [`encode_prekey_id_u24`](../../src/auth.odin#L1376) | Encode a prekey ID as three big-endian bytes. |
| [`prekey_store_remove_consumed`](../../src/auth.odin#L1382) | Erase a consumed one-time prekey and remove its entry. |

<a id="file-src-binary-node-odin"></a>

## src/binary_node.odin

| Function | Behavior |
|---|---|
| [`binary_document_destroy`](../../src/binary_node.odin#L78) | Release the decoded tree, its payload and document allocations. |
| [`binary_node_encode`](../../src/binary_node.odin#L94) | Encode an uncompressed binary node into the supplied buffer. |
| [`binary_node_decode`](../../src/binary_node.odin#L133) | Decode a binary stanza into an owning document. |
| [`binary_document_decompress`](../../src/binary_node.odin#L168) | Inflate a compressed stanza within the document's size limit. |
| [`binary_document_payload_copy`](../../src/binary_node.odin#L202) | Copy or decompress the stanza payload according to its flags. |
| [`binary_document_tree_decode`](../../src/binary_node.odin#L225) | Build the document's node tree with an arena allocator. |
| [`node_attr`](../../src/binary_node.odin#L260) | Look up an attribute by key and report whether it exists. |
| [`node_child`](../../src/binary_node.odin#L270) | Find a child node with the requested tag. |
| [`binary_write_byte`](../../src/binary_node.odin#L290) | Write one byte and advance the binary writer. |
| [`binary_write_bytes`](../../src/binary_node.odin#L310) | Append bytes while checking capacity and overlap. |
| [`binary_write_integer`](../../src/binary_node.odin#L338) | Write a fixed-width big-endian integer. |
| [`binary_write_list`](../../src/binary_node.odin#L349) | Write a list header sized for its element count. |
| [`binary_write_length`](../../src/binary_node.odin#L365) | Choose and write the binary length tag and length bytes. |
| [`binary_write_node`](../../src/binary_node.odin#L378) | Write the tag, attributes and content of a node recursively. |
| [`binary_write_node_validate`](../../src/binary_node.odin#L417) | Check node shape, limits and depth before writing. |
| [`binary_write_string`](../../src/binary_node.odin#L472) | Choose a wire representation for text, tokens and JIDs. |
| [`binary_write_token`](../../src/binary_node.odin#L517) | Encode text using its single- or double-byte dictionary entry. |
| [`binary_write_packed_string`](../../src/binary_node.odin#L540) | Pack eligible digits or hex characters into nibbles. |
| [`binary_write_jid`](../../src/binary_node.odin#L591) | Encode the user, server and optional device portions of a JID. |
| [`binary_pack_char`](../../src/binary_node.odin#L643) | Map a packed-string character to its four-bit value. |
| [`binary_read_bytes`](../../src/binary_node.odin#L666) | Take a bounded slice and advance the binary reader. |
| [`binary_read_byte`](../../src/binary_node.odin#L686) | Consume one byte from the binary reader. |
| [`binary_read_integer`](../../src/binary_node.odin#L695) | Read a fixed-width big-endian integer. |
| [`binary_read_length`](../../src/binary_node.odin#L703) | Decode a binary payload length from its tag. |
| [`binary_read_list_size`](../../src/binary_node.odin#L722) | Read the number of entries in a binary list. |
| [`binary_read_node`](../../src/binary_node.odin#L741) | Decode a node's tag, attributes and optional content recursively. |
| [`binary_read_attribute_keys_validate`](../../src/binary_node.odin#L805) | Check a decoded attribute list for duplicate keys. |
| [`binary_read_attributes`](../../src/binary_node.odin#L837) | Read and validate a node's key/value attribute pairs. |
| [`binary_read_content`](../../src/binary_node.odin#L875) | Decode child nodes, bytes or text according to the content tag. |
| [`binary_read_string`](../../src/binary_node.odin#L941) | Resolve a wire string from tokens, packed bytes, JIDs or raw text. |
| [`binary_read_device_jid`](../../src/binary_node.odin#L998) | Decode a device-addressed JID from its wire fields. |
| [`binary_unpack_bytes`](../../src/binary_node.odin#L1010) | Expand packed nibbles into output characters. |
| [`binary_read_packed_string`](../../src/binary_node.odin#L1048) | Read the packed string length and unpack its characters. |
| [`binary_read_jid_pair`](../../src/binary_node.odin#L1088) | Read a user/server JID pair and join its components. |
| [`binary_reader_join_jid`](../../src/binary_node.odin#L1107) | Format decoded JID components into document-owned storage. |

<a id="file-src-chat-history-odin"></a>

## src/chat_history.odin

| Function | Behavior |
|---|---|
| [`decode_chat_history_cursor`](../../src/chat_history.odin#L26) | Read the direction, original timestamp and message ID from a stored chat cursor. |
| [`store_chat_history_cursor`](../../src/chat_history.odin#L39) | Keep the latest timestamped private message reference for the chat. |
| [`latest_chat_history_cursor`](../../src/chat_history.odin#L71) | Find the newest usable message reference across the chat’s phone number, LID and legacy sent records. |
| [`chat_history_request_encode`](../../src/chat_history.odin#L123) | Encode the requested private chat, page size and optional message boundary for the primary phone. |
| [`collect_chat_history_notification`](../../src/chat_history.odin#L177) | Collect bounded on-demand notifications matching the active request ID. |
| [`chat_history_alternate_jid`](../../src/chat_history.odin#L206) | Resolve the alternate private chat address using the linked account’s mappings or saved contact. |
| [`decode_chat_history_message`](../../src/chat_history.odin#L220) | Read a historical message key and body and preserve its original direction and timestamp. |
| [`decode_chat_history_chunk`](../../src/chat_history.odin#L263) | Validate the selected conversation and collect distinct messages within the page limits. |
| [`socket_fetch_chat_history`](../../src/chat_history.odin#L336) | Request a private conversation page from the primary phone and return owned messages. |

<a id="file-src-binary-framing-odin"></a>

## src/binary_framing.odin

| Function | Behavior |
|---|---|
| [`frame_encode_len`](../../src/binary_framing.odin#L20) | Encode a frame length in the three-byte WhatsApp header. |
| [`frame_decode_len`](../../src/binary_framing.odin#L36) | Decode the three-byte big-endian frame length. |
| [`frame_encode`](../../src/binary_framing.odin#L40) | Write a length-prefixed frame. |
| [`frame_decode`](../../src/binary_framing.odin#L58) | Read a complete length-prefixed frame from buffered bytes. |
| [`frame_reader_feed`](../../src/binary_framing.odin#L82) | Append received bytes to the bounded frame reader. |
| [`frame_reader_peek`](../../src/binary_framing.odin#L96) | Inspect the next frame without advancing the reader. |
| [`frame_reader_consume`](../../src/binary_framing.odin#L106) | Discard consumed bytes and retain the unread suffix. |
| [`frame_transport_init`](../../src/binary_framing.odin#L170) | Initialize framed transport around the supplied WebSocket. |
| [`frame_transport_send`](../../src/binary_framing.odin#L207) | Frame the payload and send it as a binary WebSocket message. |
| [`frame_transport_receive`](../../src/binary_framing.odin#L267) | Assemble and deliver the next complete WhatsApp frame. |
| [`frame_transport_header_receive`](../../src/binary_framing.odin#L326) | Collect the frame header and allocate space for its payload. |
| [`frame_transport_clear`](../../src/binary_framing.odin#L357) | Release the transport's pending buffers and reset its state. |
| [`frame_transport_validate`](../../src/binary_framing.odin#L367) | Check whether the transport is initialized and usable. |
| [`frame_transport_next_message`](../../src/binary_framing.odin#L383) | Read the next binary WebSocket message into the transport. |
| [`frame_transport_read_fail`](../../src/binary_framing.odin#L408) | Translate a WebSocket read failure into a frame transport error. |
| [`frame_transport_deliver`](../../src/binary_framing.odin#L428) | Copy a completed frame into the caller's destination. |
| [`frame_transport_fail`](../../src/binary_framing.odin#L450) | Record a terminal frame transport failure. |

<a id="file-src-message-connection-odin"></a>

## src/message_connection.odin

| Function | Behavior |
|---|---|
| [`message_connection_open`](../../src/message_connection.odin#L109) | Open a Surf WebSocket session and expose whole binary messages to owa. |
| [`message_connection_close`](../../src/message_connection.odin#L215) | Close the session and wait for its pending callbacks. |

<a id="file-src-noise-certificate-odin"></a>

## src/noise_certificate.odin

| Function | Behavior |
|---|---|
| [`verify_whatsapp_server_certificate`](../../src/noise_certificate.odin#L65) | Authenticate the WhatsApp server's certificate chain and handshake key at the current time. |
| [`verify_whatsapp_server_certificate_at`](../../src/noise_certificate.odin#L74) | Verify the server certificate against the pinned WhatsApp root at a supplied time. |
| [`verify_certificate_chain_against_root`](../../src/noise_certificate.odin#L87) | Verify issuer linkage, both signatures, the leaf key and certificate validity against a supplied root. |
| [`decode_and_validate_certificate_details`](../../src/noise_certificate.odin#L146) | Decode and validate the required fields of an intermediate or leaf certificate. |
| [`check_certificate_validity_at`](../../src/noise_certificate.odin#L189) | Check that the supplied time falls within the certificate's validity interval. |

<a id="file-src-noise-cipher-odin"></a>

## src/noise_cipher.odin

| Function | Behavior |
|---|---|
| [`noise_init`](../../src/noise_cipher.odin#L51) | Initialize the Noise transcript with the protocol header and ephemeral key. |
| [`noise_mix_hash`](../../src/noise_cipher.odin#L72) | Mix new handshake bytes into the transcript hash. |
| [`noise_mix_key`](../../src/noise_cipher.odin#L92) | Derive fresh handshake encryption and chaining keys. |
| [`noise_split`](../../src/noise_cipher.odin#L119) | Derive separate read and write keys for the transport phase. |
| [`noise_encrypt`](../../src/noise_cipher.odin#L144) | Authenticate and encrypt a handshake or transport payload. |
| [`noise_decrypt`](../../src/noise_cipher.odin#L192) | Authenticate and decrypt a handshake or transport payload. |
| [`noise_clear`](../../src/noise_cipher.odin#L266) | Erase Noise keys, counters and transcript state. |
| [`noise_nonce`](../../src/noise_cipher.odin#L272) | Encode the message counter into the 12-byte Noise nonce. |
| [`noise_state_validate`](../../src/noise_cipher.odin#L278) | Check the Noise phase and any previously recorded failure. |
| [`noise_fail`](../../src/noise_cipher.odin#L290) | Erase Noise state and record its terminal error. |

<a id="file-src-noise-handshake-odin"></a>

## src/noise_handshake.odin

| Function | Behavior |
|---|---|
| [`noise_credentials_generate`](../../src/noise_handshake.odin#L81) | Generate a fresh static Noise credential for a client. |
| [`client_init`](../../src/noise_handshake.odin#L91) | Bind credentials and an upgraded WebSocket to a new Noise client. |
| [`client_handshake`](../../src/noise_handshake.odin#L149) | Complete the WhatsApp handshake and install transport keys. |
| [`client_handshake_hello_send`](../../src/noise_handshake.odin#L203) | Encode and send ClientHello with the client's ephemeral public key. |
| [`client_handshake_server_read`](../../src/noise_handshake.odin#L218) | Receive and decode the ServerHello frame. |
| [`client_noise_mix_dh`](../../src/noise_handshake.odin#L256) | Mix an X25519 shared secret into the handshake chaining key. |
| [`client_handshake_server_static_decrypt`](../../src/noise_handshake.odin#L273) | Decrypt the server's static key and mix the next handshake secret. |
| [`client_decrypt_and_verify_server_certificate`](../../src/noise_handshake.odin#L294) | Decrypt the server's certificate payload and invoke the configured verifier. |
| [`client_handshake_static_send_prepare`](../../src/noise_handshake.odin#L325) | Encrypt the client's static key and mix its handshake secret. |
| [`client_handshake_finish_send`](../../src/noise_handshake.odin#L338) | Frame and send the encoded ClientFinish. |
| [`client_handshake_payload_send`](../../src/noise_handshake.odin#L361) | Encrypt the client payload and send it in ClientFinish. |
| [`client_handshake_exchange`](../../src/noise_handshake.odin#L383) | Sequence ClientHello, server authentication and ClientFinish. |
| [`client_close`](../../src/noise_handshake.odin#L427) | Release transport buffers, erase secrets and close the WebSocket. |
| [`client_fail`](../../src/noise_handshake.odin#L448) | Record the terminal client error, erase keys and close the transport. |
| [`client_secret_keys_clear`](../../src/noise_handshake.odin#L459) | Zero the static and ephemeral client private keys. |
| [`client_finish_wire_size`](../../src/noise_handshake.odin#L464) | Calculate the encoded size of ClientFinish before sending. |
| [`client_write`](../../src/noise_handshake.odin#L477) | Encrypt and send one application payload on an established client. |
| [`client_read`](../../src/noise_handshake.odin#L519) | Receive and authenticate one encrypted application payload. |
| [`client_encrypted_frame_receive`](../../src/noise_handshake.odin#L562) | Read an encrypted transport frame and validate its size. |

<a id="file-src-signal-curve25519-odin"></a>

## src/signal_curve25519.odin

| Function | Behavior |
|---|---|
| [`signal_curve_public`](../../src/signal_curve25519.odin#L47) | Derive the X25519 public key for a private scalar. |
| [`signal_curve_sign`](../../src/signal_curve25519.odin#L61) | Sign bytes with the Signal Curve25519 signature scheme. |
| [`signal_curve_verify`](../../src/signal_curve25519.odin#L153) | Verify a Signal Curve25519 signature against the public key. |
| [`signal_curve_edwards_public`](../../src/signal_curve25519.odin#L203) | Convert a Montgomery public key to the Edwards representation used for signature verification. |

<a id="file-src-contact-sync-odin"></a>

## src/contact_sync.odin

| Function | Behavior |
|---|---|
| [`read_unique_protobuf_field`](../../src/contact_sync.odin#L33) | Read an optional singular field of the specified wire type and reject duplicate or malformed fields. |
| [`store_contact_sync_key_share`](../../src/contact_sync.odin#L58) | Store the app-state keys delivered in an authenticated protocol message from the linked account. |
| [`derive_contact_mutation_keys`](../../src/contact_sync.odin#L101) | Derive the authentication and encryption keys for a mutation, or record which key ID the primary device must supply. |
| [`update_contact_collection_hash`](../../src/contact_sync.odin#L131) | Add or subtract the expanded value MAC from the contact collection hash. |
| [`apply_contact_action`](../../src/contact_sync.odin#L150) | Stage the saved-name change or deletion addressed by a contact mutation index. |
| [`remove_saved_contact_aliases`](../../src/contact_sync.odin#L222) | Remove saved records identifying either contact JID while retaining the selected primary entry. |
| [`apply_contact_record`](../../src/contact_sync.odin#L236) | Verify a record, decrypt its action and stage the resulting changes and integrity hashes. |
| [`download_contact_sync_blob`](../../src/contact_sync.odin#L308) | Read an external app-state blob reference and download its authenticated plaintext. |
| [`apply_authenticated_contact_batch`](../../src/contact_sync.odin#L329) | Apply a snapshot or incremental patch to a candidate store and verify its version and collection signatures. |
| [`apply_contact_collection`](../../src/contact_sync.odin#L436) | Decode the snapshot and patches in one server collection response. |
| [`rebase_contact_collection`](../../src/contact_sync.odin#L494) | Merge the authenticated address book and index MACs into the latest socket state after processing concurrent network events. |
| [`socket_sync_contacts`](../../src/contact_sync.odin#L521) | Fetch and persist authenticated contact pages or request a missing key from the primary device. |
| [`socket_request_contact_key`](../../src/contact_sync.odin#L677) | Send the missing key ID to the primary device in a durably staged pairwise-encrypted peer message. |
| [`socket_note_contact_update`](../../src/contact_sync.odin#L712) | Mark the address book incomplete when a server notification announces a newer version. |
| [`store_historical_contact_profiles`](../../src/contact_sync.odin#L770) | Import profile names from a history notification or persist its external reference for the socket loop. |
| [`download_contact_history`](../../src/contact_sync.odin#L790) | Copy a history reference across socket reads and fetch its authenticated compressed content. |
| [`socket_import_pending_contact_history`](../../src/contact_sync.odin#L800) | Download one persisted profile-history reference and atomically import it into the current store. |
| [`contact_history_media`](../../src/contact_sync.odin#L823) | Read the media key, path, size and hashes from an external contact-history reference. |
| [`decompress_history_chunk`](../../src/contact_sync.odin#L844) | Inflate a complete compressed history chunk into a caller-sized buffer. |
| [`import_compressed_contact_profiles`](../../src/contact_sync.odin#L857) | Decompress a push-name history chunk and persist previously unknown profile names. |
| [`download_contact_media`](../../src/contact_sync.odin#L899) | Download and authenticate a bounded contact sync or history payload with an optional declared length. |
| [`contact_value_mac`](../../src/contact_sync.odin#L984) | Authenticate an encrypted contact mutation with its operation and app-state key identifier. |
| [`encode_contact_add_patch`](../../src/contact_sync.odin#L1000) | Encode and sign a saved contact update against the current address-book hash and version. |
| [`socket_add_contact`](../../src/contact_sync.odin#L1096) | Create a saved WhatsApp contact by phone-number JID and verify its name through the linked session. |

<a id="file-src-contacts-odin"></a>

## src/contacts.odin

| Function | Behavior |
|---|---|
| [`contact_sync_status`](../../src/contacts.odin#L17) | Read whether the linked account has completed its last contact sync. |
| [`decode_saved_contact`](../../src/contacts.odin#L23) | Split a saved name record into its full name, first name and alternate JID. |
| [`contact_by_jid`](../../src/contacts.odin#L46) | Look up a contact by bare JID or its saved alternate and return the saved and profile names separately. |
| [`search_contact_jids`](../../src/contacts.odin#L78) | Return ordered JIDs whose owner-saved names contain the case-insensitive query, together with sync status. |
| [`contact_name_valid`](../../src/contacts.odin#L137) | Validate the UTF-8, length and separator constraints of a stored or queried name. |

<a id="file-src-media-odin"></a>

## src/media.odin

For an incoming private voice note or audio attachment, decode the received
`Socket_Message.protobuf` with `media_message_decode` and check for `.Audio`.
The MIME type identifies the original format, and `voice_note` indicates a
push-to-talk recording. Check `file_length` against `DEFAULT_MAX_MEDIA_SIZE`
before allocating a destination. Pass the original message and buffer to
`socket_download_media` and write the returned bytes after success.

| Function | Behavior |
|---|---|
| [`media_keys_clear`](../../src/media.odin#L91) | Erase derived media keys. |
| [`media_metadata_clear`](../../src/media.odin#L97) | Erase media metadata including the file key. |
| [`media_key_generate`](../../src/media.odin#L103) | Generate a random key for one media file. |
| [`media_keys_derive`](../../src/media.odin#L113) | Derive the IV, encryption key and MAC key for the media type. |
| [`media_encrypt`](../../src/media.odin#L155) | Encrypt a complete file and produce its authenticated download metadata. |
| [`media_decrypt`](../../src/media.odin#L230) | Verify and decrypt a complete encrypted media file. |
| [`media_ciphertext_authenticate`](../../src/media.odin#L295) | Check the encrypted file digest and authentication tag. |
| [`media_cbc_decrypt_blocks`](../../src/media.odin#L317) | Decrypt the media payload one AES-CBC block at a time. |
| [`media_plaintext_validate`](../../src/media.odin#L338) | Check decrypted size and plaintext digest against the message metadata. |
| [`compute_media_authentication_tag`](../../src/media.odin#L371) | Compute the media authentication tag over the IV and ciphertext. |
| [`media_metadata_from_message`](../../src/media.odin#L441) | Extract and validate decryption metadata from a media message. |
| [`media_download_url`](../../src/media.odin#L472) | Select the canonical CDN URL or build it from a validated direct path. |
| [`media_message_encode`](../../src/media.odin#L523) | Serialize an image or document message in its protobuf envelope. |
| [`media_message_decode`](../../src/media.odin#L551) | Decode supported media fields from a WhatsApp message. |
| [`decode_audio_message`](../../src/media.odin#L627) | Decode audio attachments and voice notes, including their duration, MIME type, CDN path, encryption key, and hashes. |
| [`media_message_field_known`](../../src/media.odin#L702) | Recognize the fields supported for the selected media type. |
| [`media_message_integer_decode`](../../src/media.odin#L729) | Read numeric media properties such as file length and timestamp. |
| [`media_message_bytes_decode`](../../src/media.odin#L759) | Assign a bytes or nested-context field to the decoded media. |
| [`media_message_string_decode`](../../src/media.odin#L804) | Validate and read text properties for the selected media type. |
| [`reaction_message_encode`](../../src/media.odin#L838) | Encode a reaction and its target message key. |
| [`reaction_message_decode`](../../src/media.odin#L862) | Decode a reaction and its target message key. |
| [`reaction_message_field_decode`](../../src/media.odin#L906) | Decode one reaction field and check its type. |
| [`reaction_checkmark_encode`](../../src/media.odin#L949) | Build the predefined checkmark reaction to a target message. |
| [`media_error_from_protobuf_writer`](../../src/media.odin#L974) | Translate protobuf writer errors into media errors. |
| [`media_emit_envelope`](../../src/media.odin#L1003) | Write the outer WhatsApp message field containing the media body. |
| [`media_emit_body`](../../src/media.odin#L1025) | Write the fields of an image or document message. |
| [`media_emit_kind_validate`](../../src/media.odin#L1068) | Check that the supplied properties are valid for the selected media type. |
| [`media_emit_bytes_fields`](../../src/media.odin#L1089) | Write binary media fields such as keys and file digests. |
| [`media_emit_integer_context_fields`](../../src/media.odin#L1121) | Write numeric media properties and any nested context. |
| [`media_emit_context`](../../src/media.odin#L1167) | Write mentions, quotes and other supported media context fields. |
| [`reaction_emit_envelope`](../../src/media.odin#L1197) | Write the outer message containing a reaction. |
| [`reaction_emit_body`](../../src/media.odin#L1214) | Write the reaction target, text and timestamp. |
| [`media_emit_message_key`](../../src/media.odin#L1247) | Serialize the remote JID, stanza ID and sender information for a message key. |
| [`media_extract_content`](../../src/media.odin#L1265) | Locate the requested content inside a supported message envelope. |
| [`media_extract_wrapper`](../../src/media.odin#L1324) | Descend through a wrapped message to locate supported content. |
| [`media_context_decode`](../../src/media.odin#L1369) | Decode the context attached to a media message. |
| [`decode_reaction_target_message_key`](../../src/media.odin#L1424) | Decode a protobuf message key identifying the target stanza. |
| [`media_validate_protobuf`](../../src/media.odin#L1479) | Check that a byte slice consists of readable protobuf fields. |
| [`media_http_native`](../../src/media.odin#L1509) | Execute a media HTTP request using the native network client. |
| [`media_connection_query_encode`](../../src/media.odin#L1540) | Encode an IQ requesting media connection credentials and hosts. |
| [`media_connection_decode`](../../src/media.odin#L1567) | Parse upload authorization, expiry and host limits from the media connection result. |
| [`media_connection_node_decode`](../../src/media.odin#L1618) | Validate the media connection IQ and select its media node. |
| [`media_connection_hosts_validate`](../../src/media.odin#L1669) | Validate and count candidate media upload hosts. |
| [`read_media_host_upload_limit`](../../src/media.odin#L1696) | Read a media host's maximum permitted content length. |
| [`media_upload_url`](../../src/media.odin#L1707) | Build the upload endpoint from the host, encrypted hash and authorization. |
| [`media_upload_auth_encode`](../../src/media.odin#L1778) | Percent-encode the upload authorization for the query string. |
| [`media_upload_response_decode`](../../src/media.odin#L1813) | Decode the upload result and validate its URL and direct path. |
| [`media_upload_json_depth_validate`](../../src/media.odin#L1874) | Bound JSON nesting before parsing a media upload response. |
| [`media_upload`](../../src/media.odin#L1921) | Try eligible upload hosts within the overall time budget. |
| [`media_upload_input_validate`](../../src/media.odin#L2022) | Check the upload inputs, metadata and encrypted payload digest. |
| [`media_upload_exchange`](../../src/media.odin#L2051) | Send an upload to one host and parse its response. |
| [`media_download`](../../src/media.odin#L2093) | Fetch the encrypted media, authenticate it and decrypt into the output. |
| [`fetch_media_ciphertext`](../../src/media.odin#L2131) | Fetch bounded media ciphertext from a validated CDN URL and check the HTTP status. |
| [`media_download_settings`](../../src/media.odin#L2181) | Validate download bounds and prepare HTTP settings. |
| [`media_request_id_valid`](../../src/media.odin#L2201) | Check a media IQ request ID's length and UTF-8 encoding. |
| [`media_hostname_valid`](../../src/media.odin#L2205) | Validate the labels of a media hostname. |
| [`media_retry_request_encode`](../../src/media.odin#L2255) | Generate a nonce and encode an encrypted media retry request. |
| [`media_retry_request_with_nonce`](../../src/media.odin#L2275) | Encrypt a retry request using the supplied nonce and derived key. |
| [`media_retry_receipt_encode`](../../src/media.odin#L2322) | Build the retry receipt stanza with its encrypted payload. |
| [`media_retry_request_validate`](../../src/media.odin#L2373) | Check the target message, owner JID and fields of a retry request. |
| [`media_retry_event_decode`](../../src/media.odin#L2393) | Decode a media retry notification or server error. |
| [`media_retry_event_route_validate`](../../src/media.odin#L2450) | Validate the notification's routing and its retry children. |
| [`media_retry_decrypt`](../../src/media.odin#L2509) | Authenticate and decrypt a media retry response. |
| [`derive_media_retry_key`](../../src/media.odin#L2579) | Derive the AES-GCM retry key from the file's media key. |
| [`media_retry_notification_decode`](../../src/media.odin#L2591) | Read the result, stanza ID and refreshed direct path from retry data. |
| [`socket_http_execute`](../../src/media.odin#L2701) | Execute an HTTP job while the socket continues processing events. |
| [`socket_media_upload_http`](../../src/media.odin#L2732) | Upload media with the socket's HTTP configuration and event handling. |
| [`socket_media_download_http`](../../src/media.odin#L2774) | Download media using the socket and the appropriate HTTP execution path. |
| [`socket_media_download_direct`](../../src/media.odin#L2869) | Run the direct media download for the supplied job. |
| [`socket_http_worker`](../../src/media.odin#L2879) | Dispatch an HTTP worker job and publish its completion. |
| [`socket_http_worker_execute`](../../src/media.odin#L2927) | Execute one worker request with cancellation checks. |
| [`socket_http_run`](../../src/media.odin#L2959) | Run the worker while pumping the socket and join it on exit. |
| [`socket_media_retry_enqueue`](../../src/media.odin#L3022) | Queue an owning copy of a retry notification for later correlation. |
| [`socket_http_event_process`](../../src/media.odin#L3061) | Preserve messages and retry notifications received during HTTP work. |
| [`socket_send_image`](../../src/media.odin#L3079) | Encrypt, upload and send a group image with its caption. |
| [`socket_send_document`](../../src/media.odin#L3092) | Encrypt, upload and send a group document with its filename. |
| [`socket_send_reaction`](../../src/media.odin#L3116) | Encode and send a group reaction to the target message. |
| [`socket_send_media`](../../src/media.odin#L3155) | Validate a media send, reuse stored intent if possible, then encrypt, upload and send. |
| [`socket_media_existing_send`](../../src/media.odin#L3234) | Check whether a prior send can satisfy this media request and message ID. |
| [`socket_media_send_validate`](../../src/media.odin#L3310) | Validate the destination and media properties before starting a send. |
| [`socket_media_upload`](../../src/media.odin#L3350) | Request upload credentials and upload the encrypted file. |
| [`socket_media_message_send`](../../src/media.odin#L3404) | Encode uploaded metadata and dispatch the group message. |
| [`socket_download_media`](../../src/media.odin#L3466) | Download media from a received message and recover an expired location when supported. |
| [`socket_media_retry_send`](../../src/media.odin#L3525) | Send an encrypted retry receipt for the requested media. |
| [`socket_media_download_recover`](../../src/media.odin#L3550) | Obtain a refreshed direct path and retry the authenticated download. |
| [`socket_media_owner_jid`](../../src/media.odin#L3638) | Resolve the account's owner JID for a media retry receipt. |
| [`socket_media_wait_retry`](../../src/media.odin#L3676) | Wait for the media retry notification matching the stanza ID. |
| [`socket_media_retry_event_read`](../../src/media.odin#L3744) | Poll for socket events within the retry deadline. |
| [`socket_media_notification_open`](../../src/media.odin#L3777) | Validate the retry notification and decrypt its response. |

<a id="file-src-pairing-odin"></a>

## src/pairing.odin

| Function | Behavior |
|---|---|
| [`default_client_payload_config`](../../src/pairing.odin#L154) | Construct the default device and browser profile for a WhatsApp client payload. |
| [`session_init`](../../src/pairing.odin#L163) | Initialize a session after validating its client, pairing settings and stored credentials. |
| [`session_start`](../../src/pairing.odin#L212) | Checkpoint credentials, build the client payload and start the authenticated handshake. |
| [`session_read`](../../src/pairing.odin#L241) | Read a client payload and dispatch its session event. |
| [`session_process`](../../src/pairing.odin#L264) | Decode an incoming stanza and advance the login or pairing session. |
| [`session_node_observe`](../../src/pairing.odin#L319) | Notify the observer of an incoming node and its acknowledgement class. |
| [`session_stream_ack_class`](../../src/pairing.odin#L345) | Classify acknowledgements present in a stream node. |
| [`session_ack_class`](../../src/pairing.odin#L384) | Map a stanza's class attribute to a protocol acknowledgement class. |
| [`session_stream_error`](../../src/pairing.odin#L424) | Translate a stream error into a session event or terminal failure. |
| [`session_login_accept`](../../src/pairing.odin#L441) | Accept a successful login and clear temporary pairing material. |
| [`session_pair_device`](../../src/pairing.odin#L453) | Handle a pair-device request, send its reply and emit the first QR code. |
| [`session_pair_success`](../../src/pairing.odin#L485) | Verify pairing success, checkpoint the account and send its signature reply. |
| [`session_tick`](../../src/pairing.odin#L515) | Drive keepalives, pairing timeouts and QR rotation at the supplied time. |
| [`session_close`](../../src/pairing.odin#L560) | Release session resources, erase pairing material and close the client. |
| [`session_payload_encode`](../../src/pairing.odin#L581) | Build a registration or login payload for the current credentials. |
| [`session_checkpoint`](../../src/pairing.odin#L618) | Save authentication state to the configured checkpoint path. |
| [`session_can_receive`](../../src/pairing.odin#L630) | Check whether the current session phase permits reads. |
| [`session_state_error`](../../src/pairing.odin#L643) | Return the stored failure or an invalid-session-state error. |
| [`session_fail`](../../src/pairing.odin#L651) | Mark the session failed and release its transport and temporary data. |
| [`session_send_keepalive_ping`](../../src/pairing.odin#L662) | Encode and send a keepalive ping IQ. |
| [`pairing_node_child`](../../src/pairing.odin#L762) | Find a tagged child in the pairing stanza. |
| [`pairing_jid_decode`](../../src/pairing.odin#L776) | Parse a supported user JID into numeric user and device components. |
| [`pairing_qr_format_valid`](../../src/pairing.odin#L844) | Check whether the QR format is supported. |
| [`pairing_qr_companion_type`](../../src/pairing.odin#L850) | Map a browser or platform name to the companion type in a linked-device QR. |
| [`pairing_qr_encode`](../../src/pairing.odin#L873) | Encode the pairing reference and public credential fields as QR text. |
| [`pairing_device_handle`](../../src/pairing.odin#L929) | Validate a pair-device stanza, load its references and prepare an IQ reply. |
| [`pairing_refs_decode`](../../src/pairing.odin#L992) | Extract and validate the QR references from a pair-device stanza. |
| [`pairing_qr_next`](../../src/pairing.odin#L1020) | Emit the next pairing reference as a QR and update its expiry. |
| [`pairing_qr_clear`](../../src/pairing.odin#L1068) | Erase outstanding pairing references and QR state. |
| [`pairing_success_handle`](../../src/pairing.odin#L1076) | Authenticate a pairing-success stanza and construct its signed reply. |
| [`pairing_success_stanza_decode`](../../src/pairing.odin#L1131) | Validate the pairing-success envelope and select its identity and device nodes. |
| [`pairing_success_hmac_decode`](../../src/pairing.odin#L1163) | Decode the identity wrapper and authenticate its HMAC. |
| [`pairing_success_signed_identity_decode`](../../src/pairing.odin#L1200) | Decode the signed identity and its embedded device details. |
| [`pairing_success_metadata_decode`](../../src/pairing.odin#L1231) | Read the paired device's JID and optional business/platform metadata. |
| [`pairing_success_signatures_prepare`](../../src/pairing.odin#L1267) | Verify the account signature and sign the new device identity. |
| [`pairing_success_reply_encode`](../../src/pairing.odin#L1308) | Encode the pair-device-sign IQ result. |
| [`pairing_ref_valid`](../../src/pairing.odin#L1342) | Check pairing reference length and permitted characters. |
| [`paired_account_validate`](../../src/pairing.odin#L1358) | Validate the paired account, its stored identity and signatures. |
| [`paired_account_signature_domain`](../../src/pairing.odin#L1396) | Choose the signing domain for the account type. |
| [`paired_account_signatures_validate`](../../src/pairing.odin#L1416) | Verify the stored account and device signatures. |
| [`qr_encode`](../../src/pairing.odin#L1584) | Encode text as a QR matrix and select a mask. |
| [`qr_data_encode`](../../src/pairing.odin#L1655) | Write QR byte-mode payload bits, terminator and padding. |
| [`qr_module_is_dark`](../../src/pairing.odin#L1673) | Read a module at the requested QR coordinates. |
| [`qr_terminal_render`](../../src/pairing.odin#L1686) | Render a QR matrix as terminal cells with a quiet border. |
| [`qr_terminal_destroy`](../../src/pairing.odin#L1741) | Release the allocated terminal rendering. |
| [`qr_bits_write`](../../src/pairing.odin#L1745) | Write a fixed number of bits into the QR data stream. |
| [`qr_count_raw_data_modules`](../../src/pairing.odin#L1751) | Calculate the number of raw data modules for a QR version. |
| [`qr_data_codeword_count`](../../src/pairing.odin#L1764) | Calculate the available data codewords after error correction. |
| [`qr_gf256_multiply`](../../src/pairing.odin#L1767) | Multiply two QR error-correction field elements. |
| [`qr_interleave`](../../src/pairing.odin#L1777) | Generate error-correction codewords and interleave QR blocks. |
| [`qr_set_function`](../../src/pairing.odin#L1832) | Set a QR module and mark it reserved for a function pattern. |
| [`qr_draw_function_patterns`](../../src/pairing.odin#L1840) | Draw and reserve the fixed QR function patterns. |
| [`qr_write_format_bits`](../../src/pairing.odin#L1903) | Write the mask and error-correction format bits to the matrix. |
| [`qr_apply_data_mask`](../../src/pairing.odin#L1930) | Apply the selected mask to data modules. |
| [`qr_penalty`](../../src/pairing.odin#L1963) | Score a QR matrix for visual patterns penalized by the specification. |
| [`qr_history_add`](../../src/pairing.odin#L2033) | Shift a new run length into the QR pattern history. |
| [`qr_history_patterns`](../../src/pairing.odin#L2044) | Count finder-like sequences in the recent runs. |
| [`web_version_discover`](../../src/pairing.odin#L2100) | Fetch WhatsApp Web version metadata and select a usable revision. |
| [`web_version_revision`](../../src/pairing.odin#L2162) | Extract the client revision from the WhatsApp Web service worker. |
| [`match_client_revision_key_at`](../../src/pairing.odin#L2202) | Recognize a revision field at a position in plain or escaped text. |
| [`parse_client_revision_digits`](../../src/pairing.odin#L2230) | Parse an unsigned revision following the field. |
| [`revision_space`](../../src/pairing.odin#L2284) | Recognize whitespace around a revision value. |
| [`web_version_parse`](../../src/pairing.odin#L2288) | Parse a dotted WhatsApp Web version into numeric components. |
| [`version_fetch_http`](../../src/pairing.odin#L2333) | Fetch version metadata over HTTP with the client headers. |

<a id="file-src-protobuf-odin"></a>

## src/protobuf.odin

| Function | Behavior |
|---|---|
| [`handshake_client_hello_encode`](../../src/protobuf.odin#L65) | Write ClientHello with its ephemeral public key. |
| [`handshake_client_finish_encode`](../../src/protobuf.odin#L79) | Write ClientFinish with its encrypted static key and payload. |
| [`handshake_message_decode`](../../src/protobuf.odin#L126) | Decode the enclosing WAProto handshake message. |
| [`cert_chain_decode`](../../src/protobuf.odin#L174) | Decode a certificate chain's leaf and intermediate certificates. |
| [`certificate_details_decode`](../../src/protobuf.odin#L214) | Decode the signed details of one certificate. |
| [`certificate_details_field_decode`](../../src/protobuf.odin#L235) | Assign a decoded field to the certificate details and reject duplicate fields. |
| [`protobuf_handshake_inner_decode`](../../src/protobuf.odin#L300) | Decode the fields of the selected handshake variant. |
| [`protobuf_handshake_field_decode`](../../src/protobuf.odin#L322) | Assign one wire field to the matching handshake message member. |
| [`protobuf_certificate_decode`](../../src/protobuf.odin#L379) | Decode a certificate's raw signed details and signature. |
| [`protobuf_field_read`](../../src/protobuf.odin#L416) | Read one protobuf field's tag, wire type and value. |
| [`protobuf_varint_read`](../../src/protobuf.odin#L466) | Read an unsigned varint and reject truncated or overflowing encodings. |
| [`protobuf_varint_size`](../../src/protobuf.odin#L487) | Count the bytes required for an unsigned varint. |
| [`protobuf_varint_write`](../../src/protobuf.odin#L491) | Write a varint and advance the cursor. |
| [`registration_payload_encode`](../../src/protobuf.odin#L536) | Encode the registration ClientPayload with device and public key material. |
| [`registration_version_md5`](../../src/protobuf.odin#L592) | Hash the dotted client version for the registration payload. |
| [`login_payload_encode`](../../src/protobuf.odin#L616) | Encode a login ClientPayload for an already paired device. |
| [`device_props_encode`](../../src/protobuf.odin#L653) | Serialize the companion's OS, version and platform properties. |
| [`protobuf_write_limit`](../../src/protobuf.odin#L712) | Calculate the effective output limit for the protobuf writer. |
| [`protobuf_write_varint`](../../src/protobuf.odin#L720) | Write an unsigned varint through the bounded writer. |
| [`protobuf_write_header`](../../src/protobuf.odin#L740) | Write a field number and wire type. |
| [`protobuf_write_uint`](../../src/protobuf.odin#L745) | Encode an unsigned integer field. |
| [`protobuf_write_bytes`](../../src/protobuf.odin#L750) | Encode a length-delimited byte field and reject aliased input. |
| [`protobuf_write_string`](../../src/protobuf.odin#L783) | Validate UTF-8 and encode a protobuf string field. |
| [`client_payload_error_from_writer`](../../src/protobuf.odin#L796) | Translate a protobuf writer failure into a client payload error. |
| [`write_common_client_payload_fields`](../../src/protobuf.odin#L810) | Write client metadata shared by registration and login. |
| [`payload_config_validate`](../../src/protobuf.odin#L881) | Validate the client profile, platform strings and country code. |
| [`browser_platform_code`](../../src/protobuf.odin#L911) | Map the configured browser name to a platform enum value. |
| [`payload_copy_result`](../../src/protobuf.odin#L968) | Copy the staged payload to the destination after validating size and overlap. |
| [`pairing_identity_hmac_decode`](../../src/protobuf.odin#L1017) | Decode the device identity and HMAC wrapper from the pairing response. |
| [`pairing_signed_identity_decode`](../../src/protobuf.odin#L1070) | Decode the device identity details, keys and signatures. |
| [`pairing_device_details_decode`](../../src/protobuf.odin#L1113) | Decode the device and account properties inside a signed identity. |
| [`pairing_signed_identity_encode`](../../src/protobuf.odin#L1165) | Serialize the signed device identity for a pairing reply. |
| [`text_message_decode`](../../src/protobuf.odin#L1274) | Decode a WhatsApp message starting at the outermost wrapper. |
| [`message_decode_inner`](../../src/protobuf.odin#L1282) | Dispatch supported message fields and descend through nested wrappers. |
| [`message_extended_text_decode`](../../src/protobuf.odin#L1340) | Decode extended text and its optional context. |
| [`message_wrapper_decode`](../../src/protobuf.odin#L1389) | Unwrap and decode the message contained in a wrapper field. |
| [`message_sender_key_distribution_decode`](../../src/protobuf.odin#L1440) | Decode a sender-key distribution and its group ID. |
| [`message_context_decode`](../../src/protobuf.odin#L1491) | Decode message context including mentions and quoted messages. |
| [`text_message_encode`](../../src/protobuf.odin#L1551) | Serialize a text message with its optional context. |
| [`text_message_encode_validate`](../../src/protobuf.odin#L1579) | Validate the text message before serialization. |
| [`text_message_context_size`](../../src/protobuf.odin#L1607) | Calculate context size and validate the quoted message. |
| [`text_message_encoded_sizes`](../../src/protobuf.odin#L1644) | Calculate the nested and complete encoded sizes for a text message. |
| [`message_context_fields_write`](../../src/protobuf.odin#L1698) | Write mentions and quoted-message fields into the context. |
| [`text_message_fields_write`](../../src/protobuf.odin#L1716) | Write the plain or extended-text message and its context. |
| [`message_field_size`](../../src/protobuf.odin#L1755) | Calculate the size of a length-delimited field including its header. |
| [`message_field_header`](../../src/protobuf.odin#L1758) | Write the tag and length of a length-delimited field. |
| [`message_field_write`](../../src/protobuf.odin#L1762) | Write a length-delimited message field and its contents. |

<a id="file-src-receive-odin"></a>

## src/receive.odin

| Function | Behavior |
|---|---|
| [`socket_process_node`](../../src/receive.odin#L17) | Dispatch incoming stanzas to message, acknowledgement and retry handlers. |
| [`socket_message_receipts_send`](../../src/receive.odin#L60) | Send the delivery, history and stanza acknowledgements needed for an incoming message. |
| [`socket_message_node_process`](../../src/receive.odin#L95) | Process an incoming message node and send acknowledgements or a retry request. |
| [`socket_message_ack_process`](../../src/receive.odin#L133) | Apply a server acknowledgement to the durable outbound message record. |
| [`socket_process_message`](../../src/receive.odin#L173) | Validate the message route, decrypt it and commit its durable outcome. |
| [`socket_message_route_decode`](../../src/receive.odin#L264) | Extract and validate the group, participant and stanza ID of an incoming message. |
| [`socket_message_processed_commit`](../../src/receive.odin#L292) | Persist a processed-message marker alongside staged state changes. |
| [`socket_message_cipher_decrypt`](../../src/receive.odin#L300) | Decrypt a group or pairwise ciphertext with the correct sender state. |
| [`socket_message_distribution_install`](../../src/receive.odin#L355) | Install a sender-key distribution carried in a decrypted message. |
| [`socket_message_child_decrypt`](../../src/receive.odin#L403) | Decrypt one encrypted child, remove padding and process key distributions. |
| [`message_encryption_nack_reason`](../../src/receive.odin#L462) | Choose a negative-acknowledgement reason for unsupported encryption. |
| [`socket_message_payload_decrypt`](../../src/receive.odin#L487) | Dispatch encrypted children and select the decrypted message payload. |
| [`socket_message_control_commit`](../../src/receive.odin#L552) | Recognize an internal control message and commit its processed marker. |
| [`socket_message_event_commit`](../../src/receive.odin#L616) | Stage the incoming message for durable delivery and return a socket event. |
| [`socket_pairwise_decrypt`](../../src/receive.odin#L672) | Decrypt pairwise data with current or archived sessions and stage resulting state. |
| [`socket_pairwise_state_load`](../../src/receive.odin#L742) | Load the current session and stored identity pin for a sender. |
| [`socket_pairwise_prekey_archive_select`](../../src/receive.odin#L770) | Select an archived session matching the incoming prekey message. |
| [`socket_pairwise_one_time_prekey_load`](../../src/receive.odin#L818) | Load the one-time prekey needed by the incoming session. |
| [`socket_pairwise_prekey_open`](../../src/receive.odin#L840) | Open a prekey envelope with the appropriate session and key material. |
| [`socket_pairwise_whisper_open`](../../src/receive.odin#L889) | Try current or archived receiving sessions for a Whisper message. |
| [`socket_pairwise_decryption_stage`](../../src/receive.odin#L943) | Stage identity, session and consumed-key changes following successful decryption. |
| [`socket_stage_group`](../../src/receive.odin#L973) | Serialize and stage an updated group sender-key record. |
| [`socket_message_unpad`](../../src/receive.odin#L994) | Check and strip the repeated padding bytes from a message. |
| [`socket_store_clone`](../../src/receive.odin#L1014) | Clone the socket's durable store for a transaction. |
| [`socket_store_commit`](../../src/receive.odin#L1026) | Persist and install a candidate store, then clean up consumed prekeys. |
| [`socket_inbox_id_valid`](../../src/receive.odin#L1043) | Check a stanza ID before using it in an inbox record name. |
| [`socket_receive_group_valid`](../../src/receive.odin#L1056) | Validate an inbound group address for the receive path. |
| [`socket_inbox_key`](../../src/receive.odin#L1075) | Compute an inbox record key using the socket's current address mappings. |
| [`socket_inbox_key_store`](../../src/receive.odin#L1082) | Build the inbox key from the group, canonical sender and stanza ID. |
| [`socket_sender_is_self`](../../src/receive.odin#L1096) | Check whether the address identifies this account using the socket's state. |
| [`socket_sender_is_self_store`](../../src/receive.odin#L1103) | Resolve a sender against the supplied store and account identities. |
| [`socket_message_new`](../../src/receive.odin#L1162) | Construct a received message with owned copies of its data. |
| [`socket_inbox_stage`](../../src/receive.odin#L1223) | Serialize a received message into a candidate inbox record. |
| [`socket_message_complete`](../../src/receive.odin#L1271) | Commit completion of delivery by marking it processed and deleting its inbox entry. |
| [`socket_inbox_restore`](../../src/receive.odin#L1304) | Rebuild the pending message queue from durable inbox entries. |
| [`socket_inbox_record_restore`](../../src/receive.odin#L1351) | Decode and validate a stored inbox entry as a received message. |
| [`socket_cleanup_consumed_prekeys`](../../src/receive.odin#L1406) | Remove prekeys marked consumed by committed decryption and save the prekey store. |
| [`socket_retry_counter_read`](../../src/receive.odin#L1455) | Decode the retry attempt count and timestamp from a stored record. |
| [`socket_retry_counter_set`](../../src/receive.odin#L1475) | Store the retry count with the current timestamp. |
| [`socket_retry_prekeys_exhausted`](../../src/receive.odin#L1495) | Persist the terminal retry count when a new prekey cannot be issued. |
| [`socket_retry_keys_prepare`](../../src/receive.odin#L1538) | Generate and persist the keys required for a retry receipt. |
| [`socket_retry_body_prepare`](../../src/receive.odin#L1587) | Build the retry count, registration and optional key child nodes. |
| [`socket_retry_receipt_send`](../../src/receive.odin#L1622) | Write the encoded retry receipt to the socket. |
| [`socket_request_retry`](../../src/receive.odin#L1654) | Validate an incoming message's retry eligibility, persist the attempt and send the receipt. |
| [`socket_archive_session`](../../src/receive.odin#L1706) | Archive a pairwise session under its identity and prune displaced archives. |
| [`socket_send_delivery_receipt`](../../src/receive.odin#L1741) | Build and send a delivery receipt for the incoming stanza. |
| [`encode_current_unix_timestamp`](../../src/receive.odin#L1800) | Encode the current time as a processed-message timestamp. |
| [`processed_history_receipt`](../../src/receive.odin#L1807) | Check whether a durable processed marker requests a history-sync receipt on redelivery. |
| [`socket_processed_set`](../../src/receive.odin#L1811) | Store a timestamped marker for a processed message. |
| [`unwrap_protocol_message`](../../src/receive.odin#L1824) | Find the protocol payload in a decrypted message through supported wrappers. |
| [`message_contains_history_sync_notification`](../../src/receive.odin#L1892) | Detect a history sync notification inside supported message wrappers. |
| [`socket_protocol_has_history`](../../src/receive.odin#L1896) | Check a protocol message for a history sync field. |
| [`socket_send_history_receipt`](../../src/receive.odin#L1901) | Send the history-sync receipt to the appropriate account address. |
| [`socket_defer_retry`](../../src/receive.odin#L1936) | Queue an owned copy of an incoming retry request for deferred processing. |
| [`socket_acknowledge`](../../src/receive.odin#L1976) | Send the stanza acknowledgement with the original routing attributes. |
| [`socket_retry_outgoing`](../../src/receive.odin#L2030) | Process a peer retry request using the saved outbound message. |
| [`socket_retry_session_archive`](../../src/receive.odin#L2095) | Resolve and archive the current session before retrying delivery. |
| [`socket_replay_outbox`](../../src/receive.odin#L2126) | Resend the wire bytes for durable pending outbound messages. |
| [`socket_trust_identity`](../../src/receive.odin#L2146) | Commit an explicitly trusted identity for the device. |
| [`socket_prune_pending_ids`](../../src/receive.odin#L2199) | Collect pending message IDs that must survive pruning. |
| [`socket_retry_record_id`](../../src/receive.odin#L2233) | Extract a message ID from a retry record name. |
| [`socket_prune_retry_record`](../../src/receive.odin#L2253) | Check retry metadata for expiry and migrate its timestamp when needed. |
| [`socket_prune_record`](../../src/receive.odin#L2291) | Determine whether a stored record is eligible for expiry. |
| [`socket_prune_state`](../../src/receive.odin#L2338) | Prune eligible expired records in a single store transaction. |
| [`socket_message_alias_stage`](../../src/receive.odin#L2428) | Stage phone/LID aliases learned from an incoming message. |

<a id="file-src-send-odin"></a>

## src/send.odin

| Function | Behavior |
|---|---|
| [`socket_group_summaries_destroy`](../../src/send.odin#L16) | Free the strings and array owned by group summaries. |
| [`socket_groups_participating`](../../src/send.odin#L32) | Query the groups the account participates in and return owned summaries. |
| [`socket_groups_decode`](../../src/send.odin#L58) | Decode group IDs and subjects from the participating-groups response. |
| [`socket_groups_children_decode`](../../src/send.odin#L122) | Validate the response ID and expose the group list's child nodes. |
| [`socket_group_destroy`](../../src/send.odin#L150) | Release metadata and document storage owned by a socket group. |
| [`socket_group_metadata`](../../src/send.odin#L161) | Query group metadata and persist the participant address mappings. |
| [`socket_group_metadata_decode`](../../src/send.odin#L202) | Decode the response into a socket-owned group result. |
| [`socket_send_text`](../../src/send.odin#L222) | Encode text and send it as an encrypted group message. |
| [`socket_send_group`](../../src/send.odin#L265) | Resolve group recipients and send or replay an encrypted outbound message. |
| [`socket_group_device_select`](../../src/send.odin#L340) | Resolve device addresses and select recipients for the group send. |
| [`socket_group_sender_prepare`](../../src/send.odin#L398) | Load or create the sending chain for this group and recipient set. |
| [`socket_group_distribution_pad`](../../src/send.odin#L430) | Encode and pad a sender-key distribution message. |
| [`socket_group_participants_destroy`](../../src/send.odin#L470) | Free the transient per-device participant data. |
| [`socket_group_distribution_encrypt`](../../src/send.odin#L482) | Encrypt a sender-key distribution for one device and stage its session. |
| [`socket_group_participants_prepare`](../../src/send.odin#L512) | Build participant nodes containing per-device encrypted distributions. |
| [`socket_group_sender_stage`](../../src/send.odin#L566) | Stage the updated sender-key record in the candidate store. |
| [`socket_group_stanza_wire`](../../src/send.odin#L594) | Assemble and encode the outbound encrypted group stanza. |
| [`socket_group_stanza_encode`](../../src/send.odin#L647) | Prepare any required device identity and encode the group stanza. |
| [`socket_group_content_stage`](../../src/send.odin#L689) | Stage the original message content and destination for future retry. |
| [`socket_group_existing_send`](../../src/send.odin#L717) | Recognize an existing message ID and replay a pending send when appropriate. |
| [`socket_group_existing_intent`](../../src/send.odin#L745) | Check that stored content and destination match the requested message ID. |
| [`socket_group_pending_replay`](../../src/send.odin#L789) | Write the saved wire bytes for a pending outbound message. |
| [`socket_group_outbound_commit`](../../src/send.odin#L813) | Durably commit the outbound intent, wire bytes and encryption state. |
| [`socket_group_dispatch`](../../src/send.odin#L836) | Choose a message ID, encode and commit the stanza, then send it. |
| [`socket_group_payload_send`](../../src/send.odin#L874) | Pad and encrypt the group payload and stage the updated sender chain. |
| [`socket_group_send_prepared`](../../src/send.odin#L912) | Prepare sender keys and participant distributions before dispatch. |
| [`socket_stage_session`](../../src/send.odin#L965) | Serialize and stage a pairwise Signal session in the candidate store. |
| [`socket_outgoing_session`](../../src/send.odin#L1000) | Load an outbound session or establish one from the recipient's prekey bundle. |
| [`socket_outgoing_identity_validate`](../../src/send.odin#L1050) | Check the recipient identity against the stored identity pin. |
| [`socket_outgoing_session_cached`](../../src/send.odin#L1064) | Decode a cached session and check its remote identity. |
| [`socket_outgoing_keys_query`](../../src/send.odin#L1084) | Query the encryption key bundle for a destination device. |
| [`socket_group_devices`](../../src/send.odin#L1102) | Collect the group's users and query their eligible devices. |
| [`socket_group_users_collect`](../../src/send.odin#L1144) | Build the distinct user addresses needed for group device discovery. |
| [`socket_group_devices_append`](../../src/send.odin#L1184) | Append eligible device JIDs while excluding the sending device. |
| [`socket_group_devices_batch`](../../src/send.odin#L1209) | Query one batch of users and append the devices in the response. |
| [`pad_outbound_message`](../../src/send.odin#L1252) | Append a randomly chosen length of repeated padding bytes to a message. |
| [`generate_outbound_message_id`](../../src/send.odin#L1264) | Generate a WhatsApp outbound message ID using random bytes. |
| [`socket_same_device`](../../src/send.odin#L1270) | Compare the user, device and addressing domain of two device JIDs. |
| [`socket_send_primary_device_message`](../../src/send.odin#L1285) | Encrypt a control message for the primary device and durably stage its ciphertext before writing. |

<a id="file-src-signal-odin"></a>

## src/signal.odin

| Function | Behavior |
|---|---|
| [`signal_group_record_clear`](../../src/signal.odin#L79) | Erase a group's sender-key record. |
| [`signal_group_init_sender`](../../src/signal.odin#L88) | Initialize a sending chain and signing identity for a group sender. |
| [`signal_group_distribution_encode`](../../src/signal.odin#L119) | Encode the current sender-key distribution for recipients. |
| [`signal_group_distribution_decode`](../../src/signal.odin#L160) | Decode and validate a sender-key distribution. |
| [`signal_group_distribution_process`](../../src/signal.odin#L239) | Install the received sender key while checking conflicting state. |
| [`signal_group_message_decode`](../../src/signal.odin#L286) | Decode a signed group message and its encrypted payload. |
| [`signal_group_message_encode`](../../src/signal.odin#L354) | Build and sign the group message for a supplied ciphertext. |
| [`signal_group_encrypt`](../../src/signal.odin#L403) | Derive message keys, encrypt and sign the group payload and advance sender state. |
| [`group_message_sign`](../../src/signal.odin#L477) | Write the group header and append the sender signature. |
| [`signal_group_decrypt`](../../src/signal.odin#L496) | Verify the sender signature, derive keys and decrypt the group message. |
| [`group_message_seed`](../../src/signal.odin#L556) | Retrieve or derive the seed for a given sender-chain iteration. |
| [`group_state_append`](../../src/signal.odin#L610) | Append a sender state to the bounded group history. |
| [`group_signing_public_key_valid`](../../src/signal.odin#L621) | Check whether a group signing public key is acceptable. |
| [`group_record_validate`](../../src/signal.odin#L628) | Validate all states and key pairs in a group sender record. |
| [`group_record_overlaps_buffer`](../../src/signal.odin#L670) | Check whether a buffer overlaps the group record's memory. |
| [`group_uint_write`](../../src/signal.odin#L673) | Write an unsigned protobuf field for a group message. |
| [`group_message_header_size`](../../src/signal.odin#L677) | Calculate the header size for a signed group message. |
| [`write_group_message_header`](../../src/signal.odin#L688) | Write the sender ID, chain iteration and ciphertext length. |
| [`signal_group_record_encode`](../../src/signal.odin#L702) | Serialize the group sender-key record with its checksum. |
| [`signal_group_record_decode`](../../src/signal.odin#L752) | Decode and validate a serialized group sender-key record. |
| [`group_snapshot_states_decode`](../../src/signal.odin#L819) | Read individual sender states from the group snapshot. |
| [`group_bytes_write`](../../src/signal.odin#L856) | Write a length-delimited protobuf field for group data. |
| [`signal_chain_keys`](../../src/signal.odin#L899) | Derive the next chain key and current message seed. |
| [`signal_message_keys`](../../src/signal.odin#L908) | Derive the pairwise cipher key, MAC key and IV from a message seed. |
| [`signal_ratchet_keys`](../../src/signal.odin#L925) | Derive the next root and chain keys from a ratchet agreement. |
| [`signal_group_message_keys`](../../src/signal.odin#L939) | Derive cipher material for a group message from its seed. |
| [`signal_cbc_encrypt`](../../src/signal.odin#L956) | Encrypt a padded pairwise payload with AES-CBC. |
| [`signal_cbc_decrypt`](../../src/signal.odin#L1009) | Decrypt AES-CBC after checking the input, padding and output capacity. |
| [`signal_cbc_blocks_decrypt`](../../src/signal.odin#L1066) | Decrypt ciphertext blocks using the previous block or supplied IV. |
| [`signal_cbc_padding_size`](../../src/signal.odin#L1082) | Validate the final padding block and return the padding length. |
| [`signal_message_mac`](../../src/signal.odin#L1102) | Authenticate a pairwise message together with the sender and receiver identities. |
| [`signal_message_mac_verify`](../../src/signal.odin#L1131) | Check the supplied message MAC using constant-time comparison. |
| [`signal_session_clear`](../../src/signal.odin#L1257) | Erase an entire pairwise Signal session. |
| [`signal_session_init_initiator`](../../src/signal.odin#L1265) | Establish an initiating session from a validated remote prekey bundle. |
| [`signal_initiator_bundle_validate`](../../src/signal.odin#L1329) | Check the remote bundle and its signed prekey signature. |
| [`signal_initiator_root_derive`](../../src/signal.odin#L1347) | Compute the initiator's shared secrets and derive the initial root. |
| [`signal_identity_equal`](../../src/signal.odin#L1380) | Compare identity public keys in constant time. |
| [`signal_private_valid`](../../src/signal.odin#L1386) | Check the required clamp bits on a Signal private scalar. |
| [`signal_private_generate`](../../src/signal.odin#L1390) | Generate a clamped private scalar. |
| [`signal_public_valid`](../../src/signal.odin#L1396) | Check that a Signal public key has a valid field encoding and is nonzero. |
| [`signal_agreement`](../../src/signal.odin#L1404) | Perform X25519 agreement and reject invalid or zero shared secrets. |
| [`signal_x3dh_root`](../../src/signal.odin#L1420) | Derive the initial Signal root from the concatenated handshake secrets. |
| [`signal_whisper_decode`](../../src/signal.odin#L1441) | Decode a pairwise Whisper message and validate its ratchet public key. |
| [`signal_whisper_decode_field`](../../src/signal.odin#L1493) | Read one Whisper message field and enforce its wire constraints. |
| [`signal_prekey_message_decode`](../../src/signal.odin#L1531) | Decode the prekey envelope around the first pairwise message. |
| [`signal_prekey_message_decode_field`](../../src/signal.odin#L1583) | Read one prekey envelope field and check its expected representation. |
| [`signal_session_encrypt`](../../src/signal.odin#L1630) | Encrypt a pairwise payload and advance the sending chain. |
| [`signal_session_encrypt_sizes`](../../src/signal.odin#L1684) | Calculate the packet type and buffer sizes for pairwise encryption. |
| [`signal_session_whisper_encrypt`](../../src/signal.odin#L1725) | Encode, encrypt and authenticate the inner Whisper message. |
| [`signal_session_prekey_wrap`](../../src/signal.odin#L1760) | Wrap an initial Whisper message with the sender's prekey metadata. |
| [`signal_session_decrypt`](../../src/signal.odin#L1782) | Decrypt a pairwise message and commit the resulting session state on success. |
| [`signal_session_decrypt_prekey`](../../src/signal.odin#L1818) | Open a prekey message using the existing session or a new recipient session. |
| [`signal_prekey_existing_session_validate`](../../src/signal.odin#L1877) | Check that an existing session matches the incoming prekey envelope. |
| [`signal_session_init_recipient`](../../src/signal.odin#L1898) | Derive and initialize the recipient side of a prekey session. |
| [`signal_recipient_keys_validate`](../../src/signal.odin#L1948) | Validate the recipient's identity and prekey private material. |
| [`signal_session_decrypt_next`](../../src/signal.odin#L1970) | Select or ratchet the receiving chain, verify the MAC and decrypt. |
| [`signal_session_ratchet`](../../src/signal.odin#L2019) | Advance the Diffie–Hellman ratchet and establish fresh chains. |
| [`signal_session_message_seed`](../../src/signal.odin#L2076) | Look up or derive the seed for a received message counter. |
| [`signal_session_skip_through`](../../src/signal.odin#L2126) | Advance a receiving chain while saving skipped message keys. |
| [`signal_session_save_skipped`](../../src/signal.odin#L2154) | Store a skipped message key within the configured limit. |
| [`signal_receiving_chain_find`](../../src/signal.odin#L2180) | Find the receiving chain for a remote ratchet key. |
| [`signal_receiving_chain_slot`](../../src/signal.odin#L2190) | Choose or reclaim a slot for a receiving chain. |
| [`signal_session_ready`](../../src/signal.odin#L2219) | Check initialization and identity prerequisites for a session operation. |
| [`signal_session_overlaps_buffer`](../../src/signal.odin#L2236) | Check whether a data buffer overlaps the session structure. |
| [`signal_session_put_uint`](../../src/signal.odin#L2240) | Write an unsigned protobuf field for a pairwise session message. |
| [`signal_session_put_public`](../../src/signal.odin#L2246) | Write a typed public key into a session message. |
| [`signal_session_validate`](../../src/signal.odin#L2255) | Validate session keys, counters and receiving-chain state. |
| [`signal_session_chains_validate`](../../src/signal.odin#L2287) | Validate receiving chains and the associated skipped keys. |
| [`signal_session_encode`](../../src/signal.odin#L2354) | Serialize the pairwise session and append an integrity digest. |
| [`signal_session_keys_encode`](../../src/signal.odin#L2412) | Write the session's identities, ratchet keys and counters to its snapshot. |
| [`signal_session_chains_encode`](../../src/signal.odin#L2441) | Serialize receiving chains and skipped-message keys. |
| [`signal_session_decode`](../../src/signal.odin#L2474) | Decode and validate a snapshot before replacing the pairwise session. |
| [`signal_session_keys_decode`](../../src/signal.odin#L2526) | Read the key and counter fields of a session snapshot. |
| [`signal_session_snapshot_validate`](../../src/signal.odin#L2554) | Check the session snapshot's header, bounds and checksum. |
| [`signal_session_chains_decode`](../../src/signal.odin#L2580) | Read receiving chains and skipped keys from the snapshot. |

<a id="file-src-socket-odin"></a>

## src/socket.odin

Application loops can call `socket_read` or its alias `socket_receive`. Both return queued messages before reading the network.

| Function | Behavior |
|---|---|
| [`socket_message_destroy`](../../src/socket.odin#L122) | Release all allocations owned by a received socket message. |
| [`socket_connect`](../../src/socket.odin#L179) | Validate settings, open the WebSocket and start the WhatsApp session. |
| [`socket_client_init`](../../src/socket.odin#L234) | Initialize the Noise client on the socket's existing transport. |
| [`socket_websocket_dial`](../../src/socket.odin#L245) | Dial the configured WhatsApp WebSocket and retain it on the socket. |
| [`socket_connect_validate`](../../src/socket.odin#L260) | Validate credentials and stores before opening the connection. |
| [`socket_connect_settings`](../../src/socket.odin#L296) | Fill in socket defaults and validate the pairing configuration. |
| [`socket_close`](../../src/socket.odin#L334) | Close the session and release pending messages and transport resources. |
| [`socket_tick`](../../src/socket.odin#L372) | Advance timers, retry work and maintenance for an open socket. |
| [`socket_receive_wire`](../../src/socket.odin#L441) | Receive the next network event under a temporary read deadline while synchronous waiters retain queued messages. |
| [`socket_receive_inner`](../../src/socket.odin#L453) | Route incoming session events through provisioning or online processing. |
| [`socket_login_provision_start`](../../src/socket.odin#L517) | Start the post-login prekey check and record the socket's own LID. |
| [`socket_provision`](../../src/socket.odin#L555) | Dispatch the IQ reply for the current provisioning stage. |
| [`socket_provision_count`](../../src/socket.odin#L570) | Handle the reported prekey count and upload keys or request activation. |
| [`socket_provision_upload`](../../src/socket.odin#L621) | Record an accepted prekey upload and request activation. |
| [`socket_handle_activation_response`](../../src/socket.odin#L648) | Handle the activation reply, restore messages and move the socket online. |
| [`socket_request_activation`](../../src/socket.odin#L704) | Send the active-state IQ and wait for its provisioning reply. |
| [`socket_provision_write`](../../src/socket.odin#L731) | Send a provisioning request under its write deadline. |
| [`socket_next_iq_id`](../../src/socket.odin#L743) | Generate the next IQ ID from time and the socket sequence. |
| [`socket_write`](../../src/socket.odin#L749) | Write encrypted stanza bytes under a bounded write deadline. |
| [`socket_fail`](../../src/socket.odin#L769) | Close the socket and retain its terminal error. |
| [`socket_read`](../../src/socket.odin#L783) | Return a queued message first or receive the next socket event. |
| [`socket_control_node`](../../src/socket.odin#L796) | Handle control stanzas such as offline previews and key notifications. |
| [`socket_poll`](../../src/socket.odin#L857) | Check for queued or network activity within a timeout. |
| [`socket_network_poll`](../../src/socket.odin#L884) | Poll the transport file descriptor for readable network events. |
| [`query_observer_set`](../../src/socket.odin#L923) | Install the process-wide IQ query observer. |
| [`query_observe`](../../src/socket.odin#L927) | Report a query observation to the installed observer. |
| [`socket_query`](../../src/socket.odin#L937) | Send an IQ and wait for the reply with the matching ID. |
| [`socket_query_send`](../../src/socket.odin#L984) | Encode a query node and write it to the socket. |
| [`socket_query_message_enqueue`](../../src/socket.odin#L1011) | Retain an unrelated incoming message while waiting for a query result. |
| [`socket_query_response_copy`](../../src/socket.odin#L1025) | Make an owning copy of the response node. |
| [`socket_query_response_receive`](../../src/socket.odin#L1054) | Read events until the matching IQ arrives or the deadline expires. |
| [`socket_receive_while_waiting`](../../src/socket.odin#L1087) | Poll for one frame during a synchronous request and queue unrelated live messages. |

<a id="file-src-state-store-odin"></a>

## src/state_store.odin

If a save returns `.Directory_Flush_Failed`, the replacement file is visible and its directory still needs to be flushed. Restore filesystem access and call `state_store_load` on the same store and path. A successful reload reconciles the revision and enables writes. Reconnect with a fresh socket.

| Function | Behavior |
|---|---|
| [`state_store_init`](../../src/state_store.odin#L75) | Initialize a record store bound to its owner identity. |
| [`state_store_clear`](../../src/state_store.odin#L97) | Erase stored record bytes and free the record list. |
| [`state_store_get`](../../src/state_store.odin#L117) | Look up record data by kind and name. |
| [`state_store_find_record`](../../src/state_store.odin#L122) | Find a stored record by kind and name and return its store-owned key and data. |
| [`state_store_delete`](../../src/state_store.odin#L136) | Erase and remove a matching record from the store. |
| [`state_store_set`](../../src/state_store.odin#L164) | Insert or replace a validated record while enforcing store limits. |
| [`state_store_find_upsert_index`](../../src/state_store.odin#L220) | Find the replacement index and check projected store size for an upsert. |
| [`state_store_encode`](../../src/state_store.odin#L254) | Serialize all records with the owner, revision and checksum. |
| [`state_store_clone`](../../src/state_store.odin#L306) | Deep-copy the store into independently owned records. |
| [`state_store_append_owned`](../../src/state_store.odin#L380) | Append a record with owned copies of its name and data. |
| [`state_store_decode_header`](../../src/state_store.odin#L411) | Check snapshot identity and integrity and read its revision and record count. |
| [`state_store_decode_records`](../../src/state_store.odin#L455) | Decode and validate snapshot records into the candidate store. |
| [`state_store_decode`](../../src/state_store.odin#L514) | Decode a complete snapshot before replacing the destination store. |
| [`state_store_save`](../../src/state_store.odin#L542) | Serialize the store and atomically replace the on-disk snapshot. |
| [`state_atomic_write`](../../src/state_store.odin#L578) | Translate durable file replacement failures into state-store errors. |
| [`state_store_load`](../../src/state_store.odin#L597) | Read a bounded snapshot from disk and restore the store. |
| [`state_record_valid`](../../src/state_store.odin#L650) | Check a record's kind, name and size constraints. |
| [`replace_file_durably`](../../src/state_store.odin#L705) | Write a temporary file, flush it, rename it and sync its directory. |
| [`read_file_into_bounded_buffer`](../../src/state_store.odin#L769) | Fill a bounded buffer from a file and detect oversized input. |
| [`sha256`](../../src/state_store.odin#L789) | Return the 32-byte SHA-256 digest of the input. |
| [`state_store_export_v0_2`](../../src/state_store.odin#L797) | Export a durable snapshot with the contact cursor, version hint and processed-message timestamps supported by owa v0.2.0 through v0.2.2. |

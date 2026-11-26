# Function name changes

[Catalog index](README.md)

Each row maps a previous spelling to the current declaration. External source callers using an earlier spelling need the corresponding rename.

For callers upgrading from a checkout that used `strict_certificate_policy`, the current entry point is `verify_whatsapp_server_certificate`. Its clock-controlled counterpart is `verify_whatsapp_server_certificate_at`.

| Previous name | Current function | Behavior made explicit |
|---|---|---|
| `device_child_bytes` | [`device_read_fixed_child_bytes`](../../src/addressing.odin#L236) | Read a uniquely named child and require its bytes to have the expected length. |
| `device_request_valid` | [`stanza_id_valid`](../../src/addressing.odin#L539) | Check that a stanza ID contains 1–128 printable, non-space ASCII bytes. |
| `device_user_valid` | [`device_user_jid_valid`](../../src/addressing.odin#L552) | Check the user JID against the supported addressing domains. |
| `prekey_count_response` | [`decode_prekey_count_response`](../../src/auth.odin#L914) | Parse the prekey count from a matching server response. |
| `prekey_id_bytes` | [`encode_prekey_id_u24`](../../src/auth.odin#L1376) | Encode a prekey ID as three big-endian bytes. |
| `client_handshake_certificate_verify` | [`client_decrypt_and_verify_server_certificate`](../../src/noise_handshake.odin#L330) | Decrypt the server's certificate payload and invoke the configured verifier. |
| `verify_noise_server_certificate` | [`verify_whatsapp_server_certificate`](../../src/noise_certificate.odin#L65) | Authenticate the WhatsApp server's certificate chain and handshake key at the current time. |
| `verify_noise_server_certificate_at` | [`verify_whatsapp_server_certificate_at`](../../src/noise_certificate.odin#L74) | Verify the server certificate against the pinned WhatsApp root at a supplied time. |
| `strict_certificate_chain_verify` | [`verify_certificate_chain_against_root`](../../src/noise_certificate.odin#L87) | Verify issuer linkage, both signatures, the leaf key and certificate validity against a supplied root. |
| `strict_certificate_details` | [`decode_and_validate_certificate_details`](../../src/noise_certificate.odin#L146) | Decode and validate the required fields of an intermediate or leaf certificate. |
| `strict_certificate_time` | [`check_certificate_validity_at`](../../src/noise_certificate.odin#L189) | Check that the supplied time falls within the certificate's validity interval. |
| `media_mac` | [`compute_media_authentication_tag`](../../src/media.odin#L335) | Compute the media authentication tag over the IV and ciphertext. |
| `media_write_error` | [`media_error_from_protobuf_writer`](../../src/media.odin#L834) | Translate protobuf writer errors into media errors. |
| `media_key_decode` | [`decode_reaction_target_message_key`](../../src/media.odin#L1252) | Decode a protobuf message key identifying the target stanza. |
| `media_host_limit` | [`read_media_host_upload_limit`](../../src/media.odin#L1511) | Read a media host's maximum permitted content length. |
| `media_retry_key` | [`derive_media_retry_key`](../../src/media.odin#L2283) | Derive the AES-GCM retry key from the file's media key. |
| `default_payload_config` | [`default_client_payload_config`](../../src/pairing.odin#L154) | Construct the default device and browser profile for a WhatsApp client payload. |
| `session_receiving` | [`session_can_receive`](../../src/pairing.odin#L630) | Check whether the current session phase permits reads. |
| `session_keepalive` | [`session_send_keepalive_ping`](../../src/pairing.odin#L662) | Encode and send a keepalive ping IQ. |
| `qr_module` | [`qr_module_is_dark`](../../src/pairing.odin#L1673) | Read a module at the requested QR coordinates. |
| `qr_raw_modules` | [`qr_count_raw_data_modules`](../../src/pairing.odin#L1751) | Calculate the number of raw data modules for a QR version. |
| `qr_data_words` | [`qr_data_codeword_count`](../../src/pairing.odin#L1764) | Calculate the available data codewords after error correction. |
| `qr_multiply` | [`qr_gf256_multiply`](../../src/pairing.odin#L1767) | Multiply two QR error-correction field elements. |
| `qr_functions` | [`qr_draw_function_patterns`](../../src/pairing.odin#L1840) | Draw and reserve the fixed QR function patterns. |
| `qr_format` | [`qr_write_format_bits`](../../src/pairing.odin#L1903) | Write the mask and error-correction format bits to the matrix. |
| `qr_mask` | [`qr_apply_data_mask`](../../src/pairing.odin#L1930) | Apply the selected mask to data modules. |
| `revision_key_at` | [`match_client_revision_key_at`](../../src/pairing.odin#L2202) | Recognize a revision field at a position in plain or escaped text. |
| `revision_digits` | [`parse_client_revision_digits`](../../src/pairing.odin#L2230) | Parse an unsigned revision following the field. |
| `registration_build_hash` | [`registration_version_md5`](../../src/protobuf.odin#L592) | Hash the dotted client version for the registration payload. |
| `payload_write_error` | [`client_payload_error_from_writer`](../../src/protobuf.odin#L796) | Translate a protobuf writer failure into a client payload error. |
| `payload_common` | [`write_common_client_payload_fields`](../../src/protobuf.odin#L810) | Write client metadata shared by registration and login. |
| `payload_platform` | [`browser_platform_code`](../../src/protobuf.odin#L911) | Map the configured browser name to a platform enum value. |
| `socket_message_encryption_nack` | [`message_encryption_nack_reason`](../../src/receive.odin#L461) | Choose a negative-acknowledgement reason for unsupported encryption. |
| `socket_delivery_receipt` | [`socket_send_delivery_receipt`](../../src/receive.odin#L1727) | Build and send a delivery receipt for the incoming stanza. |
| `socket_processed_stamp` | [`encode_current_unix_timestamp`](../../src/receive.odin#L1786) | Encode the current time as a processed-message timestamp. |
| `socket_history_notification` | [`message_contains_history_sync_notification`](../../src/receive.odin#L1878) | Detect a history sync notification inside supported message wrappers. |
| `socket_history_receipt` | [`socket_send_history_receipt`](../../src/receive.odin#L1887) | Send the history-sync receipt to the appropriate account address. |
| `socket_pad` | [`pad_outbound_message`](../../src/send.odin#L1252) | Append a randomly chosen length of repeated padding bytes to a message. |
| `socket_message_id` | [`generate_outbound_message_id`](../../src/send.odin#L1264) | Generate a WhatsApp outbound message ID using random bytes. |
| `group_public_valid` | [`group_signing_public_key_valid`](../../src/signal.odin#L621) | Check whether a group signing public key is acceptable. |
| `group_record_alias` | [`group_record_overlaps_buffer`](../../src/signal.odin#L670) | Check whether a buffer overlaps the group record's memory. |
| `group_message_header` | [`write_group_message_header`](../../src/signal.odin#L688) | Write the sender ID, chain iteration and ciphertext length. |
| `signal_session_alias` | [`signal_session_overlaps_buffer`](../../src/signal.odin#L2236) | Check whether a data buffer overlaps the session structure. |
| `socket_provision_active` | [`socket_handle_activation_response`](../../src/socket.odin#L608) | Handle the activation reply, restore messages and move the socket online. |
| `socket_activate` | [`socket_request_activation`](../../src/socket.odin#L656) | Send the active-state IQ and wait for its provisioning reply. |
| `socket_next_id` | [`socket_next_iq_id`](../../src/socket.odin#L694) | Generate the next IQ ID from time and the socket sequence. |
| `state_store_set_index` | [`state_store_find_upsert_index`](../../src/state_store.odin#L219) | Find the replacement index and check projected store size for an upsert. |
| `durable_write` | [`replace_file_durably`](../../src/state_store.odin#L701) | Write a temporary file, flush it, rename it and sync its directory. |
| `bounded_read` | [`read_file_into_bounded_buffer`](../../src/state_store.odin#L765) | Fill a bounded buffer from a file and detect oversized input. |
| `options` | [`parse_option_pairs`](../../tools/protocol_watcher/src/main.odin#L30) | Parse unique option/value pairs into a JSON object. |
| `manifest` | [`load_source_manifest`](../../tools/protocol_watcher/src/main.odin#L45) | Load the configured or default upstream manifest. |
| `append_env` | [`append_to_env_named_file`](../../tools/protocol_watcher/src/main.odin#L77) | Append output to the file named by a CI environment variable. |
| `source_digest` | [`hash_candidate_source_files`](../../tools/protocol_watcher/src/release.odin#L7) | Hash the candidate's Odin source set and build its file manifest. |
| `evidence_matches` | [`check_evidence_file_digest`](../../tools/protocol_watcher/src/release.odin#L29) | Verify a release check's recorded digest against its evidence file. |
| `command` | [`build_review_agent_argv`](../../tools/protocol_watcher/src/schedule.odin#L43) | Build the argument vector for the read-only review agent. |
| `report_open` | [`open_private_watch_report`](../../tools/protocol_watcher/src/schedule.odin#L293) | Open a private report file and validate its metadata. |
| `cat` | [`concatenate_strings`](../../tools/protocol_watcher/src/tracker.odin#L527) | Concatenate string fragments. |
| `source_for` | [`find_manifest_source_for_path`](../../tools/protocol_watcher/src/tracker.odin#L530) | Find the manifest source that owns a repository path. |
| `terminal` | [`issue_is_terminal`](../../tools/protocol_watcher/src/tracker.odin#L856) | Check whether a Linear issue is in a terminal state. |
| `page` | [`fetch_linear_page`](../../tools/protocol_watcher/src/tracker.odin#L966) | Fetch a bound page of Linear issues or comments. |
| `advance` | [`advance_linear_cursor`](../../tools/protocol_watcher/src/tracker.odin#L995) | Validate the next cursor and advance paginated scanning. |
| `fresh_issue` | [`fetch_current_issue`](../../tools/protocol_watcher/src/tracker.odin#L1082) | Fetch and validate an issue by its exact ID immediately before use. |
| `track` | [`sync_review_findings`](../../tools/protocol_watcher/src/tracker.odin#L1361) | Reconcile a protocol report with existing review issues and comments. |
| `ticket` | [`build_review_ticket`](../../tools/protocol_watcher/src/tracker.odin#L1493) | Build the review title, body and machine payload for a report. |
| `identifier_part` | [`is_identifier_continuation`](../../tools/protocol_watcher/src/triage.odin#L238) | Check whether a byte can continue a source identifier. |
| `number_end` | [`find_numeric_token_end`](../../tools/protocol_watcher/src/triage.odin#L294) | Locate the end of a numeric token. |
| `table` | [`extract_single_byte_token_table`](../../tools/protocol_watcher/src/triage.odin#L625) | Extract the single-byte dictionary and surrounding tokens from a TypeScript or Odin token stream. |
| `finish` | [`finish_change_assessment`](../../tools/protocol_watcher/src/triage.odin#L781) | Populate a triage assessment with its classification, reason and summary. |
| `assess` | [`assess_upstream_file_change`](../../tools/protocol_watcher/src/triage.odin#L923) | Classify an upstream change against its reference, local ownership and evidence. |
| `truth` | [`json_boolean_equals`](../../tools/protocol_watcher/src/value.odin#L95) | Check whether a JSON boolean equals the expected value. |
| `fields` | [`has_exact_object_fields`](../../tools/protocol_watcher/src/value.odin#L119) | Check that an object has exactly the expected fields. |
| `allowed_fields` | [`has_required_and_allowed_fields`](../../tools/protocol_watcher/src/value.odin#L360) | Check required and optional JSON object fields. |
| `run_valid` | [`is_project_actions_run_url`](../../tools/protocol_watcher/src/value.odin#L399) | Validate the exact GitHub Actions run URL for the monitored repository. |
| `prefix_runes` | [`unicode_prefix`](../../tools/protocol_watcher/src/value.odin#L523) | Return a prefix containing at most the requested number of Unicode characters. |
| `private_stat` | [`is_private_state_file`](../../tools/protocol_watcher/src/watch.odin#L321) | Check that a state file's stat data meets private ownership and mode requirements. |
| `check` | [`check_upstream_changes`](../../tools/protocol_watcher/src/watch.odin#L461) | Lock the state directory, run the check and record its outcome. |
| `good` | [`valid_agent_result`](../../tests/fixtures/protocol_watch/helpers.odin#L6) | Return a valid no-action result from a synthetic review agent. |
| `args_for` | [`schedule_options_for_test`](../../tests/fixtures/protocol_watch/helpers.odin#L14) | Construct a schedule rooted in the temporary test directory. |

The former byte helpers `store_get` and `store_put` were removed. The codecs now use `core:encoding/endian` for multibyte integers and index the buffer directly for one-byte fields.

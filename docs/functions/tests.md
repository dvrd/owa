# Tests and test harnesses

[Catalog index](README.md) · [Name changes](renames.md)

545 entries across 49 source files. Select a function to open its declaration.

| Source file | Functions |
|---|---:|
| [Taskfile.yml](#file-taskfile-yml) | 5 |
| [tests/addressing_test.odin](#file-tests-addressing-test-odin) | 9 |
| [tests/ascii_test.odin](#file-tests-ascii-test-odin) | 1 |
| [tests/auth_test.odin](#file-tests-auth-test-odin) | 14 |
| [tests/binary_node_test.odin](#file-tests-binary-node-test-odin) | 1 |
| [tests/binary_tokens_test.odin](#file-tests-binary-tokens-test-odin) | 1 |
| [tests/connection_test.odin](#file-tests-connection-test-odin) | 16 |
| [tests/contact_sync_test.odin](#file-tests-contact-sync-test-odin) | 3 |
| [tests/contacts_test.odin](#file-tests-contacts-test-odin) | 2 |
| [tests/e2e/child_process/child_process.odin](#file-tests-e2e-child-process-child-process-odin) | 5 |
| [tests/e2e/client/contact_sync_test.odin](#file-tests-e2e-client-contact-sync-test-odin) | 3 |
| [tests/e2e/client/media_test.odin](#file-tests-e2e-client-media-test-odin) | 6 |
| [tests/e2e/client/receive_test.odin](#file-tests-e2e-client-receive-test-odin) | 27 |
| [tests/e2e/client/send_peer.odin](#file-tests-e2e-client-send-peer-odin) | 23 |
| [tests/e2e/client/send_test.odin](#file-tests-e2e-client-send-test-odin) | 2 |
| [tests/e2e/client/socket_test.odin](#file-tests-e2e-client-socket-test-odin) | 9 |
| [tests/e2e/encrypted_recovery/compatibility.odin](#file-tests-e2e-encrypted-recovery-compatibility-odin) | 2 |
| [tests/e2e/encrypted_recovery/file_error_darwin.odin](#file-tests-e2e-encrypted-recovery-file-error-darwin-odin) | 1 |
| [tests/e2e/encrypted_recovery/file_error_linux.odin](#file-tests-e2e-encrypted-recovery-file-error-linux-odin) | 1 |
| [tests/e2e/encrypted_recovery/fixture.odin](#file-tests-e2e-encrypted-recovery-fixture-odin) | 17 |
| [tests/e2e/encrypted_recovery/main.odin](#file-tests-e2e-encrypted-recovery-main-odin) | 8 |
| [tests/e2e/encrypted_recovery/process_test.odin](#file-tests-e2e-encrypted-recovery-process-test-odin) | 8 |
| [tests/e2e/encrypted_recovery/recovery_test.odin](#file-tests-e2e-encrypted-recovery-recovery-test-odin) | 10 |
| [tests/e2e/encrypted_recovery/socket_recovery.odin](#file-tests-e2e-encrypted-recovery-socket-recovery-odin) | 16 |
| [tests/e2e/encrypted_recovery/socket_tcp.odin](#file-tests-e2e-encrypted-recovery-socket-tcp-odin) | 6 |
| [tests/e2e/loopback/loopback.odin](#file-tests-e2e-loopback-loopback-odin) | 6 |
| [tests/e2e/loopback_noise/handshake_test.odin](#file-tests-e2e-loopback-noise-handshake-test-odin) | 8 |
| [tests/e2e/protocol_watch/integration_test.odin](#file-tests-e2e-protocol-watch-integration-test-odin) | 17 |
| [tests/e2e/protocol_watch/schedule_test.odin](#file-tests-e2e-protocol-watch-schedule-test-odin) | 10 |
| [tests/e2e/recovery_campaign/main.odin](#file-tests-e2e-recovery-campaign-main-odin) | 12 |
| [tests/e2e/recovery_campaign/recovery_test.odin](#file-tests-e2e-recovery-campaign-recovery-test-odin) | 2 |
| [tests/e2e/version_http/version_test.odin](#file-tests-e2e-version-http-version-test-odin) | 2 |
| [tests/fixtures/client/helpers.odin](#file-tests-fixtures-client-helpers-odin) | 18 |
| [tests/fixtures/protocol_watch/helpers.odin](#file-tests-fixtures-protocol-watch-helpers-odin) | 4 |
| [tests/media_test.odin](#file-tests-media-test-odin) | 27 |
| [tests/pairing_test.odin](#file-tests-pairing-test-odin) | 41 |
| [tests/protobuf_test.odin](#file-tests-protobuf-test-odin) | 9 |
| [tests/receive_test.odin](#file-tests-receive-test-odin) | 47 |
| [tests/send_test.odin](#file-tests-send-test-odin) | 7 |
| [tests/signal_test.odin](#file-tests-signal-test-odin) | 1 |
| [tests/socket_test.odin](#file-tests-socket-test-odin) | 3 |
| [tests/state_store_test.odin](#file-tests-state-store-test-odin) | 4 |
| [tools/protocol_watcher/tests/main_test.odin](#file-tools-protocol-watcher-tests-main-test-odin) | 1 |
| [tools/protocol_watcher/tests/release_test.odin](#file-tools-protocol-watcher-tests-release-test-odin) | 12 |
| [tools/protocol_watcher/tests/schedule_test.odin](#file-tools-protocol-watcher-tests-schedule-test-odin) | 10 |
| [tools/protocol_watcher/tests/tracker_test.odin](#file-tools-protocol-watcher-tests-tracker-test-odin) | 73 |
| [tools/protocol_watcher/tests/triage_test.odin](#file-tools-protocol-watcher-tests-triage-test-odin) | 25 |
| [tools/protocol_watcher/tests/value_test.odin](#file-tools-protocol-watcher-tests-value-test-odin) | 1 |
| [tools/protocol_watcher/tests/watch_test.odin](#file-tools-protocol-watcher-tests-watch-test-odin) | 9 |

<a id="file-taskfile-yml"></a>

## Taskfile.yml

| Function | Behavior |
|---|---|
| [`cleanup`](../../Taskfile.yml#L86) | Terminate owned jobs and remove the staged test workspace. |
| [`copy_tree`](../../Taskfile.yml#L122) | Copy the selected repository or dependency tree into staging. |
| [`imports_of`](../../Taskfile.yml#L145) | List shared Odin imports used by the selected tree. |
| [`normalize`](../../Taskfile.yml#L150) | Resolve dot segments in an absolute path. |
| [`escaping_imports`](../../Taskfile.yml#L169) | Find relative imports that escape the staged tree. |

<a id="file-tests-addressing-test-odin"></a>

## tests/addressing_test.odin

| Function | Behavior |
|---|---|
| [`group_metadata_query_encode_builds_the_interactive_query_and_validates_input`](../../tests/addressing_test.odin#L10) | Check the encoded interactive group metadata IQ and invalid argument errors. |
| [`identity_api_fixture`](../../tests/addressing_test.odin#L42) | Initialize persistent identity and prekey stores for the socket. |
| [`identity_api_fixture_destroy`](../../tests/addressing_test.odin#L69) | Erase identity fixture secrets and release files and stores. |
| [`identity_api_pin`](../../tests/addressing_test.odin#L80) | Construct deterministic identity pin bytes. |
| [`identity_api_has`](../../tests/addressing_test.odin#L89) | Check for a specific record in the fixture store. |
| [`lid_mapping_records_both_directions_durably_and_is_idempotent`](../../tests/addressing_test.odin#L96) | Store a phone/LID pair twice and reload both lookup directions. |
| [`lid_mapping_rejects_conflicts_and_malformed_pairs_without_mutation`](../../tests/addressing_test.odin#L131) | Attempt conflicting and malformed mappings and compare store contents. |
| [`lid_mapping_migrates_existing_lid_state_to_the_phone_address`](../../tests/addressing_test.odin#L164) | Migrate existing LID-keyed state to the resolved phone address. |
| [`lid_mapping_failed_save_keeps_the_store_unchanged`](../../tests/addressing_test.odin#L185) | Fail persistence and verify that the live mapping stays intact. |

<a id="file-tests-ascii-test-odin"></a>

## tests/ascii_test.odin

| Function | Behavior |
|---|---|
| [`ascii_character_classes_preserve_byte_and_rune_boundaries`](../../tests/ascii_test.odin#L7) | Check byte and rune class boundaries, including a non-ASCII rune with an ASCII low byte. |

<a id="file-tests-auth-test-odin"></a>

## tests/auth_test.odin

| Function | Behavior |
|---|---|
| [`pairing_domain_auth`](../../tests/auth_test.odin#L12) | Build authentication state for an account-domain fixture. |
| [`pairing_domain_checksum`](../../tests/auth_test.odin#L23) | Recompute the test snapshot checksum. |
| [`pairing_domain_v1`](../../tests/auth_test.odin#L30) | Construct a version-one authentication snapshot. |
| [`pairing_auth_current_roundtrip_retains_policy_and_rejects_legacy_domain`](../../tests/auth_test.odin#L43) | Round-trip current account policy and reject a signature from the legacy domain. |
| [`pairing_auth_reads_historical_v1_and_rewrites_without_resigning_or_domain_guessing`](../../tests/auth_test.odin#L75) | Load a v1 snapshot and write it back while preserving its original signatures. |
| [`pairing_auth_invalid_policy_version_and_truncation_preserve_destination`](../../tests/auth_test.odin#L120) | Corrupt policy/version fields or truncate input and check the destination is intact. |
| [`pairing_auth_unpaired_v1_remains_readable`](../../tests/auth_test.odin#L157) | Decode an unpaired version-one authentication snapshot. |
| [`pairing_auth_disk_save_load_preserves_current_and_historical_policy`](../../tests/auth_test.odin#L178) | Save and reopen both historical and current account policy formats. |
| [`prekey_lifecycle_fixture`](../../tests/auth_test.odin#L229) | Initialize device credentials and a prekey store for a lifecycle test. |
| [`prekey_lifecycle_destroy`](../../tests/auth_test.odin#L243) | Erase and release prekey lifecycle fixture resources. |
| [`prekey_lifecycle_ack`](../../tests/auth_test.odin#L252) | Construct the IQ response used to acknowledge a prekey upload. |
| [`prekey_lifecycle_capacity_and_id_exhaustion_are_explicit_and_unchanged`](../../tests/auth_test.odin#L259) | Exercise capacity and key-ID exhaustion and compare state after rejection. |
| [`prekey_lifecycle_lost_response_reloads_and_reuses_pending_keys_until_matching_iq`](../../tests/auth_test.odin#L286) | Lose an upload reply, reopen the store and check batch reuse until the matching IQ. |
| [`prekey_lifecycle_consumed_highest_id_may_be_absent_without_reuse`](../../tests/auth_test.odin#L340) | Consume the highest allocated ID and verify generation advances past it. |

<a id="file-tests-binary-node-test-odin"></a>

## tests/binary_node_test.odin

| Function | Behavior |
|---|---|
| [`binary_node_decode_requires_exactly_one_complete_node`](../../tests/binary_node_test.odin#L7) | Decode a complete receipt node and reject a truncated node or trailing wire bytes. |

<a id="file-tests-binary-tokens-test-odin"></a>

## tests/binary_tokens_test.odin

| Function | Behavior |
|---|---|
| [`binary_token_dictionary_prefixes_select_the_expected_wire_table`](../../tests/binary_tokens_test.odin#L7) | Decode a fixed wire prefix from each dictionary and check the single-byte table endpoints used by the protocol. |

<a id="file-tests-connection-test-odin"></a>

## tests/connection_test.odin

| Function | Behavior |
|---|---|
| [`policy_test_options`](../../tests/connection_test.odin#L28) | Build valid initial certificate options for a synthetic chain. |
| [`policy_test_bytes`](../../tests/connection_test.odin#L37) | Write a length-delimited field into the test certificate. |
| [`policy_test_scalar`](../../tests/connection_test.odin#L44) | Write an integer field into the test certificate. |
| [`policy_test_details`](../../tests/connection_test.odin#L50) | Encode test certificate details with the configured omissions and sizes. |
| [`policy_test_certificate`](../../tests/connection_test.odin#L86) | Wrap signed test details and signature as a certificate. |
| [`policy_test_chain`](../../tests/connection_test.odin#L100) | Encode the test leaf and intermediate into a chain. |
| [`policy_test_fixture`](../../tests/connection_test.odin#L117) | Generate deterministic keys and sign a synthetic server chain. |
| [`policy_test_verify`](../../tests/connection_test.odin#L162) | Verify the fixture at the requested time using its test root. |
| [`certificate_policy_valid_synthetic_chain_does_not_replace_pinned_root`](../../tests/connection_test.odin#L170) | Check that a valid test-root signature cannot replace the pinned WhatsApp root. |
| [`certificate_policy_checks_both_raw_signatures_and_server_static`](../../tests/connection_test.odin#L187) | Independently alter each signature and the handshake key and verify rejection. |
| [`certificate_policy_enforces_presence_lengths_and_issuer_linkage`](../../tests/connection_test.odin#L233) | Vary missing fields, key lengths and issuer serial linkage. |
| [`certificate_policy_checks_exact_time_boundaries_without_epoch_overflow`](../../tests/connection_test.odin#L267) | Exercise the exact validity endpoints and out-of-range timestamps. |
| [`certificate_policy_malformed_or_incomplete_chain_fails_closed`](../../tests/connection_test.odin#L302) | Feed malformed or incomplete certificate chains and check their errors. |
| [`certificate_policy_genuine_public_chain_matches_pinned_signal_root`](../../tests/connection_test.odin#L351) | Verify a recorded public chain against the pinned root at its capture time. |
| [`frame_reader_reassembles_split_frames_and_bounds_its_storage`](../../tests/connection_test.odin#L367) | Feed partial frames and verify reassembly and bounded reader capacity. |
| [`noise_credentials_are_random_nonzero_and_accepted_by_client_init`](../../tests/connection_test.odin#L395) | Generate distinct nonzero Noise credentials and use them to initialize a client. |

<a id="file-tests-contact-sync-test-odin"></a>

## tests/contact_sync_test.odin

| Function | Behavior |
|---|---|
| [`contact_sync_rejects_forged_records_and_collection_signatures`](../../tests/contact_sync_test.odin#L8) | Reject corrupted index, value and collection signatures without committing candidate contacts. |
| [`alternate_contact_index_renames_and_removes_one_saved_contact`](../../tests/contact_sync_test.odin#L60) | Rename and delete through either linked JID and verify that the original name disappears. |
| [`contact_add_patch_round_trips_through_authenticated_sync`](../../tests/contact_sync_test.odin#L83) | Decode two signed updates for the same address, verify its names and linked identity, and reject an undersized output buffer. |

<a id="file-tests-contacts-test-odin"></a>

## tests/contacts_test.odin

| Function | Behavior |
|---|---|
| [`contact_search_matches_unicode_saved_names_and_rejects_blank_queries`](../../tests/contacts_test.odin#L7) | Search stored Unicode names case-insensitively during sync and reject a blank query. |
| [`contact_jids_outlive_the_lookup_buffer`](../../tests/contacts_test.odin#L26) | Reuse the input buffer after saved and profile-only lookups and verify that both return a stable JID. |

<a id="file-tests-e2e-child-process-child-process-odin"></a>

## tests/e2e/child_process/child_process.odin

| Function | Behavior |
|---|---|
| [`start`](../../tests/e2e/child_process/child_process.odin#L18) | Start another copy of the test executable and capture its fixture output. |
| [`read_line`](../../tests/e2e/child_process/child_process.odin#L36) | Read one bounded line of output from the fixture before its deadline. |
| [`wait`](../../tests/e2e/child_process/child_process.odin#L61) | Reap the child and verify its expected exit or signal. |
| [`kill_at_boundary`](../../tests/e2e/child_process/child_process.odin#L76) | Send SIGKILL to the owned fixture process and verify its termination. |
| [`close`](../../tests/e2e/child_process/child_process.odin#L81) | Release the output pipe and reap a fixture that is still running. |

<a id="file-tests-e2e-client-contact-sync-test-odin"></a>

## tests/e2e/client/contact_sync_test.odin

| Function | Behavior |
|---|---|
| [`contact_sync_searches_saved_names_and_resumes_after_restart`](../../tests/e2e/client/contact_sync_test.odin#L13) | Exercise a missing key request, authenticated contact import, persisted search, rename, removal and rejected patch. |
| [`contact_download_during_update`](../../tests/e2e/client/contact_sync_test.odin#L268) | Apply a live profile update during a simulated CDN fetch. |
| [`external_profile_history_resumes_and_preserves_incoming_updates`](../../tests/e2e/client/contact_sync_test.odin#L276) | Restart with a pending history download, retry a CDN failure and verify both historical and live profile names. |

<a id="file-tests-e2e-client-media-test-odin"></a>

## tests/e2e/client/media_test.odin

| Function | Behavior |
|---|---|
| [`send_image_encrypts_uploads_and_delivers_to_every_device`](../../tests/e2e/client/media_test.odin#L12) | Send a group image and decrypt it at every synthetic recipient. |
| [`send_image_upload_rejection_sends_no_message`](../../tests/e2e/client/media_test.odin#L64) | Reject the upload and verify that no message stanza is sent. |
| [`send_image_failed_write_keeps_the_durable_outbound_message`](../../tests/e2e/client/media_test.odin#L81) | Fail the final image write and reopen the persisted outbound intent. |
| [`send_reaction_delivers_checkmark_by_default_and_custom_text`](../../tests/e2e/client/media_test.odin#L101) | Send the default checkmark and a custom reaction through the group path. |
| [`http_execute_runs_off_thread_while_the_socket_keeps_serving_the_connection`](../../tests/e2e/client/media_test.odin#L137) | Check that an HTTP job runs on a worker while the socket continues servicing events. |
| [`http_execute_reports_executor_failure_as_media_http_failure`](../../tests/e2e/client/media_test.odin#L171) | Map an HTTP executor failure into the socket media error. |

<a id="file-tests-e2e-client-receive-test-odin"></a>

## tests/e2e/client/receive_test.odin

| Function | Behavior |
|---|---|
| [`ack_routing_input`](../../tests/e2e/client/receive_test.odin#L14) | Turn a test stanza into encrypted WebSocket input. |
| [`ack_routing_stage`](../../tests/e2e/client/receive_test.odin#L52) | Set the socket phase and provisioning stage for an ACK scenario. |
| [`ack_routing_expect_exact`](../../tests/e2e/client/receive_test.odin#L68) | Decrypt a captured outgoing stanza and check its exact acknowledgement attributes. |
| [`ack_routing_encrypted_case`](../../tests/e2e/client/receive_test.odin#L104) | Exercise a control acknowledgement through the encrypted socket path. |
| [`mandatory_receipt_ack_encrypted_provisioning_matches_online`](../../tests/e2e/client/receive_test.odin#L144) | Compare encrypted receipt ACKs during provisioning and online operation. |
| [`mandatory_call_ack_encrypted_preserves_call_visibility_without_answering`](../../tests/e2e/client/receive_test.odin#L153) | Check that acknowledging a call preserves its event without answering it. |
| [`ack_routing_retry_node`](../../tests/e2e/client/receive_test.odin#L171) | Build an incoming retry receipt. |
| [`ack_routing_expect_retry_ack`](../../tests/e2e/client/receive_test.odin#L175) | Check routing fields on the outgoing retry acknowledgement. |
| [`ack_retry_tick_read`](../../tests/e2e/client/receive_test.odin#L207) | Return EOF from the controlled retry stream. |
| [`ack_retry_tick_write`](../../tests/e2e/client/receive_test.odin#L214) | Simulate a stream write that makes no progress. |
| [`mandatory_provisioning_retry_is_owned_until_online_and_outside_query`](../../tests/e2e/client/receive_test.odin#L222) | Queue a retry during provisioning and process it once online outside a query. |
| [`mandatory_provisioning_retry_keeps_existing_64_bound_and_ack_order`](../../tests/e2e/client/receive_test.odin#L293) | Fill the deferred retry queue and check its 64-entry limit and acknowledgement order. |
| [`message_ack_durable_write`](../../tests/e2e/client/receive_test.odin#L338) | Inspect the persisted inbox from inside the transport write callback. |
| [`message_ack_event_stage`](../../tests/e2e/client/receive_test.odin#L356) | Stage the incoming message as a durable socket event. |
| [`message_ack_expect_frames`](../../tests/e2e/client/receive_test.odin#L377) | Decode outgoing frames and check their acknowledgement sequence. |
| [`message_ack_reopen_and_complete`](../../tests/e2e/client/receive_test.odin#L428) | Reopen the store and complete the recovered incoming message. |
| [`message_ack_durable_inbox_precedes_wire_and_failed_ack_remains_recoverable`](../../tests/e2e/client/receive_test.odin#L477) | Observe persisted inbox state at wire-write time and reopen it after failed acknowledgement. |
| [`message_ack_failed_inbox_commit_exposes_no_event_or_wire`](../../tests/e2e/client/receive_test.odin#L516) | Fail the inbox transaction and verify that neither an event nor wire bytes escape. |
| [`negative_ack_stream_read`](../../tests/e2e/client/receive_test.odin#L541) | Serve encrypted fixture bytes to the socket. |
| [`negative_ack_stream_write`](../../tests/e2e/client/receive_test.odin#L555) | Record or reject writes from the negative-ack socket. |
| [`negative_ack_stream_close`](../../tests/e2e/client/receive_test.odin#L562) | Close the simulated negative-ack transport. |
| [`negative_ack_encrypted_stream`](../../tests/e2e/client/receive_test.odin#L566) | Wrap a test stanza in an encrypted stream for socket reception. |
| [`negative_ack_encrypted_socket_read_surfaces_rejection_before_pending_absence`](../../tests/e2e/client/receive_test.odin#L631) | Receive an encrypted rejection and check the error seen by the socket caller. |
| [`status_ack_read`](../../tests/e2e/client/receive_test.odin#L658) | Read encrypted status input from the test stream. |
| [`status_ack_write`](../../tests/e2e/client/receive_test.odin#L664) | Capture the outgoing status acknowledgement. |
| [`status_ack_encrypted_input`](../../tests/e2e/client/receive_test.odin#L670) | Wrap a status node in the encrypted transport input. |
| [`status_ack_encrypted_socket_read_handles_provisioning_offline_batch`](../../tests/e2e/client/receive_test.odin#L718) | Read a status from an encrypted offline batch during provisioning. |

<a id="file-tests-e2e-client-send-peer-odin"></a>

## tests/e2e/client/send_peer.odin

| Function | Behavior |
|---|---|
| [`send_peer_private`](../../tests/e2e/client/send_peer.odin#L49) | Generate deterministic private-key material for a peer. |
| [`send_peer_local`](../../tests/e2e/client/send_peer.odin#L62) | Construct a peer’s local Signal identity and prekeys. |
| [`send_peer_bundle`](../../tests/e2e/client/send_peer.odin#L74) | Build and sign a remote prekey bundle. |
| [`send_peer_noise_key`](../../tests/e2e/client/send_peer.odin#L94) | Construct deterministic transport-key bytes. |
| [`send_peer_server_frame`](../../tests/e2e/client/send_peer.odin#L104) | Encode the peer’s binary WebSocket frame. |
| [`send_peer_read`](../../tests/e2e/client/send_peer.odin#L122) | Serve queued peer data through the test transport. |
| [`send_peer_close`](../../tests/e2e/client/send_peer.odin#L144) | Close the simulated peer connection. |
| [`send_peer_deadline`](../../tests/e2e/client/send_peer.odin#L148) | Handle a stream deadline in the fixture. |
| [`send_peer_enqueue`](../../tests/e2e/client/send_peer.odin#L152) | Queue an encrypted peer reply. |
| [`send_peer_device_node`](../../tests/e2e/client/send_peer.odin#L179) | Build a device child for a discovery result. |
| [`send_peer_user_node`](../../tests/e2e/client/send_peer.odin#L186) | Build a user node with its device list. |
| [`send_peer_participant_node`](../../tests/e2e/client/send_peer.odin#L197) | Build a participant node for the group metadata response. |
| [`send_peer_iq`](../../tests/e2e/client/send_peer.odin#L204) | Create the peer’s IQ response envelope. |
| [`send_peer_device_index`](../../tests/e2e/client/send_peer.odin#L255) | Locate the fixture device matching an address. |
| [`send_peer_keys`](../../tests/e2e/client/send_peer.odin#L263) | Build a key bundle response for the requested devices. |
| [`send_peer_unpad`](../../tests/e2e/client/send_peer.odin#L301) | Remove test message padding before verification. |
| [`send_peer_message`](../../tests/e2e/client/send_peer.odin#L324) | Decrypt and inspect the group message at the receiving peer. |
| [`send_peer_write`](../../tests/e2e/client/send_peer.odin#L448) | Decode and route the client’s writes through the simulated server. |
| [`send_peer_http`](../../tests/e2e/client/send_peer.odin#L516) | Handle fixture media HTTP requests. |
| [`send_peer_new`](../../tests/e2e/client/send_peer.odin#L543) | Create the peer and its socket, devices and stores. |
| [`send_peer_destroy`](../../tests/e2e/client/send_peer.odin#L612) | Close the socket and release fixture secrets and files. |
| [`send_peer_use_pipe`](../../tests/e2e/client/send_peer.odin#L646) | Attach an operating-system pipe for polling behavior. |
| [`send_peer_announce`](../../tests/e2e/client/send_peer.odin#L652) | Signal availability of test peer data. |

<a id="file-tests-e2e-client-send-test-odin"></a>

## tests/e2e/client/send_test.odin

| Function | Behavior |
|---|---|
| [`send_id_successful_pending_replay_preserves_exact_inner_packet`](../../tests/e2e/client/send_test.odin#L8) | Decrypt a replay and compare its inner packet with the saved bytes. |
| [`send_id_targeted_retry_bypasses_pending_replay_without_changing_intent`](../../tests/e2e/client/send_test.odin#L32) | Force a device-targeted retry and verify that the original intent is preserved. |

<a id="file-tests-e2e-client-socket-test-odin"></a>

## tests/e2e/client/socket_test.odin

| Function | Behavior |
|---|---|
| [`socket_cert_test_read`](../../tests/e2e/client/socket_test.odin#L24) | Serve the fixed handshake transcript in small reads. |
| [`socket_cert_test_write`](../../tests/e2e/client/socket_test.odin#L37) | Capture partial writes from the handshake under test. |
| [`socket_cert_test_close`](../../tests/e2e/client/socket_test.odin#L46) | Count transport closure after handshake success or failure. |
| [`socket_cert_test_verify`](../../tests/e2e/client/socket_test.odin#L53) | Inspect the decrypted certificate and return the configured decision. |
| [`socket_cert_test_init`](../../tests/e2e/client/socket_test.odin#L65) | Initialize the test socket with a verifier and deterministic handshake keys. |
| [`socket_cert_test_frames`](../../tests/e2e/client/socket_test.odin#L100) | Count complete WebSocket frames in the captured output. |
| [`socket_cert_test_case`](../../tests/e2e/client/socket_test.odin#L118) | Run a handshake with the chosen verifier and check its result and side effects. |
| [`socket_certificate_handshake_uses_custom_verifier_result`](../../tests/e2e/client/socket_test.odin#L169) | Supply accepting and rejecting callbacks and check handshake success, failure and frame counts. |
| [`socket_certificate_nil_default_rejects_synthetic_issuer_only_chain`](../../tests/e2e/client/socket_test.odin#L175) | Leave the callback unset and verify that the default rejects the fixture’s missing leaf. |

<a id="file-tests-e2e-encrypted-recovery-compatibility-odin"></a>

## tests/e2e/encrypted_recovery/compatibility.odin

| Function | Behavior |
|---|---|
| [`compat_credentials`](../../tests/e2e/encrypted_recovery/compatibility.odin#L9) | Construct deterministic credentials used across producer and verifier builds. |
| [`compat_verify`](../../tests/e2e/encrypted_recovery/compatibility.odin#L31) | Load the producer snapshot with the candidate build and verify subsequent traffic. |

<a id="file-tests-e2e-encrypted-recovery-file-error-darwin-odin"></a>

## tests/e2e/encrypted_recovery/file_error_darwin.odin

| Function | Behavior |
|---|---|
| [`write_error_is_efbig`](../../tests/e2e/encrypted_recovery/file_error_darwin.odin#L7) | Recognize the Darwin file-size-limit write error. |

<a id="file-tests-e2e-encrypted-recovery-file-error-linux-odin"></a>

## tests/e2e/encrypted_recovery/file_error_linux.odin

| Function | Behavior |
|---|---|
| [`write_error_is_efbig`](../../tests/e2e/encrypted_recovery/file_error_linux.odin#L5) | Recognize the Linux file-size-limit write error. |

<a id="file-tests-e2e-encrypted-recovery-fixture-odin"></a>

## tests/e2e/encrypted_recovery/fixture.odin

| Function | Behavior |
|---|---|
| [`fixture_private`](../../tests/e2e/encrypted_recovery/fixture.odin#L12) | Construct a deterministic test private scalar. |
| [`fixture_local`](../../tests/e2e/encrypted_recovery/fixture.odin#L25) | Construct local Signal keys for the selected fixture device. |
| [`fixture_bundle`](../../tests/e2e/encrypted_recovery/fixture.odin#L37) | Build the test device’s signed prekey bundle. |
| [`fixture_identity`](../../tests/e2e/encrypted_recovery/fixture.odin#L74) | Construct the identity bytes used for fixture ownership. |
| [`fixture_close`](../../tests/e2e/encrypted_recovery/fixture.odin#L81) | Clear secrets and release allocated fixture state. |
| [`session_bytes`](../../tests/e2e/encrypted_recovery/fixture.odin#L90) | Encode a session into independent bytes for comparison or persistence. |
| [`session_set`](../../tests/e2e/encrypted_recovery/fixture.odin#L100) | Save an encoded pairwise session in the test store. |
| [`session_get`](../../tests/e2e/encrypted_recovery/fixture.odin#L110) | Load and decode a pairwise session from the test store. |
| [`prekeys_set`](../../tests/e2e/encrypted_recovery/fixture.odin#L115) | Persist the fixture prekey store in the state snapshot. |
| [`prekeys_get`](../../tests/e2e/encrypted_recovery/fixture.odin#L129) | Restore and validate the fixture prekeys for the expected owner. |
| [`fixture_open`](../../tests/e2e/encrypted_recovery/fixture.odin#L151) | Initialize the scoped recovery fixture and its persistent store. |
| [`fixture_first`](../../tests/e2e/encrypted_recovery/fixture.odin#L179) | Establish the initiator and encrypt the first prekey packet. |
| [`fixture_receive_first`](../../tests/e2e/encrypted_recovery/fixture.odin#L219) | Decrypt the first packet as the recipient and record the resulting state. |
| [`fixture_established`](../../tests/e2e/encrypted_recovery/fixture.odin#L238) | Exchange messages to create established sessions on both ends. |
| [`fixture_load_pair`](../../tests/e2e/encrypted_recovery/fixture.odin#L263) | Reload both sessions and check their persisted keys. |
| [`fixture_encrypt`](../../tests/e2e/encrypted_recovery/fixture.odin#L272) | Encrypt the fixture payload and stage the resulting session and packet. |
| [`fixture_decrypt`](../../tests/e2e/encrypted_recovery/fixture.odin#L285) | Decrypt a persisted packet and stage the receiving session. |

<a id="file-tests-e2e-encrypted-recovery-main-odin"></a>

## tests/e2e/encrypted_recovery/main.odin

| Function | Behavior |
|---|---|
| [`boundary`](../../tests/e2e/encrypted_recovery/main.odin#L13) | Announce a crash boundary and wait for the controller. |
| [`stage_run`](../../tests/e2e/encrypted_recovery/main.odin#L21) | Drive the specified persistence stage or socket stage. |
| [`verify_prekey`](../../tests/e2e/encrypted_recovery/main.odin#L58) | Verify one-time prekey consumption and session integrity after recovery. |
| [`verify_sender`](../../tests/e2e/encrypted_recovery/main.odin#L93) | Verify the restored sender state by continuing encrypted traffic. |
| [`verify_run`](../../tests/e2e/encrypted_recovery/main.odin#L124) | Dispatch verification for the named recovery boundary. |
| [`limited_write`](../../tests/e2e/encrypted_recovery/main.odin#L158) | Exercise recovery from a file-size-limited write. |
| [`corrupt_load`](../../tests/e2e/encrypted_recovery/main.odin#L181) | Load corrupted state and check preservation of live state. |
| [`run_recovery_child`](../../tests/e2e/encrypted_recovery/main.odin#L207) | Dispatch a fixture operation when a parent test starts this executable as a child. |

<a id="file-tests-e2e-encrypted-recovery-process-test-odin"></a>

## tests/e2e/encrypted_recovery/process_test.odin

| Function | Behavior |
|---|---|
| [`make_owned_directory`](../../tests/e2e/encrypted_recovery/process_test.odin#L13) | Create a private temporary recovery directory with the synthetic owner marker. |
| [`fixture_file`](../../tests/e2e/encrypted_recovery/process_test.odin#L27) | Read a file from the disposable recovery fixture. |
| [`run_to_exit`](../../tests/e2e/encrypted_recovery/process_test.odin#L33) | Run a fixture operation in a fresh process and check its exit status. |
| [`socket_peer_handoff`](../../tests/e2e/encrypted_recovery/process_test.odin#L39) | Compare the independent TCP peer’s authenticated frame hash and ACK against the expected stage. |
| [`exercise_socket_stage`](../../tests/e2e/encrypted_recovery/process_test.odin#L76) | Run a real TCP peer for one send or restart and verify its observed frames and shutdown. |
| [`encrypted_state_survives_crash_boundaries`](../../tests/e2e/encrypted_recovery/process_test.odin#L119) | Kill the process at each durable boundary and check reopened state, ciphertext, prekeys and replay. |
| [`failed_write_and_corrupt_snapshots_preserve_sessions`](../../tests/e2e/encrypted_recovery/process_test.odin#L166) | Exercise file-size exhaustion, checksum damage and truncation without altering the good store. |
| [`read_sessions_written_by_prior_revision`](../../tests/e2e/encrypted_recovery/process_test.odin#L197) | Open the fixed historical state and prekey files twice and authenticate the queued message. |

<a id="file-tests-e2e-encrypted-recovery-recovery-test-odin"></a>

## tests/e2e/encrypted_recovery/recovery_test.odin

| Function | Behavior |
|---|---|
| [`unit_fixture`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L8) | Create a temporary directory and initialize the recovery fixture. |
| [`unit_cleanup`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L13) | Release recovery state and remove its temporary directory. |
| [`unit_reload`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L19) | Save and reopen state to simulate a process restart. |
| [`unit_whisper`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L29) | Encrypt a Whisper packet for use in recovery assertions. |
| [`recovery_delayed_packet_survives_dh_ratchet_and_disk_restart`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L41) | Restart both sides after a DH ratchet and decrypt a delayed packet. |
| [`recovery_untrusted_new_device_requires_explicit_identity`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L85) | Attempt recovery with a new device identity before and after explicit trust. |
| [`recovery_rotated_signed_prekey_keeps_existing_session_generation`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L155) | Rotate a signed prekey and check that an existing generation remains usable. |
| [`recovery_bad_prekey_mac_does_not_consume_key_or_initialize_session`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L221) | Tamper with a prekey MAC and compare session state and key consumption. |
| [`recovery_corrupt_inner_session_preserves_live_ratchet`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L257) | Load a corrupted inner session and check that the live ratchet survives. |
| [`recovery_socket_encrypted_send_and_inbound_positive_ack_control`](../../tests/e2e/encrypted_recovery/recovery_test.odin#L277) | Run the successful encrypted send and positive acknowledgement as a control. |

<a id="file-tests-e2e-encrypted-recovery-socket-recovery-odin"></a>

## tests/e2e/encrypted_recovery/socket_recovery.odin

| Function | Behavior |
|---|---|
| [`socket_body`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L35) | Construct the fixture message body. |
| [`socket_recovery_close`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L45) | Release socket recovery state and clear secrets. |
| [`socket_recovery_read`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L52) | Feed buffered peer data to the test WebSocket. |
| [`socket_recovery_stream_close`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L73) | Return a successful close from the fixture stream callback. |
| [`socket_owned_write`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L77) | Create a private evidence file exclusively, write its bytes and sync both the file and its directory. |
| [`socket_state_witness`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L92) | Compute evidence of the durable socket state. |
| [`socket_recovery_write`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L121) | Observe client writes and trigger the selected persistence boundary. |
| [`socket_recovery_attach`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L165) | Attach the controlled transport to the recovery socket. |
| [`socket_recovery_prepare`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L229) | Prepare persistent keys, group state and transport for a send. |
| [`socket_recovery_send`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L262) | Send the recoverable group message with its stable intent ID. |
| [`socket_recovery_ack_frame`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L284) | Encode the simulated server acknowledgement as a frame. |
| [`socket_recovery_ack`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L311) | Deliver the acknowledgement and process the resulting state. |
| [`socket_stage_run`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L330) | Run a socket send through the requested crash stage. |
| [`socket_transport_inner`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L366) | Extract the encrypted application payload from transport framing. |
| [`socket_peer_decrypt`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L387) | Open the group message as the recipient and check its plaintext. |
| [`socket_verify_run`](../../tests/e2e/encrypted_recovery/socket_recovery.odin#L450) | Reopen the store and verify replay, peer decryption and acknowledgement. |

<a id="file-tests-e2e-encrypted-recovery-socket-tcp-odin"></a>

## tests/e2e/encrypted_recovery/socket_tcp.odin

| Function | Behavior |
|---|---|
| [`socket_tcp_close`](../../tests/e2e/encrypted_recovery/socket_tcp.odin#L17) | Close the native TCP peer connection. |
| [`socket_tcp_connect`](../../tests/e2e/encrypted_recovery/socket_tcp.odin#L23) | Connect the fixture to its owned loopback peer. |
| [`socket_tcp_wait_replay`](../../tests/e2e/encrypted_recovery/socket_tcp.odin#L44) | Wait for replay on the recovering client connection. |
| [`socket_tcp_packet`](../../tests/e2e/encrypted_recovery/socket_tcp.odin#L69) | Construct the packet used by the native peer. |
| [`socket_tcp_receive`](../../tests/e2e/encrypted_recovery/socket_tcp.odin#L102) | Read one fixture packet from TCP. |
| [`socket_tcp_peer`](../../tests/e2e/encrypted_recovery/socket_tcp.odin#L138) | Listen on loopback and execute the peer side of the recovery scenario. |

<a id="file-tests-e2e-loopback-loopback-odin"></a>

## tests/e2e/loopback/loopback.odin

| Function | Behavior |
|---|---|
| [`listen`](../../tests/e2e/loopback/loopback.odin#L7) | Bind an ephemeral loopback TCP port and bound the wait for a client. |
| [`accept`](../../tests/e2e/loopback/loopback.odin#L16) | Accept a loopback connection and install its I/O deadline. |
| [`read_exact`](../../tests/e2e/loopback/loopback.odin#L25) | Read and assert the requested number of TCP bytes. |
| [`send_all`](../../tests/e2e/loopback/loopback.odin#L30) | Write and assert the complete TCP payload. |
| [`read_headers`](../../tests/e2e/loopback/loopback.odin#L35) | Read bounded HTTP headers through the terminating blank line. |
| [`header_value`](../../tests/e2e/loopback/loopback.odin#L45) | Find a unique case-insensitive header and return its trimmed value. |

<a id="file-tests-e2e-loopback-noise-handshake-test-odin"></a>

## tests/e2e/loopback_noise/handshake_test.odin

| Function | Behavior |
|---|---|
| [`fixture_verify_certificate`](../../tests/e2e/loopback_noise/handshake_test.odin#L17) | Accept the fixed certificate bytes used by the synthetic Noise transcript. |
| [`fixture_client`](../../tests/e2e/loopback_noise/handshake_test.odin#L23) | Initialize a client with synthetic static and ephemeral keys. |
| [`fixture_run`](../../tests/e2e/loopback_noise/handshake_test.odin#L44) | Check handshake success, truncation, timeout and key cleanup for the selected exchange. |
| [`check_client_allocations`](../../tests/e2e/loopback_noise/handshake_test.odin#L120) | Verify the loopback client releases its allocations without invalid frees. |
| [`expect_client_frame`](../../tests/e2e/loopback_noise/handshake_test.odin#L143) | Unmask a client WebSocket frame and compare its opcode and bytes with the fixed vector. |
| [`noise_envelope`](../../tests/e2e/loopback_noise/handshake_test.odin#L155) | Prefix fixture payload bytes with a three-byte network-order length. |
| [`serve_noise_transcript`](../../tests/e2e/loopback_noise/handshake_test.odin#L163) | Play the fixed WebSocket and Noise transcript with the requested fragmentation or error. |
| [`noise_handshake_over_local_websocket`](../../tests/e2e/loopback_noise/handshake_test.odin#L208) | Exercise normal, truncated, timed-out and repeated loopback Noise handshakes. |

<a id="file-tests-e2e-protocol-watch-integration-test-odin"></a>

## tests/e2e/protocol_watch/integration_test.odin

| Function | Behavior |
|---|---|
| [`observe_get`](../../tests/e2e/protocol_watch/integration_test.odin#L22) | Serve controlled upstream file versions to the watcher. |
| [`integrated_observation`](../../tests/e2e/protocol_watch/integration_test.odin#L33) | Build an upstream observation using the controlled transport. |
| [`integration_case`](../../tests/e2e/protocol_watch/integration_test.odin#L44) | Run one fixture change through observation and assessment. |
| [`integration_comment_drift_has_no_action_proof`](../../tests/e2e/protocol_watch/integration_test.odin#L140) | Classify a comment-only change and check the evidence for taking no action. |
| [`integration_behavior_drift_specific_spike`](../../tests/e2e/protocol_watch/integration_test.odin#L145) | Classify a behavior change and check the proposed investigation. |
| [`integration_unapproved_table_spike_indices`](../../tests/e2e/protocol_watch/integration_test.odin#L150) | Report changed dictionary indices when no approved contract is present. |
| [`integration_unchanged_no_assessment`](../../tests/e2e/protocol_watch/integration_test.odin#L155) | Confirm an unchanged file receives no change assessment. |
| [`integration_completed_watcher_returns_without_signal`](../../tests/e2e/protocol_watch/integration_test.odin#L160) | Reap a completed watcher normally. |
| [`contract_scan`](../../tests/e2e/protocol_watch/integration_test.odin#L168) | Provide a controlled scan result to the contract check. |
| [`integration_ci_only_explicit_contract`](../../tests/e2e/protocol_watch/integration_test.odin#L176) | Require an explicitly supplied contract during CI preparation. |
| [`integration_source_reference_presence_is_strict`](../../tests/e2e/protocol_watch/integration_test.odin#L200) | Reject an observation that misstates reference-file presence. |
| [`integration_watch_runner_forwards_contract_without_execution`](../../tests/e2e/protocol_watch/integration_test.odin#L221) | Pass the approved contract to the watcher without executing it as code. |
| [`serve`](../../tests/e2e/protocol_watch/integration_test.odin#L253) | Serve the controlled local HTTP response. |
| [`fetch_peer`](../../tests/e2e/protocol_watch/integration_test.odin#L274) | Start the fixture listener and run the fetch against it. |
| [`watch_redirect_never_followed`](../../tests/e2e/protocol_watch/integration_test.odin#L300) | Return an HTTP redirect and verify the fetch stops at the original endpoint. |
| [`transport_bounds_missing_http_and_redacted_auth`](../../tests/e2e/protocol_watch/integration_test.odin#L311) | Check the response-size, missing-file, HTTP error and authorization-redaction paths. |
| [`linear_owned_http_redacts_and_refuses_redirect`](../../tests/e2e/protocol_watch/integration_test.odin#L330) | Run the Linear transport against a controlled endpoint and verify redirect handling and secret redaction. |

<a id="file-tests-e2e-protocol-watch-schedule-test-odin"></a>

## tests/e2e/protocol_watch/schedule_test.odin

| Function | Behavior |
|---|---|
| [`schedule_real_child_stdin_schema`](../../tests/e2e/protocol_watch/schedule_test.odin#L14) | Send the review schema and prompt to a real fixture child. |
| [`schedule_nonreading_stdin_deadline`](../../tests/e2e/protocol_watch/schedule_test.odin#L28) | Run a child that never reads stdin and enforce the deadline. |
| [`schedule_stderr_never_returned`](../../tests/e2e/protocol_watch/schedule_test.odin#L39) | Verify that child stderr is excluded from published output. |
| [`schedule_oversized_stdout_killed`](../../tests/e2e/protocol_watch/schedule_test.odin#L51) | Overflow the output limit and verify the child is terminated. |
| [`watcher_argv`](../../tests/e2e/protocol_watch/schedule_test.odin#L59) | Build a watcher command that emits the requested summary, file and exit status. |
| [`schedule_fresh_report_and_summary_match`](../../tests/e2e/protocol_watch/schedule_test.odin#L85) | Require a fresh report matching the watcher’s printed summary. |
| [`schedule_failed_watcher_preserves_report`](../../tests/e2e/protocol_watch/schedule_test.odin#L113) | Fail a watch subprocess and compare the prior report. |
| [`schedule_stalled_watcher_hard_killed`](../../tests/e2e/protocol_watch/schedule_test.odin#L135) | Stall the watch process and verify forceful cleanup at its deadline. |
| [`schedule_exit_three_only_review_required`](../../tests/e2e/protocol_watch/schedule_test.odin#L146) | Check that exit status three corresponds to review-required results only. |
| [`schedule_sanitizes_environment`](../../tests/e2e/protocol_watch/schedule_test.odin#L166) | Inspect the environment passed to the review child. |

<a id="file-tests-e2e-recovery-campaign-main-odin"></a>

## tests/e2e/recovery_campaign/main.odin

| Function | Behavior |
|---|---|
| [`fixture_open`](../../tests/e2e/recovery_campaign/main.odin#L42) | Open or create the state store for the crash fixture. |
| [`fixture_close`](../../tests/e2e/recovery_campaign/main.odin#L78) | Close the fixture socket and release its store. |
| [`intent_write`](../../tests/e2e/recovery_campaign/main.odin#L86) | Write and flush the outbound action intent. |
| [`boundary`](../../tests/e2e/recovery_campaign/main.odin#L112) | Emit the boundary marker and wait for process termination. |
| [`child_write_stage`](../../tests/e2e/recovery_campaign/main.odin#L125) | Persist the selected send stage and wait for the parent to interrupt it. |
| [`wire_read`](../../tests/e2e/recovery_campaign/main.odin#L150) | Return EOF on the simulated replay stream. |
| [`wire_write`](../../tests/e2e/recovery_campaign/main.odin#L153) | Capture sent data for replay verification. |
| [`wire_close`](../../tests/e2e/recovery_campaign/main.odin#L160) | Close the simulated replay stream. |
| [`verify_replay`](../../tests/e2e/recovery_campaign/main.odin#L164) | Reopen the socket and compare replayed wire data. |
| [`verify_intent`](../../tests/e2e/recovery_campaign/main.odin#L206) | Check intent presence and digest at the selected boundary. |
| [`verify`](../../tests/e2e/recovery_campaign/main.odin#L236) | Reload state and verify its intent, outbox and replay behavior. |
| [`payload_digest`](../../tests/e2e/recovery_campaign/main.odin#L280) | Calculate the SHA-256 digest of the fixture payload. |

<a id="file-tests-e2e-recovery-campaign-recovery-test-odin"></a>

## tests/e2e/recovery_campaign/recovery_test.odin

| Function | Behavior |
|---|---|
| [`run_recovery_child`](../../tests/e2e/recovery_campaign/recovery_test.odin#L10) | Dispatch a fixture operation when a parent test starts this executable as a child. |
| [`send_state_survives_process_exit`](../../tests/e2e/recovery_campaign/recovery_test.odin#L28) | Check persisted send state after a normal exit and after five forced stops. |

<a id="file-tests-e2e-version-http-version-test-odin"></a>

## tests/e2e/version_http/version_test.odin

| Function | Behavior |
|---|---|
| [`serve_version_script`](../../tests/e2e/version_http/version_test.odin#L19) | Serve one synthetic version response and record the HTTP request headers. |
| [`fetch_version_from_local_web_server`](../../tests/e2e/version_http/version_test.odin#L34) | Verify the request path and browser headers, then decode the revision returned by the local peer. |

<a id="file-tests-fixtures-client-helpers-odin"></a>

## tests/fixtures/client/helpers.odin

| Function | Behavior |
|---|---|
| [`codec_api_hex`](../../tests/fixtures/client/helpers.odin#L15) | Decode a hexadecimal input for the public codec test. |
| [`download_http`](../../tests/fixtures/client/helpers.odin#L33) | Serve the configured HTTP download response. |
| [`http_marker_execute`](../../tests/fixtures/client/helpers.odin#L59) | Record which thread ran an HTTP operation and return the marker result. |
| [`http_marker_request`](../../tests/fixtures/client/helpers.odin#L81) | Construct a synthetic HTTP request carrying the marker. |
| [`ack_routing_node`](../../tests/fixtures/client/helpers.odin#L91) | Build a synthetic incoming receipt or call node. |
| [`ack_routing_unchanged`](../../tests/fixtures/client/helpers.odin#L104) | Assert that the scenario left durable chat state intact. |
| [`negative_ack_fixture`](../../tests/fixtures/client/helpers.odin#L122) | Create a test socket and durable state for negative acknowledgements. |
| [`negative_ack_destroy`](../../tests/fixtures/client/helpers.odin#L147) | Release the negative-ack fixture and its temporary files. |
| [`negative_ack_disk`](../../tests/fixtures/client/helpers.odin#L155) | Read the persisted state bytes for later comparison. |
| [`negative_ack_unchanged`](../../tests/fixtures/client/helpers.odin#L162) | Check that the failing operation preserved memory and disk state. |
| [`send_id_fixture`](../../tests/fixtures/client/helpers.odin#L188) | Create a durable outbound intent with a stable message ID. |
| [`send_id_fixture_destroy`](../../tests/fixtures/client/helpers.odin#L212) | Release the send-ID fixture and temporary state. |
| [`send_id_http`](../../tests/fixtures/client/helpers.odin#L228) | Count attempted HTTP work and simulate an I/O failure. |
| [`send_id_wire_connect`](../../tests/fixtures/client/helpers.odin#L239) | Attach a framed transport for capturing a replayed packet. |
| [`send_id_wire_write`](../../tests/fixtures/client/helpers.odin#L260) | Capture bytes written during send or replay. |
| [`send_id_wire_read`](../../tests/fixtures/client/helpers.odin#L268) | Return EOF from the simulated transport. |
| [`send_id_wire_close`](../../tests/fixtures/client/helpers.odin#L272) | Close the captured-wire transport. |
| [`send_id_wire_plain`](../../tests/fixtures/client/helpers.odin#L276) | Unmask and decrypt a captured frame to recover its inner payload. |

<a id="file-tests-fixtures-protocol-watch-helpers-odin"></a>

## tests/fixtures/protocol_watch/helpers.odin

| Function | Behavior |
|---|---|
| [`valid_agent_result`](../../tests/fixtures/protocol_watch/helpers.odin#L6) | Return a valid no-action result from a synthetic review agent. |
| [`schedule_options_for_test`](../../tests/fixtures/protocol_watch/helpers.odin#L14) | Construct a schedule rooted in the temporary test directory. |
| [`shell_argv`](../../tests/fixtures/protocol_watch/helpers.odin#L25) | Build a shell invocation for a controlled child process. |
| [`setup_arena`](../../tests/fixtures/protocol_watch/helpers.odin#L37) | Initialize the arena used by the protocol watcher tests. |

<a id="file-tests-media-test-odin"></a>

## tests/media_test.odin

| Function | Behavior |
|---|---|
| [`media_deadline_test_execute`](../../tests/media_test.odin#L21) | Simulate an upload response and record the remaining HTTP budget. |
| [`media_upload_later_dial_failure_preserves_earlier_unknown_effect`](../../tests/media_test.odin#L57) | Keep the earlier uncertain upload outcome when a later host cannot be reached. |
| [`media_upload_does_not_restart_budget_on_host_fallback`](../../tests/media_test.odin#L86) | Verify that trying another media host shares the original deadline. |
| [`media_upload_fallback_receives_only_remaining_budget`](../../tests/media_test.odin#L114) | Measure the time budget delivered to the fallback upload host. |
| [`media_retry_test_http`](../../tests/media_test.odin#L146) | Simulate the HTTP exchange used by a media retry. |
| [`media_retry_test_write`](../../tests/media_test.odin#L160) | Capture encrypted writes made by the retrying socket. |
| [`media_retry_test_read`](../../tests/media_test.odin#L167) | Serve the queued peer response to the retrying socket. |
| [`media_retry_test_close`](../../tests/media_test.odin#L171) | Close the controlled media retry stream. |
| [`media_retry_test_socket`](../../tests/media_test.odin#L175) | Attach the retry fixture to a test socket. |
| [`media_retry_test_notification`](../../tests/media_test.odin#L199) | Construct the fixed encrypted media-retry notification. |
| [`media_retry_preserves_caller_routing_metadata`](../../tests/media_test.odin#L236) | Correlate media retry with the message routing supplied by its caller. |
| [`writer_golden_media`](../../tests/media_test.odin#L308) | Build the reference media message for writer comparisons. |
| [`writer_media_encoders_match_retired_writer`](../../tests/media_test.odin#L388) | Compare encoded media fields against stored reference bytes. |
| [`codec_api_reaction_key`](../../tests/media_test.odin#L419) | Construct the message key targeted by the reaction test. |
| [`reaction_checkmark_encode_matches_reference_bytes_and_decodes_back`](../../tests/media_test.odin#L433) | Match the checkmark reaction wire bytes and decode the result. |
| [`reaction_checkmark_encode_validates_key_and_destination`](../../tests/media_test.odin#L452) | Check invalid reaction keys and undersized output buffers. |
| [`reaction_message_decode_rejects_malformed_and_ignores_other_messages`](../../tests/media_test.odin#L477) | Reject malformed reaction data and distinguish other message types. |
| [`send_image_rejects_bad_state_and_inputs_before_any_network_work`](../../tests/media_test.odin#L511) | Reject invalid image parameters before network work starts. |
| [`send_reaction_validates_state_key_and_text`](../../tests/media_test.odin#L532) | Reject invalid reaction state, target or text. |
| [`download_fixture_init`](../../tests/media_test.odin#L572) | Construct encrypted file bytes and the associated media message. |
| [`download_media_fetches_decrypts_and_verifies_over_the_cdn_path`](../../tests/media_test.odin#L606) | Download encrypted media through its canonical CDN path and check recovered bytes. |
| [`download_media_corrupt_ciphertext_fails_authentication_and_leaves_destination_untouched`](../../tests/media_test.odin#L626) | Corrupt the downloaded ciphertext and verify authentication failure preserves the output. |
| [`download_media_surfaces_http_status_without_retrying_other_codes`](../../tests/media_test.odin#L651) | Check that an HTTP failure carries its status and only eligible codes enter retry. |
| [`download_media_runs_offline_backlog_while_provisioning`](../../tests/media_test.odin#L672) | Download offline-batch media received before activation completes. |
| [`download_media_preflights_state_message_and_destination_before_network`](../../tests/media_test.odin#L711) | Reject invalid input or output capacity before attempting an HTTP request. |
| [`http_execute_requires_an_online_socket_and_never_runs_the_request_otherwise`](../../tests/media_test.odin#L753) | Require an online socket before dispatching a generic HTTP job. |
| [`download_private_voice_note_and_audio_attachment`](../../tests/media_test.odin#L767) | Download both private audio variants using independent encrypted bytes and verify that a corrupt file leaves the destination untouched. |

<a id="file-tests-pairing-test-odin"></a>

## tests/pairing_test.odin

| Function | Behavior |
|---|---|
| [`pairing_observer_receives_application_events`](../../tests/pairing_test.odin#L15) | Check that an application pairing callback receives session events. |
| [`observer`](../../tests/pairing_test.odin#L17) | Observe pairing events through the consumer callback signature. |
| [`official_version_peer_get`](../../tests/pairing_test.odin#L30) | Return a controlled HTTP response to the version-discovery client. |
| [`official_version_discovery_does_not_use_third_party_feeds`](../../tests/pairing_test.odin#L45) | Inspect discovery requests and require the official WhatsApp version endpoint. |
| [`pairing_domain_field`](../../tests/pairing_test.odin#L70) | Write a protobuf field into the signed identity fixture. |
| [`pairing_domain_fixture`](../../tests/pairing_test.odin#L76) | Construct a signed account/device fixture for the specified domains. |
| [`pairing_domain_iq`](../../tests/pairing_test.odin#L139) | Build the IQ node containing the pairing-success identity. |
| [`pairing_domain_free`](../../tests/pairing_test.odin#L143) | Free allocated pairing test data. |
| [`pairing_domain_companion_verify`](../../tests/pairing_test.odin#L148) | Check the companion signature from the encoded reply. |
| [`pairing_current_domains_follow_signed_device_type_independent_of_wrapper`](../../tests/pairing_test.odin#L163) | Choose the signature domain from signed device details across wrapper variants. |
| [`pairing_domain_legacy_account`](../../tests/pairing_test.odin#L184) | Build an account in the older persisted format. |
| [`pairing_current_rejects_wrong_domains_unknown_types_and_tampered_identity`](../../tests/pairing_test.odin#L216) | Reject mismatched domains, unsupported device types and identity tampering. |
| [`pairing_current_persisted_identity_rejects_tampering_and_legacy_companion_domain`](../../tests/pairing_test.odin#L267) | Reject altered persisted identity and an incorrect companion signing domain. |
| [`linked_device_qr_matches_observed_url_and_companion_field`](../../tests/pairing_test.odin#L306) | Check the linked-device QR URL layout and encoded companion field. |
| [`linked_device_qr_companion_mapping_and_legacy_default_are_distinct`](../../tests/pairing_test.odin#L330) | Compare companion-type selection across profiles and the legacy format. |
| [`linked_device_qr_bounds_errors_and_borrowed_reference_are_atomic`](../../tests/pairing_test.odin#L389) | Exercise output bounds and input aliasing while checking atomicity. |
| [`linked_device_qr_failed_encoding_does_not_consume_reference`](../../tests/pairing_test.odin#L466) | Fail QR encoding and check that the same pairing reference remains available. |
| [`qr_profile_fixture`](../../tests/pairing_test.odin#L515) | Prepare credentials and QR inputs for the selected companion profile. |
| [`qr_profile_destroy`](../../tests/pairing_test.odin#L529) | Release the pairing QR profile fixture. |
| [`linked_device_qr_session_initial_and_timer_events_honor_selected_format`](../../tests/pairing_test.odin#L538) | Check initial and rotated session QR events under the configured format. |
| [`linked_device_qr_invalid_configuration_is_rejected_before_initialization`](../../tests/pairing_test.odin#L595) | Reject an unsupported QR format before session initialization. |
| [`linked_device_qr_borrowed_profile_is_read_before_writing`](../../tests/pairing_test.odin#L627) | Exercise overlapping profile input and output to verify the profile is read first. |
| [`protocol_ack_capture`](../../tests/pairing_test.odin#L651) | Capture bounded observer data for a protocol acknowledgement. |
| [`protocol_ack_observer_retains_only_fixed_class_after_document_release`](../../tests/pairing_test.odin#L664) | Destroy the parsed document and check that the observer retains the acknowledgement class. |
| [`protocol_ack_observer_limits_context_and_rejects_conflicting_classes`](../../tests/pairing_test.odin#L713) | Feed oversized or conflicting context and check the classification bounds. |
| [`codec_api_qr_blank`](../../tests/pairing_test.odin#L748) | Allocate a blank QR matrix for codec API tests. |
| [`qr_terminal_render_blank_code_is_a_white_quiet_field`](../../tests/pairing_test.odin#L758) | Render a blank QR and check the surrounding white quiet zone. |
| [`qr_terminal_render_pairs_vertical_modules_into_half_blocks`](../../tests/pairing_test.odin#L774) | Verify that vertical module pairs map to the expected half-block character. |
| [`qr_terminal_render_matches_every_module_of_a_real_code`](../../tests/pairing_test.odin#L809) | Compare all rendered cells with a real encoded QR matrix. |
| [`qr_terminal_render_rejects_inconsistent_codes_and_destroy_honours_allocator`](../../tests/pairing_test.odin#L837) | Reject an inconsistent QR matrix and free the rendering with its owning allocator. |
| [`whatsapp_version_worker_revision_requires_an_exact_unsigned_integer`](../../tests/pairing_test.odin#L869) | Reject worker revisions that are not exact unsigned integers. |
| [`version_test_fetch`](../../tests/pairing_test.odin#L910) | Serve the configured synthetic version response. |
| [`whatsapp_version_discovery_uses_official_worker_or_pinned_default`](../../tests/pairing_test.odin#L932) | Exercise worker discovery and the built-in fallback. |
| [`whatsapp_version_discovery_prefers_a_caller_fallback_to_the_pin`](../../tests/pairing_test.odin#L973) | Prefer the caller-provided fallback when discovery fails. |
| [`whatsapp_version_preserves_body_and_explicit_triplet_bounds`](../../tests/pairing_test.odin#L994) | Check response body limits and numeric bounds for explicit triplets. |
| [`version_test_failed_allocator`](../../tests/pairing_test.odin#L1022) | Inject allocator failure during version discovery. |
| [`whatsapp_version_revision_needs_no_heap_allocation`](../../tests/pairing_test.odin#L1040) | Extract a revision with heap allocation disabled. |
| [`official_version_literal_boundaries_and_conflicts_fail_closed`](../../tests/pairing_test.odin#L1052) | Exercise ambiguous revision literals and conflicting values. |
| [`official_version_discovery_preserves_tighter_body_budget`](../../tests/pairing_test.odin#L1081) | Keep the caller’s tighter response-size budget during discovery. |
| [`owned_version_fetch`](../../tests/pairing_test.odin#L1100) | Return an owned fixture response for allocation and cleanup checks. |
| [`official_version_discovery_releases_owned_response_on_every_outcome`](../../tests/pairing_test.odin#L1124) | Track allocation ownership on successful and failed discovery responses. |

<a id="file-tests-protobuf-test-odin"></a>

## tests/protobuf_test.odin

| Function | Behavior |
|---|---|
| [`writer_golden_config`](../../tests/protobuf_test.odin#L7) | Return the client configuration used for reference wire bytes. |
| [`writer_golden_keys`](../../tests/protobuf_test.odin#L17) | Build deterministic registration key material. |
| [`writer_expect_hex`](../../tests/protobuf_test.odin#L52) | Compare encoded bytes against the expected hexadecimal output. |
| [`writer_payload_encoders_match_retired_writer`](../../tests/protobuf_test.odin#L58) | Compare registration and login bytes with the reference encoder. |
| [`writer_measure_mode_stores_nothing_and_counts_exactly`](../../tests/protobuf_test.odin#L80) | Count encoded size in measurement mode and check that nothing is written. |
| [`writer_fixed_buffer_overflow_is_sticky_and_leaves_tail_untouched`](../../tests/protobuf_test.odin#L104) | Exhaust a fixed buffer and verify sticky failure and an intact tail. |
| [`writer_rejects_invalid_utf8_and_aliasing_target`](../../tests/protobuf_test.odin#L123) | Reject malformed text and input overlapping the output buffer. |
| [`writer_payload_error_precedence_is_preserved`](../../tests/protobuf_test.odin#L152) | Exercise competing payload failures and compare error precedence. |
| [`protobuf_varint_preserves_u64_limits_and_cursor`](../../tests/protobuf_test.odin#L168) | Check encoded size, decoded value and input position at unsigned 64-bit protobuf boundaries. |

<a id="file-tests-receive-test-odin"></a>

## tests/receive_test.odin

| Function | Behavior |
|---|---|
| [`mandatory_control_ack_malformed_envelopes_do_not_send_or_commit`](../../tests/receive_test.odin#L12) | Feed malformed control stanzas and check both transport output and durable state. |
| [`mandatory_control_ack_write_failure_is_terminal_without_chat_commit`](../../tests/receive_test.odin#L39) | Fail the ACK write and verify that the socket closes before committing chat state. |
| [`inbound_alias_private`](../../tests/receive_test.odin#L65) | Construct a deterministic private key for the alias fixture. |
| [`inbound_alias_local`](../../tests/receive_test.odin#L78) | Build the local key material used by the alias scenarios. |
| [`inbound_alias_fixture`](../../tests/receive_test.odin#L90) | Establish sender and receiver state for an inbound address-alias test. |
| [`inbound_alias_node`](../../tests/receive_test.odin#L157) | Build an encrypted incoming group stanza with address hints. |
| [`inbound_alias_node_destroy`](../../tests/receive_test.odin#L182) | Release the constructed alias test stanza. |
| [`inbound_alias_process`](../../tests/receive_test.odin#L193) | Dispatch the fixture stanza through inbound decryption. |
| [`inbound_alias_established_session_is_discovered_before_decrypt_and_dedup`](../../tests/receive_test.odin#L200) | Recover an existing session from address hints before decryption and deduplication. |
| [`inbound_alias_failed_decrypt_or_save_never_commits_hints`](../../tests/receive_test.odin#L241) | Inject decryption and persistence failures and check that no mapping is committed. |
| [`inbound_alias_extra_attr`](../../tests/receive_test.odin#L268) | Add an attribute to an alias test stanza. |
| [`inbound_alias_refuses_conflicting_invalid_and_ambiguous_sender_hints`](../../tests/receive_test.odin#L277) | Exercise malformed, ambiguous and conflicting sender address hints. |
| [`inbound_alias_refuses_existing_mapping_or_identity_pin_conflicts`](../../tests/receive_test.odin#L315) | Check alias conflicts against stored mappings and identity pins. |
| [`inbound_alias_preserves_no_hint_and_accepts_same_device_and_canonical_domains`](../../tests/receive_test.odin#L342) | Compare no-hint delivery with equivalent device and normalized-domain cases. |
| [`inbound_alias_unsupported_encryption_preflight_precedes_hint_processing`](../../tests/receive_test.odin#L381) | Verify that unsupported encryption is rejected before alias handling. |
| [`inbound_alias_skipped_self_echo_and_unencrypted_control_cannot_install_hints`](../../tests/receive_test.odin#L399) | Check that a skipped self echo or plaintext control cannot establish an alias. |
| [`inbound_alias_inbox_key_preserves_uninitialized_state_rejection`](../../tests/receive_test.odin#L422) | Require initialized state to compute the canonical inbox key. |
| [`inbound_alias_inbox_key_preserves_nil_socket_and_store_rejection`](../../tests/receive_test.odin#L435) | Check errors from inbox-key derivation with a nil socket or store. |
| [`inbound_alias_own_device_classification_requires_successful_decrypt_and_staged_mapping`](../../tests/receive_test.odin#L454) | Require authenticated decryption and the staged mapping for own-device classification. |
| [`inbound_alias_self_classification_refuses_invalid_owner_state`](../../tests/receive_test.odin#L516) | Refuse self-sender classification with invalid account ownership state. |
| [`message_ack_expect`](../../tests/receive_test.odin#L537) | Decode a captured frame and compare the exact expected acknowledgement. |
| [`message_ack_vector`](../../tests/receive_test.odin#L558) | Send a fixture envelope through the acknowledgement path and check its wire output. |
| [`message_ack_normal_policy_uses_exact_encrypted_maps_after_document_release`](../../tests/receive_test.odin#L598) | Compare decrypted normal-message ACK attributes after releasing the source document. |
| [`message_ack_optional_participant_and_recipient_preserve_presence`](../../tests/receive_test.odin#L622) | Exercise present and absent participant and recipient attributes. |
| [`message_ack_unavailable_and_error_maps_remain_separate_legacy_policies`](../../tests/receive_test.odin#L649) | Check the distinct acknowledgement layouts for unavailable and error stanzas. |
| [`message_ack_missing_or_empty_mandatory_attrs_do_not_write`](../../tests/receive_test.odin#L708) | Omit mandatory routing fields and verify no write occurs. |
| [`message_ack_write_failure_does_not_mutate_or_replay_intent`](../../tests/receive_test.odin#L732) | Inject a write failure and check the saved send intent and replay state. |
| [`negative_ack_error_presence_rejects_tracked_intent_without_any_mutation`](../../tests/receive_test.odin#L756) | Reject an errored acknowledgement for a tracked send and compare stored state. |
| [`negative_ack_retained_or_pending_intent_alone_is_tracked`](../../tests/receive_test.odin#L779) | Check tracking when only the saved content or pending send exists. |
| [`negative_ack_unknown_missing_id_or_other_class_does_not_abort_session`](../../tests/receive_test.odin#L798) | Deliver unrelated or malformed acknowledgement IDs without terminating the session. |
| [`negative_ack_positive_control_commits_pending_removal_and_retains_content`](../../tests/receive_test.odin#L820) | Accept a successful ACK and remove the pending send while retaining its content. |
| [`trust_identity_pins_new_key_and_drops_sessions_and_sender_keys_of_that_device`](../../tests/receive_test.odin#L842) | Replace a trusted device key and remove the device’s obsolete sessions and sender keys. |
| [`trust_identity_rejects_invalid_input_and_failed_save_keeps_pin_and_sessions`](../../tests/receive_test.odin#L889) | Reject invalid trust input and inject save failure while checking prior keys and sessions. |
| [`status_ack_top_level_live_and_offline_preserves_transport_attributes`](../../tests/receive_test.odin#L920) | Compare routing attributes on status ACKs for live and offline stanzas. |
| [`status_ack_malformed_envelopes_fail_without_output_or_store_changes`](../../tests/receive_test.odin#L997) | Reject malformed status envelopes and compare output and store state. |
| [`status_ack_failed_write`](../../tests/receive_test.odin#L1021) | Simulate a failed acknowledgement write. |
| [`status_ack_write_failure_is_propagated_without_chat_state_commit`](../../tests/receive_test.odin#L1026) | Fail the status ACK write and verify no chat state is committed. |
| [`status_ack_legacy_broadcast_message_remains_transport_only`](../../tests/receive_test.odin#L1052) | Handle a legacy broadcast status message only at the transport layer. |
| [`unsupported_enc_node`](../../tests/receive_test.odin#L1083) | Build a message stanza with the selected encryption child types. |
| [`unsupported_enc_node_destroy`](../../tests/receive_test.odin#L1126) | Free the test message node. |
| [`unsupported_enc_case`](../../tests/receive_test.odin#L1137) | Check disposition of a message with unsupported encryption. |
| [`unsupported_encryption_never_success_marks_and_replay_is_bounded`](../../tests/receive_test.odin#L1187) | Receive unsupported encryption repeatedly and check bounded retries and processed markers. |
| [`unsupported_encryption_rejects_mixed_children_before_any_ratchet_mutation`](../../tests/receive_test.odin#L1196) | Mix known and unknown encrypted children and compare ratchet state after rejection. |
| [`unsupported_enc_write_fail`](../../tests/receive_test.odin#L1204) | Fail the write of the negative acknowledgement. |
| [`unsupported_encryption_failed_nack_does_not_commit_or_enqueue_retry`](../../tests/receive_test.odin#L1209) | Fail the negative ACK and check for durable changes or queued retries. |
| [`unsupported_encryption_keeps_supported_distribution_order_and_controls_admissible`](../../tests/receive_test.odin#L1234) | Accept supported sender-key distribution ordering and admissible controls. |
| [`history_redelivery_restores_receipt_after_reopening_store`](../../tests/receive_test.odin#L1251) | Reopen the state after a history message commits and verify that its duplicate requests the history receipt. |

<a id="file-tests-send-test-odin"></a>

## tests/send_test.odin

| Function | Behavior |
|---|---|
| [`send_id_conflicting_commit_preserves_pending_wire_and_durable_state`](../../tests/send_test.odin#L9) | Submit conflicting content for an existing ID and compare its pending wire and persisted state. |
| [`send_id_conflict_is_rejected_before_metadata_or_cryptographic_work`](../../tests/send_test.odin#L34) | Detect an ID conflict before requesting metadata or deriving keys. |
| [`send_id_pending_same_intent_reuses_id_without_queries_or_new_state`](../../tests/send_test.odin#L53) | Replay a matching pending intent without issuing queries or advancing state. |
| [`send_id_retained_content_does_not_fabricate_acknowledgment`](../../tests/send_test.odin#L74) | Keep retained content from being mistaken for a positive server ACK. |
| [`send_id_media_fixture`](../../tests/send_test.odin#L91) | Stage a saved media intent for message-ID replay tests. |
| [`send_id_high_level_document_replay_does_not_upload_again`](../../tests/send_test.odin#L121) | Replay a saved document through the public API and count HTTP uploads. |
| [`send_id_high_level_document_conflicts_fail_before_upload`](../../tests/send_test.odin#L152) | Reject conflicting documents with the same ID before contacting the upload server. |

<a id="file-tests-signal-test-odin"></a>

## tests/signal_test.odin

| Function | Behavior |
|---|---|
| [`signal_group_message_encode_signs_an_envelope_the_decoder_accepts`](../../tests/signal_test.odin#L7) | Produce a signed group envelope and decode its fields. |

<a id="file-tests-socket-test-odin"></a>

## tests/socket_test.odin

| Function | Behavior |
|---|---|
| [`query_observer_test_observe`](../../tests/socket_test.odin#L17) | Capture query timing and success reported to the observer. |
| [`whatsapp_query_observer_reports_sent_queries_only`](../../tests/socket_test.odin#L31) | Check that the query observer reports only requests actually sent. |
| [`official_version_explicit_payload_is_preserved_by_socket_settings`](../../tests/socket_test.odin#L58) | Preserve an explicitly configured version in socket connection settings. |

<a id="file-tests-state-store-test-odin"></a>

## tests/state_store_test.odin

| Function | Behavior |
|---|---|
| [`state_atomic_write_replaces_the_file_and_reports_a_missing_directory`](../../tests/state_store_test.odin#L10) | Replace a state file and verify the missing-directory error path. |
| [`consumer_can_store_read_and_replace_session`](../../tests/state_store_test.odin#L31) | Use only the public library API to store, read and replace session data. |
| [`post_rename_directory_failure_requires_reloading_replaced_state`](../../tests/state_store_test.odin#L52) | Deny directory reads after file replacement, verify that stale writes fail and reload the new revision. |
| [`rollback_export_preserves_session_and_queue_with_legacy_contact_fields`](../../tests/state_store_test.odin#L81) | Reopen a rollback export and compare session records, queued ciphertext, saved names, and legacy sync fields with the untouched source. |

<a id="file-tools-protocol-watcher-tests-main-test-odin"></a>

## tools/protocol_watcher/tests/main_test.odin

| Function | Behavior |
|---|---|
| [`cli_option_pairs_preserve_values_and_reject_duplicate_flags`](../../tools/protocol_watcher/tests/main_test.odin#L8) | Check that the CLI preserves option values and rejects repeated flags. |

<a id="file-tools-protocol-watcher-tests-release-test-odin"></a>

## tools/protocol_watcher/tests/release_test.odin

| Function | Behavior |
|---|---|
| [`receipt_inputs`](../../tools/protocol_watcher/tests/release_test.odin#L12) | Build source, evidence and receipt files for a release gate. |
| [`gate_case`](../../tools/protocol_watcher/tests/release_test.odin#L50) | Evaluate a release gate after applying the chosen fixture mutation. |
| [`array_strings`](../../tools/protocol_watcher/tests/release_test.odin#L104) | Read string entries from the release result array. |
| [`gate_never_authorizes_deployment`](../../tools/protocol_watcher/tests/release_test.odin#L115) | Check the decision boundary between evidence qualification and deployment. |
| [`gate_source_change_invalidates_receipts`](../../tools/protocol_watcher/tests/release_test.odin#L120) | Change candidate source and invalidate previously matching receipts. |
| [`gate_ack_alone_and_skipped_checks_fail`](../../tools/protocol_watcher/tests/release_test.odin#L125) | Submit an ACK alone or omit required checks and verify rejection. |
| [`gate_changed_evidence_rejected`](../../tools/protocol_watcher/tests/release_test.odin#L130) | Modify evidence bytes after receipt generation. |
| [`ci_scan`](../../tools/protocol_watcher/tests/release_test.odin#L134) | Return a clean, failed or drifted scan for the CI preparation test. |
| [`ci_case`](../../tools/protocol_watcher/tests/release_test.odin#L148) | Run CI preparation and inspect its published result. |
| [`ci_prepares_public_drift_without_downgrading`](../../tools/protocol_watcher/tests/release_test.odin#L174) | Prepare public drift evidence while preserving its review status. |
| [`ci_failure_redacts_raw_error`](../../tools/protocol_watcher/tests/release_test.odin#L179) | Inject a scan failure and inspect the public diagnostic for redaction. |
| [`ci_clean_scan_never_approves`](../../tools/protocol_watcher/tests/release_test.odin#L184) | Check the promotion result of a clean scan. |

<a id="file-tools-protocol-watcher-tests-schedule-test-odin"></a>

## tools/protocol_watcher/tests/schedule_test.odin

| Function | Behavior |
|---|---|
| [`schedule_command_explicit_read_only`](../../tools/protocol_watcher/tests/schedule_test.odin#L13) | Check the agent invocation for read-only sandboxing and ephemeral execution. |
| [`schedule_plist_daily_no_install`](../../tools/protocol_watcher/tests/schedule_test.odin#L30) | Generate a daily launchd plist and verify it is only prepared. |
| [`schedule_result_schema_bounded`](../../tools/protocol_watcher/tests/schedule_test.odin#L55) | Reject agent results outside the bounded output schema. |
| [`watch_ok`](../../tools/protocol_watcher/tests/schedule_test.odin#L83) | Supply a successful watch result. |
| [`watch_fail`](../../tools/protocol_watcher/tests/schedule_test.odin#L105) | Supply a watcher failure. |
| [`agent_ok`](../../tools/protocol_watcher/tests/schedule_test.odin#L109) | Supply a successful agent review. |
| [`agent_forbidden`](../../tools/protocol_watcher/tests/schedule_test.odin#L115) | Fail if a review agent is invoked on a path that should skip it. |
| [`schedule_watch_then_agent_never_approves_drift`](../../tools/protocol_watcher/tests/schedule_test.odin#L120) | Run watcher then agent and check that the result cannot approve protocol drift. |
| [`schedule_watcher_failure_skips_agent`](../../tools/protocol_watcher/tests/schedule_test.odin#L137) | Fail the watcher and confirm the review agent is skipped. |
| [`schedule_singleton_excludes_parallel_jobs`](../../tools/protocol_watcher/tests/schedule_test.odin#L149) | Attempt concurrent scheduled jobs and verify exclusive ownership. |

<a id="file-tools-protocol-watcher-tests-tracker-test-odin"></a>

## tools/protocol_watcher/tests/tracker_test.odin

| Function | Behavior |
|---|---|
| [`inflate`](../../tools/protocol_watcher/tests/tracker_test.odin#L12) | Expand stored fixture references into test values. |
| [`operation_name`](../../tools/protocol_watcher/tests/tracker_test.odin#L53) | Determine the operation name for a recorded API request. |
| [`replay_call`](../../tools/protocol_watcher/tests/tracker_test.odin#L81) | Replay a recorded tracker API response and check the request. |
| [`tracker_dispatch`](../../tools/protocol_watcher/tests/tracker_test.odin#L124) | Dispatch a tracker fixture operation. |
| [`tracker_cases`](../../tools/protocol_watcher/tests/tracker_test.odin#L199) | Run the recorded cases matching the selected test name. |
| [`cat_case`](../../tools/protocol_watcher/tests/tracker_test.odin#L310) | Concatenate strings while constructing fixture case names. |
| [`tracker_all_covered_makes_no_comment`](../../tools/protocol_watcher/tests/tracker_test.odin#L315) | Replay fully covered findings and verify no comment is posted. |
| [`tracker_all_no_action_and_clean_scan_have_no_linear_calls`](../../tools/protocol_watcher/tests/tracker_test.odin#L320) | Skip all Linear operations for clean or entirely no-action reports. |
| [`tracker_already_implemented_without_bound_current_table_is_invalid`](../../tools/protocol_watcher/tests/tracker_test.odin#L325) | Require current-table evidence for an already-implemented classification. |
| [`tracker_append_preserves_human_body_and_prior_sections`](../../tools/protocol_watcher/tests/tracker_test.odin#L330) | Append a finding and compare the human text and older machine sections. |
| [`tracker_approved_fix_promotion_keeps_ready_proof_human_readable`](../../tools/protocol_watcher/tests/tracker_test.odin#L335) | Promote an approved fix and inspect the implementation proof shown to reviewers. |
| [`tracker_bool_assessment_schema_is_invalid`](../../tools/protocol_watcher/tests/tracker_test.odin#L340) | Reject a boolean in place of the assessment schema version. |
| [`tracker_byte_identical_denial_with_changed_digests_is_invalid`](../../tools/protocol_watcher/tests/tracker_test.odin#L345) | Reject a byte-equivalence claim when the reported digests differ. |
| [`tracker_close_race_does_not_comment_or_reopen_closed_issue`](../../tools/protocol_watcher/tests/tracker_test.odin#L350) | Close an issue between discovery and append and check for side effects. |
| [`tracker_closed_and_archived_description_coverage_never_reopens`](../../tools/protocol_watcher/tests/tracker_test.odin#L355) | Use coverage from archived or closed descriptions while leaving those issues closed. |
| [`tracker_closed_comment_coverage_survives_without_reopening`](../../tools/protocol_watcher/tests/tracker_test.odin#L360) | Recover coverage from comments on a closed issue. |
| [`tracker_closed_spike_same_change_does_not_promote`](../../tools/protocol_watcher/tests/tracker_test.odin#L365) | Keep the prior closed investigation from being promoted for the same change. |
| [`tracker_comment_full_body_is_bounded_before_mutation`](../../tools/protocol_watcher/tests/tracker_test.odin#L370) | Check the complete comment length before performing a mutation. |
| [`tracker_comment_lookup_never_confirms_two_empty_coverages`](../../tools/protocol_watcher/tests/tracker_test.odin#L375) | Prevent two empty coverage sets from confirming a comment identity. |
| [`tracker_comment_only_discovery_after_human_title_and_body_change`](../../tools/protocol_watcher/tests/tracker_test.odin#L380) | Find covered work in comments after the human title and description change. |
| [`tracker_concurrent_human_comment_never_overwritten`](../../tools/protocol_watcher/tests/tracker_test.odin#L385) | Add a concurrent human comment and check that it survives tracking. |
| [`tracker_conflicting_scopes_fail_before_any_mutation`](../../tools/protocol_watcher/tests/tracker_test.odin#L390) | Refuse contradictory review scopes before updating Linear. |
| [`tracker_contract_target_binding_mismatch_rejects_new_fix`](../../tools/protocol_watcher/tests/tracker_test.odin#L395) | Reject fix promotion when the approved contract targets another change. |
| [`tracker_deterministic_uuid4_only_new_findings`](../../tools/protocol_watcher/tests/tracker_test.odin#L400) | Generate deterministic IDs only for newly uncovered findings. |
| [`tracker_duplicate_json_and_nonfinite_are_rejected`](../../tools/protocol_watcher/tests/tracker_test.odin#L405) | Reject duplicate JSON keys and nonfinite numbers in tracker inputs. |
| [`tracker_duplicate_legacy_path_or_conflicting_evidence_is_not_coverage`](../../tools/protocol_watcher/tests/tracker_test.odin#L410) | Refuse ambiguous legacy paths or conflicting evidence as proof of coverage. |
| [`tracker_duplicate_state_is_terminal_not_an_append_target`](../../tools/protocol_watcher/tests/tracker_test.odin#L415) | Exclude a duplicate-state issue from candidate append targets. |
| [`tracker_expired_scan_budget_never_performs_api_call`](../../tools/protocol_watcher/tests/tracker_test.odin#L420) | Exhaust the time budget before scanning and count API calls. |
| [`tracker_fix_complete_indices_and_proof_invalid_fail_closed`](../../tools/protocol_watcher/tests/tracker_test.odin#L425) | Validate the complete index set and proof required for a fix. |
| [`tracker_fresh_append_rechecks_scope_changed_after_initial_scan`](../../tools/protocol_watcher/tests/tracker_test.odin#L430) | Change issue scope after scanning and check it again immediately before appending. |
| [`tracker_full_v2_manual_claim_on_unbound_issue_fails_closed`](../../tools/protocol_watcher/tests/tracker_test.odin#L435) | Reject a manually copied v2 claim on an issue lacking its binding. |
| [`tracker_full_v2_manual_comment_on_wrong_id_fails_closed`](../../tools/protocol_watcher/tests/tracker_test.odin#L440) | Copy a v2 comment onto another issue and check identity binding. |
| [`tracker_historical_completed_fix_does_not_monitor_current_source_forever`](../../tools/protocol_watcher/tests/tracker_test.odin#L445) | Change the source after a completed fix and require fresh assessment. |
| [`tracker_human_prefix_note_keeps_legacy_binding`](../../tools/protocol_watcher/tests/tracker_test.odin#L450) | Recover legacy coverage with a preceding human note. |
| [`tracker_human_title_rename_keeps_legacy_and_v2_coverage`](../../tools/protocol_watcher/tests/tracker_test.odin#L455) | Rename the human title and recover both legacy and v2 coverage. |
| [`tracker_identity_ignores_heads_runs_unrelated_files_and_size`](../../tools/protocol_watcher/tests/tracker_test.odin#L460) | Vary run, head, size and unrelated paths while preserving the same change identity. |
| [`tracker_invalid_assessment_on_clean_file_is_not_skipped`](../../tools/protocol_watcher/tests/tracker_test.odin#L465) | Inject an invalid assessment on a clean file and require validation. |
| [`tracker_invalid_scan_bindings_and_clean_status_fail_before_api`](../../tools/protocol_watcher/tests/tracker_test.odin#L470) | Reject invalid source bindings and inconsistent clean status before API access. |
| [`tracker_known_rejection_not_replayed`](../../tools/protocol_watcher/tests/tracker_test.odin#L475) | Return a known rejection and check that the request is not replayed. |
| [`tracker_legacy_seven_files_are_covered_when_whatsmeow_changes`](../../tools/protocol_watcher/tests/tracker_test.odin#L480) | Change the other upstream source while keeping coverage for seven prior files. |
| [`tracker_lookalike_spike_title_without_binding_never_selected_for_append`](../../tools/protocol_watcher/tests/tracker_test.odin#L485) | Refuse to append based solely on a similar human-readable investigation title. |
| [`tracker_lost_comment_is_queried_once_not_replayed`](../../tools/protocol_watcher/tests/tracker_test.odin#L490) | Lose a comment response and query once to establish its outcome. |
| [`tracker_lost_create_is_queried_once_not_replayed`](../../tools/protocol_watcher/tests/tracker_test.odin#L495) | Lose a create response and query once to establish its outcome. |
| [`tracker_malformed_legacy_manual_or_foreign_claims_do_not_cover`](../../tools/protocol_watcher/tests/tracker_test.odin#L500) | Reject malformed, manually claimed or foreign legacy findings. |
| [`tracker_manual_v2_marker_without_valid_machine_record_does_not_cover`](../../tools/protocol_watcher/tests/tracker_test.odin#L505) | Require a valid machine record alongside a manually inserted v2 marker. |
| [`tracker_new_baileys_delta_does_not_append_to_mixed_whatsmeow_review`](../../tools/protocol_watcher/tests/tracker_test.odin#L510) | Check that new Baileys changes respect the source scope of an existing mixed review. |
| [`tracker_new_revision_reuses_same_open_source_spike`](../../tools/protocol_watcher/tests/tracker_test.odin#L515) | Advance the upstream revision and reuse the matching open investigation. |
| [`tracker_new_whatsmeow_delta_appends_to_scoped_mixed_review`](../../tools/protocol_watcher/tests/tracker_test.odin#L520) | Append a new Whatsmeow change to an eligible scoped mixed review. |
| [`tracker_normalized_legacy_markdown_has_exact_same_coverage`](../../tools/protocol_watcher/tests/tracker_test.odin#L525) | Normalize legacy Markdown formatting and compare recovered coverage. |
| [`tracker_open_spike_same_change_promotes_once_in_place`](../../tools/protocol_watcher/tests/tracker_test.odin#L530) | Promote a matching open investigation once and in place. |
| [`tracker_owner_source_changed_rejects_new_fix`](../../tools/protocol_watcher/tests/tracker_test.odin#L535) | Alter the local implementation owner and reject stale fix evidence. |
| [`tracker_pagination_cycle_fails_before_mutation`](../../tools/protocol_watcher/tests/tracker_test.odin#L540) | Return a repeating page cursor and stop before updating Linear. |
| [`tracker_project_and_comment_pagination_scan_all_pages`](../../tools/protocol_watcher/tests/tracker_test.odin#L545) | Paginate both project issues and their comments to find all existing coverage. |
| [`tracker_real_classifier_fix_produces_ready_implementation_issue`](../../tools/protocol_watcher/tests/tracker_test.odin#L550) | Use an actual classifier FIX result to build an implementation-ready issue. |
| [`tracker_recognized_malformed_v2_fails_instead_of_duplicate_create`](../../tools/protocol_watcher/tests/tracker_test.odin#L555) | Reject malformed recognized v2 content before creating a duplicate issue. |
| [`tracker_run_url_is_exact_owa`](../../tools/protocol_watcher/tests/tracker_test.odin#L560) | Validate that the reported CI run URL belongs to the expected repository. |
| [`tracker_same_source_new_path_reuses_one_spike`](../../tools/protocol_watcher/tests/tracker_test.odin#L565) | Add another path from the same source and reuse its open investigation. |
| [`tracker_scan_call_budget_fails_before_mutation`](../../tools/protocol_watcher/tests/tracker_test.odin#L570) | Exhaust the API call allowance before any mutation. |
| [`tracker_scan_error_and_bound_never_create`](../../tools/protocol_watcher/tests/tracker_test.odin#L575) | Fail or bound the scan and verify no issue is created. |
| [`tracker_scope_alone_does_not_cover_change_or_authorize_fix`](../../tools/protocol_watcher/tests/tracker_test.odin#L580) | Require change-specific proof in addition to a matching review scope. |
| [`tracker_scope_marker_keeps_all_legacy_coverage_unchanged`](../../tools/protocol_watcher/tests/tracker_test.odin#L585) | Add a scope marker and compare the recovered legacy coverage. |
| [`tracker_shallow_approval_flag_never_authorizes_fix`](../../tools/protocol_watcher/tests/tracker_test.odin#L590) | Supply only an approval flag and require independent fix proof. |
| [`tracker_source_owned_requirement_is_revalidated_not_boolean_trusted`](../../tools/protocol_watcher/tests/tracker_test.odin#L595) | Revalidate the checked-in requirement behind an approval claim. |
| [`tracker_stale_assessment_evidence_fails_before_api`](../../tools/protocol_watcher/tests/tracker_test.odin#L600) | Change assessment evidence and require rejection before API access. |
| [`tracker_three_snapshot_overlap_does_not_repeat_seven_baileys_files`](../../tools/protocol_watcher/tests/tracker_test.odin#L605) | Compare three overlapping snapshots and avoid repeating seven known changes. |
| [`tracker_truncated_page_error_prevents_mutation`](../../tools/protocol_watcher/tests/tracker_test.odin#L610) | Truncate a paginated result and check that writes are suppressed. |
| [`tracker_unapproved_table_difference_is_investigation_not_runtime_fix`](../../tools/protocol_watcher/tests/tracker_test.odin#L615) | Route an unapproved token-table difference to investigation. |
| [`tracker_unknown_comment_is_not_retried`](../../tools/protocol_watcher/tests/tracker_test.odin#L620) | Simulate an indeterminate comment operation and check it is not retried. |
| [`tracker_unknown_scope_value_is_not_a_routing_authority`](../../tools/protocol_watcher/tests/tracker_test.odin#L625) | Supply an unrecognized scope and check that it cannot direct an append. |
| [`tracker_unknown_uncommitted_create_is_not_retried`](../../tools/protocol_watcher/tests/tracker_test.odin#L630) | Simulate a create with unknown commit status and check for blind retries. |
| [`tracker_unsupported_assessment_and_fix_without_proof_fail_before_api`](../../tools/protocol_watcher/tests/tracker_test.odin#L635) | Reject unsupported assessments and missing fix proof before API work. |
| [`tracker_updates_render_readable_investigation_and_immutable_links`](../../tools/protocol_watcher/tests/tracker_test.odin#L640) | Inspect the human-readable investigation and immutable evidence links. |
| [`tracker_wrong_v2_identity_or_foreign_repo_is_not_coverage`](../../tools/protocol_watcher/tests/tracker_test.odin#L645) | Reject v2 records with the wrong identity or repository. |

<a id="file-tools-protocol-watcher-tests-triage-test-odin"></a>

## tools/protocol_watcher/tests/triage_test.odin

| Function | Behavior |
|---|---|
| [`fixture_blob`](../../tools/protocol_watcher/tests/triage_test.odin#L15) | Decode the stored bytes for a digest-addressed fixture blob. |
| [`triage_cases`](../../tools/protocol_watcher/tests/triage_test.odin#L50) | Replay the triage fixture cases selected by test name. |
| [`triage_identical_known_bytes_are_no_action`](../../tools/protocol_watcher/tests/triage_test.odin#L153) | Compare identical monitored bytes and verify the no-action disposition. |
| [`triage_conservative_comment_and_horizontal_format_proof`](../../tools/protocol_watcher/tests/triage_test.odin#L158) | Establish equivalence for supported comment and horizontal formatting changes. |
| [`triage_newlines_asi_operators_and_literals_are_not_ignored`](../../tools/protocol_watcher/tests/triage_test.odin#L163) | Exercise newline-sensitive syntax, operators and literals that affect equivalence. |
| [`triage_changed_directives_and_license_are_spikes`](../../tools/protocol_watcher/tests/triage_test.odin#L168) | Classify changed directives and licensing comments for human investigation. |
| [`triage_slash_and_syntax_uncertainty_refuse_equivalence`](../../tools/protocol_watcher/tests/triage_test.odin#L173) | Refuse equivalence when slashes or syntax cannot be interpreted safely. |
| [`triage_json_semantics_and_duplicate_key_refusal`](../../tools/protocol_watcher/tests/triage_test.odin#L178) | Compare JSON values and reject duplicate object keys. |
| [`triage_binding_missing_targets_and_limits_fail_closed`](../../tools/protocol_watcher/tests/triage_test.odin#L183) | Exercise missing local targets, broken source bindings and size limits. |
| [`triage_all_seventeen_paths_bind_existing_local_owners`](../../tools/protocol_watcher/tests/triage_test.odin#L188) | Resolve all seventeen monitored paths to their checked-in implementation owners. |
| [`triage_exact_dictionary_drift_is_relevant_but_unqualified_spike`](../../tools/protocol_watcher/tests/triage_test.odin#L193) | Report an exact dictionary delta without claiming an approved runtime fix. |
| [`triage_already_implemented_dictionary_is_no_action`](../../tools/protocol_watcher/tests/triage_test.odin#L198) | Compare local and current dictionaries and identify already implemented changes. |
| [`triage_table_other_changes_unknown_local_baseline_and_counts_are_spikes`](../../tools/protocol_watcher/tests/triage_test.odin#L203) | Exercise outside-table changes, unexpected counts and unknown local baselines. |
| [`triage_table_escaped_strings_and_bounded_evidence`](../../tools/protocol_watcher/tests/triage_test.odin#L208) | Decode escaped token strings while checking evidence size bounds. |
| [`triage_directive_position_and_indentation_are_not_harmless`](../../tools/protocol_watcher/tests/triage_test.odin#L213) | Change directive position and indentation and check the assessment. |
| [`triage_template_expression_html_numeric_and_resource_ambiguity`](../../tools/protocol_watcher/tests/triage_test.odin#L218) | Exercise template expressions and ambiguous HTML, numeric and resource constructs. |
| [`triage_go_raw_strings_and_go_or_proto_comments`](../../tools/protocol_watcher/tests/triage_test.odin#L223) | Compare Go raw strings and language-specific Go/protobuf comments. |
| [`triage_go_build_line_preamble_and_carriage_return_are_not_stripped`](../../tools/protocol_watcher/tests/triage_test.odin#L228) | Preserve build preambles, line directives and carriage returns during comparison. |
| [`triage_nested_tables_and_unsupported_escape_are_spikes`](../../tools/protocol_watcher/tests/triage_test.odin#L233) | Classify nested token tables and unsupported escapes for investigation. |
| [`triage_explicit_reviewed_contract_enables_static_gap_fix`](../../tools/protocol_watcher/tests/triage_test.odin#L238) | Supply a reviewed contract and identify the specific missing implementation change. |
| [`triage_approved_contract_binding_path_symlink_and_weak_claims_fail_closed`](../../tools/protocol_watcher/tests/triage_test.odin#L243) | Reject mismatched contract binding, symlinked evidence and weak claims. |
| [`triage_new_fix_proof_revalidation_detects_stale_owners_and_forged_metadata`](../../tools/protocol_watcher/tests/triage_test.odin#L248) | Alter local owners or forge contract metadata and revalidate proposed fix evidence. |
| [`triage_table_sensitive_comment_change_is_not_a_fix`](../../tools/protocol_watcher/tests/triage_test.odin#L253) | Change a significant comment in a dictionary and check its classification. |
| [`triage_real_owned_dictionary`](../../tools/protocol_watcher/tests/triage_test.odin#L258) | Read and assess the actual checked-in token dictionary. |
| [`reviewed_contract_paths_follow_the_watcher_directory`](../../tools/protocol_watcher/tests/triage_test.odin#L281) | Check that only the owned contracts directory admits reviewed contract files. |

<a id="file-tools-protocol-watcher-tests-value-test-odin"></a>

## tools/protocol_watcher/tests/value_test.odin

| Function | Behavior |
|---|---|
| [`integer_preserves_zero_and_rejects_numeric_strings`](../../tools/protocol_watcher/tests/value_test.odin#L7) | Distinguish the integer zero from the string containing its decimal representation. |

<a id="file-tools-protocol-watcher-tests-watch-test-odin"></a>

## tools/protocol_watcher/tests/watch_test.odin

| Function | Behavior |
|---|---|
| [`watch_manifest`](../../tools/protocol_watcher/tests/watch_test.odin#L15) | Build the synthetic upstream manifest. |
| [`upstream`](../../tools/protocol_watcher/tests/watch_test.odin#L39) | Serve a controlled upstream head or file response. |
| [`watch_drift_never_approves`](../../tools/protocol_watcher/tests/watch_test.odin#L62) | Check the review status of a changed upstream file. |
| [`watch_removal_visible`](../../tools/protocol_watcher/tests/watch_test.odin#L81) | Remove a monitored file and inspect the reported change. |
| [`watch_failed_fetch_preserves_success`](../../tools/protocol_watcher/tests/watch_test.odin#L109) | Fail a fetch after a good run and compare the last successful observation. |
| [`watch_invalid_head_missing_path_budget`](../../tools/protocol_watcher/tests/watch_test.odin#L137) | Reject an invalid head, a missing path and an exhausted observation budget. |
| [`watch_private_state_and_parallel_owner`](../../tools/protocol_watcher/tests/watch_test.odin#L160) | Exercise private state permissions and concurrent lock ownership. |
| [`watch_manifest_rejects_untrusted_sources`](../../tools/protocol_watcher/tests/watch_test.odin#L191) | Reject a manifest naming an untrusted repository. |
| [`watch_version_never_falls_back`](../../tools/protocol_watcher/tests/watch_test.odin#L216) | Require valid upstream version data when processing the version feed. |

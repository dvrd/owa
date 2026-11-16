package whatsapp

import "core:crypto"
import "core:fmt"
import "core:testing"

// Synthetic keys and a real established Signal exchange. Adapted from the
// owned encrypted_recovery fixture; no account material or fabricated sessions.
inbound_alias_private :: proc(start: int) -> [32]u8 {
 value: [32]u8
 for &b, i in value {b = u8(start + i)}
 value[0] &= 248; value[31] = value[31] & 127 | 64
 return value
}
inbound_alias_local :: proc(start: int, registration: u32) -> Signal_Recipient_Keys {
 return {identity_private = inbound_alias_private(start), registration_id = registration,
  signed_prekey_private = inbound_alias_private(start + 32), signed_prekey_id = 7,
  has_prekey = true, prekey_private = inbound_alias_private(start + 64), prekey_id = 9}
}
inbound_alias_fixture :: proc(existing_lid: bool) -> (^Negative_Ack_Fixture, []u8) {
 f := negative_ack_fixture()
 a, b := inbound_alias_local(0, 100), inbound_alias_local(96, 200)
 public_a, public_b := signal_curve_public(a.identity_private), signal_curve_public(b.identity_private)
 bundle := Signal_Prekey_Bundle{registration_id = b.registration_id, identity_public = public_b,
  signed_prekey_id = b.signed_prekey_id, signed_prekey_public = signal_curve_public(b.signed_prekey_private),
  has_prekey = true, prekey_id = b.prekey_id, prekey_public = signal_curve_public(b.prekey_private)}
 signed: [33]u8; signed[0] = 5; copy(signed[1:], bundle.signed_prekey_public[:])
 bundle.signed_prekey_signature, _ = signal_curve_sign(b.identity_private, signed[:])
 sender, receiver: Signal_Session
 defer {signal_session_clear(&sender); signal_session_clear(&receiver)}
 assert(signal_session_init_initiator(&sender, a.identity_private, a.registration_id, bundle, public_b).kind == .None)
 wire, plaintext: [4096]u8
 kind, size, error := signal_session_encrypt(&sender, wire[:], []u8{1}, public_b)
 assert(error.kind == .None && kind == .Prekey)
 _, consumed, prekey_error := signal_session_decrypt_prekey(&receiver, plaintext[:], wire[:size], b, public_a)
 assert(prekey_error.kind == .None && consumed == 9)
 kind, size, error = signal_session_encrypt(&receiver, wire[:], []u8{1}, public_a)
 assert(error.kind == .None && kind == .Whisper)
 _, error = signal_session_decrypt(&sender, plaintext[:], wire[:size], public_b)
 assert(error.kind == .None && !sender.pending_prekey)
 length, message_error := text_message_encode(plaintext[:], {kind = .Conversation, text = "synthetic inbound alias"})
 assert(message_error == .None); plaintext[length] = 1
 kind, size, error = signal_session_encrypt(&sender, wire[:], plaintext[:length + 1], public_b)
 assert(error.kind == .None && kind == .Whisper)
 encrypted := make([]u8, size); copy(encrypted, wire[:size])
 count, encoded := signal_session_encode(nil, &receiver); assert(encoded.kind == .Destination_Undersized)
 data := make([]u8, count); defer {crypto.zero_explicit(raw_data(data), len(data)); delete(data)}
 _, encoded = signal_session_encode(data, &receiver); assert(encoded.kind == .None)
 address := existing_lid ? "999:1@lid" : "111:1@s.whatsapp.net"
 assert(state_store_set(&f.store, .Session, address, data).kind == .None)
 assert(state_store_set(&f.store, .Identity, address, public_a[:]).kind == .None)
 f.auth.credentials.identity_private = b.identity_private
 f.auth.credentials.registration_id = b.registration_id
 f.auth.account.jid_size = copy(f.auth.account.jid[:], "222:1@s.whatsapp.net")
 assert(state_store_save(&f.store, f.path).kind == .None)
 return f, encrypted
}
inbound_alias_node :: proc(encrypted: []u8, lid_primary, group: bool) -> Binary_Node {
 primary := lid_primary ? "999:1@lid" : "111:1@s.whatsapp.net"
 attrs := make([dynamic]Binary_Node_Attribute)
 append(&attrs, {"id", "owa427-inbound"}, {"type", "text"})
 if group {append(&attrs, {"from", "123@g.us"}, {"participant", primary})}
 else {append(&attrs, {"from", primary})}
 field := group ? (lid_primary ? "participant_pn" : "participant_lid") :
  (lid_primary ? "sender_pn" : "sender_lid")
 append(&attrs, {field, lid_primary ? "111@s.whatsapp.net" : "999@lid"})
 children := make([]Binary_Node, 1)
 children[0] = {tag = "enc", attrs = make([]Binary_Node_Attribute, 1), content = encrypted}
 children[0].attrs[0] = {"type", "msg"}
 return {tag = "message", attrs = attrs[:], content = children}
}
inbound_alias_node_destroy :: proc(node: Binary_Node) {
 delete(node.attrs); children := node.content.([]Binary_Node)
 for child in children {delete(child.attrs)}
 delete(children)
}
inbound_alias_process :: proc(f: ^Negative_Ack_Fixture, node: Binary_Node) -> (Socket_Event, Socket_Error) {
 history: bool
 return socket_process_message(&f.socket, node, &history)
}
@(test)
inbound_alias_established_session_is_discovered_before_decrypt_and_dedup :: proc(t: ^testing.T) {
 for lid_primary in ([]bool{true, false}) {
  for group in ([]bool{false, true}) {
   f, encrypted := inbound_alias_fixture(!lid_primary)
   defer negative_ack_destroy(f); defer delete(encrypted)
   node := inbound_alias_node(encrypted, lid_primary, group); defer inbound_alias_node_destroy(node)
   event, error := inbound_alias_process(f, node)
   testing.expect_value(t, error.kind, .None)
   testing.expect_value(t, event.kind, .Message)
   if event.message == nil {continue}
   defer socket_message_destroy(event.message)
   alias, have := state_store_get(&f.store, .LID_Mapping, "lid:999@lid")
   testing.expect(t, have && string(alias) == "111@s.whatsapp.net")
   key := group ? "123@g.us|111:1@s.whatsapp.net|owa427-inbound" : "|111:1@s.whatsapp.net|owa427-inbound"
   _, inbox := state_store_get(&f.store, .Inbox_Message, key); testing.expect(t, inbox)
   testing.expect_value(t, socket_message_complete(&f.socket, event.message).kind, .None)
   // Reopen durable store, then replay through the OTHER primary address.
   restored: State_Store
   assert(state_store_load(&restored, f.path, f.store.identity).kind == .None)
   state_store_clear(&f.store); f.store = restored
   before := negative_ack_disk(f); defer delete(before)
   revision, durable := f.store.revision, f.store.durable_revision
   other := inbound_alias_node(encrypted, !lid_primary, group); defer inbound_alias_node_destroy(other)
   duplicate, duplicate_error := inbound_alias_process(f, other)
   testing.expect_value(t, duplicate_error.kind, .None)
   testing.expect_value(t, duplicate.kind, .None)
   negative_ack_unchanged(t, f, before, revision, durable)
  }
 }
}
@(test)
inbound_alias_failed_decrypt_or_save_never_commits_hints :: proc(t: ^testing.T) {
 for fail_save in ([]bool{false, true}) {
  f, encrypted := inbound_alias_fixture(false); defer negative_ack_destroy(f); defer delete(encrypted)
  before := negative_ack_disk(f); defer delete(before)
  revision, durable := f.store.revision, f.store.durable_revision
  bad_path: string
  defer delete(bad_path)
  if fail_save {
   bad_path = fmt.aprintf("%s/missing/state", f.directory)
   f.socket.config.state_path = bad_path
  } else {encrypted[len(encrypted) - 1] ~= 1}
  node := inbound_alias_node(encrypted, true, false); defer inbound_alias_node_destroy(node)
  event, error := inbound_alias_process(f, node)
  testing.expect(t, error.kind != .None)
  testing.expect_value(t, event.kind, .None)
  negative_ack_unchanged(t, f, before, revision, durable)
 }
}

inbound_alias_extra_attr :: proc(node: ^Binary_Node, attr: Binary_Node_Attribute) {
 attrs := make([]Binary_Node_Attribute, len(node.attrs) + 1)
 copy(attrs, node.attrs); attrs[len(node.attrs)] = attr
 delete(node.attrs); node.attrs = attrs
}
@(test)
inbound_alias_refuses_conflicting_invalid_and_ambiguous_sender_hints :: proc(t: ^testing.T) {
 for added in ([]Binary_Node_Attribute{
  {"addressing_mode", "pn"}, {"addressing_mode", "unknown"},
  {"sender_pn", "333@s.whatsapp.net"}, {"sender_lid", "999@lid"},
  {"sender_pn", "111@s.whatsapp.net"},
  {"sender_pn", "111:2@s.whatsapp.net"}, {"sender_pn", "111@lid"},
  {"sender_pn", "invalid"}, {"sender_pn", ""},
 }) {
  f, encrypted := inbound_alias_fixture(false); defer negative_ack_destroy(f); defer delete(encrypted)
  node := inbound_alias_node(encrypted, true, false); defer inbound_alias_node_destroy(node)
  // sender_pn is already present. To exercise both conflicts and bad values,
  // change that field when the added key repeats it; duplicate is separate.
  if added.key == "sender_pn" && added.value != "333@s.whatsapp.net" && added.value != "111@s.whatsapp.net" {
   node.attrs[len(node.attrs) - 1] = added
  } else {inbound_alias_extra_attr(&node, added)}
  before := negative_ack_disk(f); defer delete(before)
  revision, durable := f.store.revision, f.store.durable_revision
  event, error := inbound_alias_process(f, node)
  testing.expect(t, error.kind != .None)
  testing.expect_value(t, event.kind, .None)
  if event.message != nil {socket_message_destroy(event.message)}
  negative_ack_unchanged(t, f, before, revision, durable)
 }
}
@(test)
inbound_alias_refuses_existing_mapping_or_identity_pin_conflicts :: proc(t: ^testing.T) {
 for mapping_conflict in ([]bool{false, true}) {
  f, encrypted := inbound_alias_fixture(false); defer negative_ack_destroy(f); defer delete(encrypted)
  if mapping_conflict {
   assert(socket_lid_mapping_stage(&f.store, "111@s.whatsapp.net", "888@lid").kind == .None)
  } else {
   identity := signal_curve_public(inbound_alias_private(32))
   assert(state_store_set(&f.store, .Identity, "999:1@lid", identity[:]).kind == .None)
  }
  assert(state_store_save(&f.store, f.path).kind == .None)
  before := negative_ack_disk(f); defer delete(before)
  revision, durable := f.store.revision, f.store.durable_revision
  node := inbound_alias_node(encrypted, true, true); defer inbound_alias_node_destroy(node)
  event, error := inbound_alias_process(f, node)
  testing.expect_value(t, error.kind, .Identity_Changed)
  testing.expect_value(t, event.kind, .None)
  negative_ack_unchanged(t, f, before, revision, durable)
 }
}
@(test)
inbound_alias_preserves_no_hint_and_accepts_same_device_and_canonical_domains :: proc(t: ^testing.T) {
 for variant in 0 ..< 4 {
  f, encrypted := inbound_alias_fixture(false); defer negative_ack_destroy(f); defer delete(encrypted)
  node := inbound_alias_node(encrypted, variant != 0, false); defer inbound_alias_node_destroy(node)
  if variant == 0 {node.attrs = node.attrs[:len(node.attrs) - 1]}
  if variant == 1 {node.attrs[len(node.attrs) - 1].value = "111:1@s.whatsapp.net"}
  if variant == 2 {node.attrs[len(node.attrs) - 1].value = "111@c.us"}
  if variant == 3 {
   inbound_alias_extra_attr(&node, {"addressing_mode", "lid"})
   inbound_alias_extra_attr(&node, {"participant_pn", "111:1@c.us"})
  }
  event, error := inbound_alias_process(f, node)
  testing.expect_value(t, error.kind, .None)
  testing.expect_value(t, event.kind, .Message)
  if event.message != nil {socket_message_destroy(event.message)}
  _, mapped := state_store_get(&f.store, .LID_Mapping, "lid:999@lid")
  testing.expect_value(t, mapped, variant != 0)
 }
}
@(test)
inbound_alias_unsupported_encryption_preflight_precedes_hint_processing :: proc(t: ^testing.T) {
 f, encrypted := inbound_alias_fixture(false); defer negative_ack_destroy(f); defer delete(encrypted)
 node := inbound_alias_node(encrypted, true, true); defer inbound_alias_node_destroy(node)
 node.content.([]Binary_Node)[0].attrs[0].value = "msmsg"
 inbound_alias_extra_attr(&node, {"addressing_mode", "invalid"})
 before := negative_ack_disk(f); defer delete(before)
 revision, durable := f.store.revision, f.store.durable_revision
 event, error := inbound_alias_process(f, node)
 testing.expect_value(t, error.kind, .Unsupported_Message_Encryption)
 testing.expect_value(t, event.kind, .None)
 negative_ack_unchanged(t, f, before, revision, durable)
}

@(test)
inbound_alias_skipped_self_echo_and_unencrypted_control_cannot_install_hints :: proc(t: ^testing.T) {
 for own_group in ([]bool{false, true}) {
  f, encrypted := inbound_alias_fixture(false); defer negative_ack_destroy(f); defer delete(encrypted)
  node := inbound_alias_node(encrypted, !own_group, own_group); defer inbound_alias_node_destroy(node)
  if own_group {f.auth.account.jid_size = copy(f.auth.account.jid[:], "111:1@s.whatsapp.net")}
  else {node.content.([]Binary_Node)[0].tag = "unavailable"}
  event, error := inbound_alias_process(f, node)
  testing.expect_value(t, error.kind, .None)
  testing.expect_value(t, event.kind, .None)
  _, have := state_store_get(&f.store, .LID_Mapping, "lid:999@lid")
  testing.expect(t, !have)
 }
}

@(test)
inbound_alias_inbox_key_preserves_uninitialized_state_rejection :: proc(t: ^testing.T) {
 store: State_Store
 socket := Socket{store = &store}
 key, error := socket_inbox_key(&socket, "", "111@s.whatsapp.net", "inbox-guard")
 defer delete(key)
 testing.expect_value(t, error.kind, .Invalid_State)
 testing.expect_value(t, key, "")
}

@(test)
inbound_alias_inbox_key_preserves_nil_socket_and_store_rejection :: proc(t: ^testing.T) {
 for socket in ([](^Socket){nil, new(Socket)}) {
  defer if socket != nil {free(socket)}
  key, error := socket_inbox_key(socket, "", "111@s.whatsapp.net", "inbox-guard")
  defer delete(key)
  testing.expect_value(t, error.kind, .Invalid_State)
  testing.expect_value(t, key, "")
 }
 key, error := socket_inbox_key_store(nil, "", "111@s.whatsapp.net", "inbox-guard")
 defer delete(key)
 testing.expect_value(t, error.kind, .Invalid_State)
 testing.expect_value(t, key, "")
}

@(test)
inbound_alias_own_device_classification_requires_successful_decrypt_and_staged_mapping :: proc(t: ^testing.T) {
 for group in ([]bool{false, true}) {
  for corrupt in ([]bool{false, true}) {
   f, encrypted := inbound_alias_fixture(false); defer negative_ack_destroy(f); defer delete(encrypted)
   f.auth.account.jid_size = copy(f.auth.account.jid[:], "111:2@s.whatsapp.net")
   node := inbound_alias_node(encrypted, true, group); defer inbound_alias_node_destroy(node)
   before := negative_ack_disk(f); defer delete(before)
   revision, durable := f.store.revision, f.store.durable_revision
   if corrupt {encrypted[len(encrypted) - 1] ~= 1}
   event, error := inbound_alias_process(f, node)
   if corrupt {
    testing.expect(t, error.kind != .None)
    testing.expect_value(t, event.kind, .None)
    negative_ack_unchanged(t, f, before, revision, durable)
    continue
   }
   testing.expect_value(t, error.kind, .None)
   testing.expect_value(t, event.kind, .Message)
   if event.message == nil {continue}
   testing.expect(t, event.message.from_me)
   socket_message_destroy(event.message)
   restored: State_Store
   assert(state_store_load(&restored, f.path, f.store.identity).kind == .None)
   state_store_clear(&f.store); f.store = restored
   count := 0
   for record in f.store.records {
    if record.kind != .Inbox_Message {continue}
    recovered, restore_error := socket_inbox_record_restore(&f.socket, record)
    testing.expect_value(t, restore_error.kind, .None)
    if recovered != nil {
     count += 1
     testing.expect(t, recovered.from_me)
     socket_message_destroy(recovered)
    }
   }
   testing.expect_value(t, count, 1)
  }
 }
}

@(test)
inbound_alias_self_classification_refuses_invalid_owner_state :: proc(t: ^testing.T) {
 testing.expect(t, !socket_sender_is_self(nil, "111@s.whatsapp.net"))
 socket: Socket
 testing.expect(t, !socket_sender_is_self(&socket, "111@s.whatsapp.net"))
 store: State_Store
 auth: Auth_State
 testing.expect(t, !socket_sender_is_self_store(nil, &auth, "111@s.whatsapp.net"))
 testing.expect(t, !socket_sender_is_self_store(&store, &auth, "111@s.whatsapp.net"))
 testing.expect(t, !socket_sender_is_self_store(&store, nil, "111@s.whatsapp.net"))
}

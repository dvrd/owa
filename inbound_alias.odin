package whatsapp

import "core:fmt"
import "core:strings"

// Sender aliases are metadata from the authenticated message envelope, not a
// replacement for ciphertext authentication or the existing identity pins. Stage
// them only in the message candidate so failures cannot persist a routing hint.
// The pinned upstream decoder supplies bare alternates; preserve the primary
// sender device while normalizing the mapping itself to bare PN/LID identities.
socket_message_alias_stage :: proc(
 next, original: ^State_Store, node: Binary_Node, participant: string,
) -> Socket_Error {
 // No encrypted payload means no authentication gate for a new sender alias.
 children, encrypted_children := node.content.([]Binary_Node)
 if !encrypted_children {return {}}
 has_encrypted := false
 for child in children {if child.tag == "enc" {has_encrypted = true; break}}
 if !has_encrypted {return {}}
 primary_user, primary_device, primary_error := pairing_jid_decode(participant)
 if primary_error.kind != .None {return {kind = .Protocol_Error}}
 primary_lid := strings.has_suffix(participant, "@lid")
 primary_pn := strings.has_suffix(participant, "@s.whatsapp.net") ||
  strings.has_suffix(participant, "@c.us")
 if !primary_lid && !primary_pn {return {kind = .Protocol_Error}}

 alternate, mode := "", ""
 seen: u8
 for attr in node.attrs {
  bit: u8
  switch attr.key {
  case "participant_pn": bit = 1
  case "sender_pn": bit = 2
  case "participant_lid": bit = 4
  case "sender_lid": bit = 8
  case "addressing_mode": bit = 16
  case: continue
  }
  if seen & bit != 0 {return {kind = .Protocol_Error}}
  seen |= bit
  if bit == 16 {mode = attr.value; continue}
  // Only the opposite-domain sender hint can establish this mapping. Recipient
  // and peer_recipient hints are intentionally outside this sender-only policy.
  if len(attr.value) > 128 ||
   primary_lid && bit & 12 != 0 || primary_pn && bit & 3 != 0 {
   return {kind = .Protocol_Error}
  }
  user, device, error := pairing_jid_decode(attr.value)
  if error.kind != .None || device >= MAX_USER_DEVICES ||
   device != 0 && device != primary_device {
   return {kind = .Protocol_Error}
  }
  alternate_pn := strings.has_suffix(attr.value, "@s.whatsapp.net") ||
   strings.has_suffix(attr.value, "@c.us")
  if primary_lid && !alternate_pn ||
   primary_pn && !strings.has_suffix(attr.value, "@lid") {
   return {kind = .Protocol_Error}
  }
  // Attribute aliases may repeat the same bare user, but must not disagree.
  if alternate != "" && alternate != user {return {kind = .Identity_Changed}}
  alternate = user
 }
 if alternate == "" {return {}}
 if seen & 16 != 0 && mode != (primary_lid ? "lid" : "pn") {
  return {kind = .Protocol_Error}
 }
 pn := fmt.aprintf("%s@s.whatsapp.net", primary_lid ? alternate : primary_user)
 lid := fmt.aprintf("%s@lid", primary_lid ? primary_user : alternate)
 defer {delete(pn); delete(lid)}
 if error := socket_lid_mapping_stage(next, pn, lid); error.kind != .None {return error}
 return socket_lid_migrate(next, original)
}

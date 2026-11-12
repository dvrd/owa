package main

import wa "../.."
import "core:bytes"

canary_content_matches :: proc(s: ^Storage, index: int, node: wa.Binary_Node) -> bool {
 protobuf, valid := node.content.([]u8)
 if !valid || node.tag != "saved" {return false}
 media_type, _ := wa.pairing_node_attr(node, "mediatype")
 if index % 2 == 0 {
  if media_type != "" {return false}
  expected: [512]u8
  count, error := wa.text_message_encode(expected[:],
   {kind = .Conversation, text = qualification_text})
  return error == .None && bytes.equal(expected[:count], protobuf)
 }
 if media_type != "document" {return false}
 message, error := wa.media_message_decode(protobuf)
 if error.kind != .None || message.kind != .Document {return false}
 metadata, decoded := wa.media_metadata_from_message(message)
 defer wa.media_metadata_clear(&metadata)
 return decoded.kind == .None && message.caption == "Synthetic PDF transport check." &&
  message.mime_type == "application/pdf" && message.file_name == "mesa-qualification.pdf" &&
  metadata.file_length == u64(len(qualification_pdf)) &&
  metadata.file_sha256 == storage_digest(transmute([]u8)qualification_pdf)
}

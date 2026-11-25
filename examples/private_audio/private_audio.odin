package private_audio

import wa "shared:whatsapp"

// The application supplies its selected bare chat JID and calls this for an
// incoming audio event. A failure leaves the inbox available for redelivery.
complete_selected_audio :: proc(
	socket: ^wa.Socket,
	event: ^wa.Socket_Message,
	chat: string,
) -> wa.Socket_Error {
	return wa.socket_complete_private_audio(socket, event, chat)
}

Lookup :: enum {
	Local,
	Phone_By_ID,
	Missing_From_Response,
}

// Query only the linked phone when local capture has no descriptor.
// Inspect err first (including Query_Timeout and Media_Failed).
download_voice :: proc(
	socket: ^wa.Socket,
	chat, id: string,
	dst: []u8,
) -> (
	int,
	Lookup,
	wa.Socket_Error,
) {
	msg, local_err := wa.load_private_audio(socket.store, chat, id)
	if local_err.kind != .None {
		return 0, .Local, local_err
	}
	if msg != nil {
		defer wa.socket_message_destroy(msg)
		n, err := wa.socket_download_media(socket, msg, dst)
		return n, .Local, err
	}
	recovered, query_err := wa.socket_fetch_private_message_by_id(socket, chat, id)
	if query_err.kind != .None {
		return 0, .Phone_By_ID, query_err
	}
	if recovered == nil {
		return 0, .Missing_From_Response, {}
	}
	defer wa.socket_message_destroy(recovered)
	media, parse := wa.media_message_decode(recovered.protobuf)
	if parse.kind != .None {
		return 0, .Phone_By_ID, {kind = .Media_Failed, media = parse}
	}
	if media.kind != .Audio {
		return 0, .Phone_By_ID, {kind = .Media_Failed, media = {kind = .Invalid_Kind}}
	}
	n, err := wa.socket_download_media(socket, recovered, dst)
	return n, .Phone_By_ID, err
}

// Select the first two incoming voice notes after a unique outgoing question
// in this page. Equal timestamps cannot establish an order by themselves.
Question_Result :: enum {
	Found,
	Question_Missing,
	Notes_Missing,
	Ambiguous,
}
voices_after_question :: proc(
	page: wa.Recent_Chat_History,
	question: string,
) -> (
	[2]^wa.Socket_Message,
	Question_Result,
) {
	anchor: ^wa.Socket_Message
	for m in page.messages {
		if !m.from_me {
			continue
		}
		text, err := wa.text_message_decode(m.protobuf)
		if err != .None || text.kind == .None || text.text != question {
			continue
		}
		if anchor != nil {
			return {}, .Ambiguous
		}
		anchor = m
	}
	if anchor == nil {
		return {}, .Question_Missing
	}
	notes: [2]^wa.Socket_Message
	for m in page.messages {
		if m.from_me || m.timestamp < anchor.timestamp {
			continue
		}
		media, err := wa.media_message_decode(m.protobuf)
		if err.kind != .None || media.kind != .Audio || !media.voice_note {
			continue
		}
		if m.timestamp == anchor.timestamp {
			return {}, .Ambiguous
		}
		if notes[0] == nil || m.timestamp < notes[0].timestamp {
			notes[1], notes[0] = notes[0], m
		} else if notes[1] == nil || m.timestamp < notes[1].timestamp {
			notes[1] = m
		}
	}
	if notes[1] == nil {
		return {}, .Notes_Missing
	}
	for m in page.messages {
		if m == notes[1] || m.from_me || m.timestamp != notes[1].timestamp {
			continue
		}
		media, err := wa.media_message_decode(m.protobuf)
		if err.kind == .None && media.kind == .Audio && media.voice_note {
			return {}, .Ambiguous
		}
	}
	return notes, .Found
}

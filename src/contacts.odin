package whatsapp

import "core:slice"
import "core:strings"
import "core:unicode/utf8"

Contact :: struct {
	jid, alternate_jid, full_name, first_name, profile_name: string,
	is_saved:                                                bool,
}

Contact_Sync_Status :: enum {
	Syncing,
	Ready,
}

contact_sync_status :: proc(store: ^State_Store) -> Contact_Sync_Status {
	_, ready := state_store_get(store, .Contact_Sync_State, "ready")
	return .Ready if ready else .Syncing
}

@(private)
decode_saved_contact :: proc(jid: string, data: []u8) -> (Contact, bool) {
	encoded := string(data)
	first := strings.index_byte(encoded, 0)
	if first < 0 {
		return {}, false
	}
	tail := encoded[first + 1:]
	second := strings.index_byte(tail, 0)
	if second < 0 {
		return {}, false
	}
	return Contact {
			jid = jid,
			is_saved = true,
			full_name = encoded[:first],
			first_name = tail[:second],
			alternate_jid = tail[second + 1:],
		},
		true
}

// Names borrow the store until its next mutation. The exact or alternate
// bare JID can identify the same saved entry.
contact_by_jid :: proc(store: ^State_Store, jid: string) -> (Contact, bool) {
	if store == nil || !store.initialized || !device_user_jid_valid(jid, false) {
		return {}, false
	}
	result := Contact {
		jid = jid,
	}
	saved := false
	if names, exact := state_store_get(store, .Contact_Name, jid); exact {
		result, saved = decode_saved_contact(jid, names)
	} else {
		for record in store.records {
			if record.kind != .Contact_Name {
				continue
			}
			candidate, ok := decode_saved_contact(record.name, record.data)
			if ok && candidate.alternate_jid == jid {
				result, saved = candidate, true
				break
			}
		}
	}
	profile, seen := state_store_get(store, .Contact_Profile, result.jid)
	if !seen && result.alternate_jid != "" {
		profile, seen = state_store_get(store, .Contact_Profile, result.alternate_jid)
	}
	result.profile_name = string(profile)
	return result, saved || seen
}

// Returned JIDs borrow the store. The caller owns the result array. Search
// only owner-saved names, using a case-insensitive substring in either field.
search_contact_jids :: proc(
	store: ^State_Store,
	name: string,
) -> (
	jids: [dynamic]string,
	status: Contact_Sync_Status,
	error: State_Error,
) {
	if store == nil || !store.initialized {
		return nil, .Syncing, {kind = .Invalid_State}
	}
	status = contact_sync_status(store)
	query := strings.trim_space(name)
	if query == "" || !contact_name_valid(query) {
		return nil, status, {kind = .Invalid_Record}
	}
	needle, alloc_err := strings.to_lower(query)
	if alloc_err != nil {
		return nil, status, {kind = .Allocation_Failed, allocation = alloc_err}
	}
	defer delete(needle)
	for record in store.records {
		if record.kind != .Contact_Name {
			continue
		}
		// The NUL between the two fields cannot match a valid query.
		contact, valid := decode_saved_contact(record.name, record.data)
		if !valid {
			error = {
				kind = .Invalid_Record,
			}; break
		}
		names_length := len(contact.full_name) + 1 + len(contact.first_name)
		names, e := strings.to_lower(string(record.data[:names_length]))
		if e != nil {
			error = {
				kind       = .Allocation_Failed,
				allocation = e,
			}; break
		}
		matches := strings.contains(names, needle)
		delete(names)
		if matches {
			if _, err := append(&jids, record.name); err != nil {
				error = {
					kind       = .Allocation_Failed,
					allocation = err,
				}
				break
			}
		}
	}
	if error.kind != .None {
		delete(jids); return nil, status, error
	}
	slice.sort(jids[:])
	return
}

@(private)
contact_name_valid :: proc(name: string) -> bool {
	return len(name) <= 4096 && utf8.valid_string(name) && strings.index_byte(name, 0) < 0
}

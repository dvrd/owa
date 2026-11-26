package whatsapp_test

import "core:testing"
import wa "shared:whatsapp"

@(test)
contact_search_matches_unicode_saved_names_and_rejects_blank_queries :: proc(t: ^testing.T) {
	store: wa.State_Store
	testing.expect_value(t, wa.state_store_init(&store, [32]u8{0 = 1}).kind, wa.State_Error_Kind.None)
	defer wa.state_store_clear(&store)

	record := transmute([]u8)string("Ángela Mesa\x00Ángela\x00")
	testing.expect_value(t, wa.state_store_set(&store, .Contact_Name, "123@lid", record).kind, wa.State_Error_Kind.None)

	jids, status, err := wa.search_contact_jids(&store, " áNg ")
	defer delete(jids)

	testing.expect_value(t, err.kind, wa.State_Error_Kind.None)
	testing.expect_value(t, status, wa.Contact_Sync_Status.Syncing)
	testing.expect(t, len(jids) == 1 && jids[0] == "123@lid")

	empty, _, invalid := wa.search_contact_jids(&store, "  ")
	defer delete(empty)

	testing.expect_value(t, invalid.kind, wa.State_Error_Kind.Invalid_Record)
}

@(test)
contact_jids_outlive_the_lookup_buffer :: proc(t: ^testing.T) {
	store: wa.State_Store
	assert(wa.state_store_init(&store, [32]u8{0 = 1}).kind == .None)
	defer wa.state_store_clear(&store)

	for kind in ([]wa.State_Record_Kind{.Contact_Profile, .Contact_Name}) {
		value := "Profile" if kind == .Contact_Profile else "Daniel\x00Dan\x00999@lid"
		assert(wa.state_store_set(&store, kind, "123@s.whatsapp.net", transmute([]u8)value).kind == .None)
		query: [32]u8
		n := copy(query[:], "123@s.whatsapp.net")
		result, found := wa.contact_by_jid(&store, string(query[:n]))
		query[0] = '8'
		testing.expect(t, found && result.jid == "123@s.whatsapp.net")
	}
}

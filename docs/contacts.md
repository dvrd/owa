# Searching the linked account’s contacts

Set `Socket_Config.sync_contacts = true` before connecting. Continue calling `socket_receive` and `socket_tick` in the normal socket loop. On login, owa requests the address book from WhatsApp. It can fetch a contact even when that person has never sent the account a message. Changes announced by the server trigger an incremental sync on a subsequent tick.

```odin
jids, status, err := wa.search_contact_jids(store, "Daniel")
defer delete(jids)
if err.kind == .None {
	for jid in jids {
		fmt.println(jid)
	}
	if status == .Syncing {
		fmt.println("La agenda todavía se está sincronizando.")
	} else if len(jids) == 0 {
		fmt.println("No se encontraron contactos.")
	}
}
```

The query matches a case-insensitive substring of the owner's saved full or first name. It returns every matching saved entry, ordered by JID. A blank query returns an error. To read a specific contact, use `contact, found := wa.contact_by_jid(store, jid)`. The contact exposes `full_name`, `first_name`, and `profile_name`. A known JID may have only a profile name. Check `contact.is_saved` to tell whether it is in the address book. Its `alternate_jid` is populated when WhatsApp supplies the corresponding phone-number JID or LID.

Searches read the account's existing `State_Store` and work offline after a successful sync. `.Ready` describes the last completed sync. Results returned with `.Syncing` may be partial. JID strings and contact names borrow the store. Copy any values you need to keep before processing another socket event or closing the store.

To refresh explicitly, call `status, err := wa.socket_sync_contacts(socket)` on the online socket's event-loop thread. A previously linked session can lack the keys for its existing address book. In that case owa requests the missing key from the account's primary device and returns `.Syncing`. With automatic sync enabled, the event loop retries when the key arrives. Without it, keep processing incoming messages and call the refresh again. A network, authentication, or persistence failure returns an error.

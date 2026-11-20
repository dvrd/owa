# Searching the linked account’s contacts

Set `Socket_Config.sync_contacts = true` before connecting. Continue calling `socket_read` and `socket_tick` in the normal socket loop. On login, owa requests the address book from WhatsApp. It can fetch a contact even when that person has never sent the account a message. Changes announced by the server trigger an incremental sync on a subsequent tick.

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

On the first refresh after upgrading from the older contact index, owa requests the address book from version zero. Cached names remain available with `.Syncing` until an authenticated page replaces them. Profile-history downloads resume from durable references after reconnecting.

Use `socket_add_contact(socket, phone_jid, full_name)` with an online linked
session and a bare phone-number JID ending in `@s.whatsapp.net`. The library
synchronizes the address book, sends an authenticated contact update, and reads
the saved name back from WhatsApp. A repeat with the same name succeeds. If the
JID already has another saved name, the call returns `Contact_Already_Exists`.
If synchronization is pending, process incoming events and retry.

## Rolling a linked session back to v0.2.0–v0.2.2

Stop the account's connection owner and hold the same exclusive session lock
used by the application. Load the current credential, prekey and state files.
`state_store_export_v0_2(&store, new_state_path)` writes a legacy-readable
snapshot from the durable revision. Use a new private destination and include
the matching credentials and prekeys from the same checkpoint. The bot-mesa
utility provides this operation as `session export-v0.2 PARENT`.

The export preserves the authenticated contact cursor, names, Signal sessions,
pending ciphertext, and message deduplication timestamps. Its return count
reports deferred profile-history downloads omitted from the legacy copy. Their
references stay in the original. After the old version goes online, its working
files are the authoritative session for the next upgrade.

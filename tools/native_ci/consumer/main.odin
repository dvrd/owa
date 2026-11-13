package main

import wa "shared:whatsapp"
import "core:fmt"

main :: proc() {
 identity: [32]u8
 identity[0] = 1
 store: wa.State_Store
 assert(wa.state_store_init(&store, identity).kind == .None)
 defer wa.state_store_clear(&store)
 assert(wa.state_store_set(&store, .Session, "native-ci-consumer", []u8{1, 2, 3}).kind == .None)
 value, found := wa.state_store_get(&store, .Session, "native-ci-consumer")
 assert(found && len(value) == 3 && value[0] == 1 && value[2] == 3)
 assert(wa.state_store_set(&store, .Session, "native-ci-consumer", []u8{4}).kind == .None)
 value, found = wa.state_store_get(&store, .Session, "native-ci-consumer")
 assert(found && len(value) == 1 && value[0] == 4)
 fmt.println("OWA_NATIVE_CONSUMER_PASS")
}

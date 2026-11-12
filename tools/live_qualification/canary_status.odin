package main

import "core:fmt"
import "core:os"

canary_durable_completed :: proc(s: ^Storage) -> u64 {
 ledger := s.canary
 if ledger == nil || ledger.count == 0 {return 0}
 first := int(ledger.count)-2
 completed := ledger.entries[first].intent.status == .Acknowledged &&
  ledger.entries[first+1].intent.status == .Acknowledged
 return completed ? ledger.cycle : ledger.cycle-1
}

canary_status :: proc(runner: ^Runner) {
 first, last: i64
 if runner.storage.canary != nil {
  first = runner.storage.canary.first_completed_at
  last = runner.storage.canary.completed_at
 }
 fmt.printf("CANARY_STATUS completed_cycles=%d durable_completed_cycles=%d "+
  "first_ack_unix_seconds=%d last_ack_unix_seconds=%d\n", runner.canary_completed,
  canary_durable_completed(&runner.storage), first, last)
 os.flush(os.stdout)
}

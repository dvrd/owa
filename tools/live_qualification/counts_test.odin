package main

import wa "../.."
import "core:testing"

@(test)
probe_group_counts_distinguish_empty_missing_exact_and_ambiguous_subjects :: proc(t: ^testing.T) {
 empty := group_counts(nil, "offline")
 testing.expect_value(t, empty.total, 0)
 testing.expect_value(t, empty.empty_subjects, 0)
 testing.expect_value(t, empty.exact_matches, 0)

 missing := group_counts({{jid = "synthetic@g.us"}}, "offline")
 testing.expect_value(t, missing.total, 1)
 testing.expect_value(t, missing.empty_subjects, 1)
 testing.expect_value(t, missing.exact_matches, 0)

 groups := []wa.Socket_Group_Summary{
  {jid = "one@g.us", subject = "offline"},
  {jid = "two@g.us", subject = "Offline"},
  {jid = "three@g.us", subject = "other"},
  {jid = "four@g.us"},
  {jid = "five@g.us", subject = "offline"},
 }
 exact := group_counts(groups[:4], "offline")
 testing.expect_value(t, exact.total, 4)
 testing.expect_value(t, exact.empty_subjects, 1)
 testing.expect_value(t, exact.exact_matches, 1)

 duplicate := group_counts(groups, "offline")
 testing.expect_value(t, duplicate.total, 5)
 testing.expect_value(t, duplicate.empty_subjects, 1)
 testing.expect_value(t, duplicate.exact_matches, 2)
 _, ambiguity := group_select(groups, "offline")
 testing.expect_value(t, ambiguity.kind, .Target_Ambiguous)
}

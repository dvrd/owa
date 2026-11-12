package main

import "core:testing"

@(test)
retarget_requires_explicit_previous_and_new_exact_subjects :: proc(t: ^testing.T) {
 args := []string{"retarget", "--auth-dir", "/private/test-session",
  "--previous-group-subject", "Old Exact Subject", "--group-subject", "botlab"}
 options, error := options_parse(args)
 testing.expect_value(t, error.kind, .None)
 testing.expect_value(t, options.command, .Retarget)
 testing.expect_value(t, options.previous_group_subject, "Old Exact Subject")
 testing.expect_value(t, options.group_subject, "botlab")
 for suffix in ([]([]string){
  {"--send"}, {"--preview"}, {"--hold-seconds", "0"},
  {"--timeout-seconds", "60"}, {"--previous-group-subject", "Other"},
 }) {
  expanded := make([dynamic]string); defer delete(expanded)
  append(&expanded, ..args); append(&expanded, ..suffix)
  _, rejected := options_parse(expanded[:])
  testing.expect_value(t, rejected.kind, .Usage)
 }
}

@(test)
retarget_incomplete_or_misplaced_subject_contract_is_rejected :: proc(t: ^testing.T) {
 for args in ([]([]string){
  {"retarget"},
  {"retarget", "--auth-dir", "/private/test-session", "--group-subject", "botlab"},
  {"retarget", "--auth-dir", "/private/test-session",
   "--previous-group-subject", "Old Exact Subject"},
  {"inspect", "--auth-dir", "/private/test-session", "--group-subject", "botlab",
   "--previous-group-subject", "Old Exact Subject"},
 }) {
  _, rejected := options_parse(args)
  testing.expect_value(t, rejected.kind, .Usage)
 }
}

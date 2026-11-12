"""Pure evidence tests; no sockets, credentials, or native account jobs."""
import importlib.util
from pathlib import Path
import unittest
SPEC=importlib.util.spec_from_file_location('progress',Path(__file__).with_name('progress.py'))
P=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(P)

class Tests(unittest.TestCase):
    def counter(self,total,cycles=0):
        return {'phase':'CANARY_STATUS','completed_cycles':cycles,
            'durable_completed_cycles':total,'first_ack_unix_seconds':100 if total else 0,
            'last_ack_unix_seconds':200+total if total else 0}

    def healthy(self,tracker):
        for elapsed in (0,60):
            tracker.observe({'phase':'WATCH_HEALTH','process_elapsed_seconds':elapsed,
                             'reconnects':0},elapsed,elapsed)

    def test_counter_baseline_and_minimum_three_new_cycles_are_explicit(self):
        tracker=P.Progress('run',0,86400,21600)
        tracker.observe(self.counter(10),0,0); self.healthy(tracker)
        self.assertEqual(tracker.finish(86400,86400),'CANARY_COVERAGE_INCOMPLETE')
        tracker.observe(self.counter(13,3),70,70)
        self.assertIsNone(tracker.finish(86400,86400))
        self.assertEqual(tracker.values['canary_completed_baseline'],10)
        self.assertEqual(tracker.values['canary_completed_latest'],13)
        self.assertEqual(tracker.values['canary_new_completed_cycles'],3)
        self.assertEqual(tracker.values['canary_minimum_required_cycles'],3)
        self.assertNotIn('recipient_confirmed',tracker.values)

    def test_short_smoke_explicitly_records_zero_cycles(self):
        tracker=P.Progress('smoke',0,120,3600)
        tracker.observe(self.counter(0),0,0)
        self.assertIsNone(tracker.finish(120,120))
        self.assertEqual(tracker.values['canary_new_completed_cycles'],0)
        self.assertEqual(tracker.values['canary_minimum_required_cycles'],0)

    def test_missing_counter_or_premature_completion_cannot_qualify(self):
        tracker=P.Progress('run',0,86400,21600)
        self.assertEqual(tracker.finish(86400,86400),'CANARY_EVIDENCE_MISSING')
        tracker.observe(self.counter(0),0,0); tracker.observe(self.counter(3,3),60,60)
        self.healthy(tracker)
        self.assertEqual(tracker.finish(60,60),'CANARY_DURATION_INCOMPLETE')

    def test_sparse_health_is_not_counted_as_observed_coverage(self):
        tracker=P.Progress('run',0,86400,21600)
        tracker.observe(self.counter(0),0,0); tracker.observe(self.counter(3,3),1,1)
        for elapsed in (0,120):
            tracker.observe({'phase':'WATCH_HEALTH','process_elapsed_seconds':elapsed,
                             'reconnects':0},elapsed,elapsed)
        self.assertEqual(tracker.values['observed_seconds'],0)
        self.assertEqual(tracker.values['max_health_gap_seconds'],120)
        self.assertEqual(tracker.finish(86400,86400),'HEALTH_COVERAGE_INCOMPLETE')

    def test_regressing_durable_counter_fails_closed(self):
        tracker=P.Progress('run',0,86400,21600)
        tracker.observe(self.counter(10),0,0)
        with self.assertRaisesRegex(P.ProgressError,'CANARY_COUNTER_REGRESSED'):
            tracker.observe(self.counter(9),1,1)

    def test_resume_keeps_baseline_but_never_claims_continuous_coverage(self):
        tracker=P.Progress('run',0,86400,21600)
        tracker.observe(self.counter(10),0,0); self.healthy(tracker)
        tracker.observe(self.counter(11,1),60,60)
        resumed=P.Progress('run',100,86400,21600,tracker.values)
        self.assertEqual(resumed.values['canary_completed_baseline'],10)
        self.assertEqual(resumed.values['canary_completed_latest'],11)
        self.assertFalse(resumed.values['health_coverage_qualified'])
        self.assertEqual(resumed.values['connection_gap_events'],1)

    def test_private_progress_corruption_is_rejected(self):
        with self.assertRaises(P.ProgressError): P.Progress('run',0,60,0,[])
        tracker=P.Progress('run',0,60,0)
        previous=dict(tracker.values,observed_seconds='private-untyped-value')
        with self.assertRaises(P.ProgressError): P.Progress('run',0,60,0,previous)

    def test_sleep_gap_counts_wall_time_without_inventing_observed_seconds(self):
        tracker=P.Progress('run',0,86400,21600)
        tracker.observe({'phase':'WATCH_HEALTH','process_elapsed_seconds':0,
                         'reconnects':0},0,0)
        tracker.observe({'phase':'WATCH_HEALTH','process_elapsed_seconds':0,
                         'reconnects':0},0,120)
        self.assertEqual(tracker.values['max_health_gap_seconds'],120)
        self.assertEqual(tracker.values['observed_seconds'],0)
        self.assertFalse(tracker.values['health_coverage_qualified'])

if __name__=='__main__': unittest.main()

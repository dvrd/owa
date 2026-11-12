import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('protocol_ci', Path(__file__).with_name('ci.py'))
C = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(C)


class Tests(unittest.TestCase):
    def test_drift_is_not_downgraded_and_only_public_input_is_prepared(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'output'
            report = {'status': 'REVIEW_REQUIRED', 'observation': {'sources': []}}
            result = C.prepare(Path(tmp)/'state', output, lambda _: report)
            self.assertEqual(result['status'], 'REVIEW_REQUIRED')
            self.assertFalse(result['compatibility_approved'])
            self.assertTrue(result['report_ready'])
            self.assertEqual(json.loads((output/'report.json').read_text()), report)
            self.assertFalse((output/'prompt.txt').exists())
            self.assertFalse((output/'schema.json').exists())
            self.assertEqual(stat.S_IMODE((output/'report.json').stat().st_mode), 0o600)

    def test_failure_does_not_make_agent_input_or_leak_raw_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            def fail(_): raise C.schedule.ScheduleError('private-secret')
            output = Path(tmp)/'output'
            result = C.prepare(Path(tmp)/'state', output, fail)
            self.assertEqual(result['status'], 'FAILED')
            self.assertFalse(result['report_ready'])
            self.assertFalse((output/'prompt.txt').exists())
            self.assertNotIn('private-secret', (output/'result.json').read_text())

    def test_no_drift_is_distinct_from_compatibility_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = C.prepare(Path(tmp)/'state', Path(tmp)/'output',
                               lambda _: {'status': 'NO_MONITORED_DRIFT'})
            self.assertEqual(result['status'], 'NO_MONITORED_DRIFT')
            self.assertFalse(result['compatibility_approved'])


if __name__ == '__main__': unittest.main()

import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('promotion_gate',
    Path(__file__).with_name('promotion_gate.py'))
G = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G)


class GateTests(unittest.TestCase):
    def inputs(self, root):
        (root / 'runtime.odin').write_text('package synthetic\n')
        digest, _ = G.source_digest(root)
        artifact = root / 'evidence.txt'
        artifact.write_text('synthetic executed-check fixture\n')
        evidence = {'evidence_file': artifact.name,
                    'evidence_sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()}
        offline = {'candidate_source_digest': digest, 'compiler_sha256': 'c' * 64,
            'checks': {name: {'status': 'PASS', 'candidate_source_digest': digest,
                             **evidence} for name in G.REQUIRED}}
        live = {'candidate_source_digest': digest, 'isolated_group_verified': True,
            'text_server_acked': True, 'pdf_server_acked': True, 'recipient_confirmed': True,
            'pdf_opened': True, 'same_ids_after_restart': True, 'duplicates_reported': False,
            **evidence}
        return offline, live

    def test_eligible_evidence_never_authorizes_deployment_or_state_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = self.inputs(root)
            result = G.evaluate(root, *inputs)
            self.assertEqual(result['status'], 'ELIGIBLE_FOR_REVIEW')
            self.assertFalse(result['deployment_authorized'])
            self.assertFalse(result['state_rollback_authorized'])

    def test_source_change_invalidates_both_evidence_sets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = self.inputs(root)
            (root / 'runtime.odin').write_text('package changed\n')
            result = G.evaluate(root, *inputs)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertIn('OFFLINE_SOURCE_MISMATCH', result['failures'])
            self.assertIn('LIVE_SOURCE_MISMATCH', result['failures'])

    def test_ack_alone_and_missing_or_skipped_checks_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); offline, live = self.inputs(root)
            live['recipient_confirmed'] = False
            offline['checks']['unit_asan']['status'] = 'SKIPPED'
            del offline['checks']['protocol_review']
            result = G.evaluate(root, offline, live)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertIn('LIVE_QUALIFICATION_INCOMPLETE', result['failures'])
            self.assertIn('MISSING_OR_INVALID_UNIT_ASAN', result['failures'])
            self.assertIn('MISSING_OR_INVALID_PROTOCOL_REVIEW', result['failures'])

    def test_changed_evidence_is_rejected_even_when_pass_flags_remain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); inputs = self.inputs(root)
            (root / 'evidence.txt').write_text('changed after validation\n')
            result = G.evaluate(root, *inputs)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertIn('LIVE_EVIDENCE_MISSING_OR_CHANGED', result['failures'])


if __name__ == '__main__':
    unittest.main()

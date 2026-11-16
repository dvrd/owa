"""Public scan/assessment handoff using only synthetic supplied bytes."""
import copy
import importlib.util
import json
import sys
import types
from unittest import mock
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('triage_watch', (Path(__file__).resolve().parents[1] / ('watch.py')))
W = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(W)

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ['socket.odin','connection.odin','binary_node.odin','auth.odin','pairing.odin']:
            (self.root/name).write_text('package whatsapp\n')

    def observation(self, path, old, new):
        manifest = copy.deepcopy(W.manifest_read(W.HERE/'sources.json'))
        manifest['sources'] = manifest['sources'][:1]
        source = manifest['sources'][0]; source['paths'] = [path]
        def get(url, timeout):
            self.assertGreater(timeout,0); self.assertLessEqual(timeout,10)
            if '/commits/' in url: return json.dumps({'sha':'1'*40}).encode()
            return old if source['reference_commit'] in url else new
        value = W.observe(manifest, get=get, local_root=self.root)
        return value['sources'][0]['files'][0]

    def test_comment_only_drift_retains_hashes_but_proves_no_action(self):
        item = self.observation('src/Socket/socket.ts', b'const x=1; // old\n', b'const x = 1; // new\n')
        self.assertTrue(item['changed_from_reference'])
        self.assertNotEqual(item['reference']['sha256'],item['current']['sha256'])
        self.assertEqual(item['assessment']['kind'],'NO_ACTION')
        self.assertEqual(item['assessment']['evidence']['reference'],item['reference'])
        self.assertEqual(item['assessment']['evidence']['current'],item['current'])

    def test_behavior_change_arrives_as_specific_spike(self):
        item = self.observation('src/Socket/socket.ts', b'const x=1;\n', b'const x=2;\n')
        value = item['assessment']
        self.assertEqual(value['kind'],'SPIKE'); self.assertTrue(value['local_targets'])
        self.assertEqual(value['reason'],'BEHAVIOR_CHANGE_UNRESOLVED')
        self.assertEqual({x['path'] for x in value['local_targets']},
                         {'socket.odin','connection.odin','auth.odin','pairing.odin'})
        self.assertTrue(value['checks']); self.assertTrue(value['acceptance'])
        self.assertTrue(value['evidence']['question'])
        self.assertFalse(value['evidence']['server_compatibility_proven'])

    def test_unapproved_table_difference_is_spike_with_all_indices(self):
        old = ['token-'+str(i) for i in range(236)]; new=old.copy(); new[7]='replacement'
        (self.root/'binary_tokens.odin').write_text('package whatsapp\nSINGLE_BYTE_TOKENS := [236]string {'+','.join(json.dumps(v) for v in old)+'}\n')
        def source(values): return ('export const SINGLE_BYTE_TOKENS = ['+','.join(json.dumps(v) for v in values)+'];\n').encode()
        item = self.observation('src/WABinary/constants.ts', source(old), source(new))
        self.assertEqual(item['assessment']['kind'],'SPIKE')
        self.assertEqual(item['assessment']['evidence']['changed_indices'],[7])
        self.assertEqual(item['assessment']['local_targets'][0]['path'],'binary_tokens.odin')

    def test_unchanged_file_does_not_invent_an_assessment(self):
        item = self.observation('src/Socket/socket.ts',b'const x=1;\n',b'const x=1;\n')
        self.assertFalse(item['changed_from_reference']); self.assertNotIn('assessment',item)

class RunnerHandoffTests(unittest.TestCase):
    def module(self, name):
        spec=importlib.util.spec_from_file_location('handoff_'+name,(Path(__file__).resolve().parents[1] / (name+'.py')))
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

    def test_completed_watcher_is_never_signalled_after_reaping(self):
        schedule=self.module('schedule')
        with mock.patch.object(schedule,'stop_group',side_effect=AssertionError('post-reap signal')):
            result=schedule.watch_capture([sys.executable,'-c','print(\'{"status":"NO_MONITORED_DRIFT"}\')'])
        self.assertEqual(result['status'],'NO_MONITORED_DRIFT')

    def test_ci_forwards_only_explicit_reviewed_contract(self):
        ci=self.module('ci');seen=[]
        def scan(args):
            seen.append(args.approved_contract)
            return {'status':'NO_MONITORED_DRIFT'}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            ci.prepare(root/'state',root/'out1',scan)
            ci.prepare(root/'state',root/'out2',scan,approved_contract='tools/protocol_watch/contracts/reviewed.json')
        self.assertEqual(seen,[None,'tools/protocol_watch/contracts/reviewed.json'])

    def test_watch_runner_passes_contract_as_an_argument_without_execution(self):
        schedule=self.module('schedule')
        with tempfile.TemporaryDirectory() as d:
            state=Path(d);report={'status':'NO_MONITORED_DRIFT','observation':{'sources':[]}}
            args=types.SimpleNamespace(state_dir=state,manifest=state/'manifest.json',
                approved_contract='tools/protocol_watch/contracts/reviewed.json')
            def capture(argv,clock):
                self.assertEqual(argv[-2:],['--approved-contract',args.approved_contract])
                schedule.watch.atomic_json(state/'report.json',report)
                return {'status':'NO_MONITORED_DRIFT'}
            with mock.patch.object(schedule,'watch_capture',side_effect=capture):
                self.assertEqual(schedule.watch_run(args),report)

if __name__ == '__main__': unittest.main()

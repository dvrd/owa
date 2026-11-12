import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('protocol_watch', Path(__file__).with_name('watch.py'))
W = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W)
BASE, HEAD = 'a' * 40, 'b' * 40


def manifest():
    return {'schema': 1, 'sources': [{'name': 'baileys', 'repository': 'WhiskeySockets/Baileys',
        'branch': 'master', 'reference_commit': BASE, 'reference_scope': 'synthetic fixture',
        'paths': ['schema.proto', 'auth.ts']}]}


def upstream(url, timeout):
    assert 0 < timeout <= 10
    if '/commits/' in url:
        return json.dumps({'sha': HEAD}).encode()
    return b'old schema' if BASE in url else b'new schema'


class WatchTests(unittest.TestCase):
    def test_observed_head_does_not_approve_or_hide_reference_drift(self):
        initial = W.observe(manifest(), upstream)
        first = W.compare(initial)
        second = W.compare(initial, copy.deepcopy(initial))
        self.assertEqual(first['status'], 'REVIEW_REQUIRED')
        self.assertEqual(second['historical_reference_drift'],
                         ['baileys:schema.proto', 'baileys:auth.ts'])
        self.assertEqual(second['changes_since_observation'], [])
        self.assertFalse(second['compatibility_approved'])
        self.assertFalse(second['runtime_version_changed'])

    def test_new_drift_and_file_removal_are_visible(self):
        previous = W.observe(manifest(), upstream)
        def changed(url, timeout):
            if url.endswith('/schema.proto') and HEAD in url:
                return None
            return upstream(url, timeout)
        current = W.observe(manifest(), changed)
        result = W.compare(current, previous)
        self.assertEqual(result['changes_since_observation'], ['baileys:schema.proto'])
        self.assertFalse(current['sources'][0]['files'][0]['current']['present'])

    def test_failed_fetch_preserves_successful_observation_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state'
            W.check(manifest(), state, upstream)
            before = {name: (state / name).read_bytes() for name in ['observed.json', 'report.json']}
            def fail(url, timeout):
                raise W.WatchError('UPSTREAM_FETCH_FAILED')
            with self.assertRaisesRegex(W.WatchError, 'UPSTREAM_FETCH_FAILED'):
                W.check(manifest(), state, fail)
            for name, content in before.items():
                self.assertEqual((state / name).read_bytes(), content)
            failure = json.loads((state / 'last_attempt.json').read_bytes())
            self.assertEqual(failure['status'], 'FAILED')
            self.assertFalse(failure['compatibility_approved'])

    def test_invalid_head_missing_paths_and_budget_do_not_pass(self):
        for value in [None, b'{}', b'{"sha":"not-a-commit"}', b'[]']:
            with self.assertRaises(W.WatchError): W.observe(manifest(), lambda u, t: value)
        with self.assertRaisesRegex(W.WatchError, 'MONITORED_PATH_MISSING'):
            W.observe(manifest(), lambda u, t: upstream(u, t) if '/commits/' in u else None)
        ticks = iter([0, 181])
        with self.assertRaisesRegex(W.WatchError, 'CHECK_BUDGET_EXPIRED'):
            W.observe(manifest(), upstream, now=lambda: next(ticks))

    def test_state_refuses_unsafe_paths_and_parallel_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shared = root / 'shared'; shared.mkdir(mode=0o755)
            with self.assertRaisesRegex(W.WatchError, 'STATE_DIRECTORY_UNSAFE'):
                with W.locked_state(shared): pass
            target = root / 'target'; target.mkdir(mode=0o700)
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaises(W.WatchError):
                with W.locked_state(link): pass
            state = root / 'state'
            with W.locked_state(state):
                with self.assertRaisesRegex(W.WatchError, 'ALREADY_RUNNING'):
                    with W.locked_state(state): pass
            external = root / 'external'; external.write_text('{}'); external.chmod(0o600)
            (state / 'observed.json').hardlink_to(external)
            with self.assertRaisesRegex(W.WatchError, 'STATE_FILE_UNSAFE'):
                W.check(manifest(), state, upstream)
            self.assertEqual(external.read_text(), '{}')

    def test_manifest_is_immutable_and_rejects_untrusted_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'manifest.json'
            path.write_text(json.dumps(manifest()))
            before = path.read_bytes()
            W.check(W.manifest_read(path), Path(tmp) / 'state', upstream)
            self.assertEqual(path.read_bytes(), before)
            for key, value in [('repository', 'other/repo'), ('paths', ['../private']),
                               ('paths', ['schema.proto'] * 17), ('reference_commit', 'master')]:
                bad = manifest(); bad['sources'][0][key] = value
                path.write_text(json.dumps(bad))
                with self.assertRaises(W.WatchError): W.manifest_read(path)

    def test_redirect_is_never_followed(self):
        with self.assertRaisesRegex(W.WatchError, 'UPSTREAM_REDIRECT'):
            W.NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_invalid_version_feed_never_silently_falls_back(self):
        self.assertEqual(W.version_decode(b'{"version":[2,3000,42]}'), [2, 3000, 42])
        for data in [b'{}', b'{"version":[true,2,3]}', b'{"version":[1,2]}',
                     b'{"version":[-1,2,3]}', b'not JSON', None]:
            with self.assertRaisesRegex(W.WatchError, 'VERSION_FEED_INVALID'):
                W.version_decode(data)


if __name__ == '__main__':
    unittest.main()

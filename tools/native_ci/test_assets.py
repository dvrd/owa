import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import sys
import unittest
from unittest import mock

import assets


class Tests(unittest.TestCase):
    def gate(self):
        spec = importlib.util.spec_from_file_location('native_gate', Path(__file__).with_name('run.py'))
        gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
        return gate

    def archive(self, directory, members):
        path = directory/'archive.tar.gz'
        with tarfile.open(path, 'w:gz') as stream:
            for name, data, kind in members:
                info = tarfile.TarInfo(name); info.mode = 0o644; info.type = kind
                if kind == tarfile.REGTYPE: info.size = len(data)
                if kind == tarfile.SYMTYPE: info.linkname = '/tmp/outside'
                stream.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        return path

    def test_roundtrip_regular_sources_and_executable_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'source'; source.mkdir()
            (source/'run').write_bytes(b'fixture'); (source/'run').chmod(0o755)
            (source/'nested').mkdir(); (source/'nested/data').write_bytes(b'data')
            entry = assets.package(source, ['run', 'nested/data'], root/'package.tar.gz', root/'manifest.json', 'fixture')
            assets.verify_object(root/entry['archive']['name'], entry['archive'])
            expected = assets.files_manifest(root/'manifest.json')
            assets.extract(root/'package.tar.gz', root/'output', expected, 'fixture')
            self.assertEqual((root/'output/nested/data').read_bytes(), b'data')
            self.assertTrue((root/'output/run').stat().st_mode & 0o100)

    def test_archive_paths_links_duplicates_and_size_mismatch_are_rejected(self):
        bad = [('../outside', b'x', tarfile.REGTYPE), ('fixture/../../outside', b'x', tarfile.REGTYPE),
               ('fixture/data', b'', tarfile.SYMTYPE), ('other/data', b'x', tarfile.REGTYPE),
               ('fixture/data', b'xx', tarfile.REGTYPE)]
        expected = {'data': {'bytes': 1, 'sha256': 'a'*64}}
        for item in bad:
            with self.subTest(item=item), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); archive = self.archive(root, [item])
                with self.assertRaises(assets.AssetError): assets.extract(archive, root/'out', expected, 'fixture')
                self.assertFalse((root/'outside').exists())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = self.archive(root, [('fixture/data', b'x', tarfile.REGTYPE)]*2)
            with self.assertRaisesRegex(assets.AssetError, 'DUPLICATE'):
                assets.extract(archive, root/'out', expected, 'fixture')

    def test_missing_or_unexpected_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = self.archive(root, [])
            with self.assertRaisesRegex(assets.AssetError, 'FILES_MISSING'):
                assets.extract(archive, root/'out', {'data': {'bytes': 1, 'sha256': 'a'*64}}, 'fixture')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'extra').write_text('unexpected')
            with self.assertRaisesRegex(assets.AssetError, 'MEMBERS_MISMATCH'):
                assets.verify_tree(root, {})

    def test_objects_refuse_wrong_hash_wrong_size_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root/'object'; path.write_bytes(b'fixture')
            record = assets.object_record(path)
            with self.assertRaisesRegex(assets.AssetError, 'HASH_MISMATCH'):
                assets.verify_object(path, {**record, 'sha256': 'a'*64})
            with self.assertRaisesRegex(assets.AssetError, 'SIZE_OR_TYPE'):
                assets.verify_object(path, {**record, 'bytes': record['bytes']+1})
            (root/'link').symlink_to(path)
            with self.assertRaisesRegex(assets.AssetError, 'SIZE_OR_TYPE'):
                assets.verify_object(root/'link', record)

    def test_manifest_rejects_traversal_invalid_hash_and_total_bounds(self):
        for value in ({'../escape': {'bytes': 1, 'sha256': 'a'*64}},
                      {'data': {'bytes': 1, 'sha256': 'bad'}},
                      {'data': {'bytes': True, 'sha256': 'a'*64}},
                      {'data': {'bytes': assets.MAX_FILE+1, 'sha256': 'a'*64}}):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp)/'manifest.json'; path.write_text(json.dumps(value))
                with self.assertRaises(assets.AssetError): assets.files_manifest(path)

    def test_invalid_object_name_never_creates_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); record = {'name': '../escape', 'bytes': 1, 'sha256': 'a'*64}
            with self.assertRaises(assets.AssetError): assets.fetch({}, record, root)
            self.assertEqual(list(root.iterdir()), [])

    def test_dependency_cache_corruption_is_not_repaired(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); cache = root/'cache'; local = root/'local'; cache.mkdir(); local.mkdir()
            (local/'asset').write_bytes(b'good'); record = assets.object_record(local/'asset')
            (cache/'asset').write_bytes(b'evil')
            with self.assertRaisesRegex(assets.AssetError, 'HASH_MISMATCH'):
                assets.fetch({}, record, cache, local)
            self.assertEqual((cache/'asset').read_bytes(), b'evil')

    def test_non_github_or_plaintext_redirect_is_refused(self):
        for url in ('http://github.com/file', 'https://example.com/file'):
            with self.assertRaisesRegex(assets.AssetError, 'REDIRECT_REFUSED'):
                assets.Redirects().redirect_request(None, None, 302, '', {}, url)

    def test_native_host_guard_rejects_wrong_architecture(self):
        gate = self.gate()
        with mock.patch.object(gate.platform, 'system', return_value='Linux'), \
                mock.patch.object(gate.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(gate.GateError, 'UNSUPPORTED'): gate.host_key()

    def test_owned_child_timeout_is_a_failing_gate(self):
        gate = self.gate(); rows = []
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(gate.GateError):
                gate.execute([sys.executable, '-c', 'import time;time.sleep(10)'],
                    'timeout', Path(tmp), {}, rows, timeout=.05)
            self.assertEqual(rows[0]['failure'], 'TIMEOUT')
            self.assertNotEqual(rows[0]['exit_code'], 0)

    def test_output_limit_is_enforced_even_when_child_exits_zero(self):
        gate = self.gate(); rows = []
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(gate, 'MAX_LOG', 64):
            with self.assertRaises(gate.GateError):
                gate.execute([sys.executable, '-c', 'print("x"*1024)'],
                    'overflow', Path(tmp), {}, rows)
            self.assertEqual(rows[0]['failure'], 'OUTPUT_LIMIT')
            self.assertEqual((Path(tmp)/'overflow.log').stat().st_size, 64)

    def test_post_success_validation_exception_cannot_report_a_pass(self):
        gate = self.gate()
        def fail_after_commands(args, report):
            report['passed'] = True
            raise gate.GateError('FINAL_SOURCE_VALIDATION_FAILED')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(sys, 'argv', ['run', '--work', str(root/'work'),
                    '--evidence', str(root/'evidence')]), mock.patch.object(gate, 'run', side_effect=fail_after_commands):
                self.assertEqual(gate.main(), 1)
            result = json.loads((root/'evidence/qualification.json').read_text())
            self.assertFalse(result['passed'])

    def test_external_recovery_scorecard_preserves_checkout(self):
        path = Path(__file__).resolve().parents[2]/'tests/recovery_campaign/run.py'
        spec = importlib.util.spec_from_file_location('recovery_fixture', path)
        recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)
        tracked = path.parents[2]/'.cruft/chaos-results.tsv'
        before = tracked.read_bytes() if tracked.exists() else None
        with tempfile.TemporaryDirectory() as tmp:
            scorecard = Path(tmp)/'evidence/chaos.tsv'
            recovery.tsv_log([{'name': 'synthetic', 'hypothesis': 'external evidence',
                'duration_seconds': .25, 'result': 'PASS'}], scorecard)
            self.assertIn('synthetic', scorecard.read_text())
        self.assertEqual(before, tracked.read_bytes() if tracked.exists() else None)


if __name__ == '__main__': unittest.main()

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
    def test_live_artifact_identity_checks_actual_platform_and_executable(self):
        gate = self.gate()
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary)/'live'
            elf = bytearray(32); elf[:6] = b'\x7fELF\x02\x01'; elf[18:20] = b'\x3e\x00'
            binary.write_bytes(elf); binary.chmod(0o700)
            self.assertEqual(gate.live_binary_identity(binary, 'linux-amd64')['sha256'],
                             assets.digest(binary))
            with self.assertRaisesRegex(gate.GateError, 'ARCHITECTURE_MISMATCH'):
                gate.live_binary_identity(binary, 'macos-arm64')
            mac = bytearray(32); mac[:4] = b'\xcf\xfa\xed\xfe'
            mac[4:8] = (0x0100000c).to_bytes(4, 'little')
            mac[12:16] = (2).to_bytes(4, 'little')
            binary.write_bytes(mac)
            self.assertEqual(gate.live_binary_identity(binary, 'macos-arm64')['platform'],
                             'macos-arm64')
            binary.chmod(0o600)
            with self.assertRaisesRegex(gate.GateError, 'NOT_EXECUTABLE'):
                gate.live_binary_identity(binary, 'macos-arm64')
            link = Path(temporary)/'link'; link.symlink_to(binary)
            with self.assertRaisesRegex(gate.GateError, 'NOT_EXECUTABLE'):
                gate.live_binary_identity(link, 'macos-arm64')

    def gate(self):
        spec = importlib.util.spec_from_file_location('native_gate', Path(__file__).with_name('run.py'))
        gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
        return gate

    def test_coupled_recovery_gate_rejects_memory_missing_peer_and_false_source_guards(self):
        gate = self.gate()
        owner = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location('tcp_controls',
            owner/'tests/encrypted_recovery/test_native_tcp.py')
        fixture_path = str(owner/'tests/encrypted_recovery')
        sys.path.insert(0, fixture_path)
        try:
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            peers = module.NativeTCPControls().matrix()
            summary = module.native_tcp.validate_peers(peers, module.run.STAGES)
            initial = {'passed': True, 'source_unchanged': True, 'compiler_unchanged': True,
                'native_tcp_peers': peers, 'socket_recovery': {'transport': 'native-tcp',
                'coupled_native_tcp_verified': True, 'native_tcp_summary': summary}}
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)/'report.json'; path.write_text(json.dumps(initial))
                self.assertTrue(gate.coupled_recovery_result(path, owner)['passed'])
                for update in ({'source_unchanged': False}, {'compiler_unchanged': False},
                               {'native_tcp_peers': peers[:-1]},
                               {'socket_recovery': {'transport': 'memory'}}):
                    path.write_text(json.dumps({**initial, **update}))
                    with self.assertRaises(gate.GateError): gate.coupled_recovery_result(path, owner)
        finally: sys.path.remove(fixture_path)

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

    def test_linker_selection_is_explicit(self):
        gate = self.gate()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(gate.os.environ, {}, clear=True):
            with self.assertRaisesRegex(gate.GateError, 'EXPLICIT_CLANG_REQUIRED'):
                gate.linker_runtime('linux-amd64', Path(tmp), {}, [])

    def fake_clang(self, root, version):
        directory = root/'tools'; directory.mkdir()
        resource = root/'resource'; (resource/'lib/linux').mkdir(parents=True)
        for name in ('asan', 'tsan'):
            (resource/'lib/linux'/('libclang_rt.'+name+'-x86_64.a')).write_bytes(b'synthetic-runtime')
        driver = directory/'clang'
        driver.write_text('#!'+sys.executable+'\nimport sys\n'
            'print('+repr('clang version '+version)+' if "--version" in sys.argv else '+repr(str(resource))+')\n')
        driver.chmod(0o700)
        return driver

    def test_selected_linker_controls_path_and_records_runtime_bytes(self):
        gate = self.gate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); driver = self.fake_clang(root, '18.1.8')
            env = {'PATH': str(driver.parent)}
            with mock.patch.dict(gate.os.environ, {'OWA_NATIVE_CLANG': str(driver)}):
                value = gate.linker_runtime('linux-amd64', root, env, [])
            self.assertEqual(value['driver']['path'], str(driver.resolve()))
            self.assertTrue(env['PATH'].startswith(str(driver.resolve().parent)))
            for runtime in value['sanitizer_runtimes'].values():
                self.assertEqual(runtime['sha256'], assets.digest(Path(runtime['path'])))

    def test_incompatible_clang_major_fails_before_probe_or_native_tests(self):
        gate = self.gate()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); driver = self.fake_clang(root, '21.0.0'); rows = []
            with mock.patch.dict(gate.os.environ, {'OWA_NATIVE_CLANG': str(driver)}):
                with self.assertRaisesRegex(gate.GateError, 'CLANG_MAJOR_MISMATCH'):
                    gate.linker_runtime('macos-arm64', root, {'PATH': str(driver.parent)}, rows)
            self.assertEqual([row['name'] for row in rows], ['ambient-clang-version', 'selected-clang-version'])

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


    def test_compatibility_ref_must_be_exact_and_result_must_match_checkout(self):
        gate = self.gate()
        with self.assertRaisesRegex(gate.GateError, 'EXACT_COMPATIBILITY_REVISION_REQUIRED'):
            gate.compatibility_argv(Path('/copied'), Path('/repository'), 'HEAD',
                                    Path('/objects'), '/clang', 'address', Path('/report'))
        revision = '1'*40
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'report.json'
            for result in ({'passed': True, 'prior_commit': gate.COMPAT_PRIOR, 'current_commit': '2'*40},
                           {'passed': True, 'prior_commit': '3'*40, 'current_commit': revision},
                           {'passed': False, 'prior_commit': gate.COMPAT_PRIOR, 'current_commit': revision}):
                path.write_text(json.dumps(result))
                with self.assertRaisesRegex(gate.GateError, 'COMPATIBILITY_IDENTITY_OR_RESULT_MISMATCH'):
                    gate.compatibility_result(path, revision)
            path.write_text(json.dumps({'passed': True, 'prior_commit': gate.COMPAT_PRIOR,
                                        'current_commit': revision}))
            self.assertTrue(gate.compatibility_result(path, revision)['passed'])

if __name__ == '__main__': unittest.main()

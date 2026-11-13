"""Offline-only checks: no probe, account, or provider is started."""
import binascii, contextlib, importlib.util, io, json, os, stat, struct, tempfile, unittest, zlib
from pathlib import Path
from unittest import mock
SPEC = importlib.util.spec_from_file_location(
    'qr_display', Path(__file__).with_name('qr_display.py'))
QR = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(QR)

class QRTests(unittest.TestCase):
    def test_terminal_node_context_survives_typed_error_without_raw_strings(self):
        line = (b'ERROR Protocol STORAGE None SOCKET Session_Failed CERTIFICATE None '
                b'SESSION Server_Failure CODE 0 NODE Stream_Error DETAIL Conflict UNKNOWN_CHILDREN 1\n')
        value = QR.native_error(line)
        self.assertIsNotNone(value)
        self.assertEqual(value['server_node'], 'Stream_Error')
        self.assertEqual(value['server_detail'], 'Conflict')
        self.assertEqual(value['server_unknown_children'], 1)

    def test_terminal_ack_detail_is_fixed_and_does_not_accept_raw_metadata(self):
        prefix = (b'ERROR Protocol STORAGE None SOCKET Session_Failed CERTIFICATE None '
                  b'SESSION Server_Failure CODE 0 NODE Stream_Error DETAIL ')
        value = QR.native_error(prefix+b'Ack UNKNOWN_CHILDREN 0\n')
        self.assertEqual(value['server_detail'], 'Ack')
        self.assertEqual(value['server_unknown_children'], 0)
        for suffix in (b'AckPrivate UNKNOWN_CHILDREN 0', b'ack UNKNOWN_CHILDREN 0',
                       b'Ack UNKNOWN_CHILDREN 0 class=status', b'Ack UNKNOWN_CHILDREN 0 id=private'):
            self.assertIsNone(QR.native_error(prefix+suffix+b'\n'))

    def test_terminal_ack_classes_accept_only_fixed_names(self):
        prefix = (b'ERROR Protocol STORAGE None SOCKET Session_Failed CERTIFICATE None '
                  b'SESSION Server_Failure CODE 0 NODE Stream_Error DETAIL ')
        for name in ('Ack_Message', 'Ack_Receipt', 'Ack_Notification', 'Ack_Status',
                     'Ack_Call', 'Ack_Other', 'Ack_Unknown'):
            value = QR.native_error(prefix+name.encode()+b' UNKNOWN_CHILDREN 0\n')
            self.assertIsNotNone(value, name)
            self.assertEqual(value['server_detail'], name)
        for name in ('Ack_private_class', 'Ack_StatusPrivate', 'Ack_status',
                     'Ack_Status class=private', 'Ack_Status id=private'):
            self.assertIsNone(QR.native_error(prefix+name.encode()+b' UNKNOWN_CHILDREN 0\n'))

    def test_terminal_diagnostics_reject_unknown_values_or_unbounded_counts(self):
        prefix = (b'ERROR Protocol STORAGE None SOCKET Session_Failed CERTIFICATE None '
                  b'SESSION Server_Failure CODE 0 ')
        for tail in (b'NODE private_secret DETAIL Conflict UNKNOWN_CHILDREN 0',
                     b'NODE Failure DETAIL private_secret UNKNOWN_CHILDREN 0',
                     b'NODE Stream_Error DETAIL Conflict UNKNOWN_CHILDREN 33',
                     b'NODE Stream_Error DETAIL Conflict UNKNOWN_CHILDREN -1',
                     b'NODE Stream_Error DETAIL Conflict UNKNOWN_CHILDREN 0 private_secret'):
            self.assertIsNone(QR.native_error(prefix+tail+b'\n'))

    def matrix(self, size=21):
        return {'size': size, 'modules': [i % 3 == 0 for i in range(size * size)]}

    def test_exact_pixels_crc_quiet_zone(self):
        value = self.matrix(); png = QR.matrix_png(21, value['modules'])
        self.assertEqual(png[:8], b'\x89PNG\r\n\x1a\n')
        at, compressed, header = 8, b'', None
        while at < len(png):
            count = struct.unpack_from('>I', png, at)[0]
            kind, data = png[at+4:at+8], png[at+8:at+8+count]
            checksum = struct.unpack_from('>I', png, at+8+count)[0]
            self.assertEqual(checksum, binascii.crc32(kind+data) & 0xffffffff)
            if kind == b'IHDR': header = struct.unpack('>IIBBBBB', data)
            if kind == b'IDAT': compressed += data
            at += count + 12
        width = 29 * 8; self.assertEqual(header, (width, width, 8, 0, 0, 0, 0))
        rows = zlib.decompress(compressed)
        self.assertEqual(len(rows), width * (width + 1))
        for y in range(width):
            self.assertEqual(rows[y*(width+1)], 0)
            for x in range(width):
                mx, my = x//8-4, y//8-4
                dark = 0 <= mx < 21 and 0 <= my < 21 and value['modules'][my*21+mx]
                self.assertEqual(rows[y*(width+1)+1+x], 0 if dark else 255)

    def test_matrix_validation(self):
        bad = [{'size': True, 'modules': []}, self.matrix(20), self.matrix(22),
               self.matrix(181), {'size': 21, 'modules': [0]*441},
               {'size': 21, 'modules': [True]*440}, {**self.matrix(), 'token': 'secret'}]
        for item in bad:
            with self.assertRaises(QR.DisplayError): QR.matrix_decode(json.dumps(item).encode())
        for data in [b'{"size":21,"size":21,"modules":[]}', b'x'*(QR.QR_JSON_MAX+1)]:
            with self.assertRaises(QR.DisplayError): QR.matrix_decode(data)
        self.assertEqual(QR.matrix_decode(json.dumps(self.matrix(177)).encode())[0], 177)

    def test_private_atomic_output_and_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); os.chmod(directory, 0o700)
            source = directory/'qr.json'; source.write_text(json.dumps(self.matrix()))
            os.chmod(source, 0o600); QR.render_private(directory)
            output = directory/'qr.png'
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(output.read_bytes(), QR.matrix_png(21, self.matrix()['modules']))
            self.assertFalse(list(directory.glob('.qr.png.*')))
            os.chmod(source, 0o644)
            with self.assertRaises(QR.DisplayError): QR.render_private(directory)
            source.unlink(); source.symlink_to(output)
            with self.assertRaises(QR.DisplayError): QR.render_private(directory)
            source.unlink(); os.mkfifo(source, 0o600)
            with self.assertRaises(QR.DisplayError): QR.render_private(directory)
            source.unlink(); os.chmod(directory, 0o755)
            with self.assertRaises(QR.DisplayError): QR.render_private(directory)

    def test_no_implicit_live_or_overridden_auth_and_no_token_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp)/'probe'; binary.write_text('not executable')
            args = ['--auth-dir', tmp, '--binary', str(binary), 'pair']
            out = io.StringIO()
            with mock.patch.object(QR.subprocess, 'Popen') as start:
                with contextlib.redirect_stdout(out): self.assertEqual(QR.main(args), 2)
                start.assert_not_called()
            self.assertEqual(json.loads(out.getvalue())['reason'], 'LIVE_OPT_IN_REQUIRED')
            with self.assertRaises(QR.DisplayError):
                QR.arguments(['--live', *args, '--', '--auth-dir', '/other'])
        for line in [b'PHASE raw-qr-secret\n', b'raw-qr-secret\n', b'QR_READY /elsewhere\n']:
            with self.assertRaises(QR.DisplayError): QR.native_phase(line)
        self.assertEqual(QR.native_phase(b'QR_READY qr.json\n'), 'QR_READY')
        self.assertEqual(QR.native_phase(b'PHASE ONLINE\n'), 'ONLINE')

    def test_typed_stderr_is_bounded_and_unmatched_material_is_never_echoed(self):
        valid = b'ERROR Storage STORAGE Locked SOCKET None CERTIFICATE None\n'
        self.assertEqual(QR.native_error(valid), {'error': 'Storage', 'storage': 'Locked',
                         'socket': 'None', 'certificate': 'None'})
        for line in [b'raw-qr-secret\n', valid[:-1] + b' raw-qr-secret\n',
                     b'ERROR Token/secret STORAGE None SOCKET None CERTIFICATE None\n']:
            self.assertIsNone(QR.native_error(line))
        state = {'last': None}
        payload = b'raw-qr-secret\n' + valid + b'x' * 10000 + valid
        out = io.StringIO()
        with contextlib.redirect_stdout(out): QR.drain_diagnostics(io.BytesIO(payload), state)
        self.assertEqual(state['last']['storage'], 'Locked')
        self.assertNotIn('raw-qr-secret', out.getvalue())
        self.assertLess(len(repr(state)), 512)

    def test_extended_typed_diagnostic_has_bounded_session_and_numeric_code(self):
        prefix = b'ERROR Protocol STORAGE None SOCKET Session_Failed CERTIFICATE None'
        for code in (0, 515, 65535):
            line = prefix + b' SESSION QR_Expired CODE ' + str(code).encode() + b'\n'
            parsed = QR.native_error(line)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed['session'], 'QR_Expired')
            self.assertEqual(parsed['server_code'], code)
        for suffix in (b' SESSION QR_Expired', b' SESSION QR_Expired CODE -1',
                       b' SESSION QR_Expired CODE 65536', b' SESSION QR_Expired CODE 999999',
                       b' SESSION QR_Expired CODE 1.5', b' SESSION QR_Expired CODE 1 secret',
                       b' SESSION raw/token CODE 1', b' SESSION ' + b'x' * 65 + b' CODE 1',
                       b' SESSION QR_Expired CODE \xff'):
            self.assertIsNone(QR.native_error(prefix + suffix + b'\n'))
        state = {'last': None}
        valid = prefix + b' SESSION Stream_Error CODE 515\n'
        QR.drain_diagnostics(io.BytesIO(b'raw-qr-secret\n' + valid), state)
        self.assertEqual(state['last']['server_code'], 515)
        self.assertNotIn('raw-qr-secret', repr(state))

    def test_safe_typed_failure_reaches_structured_output(self):
        child = mock.Mock()
        child.stdout = io.BytesIO(b'PHASE STORAGE_READY\n')
        child.stderr = io.BytesIO(b'raw-qr-secret\nERROR Storage STORAGE Locked '
                                b'SOCKET None CERTIFICATE None\n')
        child.wait.return_value = 1; child.poll.return_value = 1
        args = mock.Mock(binary=Path('/fake'), command='pair', auth_dir=Path('/private'))
        out = io.StringIO()
        with mock.patch.object(QR, 'arguments', return_value=(args, [])):
            with mock.patch.object(QR.subprocess, 'Popen', return_value=child):
                with contextlib.redirect_stdout(out): self.assertEqual(QR.main([]), 2)
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(rows[-1], {'phase': 'FAILED', 'reason': 'PROBE_FAILED',
                         'error': 'Storage', 'storage': 'Locked',
                         'socket': 'None', 'certificate': 'None'})
        self.assertNotIn('raw-qr-secret', out.getvalue())

    def test_extended_failure_reaches_output_without_unmatched_stderr(self):
        child = mock.Mock()
        child.stdout = io.BytesIO(b'PHASE CONNECTING\n')
        child.stderr = io.BytesIO(b'private-token-must-not-escape\nERROR Protocol '
            b'STORAGE None SOCKET Session_Failed CERTIFICATE None '
            b'SESSION Stream_Error CODE 515\n')
        child.wait.return_value = 1; child.poll.return_value = 1
        args = mock.Mock(binary=Path('/fake'), command='pair', auth_dir=Path('/private'))
        out = io.StringIO()
        with mock.patch.object(QR, 'arguments', return_value=(args, [])):
            with mock.patch.object(QR.subprocess, 'Popen', return_value=child):
                with contextlib.redirect_stdout(out): self.assertEqual(QR.main([]), 2)
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(rows[-1], {'phase': 'FAILED', 'reason': 'PROBE_FAILED',
            'error': 'Protocol', 'storage': 'None', 'socket': 'Session_Failed',
            'certificate': 'None', 'session': 'Stream_Error', 'server_code': 515})
        self.assertNotIn('private-token-must-not-escape', out.getvalue())

    def test_hold_phase_and_arguments_are_forwarded_without_implicit_action(self):
        self.assertEqual(QR.native_phase(b'PHASE CONNECTED_HOLD\n'), 'CONNECTED_HOLD')
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp)/'probe'; binary.write_text('not executable')
            args, native = QR.arguments(['--live', '--auth-dir', tmp, '--binary',
                str(binary), 'inspect', '--', '--group-subject', 'offline',
                '--hold-seconds', '300'])
            self.assertEqual(args.command, 'inspect')
            self.assertEqual(native[-2:], ['--hold-seconds', '300'])
            self.assertNotIn('--send', native)

    def test_group_counts_are_bounded_numeric_and_never_include_private_fields(self):
        expected = {'total': 3, 'empty_subjects': 1, 'exact_matches': 1}
        self.assertEqual(QR.native_group_counts(
            b'GROUP_COUNTS total=3 empty_subjects=1 exact_matches=1\n'), expected)
        self.assertEqual(QR.native_group_counts(
            b'GROUP_COUNTS total=0 empty_subjects=0 exact_matches=0\n')['total'], 0)
        for line in [b'GROUP_COUNTS total=10001 empty_subjects=0 exact_matches=0\n',
                     b'GROUP_COUNTS total=1 empty_subjects=2 exact_matches=0\n',
                     b'GROUP_COUNTS total=1 empty_subjects=1 exact_matches=1\n',
                     b'GROUP_COUNTS total=-1 empty_subjects=0 exact_matches=0\n',
                     b'GROUP_COUNTS total=1 empty_subjects=0 exact_matches=0 name=secret\n',
                     b'GROUP_COUNTS total=1 empty_subjects=0 exact_matches=0',
                     b'GROUP_COUNTS total=1 empty_subjects=0 exact_matches=\xff\n']:
            self.assertIsNone(QR.native_group_counts(line))

    def test_hold_and_count_output_is_structured_through_launcher(self):
        child = mock.Mock()
        child.stdout = io.BytesIO(b'PHASE CONNECTED_HOLD\nGROUP_COUNTS total=3 '
                                 b'empty_subjects=1 exact_matches=0\nPHASE COMPLETE\n')
        child.stderr = io.BytesIO(b'')
        child.wait.return_value = 0; child.poll.return_value = 0
        args = mock.Mock(binary=Path('/fake'), command='inspect', auth_dir=Path('/private'))
        out = io.StringIO()
        with mock.patch.object(QR.subprocess, 'Popen', return_value=child) as start:
            with contextlib.redirect_stdout(out):
                self.assertEqual(QR.launch(args, ['--hold-seconds', '60']), 0)
        self.assertEqual(start.call_args.args[0][-2:], ['--hold-seconds', '60'])
        self.assertEqual([json.loads(line) for line in out.getvalue().splitlines()],
            [{'phase': 'CONNECTED_HOLD'}, {'phase': 'GROUP_COUNTS', 'total': 3,
              'empty_subjects': 1, 'exact_matches': 0}, {'phase': 'COMPLETE'}])

    def test_watch_version_canary_metadata_and_phases_are_strictly_typed(self):
        self.assertEqual(QR.native_watch_metadata(
            b'WATCH_VERSION major=2 minor=3000 patch=4294967295\n'),
            {'phase':'WATCH_VERSION','major':2,'minor':3000,'patch':4294967295})
        line=(b'CANARY_STATUS completed_cycles=3 durable_completed_cycles=10 '
              b'first_ack_unix_seconds=100 last_ack_unix_seconds=200\n')
        self.assertEqual(QR.native_watch_metadata(line)['durable_completed_cycles'],10)
        for phase in ('CANARY_PREPARED','CANARY_TEXT_ACKED','CANARY_PDF_ACKED',
                      'CANARY_COMPLETE','CANARY_UNKNOWN','WATCH_COMPLETE'):
            self.assertEqual(QR.native_phase(('PHASE '+phase+'\n').encode()),phase)
        for invalid in (b'WATCH_VERSION major=4294967296 minor=0 patch=0\n',
                        line.replace(b'cycles=3 ',b'cycles=49 '),
                        line.replace(b'cycles=10 ',b'cycles=2 '),
                        line.replace(b'seconds=100 ',b'seconds=201 '),
                        line[:-1]+b' private-token\n',
                        b'CANARY_STATUS completed_cycles=1\n'):
            self.assertIsNone(QR.native_watch_metadata(invalid))

if __name__ == '__main__': unittest.main()

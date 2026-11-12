"""Offline-only checks: no probe, account, or provider is started."""
import binascii, contextlib, importlib.util, io, json, os, stat, struct, tempfile, unittest, zlib
from pathlib import Path
from unittest import mock
SPEC = importlib.util.spec_from_file_location('qr_display', Path(__file__).with_name('qr_display.py'))
QR = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(QR)

class QRTests(unittest.TestCase):
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

if __name__ == '__main__': unittest.main()

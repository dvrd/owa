#!/usr/bin/env python3
"""Owned localhost HTTP request contract; never contacts WhatsApp or loads a session."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading

HERE = Path(__file__).resolve().parent
USER_AGENT = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36')
BODY = b'self.cfg={"client_revision":1234567890};'


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.server.observed = {
            'method': self.command, 'path': self.path,
            'user_agent': self.headers.get_all('User-Agent', []),
            'sec_fetch_site': self.headers.get_all('Sec-Fetch-Site', []),
        }
        expected = {'method': 'GET', 'path': '/sw.js',
                    'user_agent': [USER_AGENT], 'sec_fetch_site': ['none']}
        self.server.errors.extend(key for key in expected
                                  if self.server.observed[key] != expected[key])
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript')
        self.send_header('Content-Length', str(len(BODY)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(BODY)
        self.close_connection = True

    def log_message(self, *_):
        pass


class Peer(HTTPServer):
    allow_reuse_address = False
    request_queue_size = 1

    def __init__(self, *args):
        self.active_lock = threading.Lock()
        self.active, self.closing = None, False
        super().__init__(*args)

    def get_request(self):
        peer, address = super().get_request()
        with self.active_lock:
            if self.closing:
                peer.close()
                raise OSError("OWNED_PEER_CLOSED")
            peer.settimeout(2)
            self.active = peer
        return peer, address

    def handle_error(self, *_):
        if not self.closing:
            self.errors.append('HTTP_HANDLER_FAILED')

    def one_request(self):
        try:
            self.handle_request()
        except (OSError, ValueError):
            if not self.closing:
                self.errors.append('HTTP_REQUEST_FAILED')

    def close_owned(self):
        with self.active_lock:
            self.closing = True
            if self.active is not None:
                try:
                    self.active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # Close below also retires an already-closed peer.
                self.active.close()
        self.server_close()


def capture(argv, seconds):
    child = subprocess.Popen(list(map(str, argv)), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    try:
        try:
            out, err = child.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            out, err = child.communicate(timeout=3)
            raise RuntimeError('OWNED_CHILD_TIMEOUT') from None
        return {'command': list(map(str, argv)), 'returncode': child.returncode,
                'stdout': out.decode('utf-8', 'replace'),
                'stderr': err.decode('utf-8', 'replace'), 'reaped': True}
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=3)
        child.stdout.close()
        child.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', type=Path, required=True)
    parser.add_argument('--shared-root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--sanitize', choices=('address', 'thread'), default='address')
    parser.add_argument('--legacy-decoder', action='store_true',
                        help='Old-runtime RED only: its decoder API does not exist yet')
    args = parser.parse_args()
    report = {'passed': False, 'legacy_decoder': args.legacy_decoder,
              'sanitizer': args.sanitize,
              'scope': 'Synthetic one-request localhost HTTP only',
              'compiler_sha256': hashlib.sha256(args.odin.read_bytes()).hexdigest(),
              'runtime_pairing_sha256': hashlib.sha256(
                  (args.shared_root/'whatsapp/pairing.odin').read_bytes()).hexdigest()}
    try:
        with tempfile.TemporaryDirectory(prefix='owa-version-http-') as tmp:
            binary = Path(tmp)/'client'
            command = [args.odin, 'build', HERE, '-thread-count:1', '-vet',
                       '-warnings-as-errors', '-sanitize:'+args.sanitize,
                       '-collection:shared='+str(args.shared_root), '-out:'+str(binary)]
            if args.legacy_decoder:
                command.append('-define:VERSION_HTTP_LEGACY=true')
            report['build'] = capture(command, 120)
            assert report['build']['returncode'] == 0, 'BUILD_FAILED'
            peer = Peer(('127.0.0.1', 0), Handler)
            peer.timeout = 3
            peer.errors, peer.observed = [], None
            worker = threading.Thread(target=peer.one_request, name='owned-version-http')
            try:
                worker.start()
                report['client'] = capture([binary, str(peer.server_port)], 8)
            finally:
                peer.close_owned()
                if worker.ident is not None:
                    worker.join(timeout=4)
                report['peer_joined'] = not worker.is_alive()
                report['listener_closed'] = peer.socket.fileno() == -1
            report['request'], report['peer_errors'] = peer.observed, peer.errors
            assert report['peer_joined'] and report['listener_closed'], 'CLEANUP_FAILED'
            assert report['client']['returncode'] == 0, 'CLIENT_FAILED'
            assert 'OWA_VERSION_HTTP_RESPONSE_PASS' in report['client']['stdout']
            assert report['request'] is not None and not peer.errors, 'REQUEST_HEADERS_MISMATCH'
            report['passed'] = True
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        report['failure'] = str(error)
    finally:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({key: report[key] for key in ('passed', 'scope')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Negative owner/evidence controls; fake peer children never bind a socket."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import native_tcp
import run


class NativeTCPControls(unittest.TestCase):
    def fake_peer(self, directory, body):
        binary = directory/'peer'
        binary.write_text('#!'+sys.executable+'\n'+body+'\n')
        binary.chmod(0o700)
        return binary

    def test_bad_ready_deadline_and_premature_ack_reap_only_owned_child(self):
        cases = [('print("WRONG",flush=True)\nimport time;time.sleep(20)', 'READY_INVALID'),
                 ('import time;time.sleep(20)', 'DEADLINE'),
                 ('print("ENCRYPTED_TCP_PEER_READY port=12345",flush=True)\n'
                  'print("ENCRYPTED_TCP_ACK_SENT bytes=40",flush=True)\n'
                  'import time;time.sleep(20)', 'HANDOFF_INVALID')]
        for body, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); children = []
                binary = self.fake_peer(directory, body)
                original = native_tcp.subprocess.Popen
                def launch(*args, **kwargs):
                    child = original(*args, **kwargs); children.append(child); return child
                with mock.patch.object(native_tcp.subprocess, 'Popen', side_effect=launch):
                    with self.assertRaisesRegex(native_tcp.TCPError, reason):
                        with native_tcp.Peer(binary, directory, 'socket-after-positive-ack',
                                             False, os.environ.copy(), timeout=.3) as peer:
                            peer.before_kill()
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())

    def matrix(self):
        peers = []
        for stage in run.STAGES:
            if not stage.startswith('socket-'): continue
            for replay in (False, True):
                received = stage in ('socket-after-commit-before-write',
                    'socket-after-wire-before-return', 'socket-after-send-before-ack') if replay else stage not in (
                    'socket-before-send', 'socket-after-commit-before-write')
                ack = not replay and stage in ('socket-after-positive-ack', 'socket-after-ack-journal')
                row = {'stage': stage, 'replay': replay, 'transport': 'native_tcp_127.0.0.1',
                       'received': received, 'ack_sent': ack, 'exit_code': 0,
                       'owned_child_reaped': True, 'native_socket_closed': True}
                if received: row.update(authenticated=True, frame_sha256='a'*64, frame_bytes=400)
                if ack: row['ack_bytes'] = 40
                peers.append(row)
        return peers

    def test_coupled_evidence_requires_each_exact_stage_and_actual_handoff_ack_cleanup(self):
        original = self.matrix()
        self.assertEqual(native_tcp.validate_peers(original, run.STAGES),
            {'connections': 12, 'authenticated_frames': 7, 'peer_acks_sent': 2,
             'owned_peers_reaped': True, 'native_sockets_closed': True})
        for update in ({'transport': 'callback'}, {'authenticated': False},
                       {'frame_sha256': 'untrusted'}, {'frame_bytes': 0},
                       {'owned_child_reaped': False}, {'native_socket_closed': False}, {'exit_code': -9}, {'ack_bytes': 0}):
            value = copy.deepcopy(original)
            index = next(i for i, p in enumerate(value) if p['ack_sent'])
            value[index].update(update)
            with self.assertRaises(native_tcp.TCPError): native_tcp.validate_peers(value, run.STAGES)
        for value in (original[:-1], [original[0], *original[:-1]]):
            with self.assertRaises(native_tcp.TCPError): native_tcp.validate_peers(value, run.STAGES)

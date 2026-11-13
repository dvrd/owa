"""Owned native loopback peers for the coupled prepared-Socket crash campaign."""
import hashlib
import os
import re
import selectors
import signal
import subprocess
import time


class TCPError(Exception): pass


class Peer:
    def __init__(self, binary, directory, stage, replay, env, timeout=25):
        if not 0 < timeout <= 25: raise TCPError("PEER_BUDGET_INVALID")
        self.directory, self.stage, self.replay = directory, stage, replay
        self.received = stage in ('socket-after-commit-before-write',
            'socket-after-wire-before-return', 'socket-after-send-before-ack') if replay else stage not in (
            'socket-before-send', 'socket-after-commit-before-write')
        self.ack = not replay and stage in ('socket-after-positive-ack', 'socket-after-ack-journal')
        self.buffer = bytearray(); self.rows = []; self.handoff = False
        self.receipt = {'transport': 'native_tcp_127.0.0.1', 'stage': stage,
                        'replay': replay, 'received': False, 'ack_sent': False}
        self.deadline = time.monotonic()+timeout
        self.child = subprocess.Popen([str(binary), 'tcp-peer', str(directory),
            ('replay:' if replay else 'stage:')+stage], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.child.stdout, selectors.EVENT_READ, 'stdout')
        self.selector.register(self.child.stderr, selectors.EVENT_READ, 'stderr')
        try:
            line = self.line()
            found = re.fullmatch(rb'ENCRYPTED_TCP_PEER_READY port=([0-9]{1,5})\n', line)
            if found is None or not 0 < int(found[1]) < 65536: raise TCPError('PEER_READY_INVALID')
            self.port = int(found[1])
        except BaseException:
            self.close(); raise

    def line(self):
        while b'\n' not in self.buffer:
            remaining = self.deadline-time.monotonic()
            if remaining <= 0: raise TCPError('PEER_DEADLINE')
            events = self.selector.select(min(remaining, 1))
            if not events and self.child.poll() is not None: raise TCPError('PEER_EARLY_EXIT')
            for key, _ in events:
                data = os.read(key.fd, 512)
                if not data:
                    self.selector.unregister(key.fileobj)
                    if key.data == 'stdout': raise TCPError('PEER_OUTPUT_TRUNCATED')
                elif key.data == 'stderr': raise TCPError('PEER_STDERR')
                else: self.buffer.extend(data)
                if len(self.buffer) > 4096: raise TCPError('PEER_OUTPUT_LIMIT')
        line, _, rest = self.buffer.partition(b'\n'); self.buffer[:] = rest
        if len(line) > 255: raise TCPError('PEER_LINE_LIMIT')
        self.rows.append((line+b'\n').decode('ascii'))
        return line+b'\n'

    def before_kill(self):
        if not self.received or self.handoff: return
        found = re.fullmatch(rb'ENCRYPTED_TCP_HANDOFF hash=([0-9a-f]{64}) bytes=([0-9]{1,4}) '
            rb'authenticated=true replay=(true|false)\n', self.line())
        path = self.directory/('replay.bin' if self.replay else 'transport.bin')
        if found is None or found[3] != str(self.replay).lower().encode() or \
                not 0 < int(found[2]) <= 8192 or not path.is_file() or \
                path.stat().st_size != int(found[2]) or \
                hashlib.sha256(path.read_bytes()).hexdigest().encode() != found[1]:
            raise TCPError('PEER_HANDOFF_INVALID')
        self.receipt.update(received=True, authenticated=True,
            frame_sha256=found[1].decode(), frame_bytes=int(found[2]))
        if self.ack:
            sent = re.fullmatch(rb'ENCRYPTED_TCP_ACK_SENT bytes=([0-9]{1,4})\n', self.line())
            if sent is None or not 0 < int(sent[1]) <= 2048: raise TCPError('PEER_ACK_INVALID')
            self.receipt.update(ack_sent=True, ack_bytes=int(sent[1]))
        self.handoff = True

    def finish(self):
        self.before_kill()
        expected = ('ENCRYPTED_TCP_PEER_DONE received='+str(self.received).lower()+
                    ' ack='+str(self.ack).lower()+' replay='+str(self.replay).lower()+' closed=true\n').encode()
        if self.line() != expected: raise TCPError('PEER_COMPLETION_INVALID')
        output, error = self.child.communicate(timeout=5)
        if self.child.returncode != 0 or output or error or self.buffer:
            raise TCPError('PEER_NOT_CLEANLY_REAPED')
        self.receipt.update(exit_code=0, owned_child_reaped=True, native_socket_closed=True, output=self.rows)
        return self.receipt

    def close(self):
        self.selector.close()
        if self.child.poll() is None:
            try: os.killpg(self.child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        try: self.child.communicate(timeout=5)
        finally:
            self.child.stdout.close(); self.child.stderr.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def validate_peers(peers, stages):
    expected = {(stage, replay) for stage in stages if stage.startswith('socket-')
                for replay in (False, True)}
    actual = {(p.get('stage'), p.get('replay')) for p in peers}
    if len(peers) != len(expected) or actual != expected:
        raise TCPError('PEER_STAGE_COVERAGE_INVALID')
    for peer in peers:
        stage, replay = peer['stage'], peer['replay']
        received = stage in ('socket-after-commit-before-write',
            'socket-after-wire-before-return', 'socket-after-send-before-ack') if replay else stage not in (
            'socket-before-send', 'socket-after-commit-before-write')
        ack = not replay and stage in ('socket-after-positive-ack', 'socket-after-ack-journal')
        if peer.get('transport') != 'native_tcp_127.0.0.1' or peer.get('received') is not received or \
                peer.get('ack_sent') is not ack or peer.get('owned_child_reaped') is not True or \
                peer.get('native_socket_closed') is not True or peer.get('exit_code') != 0:
            raise TCPError('PEER_TRANSPORT_OR_CLEANUP_INVALID')
        if received and (peer.get('authenticated') is not True or
                not re.fullmatch('[0-9a-f]{64}', peer.get('frame_sha256', '')) or
                not 0 < peer.get('frame_bytes', 0) <= 8192):
            raise TCPError('PEER_AUTHENTICATED_HANDOFF_REQUIRED')
        if ack and not 0 < peer.get('ack_bytes', 0) <= 2048:
            raise TCPError('PEER_ACK_EVIDENCE_REQUIRED')
    return {'connections': len(peers), 'authenticated_frames': sum(p['received'] for p in peers),
            'peer_acks_sent': sum(p['ack_sent'] for p in peers), 'owned_peers_reaped': True,
            'native_sockets_closed': True}

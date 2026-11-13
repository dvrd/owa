#!/usr/bin/env python3
"""Owned offline Signal/persistence campaign; no account, provider or network input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
SHARED = HERE.parents[2]
OWNER = b'OWA-ENCRYPTED-RECOVERY-V1'
STAGES = ('receiver-before-commit', 'receiver-after-commit', 'sender-before-commit',
          'sender-after-commit', 'receiver-after-message-commit',
          'socket-before-send', 'socket-after-commit-before-write', 'socket-after-wire-before-return',
          'socket-after-send-before-ack', 'socket-after-positive-ack', 'socket-after-ack-journal')
MAX_OUTPUT = 1 << 20


class CampaignError(Exception): pass


def digest(path):
    with Path(path).open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def capture(argv, env, timeout=120, limit=False):
    def restrict():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (512, 512))
    child = subprocess.Popen(list(map(str, argv)), env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        preexec_fn=restrict if limit else None)
    deadline = time.monotonic()+timeout; output = bytearray(); errors = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ, output)
    selector.register(child.stderr, selectors.EVENT_READ, errors)
    try:
        while selector.get_map():
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise CampaignError('CHILD_TIMEOUT')
            for key, _ in selector.select(min(remaining, 1)):
                data = os.read(key.fd, 65536)
                if not data: selector.unregister(key.fileobj); continue
                key.data.extend(data)
                if len(output)+len(errors) > MAX_OUTPUT: raise CampaignError('CHILD_OUTPUT_LIMIT')
        code = child.wait(timeout=max(.01, deadline-time.monotonic()))
        return {'exit_code': code, 'stdout': output.decode('utf-8', 'replace'),
                'stderr': errors.decode('utf-8', 'replace')}
    finally:
        selector.close()
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
        child.stdout.close(); child.stderr.close()


def execute(argv, env, records, timeout=120, limit=False):
    started = time.monotonic(); result = capture(argv, env, timeout, limit)
    row = {'command': list(map(str, argv)), **result, 'seconds': time.monotonic()-started}
    records.append(row)
    if result['exit_code'] or 'ERROR: AddressSanitizer' in result['stderr'] or \
            'WARNING: ThreadSanitizer' in result['stderr']:
        raise CampaignError('CHILD_FAILED')
    return result


def scope(directory):
    if directory.is_symlink() or directory.parent.resolve() != Path('/tmp').resolve() or \
            not directory.name.startswith('wa-encrypted-'):
        raise CampaignError('DISPOSABLE_SCOPE_REQUIRED')
    (directory/'owner').write_bytes(OWNER); (directory/'owner').chmod(0o600)


def crash(binary, directory, stage, env, records):
    child = subprocess.Popen([str(binary), 'stage', str(directory), stage], env=env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic()+15; ready = bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while not ready.endswith(b'\n'):
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not selector.select(remaining): raise CampaignError('BOUNDARY_TIMEOUT')
                block = os.read(child.stdout.fileno(), 256-len(ready))
                if not block or len(ready)+len(block) >= 256: raise CampaignError('BOUNDARY_FAILED')
                ready.extend(block)
        if ready != ('ENCRYPTED_BOUNDARY_READY '+stage+'\n').encode() or child.poll() is not None:
            raise CampaignError('BOUNDARY_MISMATCH')
        # Only the actual unreaped child object is killed; no PID discovery.
        child.kill(); stdout, stderr = child.communicate(timeout=5)
        if child.returncode != -signal.SIGKILL or stdout or stderr:
            raise CampaignError('OWNED_KILL_NOT_CONFIRMED')
        records.append({'stage': stage, 'owned_child': True, 'exit_code': child.returncode,
                        'killed_signal': 'SIGKILL', 'seconds': 15-(deadline-time.monotonic())})
    finally:
        if child.poll() is None: child.kill()
        child.communicate(timeout=5)


def campaign(binary, env, report):
    for stage in STAGES:
        with tempfile.TemporaryDirectory(prefix='wa-encrypted-', dir='/tmp') as temporary:
            directory = Path(temporary); scope(directory)
            crash(binary, directory, stage, env, report['crashes'])
            before = digest(directory/'state.bin')
            prekey_before = digest(directory/'prekeys.bin') if (directory/'prekeys.bin').exists() else None
            result = execute([binary, 'verify', directory, stage], env, report['commands'], 20)
            marker = 'ENCRYPTED_SOCKET_REOPEN_PASS' if stage.startswith('socket-') else 'ENCRYPTED_REOPEN_PASS'
            if marker not in result['stdout'] or digest(directory/'state.bin') != before:
                raise CampaignError('REOPEN_DURABILITY_FAILED')
            if prekey_before is not None and digest(directory/'prekeys.bin') != prekey_before:
                raise CampaignError('SOCKET_PREKEY_FILE_CHANGED')
    report['socket_recovery'] = {'owned_crash_boundaries': 6,
        'production_prepared_send_and_encrypted_ack': True,
        'exact_handoff_hashes_match_ratchet_key_membership_content_prekey': True,
        'real_pairwise_distribution_and_group_payload_decrypted': True,
        'pending_replay_preserves_exact_ciphertext_and_store': True,
        'ack_without_application_journal_remains_unknown_without_resend': True,
        'prekey_file_and_consumed_marker_remain_consistent': True,
        'synthetic_metadata_and_transport_peer': True, 'recipient_delivery': False}
    with tempfile.TemporaryDirectory(prefix='wa-encrypted-', dir='/tmp') as temporary:
        directory = Path(temporary); scope(directory)
        execute([binary, 'prepare', directory, 'control'], env, report['commands'], 20)
        before = digest(directory/'state.bin'); parent_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        result = execute([binary, 'limited-write', directory, 'file-limit'], env, report['commands'], 20, True)
        if 'errno=EFBIG' not in result['stdout'] or digest(directory/'state.bin') != before or \
                parent_limit != resource.getrlimit(resource.RLIMIT_FSIZE) or list(directory.glob('state.bin.tmp-*')):
            raise CampaignError('FILE_LIMIT_CONTAINMENT_FAILED')
        execute([binary, 'verify', directory, 'file-limit'], env, report['commands'], 20)
        report['file_limit'] = {'observed_errno': 'EFBIG', 'parent_unchanged': True,
                                'old_file_byte_identical': True, 'temporary_files_retired': True}
        data = (directory/'state.bin').read_bytes()
        for kind, body in [('corrupt', data[:-1]+bytes([data[-1]^1])), ('truncated', data[:len(data)//2])]:
            target = directory/(kind+'.bin'); target.write_bytes(body); target.chmod(0o600)
            execute([binary, 'corrupt-load', directory, kind], env, report['commands'], 20)
            if digest(directory/'state.bin') != before: raise CampaignError('GOOD_STORE_CHANGED')
        report['corruption'] = {'checksum_damage_rejected': True, 'truncation_rejected': True,
                                 'old_sessions_still_encrypt_and_decrypt': True}
        path = directory
    report['owned_fixture_removed'] = not path.exists()


def source_snapshot(shared, compiler_root):
    files = list(HERE.rglob('*.odin'))+list(HERE.glob('*.py'))+list(HERE.glob('README.md'))
    for root in ('whatsapp', 'ascii', 'async', 'http', 'surf', 'websocket'):
        files += list((shared/root).rglob('*.odin'))
    for root in ('base', 'core', 'vendor/zlib'):
        files += list((compiler_root/root).rglob('*.odin'))
    return {str(p): digest(p) for p in sorted(set(files)) if p.is_file() and '.git' not in p.parts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', type=Path, required=True)
    parser.add_argument('--shared-root', type=Path, default=SHARED)
    parser.add_argument('--sanitize', choices=('address', 'thread'), required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL',
            'DYLD_LIBRARY_PATH', 'LD_LIBRARY_PATH') if key in os.environ}
    env.update(PYTHONDONTWRITEBYTECODE='1', AWS_EC2_METADATA_DISABLED='true')
    args.odin = args.odin.resolve(); args.shared_root = args.shared_root.resolve()
    compiler_root = Path(capture([args.odin, 'root'], env)['stdout'].strip()).resolve()
    env['ODIN_ROOT'] = str(compiler_root)
    before = source_snapshot(args.shared_root, compiler_root)
    report = {'schema': 1, 'passed': False, 'candidate_release_gate': False, 'commands': [], 'crashes': [],
        'scope': 'Real Signal/prekeys/StateStore plus production prepared Socket group send, transport handoff and encrypted positive ACK; synthetic peer and supplied metadata, no live accounts/discovery/full handshake/upgrade/ENOSPC/power-loss proof',
        'sanitizer': args.sanitize, 'compiler_sha256': digest(args.odin),
        'compiler_root': str(compiler_root), 'compiler_version': capture([args.odin, 'version'], env)['stdout'].strip(),
        'clang_version': capture([shutil.which('clang', path=env['PATH']), '--version'], env)['stdout'].strip(),
        'source_before': before}
    try:
        with tempfile.TemporaryDirectory(prefix='owa-encrypted-build-') as tmp:
            binary = Path(tmp)/'campaign'; unit = Path(tmp)/'unit'
            flags = ['-collection:shared='+str(args.shared_root), '-vet', '-warnings-as-errors',
                     '-thread-count:1', '-sanitize:'+args.sanitize]
            execute([args.odin, 'test', HERE, *flags, '-define:ODIN_TEST_THREADS=1',
                     '-define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true', '-out:'+str(unit)], env, report['commands'])
            execute([args.odin, 'build', HERE, *flags, '-out:'+str(binary)], env, report['commands'])
            report['binary_sha256'] = digest(binary)
            campaign(binary, env, report)
        report['passed'] = True
    except (CampaignError, OSError, ValueError, subprocess.SubprocessError) as error:
        report['failure'] = type(error).__name__+': '+str(error)[:300]
    finally:
        report['source_after'] = source_snapshot(args.shared_root, compiler_root)
        report['source_unchanged'] = before == report['source_after']
        report['compiler_unchanged'] = report['compiler_sha256'] == digest(args.odin)
        report['passed'] = report['passed'] and report['source_unchanged'] and report['compiler_unchanged']
        report['candidate_release_gate'] = report['passed']
        args.report.write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
    print(json.dumps({'passed': report['passed'], 'sanitizer': args.sanitize, 'failure': report.get('failure')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__': sys.exit(main())

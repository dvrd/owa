#!/usr/bin/env python3
"""Finite disposable-process recovery campaign; never loads account/session files."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
SHARED = HERE.parents[2]
STAGES = {
    'before-commit': 'Uncommitted in-memory ratchet changes do not reach the reopened store.',
    'after-intent': 'Durable caller intent preserves its ID, without inventing queued wire or delivery.',
    'after-pending-wire': 'Committed ratchet, content and exact pending packet survive; replay keeps ID.',
    'after-positive-ack': 'ACK removes wire but queued caller journal remains UNKNOWN after crash.',
    'after-ack-journal': 'Durable caller ACK evidence survives; it still never establishes delivery.',
}
FOCUSED = ['send_id_test.odin', 'negative_ack_test.odin', 'media_retry_test.odin',
           'media_deadline_test.odin', 'certificate_policy_test.odin']
COMPILE_TIMEOUT = 300


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(shared):
    paths = list((shared/'whatsapp').glob('*.odin'))
    for directory in ['ascii', 'surf', 'http', 'websocket', 'async']:
        paths += list((shared/directory).rglob('*.odin'))
    for directory in ['core', 'base', 'vendor/zlib']:
        paths += list((shared.parent/directory).rglob('*.odin'))
    paths += list(HERE.glob('*.odin')) + list(HERE.glob('*.py'))
    paths += list((shared/'whatsapp/tests/loopback_noise').glob('*'))
    paths += list((shared/'whatsapp/tests/certificate_policy').rglob('*'))
    return {str(p): digest(p) for p in sorted(set(paths))
            if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts}


def execute(command, receipt, timeout=120):
    start = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
        receipt.append(dict(command=command, returncode=None, stdout=text(error.stdout),
                            stderr=text(error.stderr), timeout_seconds=timeout, timed_out=True,
                            elapsed_seconds=time.monotonic()-start))
        raise
    row = dict(command=command, returncode=result.returncode, stdout=result.stdout,
               stderr=result.stderr, timeout_seconds=timeout,
               elapsed_seconds=time.monotonic()-start)
    receipt.append(row)
    assert result.returncode == 0, row
    return row


def control(binary, receipt):
    # Tested rollback: owned process exits, its same-store reopen passes, then
    # the disposable directory disappears. No account directory is accepted.
    with tempfile.TemporaryDirectory(prefix='wa-recovery-', dir='/tmp') as tmp:
        execute([str(binary), 'child', tmp, 'control'], receipt, 10)
        execute([str(binary), 'verify', tmp, 'control'], receipt, 10)
        path = Path(tmp)
    assert not path.exists()


def crash(binary, stage, receipt):
    with tempfile.TemporaryDirectory(prefix='wa-recovery-', dir='/tmp') as tmp:
        command = [str(binary), 'child', tmp, stage]
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        start = time.monotonic()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                assert selector.select(timeout=10), 'boundary readiness timed out'
                ready = child.stdout.readline(256).decode('ascii')
            assert ready == f'BOUNDARY_READY {stage}\n', ready
            assert child.poll() is None, 'child must be alive at durable boundary'
            # Only this unreaped child object is targeted. Never use a PID search.
            child.kill()
            stdout, stderr = child.communicate(timeout=10)
            receipt.append(dict(command=command, killed_signal='SIGKILL',
                                returncode=child.returncode, stdout=stdout.decode(),
                                stderr=stderr.decode(), owned_child=True, boundary=stage,
                                elapsed_seconds=time.monotonic()-start))
            assert child.returncode == -signal.SIGKILL, report_safe_exit(child.returncode)
            assert not stdout and not stderr, (stdout, stderr)
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        recovered = execute([str(binary), 'verify', tmp, stage], receipt, 10)
        assert 'delivery=false' in recovered['stdout']
        if stage == 'after-positive-ack':
            assert 'RECOVERY_UNKNOWN recipient_delivery=false automatic_send=false' in recovered['stdout']


def report_safe_exit(code):
    return f"owned child exited {code}; expected SIGKILL; inspect receipt"


def focused_names(shared):
    names = []
    for file in FOCUSED:
        source = (shared/'whatsapp'/file).read_text()
        names += ['whatsapp.'+name for name in re.findall(r'@\(test\)\s*(\w+)\s*::', source)]
    assert len(names) >= 20
    return names


def tsv_log(rows, path=None):
    path = path or HERE.parents[1]/'.cruft/chaos-results.tsv'
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text('timestamp\texperiment_name\thypothesis\tblast_radius\tduration\tresult\tsurprises\n')
    with path.open('a') as output:
        for row in rows:
            output.write('\t'.join([datetime.now(timezone.utc).isoformat(), row['name'],
                row['hypothesis'], 'owned-disposable-child', f"{row['duration_seconds']:.6f}",
                row['result'], row.get('surprises', 'none')])+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--odin', required=True, type=Path)
    parser.add_argument('--shared-root', type=Path, default=SHARED)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--sanitize', choices=['none', 'address', 'thread'], default='address')
    parser.add_argument('--scorecard', type=Path, help='Optional external TSV evidence path')
    args = parser.parse_args()
    args.odin = args.odin.resolve(); args.shared_root = args.shared_root.resolve()
    if args.scorecard:
        if not args.scorecard.is_absolute() or any(args.scorecard.resolve().is_relative_to(root)
                for root in (HERE.parents[1].resolve(), args.shared_root/'whatsapp')):
            parser.error('--scorecard must be an absolute path outside the source checkout')
    assert os.name == 'posix' and args.odin.is_file()
    report = dict(passed=False, candidate_release_gate=False, sanitizer=args.sanitize,
                  commands=[], experiments=[], compile_timeout_seconds=COMPILE_TIMEOUT,
                  scope='synthetic offline process + owned loopback')
    before = snapshot(args.shared_root)
    report['source_before'] = before
    report['compiler'] = dict(path=str(args.odin), sha256=digest(args.odin),
        version=subprocess.check_output([str(args.odin), 'version'], text=True).strip(),
        root=subprocess.check_output([str(args.odin), 'root'], text=True).strip())
    report['gaps'] = [
        'Synthetic caller journal, not the live qualification storage implementation.',
        'Crash boundaries are explicit completed durable operations, not arbitrary filesystem syscalls.',
        'Ratchet sentinel proves atomic state presence; it is not a live Signal session or key rotation.',
        'Pending replay verifies actual public send_group transport in memory, not external delivery.',
        'Noise wire fixture is explicit legacy synthetic-certificate policy, not strict TLS/account qualification.',
        'No power loss, disk full, filesystem corruption, DNS outage, live account or Linux certification.',
    ]
    try:
        with tempfile.TemporaryDirectory(prefix='wa-recovery-build-', dir='/tmp') as tmp:
            binary = Path(tmp)/'campaign'
            compile_command = [str(args.odin), 'build', str(HERE), '-thread-count:1',
                               '-warnings-as-errors', '-vet', '-out:'+str(binary)]
            if args.sanitize != 'none': compile_command.append('-sanitize:'+args.sanitize)
            execute(compile_command, report['commands'], COMPILE_TIMEOUT)
            report['binary_sha256'] = digest(binary)
            control(binary, report['commands'])
            report['steady_state_and_rollback_verified'] = True
            for stage, hypothesis in STAGES.items():
                # HALT guard: every preceding recovery must have passed.
                assert all(row['result'] == 'CONFIRMED' for row in report['experiments'])
                start = time.monotonic()
                row = dict(name=stage, hypothesis=hypothesis, result='INCONCLUSIVE')
                report['experiments'].append(row)
                try:
                    crash(binary, stage, report['commands'])
                    row['result'] = 'CONFIRMED'
                except BaseException as error:
                    row['surprises'] = type(error).__name__
                    raise
                finally:
                    row['duration_seconds'] = time.monotonic()-start
            names = focused_names(args.shared_root)
            focused = Path(tmp)/'focused'
            command = [str(args.odin), 'build', str(args.shared_root/'whatsapp'),
                       '-build-mode:test', '-thread-count:1',
                       '-define:ODIN_TEST_THREADS=1', '-define:ODIN_TEST_NAMES='+','.join(names),
                       '-warnings-as-errors', '-vet', '-out:'+str(focused)]
            if args.sanitize != 'none': command.append('-sanitize:'+args.sanitize)
            execute(command, report['commands'], COMPILE_TIMEOUT)
            focused_result = execute([str(focused)], report['commands'])
            assert re.search(r'Finished\s+' + str(len(names)) + r'\s+tests\b',
                             focused_result['stdout'] + focused_result['stderr'])
            report['focused_test_names'] = names
            wire_report = Path(tmp)/'noise.json'
            execute(['python3', str(args.shared_root/'whatsapp/tests/loopback_noise/run.py'),
                '--odin', str(args.odin), '--shared-root', str(args.shared_root),
                '--report', str(wire_report), '--sanitize', args.sanitize], report['commands'], 180)
            report['owned_noise_wire'] = json.loads(wire_report.read_text())
            assert report['owned_noise_wire']['passed']
            report['passed'] = True
    finally:
        report['source_after'] = snapshot(args.shared_root)
        report['source_unchanged'] = before == report['source_after']
        report['compiler_unchanged'] = report['compiler']['sha256'] == digest(args.odin)
        report['passed'] &= report['source_unchanged'] and report['compiler_unchanged']
        report['candidate_release_gate'] = report['passed']
        report['scorecard'] = {'process_durable_boundaries': 'A' if report['passed'] else 'INCOMPLETE',
            'network_eof_stall_recovery': 'A' if report.get('owned_noise_wire', {}).get('passed') else 'INCOMPLETE',
            'overall': 'RESILIENT_WITHIN_EXECUTED_SYNTHETIC_SCOPE' if report['passed'] else 'UNQUALIFIED'}
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2)+'\n')
        tsv_log(report['experiments'], args.scorecard)
    assert report['passed'], 'candidate gate failed; inspect report'
    print('WHATSAPP_RECOVERY_CAMPAIGN_PASS '+args.sanitize)

if __name__ == '__main__':
    main()

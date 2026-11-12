#!/usr/bin/env python3
"""Validate source-bound release evidence; never deploy or change protocol state."""
import argparse
import hashlib
import json
from pathlib import Path
import re

REQUIRED = {'unit_asan', 'noise_loopback', 'consumer', 'protocol_review'}
DIGEST = re.compile(r'[0-9a-f]{64}')


def source_digest(root):
    files = sorted(path for path in root.glob('*.odin') if not path.name.endswith('_test.odin'))
    if not files or len(files) > 100:
        raise ValueError('SOURCE_SET_INVALID')
    if any(path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024 for path in files):
        raise ValueError('SOURCE_SET_INVALID')
    manifest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    return hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(), manifest


def evidence_matches(check, directory):
    name = check.get('evidence_file')
    if not isinstance(name, str) or len(name) > 200:
        return False
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        return False
    path = directory / relative
    if (not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024 or
            directory.resolve() not in path.resolve().parents):
        return False
    return hashlib.sha256(path.read_bytes()).hexdigest() == check.get('evidence_sha256')


def evaluate(root, offline, live, evidence_dir=None):
    evidence_dir = root if evidence_dir is None else evidence_dir
    digest, files = source_digest(root)
    failures = []
    if offline.get('candidate_source_digest') != digest:
        failures.append('OFFLINE_SOURCE_MISMATCH')
    checks = offline.get('checks', {})
    for name in sorted(REQUIRED):
        check = checks.get(name, {}) if isinstance(checks, dict) else {}
        if (check.get('status') != 'PASS' or check.get('candidate_source_digest') != digest or
                not DIGEST.fullmatch(str(check.get('evidence_sha256', ''))) or
                not evidence_matches(check, evidence_dir)):
            failures.append('MISSING_OR_INVALID_' + name.upper())
    if not DIGEST.fullmatch(str(offline.get('compiler_sha256', ''))):
        failures.append('COMPILER_UNBOUND')
    if live.get('candidate_source_digest') != digest:
        failures.append('LIVE_SOURCE_MISMATCH')
    if not evidence_matches(live, evidence_dir):
        failures.append('LIVE_EVIDENCE_MISSING_OR_CHANGED')
    if (live.get('isolated_group_verified') is not True or
            live.get('text_server_acked') is not True or live.get('pdf_server_acked') is not True or
            live.get('recipient_confirmed') is not True or live.get('pdf_opened') is not True or
            live.get('same_ids_after_restart') is not True or live.get('duplicates_reported') is not False):
        failures.append('LIVE_QUALIFICATION_INCOMPLETE')
    return {'status': 'ELIGIBLE_FOR_REVIEW' if not failures else 'BLOCKED',
            'candidate_source_digest': digest, 'source_files': files, 'failures': failures,
            'deployment_authorized': False, 'state_rollback_authorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--offline-receipt', type=Path, required=True)
    parser.add_argument('--live-receipt', type=Path, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        inputs = []
        for path in [args.offline_receipt, args.live_receipt]:
            if path.stat().st_size > 1024 * 1024:
                raise ValueError('RECEIPT_TOO_LARGE')
            inputs.append(json.loads(path.read_bytes()))
        result = evaluate(args.source_root, *inputs, evidence_dir=args.evidence_dir)
    except (OSError, ValueError, TypeError, AttributeError):
        result = {'status': 'BLOCKED', 'failures': ['INVALID_SOURCE_OR_RECEIPT'],
                  'deployment_authorized': False, 'state_rollback_authorized': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'ELIGIBLE_FOR_REVIEW' else 1


if __name__ == '__main__':
    raise SystemExit(main())

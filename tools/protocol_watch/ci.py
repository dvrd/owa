#!/usr/bin/env python3
"""Public-only GitHub Actions scan preparation; no account or model credentials."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('protocol_schedule', HERE/'schedule.py')
schedule = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(schedule)


def prepare(state, output, scan=schedule.watch_run):
    with schedule.watch.locked_state(output):
        try:
            report = scan(types.SimpleNamespace(state_dir=state, manifest=HERE/'sources.json'))
            if report.get('status') not in ('REVIEW_REQUIRED', 'NO_MONITORED_DRIFT'):
                raise ValueError('invalid status')
            encoded = json.dumps(report, separators=(',', ':')).encode()
            if len(encoded) > schedule.watch.MAX_REPORT:
                raise ValueError('oversized report')
            schedule.watch.atomic_json(output/'report.json', report)
            result = {'status': report['status'], 'report_ready': True,
                      'compatibility_approved': False}
        except (schedule.ScheduleError, schedule.watch.WatchError, OSError, ValueError, KeyError, TypeError):
            result = {'status': 'FAILED', 'report_ready': False,
                      'compatibility_approved': False, 'reason': 'PUBLIC_SCAN_FAILED'}
        schedule.watch.atomic_json(output/'result.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if not args.state_dir.is_absolute() or not args.output_dir.is_absolute():
        parser.error('absolute directories required')
    result = prepare(args.state_dir, args.output_dir)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('status='+result['status']+'\n')
    print(json.dumps(result))
    return 2 if result['status'] == 'FAILED' else 0


if __name__ == '__main__':
    sys.exit(main())

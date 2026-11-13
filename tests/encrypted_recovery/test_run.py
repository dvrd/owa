#!/usr/bin/env python3
"""Disposable subprocess controls; no compiler, accounts or provider required."""
import errno
import os
from pathlib import Path
import resource
import sys
import tempfile
import unittest

import run


class CampaignControls(unittest.TestCase):
    def test_bounded_capture_drains_stdout_and_stderr(self):
        result = run.capture([sys.executable, '-c',
            'import sys;print("owned-out");print("owned-err",file=sys.stderr)'], os.environ.copy())
        self.assertEqual(result, {'exit_code': 0, 'stdout': 'owned-out\n', 'stderr': 'owned-err\n'})

    def test_excess_output_fails_and_reaps_owned_child(self):
        with self.assertRaisesRegex(run.CampaignError, 'CHILD_OUTPUT_LIMIT'):
            run.capture([sys.executable, '-c',
                'import os;\nwhile True: os.write(1,b"x"*65536)'], os.environ.copy(), timeout=5)

    def test_deadline_retires_owned_child(self):
        with self.assertRaisesRegex(run.CampaignError, 'CHILD_TIMEOUT'):
            run.capture([sys.executable, '-c', 'import time;time.sleep(20)'],
                        os.environ.copy(), timeout=.1)

    def test_actual_child_file_limit_leaves_parent_unchanged(self):
        before = resource.getrlimit(resource.RLIMIT_FSIZE)
        with tempfile.TemporaryDirectory(prefix='wa-encrypted-', dir='/tmp') as temporary:
            target = Path(temporary)/'limited'
            program = ('import os,errno,sys\n'
                       'try:\n'
                       ' with open(sys.argv[1],"wb",buffering=0) as f:\n'
                       '  f.write(b"x"*4096);f.write(b"x"*4096)\n'
                       'except OSError as error:\n'
                       ' assert error.errno==errno.EFBIG\n'
                       ' print("EFBIG")\n')
            result = run.capture([sys.executable, '-c', program, str(target)],
                                 os.environ.copy(), limit=True)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['stdout'], 'EFBIG\n')
            self.assertEqual(target.stat().st_size, 512)
        self.assertEqual(before, resource.getrlimit(resource.RLIMIT_FSIZE))

    def test_owned_scope_rejects_unrelated_and_symlink_paths(self):
        with tempfile.TemporaryDirectory(prefix='wa-encrypted-', dir='/tmp') as temporary:
            directory = Path(temporary)
            run.scope(directory)
            self.assertEqual((directory/'owner').read_bytes(), run.OWNER)
            self.assertEqual((directory/'owner').stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(run.CampaignError, 'DISPOSABLE_SCOPE_REQUIRED'):
                run.scope(directory/'..')
            alias = directory/'wa-encrypted-alias'; alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(run.CampaignError, 'DISPOSABLE_SCOPE_REQUIRED'):
                run.scope(alias)

    def test_wrong_boundary_fails_without_touching_other_processes(self):
        with tempfile.TemporaryDirectory(prefix='wa-encrypted-', dir='/tmp') as temporary:
            directory = Path(temporary); run.scope(directory)
            program = directory/'wrong-boundary'
            program.write_text('#!'+sys.executable+'\nimport time\nprint("WRONG",flush=True)\ntime.sleep(20)\n')
            program.chmod(0o700)
            with self.assertRaisesRegex(run.CampaignError, 'BOUNDARY_MISMATCH'):
                run.crash(program, directory, 'sender-before-commit', os.environ.copy(), [])


if __name__ == '__main__': unittest.main()

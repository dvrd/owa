#!/usr/bin/env python3
"""Small local Git fixtures only; never compiles or contacts a provider."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import compatibility


class CompatibilityControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='owa-format-git-', dir='/tmp')
        self.root = Path(self.temporary.name)
        subprocess.run(['git', 'init', '-q', self.root], check=True)
        (self.root/'empty-hooks').mkdir()
        self.git('config', 'core.hooksPath', str(self.root/'empty-hooks'))
        self.git('config', 'user.name', 'Synthetic Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.root/'state_store.odin').write_text('package fixture\nVERSION :: 1\n')
        (self.root/'session.odin').write_text('package fixture\nVALUE :: 7\n')
        (self.root/'runtime_test.odin').write_text('package fixture\n')
        (self.root/'synthetic-account.json').write_text('{}')
        (self.root/'reports').mkdir()
        (self.root/'reports/private.odin').write_text('package fixture\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic format fixture')
        self.commit = self.git('rev-parse', 'HEAD').strip()

    def tearDown(self): self.temporary.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True)

    def test_export_is_exact_git_blob_and_excludes_non_runtime_paths(self):
        target = self.root/'export'
        manifest = compatibility.export_runtime(self.root, self.commit, target)
        self.assertEqual(set(manifest), {'state_store.odin', 'session.odin'})
        compatibility.verify_export(self.root, target, manifest)
        for name, entry in manifest.items():
            self.assertEqual(entry['git_blob'], self.git('rev-parse', self.commit+':'+name).strip())
            self.assertEqual(entry['git_blob'], self.git('hash-object', str(target/name)).strip())

    def test_export_mutation_is_rejected(self):
        target = self.root/'export'
        manifest = compatibility.export_runtime(self.root, self.commit, target)
        (target/'session.odin').write_text('package fixture\nVALUE :: 8\n')
        with self.assertRaisesRegex(compatibility.CompatibilityError, 'RUNTIME_EXPORT_CHANGED'):
            compatibility.verify_export(self.root, target, manifest)

    def test_only_full_commit_identity_is_accepted(self):
        for value in ('HEAD', self.commit[:12], '../HEAD', 'g'*40):
            with self.assertRaisesRegex(compatibility.CompatibilityError, 'FULL_COMMIT_REQUIRED'):
                compatibility.runtime_entries(self.root, value)

    def test_runtime_symlink_is_rejected(self):
        (self.root/'session.odin').unlink()
        (self.root/'session.odin').symlink_to('state_store.odin')
        self.git('add', 'session.odin'); self.git('commit', '-qm', 'synthetic symlink refusal')
        commit = self.git('rev-parse', 'HEAD').strip()
        with self.assertRaisesRegex(compatibility.CompatibilityError, 'RUNTIME_BLOB_INVALID'):
            compatibility.runtime_entries(self.root, commit)


    def test_wrong_repository_without_pinned_prior_is_refused(self):
        with self.assertRaisesRegex(compatibility.CompatibilityError, 'REPOSITORY_REVISION_MISSING'):
            compatibility.validate_repository(self.root, self.commit)

    def test_repository_root_and_exact_existing_revision_are_required(self):
        for revision in ('HEAD', self.commit[:12]):
            with self.assertRaisesRegex(compatibility.CompatibilityError, 'FULL_CURRENT_COMMIT_REQUIRED'):
                compatibility.validate_repository(self.root, revision)
        with self.assertRaisesRegex(compatibility.CompatibilityError, 'REPOSITORY_ROOT_REQUIRED'):
            compatibility.validate_repository(self.root/'reports', self.commit)
        with mock.patch.object(compatibility, 'PRIOR', self.commit):
            with self.assertRaisesRegex(compatibility.CompatibilityError, 'REPOSITORY_REVISION_MISSING'):
                compatibility.validate_repository(self.root, 'a'*40)

    def test_readonly_repository_accepts_exact_descendant_without_git_mutation(self):
        (self.root/'session.odin').write_text('package fixture\nVALUE :: 9\n')
        self.git('add', 'session.odin'); self.git('commit', '-qm', 'synthetic descendant')
        current = self.git('rev-parse', 'HEAD').strip()
        before = self.git('status', '--porcelain')
        with mock.patch.object(compatibility, 'PRIOR', self.commit):
            self.assertEqual(compatibility.validate_repository(self.root, current), self.root.resolve())
        self.assertEqual(self.git('status', '--porcelain'), before)
        self.assertEqual(self.git('rev-parse', 'HEAD').strip(), current)


if __name__ == '__main__': unittest.main()

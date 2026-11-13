#!/usr/bin/env python3
"""Offline same-format cross-commit StateStore/Signal/prekey compatibility."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

import run as bounded

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
NATIVE = REPO/'tools/native_ci'
sys.path.insert(0, str(NATIVE))
import assets

PRIOR = 'fa2734f60b60cc9770809bb1be873cea60fe3c12'
CURRENT = '1d5160f384d3055eef314557c31c912bea5ce557'
COMMIT = re.compile(r'[0-9a-f]{40}')


class CompatibilityError(Exception): pass


def git(repository, *args):
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'LANG', 'LC_ALL') if key in os.environ}
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    result = bounded.capture(['git', '-C', repository, *args], env, 15)
    if result['exit_code']: raise CompatibilityError('GIT_COMMAND_FAILED')
    return result['stdout']


def runtime_entries(repository, commit):
    if not COMMIT.fullmatch(commit): raise CompatibilityError('FULL_COMMIT_REQUIRED')
    if git(repository, 'rev-parse', '--verify', commit+'^{commit}').strip() != commit:
        raise CompatibilityError('COMMIT_MISMATCH')
    result = {}
    for entry in git(repository, 'ls-tree', '-rz', commit).split('\0'):
        if not entry: continue
        metadata, name = entry.split('\t', 1)
        mode, kind, blob = metadata.split()
        # Export public root runtime code/notices only, never tests, reports,
        # application/account files, arbitrary nested paths or Git metadata.
        selected = ('/' not in name and name.endswith('.odin') and
                    not name.endswith('_test.odin')) or name in ('LICENSE', 'LICENSE.txt', 'BAILEYS_LICENSE.txt')
        if not selected: continue
        if mode not in ('100644', '100755') or kind != 'blob' or not COMMIT.fullmatch(blob):
            raise CompatibilityError('RUNTIME_BLOB_INVALID')
        result[name] = blob
    if not result or 'state_store.odin' not in result: raise CompatibilityError('RUNTIME_CLOSURE_MISSING')
    return result


def validate_repository(repository, current):
    if not COMMIT.fullmatch(current): raise CompatibilityError('FULL_CURRENT_COMMIT_REQUIRED')
    repository = Path(repository).resolve(strict=True)
    if not repository.is_dir(): raise CompatibilityError('REPOSITORY_DIRECTORY_REQUIRED')
    if Path(git(repository, 'rev-parse', '--show-toplevel').strip()).resolve() != repository:
        raise CompatibilityError('REPOSITORY_ROOT_REQUIRED')
    try:
        prior = git(repository, 'rev-parse', '--verify', PRIOR+'^{commit}').strip()
        actual = git(repository, 'rev-parse', '--verify', current+'^{commit}').strip()
    except CompatibilityError as error:
        raise CompatibilityError('REPOSITORY_REVISION_MISSING') from error
    if prior != PRIOR or actual != current: raise CompatibilityError('COMMIT_MISMATCH')
    if current == PRIOR: raise CompatibilityError('DISTINCT_RUNTIME_COMMITS_REQUIRED')
    if git(repository, 'merge-base', PRIOR, current).strip() != PRIOR:
        raise CompatibilityError('PRIOR_NOT_ANCESTOR')
    return repository


def export_runtime(repository, commit, destination):
    destination.mkdir()
    manifest = {}
    for name, blob in sorted(runtime_entries(repository, commit).items()):
        text = git(repository, 'cat-file', 'blob', blob)
        target = destination/name; target.write_bytes(text.encode('utf-8'))
        if git(repository, 'hash-object', str(target)).strip() != blob:
            raise CompatibilityError('EXPORTED_GIT_BLOB_MISMATCH')
        manifest[name] = {'git_blob': blob, 'sha256': bounded.digest(target), 'bytes': target.stat().st_size}
    return manifest


def verify_export(repository, root, expected):
    for name, record in expected.items():
        path = root/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record['bytes'] or \
                bounded.digest(path) != record['sha256'] or \
                git(repository, 'hash-object', str(path)).strip() != record['git_blob']:
            raise CompatibilityError('RUNTIME_EXPORT_CHANGED')


def fixture_snapshot():
    names = list(HERE.glob('*.odin'))+list(HERE.glob('*.py'))+[HERE/'README.md', NATIVE/'assets.py', NATIVE/'pin.json']
    return {str(path): bounded.digest(path) for path in sorted(names)}


def host_key():
    key = (platform.system(), platform.machine())
    if key == ('Darwin', 'arm64'): return 'macos-arm64'
    if key == ('Linux', 'x86_64'): return 'linux-amd64'
    raise CompatibilityError('NATIVE_HOST_UNSUPPORTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets-dir', type=Path, required=True,
                        help='Already downloaded pinned SDK objects; this runner never downloads')
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--repository', type=Path, default=REPO,
                        help='Read-only local Git owner; required when executing a copied fixture without .git')
    parser.add_argument('--current-revision', default=CURRENT, help='Exact full consumer commit; never a moving ref')
    parser.add_argument('--sanitize', choices=('address', 'thread'), required=True)
    parser.add_argument('--work', type=Path, required=True, help='New owned /tmp directory; retained for review')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    report = {'schema': 1, 'passed': False, 'scope': 'Offline same-format cross-commit compatibility; normal producer exit, no network/fault injection/account data',
              'commands': [], 'prior_commit': PRIOR,
              'prior_publication': 'https://github.com/dvrd/owa/commit/'+PRIOR,
              'sanitizer': args.sanitize}
    before = fixture_snapshot()
    try:
        if args.work.parent.resolve() != Path('/tmp').resolve() or not args.work.name.startswith('owa-format-compat-'):
            raise CompatibilityError('NEW_OWNED_TMP_WORK_REQUIRED')
        args.work.mkdir(mode=0o700)
        args.assets_dir = args.assets_dir.resolve()
        args.clang = args.clang.resolve(strict=True)
        if not args.assets_dir.is_dir() or not args.clang.is_file(): raise CompatibilityError('LOCAL_INPUT_MISSING')
        current = args.current_revision
        repository = validate_repository(args.repository, current)
        report['repository'] = str(repository)
        report['current_commit'] = current
        pin = json.loads((NATIVE/'pin.json').read_bytes())
        report.update(pin_sha256=bounded.digest(NATIVE/'pin.json'), core_revision=pin['core_source_revision'],
                      compiler_source_revision=pin['compiler_source_revision'], dependency_manifest_sha256=pin['dependencies']['manifest']['sha256'])
        objects = args.work/'objects'; objects.mkdir()
        sdk = args.work/'sdk'
        sdk_expected = assets.install(pin, pin['platforms'][host_key()], objects, sdk, args.assets_dir)
        compiler = sdk/'odin'
        env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL') if k in os.environ}
        env.update(PATH=str(args.clang.parent)+os.pathsep+env.get('PATH', ''), ODIN_ROOT=str(sdk), PYTHONDONTWRITEBYTECODE='1')
        if platform.system() == 'Darwin': env['DYLD_LIBRARY_PATH'] = str(sdk/'lib')
        selected = shutil.which('clang', path=env['PATH'])
        if not selected or Path(selected).resolve() != args.clang: raise CompatibilityError('CLANG_SELECTION_MISMATCH')
        report['compiler_sha256'] = bounded.digest(compiler)
        report['compiler_version'] = bounded.capture([compiler, 'version'], env)['stdout'].strip()
        if pin['compiler_version'] not in report['compiler_version']: raise CompatibilityError('COMPILER_VERSION_MISMATCH')
        report['clang'] = {'path': str(args.clang), 'sha256': bounded.digest(args.clang),
                           'version': bounded.capture([args.clang, '--version'], env)['stdout'].strip()}
        owners = {}; dependency_manifests = {}
        binaries = args.work/'bin'; binaries.mkdir()
        for role, commit in [('prior', PRIOR), ('current', current)]:
            shared = args.work/(role+'-shared')
            dependencies = assets.install(pin, pin['dependencies'], objects, shared, args.assets_dir)
            dependency_manifests[role] = dependencies
            owner = shared/'whatsapp'
            manifest = export_runtime(repository, commit, owner)
            fixture = owner/'tests/encrypted_recovery'; fixture.mkdir(parents=True)
            copied = {}
            for source in sorted(HERE.glob('*.odin')):
                target = fixture/source.name; shutil.copyfile(source, target)
                if bounded.digest(target) != before[str(source)]: raise CompatibilityError('FIXTURE_CHANGED_DURING_COPY')
                copied[source.name] = bounded.digest(target)
            binary = binaries/role
            owners[role] = {'commit': commit, 'directory': str(owner), 'git_blobs_and_sha256': manifest,
                            'fixture_sha256': copied, 'binary': str(binary)}
            bounded.execute([compiler, 'build', fixture, '-collection:shared='+str(shared),
                '-vet', '-warnings-as-errors', '-thread-count:1', '-sanitize:'+args.sanitize,
                '-out:'+str(binary)], env, report['commands'])
            owners[role]['binary_sha256'] = bounded.digest(binary)
        if owners['prior']['fixture_sha256'] != owners['current']['fixture_sha256']:
            raise CompatibilityError('FIXTURE_ROLES_DIFFER')
        report['owners'] = owners
        changed = [name for name in sorted(set(owners['prior']['git_blobs_and_sha256']) | set(owners['current']['git_blobs_and_sha256']))
                   if owners['prior']['git_blobs_and_sha256'].get(name) != owners['current']['git_blobs_and_sha256'].get(name)]
        if not changed: raise CompatibilityError('DISTINCT_RUNTIME_SOURCE_REQUIRED')
        report['changed_runtime_files'] = changed
        with tempfile.TemporaryDirectory(prefix='wa-encrypted-', dir='/tmp') as temporary:
            directory = Path(temporary); bounded.scope(directory)
            produced = bounded.execute([binaries/'prior', 'compat-produce', directory, 'same-format'], env, report['commands'], 20)
            if 'COMPAT_PRODUCED' not in produced['stdout']: raise CompatibilityError('PRODUCER_RECEIPT_MISSING')
            original = {name: bounded.digest(directory/name) for name in ('state.bin', 'prekeys.bin')}
            report['prior_produced_file_sha256'] = original
            for _ in range(2):
                verified = bounded.execute([binaries/'current', 'compat-verify', directory, 'same-format'], env, report['commands'], 20)
                if 'COMPAT_VERIFIED' not in verified['stdout']: raise CompatibilityError('CONSUMER_RECEIPT_MISSING')
                if original != {name: bounded.digest(directory/name) for name in original}:
                    raise CompatibilityError('PRIOR_FILES_REWRITTEN')
            report['exact_prior_file_bytes_preserved'] = True
            report['producer_exit_normal'] = True
            report['fresh_current_readonly_processes'] = 2
        for role, owner in owners.items():
            verify_export(repository, Path(owner['directory']), owner['git_blobs_and_sha256'])
            owner['runtime_sha256_after'] = {name: bounded.digest(Path(owner['directory'])/name)
                                              for name in owner['git_blobs_and_sha256']}
            assets.verify_tree(Path(owner['directory']).parent, dependency_manifests[role], extra_root='whatsapp')
            if bounded.digest(owner['binary']) != owner['binary_sha256']: raise CompatibilityError('BINARY_CHANGED')
        assets.verify_tree(sdk, sdk_expected)
        if report['clang']['sha256'] != bounded.digest(args.clang): raise CompatibilityError('CLANG_CHANGED')
        report['runtime_exports_unchanged'] = True
        report['sdk_and_dependencies_unchanged'] = True
        report['passed'] = True
    except (CompatibilityError, bounded.CampaignError, assets.AssetError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['failure'] = type(error).__name__+': '+str(error)[:200]
    finally:
        report['fixture_source_unchanged'] = before == fixture_snapshot()
        report['passed'] = report['passed'] and report['fixture_source_unchanged']
        report['limits'] = 'Same serialized format across exact OWA commits, same pinned compiler/Core/dependencies. No historical schema migration, full Socket upgrade, live service, concurrent writers, ENOSPC or crash proof.'
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'passed': report['passed'], 'failure': report.get('failure')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__': sys.exit(main())

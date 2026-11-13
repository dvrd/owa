#!/usr/bin/env python3
"""Prepare reviewed public native-CI assets locally; never upload or push."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

import assets

HERE = Path(__file__).resolve().parent
PACKAGES = ('ascii', 'async', 'async/connection', 'http', 'http/testsupport',
            'http/v1', 'http/v2', 'http/v2/hpack', 'http/v3', 'surf', 'websocket')
OWNERS = ('ascii', 'async', 'http', 'surf', 'websocket')
LOAD = re.compile(r'#load\s*\(\s*"([^"]+)"')
SOURCE_PREFIXES = {'src', 'base', 'core', 'vendor', 'tests', 'misc', 'bin', 'ci'}
SOURCE_FILES = {'LICENSE', 'README.md', 'Makefile', 'build_odin.sh', 'build.bat',
                'build_vendor.bat', 'run_tests.sh', 'run_tests.bat', 'check_all.sh',
                'check_all.bat', 'odin.ebnf', 'shell.nix'}


def git(root, *arguments):
    return subprocess.check_output(['git', '-C', str(root), *arguments], text=True).strip()


def sealed(entry, directory, prefix):
    for kind in ('archive', 'manifest'):
        record = entry[kind]
        suffix = '.tar.gz' if kind == 'archive' else '.manifest.json'
        name = prefix+'-'+record['sha256'][:16]+suffix
        old, new = directory/record['name'], directory/name
        if new.exists(): raise assets.AssetError('OUTPUT_COLLISION')
        old.rename(new); record['name'] = name
    return entry


def pinned_runtime(base, pin, platform, output):
    entry = {'top': 'odin-'+platform}
    for kind in ('archive', 'manifest'):
        original = pin['platforms'][platform][kind]
        source = base/assets.relative(original['key'])
        record = {'name': source.name, 'bytes': original['bytes'], 'sha256': original['sha256']}
        assets.verify_object(source, record)
        target = output/('runtime-'+platform+('.tar.gz' if kind == 'archive' else '.json'))
        shutil.copyfile(source, target); entry[kind] = assets.object_record(target)
    return sealed(entry, output, 'sdk-'+platform)


def dependency_sources(shared, stage):
    repositories, selected = {}, set()
    for owner in OWNERS:
        root = shared/owner
        if git(root, 'status', '--porcelain', '--untracked-files=all'):
            raise assets.AssetError('DEPENDENCY_REPOSITORY_DIRTY: '+owner)
        repositories[owner] = {'revision': git(root, 'rev-parse', 'HEAD'), 'files': {}}
    for package in PACKAGES:
        directory = shared/package
        for path in directory.glob('*.odin'):
            selected.add(path.relative_to(shared).as_posix())
            for loaded in LOAD.findall(path.read_text()):
                resource = (directory/loaded).resolve()
                selected.add(resource.relative_to(shared).as_posix())
        readme = directory/'README.md'
        if readme.is_file(): selected.add(readme.relative_to(shared).as_posix())
    for owner in OWNERS:
        for path in (shared/owner).rglob('*'):
            if path.is_file() and path.name.startswith(('LICENSE', 'NOTICE', 'COPYING', 'PROVENANCE')):
                if '.git' not in path.parts: selected.add(path.relative_to(shared).as_posix())
    for name in sorted(selected):
        owner, inner = name.split('/', 1)
        if owner not in repositories: raise assets.AssetError('DEPENDENCY_OUTSIDE_DECLARED_OWNER')
        source = shared/assets.relative(name)
        if source.is_symlink() or not source.is_file(): raise assets.AssetError('DEPENDENCY_FILE_INVALID')
        committed = subprocess.check_output(['git', '-C', str(shared/owner), 'show', 'HEAD:'+inner])
        if hashlib.sha256(committed).hexdigest() != assets.digest(source):
            raise assets.AssetError('DEPENDENCY_COMMIT_MISMATCH')
        target = stage/name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        repositories[owner]['files'][inner] = assets.digest(target)
    for owner, record in repositories.items():
        if git(shared/owner, 'rev-parse', 'HEAD') != record['revision'] or \
                git(shared/owner, 'status', '--porcelain', '--untracked-files=all'):
            raise assets.AssetError('DEPENDENCY_CHANGED_DURING_EXPORT')
    metadata = {'schema': 1, 'packages': list(PACKAGES), 'repositories': repositories,
                'license_policy': 'Existing source notices retained unchanged; no new blanket license imposed.'}
    (stage/'provenance.json').write_text(json.dumps(metadata, sort_keys=True, indent=2)+'\n')
    return selected | {'provenance.json'}, metadata


def filtered_source(base, pin, stage):
    original = pin['source']['archive']; original_manifest = pin['source']['manifest']
    archive = base/assets.relative(original['key']); manifest = base/assets.relative(original_manifest['key'])
    for path, record in ((archive, original), (manifest, original_manifest)):
        assets.verify_object(path, {'name': path.name, 'bytes': record['bytes'], 'sha256': record['sha256']})
    expected = assets.files_manifest(manifest)
    chosen = {name for name in expected if name in SOURCE_FILES or name.split('/')[0] in SOURCE_PREFIXES}
    seen = set(); top = None
    with tarfile.open(archive, 'r:gz') as packed:
        for member in packed:
            path = assets.relative(member.name.rstrip('/'))
            top = top or path.parts[0]
            if path.parts[0] != top: raise assets.AssetError('SOURCE_ARCHIVE_TOP_INVALID')
            name = Path(*path.parts[1:]).as_posix()
            if name not in chosen: continue
            if name in seen or not member.isfile() or member.size != expected[name]['bytes']:
                raise assets.AssetError('SOURCE_MEMBER_INVALID')
            target = stage/name; target.parent.mkdir(parents=True, exist_ok=True)
            with packed.extractfile(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output, 1 << 20)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
            if assets.digest(target) != expected[name]['sha256']:
                raise assets.AssetError('SOURCE_MEMBER_HASH_MISMATCH')
            seen.add(name)
    if chosen != seen or not {'LICENSE', 'build_odin.sh'} <= seen:
        raise assets.AssetError('SOURCE_EXPORT_INCOMPLETE')
    excluded = sorted(set(expected)-chosen)
    return chosen, {'original_source_commit': pin['source_revision'],
                    'original_archive_sha256': original['sha256'],
                    'included_files': len(chosen), 'excluded_files': excluded}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mesa-root', type=Path, required=True)
    parser.add_argument('--shared-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release-tag', required=True)
    parser.add_argument('--pin-output', type=Path, default=HERE/'pin.json')
    args = parser.parse_args()
    if not assets.NAME.fullmatch(args.release_tag): parser.error('invalid release tag')
    if args.pin_output.resolve().parent != HERE: parser.error('pin must stay in tools/native_ci')
    args.output.mkdir(mode=0o700)
    mesa_pin = json.loads((args.mesa_root/'vendor/odin/pin.json').read_bytes())
    base = args.mesa_root/'dist/toolchain'
    pin = {'schema': 1, 'repository': assets.REPOSITORY, 'release_tag': args.release_tag,
           'compiler_version': mesa_pin['version'], 'compiler_source_revision': 'c826157de61987cbe706b1203e35d138e61429f9',
           'core_source_revision': mesa_pin['source_revision'], 'platforms': {}}
    for platform in ('linux-amd64', 'macos-arm64'):
        pin['platforms'][platform] = pinned_runtime(base, mesa_pin, platform, args.output)
    with tempfile.TemporaryDirectory(prefix='owa-public-dependencies-') as tmp:
        stage = Path(tmp)
        names, dependency_metadata = dependency_sources(args.shared_root.resolve(), stage)
        pin['dependencies'] = sealed(assets.package(stage, names, args.output/'dependencies.tar.gz',
            args.output/'dependencies.manifest.json', 'dependencies'), args.output, 'dependencies')
    with tempfile.TemporaryDirectory(prefix='owa-public-source-') as tmp:
        stage = Path(tmp); names, source_metadata = filtered_source(base, mesa_pin, stage)
        pin['source'] = sealed(assets.package(stage, names, args.output/'source.tar.gz',
            args.output/'source.manifest.json', 'odin-source'), args.output, 'source')
    args.pin_output.write_text(json.dumps(pin, sort_keys=True, indent=2)+'\n')
    review = {'published': False, 'pin_sha256': assets.digest(args.pin_output),
              'dependencies': dependency_metadata, 'source_export': source_metadata,
              'assets': [record for entry in [*pin['platforms'].values(), pin['dependencies'], pin['source']]
                         for record in (entry['archive'], entry['manifest'])]}
    (args.output/'publication-review.json').write_text(json.dumps(review, sort_keys=True, indent=2)+'\n')
    print(json.dumps({'prepared': True, 'published': False, 'asset_count': len(review['assets']),
                      'source_files': source_metadata['included_files'],
                      'dependency_files': sum(len(r['files']) for r in dependency_metadata['repositories'].values())}))


if __name__ == '__main__': main()

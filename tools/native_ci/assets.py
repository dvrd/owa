#!/usr/bin/env python3
"""Bounded immutable OWA CI objects. Derived from Mesa tools/toolchain.py c0b14445.

Archives contain regular files only, with a single declared top-level directory.
Every input object and every extracted file must match the committed pin.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

MAX_FILES = 50000
MAX_FILE = 512 << 20
MAX_TREE = 2 << 30
MAX_MANIFEST = 4 << 20
SHA = re.compile(r'[0-9a-f]{64}')
NAME = re.compile(r'[A-Za-z0-9._-]+')
REPOSITORY = 'dvrd/owa'


class AssetError(Exception): pass


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise AssetError('PATH_INVALID')
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ('', '.', '..') for p in value.split('/')):
        raise AssetError('PATH_INVALID')
    return Path(*path.parts)


def files_manifest(path):
    if path.stat().st_size > MAX_MANIFEST: raise AssetError('MANIFEST_TOO_LARGE')
    value = json.loads(path.read_bytes())
    if isinstance(value, dict) and set(value) == {'packages', 'files'}:
        if not isinstance(value['packages'], list): raise AssetError('PACKAGES_INVALID')
        value = value['files']
    if not isinstance(value, dict) or not 0 < len(value) <= MAX_FILES:
        raise AssetError('MANIFEST_INVALID')
    total = 0
    for name, record in value.items():
        relative(name)
        if not isinstance(record, dict) or set(record) != {'bytes', 'sha256'}:
            raise AssetError('FILE_RECORD_INVALID')
        if type(record['bytes']) is not int or not 0 <= record['bytes'] <= MAX_FILE:
            raise AssetError('FILE_SIZE_INVALID')
        if not isinstance(record['sha256'], str) or not SHA.fullmatch(record['sha256']):
            raise AssetError('FILE_HASH_INVALID')
        total += record['bytes']
    if total > MAX_TREE: raise AssetError('TREE_TOO_LARGE')
    return value


def validate_record(record):
    if (not isinstance(record, dict) or set(record) != {'name', 'bytes', 'sha256'} or
            not isinstance(record['name'], str) or record['name'] in ('.', '..') or
            not NAME.fullmatch(record['name']) or
            type(record['bytes']) is not int or not 0 < record['bytes'] <= MAX_TREE or
            not isinstance(record['sha256'], str) or not SHA.fullmatch(record['sha256'])):
        raise AssetError('OBJECT_PIN_INVALID')


def verify_object(path, record):
    validate_record(record)
    if path.is_symlink() or not path.is_file() or path.stat().st_size != record['bytes']:
        raise AssetError('OBJECT_SIZE_OR_TYPE_MISMATCH')
    if digest(path) != record['sha256']: raise AssetError('OBJECT_HASH_MISMATCH')


def object_record(path):
    return {'name': path.name, 'bytes': path.stat().st_size, 'sha256': digest(path)}


def verify_tree(root, expected, extra_root=None):
    actual = set()
    for path in root.rglob('*'):
        if path.is_symlink(): raise AssetError('TREE_SYMLINK')
        if path.is_file():
            name = path.relative_to(root).as_posix()
            if extra_root and name.startswith(extra_root+'/'): continue
            actual.add(name)
    if actual != set(expected): raise AssetError('TREE_MEMBERS_MISMATCH')
    for name, record in expected.items():
        path = root/relative(name)
        if path.stat().st_size != record['bytes'] or digest(path) != record['sha256']:
            raise AssetError('TREE_FILE_MISMATCH')


def extract(archive, destination, expected, top):
    if not NAME.fullmatch(top): raise AssetError('ARCHIVE_TOP_INVALID')
    destination.mkdir(mode=0o700)
    directories = {'.'}
    for name in expected:
        directories.update(p.as_posix() for p in relative(name).parents)
    seen = set(); members = set(); count = 0
    try:
        with tarfile.open(archive, 'r:gz') as packed:
            for member in packed:
                count += 1
                if count > MAX_FILES*2: raise AssetError('ARCHIVE_TOO_MANY_MEMBERS')
                name = member.name.rstrip('/')
                relative(name)
                if name in members: raise AssetError('ARCHIVE_DUPLICATE_MEMBER')
                members.add(name)
                parts = PurePosixPath(name).parts
                if parts[0] != top: raise AssetError('ARCHIVE_TOP_MISMATCH')
                inner = PurePosixPath(*parts[1:]).as_posix()
                if member.isdir():
                    if inner not in directories: raise AssetError('ARCHIVE_DIRECTORY_UNEXPECTED')
                    (destination/inner).mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or len(parts) < 2 or member.mode & ~0o777:
                    raise AssetError('ARCHIVE_MEMBER_TYPE_INVALID')
                record = expected.get(inner)
                if record is None or member.size != record['bytes']:
                    raise AssetError('ARCHIVE_FILE_MISMATCH')
                target = destination/relative(inner)
                target.parent.mkdir(parents=True, exist_ok=True)
                with packed.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output, 1 << 20)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
                seen.add(inner)
        if seen != set(expected): raise AssetError('ARCHIVE_FILES_MISSING')
        verify_tree(destination, expected)
    except BaseException:
        # Failed partial extraction is evidence, never a cache to reuse.
        raise


class Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in (
                'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'):
            raise AssetError('DOWNLOAD_REDIRECT_REFUSED')
        return super().redirect_request(request, response, code, message, headers, url)


def fetch(pin, record, directory, local=None):
    validate_record(record)
    target = directory/record['name']
    if target.exists():
        verify_object(target, record)
        return target
    if local is not None:
        source = local/record['name']; verify_object(source, record)
        shutil.copyfile(source, target)
    else:
        if pin['repository'] != REPOSITORY or not NAME.fullmatch(pin['release_tag']) or \
                pin['release_tag'] in ('.', '..'):
            raise AssetError('RELEASE_SCOPE_INVALID')
        url = ('https://github.com/'+REPOSITORY+'/releases/download/'+pin['release_tag']+'/'+record['name'])
        started = time.monotonic(); size = 0
        with urllib.request.build_opener(Redirects).open(url, timeout=30) as source:
            with target.open('xb') as output:
                while block := source.read(1 << 20):
                    size += len(block)
                    if size > record['bytes'] or time.monotonic()-started > 240:
                        raise AssetError('DOWNLOAD_BOUND_EXCEEDED')
                    output.write(block)
    verify_object(target, record)
    return target


def install(pin, entry, work, destination, local=None):
    manifest = fetch(pin, entry['manifest'], work, local)
    archive = fetch(pin, entry['archive'], work, local)
    expected = files_manifest(manifest)
    extract(archive, destination, expected, entry['top'])
    return expected


def package(tree, names, archive, manifest, top):
    names = sorted(set(names))
    records = {}
    for name in names:
        path = tree/relative(name)
        if path.is_symlink() or not path.is_file(): raise AssetError('PACKAGE_FILE_INVALID')
        records[name] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
    manifest.write_text(json.dumps(records, sort_keys=True, indent=2)+'\n')
    with archive.open('xb') as output:
        with gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as packed:
                for name in names:
                    path = tree/name
                    info = tarfile.TarInfo(top+'/'+name)
                    info.size = records[name]['bytes']; info.mode = 0o755 if os.access(path, os.X_OK) else 0o644
                    with path.open('rb') as source: packed.addfile(info, source)
    return {'top': top, 'archive': object_record(archive), 'manifest': object_record(manifest)}

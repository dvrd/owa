#!/usr/bin/env python3
"""Read-only upstream observation. A revision observation never approves compatibility."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
MAX_BYTES = 4 * 1024 * 1024
MAX_REPORT = 256 * 1024
SHA = re.compile(r"[0-9a-f]{40}")
NAME = re.compile(r"[A-Za-z0-9_.-]+")
REPOSITORIES = {"WhiskeySockets/Baileys", "tulir/whatsmeow"}


class WatchError(Exception):
    pass


def manifest_read(path):
    manifest = json.loads(Path(path).read_bytes())
    if manifest.get('schema') != 1 or not 1 <= len(manifest.get('sources', [])) <= 2:
        raise WatchError('MANIFEST_INVALID')
    names = set()
    for source in manifest['sources']:
        if (source.get('repository') not in REPOSITORIES or
                not NAME.fullmatch(source.get('name', '')) or source['name'] in names or
                not NAME.fullmatch(source.get('branch', '')) or
                not SHA.fullmatch(source.get('reference_commit', '')) or
                not 1 <= len(source.get('paths', [])) <= 16):
            raise WatchError('MANIFEST_INVALID')
        names.add(source['name'])
        for item in source['paths']:
            if (not isinstance(item, str) or len(item) > 200 or
                    not all(NAME.fullmatch(part) and part not in ('.', '..')
                            for part in item.split('/'))):
                raise WatchError('MANIFEST_INVALID')
        if len(set(source['paths'])) != len(source['paths']):
            raise WatchError('MANIFEST_INVALID')
    return manifest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise WatchError('UPSTREAM_REDIRECT')


def fetch(url, timeout):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'webtools-whatsapp-protocol-watch', 'Accept-Encoding': 'identity'})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise WatchError('UPSTREAM_OVERSIZED')
            return data
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise WatchError('UPSTREAM_HTTP_FAILED') from None
    except (OSError, ValueError):
        raise WatchError('UPSTREAM_FETCH_FAILED') from None


def file_digest(data):
    return {'present': data is not None, 'bytes': len(data) if data is not None else 0,
            'sha256': hashlib.sha256(data).hexdigest() if data is not None else None}


def version_decode(data):
    try:
        version = json.loads(data)['version']
        if (not isinstance(version, list) or len(version) != 3 or
                any(type(value) is not int or not 0 <= value <= 0xffffffff for value in version)):
            raise ValueError()
        return version
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise WatchError('VERSION_FEED_INVALID') from None


def observe(manifest, get=fetch, now=time.monotonic, budget_seconds=180):
    deadline = now() + budget_seconds

    def bounded_get(url):
        remaining = deadline - now()
        if remaining <= 0:
            raise WatchError('CHECK_BUDGET_EXPIRED')
        return get(url, min(10, remaining))

    observed = {'schema': 1, 'checked_at_unix': int(time.time()), 'sources': []}
    for source in manifest['sources']:
        repository = source['repository']
        head_data = bounded_get(f"https://api.github.com/repos/{repository}/commits/{source['branch']}")
        if head_data is None:
            raise WatchError('UPSTREAM_HEAD_MISSING')
        try:
            head = json.loads(head_data)['sha']
        except (ValueError, KeyError, TypeError):
            raise WatchError('UPSTREAM_HEAD_INVALID') from None
        if not isinstance(head, str) or not SHA.fullmatch(head):
            raise WatchError('UPSTREAM_HEAD_INVALID')
        result = {key: source[key] for key in ('name', 'repository', 'reference_commit',
                                               'reference_scope')}
        result.update(head_commit=head, files=[])
        for path in source['paths']:
            prefix = f'https://raw.githubusercontent.com/{repository}'
            reference_data = bounded_get(f"{prefix}/{source['reference_commit']}/{path}")
            current_data = reference_data if head == source['reference_commit'] else bounded_get(
                f'{prefix}/{head}/{path}')
            reference, current = file_digest(reference_data), file_digest(current_data)
            if not reference['present'] and not current['present']:
                raise WatchError('MONITORED_PATH_MISSING')
            result['files'].append({'path': path, 'reference': reference, 'current': current,
                                    'changed_from_reference': reference != current})
            if path.endswith('baileys-version.json'):
                result['advertised_versions'] = {'reference': version_decode(reference_data),
                    'current': version_decode(current_data), 'fallback_used': False,
                    'auto_adopted': False}
        observed['sources'].append(result)
    return observed


def compare(observed, previous=None):
    old = {source['name']: source for source in (previous or {}).get('sources', [])}
    historical, changes = [], []
    for source in observed['sources']:
        prior = {item['path']: item['current'] for item in old.get(source['name'], {}).get('files', [])}
        for item in source['files']:
            key = f"{source['name']}:{item['path']}"
            if item['changed_from_reference']:
                historical.append(key)
            if previous is not None and prior.get(item['path']) != item['current']:
                changes.append(key)
    return {'status': 'REVIEW_REQUIRED' if historical or changes else 'NO_MONITORED_DRIFT',
            'first_observation': previous is None, 'historical_reference_drift': historical,
            'changes_since_observation': changes, 'compatibility_approved': False,
            'runtime_version_changed': False}


def private_file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
            info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > MAX_REPORT):
        raise WatchError('STATE_FILE_UNSAFE')


@contextlib.contextmanager
def locked_state(path):
    if not path.is_absolute():
        raise WatchError('STATE_PATH_INVALID')
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise WatchError('STATE_DIRECTORY_UNSAFE')
    lock = path / 'watch.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        private_file(lock)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise WatchError('ALREADY_RUNNING') from None
        yield
    finally:
        os.close(fd)


def atomic_json(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    if len(data) > MAX_REPORT:
        raise WatchError('REPORT_TOO_LARGE')
    fd, name = tempfile.mkstemp(prefix='.watch-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def check(manifest, state, get=fetch):
    with locked_state(state):
        previous_path = state / 'observed.json'
        previous = None
        try:
            if previous_path.exists() or previous_path.is_symlink():
                private_file(previous_path)
                previous = json.loads(previous_path.read_bytes())
            observation = observe(manifest, get)
            result = compare(observation, previous)
            result['observation'] = observation
        except (WatchError, ValueError, TypeError, KeyError) as error:
            reason = str(error) if isinstance(error, WatchError) else 'STATE_OR_SOURCE_INVALID'
            atomic_json(state / 'last_attempt.json', {'status': 'FAILED', 'reason': reason,
                'checked_at_unix': int(time.time()), 'compatibility_approved': False})
            raise WatchError(reason) from None
        atomic_json(state / 'report.json', result)
        atomic_json(previous_path, observation)
        atomic_json(state / 'last_attempt.json', {'status': result['status'],
            'checked_at_unix': observation['checked_at_unix'], 'compatibility_approved': False})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=HERE / 'sources.json')
    parser.add_argument('--state-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(manifest_read(args.manifest), args.state_dir)
        print(json.dumps({key: value for key, value in result.items() if key != 'observation'}))
        return 3 if result['status'] == 'REVIEW_REQUIRED' else 0
    except (WatchError, OSError, ValueError) as error:
        print(json.dumps({'status': 'FAILED', 'reason': str(error) if isinstance(error, WatchError)
                          else 'LOCAL_STATE_FAILED', 'compatibility_approved': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

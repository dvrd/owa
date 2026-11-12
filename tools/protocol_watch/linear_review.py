#!/usr/bin/env python3
"""Create one human review issue per public monitored content snapshot. No agent."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('protocol_watch', HERE/'watch.py')
watch = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(watch)
PROJECT = 'b16b3039-a8cd-4080-adc2-d032669d0365'
TEAM = 'f8cf5dbc-16dd-445e-ba0c-b3950e31f13b'
BACKLOG = 'dd80a97e-0581-4d76-b659-83b1ec927019'
RUN = re.compile(r'https://github\.com/dvrd/owa/actions/runs/[0-9]+')
HEX = re.compile(r'[0-9a-f]{64}')
LOOKUP = '''query($ids:[ID!]!){issues(filter:{id:{in:$ids}},includeArchived:true,first:2){
 nodes{id identifier url description project{id}}}}'''
CREATE = '''mutation($input:IssueCreateInput!){issueCreate(input:$input){success}}'''


class ReviewError(Exception): pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): return None


def request(query, variables):
    key = os.environ.get('LINEAR_API', '').strip()
    if not key or '\n' in key or '\r' in key:
        raise ReviewError('LINEAR_CREDENTIAL_MISSING')
    body = json.dumps({'query': query, 'variables': variables}).encode()
    req = urllib.request.Request('https://api.linear.app/graphql', data=body, headers={
        'Authorization': key, 'Content-Type': 'application/json'})
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as response:
            data = response.read(watch.MAX_REPORT+1)
        if len(data) > watch.MAX_REPORT: raise ValueError()
        value = json.loads(data)
        if value.get('errors'): raise ReviewError('LINEAR_API_REJECTED')
        if not isinstance(value.get('data'), dict): raise ValueError()
        return value['data']
    except (OSError, ValueError, TypeError):
        # Never return response bodies, headers, credentials or raw API errors.
        raise ReviewError('LINEAR_REQUEST_FAILED') from None


def digest(value):
    if not isinstance(value, dict) or set(value) != {'present', 'bytes', 'sha256'}:
        raise ReviewError('REPORT_DIGEST_INVALID')
    present, size, sha = value['present'], value['bytes'], value['sha256']
    if type(present) is not bool or type(size) is not int or not 0 <= size <= watch.MAX_BYTES:
        raise ReviewError('REPORT_DIGEST_INVALID')
    if (present and (not isinstance(sha, str) or not HEX.fullmatch(sha))) or \
            (not present and (size != 0 or sha is not None)):
        raise ReviewError('REPORT_DIGEST_INVALID')
    return value


def snapshot(report):
    manifest = watch.manifest_read(HERE/'sources.json')
    sources = report['observation']['sources']
    if len(sources) != len(manifest['sources']): raise ReviewError('REPORT_SOURCES_INVALID')
    canonical, changed = [], []
    for actual, expected in zip(sources, manifest['sources']):
        if any(actual.get(k) != expected[k] for k in ('name', 'repository', 'reference_commit')):
            raise ReviewError('REPORT_SOURCE_INVALID')
        if not isinstance(actual.get('head_commit'), str) or not watch.SHA.fullmatch(actual['head_commit']):
            raise ReviewError('REPORT_HEAD_INVALID')
        files = actual['files']
        if [item['path'] for item in files] != expected['paths']:
            raise ReviewError('REPORT_PATHS_INVALID')
        entries = []
        for item in files:
            reference, current = digest(item['reference']), digest(item['current'])
            if item.get('changed_from_reference') is not (reference != current):
                raise ReviewError('REPORT_CHANGE_INVALID')
            entries.append({'path': item['path'], 'reference': reference, 'current': current})
            if reference != current: changed.append((actual, item))
        canonical.append({'name': actual['name'], 'repository': actual['repository'],
                          'reference_commit': actual['reference_commit'], 'files': entries})
    if report.get('compatibility_approved') is not False or report.get('runtime_version_changed') is not False:
        raise ReviewError('REPORT_POLICY_INVALID')
    if report['status'] == 'NO_MONITORED_DRIFT' and changed:
        raise ReviewError('REPORT_STATUS_INVALID')
    fingerprint = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return fingerprint, changed


def ticket(report, run_url):
    if not RUN.fullmatch(run_url): raise ReviewError('RUN_URL_INVALID')
    fingerprint, changed = snapshot(report)
    # Linear rejects UUIDv5 IDs. Retain deterministic idempotency with the UUIDv4
    # version/variant shape required by its issue-create validator.
    seed = hashlib.sha256((PROJECT+'/owa-protocol-review/v1/'+fingerprint).encode()).digest()[:16]
    issue_id = str(uuid.UUID(bytes=seed, version=4))
    marker = 'owa-protocol-drift:v1:'+fingerprint
    lines = [
        'Review public upstream protocol changes detected by OWA. No automated agent or fix was run.',
        '', 'Evidence: '+run_url, '',
        'Hash differences do not establish a protocol regression or compatibility. '
        'The historical Baileys pin is a wire reference; the whatsmeow pin is a certificate oracle, not full Odin parity.',
        '', '## Monitored differences from reference', '']
    for source, item in changed:
        repo, path = source['repository'], item['path']
        lines.extend([
            f"- {source['name']}: `{path}`",
            f"  - [reference](https://github.com/{repo}/blob/{source['reference_commit']}/{path}) / "
            f"[observed](https://github.com/{repo}/blob/{source['head_commit']}/{path})",
            f"  - SHA256: `{item['reference']['sha256']}` → `{item['current']['sha256']}`"])
    if not changed:
        lines.append('No current reference drift; observation history changed. Inspect the attached run report.')
    lines.extend(['', '## Human review and follow-up', '',
        '1. Inspect the actual immutable upstream diffs and determine whether our implementation is affected.',
        '2. Record relevant changes, harmless differences and remaining uncertainties.',
        '3. Create scoped Webtools fix issues, dependencies and regression/qualification checks for actionable gaps.',
        '4. Close this review only after triage and follow-up organization are complete. Do not auto-adopt protocol versions or roll back account state.',
        '', 'Snapshot fingerprint: `'+fingerprint+'`', '', marker])
    return issue_id, marker, {
        'id': issue_id, 'title': f'OWA: review upstream protocol changes ({fingerprint[:12]})',
        'description': '\n'.join(lines), 'projectId': PROJECT, 'teamId': TEAM,
        'stateId': BACKLOG, 'priority': 3}


def lookup(api, issue_id, marker):
    nodes = api(LOOKUP, {'ids': [issue_id]})['issues']['nodes']
    if not nodes: return None
    if len(nodes) != 1: raise ReviewError('LINEAR_LOOKUP_INVALID')
    item = nodes[0]
    if item['id'] != issue_id or item['project']['id'] != PROJECT or marker not in item['description']:
        raise ReviewError('LINEAR_BINDING_MISMATCH')
    if not re.fullmatch(r'OKAMI-[0-9]+', item['identifier']) or not \
            re.fullmatch(r'https://linear\.app/devoured/issue/OKAMI-[0-9]+(?:/[A-Za-z0-9_-]+)?', item['url']):
        raise ReviewError('LINEAR_ISSUE_INVALID')
    return {'identifier': item['identifier'], 'url': item['url']}


def track(report, run_url, api=request):
    if report.get('status') not in ('REVIEW_REQUIRED', 'NO_MONITORED_DRIFT'):
        raise ReviewError('SCAN_NOT_SUCCESSFUL')
    # Even a no-drift report must be source/path/policy validated before skipping.
    issue_id, marker, payload = ticket(report, run_url)
    if report['status'] == 'NO_MONITORED_DRIFT':
        return {'status': 'NO_REVIEW_NEEDED', 'compatibility_approved': False}
    found = lookup(api, issue_id, marker)
    if found: return {'status': 'EXISTING', **found, 'compatibility_approved': False}
    try:
        if api(CREATE, {'input': payload})['issueCreate']['success'] is not True:
            raise ReviewError('LINEAR_CREATE_UNCONFIRMED')
    except ReviewError as error:
        # A lost response may hide a successful mutation. Query only; never replay
        # the create in this invocation. Future runs use the exact same UUID.
        found = lookup(api, issue_id, marker)
        if found: return {'status': 'EXISTING', **found, 'compatibility_approved': False}
        if str(error) == 'LINEAR_API_REJECTED': raise
        raise ReviewError('LINEAR_CREATE_OUTCOME_UNKNOWN') from None
    found = lookup(api, issue_id, marker)
    if not found: raise ReviewError('LINEAR_CREATE_NOT_VERIFIED')
    return {'status': 'CREATED', **found, 'compatibility_approved': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run-url', required=True)
    args = parser.parse_args()
    try:
        with args.report.open('rb') as stream: data = stream.read(watch.MAX_REPORT+1)
        if len(data) > watch.MAX_REPORT: raise ReviewError('REPORT_TOO_LARGE')
        result = track(json.loads(data), args.run_url)
    except ReviewError as error:
        result = {'status': 'FAILED', 'reason': str(error)}
    except (OSError, ValueError, TypeError, KeyError):
        result = {'status': 'FAILED', 'reason': 'TRACKING_METADATA_INVALID'}
    watch.atomic_json(args.output, result)
    if result['status'] != 'FAILED' and os.environ.get('GITHUB_STEP_SUMMARY'):
        text = ('Protocol scan: '+result['status']+'.\n')
        if result.get('url'): text += '\nHuman review: ['+result['identifier']+']('+result['url']+').\n'
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream: stream.write(text)
    print(json.dumps(result))
    return 2 if result['status'] == 'FAILED' else 0


if __name__ == '__main__': sys.exit(main())

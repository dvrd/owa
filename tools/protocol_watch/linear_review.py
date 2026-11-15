#!/usr/bin/env python3
"""Deduplicate per-file protocol findings; append-only triage metadata. No source adoption."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('protocol_watch', HERE/'watch.py')
watch = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(watch)
TRIAGE_SPEC = importlib.util.spec_from_file_location('protocol_triage', HERE/'triage.py')
triage = importlib.util.module_from_spec(TRIAGE_SPEC); TRIAGE_SPEC.loader.exec_module(triage)
PROJECT = 'b16b3039-a8cd-4080-adc2-d032669d0365'
TEAM = 'f8cf5dbc-16dd-445e-ba0c-b3950e31f13b'
BACKLOG = 'dd80a97e-0581-4d76-b659-83b1ec927019'
RUN = re.compile(r'https://github\.com/dvrd/owa/actions/runs/[0-9]+')
HEX = re.compile(r'[0-9a-f]{64}')
CREATE = '''mutation($input:IssueCreateInput!){issueCreate(input:$input){success}}'''
READY = 'd47c0045-e2ba-4bd5-a22b-d047f9cbb6a6'
FIELDS = 'id identifier url title description archivedAt state{type} project{id}'
SCAN = ('query($after:String){issues(filter:{project:{id:{eq:"'+PROJECT+'"}},or:['
        '{title:{contains:"OWA:"}},{description:{contains:"owa-protocol-drift:v1:"}},'
        '{description:{contains:"owa-protocol-review:v2"}},{comments:{some:{body:{contains:"owa-protocol-review:v2:begin"}}}}]},'
        'includeArchived:true,first:10,after:$after){nodes{'+FIELDS+'}pageInfo{hasNextPage endCursor}}}')
LOOKUP = 'query($ids:[ID!]!){issues(filter:{id:{in:$ids}},includeArchived:true,first:2){nodes{'+FIELDS+'}}}'
COMMENTS = '''query($id:String!,$after:String){issue(id:$id){id project{id}
 comments(first:20,after:$after){nodes{id body}pageInfo{hasNextPage endCursor}}}}'''
COMMENT_LOOKUP = '''query($id:ID!){comments(filter:{id:{eq:$id}},first:2){nodes{id body issue{id project{id}}}}}'''
COMMENT_CREATE = '''mutation($input:CommentCreateInput!){commentCreate(input:$input){success}}'''
BEGIN = 'owa-protocol-review:v2:begin'
END = 'owa-protocol-review:v2:end'
MAX_CALLS = 64
MAX_ISSUES = 200
LOCAL_ROOT = HERE.parent.parent
TERMINAL = ('completed','canceled','duplicate')



class ReviewError(Exception): pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): return None


def decode(data):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('DUPLICATE_JSON_KEY')
            value[key]=item
        return value
    def finite(_):raise ValueError('NONFINITE_JSON')
    return json.loads(data,object_pairs_hook=unique,parse_constant=finite)


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
        value = decode(data)
        if not isinstance(value,dict):raise ValueError()
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
            if not reference['present'] and not current['present']:raise ReviewError('REPORT_PATH_MISSING')
            if reference['sha256']==current['sha256'] and reference['bytes']!=current['bytes']:raise ReviewError('REPORT_DIGEST_INVALID')
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


def stable_id(namespace, values):
    encoded = json.dumps(values, sort_keys=True, separators=(',', ':'))
    seed = hashlib.sha256((PROJECT+'/'+namespace+'/'+encoded).encode()).digest()[:16]
    return str(uuid.UUID(bytes=seed, version=4))


def change_identity(repository, path, reference, current):
    # Neither observation heads/times/runs nor unrelated files enter this identity.
    value = [repository, path, reference['present'], reference['sha256'],
             current['present'], current['sha256']]
    return hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()


def manifest_paths():
    return {(s['repository'], p): s for s in watch.manifest_read(HERE/'sources.json')['sources']
            for p in s['paths']}


def assessment(source, item, verify_contract=True):
    value = item.get('assessment')
    if value is None:
        return {'schema': 1, 'kind': 'SPIKE', 'reason': 'ASSESSMENT_MISSING',
                'summary': 'Does this changed reference affect the local implementation? Impact is unassessed.',
                'source':source['name'],'path':item['path'],
                'local_targets': [], 'checks': ['Establish the affected contract and inspect local ownership.'],
                'acceptance': ['Record evidence for no action or a bounded implementation fix.'],
                'evidence': {'reference': item['reference'], 'current': item['current'],
                    'question':triage.OWNERS[(source['name'],item['path'])][2],
                    'server_compatibility_proven':False}}
    if not isinstance(value, dict) or set(value)!={'schema','kind','reason','summary','source','path','local_targets','checks','acceptance','evidence'} or type(value.get('schema')) is not int or value['schema'] != 1 or \
            value.get('kind') not in ('NO_ACTION', 'SPIKE', 'FIX'):
        raise ReviewError('ASSESSMENT_INVALID')
    if value.get('reason') not in triage.REASONS | {'ASSESSMENT_MISSING'}:
        raise ReviewError('ASSESSMENT_INVALID')
    if not isinstance(value.get('summary'), str) or not 1 <= len(value['summary']) <= 2000:
        raise ReviewError('ASSESSMENT_INVALID')
    if value.get('source', source['name']) != source['name'] or value.get('path', item['path']) != item['path']:
        raise ReviewError('ASSESSMENT_BINDING_INVALID')
    for key in ('checks', 'acceptance'):
        entries = value.get(key)
        if not isinstance(entries, list) or len(entries) > 32 or \
                any(not isinstance(x, str) or not 1 <= len(x) <= 1000 for x in entries):
            raise ReviewError('ASSESSMENT_INVALID')
    targets = value.get('local_targets')
    if not isinstance(targets, list) or len(targets) > 32:
        raise ReviewError('ASSESSMENT_INVALID')
    for target in targets:
        if not isinstance(target, dict) or set(target) != {'path', 'sha256'} or \
                not isinstance(target['path'], str) or len(target['path']) > 200 or \
                not all(watch.NAME.fullmatch(x) and x not in ('.', '..') for x in target['path'].split('/')) or \
                not isinstance(target['sha256'], str) or not HEX.fullmatch(target['sha256']):
            raise ReviewError('ASSESSMENT_INVALID')
    evidence = value.get('evidence')
    if not isinstance(evidence, dict) or evidence.get('reference') != item['reference'] or \
            evidence.get('current') != item['current']:
        raise ReviewError('ASSESSMENT_EVIDENCE_INVALID')
    if value['kind'] == 'FIX' and (not targets or not value['checks'] or not value['acceptance']):
        raise ReviewError('FIX_PROOF_REQUIRED')
    allowed_targets = triage.OWNERS[(source['name'],item['path'])][0]
    if any(x['path'] not in allowed_targets for x in targets):raise ReviewError('ASSESSMENT_TARGET_INVALID')
    harmless={'BYTE_IDENTICAL','LEXICALLY_EQUIVALENT','JSON_NORMALIZED_EQUIVALENT','ALREADY_IMPLEMENTED'}
    if (value['kind']=='NO_ACTION') != (value['reason'] in harmless):raise ReviewError('ASSESSMENT_KIND_INVALID')
    if (value['kind']=='FIX') != (value['reason']=='APPROVED_DICTIONARY_CONTRACT_GAP'):raise ReviewError('ASSESSMENT_KIND_INVALID')
    if value['reason']=='BYTE_IDENTICAL' and item['reference']!=item['current']:raise ReviewError('ASSESSMENT_KIND_INVALID')
    if value['kind']=='NO_ACTION' and [x['path'] for x in targets]!=list(allowed_targets):raise ReviewError('ASSESSMENT_TARGET_INVALID')
    if value['reason']=='ALREADY_IMPLEMENTED' and ((source['name'],item['path'])!=('baileys','src/WABinary/constants.ts') or evidence.get('local_table_matches')!='current' or evidence.get('server_compatibility_proven') is not False):raise ReviewError('ASSESSMENT_EVIDENCE_INVALID')
    if value['kind']=='FIX' or value['reason']=='LOCAL_DICTIONARY_CONTRACT_DRIFT':
        changes=evidence.get('changes');count=evidence.get('changed_count')
        if (source['name'],item['path'])!=('baileys','src/WABinary/constants.ts') or \
                [x['path'] for x in targets]!=list(allowed_targets) or type(evidence.get('table_count')) is not int or evidence['table_count']!=236 or \
                evidence.get('outside_tokens_equal') is not True or evidence.get('local_table_matches')!='reference' or \
                evidence.get('server_compatibility_proven') is not False or type(count) is not int or not 1<=count<=236 or \
                not isinstance(changes,list) or len(changes)!=min(count,32) or \
                evidence.get('changes_truncated') is not (count>32):raise ReviewError('FIX_PROOF_REQUIRED')
        all_indices=evidence.get('changed_indices')
        if not isinstance(all_indices,list) or len(all_indices)!=count or \
                any(type(x) is not int or not 0<=x<236 for x in all_indices) or \
                all_indices!=sorted(set(all_indices)):raise ReviewError('FIX_PROOF_REQUIRED')
        indices=[]
        for change in changes:
            if not isinstance(change,dict) or set(change)!={'index','old','new','old_sha256','new_sha256'} or \
                    type(change['index']) is not int or not 0<=change['index']<236 or \
                    any(not isinstance(change[k],str) or len(change[k])>128 for k in ['old','new']) or \
                    any(not isinstance(change[k],str) or not HEX.fullmatch(change[k]) for k in ['old_sha256','new_sha256']) or \
                    change['old_sha256']==change['new_sha256']:raise ReviewError('FIX_PROOF_REQUIRED')
            indices.append(change['index'])
        if indices!=all_indices[:32]:raise ReviewError('FIX_PROOF_REQUIRED')
    if value['kind']=='FIX':
        proof=evidence.get('approved_contract')
        required={'path','sha256','target_table_sha256','requirement','basis','trust_limit'}
        if not isinstance(proof,dict) or not required<=set(proof) or set(proof)-required-{'fixture'} or \
                proof['basis']!='explicit_reviewed_requirement_and_owned_indexed_comparison' or \
                not isinstance(proof['trust_limit'],str) or not 1<=len(proof['trust_limit'])<=500 or \
                evidence.get('static_regression')!='indexed_table_comparison':raise ReviewError('FIX_CONTRACT_REQUIRED')
        for key in ['reference_table_sha256','target_table_sha256','local_table_sha256']:
            if not isinstance(evidence.get(key),str) or not HEX.fullmatch(evidence[key]):raise ReviewError('FIX_CONTRACT_REQUIRED')
        if proof['target_table_sha256']!=evidence['target_table_sha256'] or \
                evidence['local_table_sha256']!=evidence['reference_table_sha256'] or \
                evidence['target_table_sha256']==evidence['reference_table_sha256']:raise ReviewError('FIX_CONTRACT_REQUIRED')
        records=[(proof,'tools/protocol_watch/contracts/','.json'),(proof['requirement'],'tools/protocol_watch/contracts/','.md')]
        if 'fixture' in proof:records.append((proof['fixture'],'tests/',None))
        for record,prefix,suffix in records:
            path=record.get('path') if isinstance(record,dict) else None
            if not isinstance(path,str) or not path.startswith(prefix) or \
                    (suffix and not path.endswith(suffix)) or \
                    not all(watch.NAME.fullmatch(x) and x not in ('.','..') for x in path.split('/')) or \
                    not isinstance(record.get('sha256'),str) or not HEX.fullmatch(record['sha256']):raise ReviewError('FIX_CONTRACT_REQUIRED')
        # Revalidate NEW claims against explicit source-owned policy; historical
        # machine coverage records remain source-bound evidence, not a lifetime monitor.
        if verify_contract and not triage.validate_approved_contract(value,LOCAL_ROOT):raise ReviewError('FIX_CONTRACT_INVALID')
    # All text is data inside the JSON machine section, never executable commands.
    try: encoded=json.dumps(value,allow_nan=False).encode()
    except (ValueError,TypeError):raise ReviewError('ASSESSMENT_INVALID') from None
    if len(encoded)>16384:raise ReviewError('ASSESSMENT_TOO_LARGE')
    return value


def findings(report):
    _, changed = snapshot(report)
    for source in report['observation']['sources']:
        for item in source['files']:
            if 'assessment' in item:assessment(source,item)
    result = []
    for source, item in changed:
        value = assessment(source, item)
        if value['kind'] == 'NO_ACTION': continue
        result.append(dict(id=change_identity(source['repository'], item['path'], item['reference'], item['current']),
            source=source['name'], repository=source['repository'], path=item['path'],
            reference=item['reference'], current=item['current'],
            reference_commit=source['reference_commit'], head_commit=source['head_commit'],
            assessment=value))
    return result


def machine_section(items, run_url):
    value = {'schema': 2, 'run': run_url, 'findings': items,
             'markers': ['owa-protocol-change:v2:'+item['id'] for item in items]}
    text = BEGIN+'\n\n```json\n'+json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n```\n\n'+END
    if len(text.encode()) > watch.MAX_REPORT: raise ReviewError('MACHINE_SECTION_TOO_LARGE')
    return text


def v2_coverage(body):
    result = {}
    if not isinstance(body, str) or len(body.encode()) > watch.MAX_REPORT: return result
    sections=re.findall(re.escape(BEGIN)+r'\n\n```json\n(.*?)\n```\n\n'+re.escape(END), body, re.S)
    if len(re.findall('^'+re.escape(BEGIN)+'$',body,re.M))!=len(sections) or len(re.findall('^'+re.escape(END)+'$',body,re.M))!=len(sections):raise ReviewError('LINEAR_V2_INVALID')
    for text in sections:
        try:
            value = decode(text)
            if set(value) != {'schema', 'run', 'findings', 'markers'} or type(value['schema']) is not int or value['schema'] != 2 or \
                    not RUN.fullmatch(value['run']) or not isinstance(value['findings'], list) or \
                    not 1 <= len(value['findings']) <= 32: raise ValueError()
            found = {}; allowed = manifest_paths()
            for item in value['findings']:
                if set(item) != {'id','source','repository','path','reference','current',
                                 'reference_commit','head_commit','assessment'}: raise ValueError()
                source = allowed[(item['repository'], item['path'])]
                if item['source'] != source['name'] or item['reference_commit'] != source['reference_commit'] or \
                        not watch.SHA.fullmatch(item['head_commit']): raise ValueError()
                ref, cur = digest(item['reference']), digest(item['current'])
                if ref == cur or item['id'] != change_identity(item['repository'], item['path'], ref, cur):
                    raise ValueError()
                if assessment(source, item,verify_contract=False)['kind']=='NO_ACTION':raise ValueError()
                if item['id'] in found: raise ValueError()
                found[item['id']] = item
            if value['markers'] != ['owa-protocol-change:v2:'+x['id'] for x in value['findings']]:raise ValueError()
            result.update(found)
        except (ValueError, TypeError, KeyError, ReviewError):raise ReviewError('LINEAR_V2_INVALID') from None
    return result


def legacy_coverage(issue):
    """Only exact v1 generator provenance/links/hashes can cover legacy drift."""
    body = issue['description']
    # Linear normalizes generator Markdown; accept only these exact transformations.
    body=re.sub(r'^\* ', '- ', body, flags=re.M)
    body=re.sub(r'^  \* ', '  - ', body, flags=re.M)
    body=re.sub(r'\((<https://github\.com/[^<>\s]+>)\)',lambda m:'('+m[1][1:-1]+')',body)
    body=re.sub(r'^Evidence: \[(https://github\.com/dvrd/owa/actions/runs/[0-9]+)\]\(\1\)$',r'Evidence: \1',body,flags=re.M)
    matches = re.findall(r'^owa-protocol-drift:v1:([0-9a-f]{64})$', body, re.M)
    if len(matches) != 1: return {}
    fingerprint = matches[0]
    expected = str(uuid.UUID(bytes=hashlib.sha256((PROJECT+'/owa-protocol-review/v1/'+fingerprint).encode()).digest()[:16],version=4))
    if issue['id'] != expected or \
            body.splitlines().count('Review public upstream protocol changes detected by OWA. No automated agent or fix was run.')!=1 or \
            re.findall(r'^Snapshot fingerprint: `([0-9a-f]{64})`$',body,re.M) != [fingerprint] or \
            len(re.findall(r'^Evidence: https://github\.com/dvrd/owa/actions/runs/[0-9]+$',body,re.M))!=1: return {}
    try: text = body.split('## Monitored differences from reference\n\n',1)[1].split('\n## Human review and follow-up',1)[0]
    except IndexError: return {}
    pattern = re.compile(r'- ([A-Za-z0-9_.-]+): `([^`\n]+)`\n'
        r'  - \[reference\]\(https://github\.com/([^/\s)]+/[^/\s)]+)/blob/([0-9a-f]{40})/([^\s)]+)\) / '
        r'\[observed\]\(https://github\.com/([^/\s)]+/[^/\s)]+)/blob/([0-9a-f]{40})/([^\s)]+)\)\n'
        r'  - SHA256: `(None|[0-9a-f]{64})` → `(None|[0-9a-f]{64})`')
    result = {}; allowed = manifest_paths(); remaining = text.strip(); heads = {};last_index=-1
    while remaining:
        match = pattern.match(remaining)
        if not match: return {}
        name,path,repo,refcommit,refpath,otherrepo,head,otherpath,refsha,cursha=match.groups()
        source=allowed.get((repo,path))
        if source is None or name != source['name'] or refcommit != source['reference_commit'] or \
                refpath != path or otherpath != path or otherrepo != repo or heads.get(repo,head) != head:
            return {}
        index=list(allowed).index((repo,path))
        if index<=last_index:return {}
        last_index=index;heads[repo]=head
        ref=dict(present=refsha!='None',sha256=None if refsha=='None' else refsha)
        cur=dict(present=cursha!='None',sha256=None if cursha=='None' else cursha)
        if ref==cur or not (ref['present'] or cur['present']): return {}
        identity=change_identity(repo,path,ref,cur)
        if identity in result:return {}
        result[identity]=dict(id=identity,source=name,repository=repo,path=path,reference=ref,current=cur,reference_commit=refcommit,head_commit=head)
        remaining=remaining[match.end():].strip()
    return result


def validate_issue(item):
    if not isinstance(item, dict) or item.get('project',{}).get('id') != PROJECT or \
            not isinstance(item.get('id'),str) or not isinstance(item.get('description'),str) or \
            not isinstance(item.get('title'),str) or not isinstance(item.get('state'),dict) or 'archivedAt' not in item or \
            item['state'].get('type') not in ('triage','backlog','unstarted','started',*TERMINAL):
        raise ReviewError('LINEAR_ISSUE_INVALID')
    try: uuid.UUID(item['id'])
    except ValueError: raise ReviewError('LINEAR_ISSUE_INVALID') from None
    if not re.fullmatch(r'OKAMI-[0-9]+',item.get('identifier','')) or not \
            re.fullmatch(r'https://linear\.app/devoured/issue/OKAMI-[0-9]+(?:/[A-Za-z0-9_-]+)?',item.get('url','')):
        raise ReviewError('LINEAR_ISSUE_INVALID')
    return item


class BoundedAPI:
    def __init__(self, api): self.api=api;self.calls=0;self.bytes=0;self.deadline=time.monotonic()+120
    def __call__(self, query, variables):
        if time.monotonic()>=self.deadline:raise ReviewError('LINEAR_SCAN_BUDGET')
        self.calls+=1
        if self.calls>MAX_CALLS:raise ReviewError('LINEAR_SCAN_BOUND')
        value=self.api(query,variables)
        try: self.bytes+=len(json.dumps(value,allow_nan=False).encode())
        except (TypeError,ValueError):raise ReviewError('LINEAR_RESPONSE_INVALID') from None
        if self.bytes>watch.MAX_REPORT:raise ReviewError('LINEAR_SCAN_BOUND')
        return value


def pages(fetch):
    after=None;seen=set()
    while True:
        value=fetch(after)
        if not isinstance(value,dict) or not isinstance(value.get('nodes'),list) or not isinstance(value.get('pageInfo'),dict):raise ReviewError('LINEAR_PAGINATION_INVALID')
        nodes,info=value['nodes'],value['pageInfo']
        if not isinstance(nodes,list) or type(info.get('hasNextPage')) is not bool:raise ReviewError('LINEAR_PAGINATION_INVALID')
        yield nodes
        if not info['hasNextPage']:return
        cursor=info.get('endCursor')
        if not isinstance(cursor,str) or not cursor or cursor in seen or len(cursor)>512:
            raise ReviewError('LINEAR_PAGINATION_INVALID')
        seen.add(cursor);after=cursor


def merge_coverage(target, incoming):
    for identity,item in incoming.items():
        if target.get(identity,{}).get('assessment',{}).get('kind')!='FIX':target[identity]=item


def issue_coverage(issue):
    own=legacy_coverage(issue)
    current=v2_coverage(issue['description'])
    if current:
        kinds={x['assessment']['kind'] for x in current.values()}
        if len(kinds)!=1 or stable_id('owa-protocol-review/v2',[next(iter(kinds)),sorted(current)])!=issue['id']:
            raise ReviewError('LINEAR_V2_BINDING_MISMATCH')
        merge_coverage(own,current)
    return own


def comment_identity(issue_id, items):
    assessment_ids=sorted([x['id'],x['assessment']['kind'],x['assessment']['reason'],'assessment-v1'] for x in items)
    return stable_id('owa-protocol-review-comment/v2',[issue_id,assessment_ids])


def comments(api, issue):
    result={};seen=set()
    def fetch(after):
        value=api(COMMENTS,{'id':issue['id'],'after':after})['issue']
        if value['id']!=issue['id'] or value['project']['id']!=PROJECT:raise ReviewError('LINEAR_BINDING_MISMATCH')
        return value['comments']
    for nodes in pages(fetch):
        for comment in nodes:
            if not isinstance(comment.get('id'),str) or comment['id'] in seen or not isinstance(comment.get('body'),str):
                raise ReviewError('LINEAR_COMMENTS_INVALID')
            seen.add(comment['id']);found=v2_coverage(comment['body'])
            if found and comment['id']!=comment_identity(issue['id'],list(found.values())):raise ReviewError('LINEAR_V2_BINDING_MISMATCH')
            merge_coverage(result,found)
    return result


def scan(api):
    issues=[];covered={};seen=set()
    for nodes in pages(lambda after:api(SCAN,{'after':after})['issues']):
        for raw in nodes:
            item=validate_issue(raw)
            if item['id'] in seen or len(issues)>=MAX_ISSUES:raise ReviewError('LINEAR_SCAN_BOUND')
            seen.add(item['id']);issues.append(item)
            own=issue_coverage(item);merge_coverage(own,comments(api,item))
            item['_coverage']=own;merge_coverage(covered,own)
    return issues,covered


def fresh_issue(api, issue_id):
    nodes=api(LOOKUP,{'ids':[issue_id]})['issues']['nodes']
    if not nodes:return None
    if len(nodes)!=1 or nodes[0]['id']!=issue_id:raise ReviewError('LINEAR_LOOKUP_INVALID')
    return validate_issue(nodes[0])


def public_issue(item):return {'identifier':item['identifier'],'url':item['url']}


def readable_findings(items):
    lines=[]
    for item in items:
        a=item['assessment']
        lines.append('- '+item['source']+': `'+item['path']+'` — '+a['summary'])
        if a['evidence'].get('question'):lines.append('  - Question: '+a['evidence']['question'])
        lines.extend('  - Check: '+x for x in a['checks'])
        lines.extend('  - Accept: '+x for x in a['acceptance'])
        lines.extend('  - Local target: `'+x['path']+'` SHA256 `'+x['sha256']+'`' for x in a['local_targets'])
        if 'changed_indices' in a['evidence']:
            lines.append('  - Complete changed indices ('+str(a['evidence']['changed_count'])+'): '+json.dumps(a['evidence']['changed_indices']))
            lines.append('  - Excerpts are capped at32; truncated: '+str(a['evidence']['changes_truncated']).lower())
        lines.append('  - Immutable reference: https://github.com/'+item['repository']+'/blob/'+item['reference_commit']+'/'+item['path'])
        lines.append('  - Immutable observed: https://github.com/'+item['repository']+'/blob/'+item['head_commit']+'/'+item['path'])
    return lines


def payload_for(items, run_url):
    kind=items[0]['assessment']['kind']
    issue_id=stable_id('owa-protocol-review/v2',[kind,sorted(x['id'] for x in items)])
    first=items[0];a=first['assessment']
    if kind=='FIX':title='OWA: FIX '+a['summary'][:150]
    else:title='OWA: SPIKE Does '+first['source']+' drift affect our implementation? ('+a['reason'][:60]+')'
    lines=[a['summary'],'','## '+('Implementation evidence' if kind=='FIX' else 'Question and investigation checklist'),'']
    lines+=readable_findings(items)
    lines+=['','Hash drift alone is not a compatibility decision. No automated source adoption, runtime version change or completed review is implied.','',machine_section(items,run_url)]
    payload=dict(id=issue_id,title=title,description='\n'.join(lines),projectId=PROJECT,teamId=TEAM,
                 stateId=READY if kind=='FIX' else BACKLOG,priority=2 if kind=='FIX' else 3)
    if len(json.dumps(payload).encode())>watch.MAX_REPORT:raise ReviewError('LINEAR_PAYLOAD_BOUND')
    return payload


def ticket(report,run_url):
    if not RUN.fullmatch(run_url):raise ReviewError('RUN_URL_INVALID')
    items=findings(report)
    if not items:raise ReviewError('NO_FINDINGS')
    payload=payload_for(items,run_url)
    return payload['id'],'owa-protocol-change:v2:'+items[0]['id'],payload


def lookup_comment(api, comment_id, issue_id, body):
    expected=v2_coverage(body)
    if not expected or len(body.encode())>watch.MAX_REPORT:raise ReviewError('LINEAR_COMMENT_BINDING_MISMATCH')
    nodes=api(COMMENT_LOOKUP,{'id':comment_id})['comments']['nodes']
    if not nodes:return False
    if len(nodes)!=1:raise ReviewError('LINEAR_COMMENT_BINDING_MISMATCH')
    value=nodes[0]
    if value.get('id')!=comment_id or value.get('issue',{}).get('id')!=issue_id or \
            value['issue'].get('project',{}).get('id')!=PROJECT or \
            v2_coverage(value.get('body'))!=expected:raise ReviewError('LINEAR_COMMENT_BINDING_MISMATCH')
    return True


def append_findings(api, issue, items, run_url, promote=False):
    # Re-read state and coverage. Append-only comments cannot overwrite human text.
    current=fresh_issue(api,issue['id'])
    if current is None or current.get('archivedAt') or current['state']['type'] in TERMINAL:
        return None
    covered=issue_coverage(current);merge_coverage(covered,comments(api,current))
    items=[x for x in items if x['id'] not in covered or (promote and covered[x['id']].get('assessment',{}).get('kind')!='FIX')]
    if not items:return {'status':'EXISTING',**public_issue(current)}
    heading='## FIX readiness: exact proof and acceptance' if promote else '## SPIKE: new evidence; investigation remains open'
    body=heading+'\n\n'+'\n'.join(readable_findings(items))+'\n\n'+machine_section(items,run_url)
    if len(body.encode())>watch.MAX_REPORT:raise ReviewError('LINEAR_PAYLOAD_BOUND')
    cid=comment_identity(current['id'],items)
    if lookup_comment(api,cid,current['id'],body):return {'status':'EXISTING',**public_issue(current)}
    error=None
    try:
        if api(COMMENT_CREATE,{'input':dict(id=cid,issueId=current['id'],body=body,doNotSubscribeToIssue=True)})['commentCreate']['success'] is not True:
            raise ReviewError('LINEAR_COMMENT_UNCONFIRMED')
    except ReviewError as caught:error=caught
    # One read after mutation; no mutation replay after any uncertain result.
    if not lookup_comment(api,cid,current['id'],body):
        if error and str(error)=='LINEAR_API_REJECTED':raise error
        raise ReviewError('LINEAR_COMMENT_OUTCOME_UNKNOWN')
    return {'status':'UPDATED',**public_issue(current),'ready_findings':[x['id'] for x in items] if promote else []}


def create_findings(api,items,run_url):
    payload=payload_for(items,run_url);wanted={x['id'] for x in items}
    current=fresh_issue(api,payload['id'])
    if current is not None:
        if not wanted.issubset(v2_coverage(current['description'])):raise ReviewError('LINEAR_BINDING_MISMATCH')
        return {'status':'EXISTING',**public_issue(current)}
    error=None
    try:
        if api(CREATE,{'input':payload})['issueCreate']['success'] is not True:raise ReviewError('LINEAR_CREATE_UNCONFIRMED')
    except ReviewError as caught:error=caught
    current=fresh_issue(api,payload['id'])
    if current is None:
        if error and str(error)=='LINEAR_API_REJECTED':raise error
        raise ReviewError('LINEAR_CREATE_OUTCOME_UNKNOWN')
    if not wanted.issubset(v2_coverage(current['description'])):raise ReviewError('LINEAR_BINDING_MISMATCH')
    return {'status':'CREATED' if error is None else 'EXISTING',**public_issue(current)}


def track(report,run_url,api=request):
    if report.get('status') not in ('REVIEW_REQUIRED','NO_MONITORED_DRIFT'):raise ReviewError('SCAN_NOT_SUCCESSFUL')
    if not RUN.fullmatch(run_url):raise ReviewError('RUN_URL_INVALID')
    items=findings(report)
    if report['status']=='NO_MONITORED_DRIFT' or not items:
        return {'status':'NO_REVIEW_NEEDED','compatibility_approved':False}
    api=BoundedAPI(api);issues,covered=scan(api)
    results=[]
    pending=[]
    for item in items:
        identity=item['id']
        if identity not in covered:pending.append(item);continue
        if item['assessment']['kind']!='FIX' or covered[identity].get('assessment',{}).get('kind')=='FIX':continue
        owners=[i for i in issues if identity in i['_coverage']]
        if any(i.get('archivedAt') or i['state']['type'] in TERMINAL for i in owners):continue
        if owners:
            result=append_findings(api,sorted(owners,key=lambda i:i['id'])[0],[item],run_url,promote=True)
            if result is not None:results.append(result)
    items=pending
    if not items and not results:return {'status':'EXISTING','compatibility_approved':False}
    groups={}
    for item in items:
        key=(item['assessment']['kind'],item['source']) if item['assessment']['kind']=='SPIKE' else ('FIX',item['id'])
        groups.setdefault(key,[]).append(item)
    for (kind,source),group in sorted(groups.items()):
        related=[i for i in issues if not i.get('archivedAt') and i['state']['type'] not in TERMINAL and
                 any(x['source']==group[0]['source'] and x.get('assessment',{}).get('kind','SPIKE')=='SPIKE'
                     for x in i['_coverage'].values())]
        result=None
        if kind=='SPIKE' and related:result=append_findings(api,sorted(related,key=lambda i:i['id'])[0],group,run_url)
        if result is None:result=create_findings(api,group,run_url)
        results.append(result)
    status='UPDATED' if any(x['status']=='UPDATED' for x in results) else 'CREATED' if any(x['status']=='CREATED' for x in results) else 'EXISTING'
    value={'status':status,'issues':results,'compatibility_approved':False,**public_issue(results[0])}
    if len(json.dumps(value).encode())>watch.MAX_REPORT:raise ReviewError('TRACKING_OUTPUT_BOUND')
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--run-url',required=True);args=parser.parse_args()
    try:
        with args.report.open('rb') as stream:data=stream.read(watch.MAX_REPORT+1)
        if len(data)>watch.MAX_REPORT:raise ReviewError('REPORT_TOO_LARGE')
        result=track(decode(data),args.run_url)
    except ReviewError as error:result={'status':'FAILED','reason':str(error)}
    except (OSError,ValueError,TypeError,KeyError):result={'status':'FAILED','reason':'TRACKING_METADATA_INVALID'}
    watch.atomic_json(args.output,result)
    if result['status']!='FAILED' and os.environ.get('GITHUB_STEP_SUMMARY'):
        text='Protocol scan: '+result['status']+'.\n'
        for issue in result.get('issues',[]):text+='\nTriage: ['+issue['identifier']+']('+issue['url']+').\n'
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:stream.write(text)
    print(json.dumps(result));return 2 if result['status']=='FAILED' else 0


if __name__=='__main__':sys.exit(main())

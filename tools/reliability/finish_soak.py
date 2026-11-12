#!/usr/bin/env python3
"""Metadata-only, idempotent soak completion gate; never opens session/account files."""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

LIMIT = 65536
PROJECT = 'b16b3039-a8cd-4080-adc2-d032669d0365'
HASH = re.compile(r'[0-9a-f]{64}')
RUN = re.compile(r'[0-9a-f]{32}')
KNOWN_FAILURES = {'CANARY_EVIDENCE_MISSING','CANARY_COVERAGE_INCOMPLETE',
    'CANARY_DURATION_INCOMPLETE','HEALTH_COVERAGE_INCOMPLETE','CHILD_STALLED',
    'CHILD_FAILED','CHILD_PROTOCOL_INVALID','CHILD_TIMEOUT','SUPERVISOR_ERROR',
    'BINARY_CHANGED','INTERRUPTED','STOPPED','FAILED'}

class GateError(Exception): pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise GateError('DUPLICATE_JSON_FIELD')
        result[key] = value
    return result


def checked_file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise GateError('METADATA_FILE_UNSAFE')
    return info


def private_directory(path, create=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: raise GateError('DIRECTORY_INVALID')
    if create: path.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd); raise GateError('DIRECTORY_UNSAFE')
    return fd


def read_json(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as stream:
        info = checked_file(stream.fileno()); data = stream.read(LIMIT+1)
    if len(data) > LIMIT: raise GateError('METADATA_LIMIT')
    value = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(value, dict): raise GateError('METADATA_INVALID')
    return value, info


def write_json(directory, name, value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    if len(data) > LIMIT: raise GateError('RECEIPT_LIMIT')
    temporary = '.finish-'+secrets.token_hex(12)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try: os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError: pass


def number(value, lower=0, upper=0xffffffffffffffff, integer=False):
    allowed = (int,) if integer else (int, float)
    if type(value) not in allowed or not lower <= value <= upper or not math.isfinite(value):
        raise GateError('NUMERIC_EVIDENCE_INVALID')
    return value


def evaluate(config, status, progress, confirmation, expected, config_mtime, now, status_mtime=None):
    if any(not isinstance(v,dict) for v in (config,status,progress,confirmation,expected)):
        raise GateError('METADATA_INVALID')
    if status.get('run_id') != expected['run_id']: raise GateError('RUN_BINDING_MISMATCH')
    phase = status.get('phase')
    if phase in ('FAILED', 'STOPPED', 'INTERRUPTED'):
        reason = status.get('reason', phase)
        raise GateError(reason if isinstance(reason,str) and reason in KNOWN_FAILURES else 'RUN_FAILED')
    if phase in ('STARTING', 'RUNNING', 'PREPARED'):
        last=progress.get('last_health_unix') if progress.get('run_id')==expected['run_id'] else None
        if last is None: last=status.get('started_unix',status_mtime or config_mtime)
        if last is not None and now-number(last) > 180: raise GateError('ACTIVE_RUN_STALE')
        return {'phase':'WAITING'}
    if phase != 'COMPLETE': raise GateError('RUN_PHASE_INVALID')
    if status.get('reason') or status.get('error') or progress.get('errors',0):
        raise GateError('RUN_ERROR_PRESENT')
    if (type(config.get('schema')) is not int or config.get('schema') != 1 or
            config.get('mode') != 'watch' or
            type(config.get('duration_seconds')) is not int or
            type(config.get('canary_interval_seconds')) is not int or
            config.get('binary_sha256') != expected['binary_sha256'] or
            config.get('duration_seconds') != expected['duration_seconds'] or
            config.get('canary_interval_seconds') != expected['interval_seconds'] or
            config.get('send') is not True or config.get('allow_scoped_retries') is not True):
        raise GateError('CONFIG_BINDING_MISMATCH')
    if progress.get('run_id') != expected['run_id']: raise GateError('PROGRESS_BINDING_MISMATCH')
    if 'progress' in status and status['progress'] != progress:
        raise GateError('PROGRESS_SNAPSHOT_MISMATCH')
    started = number(status.get('started_unix'), integer=True)
    finished = number(status.get('finished_unix'), started, integer=True)
    if config_mtime > started+1: raise GateError('CONFIG_PREPARED_AFTER_RUN_STARTED')
    duration = expected['duration_seconds']
    if finished-started < duration-5 or finished > now+5: raise GateError('WALL_DURATION_INCOMPLETE')
    if progress.get('duration_seconds') != duration or \
            progress.get('canary_interval_seconds') != expected['interval_seconds']:
        raise GateError('PROGRESS_CONFIG_MISMATCH')
    if progress.get('run_started_unix') != started: raise GateError('START_BINDING_MISMATCH')
    ended = number(progress.get('run_finished_unix'), started, integer=True)
    if abs(ended-finished) > 5: raise GateError('FINISH_BINDING_MISMATCH')
    observed = number(progress.get('observed_run_seconds'))
    if observed < duration-5: raise GateError('MONOTONIC_DURATION_INCOMPLETE')
    baseline = number(progress.get('canary_completed_baseline'), integer=True)
    latest = number(progress.get('canary_completed_latest'), baseline, integer=True)
    new = number(progress.get('canary_new_completed_cycles'), integer=True)
    minimum = max(expected['minimum_cycles'], duration//expected['interval_seconds']-1)
    if latest-baseline != new or new < minimum: raise GateError('CANARY_COVERAGE_INCOMPLETE')
    if (progress.get('health_coverage_qualified') is not True or
            number(progress.get('max_health_gap_seconds')) > 180 or
            number(progress.get('health_gap_events'), integer=True) != 0 or
            number(progress.get('connection_gap_events'), integer=True) != 0):
        raise GateError('HEALTH_COVERAGE_INCOMPLETE')
    health_seconds = number(progress.get('observed_seconds'))
    if health_seconds < duration-180: raise GateError('HEALTH_DURATION_INCOMPLETE')
    first_health = number(progress.get('first_health_unix'), started-5)
    last_health = number(progress.get('last_health_unix'), first_health, finished+5)
    if first_health > started+180 or last_health < finished-180:
        raise GateError('HEALTH_ENDPOINT_GAP')
    version = progress.get('version')
    if not isinstance(version, dict) or set(version) != {'major','minor','patch'}:
        raise GateError('VERSION_EVIDENCE_MISSING')
    for part in version.values(): number(part, 0, 0xffffffff, integer=True)
    if (confirmation.get('schema') != 1 or confirmation.get('recipient_confirmed') is not True or
            confirmation.get('binary_sha256') != expected['binary_sha256'] or
            confirmation.get('scope_sha256') != scope_hash(config) or
            confirmation.get('version') != version):
        return {'phase':'PENDING_HUMAN_CONFIRMATION'}
    proof_version=confirmation.get('version',{})
    if any(type(v) is not int for v in proof_version.values()):
        return {'phase':'PENDING_HUMAN_CONFIRMATION'}
    confirmed=number(confirmation.get('confirmed_unix'), 0, now+5, integer=True)
    first_ack = number(progress.get('first_canary_ack_unix'), integer=True)
    last_ack = number(progress.get('last_canary_ack_unix'), first_ack, finished+5, integer=True)
    if last_ack < started: raise GateError('CANARY_ACK_TIME_INVALID')
    return {'phase':'QUALIFIED', 'run_id':expected['run_id'],
        'binary_sha256':expected['binary_sha256'], 'scope_sha256':scope_hash(config),
        'initial_recipient_confirmed_unix':confirmed, 'started_unix':started,
        'finished_unix':finished, 'duration_seconds':duration,
        'canary_interval_seconds':expected['interval_seconds'], 'new_completed_cycles':new,
        'durable_completed_cycles':latest, 'observed_seconds':health_seconds,
        'max_health_gap_seconds':progress['max_health_gap_seconds'],
        'version':version, 'version_fallback':progress.get('version_fallback') is True,
        'first_completed_pair_ack_unix':first_ack, 'last_completed_pair_ack_unix':last_ack,
        'recipient_delivery_claimed':False, 'initial_recipient_confirmation':True}

QUERY = '''query SoakLookup($issue:String!,$after:String){issue(id:$issue){
 id identifier project{id} state{id type} team{states{nodes{id name type}}}
 comments(first:100,after:$after){nodes{id body} pageInfo{hasNextPage endCursor}}}}'''
COMMENT = '''mutation SoakComment($issue:String!,$body:String!){
 commentCreate(input:{issueId:$issue,body:$body}){success comment{id}}}'''
DONE = '''mutation SoakDone($issue:String!,$state:String!){
 issueUpdate(id:$issue,input:{stateId:$state}){success issue{id state{id}}}}'''

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def graphql(token, query, variables):
    request = urllib.request.Request('https://api.linear.app/graphql',
        data=json.dumps({'query':query,'variables':variables}).encode(),
        headers={'Authorization':token,'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            data = response.read(1024*1024+1)
        if len(data)>1024*1024: raise GateError('LINEAR_RESPONSE_LIMIT')
        result = json.loads(data)
        if result.get('errors') or not isinstance(result.get('data'),dict):
            raise GateError('LINEAR_RESPONSE_INVALID')
        return result['data']
    except (OSError,ValueError,urllib.error.URLError):
        raise GateError('LINEAR_UNAVAILABLE') from None


def lookup(token, issue, marker, call=graphql):
    cursor = None; matches = []
    for _ in range(10):
        item = call(token, QUERY, {'issue':issue,'after':cursor}).get('issue')
        if (not isinstance(item,dict) or item.get('identifier')!=issue or
                item.get('project',{}).get('id')!=PROJECT):
            raise GateError('LINEAR_SCOPE_MISMATCH')
        states = [s for s in item['team']['states']['nodes']
                  if s.get('name')=='Done' and s.get('type')=='completed']
        if len(states)!=1: raise GateError('LINEAR_DONE_STATE_MISSING')
        done = states[0]['id']; comments = item['comments']
        matches += [c['id'] for c in comments['nodes'] if marker in c.get('body','')]
        page = comments['pageInfo']
        if not page['hasNextPage']:
            if len(matches)>1: raise GateError('LINEAR_DUPLICATE_MARKERS')
            return {'issue_id':item['id'],'done_state_id':done,
                'done':item['state']['id']==done,'comment_id':matches[0] if matches else None}
        cursor = page['endCursor']
        if not isinstance(cursor,str) or len(cursor)>1024: raise GateError('LINEAR_RESPONSE_INVALID')
    raise GateError('LINEAR_COMMENT_SEARCH_LIMIT')


def linear_worker(payload, call=graphql):
    op = payload['operation']; token = payload['token']
    if op=='lookup': return lookup(token,payload['issue'],payload['marker'],call)
    if op=='comment':
        result = call(token,COMMENT,{'issue':payload['issue_id'],'body':payload['body']})
        item = result.get('commentCreate',{})
        if not item.get('success') or not item.get('comment',{}).get('id'):
            raise GateError('LINEAR_COMMENT_UNCONFIRMED')
        return {'comment_id':item['comment']['id']}
    if op=='done':
        result = call(token,DONE,{'issue':payload['issue_id'],'state':payload['state_id']})
        if not result.get('issueUpdate',{}).get('success'): raise GateError('LINEAR_DONE_UNCONFIRMED')
        return {'updated':True}
    raise GateError('LINEAR_OPERATION_INVALID')


def isolated_linear(payload):
    # Only a private pipe carries the secret. The parent bounds even blocked DNS.
    result = subprocess.run([sys.executable,str(Path(__file__).resolve()),'_linear'],
        input=json.dumps(payload).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        timeout=15,check=False)
    if result.returncode or len(result.stdout)>LIMIT: raise GateError('LINEAR_UNAVAILABLE')
    value = json.loads(result.stdout)
    if value.get('error'): raise GateError(value['error'])
    return value


def credential_get():
    value = os.environ.get('LINEAR_API')
    if value is None:
        try:
            result = subprocess.run(['wayu','const','get','LINEAR_API'],stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,timeout=5,check=False)
            if result.returncode or len(result.stdout)>4096: return None
            value = result.stdout.decode('ascii').strip()
        except (OSError,UnicodeError,subprocess.SubprocessError): return None
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,4096}',value): return None
    return value


def scope_hash(config):
    scope = {key:config.get(key) for key in ('auth_dir','group_subject')}
    if any(not isinstance(v,str) or not v for v in scope.values()):
        raise GateError('SCOPE_METADATA_INVALID')
    return hashlib.sha256(json.dumps(scope,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def completion_body(evidence, marker):
    v=evidence['version']
    return ("Automated local 24-hour synthetic soak gate passed.\n\n"
        f"Run: {evidence['run_id']}\nDuration: {evidence['duration_seconds']} seconds; "
        f"new acknowledged pairs: {evidence['new_completed_cycles']}.\n"
        f"Version: {v['major']}.{v['minor']}.{v['patch']}.\n"
        f"Reviewed binary SHA-256: {evidence['binary_sha256']}.\n\n"
        "No recorded health/connection gaps or final errors. Initial readability was "
        "confirmed separately for this binary and scope. Periodic server ACKs do not "
        "certify recipient delivery or exactly-once semantics.\n\n"+marker)


def linear_complete(directory, state, evidence, issue, getter=credential_get, transport=isolated_linear):
    token=getter()
    if not token: return 'LINEAR_CREDENTIAL_UNAVAILABLE'
    marker='webtools-soak-completion:'+evidence['run_id']+':'+evidence['binary_sha256']
    base={'token':token}
    try:
        found=transport({**base,'operation':'lookup','issue':issue,'marker':marker})
        if found.get('comment_id'):
            state['comment_attempted']=True
            state['comment_confirmed']=True; state['comment_id']=found['comment_id']
            write_json(directory,'finish-state.json',state)
        elif state.get('comment_attempted') or state.get('comment_confirmed'):
            return 'LINEAR_COMMENT_OUTCOME_UNRESOLVED'
        else:
            state['comment_attempted']=True
            write_json(directory,'finish-state.json',state)
            made=transport({**base,'operation':'comment','issue_id':found['issue_id'],
                            'body':completion_body(evidence,marker)})
            state['comment_confirmed']=True; state['comment_id']=made['comment_id']
            write_json(directory,'finish-state.json',state)
        if found['done']:
            state['done_observed']=True
            write_json(directory,'finish-state.json',state)
        if not found['done']:
            if state.get('done_attempted') or state.get('done_observed'):
                return 'LINEAR_DONE_OUTCOME_UNRESOLVED'
            state['done_attempted']=True
            write_json(directory,'finish-state.json',state)
            transport({**base,'operation':'done','issue_id':found['issue_id'],
                       'state_id':found['done_state_id']})
        verified=transport({**base,'operation':'lookup','issue':issue,'marker':marker})
        if not verified.get('done') or not verified.get('comment_id'):
            return 'LINEAR_VERIFICATION_PENDING'
        state['phase']='DONE_VERIFIED'
        write_json(directory,'finish-state.json',state)
        return None
    except (GateError,OSError,ValueError,KeyError,subprocess.SubprocessError):
        return 'LINEAR_UPDATE_PENDING'
    finally:
        token=None


def handoff(directory, reason, run_id):
    value={'schema':1,'phase':'HANDOFF','run_id':run_id,'reason':reason,
        'action':'Inspect private supervisor evidence; do not mark Done or blindly restart account work.'}
    write_json(directory,'handoff.json',value); write_json(directory,'receipt.json',value)
    return value


def expected_from_args(args):
    if not RUN.fullmatch(args.expected_run_id) or not HASH.fullmatch(args.expected_binary_sha256):
        raise GateError('EXPECTED_BINDING_INVALID')
    if not 86400<=args.expected_duration_seconds<=172800 or \
            not 3600<=args.expected_canary_interval_seconds<=86400 or not 3<=args.minimum_cycles<=48:
        raise GateError('EXPECTED_COVERAGE_INVALID')
    if not re.fullmatch(r'OKAMI-[0-9]{1,6}',args.issue): raise GateError('ISSUE_INVALID')
    return {'run_id':args.expected_run_id,'binary_sha256':args.expected_binary_sha256,
        'duration_seconds':args.expected_duration_seconds,
        'interval_seconds':args.expected_canary_interval_seconds,'minimum_cycles':args.minimum_cycles}


def poll(args, getter=credential_get, transport=isolated_linear, now=None):
    expected=expected_from_args(args)
    if Path(args.state_dir)==Path(args.controller_dir): raise GateError('DIRECTORIES_MUST_DIFFER')
    source=private_directory(args.state_dir)
    try: destination=private_directory(args.controller_dir,create=True)
    except BaseException:
        os.close(source); raise
    owner=None
    try:
        owner=os.open('finish.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=destination)
        checked_file(owner); fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            config, info=read_json(source,'config.json')
            status, status_info=read_json(source,'status.json')
            try: progress, _=read_json(source,'progress.json')
            except FileNotFoundError: progress=status.get('progress',{})
            try: confirmation, _=read_json(destination,'recipient-confirmation.json')
            except FileNotFoundError: confirmation={}
            evidence=evaluate(config,status,progress,confirmation,expected,
                              info.st_mtime,time.time() if now is None else now,status_info.st_mtime)
        except GateError as error:
            return handoff(destination,str(error),expected['run_id'])
        except (OSError,ValueError,KeyError,TypeError,AttributeError):
            return handoff(destination,'METADATA_INVALID',expected['run_id'])
        if evidence['phase']!='QUALIFIED':
            write_json(destination,'receipt.json',evidence)
            return evidence
        proof=hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        try: state, _=read_json(destination,'finish-state.json')
        except FileNotFoundError:
            state={'schema':1,'phase':'LOCAL_QUALIFIED','run_id':expected['run_id'],
                'binary_sha256':expected['binary_sha256'],'proof_sha256':proof,'issue':args.issue}
        if any(state.get(key)!=value for key,value in (
                ('run_id',expected['run_id']),('binary_sha256',expected['binary_sha256']),
                ('proof_sha256',proof),('issue',args.issue))):
            return handoff(destination,'FINISH_BINDING_MISMATCH',expected['run_id'])
        write_json(destination,'finish-state.json',state)
        receipt={**evidence,'schema':1,'proof_sha256':proof,'linear_update_pending':True}
        if state.get('phase')=='DONE_VERIFIED':
            receipt.update(phase='COMPLETE',linear_update_pending=False,linear_done_verified=True)
        elif args.linear:
            pending=linear_complete(destination,state,evidence,args.issue,getter,transport)
            receipt['linear_update_pending']=pending is not None
            if pending: receipt['linear_reason']=pending
            else: receipt.update(phase='COMPLETE',linear_done_verified=True)
        else: receipt['linear_reason']='LINEAR_DISABLED'
        write_json(destination,'receipt.json',receipt)
        return receipt
    finally:
        for fd in (owner,destination,source):
            if fd is not None: os.close(fd)


class Parser(argparse.ArgumentParser):
    def error(self, message): raise GateError('INVALID_ARGUMENTS')


def arguments(argv):
    parser=Parser(description=__doc__)
    parser.add_argument('--state-dir',type=Path,required=True)
    parser.add_argument('--controller-dir',type=Path,required=True)
    parser.add_argument('--expected-run-id',required=True)
    parser.add_argument('--expected-binary-sha256',required=True)
    parser.add_argument('--expected-duration-seconds',type=int,default=86400)
    parser.add_argument('--expected-canary-interval-seconds',type=int,default=21600)
    parser.add_argument('--minimum-cycles',type=int,default=3)
    parser.add_argument('--issue',default='OKAMI-408')
    parser.add_argument('--linear',action='store_true')
    return parser.parse_args(argv)


def main(argv=None):
    argv=sys.argv[1:] if argv is None else argv
    if argv==['_linear']:
        try:
            data=sys.stdin.buffer.read(LIMIT+1)
            if len(data)>LIMIT: raise GateError('LINEAR_REQUEST_LIMIT')
            result=linear_worker(json.loads(data))
        except (GateError,OSError,ValueError,KeyError,TypeError):
            result={'error':'LINEAR_UPDATE_PENDING'}
        print(json.dumps(result,separators=(',',':')))
        return 0
    try:
        result=poll(arguments(argv))
        print(json.dumps({'phase':result['phase'],
            'linear_update_pending':result.get('linear_update_pending',True)},separators=(',',':')))
        return 0 if result['phase'] in ('WAITING','PENDING_HUMAN_CONFIRMATION','QUALIFIED','COMPLETE') else 2
    except BlockingIOError:
        print('{"phase":"ALREADY_CHECKING"}'); return 0
    except (GateError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('{"phase":"HANDOFF","reason":"CONTROLLER_METADATA_ERROR"}'); return 2

if __name__=='__main__': raise SystemExit(main())

#!/usr/bin/env python3
"""15-minute metadata poll for continuing canaries after an immutable qualified soak.

Generate a private plist with the seven explicit binding/path options shown by
--help, then install controller-dir/periodic-canary.plist as a user LaunchAgent.
RunAtLoad checks immediately; subsequent polls are every 900s. Before the primary
receipt qualifies, polling only reports WAITING. It does not contact Linear or a
model and never opens account files. No credential is requested or copied.

A qualified primary proof must match its source metadata and original binary,
session/group scope, run ID and human confirmation. Each due poll may launch one
180-second native watch using that original private config and a 6h interval.
The native ledger alone allocates durable IDs and decides whether a cycle is due.
No journal, native content or crypto state is deleted. Only the frozen supervisor
and native child own session access. Reports contain hashes, counters and times.

A completed periodic run needs a new durable cycle, fresh text/PDF ACK observations,
clean health and the qualified public version. Newer ACKs move the next due time;
polls before then launch nothing. Cadence can be delayed by up to 15 minutes.
Any failed, stopped, interrupted, unknown, ambiguous, version-changed or zero-cycle
run suspends future launches and writes a local alert. There is no automatic
--resume or unknown-intent retry. Operator review is required; never clear native
journals to reset a controller. Preserve the Mac-awake requirement of supervision.

Root installs/starts the generated schedule after offline verification; generation
itself does not install or launch anything. Unit tests use synthetic metadata and
fake launchers only, never a real account job.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import sys
import tempfile
import time
import types

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location('periodic_'+name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

F=load('finish_soak'); S=load('supervisor')
RUN=re.compile(r'[0-9a-f]{32}'); HASH=re.compile(r'[0-9a-f]{64}')
DURATION=180; INTERVAL=21600; LABEL='com.webtools.whatsapp.periodic-canary'

class ControllerError(Exception): pass

def validate_args(args):
    if not RUN.fullmatch(args.expected_primary_run_id) or any(not HASH.fullmatch(value)
            for value in (args.expected_binary_sha256,args.expected_scope_sha256)):
        raise ControllerError('EXPECTED_BINDING_INVALID')
    paths=(args.primary_state_dir,args.primary_finish_dir,args.state_dir,args.controller_dir)
    if any(not path.is_absolute() or '..' in path.parts for path in paths):
        raise ControllerError('DIRECTORY_INVALID')
    if len({path.resolve() for path in paths})!=4:
        raise ControllerError('DIRECTORIES_MUST_DIFFER')

def number(value,lower=0,upper=0x7fffffffffffffff):
    if type(value) is not int or not lower<=value<=upper:
        raise ControllerError('NUMERIC_METADATA_INVALID')
    return value

def metadata(path,name):
    directory=F.private_directory(path)
    try: return F.read_json(directory,name)
    finally: os.close(directory)

def read(path,name): return metadata(path,name)[0]

def optional(path,name):
    try: return read(path,name)
    except FileNotFoundError: return None

def binding(args):
    return {'schema':1,'primary_run_id':args.expected_primary_run_id,
            'binary_sha256':args.expected_binary_sha256,'scope_sha256':args.expected_scope_sha256}

def result(directory,state,phase,reason=None,**values):
    value={**binding_values(state),'phase':phase,**values}
    if reason is not None: value['reason']=reason
    F.write_json(directory,'receipt.json',value)
    return value

def binding_values(state):
    return {key:state[key] for key in ('primary_run_id','binary_sha256','scope_sha256')}

def suspend(directory,state,reason):
    state.update(phase='SUSPENDED',reason=reason)
    F.write_json(directory,'controller.json',state)
    value=result(directory,state,'SUSPENDED',reason)
    F.write_json(directory,'alert.json',value)
    return value

def primary(args):
    receipt=optional(args.primary_finish_dir,'receipt.json')
    if receipt is None or receipt.get('phase') not in ('QUALIFIED','COMPLETE'): return None
    if (receipt.get('run_id')!=args.expected_primary_run_id or
        receipt.get('binary_sha256')!=args.expected_binary_sha256 or
        receipt.get('scope_sha256')!=args.expected_scope_sha256):
        raise ControllerError('PRIMARY_RECEIPT_BINDING_MISMATCH')
    config,config_info=metadata(args.primary_state_dir,'config.json')
    status,status_info=metadata(args.primary_state_dir,'status.json')
    progress=read(args.primary_state_dir,'progress.json')
    if (config.get('binary_sha256')!=args.expected_binary_sha256 or
        F.scope_hash(config)!=args.expected_scope_sha256 or status.get('phase')!='COMPLETE' or
        status.get('run_id')!=args.expected_primary_run_id or
        progress.get('run_id')!=args.expected_primary_run_id or
        progress.get('version')!=receipt.get('version')):
        raise ControllerError('PRIMARY_METADATA_BINDING_MISMATCH')
    ack=number(receipt.get('last_completed_pair_ack_unix'),1)
    cycles=number(receipt.get('durable_completed_cycles'),1,0xffffffffffffffff)
    if progress.get('last_canary_ack_unix')!=ack or progress.get('canary_completed_latest')!=cycles:
        raise ControllerError('PRIMARY_PROGRESS_MISMATCH')
    proof=receipt.get('proof_sha256')
    if not isinstance(proof,str) or not HASH.fullmatch(proof):
        raise ControllerError('PRIMARY_PROOF_MISSING')
    confirmation=read(args.primary_finish_dir,'recipient-confirmation.json')
    expected={'run_id':args.expected_primary_run_id,'binary_sha256':args.expected_binary_sha256,
        'duration_seconds':number(receipt.get('duration_seconds'),86400,172800),
        'interval_seconds':number(receipt.get('canary_interval_seconds'),3600,86400),
        'minimum_cycles':3}
    qualified=F.evaluate(config,status,progress,confirmation,expected,
                         config_info.st_mtime,time.time(),status_info.st_mtime)
    if qualified.get('phase')!='QUALIFIED':
        raise ControllerError('PRIMARY_QUALIFICATION_CHANGED')
    encoded=json.dumps(qualified,sort_keys=True,separators=(',',':')).encode()
    if hashlib.sha256(encoded).hexdigest()!=proof:
        raise ControllerError('PRIMARY_PROOF_MISMATCH')
    return config,receipt,ack,cycles,proof

def periodic_config(args):
    config=read(args.state_dir,'config.json')
    if (config.get('binary_sha256')!=args.expected_binary_sha256 or
        F.scope_hash(config)!=args.expected_scope_sha256 or config.get('duration_seconds')!=DURATION or
        config.get('canary_interval_seconds')!=INTERVAL or config.get('send') is not True or
        config.get('allow_scoped_retries') is not True):
        raise ControllerError('PERIODIC_CONFIG_MISMATCH')
    return config

def accept_completed(args,state,status,receipt,now):
    periodic_config(args)
    run_id=status.get('run_id')
    if not isinstance(run_id,str) or run_id!=state.get('periodic_run_id'):
        raise ControllerError('PERIODIC_RUN_UNKNOWN')
    progress=read(args.state_dir,'progress.json')
    if progress.get('run_id')!=run_id or progress.get('version')!=receipt.get('version'):
        raise ControllerError('PERIODIC_PROGRESS_OR_VERSION_MISMATCH')
    encoded=json.dumps(progress,sort_keys=True,separators=(',',':')).encode()
    digest=hashlib.sha256(encoded).hexdigest()
    if state.get('accepted_periodic_run_id')==run_id:
        if digest!=state.get('accepted_progress_sha256'):
            raise ControllerError('PERIODIC_EVIDENCE_CHANGED')
        return
    started=number(status.get('started_unix'),1,now+5)
    finished=number(status.get('finished_unix'),started,now+5)
    baseline=number(progress.get('canary_completed_baseline'),0,0xffffffffffffffff)
    latest=number(progress.get('canary_completed_latest'),baseline+1,0xffffffffffffffff)
    ack=number(progress.get('last_canary_ack_unix'),started,finished+5)
    if (number(progress.get('canary_new_completed_cycles'),1)!=latest-baseline or
        ack<=state['before_start_ack'] or baseline<state['before_start_cycles'] or
        number(progress.get('last_text_ack_unix'),started,finished+5)>ack+5 or
        number(progress.get('last_pdf_ack_unix'),started,finished+5)>ack+5 or
        F.number(progress.get('observed_run_seconds'))<DURATION-5 or
        finished-started<DURATION-5 or progress.get('health_coverage_qualified') is not True or
        number(progress.get('health_gap_events')) or number(progress.get('connection_gap_events'))):
        raise ControllerError('PERIODIC_CYCLE_INCOMPLETE')
    if status.get('reason') or status.get('error') or progress.get('errors'):
        raise ControllerError('PERIODIC_ERROR_PRESENT')
    state.update(cadence_ack_unix=ack,cadence_durable_cycles=latest,
                 accepted_periodic_run_id=run_id,accepted_progress_sha256=digest)

def launch_options(config,args):
    # Prepare opens only directory metadata; the reviewed native child alone opens stores.
    options=types.SimpleNamespace(state_dir=args.state_dir,auth_dir=Path(config['auth_dir']),
        binary=Path(config['binary']),group_subject=config['group_subject'],duration_seconds=DURATION,
        allow_scoped_retries=True,send=True,canary_interval_seconds=INTERVAL)
    S.prepare(options)
    prepared=periodic_config(args)
    if prepared['binary_sha256']!=config['binary_sha256']:
        raise ControllerError('BINARY_CHANGED')
    return types.SimpleNamespace(state_dir=args.state_dir,live=True,resume=False)

def launch(config,args):
    return S.start(launch_options(config,args))

def launch_owned(config,args,environment):
    options=launch_options(config,args)
    return S.start_owned(options,environment,expected_config=periodic_config(args))

def inspect_periodic(args):
    if optional(args.state_dir,'status.json') is None: return None
    return S.inspect_state(types.SimpleNamespace(state_dir=args.state_dir,command='status'))

def check_periodic(args,directory,state,receipt,now,inspector):
    status=inspector(args)
    if status is None:
        if state.get('phase')=='LAUNCH_INTENT' or state.get('periodic_run_id') or \
                optional(args.state_dir,'config.json') is not None:
            raise ControllerError('PERIODIC_LAUNCH_OUTCOME_UNKNOWN')
        return None
    periodic_config(args)
    phase=status.get('phase')
    if not isinstance(status.get('run_id'),str) or not RUN.fullmatch(status['run_id']):
        raise ControllerError('PERIODIC_RUN_INVALID')
    if phase in ('STARTING','RUNNING'):
        if state.get('periodic_run_id')!=status.get('run_id') and state.get('phase')!='LAUNCH_INTENT':
            raise ControllerError('PERIODIC_RUN_MISMATCH')
        return result(directory,state,'ACTIVE',periodic_run_id=status.get('run_id'))
    if phase!='COMPLETE': raise ControllerError('PERIODIC_TERMINAL_OR_UNKNOWN')
    if state.get('phase')=='LAUNCH_INTENT':
        raise ControllerError('PERIODIC_LAUNCH_OUTCOME_UNKNOWN')
    accept_completed(args,state,status,receipt,now)
    state['phase']='IDLE'; F.write_json(directory,'controller.json',state)
    return None

def start_due(args,directory,state,config,launcher,now):
    # Persist uncertainty before any prepare/spawn effect. Never infer a retry is safe.
    state.update(phase='LAUNCH_INTENT',before_start_ack=state['cadence_ack_unix'],
                 before_start_cycles=state['cadence_durable_cycles'],launch_requested_unix=now)
    F.write_json(directory,'controller.json',state)
    try: launched=launcher(config,args)
    except (OSError,ValueError,KeyError,S.Failure,ControllerError):
        return suspend(directory,state,'LAUNCH_OUTCOME_UNKNOWN')
    run_id=launched.get('run_id')
    if launched.get('phase')!='STARTED' or not isinstance(run_id,str) or not RUN.fullmatch(run_id):
        return suspend(directory,state,'LAUNCH_OUTCOME_UNKNOWN')
    state.update(phase='STARTED',periodic_run_id=run_id)
    F.write_json(directory,'controller.json',state)
    return result(directory,state,'STARTED',periodic_run_id=run_id)

def poll_locked(args,directory,state,launcher,inspector,now):
    if state.get('phase')=='SUSPENDED': return result(directory,state,'SUSPENDED','CONTROLLER_SUSPENDED')
    qualified=primary(args)
    if qualified is None:
        if state.get('primary_proof_sha256'): raise ControllerError('PRIMARY_QUALIFICATION_LOST')
        F.write_json(directory,'controller.json',state)
        return result(directory,state,'WAITING','PRIMARY_NOT_QUALIFIED')
    config,receipt,ack,cycles,proof=qualified
    if state.get('primary_proof_sha256',proof)!=proof:
        raise ControllerError('PRIMARY_PROOF_CHANGED')
    state.setdefault('primary_proof_sha256',proof)
    state.setdefault('cadence_ack_unix',ack); state.setdefault('cadence_durable_cycles',cycles)
    if state['cadence_ack_unix']>now+5: raise ControllerError('ACK_CLOCK_INVALID')
    active=check_periodic(args,directory,state,receipt,now,inspector)
    if active is not None: return active
    due=number(state['cadence_ack_unix'],1)+INTERVAL
    if due>now:
        F.write_json(directory,'controller.json',state)
        return result(directory,state,'NOT_DUE',last_complete_ack_unix=state['cadence_ack_unix'],
                      next_due_unix=due,durable_completed_cycles=state['cadence_durable_cycles'])
    return start_due(args,directory,state,config,launcher,now)

def avoid_account_directory(args):
    try: config=read(args.primary_state_dir,'config.json')
    except FileNotFoundError: return False
    auth=config.get('auth_dir')
    if not isinstance(auth,str) or not Path(auth).is_absolute():
        raise ControllerError('PRIMARY_CONFIG_INVALID')
    paths=(args.primary_state_dir,args.primary_finish_dir,args.state_dir,args.controller_dir)
    account=Path(auth).resolve()
    if any(account.is_relative_to(path.resolve()) or path.resolve().is_relative_to(account)
           for path in paths):
        raise ControllerError('ACCOUNT_DIRECTORY_COLLISION')
    return True

MONITOR_GUARD='monitor-latch.json'

def monitor_access(args,token=None):
    # An armed guard is durable before spawn. All ordinary polls fail closed;
    # only the same foreground invocation may finish its one owned job.
    try: guard=optional(args.controller_dir,MONITOR_GUARD)
    except (OSError,ValueError,TypeError,F.GateError,S.Failure): return False
    if guard is None: return token is None
    if token is None or not isinstance(guard,dict): return False
    if guard.get('phase')!='ARMED' or guard.get('mode')!='periodic': return False
    if guard.get('monitor_token')!=token: return False
    return all(guard.get(key)==value for key,value in binding(args).items())

def poll(args,launcher=launch,inspector=inspect_periodic,now=None,monitor_token=None):
    validate_args(args)
    ready=avoid_account_directory(args)
    if not monitor_access(args,monitor_token):
        return {'phase':'SUSPENDED','reason':'MONITOR_REVIEW_REQUIRED'}
    if not ready: return {'phase':'WAITING','reason':'PRIMARY_NOT_READY'}
    directory=F.private_directory(args.controller_dir,create=True); owner=None
    state={**binding(args),'phase':'WAITING'}
    try:
        owner=os.open('periodic.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=directory)
        F.checked_file(owner); fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if not monitor_access(args,monitor_token):
            return {'phase':'SUSPENDED','reason':'MONITOR_REVIEW_REQUIRED'}
        try: previous=F.read_json(directory,'controller.json')[0]
        except FileNotFoundError: previous=None
        if previous is not None:
            if any(previous.get(key)!=value for key,value in binding(args).items()):
                return suspend(directory,state,'CONTROLLER_BINDING_MISMATCH')
            state=previous
        try:
            return poll_locked(args,directory,state,launcher,inspector,
                               int(time.time()) if now is None else now)
        except ControllerError as error: return suspend(directory,state,str(error))
        except (F.GateError,S.Failure,OSError,ValueError,KeyError,TypeError):
            return suspend(directory,state,'METADATA_INVALID')
    finally:
        if owner is not None: os.close(owner)
        os.close(directory)

def plist(args):
    validate_args(args)
    argv=[sys.executable,str(Path(__file__).resolve()),'poll']
    for flag,name in (('--primary-state-dir','primary_state_dir'),
        ('--primary-finish-dir','primary_finish_dir'),('--state-dir','state_dir'),
        ('--controller-dir','controller_dir'),('--expected-primary-run-id','expected_primary_run_id'),
        ('--expected-binary-sha256','expected_binary_sha256'),
        ('--expected-scope-sha256','expected_scope_sha256')):
        argv.extend([flag,str(getattr(args,name))])
    return {'Label':LABEL,'ProgramArguments':argv,'StartInterval':900,'RunAtLoad':True,
        'ProcessType':'Background','ExitTimeOut':15,'Umask':0o077,
        'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null',
        'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin'}}

def write_plist(args):
    value=plist(args); directory=F.private_directory(args.controller_dir,create=True)
    try:
        fd,name=tempfile.mkstemp(prefix='.periodic-',dir=args.controller_dir)
        path=args.controller_dir/'periodic-canary.plist'
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(plistlib.dumps(value)); stream.flush(); os.fsync(stream.fileno())
            os.replace(name,path); os.fsync(directory)
        finally: Path(name).unlink(missing_ok=True)
        if plistlib.loads(path.read_bytes())!=value: raise ControllerError('PLIST_INVALID')
    finally: os.close(directory)
    return {'phase':'PLIST_PREPARED','installed':False,'poll_interval_seconds':900}

class Parser(argparse.ArgumentParser):
    def error(self,message): raise ControllerError('ARGUMENTS_INVALID')

def main(argv=None):
    parser=Parser(description=__doc__)
    parser.add_argument('command',choices=('poll','plist'))
    for name in ('primary-state-dir','primary-finish-dir','state-dir','controller-dir'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('expected-primary-run-id','expected-binary-sha256','expected-scope-sha256'):
        parser.add_argument('--'+name,required=True)
    try:
        args=parser.parse_args(argv)
        value=write_plist(args) if args.command=='plist' else poll(args)
        print(json.dumps(value,separators=(',',':')))
        return 2 if value['phase']=='SUSPENDED' else 0
    except BlockingIOError:
        print('{"phase":"ALREADY_POLLING"}'); return 0
    except (ControllerError,F.GateError,S.Failure,OSError,ValueError,KeyError,TypeError):
        print('{"phase":"SUSPENDED","reason":"CONTROLLER_METADATA_ERROR"}'); return 2

if __name__=='__main__': raise SystemExit(main())

#!/usr/bin/env python3
"""Prepare private units, or explicitly own one finite Linux qualification job.

Generation never opens account files, installs units or starts a process. Runtime
requires --live and a non-root Linux service user. A durable guard is armed before
spawn and blocks all ordinary periodic polls until a verified, reaped success.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import subprocess
import sys
import time
import types

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('systemd_periodic',HERE/'periodic_canary.py')
P=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(P)
F,S=P.F,P.S
PRIMARY_BUDGET=86520
PERIODIC_BUDGET=240
SAFE_PATH=re.compile(r'/[A-Za-z0-9_./-]+')
USER=re.compile(r'[a-z_][a-z0-9_-]{0,31}')
PATH_FIELDS=('primary_state_dir','primary_finish_dir','state_dir','controller_dir')

class MonitorError(Exception): pass


def safe_path(value):
    value=Path(value)
    if not SAFE_PATH.fullmatch(str(value)) or '..' in value.parts:
        raise MonitorError('PATH_INVALID')
    return value


def validate(args):
    if args.mode not in ('primary','periodic'): raise MonitorError('MODE_INVALID')
    for name in PATH_FIELDS: safe_path(getattr(args,name))
    paths=[getattr(args,name).resolve() for name in PATH_FIELDS]
    if len(set(paths))!=4: raise MonitorError('DIRECTORIES_MUST_DIFFER')
    if any(a.is_relative_to(b) for a in paths for b in paths if a!=b):
        raise MonitorError('DIRECTORIES_MUST_NOT_NEST')
    if any(not P.HASH.fullmatch(getattr(args,name)) for name in
           ('expected_binary_sha256','expected_scope_sha256')):
        raise MonitorError('EXPECTED_BINDING_INVALID')
    if args.mode=='periodic': P.validate_args(args)


def environment():
    # The worker/native process requires no vendor API or cloud credential.
    value={key:os.environ[key] for key in ('HOME','LANG','LC_ALL','TMPDIR') if key in os.environ}
    value.update(PATH='/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1')
    return value


def guard_exists(args):
    try: return P.optional(args.controller_dir,P.MONITOR_GUARD) is not None
    except (OSError,ValueError,TypeError,F.GateError,S.Failure): return True


class Owner:
    def __init__(self,args):
        self.args=args; self.token=secrets.token_hex(16); self.child=None
        self.armed=False; self.completed=False

    def arm(self):
        if self.armed or guard_exists(self.args): raise MonitorError('MONITOR_REVIEW_REQUIRED')
        directory=F.private_directory(self.args.controller_dir,create=True)
        try:
            value={'schema':1,'phase':'ARMED','mode':self.args.mode,'monitor_token':self.token,
                   'binary_sha256':self.args.expected_binary_sha256,
                   'scope_sha256':self.args.expected_scope_sha256}
            if self.args.mode=='periodic': value.update(P.binding(self.args))
            F.write_json(directory,P.MONITOR_GUARD,value)
            self.armed=True
        finally: os.close(directory)

    def claim(self,result,child):
        # Never obtain a signal target from disk/PID metadata.
        if not isinstance(child,subprocess.Popen): raise MonitorError('OWNED_CHILD_REQUIRED')
        self.child=child
        if result.get('phase')!='STARTED' or result.get('pid')!=child.pid or \
                not P.RUN.fullmatch(result.get('run_id','')):
            raise MonitorError('START_OUTCOME_UNKNOWN')
        return result

    def suspend(self,reason):
        # The pre-spawn ARMED guard is already a durable stop if this update fails.
        if not self.armed: return
        directory=F.private_directory(self.args.controller_dir)
        try:
            value=F.read_json(directory,P.MONITOR_GUARD)[0]
            if value.get('monitor_token')!=self.token: raise MonitorError('GUARD_CHANGED')
            value.update(phase='SUSPENDED',reason=reason)
            F.write_json(directory,P.MONITOR_GUARD,value)
        finally: os.close(directory)

    def finish(self):
        if self.child is None or self.child.wait(timeout=0)!=0:
            raise MonitorError('CHILD_NOT_SUCCESSFULLY_REAPED')
        directory=F.private_directory(self.args.controller_dir)
        try:
            guard=F.read_json(directory,P.MONITOR_GUARD)[0]
            if guard.get('monitor_token')!=self.token or guard.get('phase')!='ARMED':
                raise MonitorError('GUARD_CHANGED')
            os.unlink(P.MONITOR_GUARD,dir_fd=directory); os.fsync(directory)
            self.completed=True
        finally: os.close(directory)

    def cleanup(self):
        if self.child is not None:
            # Native cleanup already belongs to supervisor.monitor's finally.
            # Allow its existing 5+5 seconds before stopping/reaping the supervisor.
            S.stop_child(self.child,grace_seconds=15)
            self.child.wait(timeout=5)


def deny_launch(_config,_args): raise P.ControllerError('SECOND_LAUNCH_FORBIDDEN')


def primary_config(args):
    directory=S.private_dir(args.primary_state_dir)
    try:
        config=S.validate_config(S.read_json(directory,'config.json'))
        try: S.read_json(directory,'status.json')
        except FileNotFoundError: pass
        else: raise MonitorError('PRIMARY_STATE_ALREADY_USED')
    finally: os.close(directory)
    if config['binary_sha256']!=args.expected_binary_sha256 or F.scope_hash(config)!=args.expected_scope_sha256:
        raise MonitorError('PRIMARY_BINDING_MISMATCH')
    if config['duration_seconds']!=86400 or config.get('canary_interval_seconds')!=21600 or \
            config.get('send') is not True or config.get('allow_scoped_retries') is not True:
        raise MonitorError('PRIMARY_CONFIG_NOT_QUALIFIABLE')
    return config


def primary_status(args,run_id):
    value=P.read(args.primary_state_dir,'status.json')
    if value.get('run_id')!=run_id: raise MonitorError('PRIMARY_RUN_CHANGED')
    return value.get('phase')


def run_owned(args,poller=P.poll,periodic_starter=P.launch_owned,primary_starter=S.start_owned,
              clock=time.monotonic,sleep=time.sleep,cancelled=lambda:False,
              primary_reader=primary_status,config_reader=primary_config):
    validate(args)
    # Reject declared controller/session collisions before creating any lock.
    P.avoid_account_directory(args)
    directory=F.private_directory(args.controller_dir,create=True); lock=None
    owner=Owner(args); reason='MONITOR_FAILED'
    try:
        lock=S.lock(directory,'systemd-monitor.lock')
        if guard_exists(args): return {'phase':'SUSPENDED','reason':'MONITOR_REVIEW_REQUIRED'}
        if cancelled():
            owner.arm(); raise MonitorError('MONITOR_CANCELLED')
        if args.mode=='primary':
            config=config_reader(args); owner.arm()
            options=types.SimpleNamespace(state_dir=args.primary_state_dir,live=True,resume=False)
            result=owner.claim(*primary_starter(options,environment(),expected_config=config,require_fresh=True))
            budget=PRIMARY_BUDGET
        else:
            def launch(config,options):
                owner.arm()
                return owner.claim(*periodic_starter(config,options,environment()))
            result=poller(args,launcher=launch)
            if owner.child is None:
                return {'phase':result['phase']} if result['phase'] in ('WAITING','NOT_DUE','ACTIVE','SUSPENDED') \
                    else {'phase':'SUSPENDED','reason':'START_OUTCOME_UNKNOWN'}
            if result.get('phase')!='STARTED': raise MonitorError('START_OUTCOME_UNKNOWN')
            budget=PERIODIC_BUDGET
        deadline=clock()+budget
        while True:
            if cancelled(): raise MonitorError('MONITOR_CANCELLED')
            if clock()>=deadline: raise MonitorError('MONITOR_TIMEOUT')
            code=owner.child.poll()
            if code is not None and code!=0: raise MonitorError('OWNED_CHILD_FAILED')
            if args.mode=='primary':
                phase=primary_reader(args,result['run_id'])
                healthy=phase=='COMPLETE'
                if phase not in ('STARTING','RUNNING','COMPLETE'): raise MonitorError('PRIMARY_TERMINAL')
            else:
                observed=poller(args,launcher=deny_launch,monitor_token=owner.token)
                phase=observed.get('phase'); healthy=phase=='NOT_DUE'
                if phase not in ('ACTIVE','NOT_DUE'): raise MonitorError('PERIODIC_TERMINAL_OR_UNKNOWN')
            if code is not None:
                if not healthy: raise MonitorError('CHILD_EVIDENCE_INCOMPLETE')
                owner.finish(); return {'phase':'COMPLETE'}
            sleep(.25)
    except BlockingIOError:
        reason='OWNER_LOCK_BUSY'
        return {'phase':'SUSPENDED' if owner.armed else 'ALREADY_MONITORED','reason':reason}
    except (MonitorError,P.ControllerError,F.GateError,S.Failure,OSError,ValueError,KeyError,TypeError) as error:
        reason=str(error) if isinstance(error,MonitorError) else 'MONITOR_METADATA_OR_START_FAILED'
        return {'phase':'SUSPENDED','reason':reason}
    finally:
        try:
            if owner.armed and not owner.completed:
                try: owner.suspend(reason)
                except (OSError,ValueError,TypeError,F.GateError,MonitorError): pass
        finally:
            try: owner.cleanup()
            finally:
                if lock is not None: os.close(lock)
                os.close(directory)


def unit_text(args):
    validate(args)
    if not args.user or not USER.fullmatch(args.user) or args.user=='root':
        raise MonitorError('NONROOT_SERVICE_USER_REQUIRED')
    interpreter=safe_path(args.python); monitor=safe_path(args.monitor_path)
    argv=[str(interpreter),str(monitor),'run','--mode',args.mode,'--live']
    for name in PATH_FIELDS+('expected_binary_sha256','expected_scope_sha256'):
        argv.extend(['--'+name.replace('_','-'),str(getattr(args,name))])
    if args.mode=='periodic': argv.extend(['--expected-primary-run-id',args.expected_primary_run_id])
    name='owa-'+args.mode
    runtime=86640 if args.mode=='primary' else 300
    service=('''[Unit]
Description=Finite OWA qualification monitor
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
User='''+args.user+'''
Restart=no
KillMode=control-group
TimeoutStopSec=30s
RuntimeMaxSec='''+str(runtime)+'''s
UMask=0077
NoNewPrivileges=yes
StandardOutput=null
StandardError=null
Environment=PATH=/usr/bin:/bin
Environment=PYTHONDONTWRITEBYTECODE=1
UnsetEnvironment=OPENAI_API_KEY LINEAR_API GMKR_LINEAR_API AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE GOOGLE_APPLICATION_CREDENTIALS
ExecStart='''+' '.join(argv)+'\n')
    units={name+'.service':service}
    if args.mode=='periodic':
        units[name+'.timer']='''[Unit]
Description=Poll qualified OWA canary metadata

[Timer]
OnBootSec=60s
OnUnitActiveSec=900s
AccuracySec=1s
Unit=owa-periodic.service

[Install]
WantedBy=timers.target
'''
    return units


def generate(args):
    units=unit_text(args); output=safe_path(args.output_dir)
    if any(output.resolve().is_relative_to(getattr(args,name).resolve()) or
           getattr(args,name).resolve().is_relative_to(output.resolve()) for name in PATH_FIELDS):
        raise MonitorError('OUTPUT_MUST_BE_SEPARATE')
    output.mkdir(mode=0o700)
    directory=F.private_directory(output)
    try:
        for name,content in units.items():
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as stream:
                stream.write(content.encode()); stream.flush(); os.fsync(stream.fileno())
        os.fsync(directory)
    finally: os.close(directory)
    return {'phase':'UNITS_PREPARED','installed':False,'files':len(units)}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('generate','run'))
    parser.add_argument('--mode',choices=('primary','periodic'),required=True)
    for name in PATH_FIELDS: parser.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    for name in ('expected_binary_sha256','expected_scope_sha256'):
        parser.add_argument('--'+name.replace('_','-'),required=True)
    parser.add_argument('--expected-primary-run-id')
    parser.add_argument('--user'); parser.add_argument('--output-dir',type=Path)
    parser.add_argument('--python',type=Path,default=Path('/usr/bin/python3'))
    parser.add_argument('--monitor-path',type=Path,default=Path(__file__).resolve())
    parser.add_argument('--live',action='store_true')
    args=parser.parse_args(argv)
    try:
        if args.command=='generate': result=generate(args)
        else:
            if not args.live or platform.system()!='Linux' or os.geteuid()==0:
                raise MonitorError('EXPLICIT_NONROOT_LINUX_LIVE_REQUIRED')
            stopped=[False]; previous={}
            try:
                for number in (signal.SIGTERM,signal.SIGINT):
                    previous[number]=signal.signal(number,lambda *_:stopped.__setitem__(0,True))
                result=run_owned(args,cancelled=lambda:stopped[0])
            finally:
                for number,handler in previous.items(): signal.signal(number,handler)
        print(json.dumps(result,separators=(',',':')))
        return 2 if result['phase']=='SUSPENDED' else 0
    except (MonitorError,P.ControllerError,F.GateError,S.Failure,OSError,ValueError,KeyError,TypeError):
        print('{"phase":"SUSPENDED","reason":"MONITOR_CONFIGURATION_ERROR"}'); return 2


if __name__=='__main__': raise SystemExit(main())

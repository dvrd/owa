#!/usr/bin/env python3
"""Daily finite read-only Codex triage of a deterministic public protocol report."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import selectors
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('protocol_watch', HERE/'watch.py')
watch = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(watch)
MAX_OUTPUT = 65536
MAX_STREAM = 2*1024*1024
LABEL = 'com.webtools.whatsapp.protocol-review'
SCHEMA = {'type':'object','additionalProperties':False,
 'required':['status','summary','findings'],'properties':{
 'status':{'type':'string','enum':['NO_ACTION','REVIEW_REQUIRED','FAILED']},
 'summary':{'type':'string','maxLength':2000},
 'findings':{'type':'array','maxItems':10,'items':{'type':'object',
  'additionalProperties':False,'required':['severity','source','path','recommendation'],
  'properties':{'severity':{'type':'string','enum':['low','medium','high']},
   'source':{'type':'string','maxLength':200},'path':{'type':'string','maxLength':200},
   'recommendation':{'type':'string','maxLength':2000}}}}}}

class ScheduleError(Exception): pass

def validate_result(value):
    if not isinstance(value,dict) or set(value)!={'status','summary','findings'}:
        raise ScheduleError('AGENT_RESULT_INVALID')
    if value['status'] not in ('NO_ACTION','REVIEW_REQUIRED','FAILED'):
        raise ScheduleError('AGENT_RESULT_INVALID')
    if not isinstance(value['summary'],str) or len(value['summary'])>2000:
        raise ScheduleError('AGENT_RESULT_INVALID')
    if not isinstance(value['findings'],list) or len(value['findings'])>10:
        raise ScheduleError('AGENT_RESULT_INVALID')
    for item in value['findings']:
        if not isinstance(item,dict) or set(item)!={'severity','source','path','recommendation'}:
            raise ScheduleError('AGENT_RESULT_INVALID')
        if item['severity'] not in ('low','medium','high'):
            raise ScheduleError('AGENT_RESULT_INVALID')
        for key,limit in (('source',200),('path',200),('recommendation',2000)):
            if not isinstance(item[key],str) or len(item[key])>limit:
                raise ScheduleError('AGENT_RESULT_INVALID')
    return value

def command(codex, library, schema):
    return [str(codex),'exec','--sandbox','read-only','--ephemeral','-C',str(library),
            '--output-schema',str(schema),'--color','never','-']

def stop_group(child, hard=False):
    first=signal.SIGKILL if hard else signal.SIGTERM
    try: os.killpg(child.pid,first)
    except ProcessLookupError: pass
    try: child.wait(timeout=5)
    except subprocess.TimeoutExpired: pass
    # Tool descendants can outlive the Codex process-group leader.
    try: os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    child.wait(timeout=5)

def agent_environment():
    # Reuse saved CLI auth without forwarding business/provider credential variables.
    allowed=('HOME','USER','LOGNAME','PATH','TMPDIR','LANG','LC_ALL','SHELL','CODEX_HOME')
    return {key:os.environ[key] for key in allowed if key in os.environ}

def agent_run(argv, prompt, seconds, clock=time.monotonic, spawn=subprocess.Popen):
    if not 1<=seconds<=600: raise ScheduleError('BUDGET_INVALID')
    child=spawn(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                start_new_session=True,env=agent_environment())
    output=bytearray(); total=0; selector=selectors.DefaultSelector()
    deadline=clock()+seconds; expired=False
    try:
        os.set_blocking(child.stdin.fileno(),False)
        selector.register(child.stdin,selectors.EVENT_WRITE,'stdin')
        pending=memoryview(prompt)
        for stream in (child.stdout,child.stderr):
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,stream is child.stdout)
        while selector.get_map():
            if clock()>=deadline:
                expired=True; raise ScheduleError('AGENT_DEADLINE')
            for key,_ in selector.select(timeout=min(1,max(0,deadline-clock()))):
                if key.data=='stdin':
                    try: count=os.write(key.fd,pending[:4096])
                    except BrokenPipeError:
                        raise ScheduleError('AGENT_INPUT_FAILED') from None
                    pending=pending[count:]
                    if not pending:
                        selector.unregister(child.stdin); child.stdin.close()
                    continue
                data=os.read(key.fd,4096)
                if not data: selector.unregister(key.fileobj); continue
                total+=len(data)
                if total>MAX_STREAM: raise ScheduleError('AGENT_STREAM_LIMIT')
                if key.data:
                    output.extend(data)
                    if len(output)>MAX_OUTPUT: raise ScheduleError('AGENT_OUTPUT_LIMIT')
        try: code=child.wait(timeout=max(0,deadline-clock()))
        except subprocess.TimeoutExpired:
            expired=True; raise ScheduleError('AGENT_DEADLINE') from None
        if code!=0: raise ScheduleError('AGENT_EXEC_FAILED')
        try: value=json.loads(output)
        except (ValueError,UnicodeError): raise ScheduleError('AGENT_RESULT_INVALID') from None
        return validate_result(value)
    finally:
        selector.close(); stop_group(child,hard=expired)
        child.stdout.close(); child.stderr.close()
        if not child.stdin.closed: child.stdin.close()

def report_open(path):
    import stat
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or
                info.st_mode & 0o077 or info.st_nlink!=1 or info.st_size>watch.MAX_REPORT):
            raise ScheduleError('WATCH_REPORT_UNSAFE')
        return fd,(info.st_dev,info.st_ino)
    except BaseException:
        os.close(fd); raise

def watch_capture(argv, clock=time.monotonic):
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,start_new_session=True,env=agent_environment())
    deadline=clock()+240; output=bytearray(); total=0; expired=False
    selector=selectors.DefaultSelector()
    try:
        for stream in (child.stdout,child.stderr):
            os.set_blocking(stream.fileno(),False)
            selector.register(stream,selectors.EVENT_READ,stream is child.stdout)
        while selector.get_map():
            if clock()>=deadline:
                expired=True; raise ScheduleError('WATCH_DEADLINE')
            for key,_ in selector.select(timeout=min(1,max(0,deadline-clock()))):
                data=os.read(key.fd,4096)
                if not data: selector.unregister(key.fileobj); continue
                total+=len(data)
                if total>MAX_STREAM: raise ScheduleError('WATCH_STREAM_LIMIT')
                if key.data:
                    output.extend(data)
                    if len(output)>MAX_OUTPUT: raise ScheduleError('WATCH_OUTPUT_LIMIT')
        try: code=child.wait(timeout=max(0,deadline-clock()))
        except subprocess.TimeoutExpired:
            expired=True; raise ScheduleError('WATCH_DEADLINE') from None
        if code not in (0,3): raise ScheduleError('WATCH_EXEC_FAILED')
        try: value=json.loads(output)
        except (ValueError,UnicodeError): raise ScheduleError('WATCH_RESULT_INVALID') from None
        expected='NO_MONITORED_DRIFT' if code==0 else 'REVIEW_REQUIRED'
        if not isinstance(value,dict) or value.get('status')!=expected:
            raise ScheduleError('WATCH_RESULT_INVALID')
        return value
    finally:
        selector.close(); stop_group(child,hard=expired)
        child.stdout.close(); child.stderr.close()

def watch_run(args, clock=time.monotonic, argv=None):
    path=args.state_dir/'report.json'; previous=None
    try:
        try: previous,old_identity=report_open(path)
        except FileNotFoundError: old_identity=None
        command=argv or [sys.executable,str(HERE/'watch.py'),'--manifest',str(args.manifest),
                         '--state-dir',str(args.state_dir)]
        summary=watch_capture(command,clock)
        fd,identity=report_open(path)
        with os.fdopen(fd,'rb') as stream:
            if identity==old_identity: raise ScheduleError('WATCH_REPORT_STALE')
            data=stream.read(watch.MAX_REPORT+1)
        if len(data)>watch.MAX_REPORT: raise ScheduleError('WATCH_REPORT_LIMIT')
        try: report=json.loads(data)
        except (ValueError,UnicodeError): raise ScheduleError('WATCH_REPORT_INVALID') from None
        if not isinstance(report,dict) or not isinstance(report.get('observation'),dict):
            raise ScheduleError('WATCH_REPORT_INVALID')
        if {key:value for key,value in report.items() if key!='observation'}!=summary:
            raise ScheduleError('WATCH_REPORT_MISMATCH')
        return report
    finally:
        if previous is not None: os.close(previous)

def run(args):
    if args.library.resolve()!=HERE.parents[1].resolve():
        raise ScheduleError('LIBRARY_SCOPE_INVALID')
    with watch.locked_state(args.state_dir): pass
    state=args.state_dir/'review-agent'
    with watch.locked_state(state):
        result={'status':'FAILED','compatibility_approved':False,'runtime_version_changed':False}
        try:
            report=watch_run(args)
            if report['status'] not in ('REVIEW_REQUIRED','NO_MONITORED_DRIFT'):
                raise ScheduleError('WATCH_FAILED')
            data=json.dumps(report,separators=(',',':')).encode()
            if len(data)>watch.MAX_REPORT: raise ScheduleError('PUBLIC_REPORT_LIMIT')
            schema=state/'result-schema.json'; watch.atomic_json(schema,SCHEMA)
            prompt=(HERE/'review-agent-prompt.md').read_bytes()+b'\nPUBLIC REPORT JSON:\n'+data
            review=agent_run(command(args.codex,args.library,schema),prompt,args.budget_seconds)
            allowed={source['name']:{item['path'] for item in source['files']}
                     for source in report['observation']['sources']}
            for finding in review['findings']:
                if finding['path'] not in allowed.get(finding['source'],set()):
                    raise ScheduleError('AGENT_SOURCE_INVALID')
            result.update(status=report['status'],agent_review=review,
                          checked_at_unix=int(time.time()))
            if review['status'] in ('FAILED','REVIEW_REQUIRED'):
                result['status']=review['status']
        except (watch.WatchError,ScheduleError) as error:
            result['reason']=str(error)
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
            result['reason']='SCHEDULE_FAILED'
        watch.atomic_json(state/'agent-review.json',result)
        if result['status'] in ('FAILED','REVIEW_REQUIRED'):
            watch.atomic_json(state/'alert.json',{
                'status':result['status'],'checked_at_unix':int(time.time()),
                'reason':result.get('reason','PUBLIC_PROTOCOL_REVIEW_REQUIRED'),
                'compatibility_approved':False})
        else: (state/'alert.json').unlink(missing_ok=True)
        return result

def plist(args):
    if not 1<=args.budget_seconds<=600: raise ScheduleError('BUDGET_INVALID')
    paths=(args.state_dir,args.manifest,args.library,args.codex)
    if any(not path.is_absolute() for path in paths): raise ScheduleError('PATH_INVALID')
    argv=[sys.executable,str(Path(__file__).resolve()),'run','--manifest',str(args.manifest),
          '--state-dir',str(args.state_dir),'--library',str(args.library),'--codex',str(args.codex),
          '--budget-seconds',str(args.budget_seconds)]
    return {'Label':LABEL,'ProgramArguments':argv,'StartCalendarInterval':{'Hour':9,'Minute':0},
            'RunAtLoad':False,'ProcessType':'Background','ExitTimeOut':15,
            'WorkingDirectory':str(args.library),
            'StandardOutPath':'/dev/null','StandardErrorPath':'/dev/null',
            'EnvironmentVariables':{'PATH':'/opt/homebrew/bin:/usr/bin:/bin'},
            'Umask':0o077}

def write_plist(args):
    with watch.locked_state(args.state_dir): pass
    with watch.locked_state(args.state_dir/'review-agent'):
        value=plist(args); data=plistlib.dumps(value)
        path=args.state_dir/'review-agent'/'daily-review.plist'
        import tempfile
        fd,name=tempfile.mkstemp(prefix='.schedule-',dir=path.parent)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(name,path)
        finally: Path(name).unlink(missing_ok=True)
        if plistlib.loads(path.read_bytes())!=value: raise ScheduleError('PLIST_INVALID')
        return {'status':'PLIST_PREPARED','installed':False,'daily_local_time':'09:00'}

def interrupted(*_): raise ScheduleError('INTERRUPTED')

class Parser(argparse.ArgumentParser):
    def error(self,message): raise ScheduleError('ARGUMENTS_INVALID')

def main(argv=None):
    parser=Parser(description=__doc__)
    parser.add_argument('command',choices=('run','plist'))
    parser.add_argument('--manifest',type=Path,default=HERE/'sources.json')
    parser.add_argument('--state-dir',type=Path,required=True)
    parser.add_argument('--library',type=Path,default=HERE.parents[1])
    parser.add_argument('--codex',type=Path,default=Path('/opt/homebrew/bin/codex'))
    parser.add_argument('--budget-seconds',type=int,default=600)
    try:
        args=parser.parse_args(argv)
        if not 1<=args.budget_seconds<=600: raise ScheduleError('BUDGET_INVALID')
        previous=signal.signal(signal.SIGTERM,interrupted)
        try: result=run(args) if args.command=='run' else write_plist(args)
        finally: signal.signal(signal.SIGTERM,previous)
        print(json.dumps(result,separators=(',',':')))
        return 2 if result['status']=='FAILED' else 0
    except (watch.WatchError,ScheduleError) as error:
        result={'status':'FAILED','reason':str(error),'compatibility_approved':False}
    except (OSError,ValueError):
        result={'status':'FAILED','reason':'LOCAL_STATE_FAILED','compatibility_approved':False}
    print(json.dumps(result,separators=(',',':'))); return 2

if __name__=='__main__': raise SystemExit(main())

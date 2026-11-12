#!/usr/bin/env python3
"""Explicit, private, finite native WhatsApp watch and canary supervision."""
import argparse, fcntl, hashlib, importlib.util, json, os
from pathlib import Path
import re, secrets, selectors, signal, subprocess, sys, time, warnings
SPEC = importlib.util.spec_from_file_location('qr_protocol',
    Path(__file__).resolve().parents[1]/'live_qualification'/'qr_display.py')
PROTO = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(PROTO)
PROGRESS_SPEC = importlib.util.spec_from_file_location('watch_progress',
    Path(__file__).with_name('progress.py'))
PROGRESS = importlib.util.module_from_spec(PROGRESS_SPEC)
PROGRESS_SPEC.loader.exec_module(PROGRESS)
LIMIT = 65536
HEALTH = re.compile(rb'WATCH_HEALTH uptime_seconds=([0-9]{1,6}) reconnects=([0-9]{1,4})\n')
PHASES = PROTO.PHASES | {'WATCH_RECONNECTING', 'WATCH_COMPLETE'}
class Failure(Exception): pass

def private_dir(path, create=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: raise Failure('DIRECTORY_INVALID')
    if create: path.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o7777 != 0o700:
        os.close(fd); raise Failure('DIRECTORY_UNSAFE')
    return fd

def checked_file(fd):
    import stat
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
        info.st_mode & 0o7777 != 0o600 or info.st_nlink != 1): raise Failure('FILE_UNSAFE')

def lock(directory, name):
    fd = os.open(name, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        checked_file(fd); fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); return fd
    except BaseException:
        os.close(fd); raise

def write_json(directory, name, value):
    data = json.dumps(value, separators=(',', ':')).encode()
    if len(data) > LIMIT: raise Failure('STATE_LIMIT')
    temporary = '.pending-'+secrets.token_hex(12)
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try: os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError: pass

def read_json(directory, name):
    fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as stream:
        checked_file(stream.fileno()); data = stream.read(LIMIT+1)
    if len(data) > LIMIT: raise Failure('STATE_LIMIT')
    return json.loads(data)

def remove(directory, name):
    try: os.unlink(name, dir_fd=directory)
    except FileNotFoundError: pass

def binary_hash(path):
    with open(path, 'rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def prepare(args):
    auth = private_dir(args.auth_dir); os.close(auth)
    binary = Path(args.binary)
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise Failure('BINARY_INVALID')
    if not 60 <= args.duration_seconds <= 172800: raise Failure('DURATION_INVALID')
    interval=getattr(args,'canary_interval_seconds',0)
    send=getattr(args,'send',False)
    if (interval!=0 and (not 3600<=interval<=86400 or not send or
            not args.allow_scoped_retries)) or (send and interval==0):
        raise Failure('CANARY_CONFIG_INVALID')
    subject = args.group_subject
    if not subject or len(subject.encode()) > 256 or any(ord(c)<32 or ord(c)==127 for c in subject):
        raise Failure('SUBJECT_INVALID')
    directory = private_dir(args.state_dir, create=True); owner = None
    try:
        owner = lock(directory, 'owner.lock')
        allowed = {'owner.lock','config.json','status.json','events.json',
                   'alert.json','stop.json','version-warning.json','progress.json'}
        if set(os.listdir(directory))-allowed: raise Failure('DIRECTORY_NOT_OWNED')
        write_json(directory, 'config.json', {'schema':1, 'mode':'watch',
            'auth_dir':str(Path(args.auth_dir)), 'binary':str(binary),
            'binary_sha256':binary_hash(binary), 'group_subject':subject,
            'duration_seconds':args.duration_seconds,
            'allow_scoped_retries':args.allow_scoped_retries,
            'canary_interval_seconds':interval,'send':send})
    finally:
        if owner is not None: os.close(owner)
        os.close(directory)
    return {'phase':'PREPARED'}

def protocol_line(line):
    metadata = PROTO.native_watch_metadata(line)
    if metadata is not None: return metadata
    if line.startswith(b'PHASE ') and line.endswith(b'\n'):
        try: phase = line[6:-1].decode('ascii')
        except UnicodeError: raise Failure('CHILD_PROTOCOL_INVALID') from None
        if phase in PHASES: return {'phase':phase}
    counts = PROTO.native_group_counts(line)
    if counts is not None: return {'phase':'GROUP_COUNTS', **counts}
    raise Failure('CHILD_PROTOCOL_INVALID')

def event(directory, events, value):
    events.append({'time_unix':int(time.time()), **value}); del events[:-128]
    write_json(directory, 'events.json', events)

def stop_child(child):
    if child.poll() is None:
        child.terminate()
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait(timeout=5)

def monitor(child, directory, duration, clock=time.monotonic, cancelled=lambda: False,
            canary_interval=0, wall_clock=time.time):
    selector=selectors.DefaultSelector()
    try:
        return monitor_io(child,directory,duration,clock,cancelled,canary_interval,
                          selector,wall_clock)
    finally:
        selector.close(); stop_child(child); child.stdout.close(); child.stderr.close()


def monitor_io(child,directory,duration,clock,cancelled,canary_interval,selector,wall_clock):
    started = clock()
    deadline = started+duration+30
    last_progress = started; last_clock = started
    last_progress_wall=wall_clock()
    try: current = read_json(directory,'status.json')
    except FileNotFoundError: current = {}
    try: previous = read_json(directory,'progress.json')
    except FileNotFoundError: previous = None
    if not isinstance(current,dict): raise Failure('STATE_INVALID')
    tracker = PROGRESS.Progress(current.get('run_id'),
        current.get('started_unix',int(time.time())),duration,canary_interval,previous)
    for stream, kind in ((child.stdout,'stdout'),(child.stderr,'stderr')):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, kind)
    buffers = {'stdout':bytearray(),'stderr':bytearray()}
    discarding = False; events = []; last_error = None; complete = False
    try:
        while selector.get_map():
            if cancelled(): return {'phase':'STOPPED'}
            try:
                read_json(directory, 'stop.json'); return {'phase':'STOPPED'}
            except FileNotFoundError: pass
            now = clock(); last_clock = now
            if now >= deadline: raise Failure('CHILD_DEADLINE')
            gap=max(now-last_progress,wall_clock()-last_progress_wall)
            if gap>=180:
                tracker.values['max_health_gap_seconds']=max(
                    tracker.values['max_health_gap_seconds'],gap)
                tracker.values['health_gap_events']+=1
                raise Failure('CHILD_STALLED')
            ready=selector.select(timeout=1)
            gap=wall_clock()-last_progress_wall
            if gap>=180:
                tracker.values['max_health_gap_seconds']=max(
                    tracker.values['max_health_gap_seconds'],gap)
                tracker.values['health_gap_events']+=1
                raise Failure('CHILD_STALLED')
            for key, _ in ready:
                data = os.read(key.fd,4096); kind = key.data
                if not data:
                    selector.unregister(key.fileobj)
                    if kind == 'stdout' and buffers[kind]: raise Failure('CHILD_PROTOCOL_INVALID')
                    continue
                for byte in data:
                    if kind == 'stderr' and discarding:
                        if byte == 10: discarding = False
                        continue
                    buffers[kind].append(byte)
                    if len(buffers[kind]) > 4096:
                        buffers[kind].clear()
                        if kind == 'stdout': raise Failure('CHILD_PROTOCOL_INVALID')
                        discarding = byte != 10; continue
                    if byte != 10: continue
                    line = bytes(buffers[kind]); buffers[kind].clear()
                    if kind == 'stderr':
                        parsed = PROTO.native_error(line)
                        if parsed is not None: last_error = parsed
                    else:
                        parsed = protocol_line(line)
                        event_wall=wall_clock()
                        gap=event_wall-last_progress_wall
                        if gap>=180:
                            tracker.values['max_health_gap_seconds']=max(
                                tracker.values['max_health_gap_seconds'],gap)
                            tracker.values['health_gap_events']+=1
                            raise Failure('CHILD_STALLED')
                        last_progress = clock(); last_clock = last_progress
                        last_progress_wall=event_wall
                        tracker.observe(parsed,last_progress,int(time.time()))
                        write_json(directory,'progress.json',tracker.values)
                        if parsed['phase']=='VERSION_PINNED':
                            write_json(directory,'version-warning.json',
                                {'version_fallback':True,'warning':'VERSION_PINNED',
                                 'time_unix':int(time.time())})
                        elif parsed['phase']=='VERSION_DISCOVERED':
                            remove(directory,'version-warning.json')
                        complete = complete or parsed['phase'] == 'WATCH_COMPLETE'
                        event(directory, events, parsed)
        result = child.wait(timeout=5)
        if result != 0 or last_error is not None or not complete:
            return {'phase':'FAILED','reason':'CHILD_FAILED',**(last_error or {})}
        reason = tracker.finish(int(time.time()),max(0,last_clock-started))
        if reason is not None: return {'phase':'FAILED','reason':reason}
        return {'phase':'COMPLETE'}
    finally:
        tracker.values['run_finished_unix']=int(time.time())
        tracker.values['observed_run_seconds']=tracker.prior_elapsed+max(0,last_clock-started)
        write_json(directory,'progress.json',tracker.values)

def validate_config(config):
    config.setdefault('canary_interval_seconds',0); config.setdefault('send',False)
    interval=config['canary_interval_seconds']; send=config['send']
    if type(interval) is not int or type(send) is not bool or (
        interval!=0 and (not 3600<=interval<=86400 or not send or
                        config.get('allow_scoped_retries') is not True)) or (
        send and interval==0): raise Failure('CANARY_CONFIG_INVALID')
    if (config.get('schema') != 1 or config.get('mode') != 'watch' or
        type(config.get('duration_seconds')) is not int or
        not 60 <= config['duration_seconds'] <= 172800 or
        type(config.get('allow_scoped_retries')) is not bool): raise Failure('CONFIG_INVALID')
    for name in ('auth_dir','binary','group_subject','binary_sha256'):
        if not isinstance(config.get(name),str): raise Failure('CONFIG_INVALID')
    if not re.fullmatch(r'[0-9a-f]{64}',config['binary_sha256']): raise Failure('CONFIG_INVALID')
    subject = config['group_subject']
    if not subject or len(subject.encode())>256 or any(ord(c)<32 or ord(c)==127 for c in subject):
        raise Failure('CONFIG_INVALID')
    if binary_hash(config['binary']) != config['binary_sha256']: raise Failure('BINARY_CHANGED')
    return config

def native_command(config):
    command = [config['binary'],'watch','--auth-dir',config['auth_dir'],
               '--group-subject',config['group_subject'],'--timeout-seconds',
               str(config['duration_seconds'])]
    if config['allow_scoped_retries']: command.append('--allow-scoped-retries')
    if config.get('canary_interval_seconds',0):
        command.extend(['--send','--canary-interval-seconds',
                        str(config['canary_interval_seconds'])])
    return command

def start(args):
    if not args.live: raise Failure('LIVE_OPT_IN_REQUIRED')
    directory = private_dir(args.state_dir); owner = None
    try:
        owner = lock(directory,'owner.lock')
        validate_config(read_json(directory,'config.json'))
        previous = None
        try: previous = read_json(directory,'status.json')
        except FileNotFoundError: pass
        if previous and previous['phase'] not in ('COMPLETE','STOPPED') and not args.resume:
            raise Failure('RESUME_REQUIRED')
        if args.resume and not previous: raise Failure('NO_RUN_TO_RESUME')
        if args.resume and previous['phase']=='COMPLETE': raise Failure('RUN_ALREADY_COMPLETE')
        run_id = previous['run_id'] if args.resume else secrets.token_hex(16)
        remove(directory,'stop.json'); remove(directory,'alert.json')
        write_json(directory,'status.json',{'phase':'STARTING','run_id':run_id,'pid':None})
        env = dict(os.environ, WHATSAPP_SUPERVISOR_LOCK=str(owner))
        child = subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'_run',
            '--state-dir',str(args.state_dir)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,pass_fds=(owner,),start_new_session=True,env=env)
        pid = child.pid
        # This short-lived launcher deliberately transfers process ownership.
        # The detached worker owns child cleanup, state and its finite deadline.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',ResourceWarning)
            del child
        return {'phase':'STARTED','run_id':run_id,'pid':pid}
    finally:
        if owner is not None: os.close(owner)
        os.close(directory)

def worker(args):
    directory = private_dir(args.state_dir); owner = None; auth = None; session = None
    current = {'phase':'FAILED','run_id':'unknown'}
    previous_signals = {}
    cancelled = [False]
    try:
        current = read_json(directory,'status.json')
        owner = int(os.environ.pop('WHATSAPP_SUPERVISOR_LOCK','-1'))
        if owner < 3: raise Failure('WORKER_NOT_LAUNCHED')
        checked_file(owner)
        expected = os.stat('owner.lock',dir_fd=directory,follow_symlinks=False)
        actual = os.fstat(owner)
        if (actual.st_dev,actual.st_ino)!=(expected.st_dev,expected.st_ino):
            raise Failure('WORKER_NOT_LAUNCHED')
        config = validate_config(read_json(directory,'config.json'))
        auth = private_dir(config['auth_dir'])
        session = lock(auth,'reliability.owner.lock')
        current.update(phase='RUNNING',pid=os.getpid(),started_unix=int(time.time()))
        write_json(directory,'status.json',current)
        for number in (signal.SIGTERM,signal.SIGINT):
            handler = lambda *_: cancelled.__setitem__(0,True)
            previous_signals[number] = signal.signal(number,handler)
        child = subprocess.Popen(native_command(config),stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
        current['native_pid'] = child.pid
        write_json(directory,'status.json',current)
        result = monitor(child,directory,config['duration_seconds'],
            cancelled=lambda: cancelled[0],canary_interval=config.get('canary_interval_seconds',0))
        current.update(result)
    except (Failure,PROGRESS.ProgressError) as error:
        current.update(phase='FAILED',reason=str(error))
    except (OSError,ValueError,KeyError,subprocess.SubprocessError):
        current.update(phase='FAILED',reason='SUPERVISOR_ERROR')
    finally:
        for number,handler in previous_signals.items(): signal.signal(number,handler)
        current['finished_unix'] = int(time.time())
        try:
            progress=read_json(directory,'progress.json')
            if progress.get('run_id')==current.get('run_id'): current['progress']=progress
        except FileNotFoundError: pass
        write_json(directory,'status.json',current)
        if current['phase']=='FAILED': write_json(directory,'alert.json',current)
        for fd in (session,auth,owner,directory):
            if fd is not None and fd >= 0: os.close(fd)
    return {'phase':current['phase']}

def inspect_state(args):
    directory = private_dir(args.state_dir)
    try:
        if args.command=='stop':
            write_json(directory,'stop.json',{'stop':True}); return {'phase':'STOP_REQUESTED'}
        current = read_json(directory,'status.json')
        try:
            progress=read_json(directory,'progress.json')
            if progress.get('run_id')==current.get('run_id'): current['progress']=progress
        except FileNotFoundError: pass
        current['version_fallback']=False
        try:
            warning=read_json(directory,'version-warning.json')
            current['version_fallback']=warning.get('version_fallback') is True
        except FileNotFoundError: pass
        owner = None
        try: owner = lock(directory,'owner.lock')
        except BlockingIOError:
            if current['phase']=='RUNNING':
                progress=current.get('started_unix',int(time.time()))
                try:
                    events=read_json(directory,'events.json')
                    if events: progress=max(progress,events[-1]['time_unix'])
                except FileNotFoundError: pass
                if time.time()-progress>=180:
                    current.update(phase='STALLED',reason='CHILD_STALLED')
                    write_json(directory,'alert.json',current)
            return current
        finally:
            if owner is not None: os.close(owner)
        if current['phase'] in ('STARTING','RUNNING'):
            current['phase']='INTERRUPTED'
            write_json(directory,'alert.json',current)
        return current
    finally: os.close(directory)

class Parser(argparse.ArgumentParser):
    def error(self,message): raise Failure('INVALID_ARGUMENTS')

def main(argv=None):
    parser = Parser(description=__doc__)
    sub = parser.add_subparsers(dest='command',required=True)
    for name in ('prepare','start','stop','status','_run'):
        command = sub.add_parser(name); command.add_argument('--state-dir',type=Path,required=True)
        if name=='prepare':
            command.add_argument('--auth-dir',type=Path,required=True)
            command.add_argument('--binary',type=Path,required=True)
            command.add_argument('--group-subject',required=True)
            command.add_argument('--duration-seconds',type=int,default=86400)
            command.add_argument('--allow-scoped-retries',action='store_true')
            command.add_argument('--send',action='store_true')
            command.add_argument('--canary-interval-seconds',type=int,default=0)
        if name=='start':
            command.add_argument('--live',action='store_true')
            command.add_argument('--resume',action='store_true')
    try:
        args = parser.parse_args(argv)
        if args.command=='prepare': result=prepare(args)
        elif args.command=='start': result=start(args)
        elif args.command=='_run': result=worker(args)
        else: result=inspect_state(args)
        print(json.dumps(result,separators=(',',':')))
        return 1 if result['phase']=='FAILED' else 0
    except Failure as error: result={'phase':'FAILED','reason':str(error)}
    except (OSError,ValueError,KeyError): result={'phase':'FAILED','reason':'SUPERVISOR_ERROR'}
    print(json.dumps(result,separators=(',',':'))); return 1

if __name__=='__main__': sys.exit(main())

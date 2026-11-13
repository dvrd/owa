"""Synthetic metadata and owned disposable children; no account/provider/systemd job."""
import configparser
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location('systemd_test_'+name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

M=load('systemd_canary'); B=load('test_periodic_canary'); SB=load('test_supervisor')

class Tests(unittest.TestCase):
    def fixture(self,tmp):
        base=B.Tests();args,now,config=base.fixture(tmp)
        args.mode='periodic'
        return base,args,now+21600,config

    def child(self,seconds=.1):
        return subprocess.Popen([sys.executable,'-c','import time;time.sleep('+str(seconds)+')'],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            start_new_session=True)

    def assert_reaped(self,child):
        self.assertIsNotNone(child.returncode)
        with self.assertRaises(ChildProcessError):os.waitpid(child.pid,os.WNOHANG)

    def test_owned_start_retains_actual_handle_and_default_detached_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=SB.Tests().setup_private(tmp)
            args.binary.write_text('#!'+sys.executable+'\nprint("PHASE WATCH_COMPLETE",flush=True)\n')
            args.binary.chmod(0o700);args.duration_seconds=60
            M.S.prepare(args);args.live=True;args.resume=False
            result,child=M.S.start_owned(args,environment=M.environment(),require_fresh=True)
            self.assertIsInstance(child,subprocess.Popen)
            self.assertEqual(result['pid'],child.pid)
            try:child.wait(timeout=10)
            finally:M.S.stop_child(child)
            self.assert_reaped(child)
            d=M.S.private_dir(args.state_dir)
            try:
                fd=M.S.lock(d,'owner.lock');os.close(fd)
            finally:os.close(d)

    def test_owned_start_rejects_changed_config_and_reused_primary_before_spawn(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=SB.Tests().setup_private(tmp);M.S.prepare(args);args.live=True;args.resume=False
            with mock.patch.object(M.S.subprocess,'Popen') as spawn:
                with self.assertRaisesRegex(M.S.Failure,'CONFIG_CHANGED'):
                    M.S.start_owned(args,expected_config={})
                d=M.S.private_dir(args.state_dir)
                try:M.S.write_json(d,'status.json',{'phase':'COMPLETE','run_id':'a'*32})
                finally:os.close(d)
                with self.assertRaisesRegex(M.S.Failure,'STATE_ALREADY_USED'):
                    M.S.start_owned(args,require_fresh=True)
                spawn.assert_not_called()

    def test_periodic_one_child_guard_blocks_ordinary_polls_until_reaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,args,due,config=self.fixture(tmp);children=[];tick=[due];calls=[]
            def start(source,options,environment):
                calls.append(1)
                info=base.fake_launch(due)[1](source,options)
                child=self.child();children.append(child);info['pid']=child.pid
                self.assertTrue(M.guard_exists(args))
                self.assertNotIn('LINEAR_API',environment)
                return info,child
            def poll(options,**kw):return M.P.poll(options,inspector=base.inspector,now=tick[0],**kw)
            def pause(_):
                ordinary=mock.Mock()
                self.assertEqual(M.P.poll(args,ordinary,base.inspector,due)['phase'],'SUSPENDED')
                ordinary.assert_not_called()
                children[0].wait(timeout=2)
                base.complete(args,due);tick[0]=due+181
            result=M.run_owned(args,poller=poll,periodic_starter=start,sleep=pause)
            self.assertEqual(result,{'phase':'COMPLETE'});self.assertEqual(calls,[1])
            self.assertFalse(M.guard_exists(args));self.assert_reaped(children[0])
            self.assertEqual(poll(args)['phase'],'NOT_DUE')

    def test_timeout_and_cancel_latch_and_reap_without_later_launch(self):
        for cancel in (False,True):
            with self.subTest(cancel=cancel),tempfile.TemporaryDirectory() as tmp:
                base,args,due,_=self.fixture(tmp);children=[];calls=[]
                def start(config,options,environment):
                    info=base.fake_launch(due)[1](config,options)
                    child=self.child(30);children.append(child);info['pid']=child.pid;calls.append(1)
                    return info,child
                def poll(options,**kw):return M.P.poll(options,inspector=base.inspector,now=due,**kw)
                ticks=iter((0,241))
                result=M.run_owned(args,poller=poll,periodic_starter=start,
                    clock=lambda:next(ticks),cancelled=lambda:cancel and bool(children))
                self.assertEqual(result['phase'],'SUSPENDED');self.assertTrue(M.guard_exists(args))
                self.assert_reaped(children[0]);self.assertEqual(calls,[1])
                later=mock.Mock()
                self.assertEqual(M.P.poll(args,later,base.inspector,due+300)['phase'],'SUSPENDED')
                later.assert_not_called()
                self.assertEqual(M.run_owned(args,poller=poll,periodic_starter=start)['phase'],'SUSPENDED')
                self.assertEqual(calls,[1])

    def test_failed_latch_update_keeps_pre_spawn_guard_as_durable_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,args,due,_=self.fixture(tmp);children=[]
            def start(config,options,environment):
                info=base.fake_launch(due)[1](config,options)
                child=self.child(30);children.append(child);info['pid']=child.pid
                return info,child
            def poll(options,**kw):return M.P.poll(options,inspector=base.inspector,now=due,**kw)
            ticks=iter((0,241))
            with mock.patch.object(M.Owner,'suspend',side_effect=OSError('synthetic write failure')):
                result=M.run_owned(args,poller=poll,periodic_starter=start,clock=lambda:next(ticks))
            self.assertEqual(result['phase'],'SUSPENDED');self.assert_reaped(children[0])
            self.assertEqual(M.P.read(args.controller_dir,M.P.MONITOR_GUARD)['phase'],'ARMED')
            launcher=mock.Mock()
            self.assertEqual(M.P.poll(args,launcher,base.inspector,due+300)['phase'],'SUSPENDED')
            launcher.assert_not_called()

    def test_unknown_start_result_uses_held_handle_not_supplied_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,args,due,_=self.fixture(tmp);children=[]
            def start(config,options,environment):
                info=base.fake_launch(due)[1](config,options)
                child=self.child(30);children.append(child);info['pid']=child.pid+100000
                return info,child
            def poll(options,**kw):return M.P.poll(options,inspector=base.inspector,now=due,**kw)
            self.assertEqual(M.run_owned(args,poller=poll,periodic_starter=start)['phase'],'SUSPENDED')
            self.assert_reaped(children[0]);self.assertTrue(M.guard_exists(args))

    def test_waiting_not_due_and_foreign_active_launch_nothing(self):
        for phase in ('WAITING','NOT_DUE','ACTIVE'):
            with tempfile.TemporaryDirectory() as tmp:
                _,args,_,_=self.fixture(tmp);start=mock.Mock()
                result=M.run_owned(args,poller=lambda *_a,**_k:{'phase':phase},periodic_starter=start)
                self.assertEqual(result,{'phase':phase});start.assert_not_called()
                self.assertFalse(M.guard_exists(args))

    def test_monitor_and_controller_lock_conflicts_are_bounded_without_signals(self):
        for name in ('systemd-monitor.lock','periodic.lock'):
            with tempfile.TemporaryDirectory() as tmp:
                base,args,due,_=self.fixture(tmp);d=M.F.private_directory(args.controller_dir,create=True)
                owner=M.S.lock(d,name)
                try:
                    start=mock.Mock()
                    result=M.run_owned(args,poller=lambda options,**kw:M.P.poll(
                        options,inspector=base.inspector,now=due,**kw),periodic_starter=start)
                    self.assertEqual(result['phase'],'ALREADY_MONITORED');start.assert_not_called()
                    self.assertFalse(M.guard_exists(args))
                finally:os.close(owner);os.close(d)

    def test_primary_does_not_return_just_because_metadata_finishes_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,args,_,config=self.fixture(tmp);args.mode='primary';children=[];pauses=[]
            def start(options,environment,**kw):
                self.assertTrue(kw['require_fresh']);self.assertFalse(options.resume)
                child=self.child(.15);children.append(child)
                return {'phase':'STARTED','run_id':'b'*32,'pid':child.pid},child
            def pause(_):
                self.assertTrue(M.guard_exists(args));pauses.append(1)
                children[0].wait(timeout=2)
            result=M.run_owned(args,primary_starter=start,config_reader=lambda _:config,
                primary_reader=lambda *_:'COMPLETE',sleep=pause)
            self.assertEqual(result,{'phase':'COMPLETE'});self.assertEqual(pauses,[1])
            self.assert_reaped(children[0]);self.assertFalse(M.guard_exists(args))

    def test_malformed_guard_blocks_all_periodic_polls(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,args,due,_=self.fixture(tmp);d=M.F.private_directory(args.controller_dir,create=True)
            os.close(d);path=args.controller_dir/M.P.MONITOR_GUARD;path.write_text('{invalid');path.chmod(0o600)
            launcher=mock.Mock()
            self.assertEqual(M.P.poll(args,launcher,base.inspector,due)['phase'],'SUSPENDED')
            launcher.assert_not_called()

    def test_cancel_before_start_is_durable_and_never_launches(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,args,due,_=self.fixture(tmp);start=mock.Mock()
            result=M.run_owned(args,periodic_starter=start,cancelled=lambda:True)
            self.assertEqual(result['phase'],'SUSPENDED');start.assert_not_called()
            self.assertTrue(M.guard_exists(args))
            later=mock.Mock()
            self.assertEqual(M.P.poll(args,later,base.inspector,due)['phase'],'SUSPENDED')
            later.assert_not_called()

    def test_bad_completed_cycle_or_version_never_clears_monitor_guard(self):
        for bad_version in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                base,args,due,_=self.fixture(tmp);children=[];tick=[due]
                def start(config,options,environment):
                    info=base.fake_launch(due)[1](config,options)
                    child=self.child();children.append(child);info['pid']=child.pid
                    return info,child
                def poll(options,**kw):return M.P.poll(options,inspector=base.inspector,now=tick[0],**kw)
                def pause(_):
                    children[0].wait(timeout=2)
                    base.complete(args,due,version={'major':2,'minor':999,'patch':1} if bad_version else None,
                                  new_cycles=1 if bad_version else 0)
                    tick[0]=due+181
                self.assertEqual(M.run_owned(args,poller=poll,periodic_starter=start,sleep=pause)['phase'],'SUSPENDED')
                self.assert_reaped(children[0]);self.assertTrue(M.guard_exists(args))
                next_launch=mock.Mock()
                self.assertEqual(M.P.poll(args,next_launch,base.inspector,tick[0])['phase'],'SUSPENDED')
                next_launch.assert_not_called()

    def test_owned_supervisor_cannot_execute_native_with_foreign_session_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=SB.Tests().setup_private(tmp)
            marker=Path(tmp)/'native-was-executed'
            args.binary.write_text('#!'+sys.executable+'\nfrom pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n')
            args.binary.chmod(0o700);args.duration_seconds=60
            M.S.prepare(args);args.live=True;args.resume=False
            auth=M.S.private_dir(args.auth_dir);session=M.S.lock(auth,'reliability.owner.lock')
            try:
                _,child=M.S.start_owned(args,environment=M.environment(),require_fresh=True)
                try:child.wait(timeout=10)
                finally:M.S.stop_child(child)
                self.assert_reaped(child);self.assertFalse(marker.exists())
                state=M.P.read(args.state_dir,'status.json')
                self.assertEqual(state['phase'],'FAILED')
            finally:os.close(session);os.close(auth)

    def test_auth_and_metadata_nesting_is_rejected_before_lock_creation(self):
        for field in M.PATH_FIELDS:
            for metadata_inside_auth in (False,True):
                with self.subTest(field=field,metadata_inside_auth=metadata_inside_auth),tempfile.TemporaryDirectory() as tmp:
                    base,args,due,config=self.fixture(tmp)
                    if metadata_inside_auth:
                        auth=Path(tmp)/('auth-for-'+field);auth.mkdir(mode=0o700)
                        setattr(args,field,auth/'metadata')
                    else:
                        auth=getattr(args,field)/'auth'
                    config['auth_dir']=str(auth)
                    base.write(args.primary_state_dir,'config.json',config)
                    before=set(Path(tmp).rglob('*.lock'));launcher=mock.Mock()
                    with self.assertRaisesRegex(M.P.ControllerError,'ACCOUNT_DIRECTORY_COLLISION'):
                        M.P.poll(args,launcher,base.inspector,due)
                    launcher.assert_not_called()
                    self.assertEqual(set(Path(tmp).rglob('*.lock')),before)

    def unit_args(self,tmp,mode='periodic'):
        return types.SimpleNamespace(mode=mode,user='owa',python=Path('/usr/bin/python3'),
            monitor_path=Path('/opt/owa/frozen/tools/reliability/systemd_canary.py'),
            primary_state_dir=Path('/var/lib/owa/primary'),primary_finish_dir=Path('/var/lib/owa/proof'),
            state_dir=Path('/var/lib/owa/periodic'),controller_dir=Path('/var/lib/owa/controller'),
            expected_primary_run_id='a'*32,expected_binary_sha256='b'*64,expected_scope_sha256='c'*64,
            output_dir=Path(tmp)/'prepared')

    def test_private_units_are_bounded_and_generation_has_no_launch_or_metadata_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.unit_args(tmp)
            with mock.patch.object(M.P,'poll') as poll,mock.patch.object(M.S,'start_owned') as start,\
                 mock.patch.object(M.P,'avoid_account_directory',side_effect=AssertionError('not generation')):
                self.assertEqual(M.generate(args),{'phase':'UNITS_PREPARED','installed':False,'files':2})
                poll.assert_not_called();start.assert_not_called()
            self.assertEqual(stat.S_IMODE(args.output_dir.stat().st_mode),0o700)
            for path in args.output_dir.iterdir():self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            parser=configparser.ConfigParser(interpolation=None,strict=False);parser.optionxform=str
            parser.read(args.output_dir/'owa-periodic.service');service=parser['Service']
            self.assertEqual(service['Type'],'exec');self.assertEqual(service['Restart'],'no')
            self.assertEqual(service['KillMode'],'control-group');self.assertEqual(service['RuntimeMaxSec'],'300s')
            self.assertEqual(service['TimeoutStopSec'],'30s')
            self.assertNotIn('--resume',service['ExecStart']);self.assertIn('--live',service['ExecStart'])
            timer=(args.output_dir/'owa-periodic.timer').read_text()
            self.assertIn('OnUnitActiveSec=900s',timer);self.assertNotIn('OnCalendar',timer)
            with self.assertRaises(FileExistsError):M.generate(args)
            args=self.unit_args(tmp,'primary');units=M.unit_text(args)
            self.assertEqual(set(units),{'owa-primary.service'});self.assertNotIn('[Install]',units['owa-primary.service'])

    def test_unit_generation_rejects_argument_injection_and_root(self):
        for field,value in [('user','root'),('user','owa\nExecStart=/bad'),
            ('monitor_path',Path('/opt/%n/monitor.py')),('python',Path('/usr/bin/$PYTHON')),
            ('controller_dir',Path('/var/lib/owa/has space')),
            ('expected_primary_run_id','a'*32+'\nExecStart=/bad')]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
                args=self.unit_args(tmp);setattr(args,field,value)
                with self.assertRaises((M.MonitorError,M.P.ControllerError)):M.generate(args)
                self.assertFalse(args.output_dir.exists())

    def test_worker_environment_has_no_api_keys_or_injection(self):
        with mock.patch.dict(os.environ,{'LINEAR_API':'synthetic-secret','OPENAI_API_KEY':'synthetic-secret',
            'AWS_SECRET_ACCESS_KEY':'synthetic-secret','PYTHONPATH':'/untrusted','HOME':'/synthetic-home'}):
            env=M.environment()
        self.assertEqual(set(env)-{'PATH','PYTHONDONTWRITEBYTECODE'},set(env)&{'HOME','LANG','LC_ALL','TMPDIR'})
        self.assertNotIn('synthetic-secret',str(env));self.assertNotIn('PYTHONPATH',env)

if __name__=='__main__':unittest.main()

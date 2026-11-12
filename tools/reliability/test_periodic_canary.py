"""Offline periodic-controller tests; synthetic metadata and fake launchers only."""
import hashlib, importlib.util, json, os
from pathlib import Path
import plistlib, tempfile, time, types, unittest
from unittest import mock
HERE=Path(__file__).resolve().parent

def load(name):
    spec=importlib.util.spec_from_file_location('test_'+name,HERE/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

P=load('periodic_canary'); BASE=load('test_finish_soak')

class Tests(unittest.TestCase):
    def write(self,directory,name,value):
        fd=P.F.private_directory(directory,create=True)
        try: P.F.write_json(fd,name,value)
        finally: os.close(fd)

    def fixture(self,tmp,qualified=True):
        config,status,progress,confirmation,expected,_,_=BASE.Tests().evidence()
        now=int(time.time()); shift=now-status['finished_unix']
        for value,names in ((status,('started_unix','finished_unix')),
            (progress,('run_started_unix','run_finished_unix','first_health_unix','last_health_unix',
                       'first_canary_ack_unix','last_canary_ack_unix')),
            (confirmation,('confirmed_unix',))):
            for name in names: value[name]+=shift
        config['binary']='/synthetic-not-opened/native'
        root=Path(tmp)
        args=types.SimpleNamespace(primary_state_dir=root/'primary',primary_finish_dir=root/'finish',
            state_dir=root/'periodic',controller_dir=root/'controller',
            expected_primary_run_id=expected['run_id'],expected_binary_sha256=expected['binary_sha256'],
            expected_scope_sha256=confirmation['scope_sha256'])
        for name,value in (('config.json',config),('status.json',status),('progress.json',progress)):
            self.write(args.primary_state_dir,name,value)
        mtime=status['started_unix']-1
        os.utime(args.primary_state_dir/'config.json',(mtime,mtime))
        self.write(args.primary_finish_dir,'recipient-confirmation.json',confirmation)
        receipt=P.F.evaluate(config,status,progress,confirmation,expected,mtime,now)
        encoded=json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()
        receipt.update(schema=1,proof_sha256=hashlib.sha256(encoded).hexdigest())
        if not qualified: receipt={'phase':'WAITING'}
        self.write(args.primary_finish_dir,'receipt.json',receipt)
        return args,now,config

    def inspector(self,args): return P.optional(args.state_dir,'status.json')

    def fake_launch(self,now):
        calls=[]
        def launch(config,args):
            calls.append(1); run_id=('c' if len(calls)==1 else 'd')*32
            config={**config,'duration_seconds':180,'canary_interval_seconds':21600,
                    'send':True,'allow_scoped_retries':True}
            self.write(args.state_dir,'config.json',config)
            self.write(args.state_dir,'status.json',{'phase':'RUNNING','run_id':run_id,
                                                   'started_unix':now})
            return {'phase':'STARTED','run_id':run_id}
        return calls,launch

    def complete(self,args,started,version=None,new_cycles=1):
        run_id=P.read(args.state_dir,'status.json')['run_id']
        progress={'run_id':run_id,'version':version or {'major':2,'minor':3000,'patch':1},
            'canary_completed_baseline':14,'canary_completed_latest':14+new_cycles,
            'canary_new_completed_cycles':new_cycles,'last_canary_ack_unix':started+60,
            'last_text_ack_unix':started+30,'last_pdf_ack_unix':started+60,
            'observed_run_seconds':180.25,'health_coverage_qualified':True,
            'health_gap_events':0,'connection_gap_events':0}
        self.write(args.state_dir,'progress.json',progress)
        self.write(args.state_dir,'status.json',{'phase':'COMPLETE','run_id':run_id,
            'started_unix':started,'finished_unix':started+180})
        return progress

    def test_prequalification_and_not_due_never_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now,_=self.fixture(tmp,False); launcher=mock.Mock()
            self.assertEqual(P.poll(args,launcher,self.inspector,now)['phase'],'WAITING')
            launcher.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            args,now,_=self.fixture(tmp); launcher=mock.Mock()
            self.assertEqual(P.poll(args,launcher,self.inspector,now)['phase'],'NOT_DUE')
            launcher.assert_not_called()

    def test_due_active_healthy_complete_advances_cadence_with_real_float_elapsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now,_=self.fixture(tmp); due=now+21600
            calls,launcher=self.fake_launch(due)
            self.assertEqual(P.poll(args,launcher,self.inspector,due)['phase'],'STARTED')
            self.assertEqual(P.poll(args,launcher,self.inspector,due+10)['phase'],'ACTIVE')
            self.assertEqual(len(calls),1)
            self.complete(args,due)
            result=P.poll(args,launcher,self.inspector,due+180)
            self.assertEqual(result['phase'],'NOT_DUE')
            self.assertEqual(result['next_due_unix'],due+60+21600)
            self.assertEqual(len(calls),1)

    def test_failure_unknown_and_zero_cycle_complete_suspend_without_retry(self):
        for phase in ('FAILED','STOPPED','INTERRUPTED','UNKNOWN','ZERO_CYCLES'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                args,now,_=self.fixture(tmp); due=now+21600
                calls,launcher=self.fake_launch(due)
                P.poll(args,launcher,self.inspector,due)
                if phase=='ZERO_CYCLES': self.complete(args,due,new_cycles=0)
                else:
                    self.write(args.state_dir,'status.json',{'phase':phase,'run_id':'c'*32})
                self.assertEqual(P.poll(args,launcher,self.inspector,due+180)['phase'],'SUSPENDED')
                self.assertEqual(P.poll(args,launcher,self.inspector,due+22000)['phase'],'SUSPENDED')
                self.assertEqual(len(calls),1)
                self.assertTrue((args.controller_dir/'alert.json').exists())

    def test_wrong_primary_scope_hash_and_changed_periodic_version_suspend(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now,_=self.fixture(tmp); args.expected_scope_sha256='e'*64
            launcher=mock.Mock()
            self.assertEqual(P.poll(args,launcher,self.inspector,now+21600)['phase'],'SUSPENDED')
            launcher.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            args,now,_=self.fixture(tmp); due=now+21600; calls,launcher=self.fake_launch(due)
            P.poll(args,launcher,self.inspector,due)
            self.complete(args,due,{'major':2,'minor':3000,'patch':99})
            self.assertEqual(P.poll(args,launcher,self.inspector,due+180)['phase'],'SUSPENDED')
            self.assertEqual(len(calls),1)

    def test_old_accepted_complete_cannot_erase_uncertain_launch_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now,_=self.fixture(tmp); due=now+21600; calls,launcher=self.fake_launch(due)
            P.poll(args,launcher,self.inspector,due); self.complete(args,due)
            P.poll(args,launcher,self.inspector,due+180)
            state=P.read(args.controller_dir,'controller.json'); state['phase']='LAUNCH_INTENT'
            self.write(args.controller_dir,'controller.json',state)
            result=P.poll(args,launcher,self.inspector,due+60+21600)
            self.assertEqual(result['phase'],'SUSPENDED')
            self.assertEqual(result['reason'],'PERIODIC_LAUNCH_OUTCOME_UNKNOWN')
            self.assertEqual(len(calls),1)

    def test_uncertain_active_new_run_is_waited_then_suspended_not_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now,_=self.fixture(tmp); due=now+21600; calls,launcher=self.fake_launch(due)
            P.poll(args,launcher,self.inspector,due)
            state=P.read(args.controller_dir,'controller.json')
            state.update(phase='LAUNCH_INTENT',periodic_run_id='d'*32)
            self.write(args.controller_dir,'controller.json',state)
            self.assertEqual(P.poll(args,launcher,self.inspector,due+1)['phase'],'ACTIVE')
            self.complete(args,due)
            self.assertEqual(P.poll(args,launcher,self.inspector,due+180)['phase'],'SUSPENDED')
            self.assertEqual(len(calls),1)

    def test_account_directory_collisions_are_rejected_before_lock_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now,config=self.fixture(tmp)
            args.controller_dir=Path(config['auth_dir'])
            with mock.patch.object(P.F,'private_directory',wraps=P.F.private_directory) as opened:
                with self.assertRaisesRegex(P.ControllerError,'ACCOUNT_DIRECTORY_COLLISION'):
                    P.poll(args,mock.Mock(),self.inspector,now)
            self.assertNotIn(args.controller_dir,[call.args[0] for call in opened.call_args_list])

    def test_plist_is_private_fifteen_minute_poll_without_model_or_linear(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,_,_=self.fixture(tmp); value=P.plist(args)
            self.assertEqual(value['StartInterval'],900); self.assertTrue(value['RunAtLoad'])
            self.assertNotIn('codex',' '.join(value['ProgramArguments']))
            self.assertNotIn('--linear',value['ProgramArguments'])
            self.assertFalse(P.write_plist(args)['installed'])
            path=args.controller_dir/'periodic-canary.plist'
            self.assertEqual(plistlib.loads(path.read_bytes()),value)
            self.assertEqual(path.stat().st_mode & 0o7777,0o600)

if __name__=='__main__': unittest.main()

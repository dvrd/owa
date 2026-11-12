"""Offline schedule/fake-Codex tests: no auth/account or external network calls."""
import contextlib, importlib.util, io, json, os
from pathlib import Path
import plistlib, stat, sys, tempfile, types, unittest
from unittest import mock
SPEC=importlib.util.spec_from_file_location('schedule',Path(__file__).with_name('schedule.py'))
S=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(S)
GOOD={'status':'NO_ACTION','summary':'No behavioral contents inferred from hashes.','findings':[]}

class Tests(unittest.TestCase):
    def args(self,tmp):
        return types.SimpleNamespace(state_dir=Path(tmp)/'state',manifest=S.HERE/'sources.json',
            library=S.HERE.parents[1],codex=Path('/opt/homebrew/bin/codex'),budget_seconds=600)

    def test_command_has_explicit_read_only_ephemeral_stdin_and_no_model(self):
        argv=S.command('/fake/codex','/public/library','/private/schema')
        self.assertEqual(argv[:5],['/fake/codex','exec','--sandbox','read-only','--ephemeral'])
        self.assertEqual(argv[-1],'-'); self.assertNotIn('--model',argv)
        self.assertNotIn('--add-dir',argv)

    def test_plist_is_daily_nine_and_explicit_no_immediate_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp); value=S.plist(args)
            self.assertEqual(value['StartCalendarInterval'],{'Hour':9,'Minute':0})
            self.assertFalse(value['RunAtLoad'])
            self.assertEqual(value['StandardErrorPath'],'/dev/null')
            self.assertEqual(value['Umask'],0o077)
            self.assertEqual(S.write_plist(args)['installed'],False)
            path=args.state_dir/'review-agent'/'daily-review.plist'
            self.assertEqual(plistlib.loads(path.read_bytes()),value)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            args.budget_seconds=601
            with self.assertRaises(S.ScheduleError): S.plist(args)

    def test_result_schema_rejects_unbounded_or_unexpected_findings(self):
        self.assertEqual(S.validate_result(GOOD),GOOD)
        for value in ({**GOOD,'extra':'untrusted'}, {**GOOD,'summary':'x'*2001},
                      {**GOOD,'findings':[{}]*11}, {**GOOD,'status':'COMPATIBLE'}):
            with self.assertRaises(S.ScheduleError): S.validate_result(value)

    def test_real_fake_codex_process_receives_stdin_and_returns_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/'fake.py'
            fake.write_text('import json,sys\nassert sys.stdin.buffer.read()==b"public report"\n'
                'print(json.dumps('+repr(GOOD)+'))\n')
            result=S.agent_run([sys.executable,str(fake)],b'public report',3)
            self.assertEqual(result,GOOD)

    def test_nonreading_child_stdin_is_deadline_bounded_and_group_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/'fake.py'; fake.write_text('import time\ntime.sleep(30)\n')
            with self.assertRaisesRegex(S.ScheduleError,'AGENT_DEADLINE'):
                S.agent_run([sys.executable,str(fake)],b'x'*(256*1024),1)

    def test_raw_stderr_is_never_returned_or_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/'fake.py'
            fake.write_text('import sys\nsys.stdin.read()\n'
                'sys.stderr.write("private-secret-token")\nsys.exit(1)\n')
            with self.assertRaisesRegex(S.ScheduleError,'AGENT_EXEC_FAILED') as failure:
                S.agent_run([sys.executable,str(fake)],b'public',3)
            self.assertNotIn('private-secret',str(failure.exception))

    def test_watch_first_agent_second_and_drift_cannot_be_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp); order=[]
            report={'status':'REVIEW_REQUIRED','compatibility_approved':False,
                'observation':{'sources':[{'name':'public','files':[{'path':'protocol.go'}]}]}}
            def check(*_): order.append('watch'); return report
            def agent(argv,prompt,seconds):
                order.append('agent'); self.assertIn(b'PUBLIC REPORT JSON:',prompt)
                self.assertNotIn(b'auth_dir',prompt); return GOOD
            with mock.patch.object(S,'watch_run',side_effect=check):
                with mock.patch.object(S,'agent_run',side_effect=agent): result=S.run(args)
            self.assertEqual(order,['watch','agent'])
            self.assertEqual(result['status'],'REVIEW_REQUIRED')
            self.assertFalse(result['compatibility_approved'])
            path=args.state_dir/'review-agent'/'agent-review.json'
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertTrue((path.parent/'alert.json').is_file())

    def test_watcher_failure_does_not_invoke_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp)
            with mock.patch.object(S,'watch_run',side_effect=S.ScheduleError('WATCH_EXEC_FAILED')):
                with mock.patch.object(S,'agent_run') as agent: result=S.run(args)
            agent.assert_not_called(); self.assertEqual(result['status'],'FAILED')

    def test_singleton_excludes_parallel_agent_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp)
            with S.watch.locked_state(args.state_dir): pass
            with S.watch.locked_state(args.state_dir/'review-agent'):
                with mock.patch.object(S,'agent_run') as agent:
                    with self.assertRaises(S.watch.WatchError): S.run(args)
                agent.assert_not_called()

    def test_agent_does_not_receive_business_secret_environment(self):
        with mock.patch.dict(os.environ,{'LINEAR_API':'private','AWS_SECRET_ACCESS_KEY':'private',
                                          'HOME':'/saved-auth','CODEX_HOME':'/saved-cli'}):
            env=S.agent_environment()
        self.assertNotIn('LINEAR_API',env); self.assertNotIn('AWS_SECRET_ACCESS_KEY',env)
        self.assertEqual(env['HOME'],'/saved-auth')
        self.assertEqual(env['CODEX_HOME'],'/saved-cli')

    def test_oversized_agent_stdout_is_killed_without_saving_raw_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/'fake.py'
            fake.write_text('import sys\nsys.stdin.read()\nsys.stdout.write("x"*70000)\n')
            with self.assertRaisesRegex(S.ScheduleError,'AGENT_OUTPUT_LIMIT'):
                S.agent_run([sys.executable,str(fake)],b'public',3)

    def fake_watcher(self,root,report,write=True,code=0,summary=None):
        fake=Path(root)/'fake_watch.py'
        summary=summary or {k:v for k,v in report.items() if k!='observation'}
        text='import json,os,sys\nfrom pathlib import Path\n'
        if write:
            text+='p=Path(sys.argv[1]); q=p/"new.json"\n'
            text+='q.write_text('+repr(json.dumps(report))+')\nq.chmod(0o600)\n'
            text+='os.replace(q,p/"report.json")\n'
        text+='print('+repr(json.dumps(summary))+',flush=True)\nsys.exit('+str(code)+')\n'
        fake.write_text(text)
        return [sys.executable,str(fake),str(Path(root)/'state')]

    def test_bounded_watcher_requires_fresh_atomic_report_and_summary_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp)
            with S.watch.locked_state(args.state_dir): pass
            report={'status':'NO_MONITORED_DRIFT','compatibility_approved':False,
                    'observation':{'sources':[]}}
            S.watch.atomic_json(args.state_dir/'report.json',report)
            argv=self.fake_watcher(tmp,report)
            self.assertEqual(S.watch_run(args,argv=argv),report)
            argv=self.fake_watcher(tmp,report,write=False)
            with self.assertRaisesRegex(S.ScheduleError,'WATCH_REPORT_STALE'):
                S.watch_run(args,argv=argv)
            mismatched={**report,'compatibility_approved':True}
            argv=self.fake_watcher(tmp,mismatched,summary={k:v for k,v in report.items()
                                                         if k!='observation'})
            with self.assertRaisesRegex(S.ScheduleError,'WATCH_REPORT_MISMATCH'):
                S.watch_run(args,argv=argv)

    def test_failed_watcher_never_reuses_or_destroys_prior_good_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp)
            with S.watch.locked_state(args.state_dir): pass
            report={'status':'NO_MONITORED_DRIFT','observation':{'sources':[]}}
            path=args.state_dir/'report.json'; S.watch.atomic_json(path,report)
            before=path.read_bytes()
            argv=self.fake_watcher(tmp,report,write=False,code=2)
            with self.assertRaisesRegex(S.ScheduleError,'WATCH_EXEC_FAILED'):
                S.watch_run(args,argv=argv)
            self.assertEqual(path.read_bytes(),before)

    def test_stalled_watcher_is_hard_killed_at_240_seconds(self):
        import signal
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/'stall.py'
            fake.write_text('import signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                            'time.sleep(30)\n')
            with mock.patch.object(S.os,'killpg',wraps=S.os.killpg) as kill:
                with self.assertRaisesRegex(S.ScheduleError,'WATCH_DEADLINE'):
                    S.watch_capture([sys.executable,str(fake)],clock=iter((0,241)).__next__)
            self.assertEqual(kill.call_args_list[0].args[1],signal.SIGKILL)

    def test_watcher_exit_three_accepts_only_review_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.args(tmp)
            with S.watch.locked_state(args.state_dir): pass
            report={'status':'REVIEW_REQUIRED','observation':{'sources':[]}}
            argv=self.fake_watcher(tmp,report,code=3)
            self.assertEqual(S.watch_run(args,argv=argv)['status'],'REVIEW_REQUIRED')
            argv=self.fake_watcher(tmp,report,code=0)
            with self.assertRaisesRegex(S.ScheduleError,'WATCH_RESULT_INVALID'):
                S.watch_run(args,argv=argv)

if __name__=='__main__': unittest.main()

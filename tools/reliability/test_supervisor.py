"""Offline checks using fake children and clocks; no accounts/network."""
import importlib.util, json, os
from pathlib import Path
import stat, tempfile, types, unittest
from unittest import mock
SPEC=importlib.util.spec_from_file_location('supervisor',Path(__file__).with_name('supervisor.py'))
S=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(S)

class Tests(unittest.TestCase):
    def setup_private(self,tmp):
        root=Path(tmp); os.chmod(root,0o700)
        auth=root/'auth'; auth.mkdir(mode=0o700)
        binary=root/'native'; binary.write_bytes(b'never executed'); binary.chmod(0o700)
        return types.SimpleNamespace(state_dir=root/'state',auth_dir=auth,binary=binary,
            group_subject='synthetic',duration_seconds=86400,allow_scoped_retries=False)

    def test_prepare_is_private_and_never_starts_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp)
            with mock.patch.object(S.subprocess,'Popen') as popen:
                self.assertEqual(S.prepare(args),{'phase':'PREPARED'}); popen.assert_not_called()
            self.assertEqual(stat.S_IMODE(args.state_dir.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((args.state_dir/'config.json').stat().st_mode),0o600)
            config=json.loads((args.state_dir/'config.json').read_text())
            self.assertNotIn('--send',S.native_command(config))
            config['allow_scoped_retries']=True
            self.assertEqual(S.native_command(config)[-1],'--allow-scoped-retries')

    def test_locks_exclude_other_owners_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            try:
                owner=S.lock(d,'owner.lock')
                try:
                    with self.assertRaises(BlockingIOError): S.lock(d,'owner.lock')
                finally: os.close(owner)
                bad=Path(tmp)/'bad'; bad.write_bytes(b''); bad.chmod(0o644)
                with self.assertRaises(S.Failure): S.lock(d,'bad')
                link=Path(tmp)/'link'; link.symlink_to(bad)
                with self.assertRaises(OSError): S.lock(d,'link')
            finally: os.close(d)
            os.chmod(tmp,0o755)
            with self.assertRaises(S.Failure): S.private_dir(tmp)

    def test_start_is_explicit_durable_and_resume_keeps_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp); S.prepare(args); args.live=False; args.resume=False
            with mock.patch.object(S.subprocess,'Popen') as popen:
                with self.assertRaises(S.Failure): S.start(args)
                popen.assert_not_called(); args.live=True; popen.return_value.pid=123
                first=S.start(args)
                state=json.loads((args.state_dir/'status.json').read_text())
                self.assertEqual(state['run_id'],first['run_id'])
                self.assertEqual(state['phase'],'STARTING')
                with self.assertRaises(S.Failure): S.start(args)
                args.resume=True
                self.assertEqual(S.start(args)['run_id'],first['run_id'])
                self.assertEqual(popen.call_count,2)

    def test_protocol_rejects_private_or_unbounded_output(self):
        self.assertEqual(S.protocol_line(b'WATCH_HEALTH uptime_seconds=60 reconnects=2\n'),
            {'phase':'WATCH_HEALTH','process_elapsed_seconds':60,'reconnects':2})
        self.assertEqual(S.protocol_line(b'PHASE WATCH_COMPLETE\n')['phase'],'WATCH_COMPLETE')
        for line in (b'private account identifier\n',
                     b'WATCH_HEALTH uptime_seconds=172801 reconnects=1\n',
                     b'WATCH_HEALTH uptime_seconds=1 reconnects=1001\n',
                     b'WATCH_HEALTH uptime_seconds=1 reconnects=0 secret\n'):
            with self.assertRaises(S.Failure): S.protocol_line(line)

    def test_events_are_bounded_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp); events=[]
            try:
                for i in range(140): S.event(d,events,{'phase':'WATCH_HEALTH','uptime_seconds':i})
                self.assertEqual(len(S.read_json(d,'events.json')),128)
                self.assertLess((Path(tmp)/'events.json').stat().st_size,S.LIMIT)
                self.assertEqual(stat.S_IMODE((Path(tmp)/'events.json').stat().st_mode),0o600)
            finally: os.close(d)

    def fake_child(self,out=b'',err=b'',code=0):
        child=mock.Mock(); child.poll.return_value=code; child.wait.return_value=code
        for name,data in (('stdout',out),('stderr',err)):
            read,write=os.pipe(); os.write(write,data); os.close(write)
            setattr(child,name,os.fdopen(read,'rb',buffering=0))
        return child

    def test_monitor_requires_completion_and_sanitizes_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            try:
                child=self.fake_child(b'PHASE WATCH_COMPLETE\n')
                self.assertEqual(S.monitor(child,d,60)['phase'],'COMPLETE')
                child=self.fake_child(b'PHASE ONLINE\n',
                    b'private-token\nERROR Protocol STORAGE None '
                    b'SOCKET Message_Rejected CERTIFICATE None SESSION None CODE 0\n',1)
                result=S.monitor(child,d,60)
                self.assertEqual(result['phase'],'FAILED')
                self.assertEqual(result['socket'],'Message_Rejected')
                self.assertNotIn('private-token',repr(result))
            finally: os.close(d)

    def test_monitor_retains_only_allowlisted_terminal_node_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            try:
                child=self.fake_child(b'PHASE ONLINE\n',
                    b'private-token\nERROR Protocol STORAGE None SOCKET Session_Failed '
                    b'CERTIFICATE None SESSION Server_Failure CODE 0 NODE Stream_Error '
                    b'DETAIL Conflict UNKNOWN_CHILDREN 1\n',1)
                result=S.monitor(child,d,60)
                self.assertEqual(result['phase'],'FAILED')
                self.assertEqual(result['server_node'],'Stream_Error')
                self.assertEqual(result['server_detail'],'Conflict')
                self.assertEqual(result['server_unknown_children'],1)
                self.assertNotIn('private-token',repr(result))
            finally: os.close(d)

    def test_watchdog_and_stop_do_not_retry_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            try:
                child=self.fake_child(); child.poll.return_value=None
                with self.assertRaisesRegex(S.Failure,'CHILD_DEADLINE'):
                    S.monitor(child,d,60,clock=iter((0,100)).__next__)
                child.terminate.assert_called_once()
                S.write_json(d,'stop.json',{'stop':True})
                child=self.fake_child()
                self.assertEqual(S.monitor(child,d,60)['phase'],'STOPPED')
            finally: os.close(d)

    def test_worker_releases_session_and_persists_safe_alert_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp); S.prepare(args)
            d=S.private_dir(args.state_dir); owner=S.lock(d,'owner.lock')
            S.write_json(d,'status.json',{'phase':'STARTING','run_id':'a'*32,'pid':None})
            inherited=os.dup(owner)
            child=self.fake_child(b'PHASE ONLINE\n',b'private-secret\n',1); child.pid=456
            try:
                with mock.patch.dict(os.environ,WHATSAPP_SUPERVISOR_LOCK=str(inherited)):
                    with mock.patch.object(S.subprocess,'Popen',return_value=child) as popen:
                        self.assertEqual(S.worker(args)['phase'],'FAILED')
                self.assertEqual(popen.call_count,1)
                alert=S.read_json(d,'alert.json')
                self.assertEqual(alert['run_id'],'a'*32)
                self.assertEqual(alert['native_pid'],456)
                self.assertNotIn('private-secret',repr(alert))
                auth=S.private_dir(args.auth_dir)
                try:
                    session=S.lock(auth,'reliability.owner.lock'); os.close(session)
                finally: os.close(auth)
            finally: os.close(owner); os.close(d)

    def test_invalid_limits_binary_changes_and_cli_never_echo_input(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp); args.duration_seconds=172801
            with self.assertRaises(S.Failure): S.prepare(args)
            args.duration_seconds=60; S.prepare(args)
            config=json.loads((args.state_dir/'config.json').read_text())
            args.binary.write_bytes(b'changed')
            with self.assertRaisesRegex(S.Failure,'BINARY_CHANGED'): S.validate_config(config)
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(S.main(['private-secret-invalid-command']),1)
        self.assertNotIn('private-secret',output.getvalue())

    def test_real_detached_handoff_with_offline_fake_native(self):
        import sys, time
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp)
            args.binary.write_text('#!'+sys.executable+
                                   '\nprint("PHASE WATCH_COMPLETE",flush=True)\n')
            S.prepare(args); args.live=True; args.resume=False
            result=S.start(args)
            self.assertGreater(result['pid'],0)
            deadline=time.monotonic()+5
            status=None
            while time.monotonic()<deadline:
                status=json.loads((args.state_dir/'status.json').read_text())
                if status['phase'] not in ('STARTING','RUNNING'): break
                time.sleep(0.02)
            self.assertEqual(status['phase'],'COMPLETE')
            self.assertEqual(status['run_id'],result['run_id'])
            try: os.waitpid(result['pid'],0)
            except ChildProcessError: pass

    def test_stalled_child_is_killed_before_whole_run_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            try:
                child=self.fake_child(); child.poll.return_value=None
                with self.assertRaisesRegex(S.Failure,'CHILD_STALLED'):
                    S.monitor(child,d,86400,clock=iter((0,180)).__next__)
                child.terminate.assert_called_once()
                child=self.fake_child(b'PHASE ONLINE\nPHASE WATCH_COMPLETE\n')
                result=S.monitor(child,d,86400,clock=iter((0,10,100,101,250)).__next__)
                self.assertEqual(result['phase'],'COMPLETE')
            finally: os.close(d)

    def test_status_derives_stale_progress_alert_while_owner_is_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp); S.prepare(args); args.command='status'
            d=S.private_dir(args.state_dir); owner=S.lock(d,'owner.lock')
            try:
                S.write_json(d,'status.json',{'phase':'RUNNING','run_id':'b'*32,
                                            'pid':123,'started_unix':0})
                with mock.patch.object(S.time,'time',return_value=180):
                    status=S.inspect_state(args)
                self.assertEqual(status['phase'],'STALLED')
                self.assertEqual(S.read_json(d,'alert.json')['reason'],'CHILD_STALLED')
                S.write_json(d,'events.json',[{'phase':'WATCH_HEALTH','time_unix':179}])
                with mock.patch.object(S.time,'time',return_value=180):
                    self.assertEqual(S.inspect_state(args)['phase'],'RUNNING')
            finally: os.close(owner); os.close(d)

    def test_pinned_version_warning_persists_until_successful_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp); S.prepare(args); args.command='status'
            d=S.private_dir(args.state_dir)
            try:
                S.write_json(d,'status.json',{'phase':'COMPLETE','run_id':'c'*32})
                child=self.fake_child(b'PHASE VERSION_PINNED\nPHASE WATCH_COMPLETE\n')
                self.assertEqual(S.monitor(child,d,60)['phase'],'COMPLETE')
                self.assertTrue(S.inspect_state(args)['version_fallback'])
                self.assertEqual(S.read_json(d,'version-warning.json')['warning'],'VERSION_PINNED')
                child=self.fake_child(b'PHASE VERSION_DISCOVERED\nPHASE WATCH_COMPLETE\n')
                self.assertEqual(S.monitor(child,d,60)['phase'],'COMPLETE')
                self.assertFalse(S.inspect_state(args)['version_fallback'])
                self.assertFalse((args.state_dir/'version-warning.json').exists())
            finally: os.close(d)

    def test_canary_requires_explicit_send_and_scope_and_never_retries_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.setup_private(tmp); args.canary_interval_seconds=21600; args.send=False
            with self.assertRaises(S.Failure): S.prepare(args)
            args.send=True
            with self.assertRaises(S.Failure): S.prepare(args)
            args.allow_scoped_retries=True; S.prepare(args)
            config=json.loads((args.state_dir/'config.json').read_text())
            command=S.native_command(config)
            self.assertIn('--send',command)
            self.assertEqual(command[-2:],['--canary-interval-seconds','21600'])
            self.assertNotIn('--retry-unknown-canary',command)

    def test_rotation_cannot_erase_canary_ack_version_or_counter_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            payload=(b'WATCH_VERSION major=2 minor=3000 patch=1\n'
                b'CANARY_STATUS completed_cycles=0 durable_completed_cycles=10 '
                b'first_ack_unix_seconds=100 last_ack_unix_seconds=200\n'
                b'PHASE CANARY_TEXT_ACKED\nPHASE CANARY_PDF_ACKED\n'
                b'CANARY_STATUS completed_cycles=1 durable_completed_cycles=11 '
                b'first_ack_unix_seconds=100 last_ack_unix_seconds=300\n')
            payload+=b''.join(('WATCH_HEALTH uptime_seconds='+str(i*60)+
                               ' reconnects=0\n').encode() for i in range(140))
            payload+=b'PHASE WATCH_COMPLETE\n'
            try:
                self.assertEqual(S.monitor(self.fake_child(payload),d,86400)['phase'],'COMPLETE')
                ring=S.read_json(d,'events.json'); progress=S.read_json(d,'progress.json')
                self.assertEqual(len(ring),128)
                self.assertFalse(any(e['phase']=='CANARY_TEXT_ACKED' for e in ring))
                self.assertEqual(progress['canary_completed_baseline'],10)
                self.assertEqual(progress['canary_completed_latest'],11)
                self.assertIsNotNone(progress['last_text_ack_unix'])
                self.assertIsNotNone(progress['last_pdf_ack_unix'])
                self.assertEqual(progress['version'],{'major':2,'minor':3000,'patch':1})
            finally: os.close(d)

    def test_wallclock_sleep_gap_is_detected_before_fresh_post_wake_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            child=self.fake_child(b'WATCH_HEALTH uptime_seconds=60 reconnects=0\n')
            child.poll.return_value=None
            try:
                with self.assertRaisesRegex(S.Failure,'CHILD_STALLED'):
                    S.monitor(child,d,86400,clock=lambda:0,
                              wall_clock=iter((0,0,181)).__next__)
                child.terminate.assert_called_once()
                progress=S.read_json(d,'progress.json')
                self.assertEqual(progress['health_events'],0)
                self.assertGreaterEqual(progress['max_health_gap_seconds'],181)
            finally: os.close(d)

    def test_state_write_failure_still_stops_owned_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            child=self.fake_child(b'PHASE ONLINE\n'); child.poll.return_value=None
            try:
                with mock.patch.object(S,'write_json',side_effect=OSError('private detail')):
                    with self.assertRaises(OSError): S.monitor(child,d,60)
                child.terminate.assert_called_once()
            finally: os.close(d)

    def test_wallclock_pause_after_select_cannot_reset_the_stall_timer(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); d=S.private_dir(tmp)
            child=self.fake_child(b'WATCH_HEALTH uptime_seconds=60 reconnects=0\n')
            child.poll.return_value=None
            try:
                with self.assertRaisesRegex(S.Failure,'CHILD_STALLED'):
                    S.monitor(child,d,86400,clock=lambda:0,
                              wall_clock=iter((0,0,0,181)).__next__)
                self.assertEqual(S.read_json(d,'progress.json')['health_events'],0)
                child.terminate.assert_called_once()
            finally: os.close(d)

if __name__=='__main__': unittest.main()

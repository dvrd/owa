"""Independent completion-gate tests: synthetic metadata/fake Linear, no accounts."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
SPEC=importlib.util.spec_from_file_location(
    'finish_soak',Path(__file__).with_name('finish_soak.py'))
F=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(F)

class Tests(unittest.TestCase):
    def evidence(self):
        started=1800000000; duration=86400; ended=started+duration
        expected={'run_id':'a'*32,'binary_sha256':'b'*64,'duration_seconds':duration,
                  'interval_seconds':21600,'minimum_cycles':3}
        config={'schema':1,'mode':'watch','binary_sha256':'b'*64,'duration_seconds':duration,
            'canary_interval_seconds':21600,'send':True,'allow_scoped_retries':True,
            'auth_dir':'/synthetic-not-opened/session','group_subject':'synthetic-group'}
        status={'run_id':'a'*32,'phase':'COMPLETE','started_unix':started,'finished_unix':ended}
        progress={'run_id':'a'*32,'duration_seconds':duration,'canary_interval_seconds':21600,
            'run_started_unix':started,'run_finished_unix':ended,'observed_run_seconds':duration,
            'canary_completed_baseline':10,'canary_completed_latest':14,
            'canary_new_completed_cycles':4,'health_coverage_qualified':True,
            'max_health_gap_seconds':60,'health_gap_events':0,'connection_gap_events':0,
            'health_events':1440,'observed_seconds':duration-120,
            'first_health_unix':started+60,'last_health_unix':ended-60,
            'version':{'major':2,'minor':3000,'patch':1},'version_fallback':False,
            'first_canary_ack_unix':started-1000,'last_canary_ack_unix':ended-100}
        scope={'auth_dir':config['auth_dir'],'group_subject':config['group_subject']}
        encoded=json.dumps(scope,sort_keys=True,separators=(',',':')).encode()
        digest=hashlib.sha256(encoded).hexdigest()
        confirmation={'schema':1,'recipient_confirmed':True,'pdf_opened':True,
            'binary_sha256':'b'*64,'scope_sha256':digest,
            'version':{'major':2,'minor':3000,'patch':1},'confirmed_unix':started-100}
        return [config,status,progress,confirmation,expected,started-1,ended+10]

    def test_complete_source_bound_metadata_qualifies_without_account_access(self):
        args=self.evidence()
        with mock.patch.object(F,'private_directory',side_effect=AssertionError('account access')):
            result=F.evaluate(*args)
        self.assertEqual(result['phase'],'QUALIFIED')
        self.assertEqual(result['new_completed_cycles'],4)
        self.assertFalse(result['recipient_delivery_claimed'])
        self.assertNotIn('auth_dir',result); self.assertNotIn('group_subject',result)

    def test_wrong_run_binary_duration_or_snapshot_never_qualifies(self):
        mutations=((1,'run_id','c'*32),(0,'binary_sha256','c'*64),
            (0,'duration_seconds',60),(2,'run_id','d'*32),
            (2,'observed_run_seconds',60),(2,'run_started_unix',1800000001))
        for index,key,value in mutations:
            args=self.evidence(); args[index][key]=value
            with self.subTest(field=key):
                with self.assertRaises(F.GateError): F.evaluate(*args)
        args=self.evidence(); args[1]['progress']={'run_id':'wrong'}
        with self.assertRaises(F.GateError): F.evaluate(*args)

    def test_cycle_gaps_errors_unknown_or_partial_duration_never_qualify(self):
        for key,value in (('canary_new_completed_cycles',2),('canary_completed_latest',11),
                          ('health_gap_events',1),('connection_gap_events',1),
                          ('max_health_gap_seconds',181),('health_coverage_qualified',False),
                          ('observed_seconds',100),('version',None)):
            args=self.evidence(); args[2][key]=value
            with self.subTest(field=key):
                with self.assertRaises(F.GateError): F.evaluate(*args)
        for phase in ('FAILED','STOPPED','INTERRUPTED','STALLED','CANARY_UNKNOWN'):
            args=self.evidence(); args[1]['phase']=phase
            with self.assertRaises(F.GateError): F.evaluate(*args)
        args=self.evidence(); args[1]['finished_unix']=args[1]['started_unix']+120
        with self.assertRaises(F.GateError): F.evaluate(*args)

    def test_missing_or_mismatched_human_proof_stays_pending(self):
        for proof in ({},{'schema':1,'recipient_confirmed':False},
                      {'schema':1,'recipient_confirmed':True,'binary_sha256':'c'*64}):
            args=self.evidence(); args[3]=proof
            self.assertEqual(F.evaluate(*args)['phase'],'PENDING_HUMAN_CONFIRMATION')
        args=self.evidence(); args[3]['scope_sha256']='c'*64
        self.assertEqual(F.evaluate(*args)['phase'],'PENDING_HUMAN_CONFIRMATION')

    def test_running_is_waiting_and_stale_running_is_rejected(self):
        args=self.evidence(); args[1]['phase']='RUNNING'
        self.assertEqual(F.evaluate(*args)['phase'],'WAITING')
        args[-1]+=200
        with self.assertRaisesRegex(F.GateError,'ACTIVE_RUN_STALE'): F.evaluate(*args)

    def test_duplicate_json_and_nonprivate_metadata_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); directory=F.private_directory(Path(tmp))
            try:
                path=Path(tmp)/'bad.json'; path.write_text('{"phase":"COMPLETE","phase":"FAILED"}')
                path.chmod(0o600)
                with self.assertRaises(F.GateError): F.read_json(directory,'bad.json')
                path.chmod(0o644)
                with self.assertRaises(F.GateError): F.read_json(directory,'bad.json')
            finally: os.close(directory)

    def test_unknown_code_shaped_failure_reason_cannot_echo_private_text(self):
        args=self.evidence(); args[1].update(phase='FAILED',reason='PRIVATE_SECRET_FIXTURE')
        with self.assertRaises(F.GateError) as raised: F.evaluate(*args)
        self.assertNotIn('PRIVATE_SECRET_FIXTURE',str(raised.exception))

    def test_credential_getter_keeps_fake_key_in_memory_and_never_echoes(self):
        import contextlib, io, subprocess
        key='linear_fixture_key_0123456789'
        output=io.StringIO()
        with mock.patch.dict(F.os.environ,{'LINEAR_API':key},clear=True):
            with mock.patch.object(F.subprocess,'run') as command:
                with contextlib.redirect_stdout(output): self.assertEqual(F.credential_get(),key)
                command.assert_not_called()
        self.assertEqual(output.getvalue(),'')
        with mock.patch.dict(F.os.environ,{},clear=True):
            result=types.SimpleNamespace(returncode=0,stdout=key.encode()+b'\n')
            with mock.patch.object(F.subprocess,'run',return_value=result) as command:
                self.assertEqual(F.credential_get(),key)
                self.assertEqual(command.call_args.args[0],['wayu','const','get','LINEAR_API'])
            timeout=subprocess.TimeoutExpired('wayu',5)
            with mock.patch.object(F.subprocess,'run',side_effect=timeout):
                self.assertIsNone(F.credential_get())
            result=types.SimpleNamespace(returncode=0,stdout=b'x'*4097)
            with mock.patch.object(F.subprocess,'run',return_value=result):
                self.assertIsNone(F.credential_get())

    def test_metadata_symlinks_hardlinks_and_oversized_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); directory=F.private_directory(Path(tmp))
            try:
                path=Path(tmp)/'value.json'; path.write_text('{}'); path.chmod(0o600)
                (Path(tmp)/'link.json').symlink_to(path)
                with self.assertRaises(OSError): F.read_json(directory,'link.json')
                os.link(path,Path(tmp)/'hard.json')
                with self.assertRaises(F.GateError): F.read_json(directory,'value.json')
                (Path(tmp)/'hard.json').unlink(); path.write_bytes(b'x'*(F.LIMIT+1))
                with self.assertRaises(F.GateError): F.read_json(directory,'value.json')
            finally: os.close(directory)

    def linear_fixture(self,directory,mode=None):
        state={'run_id':'a'*32}; calls=[]; remote={'comment':None,'done':False}
        def transport(payload):
            op=payload['operation']; calls.append(op)
            if op=='lookup':
                if mode=='unavailable': raise F.GateError('LINEAR_UNAVAILABLE')
                return {'issue_id':'issue-fixture','done_state_id':'done-fixture',
                        'comment_id':remote['comment'],'done':remote['done']}
            persisted,_=F.read_json(directory,'finish-state.json')
            self.assertNotIn('linear_fixture_key',json.dumps(persisted))
            self.assertTrue(persisted[op+'_attempted'])
            if op=='comment':
                if mode=='comment_ambiguous': raise F.GateError('LINEAR_UNAVAILABLE')
                remote['comment']='comment-fixture'
                return {'comment_id':'comment-fixture'}
            if op=='done':
                if mode=='done_ambiguous': raise F.GateError('LINEAR_UNAVAILABLE')
                if mode!='done_unconfirmed': remote['done']=True
                return {'updated':True}
            self.fail('Unexpected network operation')
        return state,calls,transport

    def test_linear_success_is_verified_and_never_duplicates_comment_or_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); directory=F.private_directory(Path(tmp))
            try:
                state,calls,transport=self.linear_fixture(directory)
                proof=F.evaluate(*self.evidence()); getter=lambda:'linear_fixture_key_0123456789'
                self.assertIsNone(F.linear_complete(directory,state,proof,'OKAMI-408',
                                                     getter,transport))
                self.assertEqual(calls,['lookup','comment','done','lookup'])
                self.assertEqual(state['phase'],'DONE_VERIFIED')
                self.assertIsNone(F.linear_complete(directory,state,proof,'OKAMI-408',
                                                     getter,transport))
                self.assertEqual(calls.count('comment'),1); self.assertEqual(calls.count('done'),1)
                for path in Path(tmp).iterdir():
                    self.assertNotIn('linear_fixture_key',path.read_text())
            finally: os.close(directory)

    def test_unavailable_api_or_credentials_never_attempt_mutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); directory=F.private_directory(Path(tmp))
            try:
                state,calls,transport=self.linear_fixture(directory,'unavailable')
                proof=F.evaluate(*self.evidence())
                self.assertIsNotNone(F.linear_complete(directory,state,proof,'OKAMI-408',
                                                       lambda:None,transport))
                self.assertEqual(calls,[])
                for _ in range(2):
                    self.assertIsNotNone(F.linear_complete(directory,state,proof,'OKAMI-408',
                        lambda:'linear_fixture_key_0123456789',transport))
                self.assertEqual(calls,['lookup','lookup'])
                self.assertNotEqual(state.get('phase'),'DONE_VERIFIED')
            finally: os.close(directory)

    def test_ambiguous_comment_or_done_is_query_only_on_subsequent_polls(self):
        for mode in ('comment_ambiguous','done_ambiguous'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                os.chmod(tmp,0o700); directory=F.private_directory(Path(tmp))
                try:
                    state,calls,transport=self.linear_fixture(directory,mode)
                    proof=F.evaluate(*self.evidence())
                    getter=lambda:'linear_fixture_key_0123456789'
                    self.assertIsNotNone(F.linear_complete(directory,state,proof,'OKAMI-408',
                                                           getter,transport))
                    before=len(calls)
                    restored,_=F.read_json(directory,'finish-state.json')
                    self.assertIsNotNone(F.linear_complete(directory,restored,proof,'OKAMI-408',
                                                           getter,transport))
                    self.assertEqual(calls[before:],['lookup'])
                    self.assertEqual(calls.count('comment'),1)
                    self.assertLessEqual(calls.count('done'),1)
                    self.assertNotEqual(restored.get('phase'),'DONE_VERIFIED')
                finally: os.close(directory)

    def test_human_proof_for_a_different_public_version_stays_pending(self):
        args=self.evidence(); args[3]['version']={'major':2,'minor':3000,'patch':99}
        self.assertEqual(F.evaluate(*args)['phase'],'PENDING_HUMAN_CONFIRMATION')

    def poll_fixture(self,tmp,proof=True):
        config,status,progress,confirmation,expected,mtime,now=self.evidence()
        state=Path(tmp)/'state'; controller=Path(tmp)/'controller'
        source=F.private_directory(state,create=True)
        destination=F.private_directory(controller,create=True)
        try:
            for name,value in (('config.json',config),('status.json',status),
                               ('progress.json',progress)):
                F.write_json(source,name,value)
            if proof: F.write_json(destination,'recipient-confirmation.json',confirmation)
        finally: os.close(source); os.close(destination)
        os.utime(state/'config.json',(mtime,mtime))
        args=types.SimpleNamespace(state_dir=state,controller_dir=controller,
            expected_run_id=expected['run_id'],expected_binary_sha256=expected['binary_sha256'],
            expected_duration_seconds=expected['duration_seconds'],
            expected_canary_interval_seconds=expected['interval_seconds'],minimum_cycles=3,
            issue='OKAMI-408',linear=True)
        return args,now

    def test_poll_human_pending_never_reads_a_key_or_mutates_linear(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now=self.poll_fixture(tmp,proof=False)
            getter=mock.Mock(); transport=mock.Mock()
            result=F.poll(args,getter,transport,now)
            self.assertEqual(result['phase'],'PENDING_HUMAN_CONFIRMATION')
            getter.assert_not_called(); transport.assert_not_called()
            self.assertFalse((args.controller_dir/'finish-state.json').exists())

    def test_poll_metadata_failure_writes_handoff_and_never_marks_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now=self.poll_fixture(tmp)
            path=args.state_dir/'status.json'; status=json.loads(path.read_text())
            status['run_id']='c'*32; path.write_text(json.dumps(status))
            getter=mock.Mock(); transport=mock.Mock()
            result=F.poll(args,getter,transport,now)
            self.assertEqual(result['phase'],'HANDOFF')
            self.assertEqual(result['reason'],'RUN_BINDING_MISMATCH')
            self.assertTrue((args.controller_dir/'handoff.json').is_file())
            getter.assert_not_called(); transport.assert_not_called()

    def test_poll_only_reports_complete_after_verified_linear_and_no_secret_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now=self.poll_fixture(tmp)
            directory=F.private_directory(args.controller_dir)
            try:
                _,calls,transport=self.linear_fixture(directory)
                getter=mock.Mock(return_value=None)
                result=F.poll(args,getter,transport,now)
                self.assertNotEqual(result['phase'],'COMPLETE')
                self.assertTrue(result['linear_update_pending']); self.assertEqual(calls,[])
                getter.return_value='linear_fixture_key_0123456789'
                with mock.patch.object(F,'private_directory',wraps=F.private_directory) as opened:
                    result=F.poll(args,getter,transport,now)
                self.assertEqual(result['phase'],'COMPLETE')
                self.assertTrue(result['linear_done_verified'])
                self.assertEqual([call.args[0] for call in opened.call_args_list],
                                 [args.state_dir,args.controller_dir])
                getter.reset_mock(); before=list(calls)
                self.assertEqual(F.poll(args,getter,transport,now)['phase'],'COMPLETE')
                getter.assert_not_called(); self.assertEqual(calls,before)
                for path in args.controller_dir.iterdir():
                    self.assertNotIn('linear_fixture_key',path.read_text())
            finally: os.close(directory)

    def test_running_without_first_health_still_expires_from_start_time(self):
        args=self.evidence(); args[1]['phase']='RUNNING'; args[2]['last_health_unix']=None
        with self.assertRaisesRegex(F.GateError,'ACTIVE_RUN_STALE'): F.evaluate(*args)

    def test_malformed_json_produces_persistent_handoff_without_api_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,now=self.poll_fixture(tmp)
            (args.state_dir/'status.json').write_text('{not-json')
            getter=mock.Mock(); transport=mock.Mock()
            result=F.poll(args,getter,transport,now)
            self.assertEqual(result['phase'],'HANDOFF')
            self.assertTrue((args.controller_dir/'handoff.json').is_file())
            getter.assert_not_called(); transport.assert_not_called()

    def test_mutation_success_without_verified_remote_done_never_reports_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp,0o700); directory=F.private_directory(Path(tmp))
            try:
                state,calls,transport=self.linear_fixture(directory,'done_unconfirmed')
                proof=F.evaluate(*self.evidence()); getter=lambda:'linear_fixture_key_0123456789'
                self.assertIsNotNone(F.linear_complete(directory,state,proof,'OKAMI-408',
                                                       getter,transport))
                self.assertNotEqual(state.get('phase'),'DONE_VERIFIED')
                before=len(calls)
                self.assertIsNotNone(F.linear_complete(directory,state,proof,'OKAMI-408',
                                                       getter,transport))
                self.assertEqual(calls[before:],['lookup'])
                self.assertEqual(calls.count('done'),1)
            finally: os.close(directory)

    def test_linear_lookup_refuses_wrong_project_or_ambiguous_done_markers(self):
        item={'id':'issue','identifier':'OKAMI-408','project':{'id':F.PROJECT},
            'state':{'id':'doing'},'team':{'states':{'nodes':[
                {'id':'done','name':'Done','type':'completed'}]}},
            'comments':{'nodes':[],'pageInfo':{'hasNextPage':False,'endCursor':None}}}
        token='linear_fixture_key_0123456789'
        wrong=copy.deepcopy(item); wrong['project']['id']='another-project'
        with self.assertRaisesRegex(F.GateError,'LINEAR_SCOPE_MISMATCH'):
            F.lookup(token,'OKAMI-408','marker',lambda *_:{'issue':wrong})
        duplicated=copy.deepcopy(item)
        duplicated['comments']['nodes']=[{'id':'one','body':'marker'},
                                         {'id':'two','body':'marker'}]
        with self.assertRaisesRegex(F.GateError,'LINEAR_DUPLICATE_MARKERS'):
            F.lookup(token,'OKAMI-408','marker',lambda *_:{'issue':duplicated})

if __name__=='__main__': unittest.main()

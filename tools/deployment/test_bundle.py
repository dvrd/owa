"""Generated local Git/ELF/CI evidence fixtures, never real source proof or accounts."""
import copy,hashlib,importlib.util,json,os,subprocess,tempfile,types,unittest
from pathlib import Path
SPEC=importlib.util.spec_from_file_location('bundle',Path(__file__).with_name('bundle.py'));M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
TEST_HOST='i-00000000000000000'
class Tests(unittest.TestCase):
 def fixture(self,tmp):
  root=Path(tmp);repo=root/'repository';repo.mkdir();subprocess.run(['git','init','-q',str(repo)],check=True)
  pin={'compiler_source_revision':'1'*40,'core_source_revision':'2'*40,'dependencies':{'manifest':{'sha256':'3'*64}}}
  for name in M.HELPERS:
   p=repo/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('# Generated harmless helper fixture: '+name+'\n')
  p=repo/'tools/native_ci/pin.json';p.parent.mkdir(parents=True);p.write_text(json.dumps(pin))
  subprocess.run(['git','-C',str(repo),'add','.'],check=True);subprocess.run(['git','-C',str(repo),'-c','user.name=Synthetic','-c','user.email=fixture@example.invalid','commit','-qm','generated public fixture'],check=True)
  rev=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
  artifact=root/'artifact';artifact.mkdir();binary=b'\x7fELF\x02\x01'+bytes(12)+b'\x3e\x00'+bytes(44)
  (artifact/'owa-live-linux-amd64').write_bytes(binary)
  inspect=b'[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n Shared library: [libz.so.1]\nShared library: [libm.so.6]\nShared library: [libc.so.6]\nShared library: [ld-linux-x86-64.so.2]\nGLIBC_2.34\n'
  (artifact/'live-binary-loader.log').write_bytes(inspect);(artifact/'live-binary-preview.log').write_bytes(b'PHASE PREVIEW_READY\n')
  files={str(p.relative_to(repo)):M.sha(p.read_bytes()) for p in repo.rglob('*') if p.is_file() and '.git' not in p.parts}
  q={'passed':True,'platform':'linux-amd64','github_run_id':'123','checkout_commit':rev,'compiler_sha256':'4'*64,'compiler_source_revision':'1'*40,'core_source_revision':'2'*40,'dependency_manifest_sha256':'3'*64,'pin_sha256':M.sha((repo/'tools/native_ci/pin.json').read_bytes())}
  for field in ('checkout_clean','checkout_unchanged','runner_unchanged','source_unchanged','linker_runtime_unchanged'):q[field]=True
  for name in ('checkout_source','runner_source','input'):
   q[name+'_before']=files if name=='checkout_source' else {};q[name+'_after']=copy.deepcopy(q[name+'_before'])
  commands=[]
  for mode in ('address','thread'):
   for name in ('empty-run','unit','qualification-tools','encrypted_recovery','compatibility','consumer-run'):
    log=name+'-'+mode+'.log';(artifact/log).write_bytes(b'generated success\n');commands.append({'name':name+'-'+mode,'exit_code':0,'failure':None,'log':log,'log_sha256':M.sha((artifact/log).read_bytes())})
  q['commands']=commands;q['live_binary']={'file':'owa-live-linux-amd64','platform':'linux-amd64','bytes':len(binary),'sha256':M.sha(binary),'optimization':'speed','sanitizer':'none','account_opened':False,'provider_calls':False,'offline_preview_passed':True,'inspection_log':'live-binary-loader.log'}
  args=types.SimpleNamespace(repository=repo,runtime_revision=rev,helper_revision=rev,artifact_dir=artifact,expected_run_id='123',expected_binary_sha256=M.sha(binary),output=root/'bundle')
  self.report(args,q);return args,q
 def report(self,args,q):
  (args.artifact_dir/'qualification.json').write_bytes(M.encoded(q));args.expected_report_sha256=M.sha((args.artifact_dir/'qualification.json').read_bytes())
  cs={p.name:M.sha(p.read_bytes()) for p in args.artifact_dir.iterdir() if p.is_file() and p.name!='checksums.json'};(args.artifact_dir/'checksums.json').write_bytes(M.encoded(cs))
 def packaged(self,tmp):
  args,q=self.fixture(tmp);result=M.pack(args);return args,result
 def host(self,tmp):
  root=Path(tmp)/'host';root.mkdir()
  for name,data in {'usr/lib/os-release':'ID=ubuntu\nVERSION_ID="24.04"\n','var/lib/cloud/data/instance-id':TEST_HOST+'\n','etc/passwd':'root:x:0:0:root:/root:/bin/sh\n','etc/group':'root:x:0:\n','lib64/ld-linux-x86-64.so.2':'generated loader fixture'}.items():
   p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data)
  for name in M.NEEDED:
   p=root/('lib64/ld-linux-x86-64.so.2' if name=='ld-linux-x86-64.so.2' else 'lib/x86_64-linux-gnu/'+name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'\x7fELF\x02\x01'+bytes(12)+b'\x3e\x00'+bytes(12))
  p=root/'proc/cpuinfo';p.parent.mkdir();p.write_text('flags : '+' '.join(sorted(M.X86_V2))+'\n')
  return root
 def plan(self,args,result,host,**kw):
  a=types.SimpleNamespace(bundle=args.output,expected_manifest_sha256=result['manifest_sha256'],host_root=host,expected_instance_id=TEST_HOST)
  defaults=dict(uid=lambda:0,machine=lambda:'x86_64',libc=lambda:('glibc','2.39'),system=lambda:'Linux',owner_uid=os.geteuid());defaults.update(kw)
  return M.plan(a,**defaults)
 def test_exact_public_allowlist_manifest_source_provenance_and_no_execution(self):
  with tempfile.TemporaryDirectory() as tmp:
   args,q=self.fixture(tmp);result=M.pack(args);m=M.verify(args.output,result['manifest_sha256'])
   self.assertEqual(set(m['helpers']),set(M.HELPERS));self.assertEqual(m['runtime_revision'],args.runtime_revision)
   self.assertEqual(len(m['files']),9);self.assertEqual(set(m['abi']['needed']),M.NEEDED)
   for name in M.HELPERS:self.assertEqual((args.output/name).read_bytes(),(args.repository/name).read_bytes())
   self.assertEqual(os.stat(args.output).st_mode&0o777,0o700)
   with self.assertRaises(FileExistsError):M.pack(args)
 def test_independent_report_binary_and_manifest_digest_required(self):
  for field in ('expected_report_sha256','expected_binary_sha256'):
   with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
    args,q=self.fixture(tmp);setattr(args,field,'0'*64)
    with self.assertRaises(M.Refusal):M.pack(args)
    self.assertFalse(args.output.exists())
  with tempfile.TemporaryDirectory() as tmp:
   args,result=self.packaged(tmp)
   with self.assertRaises(M.Refusal):M.verify(args.output,'0'*64)
 def test_runtime_ref_platform_guards_native_modes_and_loader_rejected(self):
  changes=[lambda q:q.update(platform='macos-arm64'),lambda q:q.update(checkout_commit='0'*40),lambda q:q.update(checkout_clean=False),lambda q:q['commands'].pop(),lambda q:q['input_after'].update(changed='0'*64),lambda q:q['live_binary'].update(account_opened=True)]
  for change in changes:
   with tempfile.TemporaryDirectory() as tmp:
    args,q=self.fixture(tmp);change(q);self.report(args,q)
    with self.assertRaises(M.Refusal):M.pack(args)
    self.assertFalse(args.output.exists())
  for data in (b'GLIBC_2.40 /lib64/ld-linux-x86-64.so.2',b'GLIBC_2.34 /unreviewed/loader',b'GLIBC_2.34 /lib64/ld-linux-x86-64.so.2 Shared library: [libunreviewed.so]'):
   with tempfile.TemporaryDirectory() as tmp:
    args,q=self.fixture(tmp);(args.artifact_dir/'live-binary-loader.log').write_bytes(data);self.report(args,q)
    with self.assertRaises(M.Refusal):M.pack(args)
 def test_source_symlink_unknown_artifact_and_bundle_mutation_refused(self):
  for kind in ('unknown','symlink','bytes','empty_directory'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
    args,result=self.packaged(tmp)
    if kind=='unknown':(args.output/'credentials.json').write_text('generated forbidden data')
    elif kind=='symlink':
     p=args.output/M.HELPERS[0];p.unlink();p.symlink_to(args.repository/M.HELPERS[0])
    elif kind=='bytes':
     p=args.output/M.HELPERS[0];p.chmod(0o600);p.write_text('changed')
    else:(args.output/'auth').mkdir()
    with self.assertRaises(M.Refusal):M.verify(args.output,result['manifest_sha256'])
 def test_helper_and_native_revisions_are_distinct_when_sources_differ(self):
  with tempfile.TemporaryDirectory() as tmp:
   args,q=self.fixture(tmp);p=args.repository/M.HELPERS[0];p.write_text('# New generated helper revision\n')
   subprocess.run(['git','-C',str(args.repository),'add','.'],check=True);subprocess.run(['git','-C',str(args.repository),'-c','user.name=Synthetic','-c','user.email=fixture@example.invalid','commit','-qm','new generated helper'],check=True)
   args.helper_revision=subprocess.check_output(['git','-C',str(args.repository),'rev-parse','HEAD'],text=True).strip()
   result=M.pack(args);m=M.verify(args.output,result['manifest_sha256'])
   self.assertNotEqual(m['runtime_revision'],m['helper_revision']);self.assertEqual(m['helpers'][M.HELPERS[0]]['commit'],args.helper_revision)
   self.assertEqual((args.output/M.HELPERS[0]).read_bytes(),p.read_bytes())
 def test_artifact_unknown_file_or_symlink_is_rejected_before_packaging(self):
  for kind in ('unknown','symlink'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
    args,q=self.fixture(tmp)
    if kind=='unknown':(args.artifact_dir/'credentials.json').write_text('synthetic forbidden file')
    else:
     p=args.artifact_dir/'owa-live-linux-amd64';p.unlink();p.symlink_to(args.repository/M.HELPERS[0])
    with self.assertRaises(M.Refusal):M.pack(args)
    self.assertFalse(args.output.exists())
 def test_actual_loader_shape_and_rpath_runpath_unknown_library_rejected(self):
  for suffix in (' (RPATH) Library rpath: [/tmp/untrusted]', ' (RUNPATH) Library runpath: [$ORIGIN]', ' Shared library: [libunreviewed.so]'):
   with self.subTest(suffix=suffix),tempfile.TemporaryDirectory() as tmp:
    args,q=self.fixture(tmp);p=args.artifact_dir/'live-binary-loader.log';p.write_bytes(p.read_bytes()+suffix.encode());self.report(args,q)
    with self.assertRaises(M.Refusal):M.pack(args)
 def test_host_library_presence_and_architecture_are_required(self):
  for name in M.NEEDED:
   for invalid in ('missing','wrong_architecture'):
    with self.subTest(name=name,invalid=invalid),tempfile.TemporaryDirectory() as tmp:
     args,result=self.packaged(tmp);host=self.host(tmp);p=host/('lib64/ld-linux-x86-64.so.2' if name=='ld-linux-x86-64.so.2' else 'lib/x86_64-linux-gnu/'+name)
     if invalid=='missing':p.unlink()
     else:p.write_bytes(b'generated wrong architecture')
     with self.assertRaises(M.Refusal):self.plan(args,result,host)
 def test_host_cpu_feature_mismatch_refused(self):
  with tempfile.TemporaryDirectory() as tmp:
   args,result=self.packaged(tmp);host=self.host(tmp);(host/'proc/cpuinfo').write_text('flags : sse sse2\n')
   with self.assertRaisesRegex(M.Refusal,'HOST_X86_V2_FEATURES_MISSING'):self.plan(args,result,host)
 def test_metadata_and_source_commits_cannot_be_moving_refs(self):
  with tempfile.TemporaryDirectory() as tmp:
   args,q=self.fixture(tmp);args.helper_revision='HEAD'
   with self.assertRaises(M.Refusal):M.pack(args)
 def test_dryrun_exact_host_no_writes_no_apply_and_retaining_rollback(self):
  with tempfile.TemporaryDirectory() as tmp:
   args,result=self.packaged(tmp);host=self.host(tmp)
   before={str(p.relative_to(host)):p.read_bytes() for p in host.rglob('*') if p.is_file()}
   plan=self.plan(args,result,host);self.assertFalse(plan['host_changed']);self.assertTrue(plan['apply_implemented']);self.assertTrue(plan['rollback_plan']['implemented']);self.assertEqual(plan['rollback_plan']['stop_disable_only'],list(M.UNITS))
   self.assertEqual(before,{str(p.relative_to(host)):p.read_bytes() for p in host.rglob('*') if p.is_file()})
 def test_root_host_identity_os_arch_libc_and_existing_resources_fail_closed(self):
  for change in ('uid','machine','libc','system','instance','os','user','group','opt','state','unit','ancestor'):
   with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
    args,result=self.packaged(tmp);host=self.host(tmp);kw={}
    if change=='uid':kw['uid']=lambda:1001
    elif change=='machine':kw['machine']=lambda:'aarch64'
    elif change=='libc':kw['libc']=lambda:('glibc','2.40')
    elif change=='system':kw['system']=lambda:'Darwin'
    elif change=='instance':(host/'var/lib/cloud/data/instance-id').write_text('wrong')
    elif change=='os':(host/'usr/lib/os-release').write_text('ID=debian\nVERSION_ID=12\n')
    elif change=='user':(host/'etc/passwd').write_text('owa:x:1001:1001:generated:/nonexistent:/usr/sbin/nologin')
    elif change=='group':(host/'etc/group').write_text('owa:x:1001:')
    elif change in ('opt','state'):(host/('opt/owa' if change=='opt' else 'var/lib/owa')).mkdir(parents=True)
    elif change=='unit':
     p=host/'etc/systemd/system/owa-primary.service';p.parent.mkdir(parents=True);p.symlink_to('/dev/null')
    else:(host/'opt').symlink_to(host/'var')
    with self.assertRaises(M.Refusal):self.plan(args,result,host,**kw)
if __name__=='__main__':unittest.main()

"""Only disposable synthetic filesystems and fake OS operations; no real user/units."""
import importlib.util,json,os
from pathlib import Path
import tempfile,types,unittest
from unittest import mock

def load(name):
 s=importlib.util.spec_from_file_location('install_test_'+name,Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
I=load('install');T=load('test_bundle')
class Fake:
 def __init__(self,fail=False):self.created=0;self.ownership=[];self.stopped=[];self.fail=fail
 def probes(self):return dict(uid=lambda:0,machine=lambda:'x86_64',libc=lambda:('glibc','2.39'),system=lambda:'Linux')
 def user(self):return object() if self.created else None
 def group(self):return object() if self.created else None
 def create_user(self):
  self.created+=1
  if self.fail:raise OSError('generated unknown user-add outcome')
  return 1001,1001
 def chown(self,path,uid,gid):self.ownership.append((str(path),uid,gid))
 def stop_disable(self,name):self.stopped.append(name)
class Tests(unittest.TestCase):
 def fixture(self,tmp):
  base=T.Tests();a,result=base.packaged(tmp);root=base.host(tmp);args=types.SimpleNamespace(bundle=a.output,expected_manifest_sha256=result['manifest_sha256'],expected_instance_id=T.TEST_HOST,host_root=root)
  (root/'opt').mkdir();return args,Fake()
 def test_files_account_private_state_no_activation_and_retaining_rollback(self):
  with tempfile.TemporaryDirectory() as tmp:
   a,h=self.fixture(tmp);r=I.apply(a,h);self.assertEqual(r['phase'],'FILES_READY_NOT_ACTIVATED');self.assertEqual(h.created,1);self.assertEqual(h.stopped,[])
   receipt=a.host_root/'var/lib/owa/deployment-receipt.json';data=json.loads(receipt.read_text());self.assertEqual(data['units'],{});self.assertFalse(data['activation_performed']);self.assertEqual(receipt.stat().st_mode&0o777,0o600)
   for name in I.B.STATE_DIRS:
    p=a.host_root/'var/lib/owa'/name;self.assertEqual(list(p.iterdir()),[]);self.assertEqual(p.stat().st_mode&0o777,0o700)
   release=a.host_root/'opt/owa/releases'/r['release'];I.B.verify(release,a.expected_manifest_sha256);self.assertEqual(release.stat().st_mode&0o777,0o555)
   before={str(p.relative_to(a.host_root)):p.read_bytes() for p in a.host_root.rglob('*') if p.is_file() and p!=receipt}
   rolled=I.rollback(a,h);self.assertEqual(rolled['removed_paths'],0);self.assertEqual(h.stopped,[])
   self.assertEqual(before,{str(p.relative_to(a.host_root)):p.read_bytes() for p in a.host_root.rglob('*') if p.is_file() and p!=receipt})
   with self.assertRaises(I.B.Refusal):I.apply(a,Fake())
 def test_existing_paths_and_nss_account_never_overwritten(self):
  with tempfile.TemporaryDirectory() as tmp:
   a,h=self.fixture(tmp);h.created=1
   with self.assertRaises(I.B.Refusal):I.apply(a,h)
   self.assertFalse((a.host_root/'var/lib/owa').exists())
  with tempfile.TemporaryDirectory() as tmp:
   a,h=self.fixture(tmp);p=a.host_root/'opt/owa';p.mkdir();marker=p/'unrelated';marker.write_text('preserve')
   with self.assertRaises(I.B.Refusal):I.apply(a,h)
   self.assertEqual(marker.read_text(),'preserve');self.assertEqual(h.created,0)
 def test_unknown_user_creation_latches_without_retry_or_removal(self):
  with tempfile.TemporaryDirectory() as tmp:
   a,h=self.fixture(tmp);h.fail=True
   with self.assertRaises(OSError):I.apply(a,h)
   r=json.loads((a.host_root/'var/lib/owa/deployment-receipt.json').read_text());self.assertEqual(r['phase'],'UNCERTAIN_REVIEW_REQUIRED');self.assertEqual(h.created,1)
   with self.assertRaises(I.B.Refusal):I.apply(a,Fake())
   self.assertEqual(h.created,1);self.assertEqual(h.stopped,[])
 def owned_units(self,a):
  receipt=a.host_root/'var/lib/owa/deployment-receipt.json';r=json.loads(receipt.read_text());r['units']={}
  for name in I.B.UNITS:
   p=a.host_root/'etc/systemd/system'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('# generated owned-unit fixture '+name+'\n');p.chmod(0o644)
   r['units'][name]={'created_by_installer':True,'sha256':I.B.sha(p.read_bytes())}
  I.save(receipt,r);return receipt
 def test_rollback_checks_every_owned_digest_before_any_stop(self):
  with tempfile.TemporaryDirectory() as tmp:
   a,h=self.fixture(tmp);I.apply(a,h);self.owned_units(a);I.rollback(a,h);self.assertEqual(h.stopped,sorted(I.B.UNITS))
  for damage in ('bytes','foreign_name','unowned','symlink','host'):
   with self.subTest(damage=damage),tempfile.TemporaryDirectory() as tmp:
    a,h=self.fixture(tmp);I.apply(a,h);receipt=self.owned_units(a);r=json.loads(receipt.read_text())
    if damage=='bytes':(a.host_root/'etc/systemd/system'/I.B.UNITS[-1]).write_text('changed')
    elif damage=='foreign_name':r['units']['mesa.service']=r['units'].pop(I.B.UNITS[-1]);I.save(receipt,r)
    elif damage=='unowned':r['units'][I.B.UNITS[-1]]['created_by_installer']=False;I.save(receipt,r)
    elif damage=='symlink':
     p=a.host_root/'etc/systemd/system'/I.B.UNITS[-1];p.unlink();p.symlink_to('/dev/null')
    else:r['instance']='i-11111111111111111';I.save(receipt,r)
    with self.assertRaises(I.B.Refusal):I.rollback(a,h)
    self.assertEqual(h.stopped,[])
 def test_unknown_service_stop_never_retries_automatically(self):
  with tempfile.TemporaryDirectory() as tmp:
   a,h=self.fixture(tmp);I.apply(a,h);receipt=self.owned_units(a)
   def fail(name):h.stopped.append(name);raise OSError('generated unknown stop outcome')
   h.stop_disable=fail
   with self.assertRaises(OSError):I.rollback(a,h)
   self.assertEqual(json.loads(receipt.read_text())['phase'],'ROLLBACK_UNCERTAIN_REVIEW_REQUIRED');self.assertEqual(len(h.stopped),1)
   with self.assertRaises(I.B.Refusal):I.rollback(a,h)
   self.assertEqual(len(h.stopped),1)
 def test_release_write_failure_retains_receipt(self):
  with tempfile.TemporaryDirectory() as tmp:
   a,h=self.fixture(tmp);original=I.os.open
   def fail(path,*args,**kw):
    if str(path).endswith('/bin/owa-live-linux-amd64'):raise OSError('generated storage failure')
    return original(path,*args,**kw)
   with mock.patch.object(I.os,'open',side_effect=fail):
    with self.assertRaises(OSError):I.apply(a,h)
   r=json.loads((a.host_root/'var/lib/owa/deployment-receipt.json').read_text());self.assertEqual(r['phase'],'UNCERTAIN_REVIEW_REQUIRED');self.assertEqual(h.created,1);self.assertEqual(h.stopped,[])
 def test_linux_adapter_fixed_commands_scrub_environment_and_refuse_foreign_units(self):
  host=I.Linux(Path('/'));p=types.SimpleNamespace(pw_uid=1001,pw_gid=1001,pw_shell='/usr/sbin/nologin',pw_dir='/nonexistent');g=types.SimpleNamespace(gr_gid=1001)
  with mock.patch.object(I.os,'geteuid',return_value=0),mock.patch.object(I.pwd,'getpwnam',side_effect=[KeyError,p]),mock.patch.object(I.grp,'getgrnam',side_effect=[KeyError,g]),mock.patch.object(I.subprocess,'run') as run:
   self.assertEqual(host.create_user(),(1001,1001));args,kw=run.call_args;self.assertEqual(args[0],['/usr/sbin/useradd','--system','--user-group','--home-dir','/nonexistent','--no-create-home','--shell','/usr/sbin/nologin','owa']);self.assertEqual(set(kw['env']),{'PATH','LANG','LC_ALL'});self.assertEqual(kw['timeout'],20)
  with mock.patch.object(I.subprocess,'run') as run:
   with self.assertRaises(I.B.Refusal):host.stop_disable('mesa.service')
   run.assert_not_called();host.stop_disable('owa-primary.service');self.assertEqual([c.args[0] for c in run.call_args_list],[['/usr/bin/systemctl','stop','owa-primary.service'],['/usr/bin/systemctl','disable','owa-primary.service']])
 def test_real_adapter_refuses_synthetic_root_without_subprocess(self):
  with mock.patch.object(I.subprocess,'run') as run:
   with self.assertRaises(I.B.Refusal):I.Linux(Path('/tmp/generated-root'))
   run.assert_not_called()
if __name__=='__main__':unittest.main()

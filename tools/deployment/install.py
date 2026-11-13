#!/usr/bin/env python3
"""Explicit first-install files/account transaction; never starts/enables/pairs/sends.

Tests inject a disposable filesystem/OS adapter. The actual Linux adapter is not
executed by tests and remains subject to independent source/installation review.
Rollback only stops/disables digest-bound owned units and retains all state.
"""
import argparse
import grp
import importlib.util
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import subprocess

SPEC=importlib.util.spec_from_file_location('deployment_bundle',Path(__file__).with_name('bundle.py'));B=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(B)

class Linux:
 def __init__(self,root):B.require(root==Path('/'),'REAL_ADAPTER_REQUIRES_HOST_ROOT')
 def probes(self):return {}
 def user(self):
  try:return pwd.getpwnam('owa')
  except KeyError:return None
 def group(self):
  try:return grp.getgrnam('owa')
  except KeyError:return None
 def create_user(self):
  B.require(os.geteuid()==0,'ROOT_REQUIRED_FOR_ACCOUNT_CREATION')
  B.require(self.user() is None and self.group() is None,'NSS_ACCOUNT_ALREADY_EXISTS')
  subprocess.run(['/usr/sbin/useradd','--system','--user-group','--home-dir','/nonexistent','--no-create-home','--shell','/usr/sbin/nologin','owa'],check=True,timeout=20,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
  p=self.user();g=self.group()
  B.require(p is not None and g is not None and p.pw_uid>0 and p.pw_gid==g.gr_gid and p.pw_shell=='/usr/sbin/nologin' and p.pw_dir=='/nonexistent','NEW_ACCOUNT_OUTCOME_UNKNOWN')
  return p.pw_uid,p.pw_gid
 def chown(self,path,uid,gid):os.chown(path,uid,gid,follow_symlinks=False)
 def stop_disable(self,name):
  B.require(name in B.UNITS,'FOREIGN_UNIT_REFUSED')
  for action in ('stop','disable'):subprocess.run(['/usr/bin/systemctl',action,name],check=True,timeout=30,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})

def target(root,name):
 B.require(name.startswith('/') and '..' not in Path(name).parts,'UNSAFE_TARGET')
 path=root/name.lstrip('/')
 for parent in path.parents:
  if parent==root:break
  if os.path.lexists(parent):B.require(not parent.is_symlink() and parent.is_dir(),'UNSAFE_TARGET_ANCESTOR')
 return path

def save(path,value):
 # Parent was exclusively created by this transaction, and stays root-only writable.
 temporary=path.parent/('.deployment-'+secrets.token_hex(12))
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb') as stream:stream.write(B.encoded(value));stream.flush();os.fsync(stream.fileno())
  if os.path.lexists(path):
   info=path.lstat();B.require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600,'UNSAFE_RECEIPT')
  os.replace(temporary,path)
  parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(parent)
  finally:os.close(parent)
 finally:
  if temporary.exists():temporary.unlink()

def apply(args,host):
 B.plan(args,**host.probes());B.require(host.user() is None and host.group() is None,'NSS_ACCOUNT_ALREADY_EXISTS')
 m=B.verify(args.bundle,args.expected_manifest_sha256);root=args.host_root
 base=target(root,'/var/lib/owa');base.mkdir(mode=0o700)
 parent=os.open(base.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(parent)
 finally:os.close(parent)
 receipt=base/'deployment-receipt.json'
 value={'schema':1,'phase':'APPLYING','instance':args.expected_instance_id,'release':m['release'],'manifest_sha256':args.expected_manifest_sha256,'runtime_revision':m['runtime_revision'],'helper_revision':m['helper_revision'],'owned_paths':['/var/lib/owa'],'intents':[],'units':{},'account':None,'activation_performed':False}
 save(receipt,value)
 def intent(name):value['intents'].append(name);save(receipt,value)
 def made(name):
  path=target(root,name)
  for directory in (path.parent,path) if path.is_dir() else (path.parent,):
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   try:os.fsync(fd)
   finally:os.close(fd)
  if path.is_file():
   with path.open('rb') as stream:os.fsync(stream.fileno())
  value['owned_paths'].append(name);save(receipt,value)
 try:
  intent('create dedicated owa user/group once');uid,gid=host.create_user();B.require(type(uid) is int and type(gid) is int and uid>0 and gid>0,'NONROOT_ACCOUNT_REQUIRED');value['account']={'uid':uid,'gid':gid};save(receipt,value)
  for name in ('/opt/owa','/opt/owa/releases','/opt/owa/releases/'+m['release']):
   intent(name);target(root,name).mkdir(mode=0o755);made(name)
  release=target(root,'/opt/owa/releases/'+m['release'])
  for name in sorted(m['files']):
   info=m['files'][name];data=B.regular(args.bundle/name);B.require(B.sha(data)==info['sha256'] and len(data)==info['bytes'],'SOURCE_CHANGED_DURING_INSTALL')
   destination=release/name
   for relative in reversed(Path(name).parents):
    if str(relative)=='.':continue
    directory=release/relative
    if not directory.exists():
     intent(str(directory.relative_to(root)));directory.mkdir(mode=0o755);made('/'+str(directory.relative_to(root)))
   intent('/'+str(destination.relative_to(root)))
   fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,int(info['mode'],8))
   with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
   destination.chmod(int(info['mode'],8));made('/'+str(destination.relative_to(root)))
  data=B.regular(args.bundle/'manifest.json');B.require(B.sha(data)==args.expected_manifest_sha256,'MANIFEST_CHANGED_DURING_INSTALL')
  manifest=release/'manifest.json';fd=os.open(manifest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  made('/'+str(manifest.relative_to(root)))
  for directory in sorted([p for p in release.rglob('*') if p.is_dir()],reverse=True):directory.chmod(0o555)
  release.chmod(0o555);B.verify(release,args.expected_manifest_sha256)
  for directory in [release,*[p for p in release.rglob('*') if p.is_dir()]]:
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   try:os.fsync(fd)
   finally:os.close(fd)
  for name in B.STATE_DIRS:
   absolute='/var/lib/owa/'+name;intent(absolute);directory=target(root,absolute);directory.mkdir(mode=0o700);host.chown(directory,uid,gid);made(absolute)
  host.chown(base,0,gid);base.chmod(0o710)
  value['phase']='FILES_READY_NOT_ACTIVATED';save(receipt,value)
  return {'phase':value['phase'],'release':m['release'],'units_created':0,'account_and_empty_directories_created':True,'paired':False,'sent':False,'started_or_enabled':False}
 except BaseException:
  value['phase']='UNCERTAIN_REVIEW_REQUIRED'
  try:save(receipt,value)
  except (OSError,B.Refusal):pass
  raise

def rollback(args,host):
 root=B.host_identity(args,**host.probes());m=B.verify(args.bundle,args.expected_manifest_sha256)
 base=target(root,'/var/lib/owa');info=base.lstat();B.require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o022,'UNSAFE_RECEIPT_DIRECTORY')
 path=base/'deployment-receipt.json';info=path.lstat();B.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'UNSAFE_RECEIPT')
 r=B.document(path);B.require(r['schema']==1 and r['instance']==args.expected_instance_id and r['manifest_sha256']==args.expected_manifest_sha256 and r['release']==m['release'],'OWNERSHIP_RECEIPT_MISMATCH')
 B.require(r['phase'] in ('APPLYING','UNCERTAIN_REVIEW_REQUIRED','FILES_READY_NOT_ACTIVATED','ROLLBACK_UNITS_STOPPED_STATE_RETAINED'),'ROLLBACK_OUTCOME_REQUIRES_REVIEW')
 if r['phase']=='ROLLBACK_UNITS_STOPPED_STATE_RETAINED':return {'phase':r['phase'],'owned_units_stopped_disabled':0,'state_keys_journals_accounts_release_retained':True,'removed_paths':0}
 units=r['units'];B.require(isinstance(units,dict) and set(units)<=set(B.UNITS),'FOREIGN_UNIT_REFUSED')
 # Validate every owned unit before stopping any; never trust a name alone.
 for name,detail in units.items():
  B.require(detail.get('created_by_installer') is True,'UNOWNED_UNIT_REFUSED');unit=target(root,'/etc/systemd/system/'+name);info=unit.lstat()
  B.require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o022 and B.sha(B.regular(unit))==detail['sha256'],'OWNED_UNIT_CHANGED')
 r.update(phase='ROLLBACK_IN_PROGRESS',rollback_intents=[],rollback_completed_units=[]);save(path,r)
 try:
  for name in sorted(units):
   r['rollback_intents'].append(name);save(path,r);host.stop_disable(name);r['rollback_completed_units'].append(name);save(path,r)
 except BaseException:
  r['phase']='ROLLBACK_UNCERTAIN_REVIEW_REQUIRED'
  try:save(path,r)
  except (OSError,B.Refusal):pass
  raise
 r['phase']='ROLLBACK_UNITS_STOPPED_STATE_RETAINED';save(path,r)
 return {'phase':r['phase'],'owned_units_stopped_disabled':len(units),'state_keys_journals_accounts_release_retained':True,'removed_paths':0}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=('apply','rollback'));p.add_argument('--execute',action='store_true',required=True);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--expected-manifest-sha256',required=True);p.add_argument('--expected-instance-id',required=True);p.add_argument('--host-root',type=Path,default=Path('/'));a=p.parse_args()
 try:
  host=Linux(a.host_root);print(json.dumps((apply if a.command=='apply' else rollback)(a,host),sort_keys=True));return 0
 except (B.Refusal,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):print('{"phase":"REFUSED_OR_UNCERTAIN","reason":"REVIEW_RECEIPT_NO_AUTOMATIC_RETRY"}');return 2
if __name__=='__main__':raise SystemExit(main())

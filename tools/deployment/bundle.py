#!/usr/bin/env python3
"""Offline source-bound Linux canary packaging and read-only installation planning.

There is deliberately no apply, pair, start, enable, upload or rollback executor.
Expected artifact digests must come from an independent reviewed CI receipt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess

REPO=Path(__file__).resolve().parents[2]
HELPERS=('tools/reliability/supervisor.py','tools/reliability/progress.py',
 'tools/reliability/finish_soak.py','tools/reliability/periodic_canary.py',
 'tools/reliability/systemd_canary.py','tools/live_qualification/qr_display.py')
UNITS=('owa-primary.service','owa-periodic.service','owa-periodic.timer')
STATE_DIRS=('auth-linux','primary','primary-proof','periodic','controller')
HASH=re.compile('[a-f0-9]{64}')
COMMIT=re.compile('[a-f0-9]{40}')
MAX_FILE=128<<20
NEEDED={'libz.so.1','libm.so.6','libc.so.6','ld-linux-x86-64.so.2'}
X86_V2={'cmov','cx8','fpu','fxsr','mmx','sse','sse2','cx16','lahf_lm','popcnt','pni','sse4_1','sse4_2','ssse3'}
class Refusal(Exception):pass

def require(condition,reason):
 if not condition:raise Refusal(reason)

def unique(pairs):
 result={}
 for key,value in pairs:
  require(key not in result,'DUPLICATE_JSON_KEY');result[key]=value
 return result

def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def regular(path,limit=MAX_FILE):
 info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'REGULAR_SINGLE_LINK_REQUIRED')
 require(0<=info.st_size<=limit,'FILE_TOO_LARGE');return path.read_bytes()
def document(path):return json.loads(regular(path,16<<20),object_pairs_hook=unique)
def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.DEVNULL)
def revision(repo,ref):
 value=git(repo,'rev-parse','--verify',ref+'^{commit}').decode().strip()
 require(COMMIT.fullmatch(ref) and value==ref,'EXACT_LOCAL_COMMIT_REQUIRED');return value

def export(repo,ref,name):
 row=git(repo,'ls-tree',ref,'--',name).decode().split()
 require(len(row)==4 and row[0] in ('100644','100755') and row[1]=='blob' and row[3]==name,'PUBLIC_GIT_FILE_REQUIRED')
 data=git(repo,'show',ref+':'+name);require(len(data)<=MAX_FILE,'SOURCE_TOO_LARGE')
 return data,{'commit':ref,'git_blob':row[2],'sha256':sha(data),'bytes':len(data)}

def artifact(args):
 root=args.artifact_dir;report_bytes=regular(root/'qualification.json',16<<20)
 require(HASH.fullmatch(args.expected_report_sha256) and sha(report_bytes)==args.expected_report_sha256,'REVIEWED_REPORT_HASH_MISMATCH')
 q=json.loads(report_bytes,object_pairs_hook=unique)
 require(q.get('passed') is True and q.get('platform')=='linux-amd64' and q.get('github_run_id')==args.expected_run_id and q.get('checkout_commit')==args.runtime_revision,'ARTIFACT_SOURCE_BINDING_MISMATCH')
 for field in ('checkout_clean','checkout_unchanged','runner_unchanged','source_unchanged','linker_runtime_unchanged'):require(q.get(field) is True,'ARTIFACT_GUARD_FAILED')
 for prefix in ('checkout_source','runner_source','input'):require(q[prefix+'_before']==q[prefix+'_after'],'ARTIFACT_GUARD_MISMATCH')
 for name,digest in q['checkout_source_before'].items():require(sha(export(args.repository,args.runtime_revision,name)[0])==digest,'RUNTIME_GIT_SOURCE_MISMATCH')
 pin_bytes=export(args.repository,args.runtime_revision,'tools/native_ci/pin.json')[0];pin=json.loads(pin_bytes)
 require(q['pin_sha256']==sha(pin_bytes) and q['compiler_source_revision']==pin['compiler_source_revision'] and q['core_source_revision']==pin['core_source_revision'] and q['dependency_manifest_sha256']==pin['dependencies']['manifest']['sha256'],'COMPILER_CORE_DEPENDENCY_BINDING_MISMATCH')
 checks=document(root/'checksums.json')
 actual={p.name for p in root.iterdir() if p.is_file() or p.is_symlink()}-{'checksums.json'}
 require(actual==set(checks),'ARTIFACT_CHECKSUM_INVENTORY_MISMATCH')
 for name,digest in checks.items():
  require(Path(name).name==name and name not in ('.','..'),'UNSAFE_ARTIFACT_NAME')
  require(sha(regular(root/name))==digest,'ARTIFACT_CHECKSUM_MISMATCH')
 require(checks['qualification.json']==sha(report_bytes),'ARTIFACT_REPORT_CHECKSUM_MISMATCH')
 commands=q['commands'];require(all(c['exit_code']==0 and c.get('failure') is None for c in commands),'ARTIFACT_COMMAND_FAILED')
 for c in commands:
  require(Path(c['log']).name==c['log'],'UNSAFE_COMMAND_LOG_NAME')
  require(sha(regular(root/c['log']))==c['log_sha256'],'COMMAND_LOG_HASH_MISMATCH')
 for mode in ('address','thread'):
  for name in ('empty-run','unit','qualification-tools','encrypted_recovery','compatibility','consumer-run'):
   require(any(c['name']==name+'-'+mode for c in commands),'NATIVE_GATE_MISSING')
 live=q['live_binary'];require(live['file']=='owa-live-linux-amd64' and live['platform']=='linux-amd64' and live['sanitizer']=='none' and live['optimization']=='speed' and live['account_opened'] is False and live['provider_calls'] is False and live['offline_preview_passed'] is True,'LIVE_ARTIFACT_UNQUALIFIED')
 binary=regular(root/live['file']);require(HASH.fullmatch(args.expected_binary_sha256) and sha(binary)==args.expected_binary_sha256==live['sha256'] and len(binary)==live['bytes'],'REVIEWED_BINARY_HASH_MISMATCH')
 require(len(binary)>=64 and binary[:6]==b'\x7fELF\x02\x01' and binary[18:20]==b'\x3e\x00','AMD64_ELF_REQUIRED')
 inspection=regular(root/live['inspection_log']).decode();require('/lib64/ld-linux-x86-64.so.2' in inspection,'EXPECTED_LOADER_REQUIRED')
 versions={tuple(map(int,x.split('.'))) for x in re.findall(r'\bGLIBC_([0-9]+\.[0-9]+)',inspection)}
 require(versions and max(versions)<=(2,39),'GLIBC_REQUIREMENT_UNSUPPORTED')
 needed=re.findall(r'Shared library: \[([^\]]+)\]',inspection)
 require(set(needed)==NEEDED and len(needed)==len(NEEDED),'UNREVIEWED_SHARED_LIBRARY')
 require(not re.search(r'\b(?:RPATH|RUNPATH)\b',inspection),'UNSAFE_RUNTIME_SEARCH_PATH')
 require(regular(root/'live-binary-preview.log').strip()==b'PHASE PREVIEW_READY','OFFLINE_PREVIEW_MISMATCH')
 return q,report_bytes,binary,inspection.encode(),{'interpreter':'/lib64/ld-linux-x86-64.so.2','maximum_glibc':'.'.join(map(str,max(versions))),'needed':needed}

def pack(args):
 revision(args.repository,args.runtime_revision);revision(args.repository,args.helper_revision)
 q,report_bytes,binary,inspection,abi=artifact(args)
 files={'bin/owa-live-linux-amd64':binary,'evidence/qualification.json':report_bytes,'evidence/loader.log':inspection}
 components={}
 for name in HELPERS:
  data,provenance=export(args.repository,args.helper_revision,name);files[name]=data;components[name]=provenance
 body={'schema':1,'runtime_revision':args.runtime_revision,'helper_revision':args.helper_revision,'ci_run_id':args.expected_run_id,'reviewed_report_sha256':args.expected_report_sha256,'compiler_sha256':q['compiler_sha256'],'compiler_source_revision':q['compiler_source_revision'],'core_source_revision':q['core_source_revision'],'dependency_manifest_sha256':q['dependency_manifest_sha256'],'pin_sha256':q['pin_sha256'],'abi':abi,'helpers':components,'files':{name:{'sha256':sha(data),'bytes':len(data),'mode':'0555' if name.startswith('bin/') else '0444'} for name,data in files.items()},'scope':'public code and source-bound native binary only; no account/session/config/QR payload/keys'}
 release='owa-'+args.runtime_revision[:12]+'-'+args.helper_revision[:12]+'-'+sha(encoded(body))[:16]
 manifest={**body,'release':release};args.output.mkdir(mode=0o700)
 for name,data in {**files,'manifest.json':encoded(manifest)}.items():
  path=args.output/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  with path.open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  path.chmod(0o600 if name=='manifest.json' else int(body['files'][name]['mode'],8))
 return {'phase':'PACKAGED_OFFLINE','release':release,'manifest_sha256':sha(encoded(manifest)),'files':len(files),'applied':False}

def verify(bundle,expected_manifest):
 raw=regular(bundle/'manifest.json',16<<20);require(HASH.fullmatch(expected_manifest) and sha(raw)==expected_manifest,'REVIEWED_MANIFEST_HASH_REQUIRED');m=json.loads(raw,object_pairs_hook=unique)
 require(m['schema']==1 and COMMIT.fullmatch(m['runtime_revision']) and COMMIT.fullmatch(m['helper_revision']),'MANIFEST_INVALID')
 require(set(m['helpers'])==set(HELPERS),'HELPER_ALLOWLIST_MISMATCH')
 allowed=set(HELPERS)|{'bin/owa-live-linux-amd64','evidence/qualification.json','evidence/loader.log'}
 require(set(m['files'])==allowed,'FILE_ALLOWLIST_MISMATCH')
 require(not bundle.is_symlink(),'BUNDLE_DIRECTORY_SYMLINK')
 expected_dirs={str(p) for name in allowed for p in Path(name).parents if str(p)!='.'}
 actual_dirs={str(p.relative_to(bundle)) for p in bundle.rglob('*') if p.is_dir() and not p.is_symlink()}
 require(actual_dirs==expected_dirs,'BUNDLE_DIRECTORY_INVENTORY_MISMATCH')
 actual={str(p.relative_to(bundle)) for p in bundle.rglob('*') if not p.is_dir() or p.is_symlink()}
 require(actual==allowed|{'manifest.json'},'BUNDLE_INVENTORY_MISMATCH')
 for name,info in m['files'].items():
  path=bundle/name;data=regular(path);require(sha(data)==info['sha256'] and len(data)==info['bytes'] and stat.S_IMODE(path.stat().st_mode)==int(info['mode'],8),'BUNDLE_FILE_CHANGED')
  for parent in path.relative_to(bundle).parents:
   if str(parent)!='.':require(not (bundle/parent).is_symlink(),'BUNDLE_DIRECTORY_SYMLINK')
 base={k:v for k,v in m.items() if k!='release'}
 require(m['release']=='owa-'+m['runtime_revision'][:12]+'-'+m['helper_revision'][:12]+'-'+sha(encoded(base))[:16],'RELEASE_ID_MISMATCH')
 require(sha(regular(bundle/'evidence/qualification.json'))==m['reviewed_report_sha256'],'BUNDLED_REPORT_MISMATCH')
 return m

def host_file(root,path):return regular(root/path.lstrip('/'),1<<20).decode()
def host_identity(args,uid=os.geteuid,machine=platform.machine,libc=platform.libc_ver,system=platform.system):
 require(uid()==0,'ROOT_REQUIRED_FOR_HOST_PREFLIGHT')
 require(system()=='Linux' and machine()=='x86_64' and libc()==('glibc','2.39'),'HOST_RUNTIME_MISMATCH')
 root=args.host_root;require(root.is_absolute() and not root.is_symlink(),'HOST_ROOT_INVALID')
 require(re.fullmatch(r'i-[0-9a-f]{17}',args.expected_instance_id) and host_file(root,'/var/lib/cloud/data/instance-id').strip()==args.expected_instance_id,'EXACT_INSTANCE_MISMATCH')
 osinfo=dict(line.split('=',1) for line in host_file(root,'/usr/lib/os-release').splitlines() if '=' in line)
 require(osinfo.get('ID','').strip('"')=='ubuntu' and osinfo.get('VERSION_ID','').strip('"')=='24.04','HOST_OS_MISMATCH')
 cpus=[set(line.split(':',1)[1].split()) for line in host_file(root,'/proc/cpuinfo').splitlines() if line.startswith('flags') and ':' in line]
 require(cpus and X86_V2<=set.intersection(*cpus),'HOST_X86_V2_FEATURES_MISSING')
 return root

def plan(args,**probes):
 m=verify(args.bundle,args.expected_manifest_sha256);root=host_identity(args,**probes)
 for name in ('passwd','group'):require(not any(line.split(':',1)[0]=='owa' for line in host_file(root,'/etc/'+name).splitlines()),'OWA_ACCOUNT_ALREADY_EXISTS')
 # First-install only. Never follow or reuse an existing resource, even empty.
 targets=['/opt/owa','/var/lib/owa']+['/etc/systemd/system/'+x for x in UNITS]+['/run/systemd/system/'+x for x in UNITS]+['/usr/lib/systemd/system/'+x for x in UNITS]
 for target in targets:
  path=root/target.lstrip('/');require(not os.path.lexists(path),'EXISTING_RESOURCE_REFUSED')
  for parent in path.parents:
   if parent==root:break
   if os.path.lexists(parent):require(not parent.is_symlink() and parent.is_dir(),'UNSAFE_HOST_ANCESTOR')
 for name in m['abi']['needed']:
  path=root/('lib64/ld-linux-x86-64.so.2' if name=='ld-linux-x86-64.so.2' else 'lib/x86_64-linux-gnu/'+name)
  require(path.is_file(),'HOST_LIBRARY_MISSING')
  with path.open('rb') as stream:header=stream.read(32)
  require(len(header)>=20 and header[:6]==b'\x7fELF\x02\x01' and header[18:20]==b'\x3e\x00','HOST_LIBRARY_ARCHITECTURE_MISMATCH')
 return {'phase':'DRY_RUN_ONLY','host_gate':'exact independently reviewed instance; Ubuntu24.04 x86_64 glibc2.39','release':m['release'],'manifest_sha256':args.expected_manifest_sha256,'proposed_actions':['create dedicated non-login owa system user/group only if absent','create root-owned immutable /opt/owa/releases/'+m['release'],'create owa-owned0700 distinct /var/lib/owa/'+','.join(STATE_DIRS),'write installer ownership receipt before separately reviewed unit creation'],'automatic_actions_forbidden':['pair','send','start','enable','resume','overwrite','delete state','modify Mesa or ports'],'units_not_created':list(UNITS),'rollback_plan':{'precondition':'matching first-install ownership receipt and exact owned unit digests; otherwise refuse','stop_disable_only':list(UNITS),'retain':['all auth/session/keys/journals/qualification state','immutable release for investigation'],'implemented':True},'apply_implemented':True,'host_changed':False,'remaining':['independent review of Linux adapter and installer transaction before host approval','approve installation','independent pairing and primary24h proof','alert rollout review']}

def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
 b=sub.add_parser('pack');b.add_argument('--repository',type=Path,default=REPO)
 for n in ('runtime-revision','helper-revision','expected-report-sha256','expected-binary-sha256','expected-run-id'):b.add_argument('--'+n,required=True)
 b.add_argument('--artifact-dir',type=Path,required=True);b.add_argument('--output',type=Path,required=True)
 d=sub.add_parser('plan');d.add_argument('--bundle',type=Path,required=True);d.add_argument('--expected-manifest-sha256',required=True);d.add_argument('--expected-instance-id',required=True);d.add_argument('--host-root',type=Path,default=Path('/'))
 args=p.parse_args()
 try:print(json.dumps(pack(args) if args.command=='pack' else plan(args),sort_keys=True));return 0
 except (Refusal,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):print('{"phase":"REFUSED","reason":"OFFLINE_PREFLIGHT_FAILED"}');return 2
if __name__=='__main__':raise SystemExit(main())

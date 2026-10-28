#!/usr/bin/env python3
"""Descriptor-bound check of import provenance and recorded local changes."""
import errno,hashlib,json,os,re,stat,sys,tempfile
from unittest.mock import patch
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]; MAX_AUTHORITY_BYTES=1024*1024; MAX_IMPORTED_BYTES=16*1024*1024
SHA256=re.compile(r'^[0-9a-f]{64}$')
def fail(message): raise SystemExit(message)
def canonical(name):
 if not isinstance(name,str) or not name or '\\' in name or any(x in name for x in ('\0','\n','\r')): fail(f'invalid imported path: {name!r}')
 value=PurePosixPath(name)
 if value.is_absolute() or value.as_posix()!=name or any(part in {'','.','..'} for part in value.parts): fail(f'invalid imported path: {name!r}')
 return value
def direct_bytes(root,name,maximum):
 relative=canonical(name); nofollow=getattr(os,'O_NOFOLLOW',0); cloexec=getattr(os,'O_CLOEXEC',0); flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|nofollow|cloexec; opened=[]; descriptor=None
 try:
  parent=os.open(root,flags); opened.append(parent)
  for component in relative.parts[:-1]: parent=os.open(component,flags,dir_fd=parent); opened.append(parent)
  descriptor=os.open(relative.parts[-1],os.O_RDONLY|nofollow|cloexec,dir_fd=parent); before=os.fstat(descriptor)
  mode=stat.S_IMODE(before.st_mode)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid() or mode&(stat.S_ISUID|stat.S_ISGID|stat.S_ISVTX|0o022): fail(f'imported file policy mismatch: {name}')
  if before.st_size<1 or before.st_size>maximum: fail(f'imported file size is outside bounds: {name}')
  payload=bytearray()
  while len(payload)<=maximum:
   chunk=os.read(descriptor,min(65536,maximum+1-len(payload)))
   if not chunk: break
   payload.extend(chunk)
  after=os.fstat(descriptor); path_after=os.stat(relative.parts[-1],dir_fd=parent,follow_symlinks=False); identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  if len(payload)!=before.st_size or identity(before)!=identity(after) or (path_after.st_dev,path_after.st_ino)!=(before.st_dev,before.st_ino): fail(f'imported file changed while read: {name}')
  return bytes(payload)
 except OSError as error:
  if error.errno in {errno.ELOOP,errno.EMLINK,errno.ENOTDIR}: fail(f'imported path is indirect: {name}')
  fail(f'imported file cannot be opened directly: {name}: {error}')
 finally:
  if descriptor is not None: os.close(descriptor)
  for item in reversed(opened): os.close(item)
def strict_json(payload,label):
 try:
  text=payload.decode('utf-8')
  def pairs(items):
   result={}
   for key,value in items:
    if key in result: fail(f'{label} contains duplicate JSON key: {key}')
    result[key]=value
   return result
  return json.loads(text,object_pairs_hook=pairs)
 except (UnicodeDecodeError,json.JSONDecodeError) as error: fail(f'{label} is not strict UTF-8 JSON: {error}')
def verify(root=ROOT,quiet=False):
 provenance=strict_json(direct_bytes(root,'PROVENANCE.json',MAX_AUTHORITY_BYTES),'provenance'); local=strict_json(direct_bytes(root,'LOCAL-CHANGES.json',MAX_AUTHORITY_BYTES),'local changes')
 if set(provenance)!={'implementation_repository','base_branch','base_commit','prototype_repository','prototype_commit','reserve_revision','imported_files_sha256','production_ready'} or provenance['production_ready'] is not False or provenance['implementation_repository']!='https://github.com/sorenplanck/dom-protocol': fail('provenance schema or policy is invalid')
 if set(local)!={'purpose','modified_imported_files','production_ready','pushed'} or local['production_ready'] is not False or local['pushed'] is not False or not isinstance(local['purpose'],str) or not local['purpose']: fail('local changes schema or policy is invalid')
 imported=provenance['imported_files_sha256']; changes=local['modified_imported_files']
 if not isinstance(imported,dict) or not isinstance(changes,dict) or not 1<=len(imported)<=4096 or len(changes)>len(imported) or not set(changes).issubset(imported): fail('imported provenance sets are invalid')
 snapshot={}
 for name,original in imported.items():
  canonical(name)
  if not isinstance(original,str) or not SHA256.fullmatch(original): fail(f'imported digest is invalid: {name}')
  expected=original
  if name in changes:
   change=changes[name]
   if not isinstance(change,dict) or set(change)!={'original_sha256','current_sha256','reason'} or change.get('original_sha256')!=original or not isinstance(change.get('current_sha256'),str) or not SHA256.fullmatch(change['current_sha256']) or not isinstance(change.get('reason'),str) or not 1<=len(change['reason'])<=8192: fail(f'local change record is invalid: {name}')
   expected=change['current_sha256']
  payload=direct_bytes(root,name,MAX_IMPORTED_BYTES); snapshot[name]=payload
  if hashlib.sha256(payload).hexdigest()!=expected: fail(f'imported file digest mismatch: {name}')
 second={name:direct_bytes(root,name,MAX_IMPORTED_BYTES) for name in imported}
 if second!=snapshot: fail('imported source snapshot changed between descriptor-bound passes')
 if not quiet: print(f'PASS: {len(imported)} imported files checked, including {len(changes)} explicitly recorded modifications; production readiness remains false')
def expect(callable_,needle):
 try: callable_()
 except SystemExit as error:
  if needle not in str(error): raise AssertionError((needle,str(error)))
 else: raise AssertionError(f'expected failure: {needle}')
def self_test():
 with tempfile.TemporaryDirectory() as directory:
  root=Path(directory); (root/'x').write_text('safe\n'); digest=hashlib.sha256(b'safe\n').hexdigest(); provenance={'implementation_repository':'https://github.com/sorenplanck/dom-protocol','base_branch':'x','base_commit':'0'*40,'prototype_repository':'x','prototype_commit':'1'*40,'reserve_revision':'x','imported_files_sha256':{'x':digest},'production_ready':False}; local={'purpose':'test','modified_imported_files':{},'production_ready':False,'pushed':False}
  (root/'PROVENANCE.json').write_text(json.dumps(provenance)); (root/'LOCAL-CHANGES.json').write_text(json.dumps(local)); verify(root,True)
  original_direct=direct_bytes; reads=0
  def mutate_between_passes(snapshot_root,name,maximum):
   nonlocal reads
   if name=='x':
    reads+=1
    if reads==2: (root/'x').write_text('changed between passes\n')
   return original_direct(snapshot_root,name,maximum)
  with patch.object(sys.modules[__name__],'direct_bytes',side_effect=mutate_between_passes): expect(lambda:verify(root,True),'snapshot changed')
  (root/'x').write_text('safe\n')
  (root/'PROVENANCE.json').write_text('{"production_ready":false,"production_ready":true}'); expect(lambda:verify(root,True),'duplicate JSON key')
  (root/'PROVENANCE.json').write_text(json.dumps(provenance)); os.link(root/'x',root/'hard'); provenance['imported_files_sha256']={'hard':digest}; (root/'PROVENANCE.json').write_text(json.dumps(provenance)); expect(lambda:verify(root,True),'policy mismatch')
 print('PASS: import provenance rejects ambiguous authority and indirect files')
if __name__=='__main__':
 if sys.argv[1:]==['--self-test']: self_test()
 elif not sys.argv[1:]: verify()
 else: fail('usage: verify-import.py [--self-test]')

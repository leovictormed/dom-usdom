"""Descriptor-bound readers for release-specialized source manifests."""
import errno,hashlib,os,re,stat,tomllib
from pathlib import Path,PurePosixPath
LINE=re.compile(r'^([0-9a-f]{64})  (.+)$')
def fail(message): raise SystemExit(f'FAIL: {message}')
def canonical(name):
 value=PurePosixPath(name)
 if not isinstance(name,str) or not name or value.is_absolute() or value.as_posix()!=name or any(x in {'','.','..'} for x in value.parts): fail(f'invalid specialized manifest path: {name!r}')
 return value
def direct(root,name,maximum=64*1024*1024):
 relative=canonical(name); flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0); opened=[];fd=None
 try:
  parent=os.open(root,flags);opened.append(parent)
  for part in relative.parts[:-1]:parent=os.open(part,flags,dir_fd=parent);opened.append(parent)
  fd=os.open(relative.parts[-1],os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0),dir_fd=parent);before=os.fstat(fd);mode=stat.S_IMODE(before.st_mode)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or mode&(stat.S_ISUID|stat.S_ISGID|stat.S_ISVTX|0o022) or before.st_size>maximum:fail(f'unsafe specialized source: {name}')
  data=bytearray()
  while len(data)<=maximum:
   chunk=os.read(fd,min(1024*1024,maximum+1-len(data)))
   if not chunk:break
   data.extend(chunk)
  after=os.fstat(fd);current=os.stat(relative.parts[-1],dir_fd=parent,follow_symlinks=False);identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  if len(data)!=before.st_size or identity(before)!=identity(after) or (current.st_dev,current.st_ino)!=(before.st_dev,before.st_ino):fail(f'specialized source changed while read: {name}')
  return bytes(data)
 except OSError as error:
  if error.errno in {errno.ELOOP,errno.EMLINK,errno.ENOTDIR}:fail(f'indirect specialized source path: {name}')
  fail(f'cannot read specialized source directly: {name}: {error}')
 finally:
  if fd is not None:os.close(fd)
  for item in reversed(opened):os.close(item)
def snapshot(root,names):
 ordered=sorted(set(names));first={n:direct(root,n) for n in ordered};second={n:direct(root,n) for n in ordered}
 if first!=second:fail('specialized source snapshot changed between descriptor-bound passes')
 return first
def discover(root,directory,suffix):
 canonical(directory); flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0); opened=[]
 try:
  parent=os.open(root,flags);opened.append(parent)
  for part in PurePosixPath(directory).parts:parent=os.open(part,flags,dir_fd=parent);opened.append(parent)
  found=set()
  for name in os.listdir(parent):
   if '/' in name or name in {'.','..'}:fail('invalid directory entry')
   info=os.stat(name,dir_fd=parent,follow_symlinks=False)
   if stat.S_ISREG(info.st_mode) and name.endswith(suffix):
    relative=f'{directory}/{name}';direct(root,relative);found.add(relative)
   elif stat.S_ISLNK(info.st_mode):fail(f'indirect specialized source path: {directory}/{name}')
  return found
 finally:
  for item in reversed(opened):os.close(item)
def cargo_targets(root,payloads):
 try: document=tomllib.loads(payloads['Cargo.toml'].decode())
 except (UnicodeDecodeError,tomllib.TOMLDecodeError) as error:fail(f'invalid Cargo.toml: {error}')
 expected=set()
 for table,folder in (('bin','src/bin'),('example','examples')):
  explicit=document.get(table,[])
  if not isinstance(explicit,list):fail(f'invalid Cargo [[{table}]] targets')
  for entry in explicit:
   if not isinstance(entry,dict):fail(f'invalid Cargo [[{table}]] target')
   path=entry.get('path')
   if path is not None:
    canonical(path);expected.add(path)
  directory=Path(root)/folder
  if directory.exists():expected.update(discover(root,folder,'.rs'))
 package=document.get('package',{})
 build=package.get('build') if isinstance(package,dict) else None
 if isinstance(build,str):canonical(build);expected.add(build)
 elif build is not False and (Path(root)/'build.rs').exists():expected.add('build.rs')
 actual={name for name in payloads if name=='build.rs' or name.startswith('src/bin/') or name.startswith('examples/')}
 if actual!=expected:fail(f'Cargo target closure mismatch: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}')
 return expected
MOD=re.compile(r'(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;')
INCLUDE=re.compile(r'\binclude(?:_bytes|_str)?!\s*\(\s*"([^"]+)"\s*\)')
PATH_ATTRIBUTE=re.compile(r'#\s*\[(?:cfg_attr\([^]]*,\s*)?path\s*=')
def rust_closure(root,seeds,inventory):
 pending=list(seeds);seen=set()
 while pending:
  name=pending.pop()
  if name in seen:continue
  payload=direct(root,name);seen.add(name);parent=PurePosixPath(name).parent
  try:text=payload.decode()
  except UnicodeDecodeError:fail(f'Rust source is not UTF-8: {name}')
  if PATH_ATTRIBUTE.search(text):fail(f'Rust #[path] indirection is forbidden in specialized closure: {name}')
  dependencies=[]
  for module in MOD.findall(text):
   choices=[(parent/f'{module}.rs').as_posix(),(parent/module/'mod.rs').as_posix()]
   existing=[choice for choice in choices if (Path(root)/choice).exists()]
   if len(existing)!=1:fail(f'ambiguous or missing Rust module {module!r} from {name}')
   dependencies.extend(existing)
  for included in INCLUDE.findall(text):
   candidate=(parent/included).as_posix();canonical(candidate);dependencies.append(candidate)
  for dependency in dependencies:
   if dependency not in inventory:fail(f'Rust dependency omitted from specialized manifest: {dependency}')
   pending.append(dependency)
 return seen
def manifest(root,manifest_name,expected=None):
 first=direct(root,manifest_name);listed={}
 try:lines=first.decode().splitlines()
 except UnicodeDecodeError as error:fail(f'specialized manifest is not UTF-8: {error}')
 for number,line in enumerate(lines,1):
  match=LINE.fullmatch(line)
  if not match or match.group(2) in listed:fail(f'malformed or duplicate specialized manifest line {number}')
  canonical(match.group(2));listed[match.group(2)]=match.group(1)
 if expected is not None and set(listed)!=set(expected):fail(f'specialized manifest inventory mismatch: missing={sorted(set(expected)-set(listed))}, extra={sorted(set(listed)-set(expected))}')
 payloads=snapshot(root,listed)
 if direct(root,manifest_name)!=first:fail('specialized manifest changed during snapshot')
 for name,payload in payloads.items():
  if hashlib.sha256(payload).hexdigest()!=listed[name]:fail(f'specialized manifest digest mismatch: {name}')
 return payloads

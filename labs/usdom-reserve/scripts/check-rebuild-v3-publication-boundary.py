#!/usr/bin/env python3
"""Bind release-critical controls to the source snapshot, excluding secrets/artifacts."""
import ast,errno,hashlib,json,os,posixpath,re,stat,sys,tempfile,tomllib
from pathlib import Path,PurePosixPath
from rebuild_v3_build_policy import load_policy
ROOT=Path(__file__).resolve().parents[1]; INVENTORY=ROOT/'config/rebuild-v3-critical-source-inventory.json'; MANIFEST=ROOT/'MANIFEST.sha256'
MANIFEST_LINE=re.compile(r'^([0-9a-f]{64})  (.+)$'); MAX_CRITICAL_SOURCE_BYTES=1024*1024
MAX_CARGO_RESOURCE_BYTES=64*1024*1024
ARCHIVE_MAGICS=(b'\x7fELF',b'PK\x03\x04',b'\x1f\x8b',b'\x28\xb5\x2f\xfd')
SECRET_PATTERNS=(re.compile(rb'-----BEGIN '+rb'(?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),re.compile(rb'(?i)https?://[^\s/:]+:[^\s/@]+@'),re.compile(rb'''(?i)["'](?:private[_-]?key|mnemonic|seed[_-]?phrase|secret[_-]?key)["']\s*:\s*["'][^"'\r\n]{16,}["']'''))
SECRET_SUFFIXES={'.key','.pem','.p12','.pfx'}; SECRET_NAMES={'.env','id_rsa','id_ed25519'}
JS_LOCAL_IMPORT=re.compile(r'''(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["'](\.{1,2}/[^"']+)["']''')
JS_REQUIRE_LOCAL=re.compile(r'''\brequire(?:\.resolve)?\s*\(\s*["'](\.{1,2}/[^"']+)["']''')
JS_URL_LOCAL=re.compile(r'''\bnew\s+URL\s*\(\s*["'](\.{1,2}/[^"']+)["']''')
SHELL_PROJECT_SOURCE=re.compile(r'''(?m)^\s*(?:source|\.)\s+["']?\$project/([^"'\s]+)''')
SHELL_RELATIVE_SOURCE=re.compile(r'''(?m)^\s*(?:source|\.)\s+["']?(\.{1,2}/[^"'\s]+)''')
LOCAL_PATH_REFERENCE=re.compile(r'''(?<![A-Za-z0-9_.-])((?:scripts|sdk|config)/[A-Za-z0-9_./-]+\.(?:mjs|js|py|sh|json))(?![A-Za-z0-9_.-])''')
JS_DYNAMIC_EXECUTION=re.compile(r'''\b(?:spawn|spawnSync|execFile|execFileSync)\s*\(''')
def fail(message): raise SystemExit(message)
def strict_json_bytes(payload,label):
 try:
  text=payload.decode('utf-8')
  def pairs(items):
   value={}
   for key,item in items:
    if key in value: fail(f'{label} contains duplicate JSON key: {key}')
    value[key]=item
   return value
  return json.loads(text,object_pairs_hook=pairs)
 except (UnicodeDecodeError,json.JSONDecodeError) as error: fail(f'{label} is not strict UTF-8 JSON: {error}')
def parse_source_manifest(payload):
 try: lines=payload.decode('utf-8').splitlines()
 except UnicodeDecodeError as error: fail(f'source manifest is not UTF-8: {error}')
 entries={}
 for number,line in enumerate(lines,1):
  match=MANIFEST_LINE.fullmatch(line)
  if not match: fail(f'malformed source manifest line {number}')
  if match.group(2) in entries: fail(f'duplicate source manifest path at line {number}')
  entries[match.group(2)]=match.group(1)
 return entries
def canonical_relative(name):
 if not isinstance(name,str) or not name or '\\' in name or '\0' in name: fail(f'invalid critical source path: {name!r}')
 relative=PurePosixPath(name)
 if relative.is_absolute() or relative.as_posix()!=name or any(part in {'','.','..'} for part in relative.parts): fail(f'invalid critical source path: {name!r}')
 return relative
def direct_source(root,name,maximum_bytes=MAX_CRITICAL_SOURCE_BYTES):
 relative=canonical_relative(name); nofollow=getattr(os,'O_NOFOLLOW',0); cloexec=getattr(os,'O_CLOEXEC',0); directory_flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|nofollow|cloexec
 opened=[]; descriptor=None
 try:
  parent=os.open(root,directory_flags); opened.append(parent)
  for component in relative.parts[:-1]: parent=os.open(component,directory_flags,dir_fd=parent); opened.append(parent)
  descriptor=os.open(relative.parts[-1],os.O_RDONLY|nofollow|cloexec,dir_fd=parent); before=os.fstat(descriptor); mode=stat.S_IMODE(before.st_mode)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: fail(f'critical source is not a direct single-link regular file: {name}')
  if before.st_uid!=os.geteuid() or mode&(stat.S_ISUID|stat.S_ISGID|stat.S_ISVTX|0o022): fail(f'critical source has unsafe owner or mode: {name}')
  if before.st_size<1 or before.st_size>maximum_bytes: fail(f'critical source size is outside publication bounds: {name}')
  payload=bytearray()
  while len(payload)<=maximum_bytes:
   chunk=os.read(descriptor,min(65536,maximum_bytes+1-len(payload)))
   if not chunk: break
   payload.extend(chunk)
  if len(payload)!=before.st_size: fail(f'critical source changed or exceeded publication bounds: {name}')
  after=os.fstat(descriptor); path_after=os.stat(relative.parts[-1],dir_fd=parent,follow_symlinks=False)
  identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
  if identity(before)!=identity(after) or (path_after.st_dev,path_after.st_ino)!=(before.st_dev,before.st_ino): fail(f'critical source changed while inspected: {name}')
  return bytes(payload),mode
 except OSError as error:
  if error.errno in {errno.ELOOP,errno.EMLINK,errno.ENOTDIR}: fail(f'critical source path is indirect: {name}')
  fail(f'critical source cannot be opened directly: {name}: {error}')
 finally:
  if descriptor is not None: os.close(descriptor)
  for item in reversed(opened): os.close(item)
def validate_source(root,name):
 relative=canonical_relative(name); suffix=Path(relative.name).suffix.lower()
 if relative.name.lower() in SECRET_NAMES or suffix in SECRET_SUFFIXES: fail(f'secret-bearing filename is forbidden in critical publication: {name}')
 payload,mode=direct_source(root,name)
 if payload.startswith(ARCHIVE_MAGICS) or b'\0' in payload: fail(f'generated/binary artifact is forbidden in critical publication: {name}')
 if mode&0o111 and not payload.startswith(b'#!'): fail(f'critical executable lacks a script shebang: {name}')
 for pattern in SECRET_PATTERNS:
  if pattern.search(payload): fail(f'probable secret material is forbidden in critical publication: {name}')
 return payload
def resolve_js_dependency(root,source_name,specifier):
 base=posixpath.normpath(posixpath.join(posixpath.dirname(source_name),specifier))
 if base=='..' or base.startswith('../') or base.startswith('/'): fail(f'local import escapes publication root: {source_name}: {specifier}')
 candidates=[base] if PurePosixPath(base).suffix else [base+'.mjs',base+'.js',base+'/index.mjs',base+'/index.js']
 existing=[]
 for candidate in candidates:
  try: direct_source(root,candidate); existing.append(candidate)
  except SystemExit as error:
   if 'cannot be opened directly' not in str(error): raise
 if len(existing)!=1: fail(f'local import does not resolve uniquely: {source_name}: {specifier}')
 return existing[0]
def local_dependencies(root,name,payload):
 text=payload.decode('utf-8')
 dependencies=set()
 if PurePosixPath(name).suffix in {'.js','.mjs','.cjs','.py','.sh'}:
  for candidate in LOCAL_PATH_REFERENCE.findall(text):
   try: direct_source(root,candidate)
   except SystemExit as error:
    if 'cannot be opened directly' in str(error): continue
    raise
   dependencies.add(candidate)
 if PurePosixPath(name).suffix in {'.js','.mjs','.cjs'}:
  # Directory URLs are runtime roots, not JavaScript module dependencies.  Treating
  # `new URL('../..', import.meta.url)` as a module produced the invalid synthetic
  # candidate `./index.mjs` and made the global inventory checker reject a valid
  # source without improving closure coverage.
  runtime_specifiers=JS_REQUIRE_LOCAL.findall(text)+[item for item in JS_URL_LOCAL.findall(text) if PurePosixPath(item).suffix]
  dependencies.update(resolve_js_dependency(root,name,specifier) for specifier in JS_LOCAL_IMPORT.findall(text)+runtime_specifiers)
 if PurePosixPath(name).suffix=='.sh':
  dependencies.update(SHELL_PROJECT_SOURCE.findall(text))
  for specifier in SHELL_RELATIVE_SOURCE.findall(text):
   dependency=posixpath.normpath(posixpath.join(posixpath.dirname(name),specifier))
   if dependency=='..' or dependency.startswith('../'): fail(f'sourced shell dependency escapes publication root: {name}: {specifier}')
   direct_source(root,dependency); dependencies.add(dependency)
 if PurePosixPath(name).suffix=='.py':
  tree=ast.parse(text,filename=name)
  for node in ast.walk(tree):
   modules=[]
   if isinstance(node,ast.Import): modules=[alias.name for alias in node.names]
   elif isinstance(node,ast.ImportFrom) and node.module: modules=[('.'*node.level)+node.module]
   for module in modules:
    if module.startswith('.'):
     level=len(module)-len(module.lstrip('.')); base=posixpath.dirname(name)
     for _ in range(max(0,level-1)): base=posixpath.dirname(base)
     candidate=posixpath.join(base,module.lstrip('.').replace('.','/'))+'.py'
    else:
     candidates=[posixpath.join(posixpath.dirname(name),module.replace('.','/')+'.py'),module.replace('.','/')+'.py']; candidate=None
     for possible in candidates:
      try: direct_source(root,possible); candidate=possible; break
      except SystemExit as error:
       if 'cannot be opened directly' not in str(error): raise
     if candidate is None: continue
    if module.startswith('.'):
     try: direct_source(root,candidate)
     except SystemExit as error:
      if 'cannot be opened directly' in str(error): continue
      raise
    dependencies.add(candidate)
 return dependencies
def has_dynamic_execution(name,payload):
 text=payload.decode('utf-8'); suffix=PurePosixPath(name).suffix
 if suffix in {'.js','.mjs','.cjs'}: return bool(JS_DYNAMIC_EXECUTION.search(text))
 if suffix=='.py':
  for node in ast.walk(ast.parse(text,filename=name)):
   if not isinstance(node,ast.Call): continue
   function=node.func
   if isinstance(function,ast.Attribute) and isinstance(function.value,ast.Name) and function.value.id=='subprocess' and function.attr in {'run','Popen','check_output','check_call','call'}: return True
 return False
def verify_dynamic_allowlist(payloads,dynamic):
 detected=sorted(name for name,payload in payloads.items() if has_dynamic_execution(name,payload))
 if list(dynamic)!=sorted(dynamic) or set(dynamic)!=set(detected) or any(not isinstance(reason,str) or len(reason)<32 for reason in dynamic.values()): fail(f'dynamic execution allowlist mismatch: detected={detected}, allowlisted={sorted(dynamic)}')
def verify_local_closure(root,required,payloads,runtime_inputs=()):
 required_set=set(required); runtime_input_set=set(runtime_inputs); missing={}; referenced_runtime_inputs=set()
 for name,payload in payloads.items():
  dependencies=local_dependencies(root,name,payload); referenced_runtime_inputs.update(dependencies&runtime_input_set)
  absent=sorted(dependencies-required_set-runtime_input_set)
  if absent: missing[name]=absent
 if missing: fail(f'critical local dependency graph is incomplete: {json.dumps(missing,sort_keys=True)}')
 if runtime_input_set-referenced_runtime_inputs: fail(f'unreferenced excluded runtime input: {sorted(runtime_input_set-referenced_runtime_inputs)}')
def verify_repository_pins(repository_root,external):
 expected,compile_environment=derive_cargo_source_closure(repository_root)
 if set(external)!=expected: fail(f'repository Cargo closure pin set mismatch: missing={sorted(expected-set(external))}, extra={sorted(set(external)-expected)}')
 verify_hash_pins(repository_root,external)
 return compile_environment
def verify_hash_pins(repository_root,external):
 if list(external)!=sorted(external) or any(not re.fullmatch(r'[0-9a-f]{64}',digest) for digest in external.values()): fail('repository critical source pins are unordered or invalid')
 for name,expected_digest in external.items():
  payload=validate_source(repository_root,name) if PurePosixPath(name).suffix in {'.rs','.toml'} or name=='Cargo.lock' else direct_source(repository_root,name,MAX_CARGO_RESOURCE_BYTES)[0]
  if hashlib.sha256(payload).hexdigest()!=expected_digest: fail(f'repository critical source differs from pinned inventory: {name}')
def verify_second_pass(root,required,payloads):
 second={name:validate_source(root,name) for name in required}
 if second!=payloads: fail('critical source snapshot changed between descriptor-bound passes')
def derive_cargo_source_closure(repository_root):
 root_manifest=tomllib.loads(direct_source(repository_root,'Cargo.toml')[0].decode('utf-8')); workspace=root_manifest.get('workspace',{}).get('dependencies',{})
 manifests=set(); queue=['crates/dom-usdom-checkpoint-proof-host/Cargo.toml']
 while queue:
  name=queue.pop(); canonical_relative(name)
  if name in manifests: continue
  manifests.add(name); manifest=tomllib.loads(direct_source(repository_root,name)[0].decode('utf-8')); base=posixpath.dirname(name)
  for section in ('dependencies','build-dependencies','dev-dependencies'):
   for dependency,specification in manifest.get(section,{}).items():
    inherited=isinstance(specification,dict) and specification.get('workspace') is True
    specification=workspace.get(dependency,{}) if inherited else specification
    if isinstance(specification,dict) and 'path' in specification:
     origin='' if inherited else base; child=posixpath.normpath(posixpath.join(origin,specification['path'],'Cargo.toml'))
     if child=='..' or child.startswith('../') or child.startswith('/'): fail(f'Cargo path dependency escapes repository: {name}: {dependency}')
     direct_source(repository_root,child); queue.append(child)
 closure={'Cargo.toml','Cargo.lock','rust-toolchain.toml',*manifests}; rust_sources=set(); crate_roots={posixpath.dirname(item) for item in manifests}
 for manifest in manifests:
  crate=repository_root/posixpath.dirname(manifest)
  for base,directories,files in os.walk(crate,followlinks=False):
   directories[:]=[item for item in directories if item not in {'target','.git'} and not ((Path(base)/item/'Cargo.toml').is_file() and (Path(base)/item).resolve()!=crate.resolve())]
   for filename in files:
    path=Path(base)/filename
    if path.suffix=='.rs': rust_sources.add(path.relative_to(repository_root).as_posix())
 closure.update(rust_sources); compile_environment=set()
 include_any=re.compile(r'include_(?:bytes|str)!\s*\('); include_literal=re.compile(r'include_(?:bytes|str)!\s*\(\s*"([^"\r\n]+)"\s*\)',re.S); env_literal=re.compile(r'(?:option_)?env!\s*\(\s*"([^"\r\n]+)"\s*\)'); path_literal=re.compile(r'"([^"\r\n]+\.(?:json|hex|txt|bin|elf|iid|toml))"'); rerun_literal=re.compile(r'cargo:rerun-if-changed=([^\s"\\]+)'); manifest_join=re.compile(r'env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*\)\s*\.join\(\s*"([^"\r\n]+)"')
 for source in rust_sources:
  payload=direct_source(repository_root,source)[0].decode('utf-8'); literals=include_literal.findall(payload)
  if len(include_any.findall(payload))!=len(literals): fail(f'dynamic Rust include resource is forbidden: {source}')
  compile_environment.update(env_literal.findall(payload)); source_directory=posixpath.dirname(source); crate_root=max((root for root in crate_roots if source==root or source.startswith(root+'/')),key=len)
  resources=[posixpath.normpath(posixpath.join(source_directory,item)) for item in literals]
  resources.extend(posixpath.normpath(posixpath.join(crate_root,item)) for item in rerun_literal.findall(payload))
  for item in path_literal.findall(payload):
   candidates=[posixpath.normpath(posixpath.join(source_directory,item)),posixpath.normpath(posixpath.join(crate_root,item))]
   for candidate in candidates:
    try: direct_source(repository_root,candidate,MAX_CARGO_RESOURCE_BYTES)
    except SystemExit as error:
     if 'cannot be opened directly' in str(error): continue
     raise
    resources.append(candidate); break
  for relative_directory in manifest_join.findall(payload):
   directory=(repository_root/crate_root/relative_directory).resolve()
   if not directory.is_relative_to(repository_root) or not directory.is_dir(): fail(f'dynamic Cargo manifest resource directory is invalid: {source}')
   for base,directories,files in os.walk(directory,followlinks=False):
    directories[:]=[item for item in directories if item not in {'target','.git'}]
    resources.extend((Path(base)/filename).relative_to(repository_root).as_posix() for filename in files)
  for resource in resources:
   if resource=='..' or resource.startswith('../') or resource.startswith('/'): fail(f'Rust resource escapes repository: {source}: {resource}')
   direct_source(repository_root,resource,MAX_CARGO_RESOURCE_BYTES); closure.add(resource)
 return closure,compile_environment
def load_inventory(root=ROOT,inventory_path=INVENTORY):
 try: inventory_name=inventory_path.relative_to(root).as_posix()
 except ValueError: fail('critical inventory path escapes publication root')
 inventory_payload=validate_source(root,inventory_name)
 inventory=strict_json_bytes(inventory_payload,'critical inventory')
 if set(inventory)!={'schema','criticalSources','runtimeInputsExcludedFromSourceManifest','repositoryCriticalSources','cargoCompileEnvironmentAllowlist','dynamicExecutionAllowlist','forbiddenPublicationPrefixes'} or inventory['schema']!='usdom-critical-publication-inventory-v2': fail('invalid critical inventory schema')
 required=inventory['criticalSources']; runtime_inputs=inventory['runtimeInputsExcludedFromSourceManifest']; forbidden=inventory['forbiddenPublicationPrefixes']
 if required!=sorted(set(required)): fail('critical inventory is unordered or duplicate')
 if runtime_inputs!=sorted(set(runtime_inputs)) or set(required)&set(runtime_inputs): fail('excluded runtime input inventory is unordered, duplicate or overlaps critical sources')
 for name in runtime_inputs:
  canonical_relative(name)
  if not name.startswith('config/') or not name.endswith('.json'): fail(f'excluded runtime input is outside the configuration boundary: {name}')
 for name in required:
  canonical_relative(name)
  if any(name==prefix.rstrip('/') or name.startswith(prefix) for prefix in forbidden): fail('critical inventory includes generated evidence')
 payloads={name:(inventory_payload if name==inventory_name else validate_source(root,name)) for name in required}; verify_local_closure(root,required,payloads,runtime_inputs)
 verify_dynamic_allowlist(payloads,inventory['dynamicExecutionAllowlist'])
 compile_environment=verify_repository_pins(root.parents[1],inventory['repositoryCriticalSources']); environment_allowlist=inventory['cargoCompileEnvironmentAllowlist']
 if list(environment_allowlist)!=sorted(environment_allowlist) or set(environment_allowlist)!=compile_environment or any(not isinstance(reason,str) or len(reason)<32 for reason in environment_allowlist.values()): fail(f'Cargo compile environment allowlist mismatch: detected={sorted(compile_environment)}, allowlisted={sorted(environment_allowlist)}')
 verify_second_pass(root,required,payloads)
 return required,payloads,runtime_inputs
def self_test():
 with tempfile.TemporaryDirectory() as directory:
  root=Path(directory); (root/'scripts').mkdir(); good=root/'scripts/good.sh'; good.write_text('#!/bin/sh\nexit 0\n'); good.chmod(0o700); validate_source(root,'scripts/good.sh')
  cases=[('../escape',b'text\n',0o600,'invalid critical source path'),('scripts/binary',b'\x7fELFpayload',0o600,'generated/binary artifact'),('scripts/no-shebang',b'exit 0\n',0o700,'lacks a script shebang'),('scripts/key.txt',b'-----BEGIN '+b'PRIVATE KEY-----\n',0o600,'probable secret material'),('scripts/huge',b'x'*(MAX_CRITICAL_SOURCE_BYTES+1),0o600,'outside publication bounds')]
  for name,payload,mode,expected in cases:
   if not name.startswith('..'): target=root/name; target.write_bytes(payload); target.chmod(mode)
   try: validate_source(root,name)
   except SystemExit as error: assert expected in str(error),(expected,str(error))
   else: raise AssertionError(f'expected rejection: {name}')
  (root/'sdk').mkdir(); helper=root/'sdk/helper.mjs'; helper.write_text('export const value=1;\n')
  entry=root/'scripts/entry.mjs'; entry.write_text("import {value} from '../sdk/helper.mjs';\n")
  entry_payload=validate_source(root,'scripts/entry.mjs'); helper_payload=validate_source(root,'sdk/helper.mjs')
  try: verify_local_closure(root,['scripts/entry.mjs'],{'scripts/entry.mjs':entry_payload})
  except SystemExit as error: assert 'dependency graph is incomplete' in str(error)
  else: raise AssertionError('expected omitted local dependency rejection')
  verify_local_closure(root,['scripts/entry.mjs','sdk/helper.mjs'],{'scripts/entry.mjs':entry_payload,'sdk/helper.mjs':helper_payload})
  helper.write_text('export const value=2;\n')
  try: verify_second_pass(root,['scripts/entry.mjs','sdk/helper.mjs'],{'scripts/entry.mjs':entry_payload,'sdk/helper.mjs':helper_payload})
  except SystemExit as error: assert 'snapshot changed' in str(error)
  else: raise AssertionError('expected post-read critical source mutation rejection')
  helper.write_text('export const value=1;\n')
  for runtime_source in ("const x=require('../sdk/helper.mjs');\n","const x=require.resolve('../sdk/helper.mjs');\n","const x=new URL('../sdk/helper.mjs',import.meta.url);\n"):
   runtime_entry=root/'scripts/runtime-entry.mjs'; runtime_entry.write_text(runtime_source); runtime_payload=validate_source(root,'scripts/runtime-entry.mjs')
   try: verify_local_closure(root,['scripts/runtime-entry.mjs'],{'scripts/runtime-entry.mjs':runtime_payload})
   except SystemExit as error: assert 'dependency graph is incomplete' in str(error)
   else: raise AssertionError('expected omitted runtime-loaded JS dependency rejection')
  config=root/'config'; config.mkdir(); template=config/'template.json'; template.write_text('{}\n'); runner=root/'scripts/runner.mjs'; runner.write_text("const path='config/template.json';\nspawn(command,args);\n")
  runner_payload=validate_source(root,'scripts/runner.mjs')
  try: verify_local_closure(root,['scripts/runner.mjs'],{'scripts/runner.mjs':runner_payload})
  except SystemExit as error: assert 'config/template.json' in str(error)
  else: raise AssertionError('expected omitted executed/config dependency rejection')
  try: verify_dynamic_allowlist({'scripts/runner.mjs':runner_payload},{})
  except SystemExit as error: assert 'dynamic execution allowlist mismatch' in str(error)
  else: raise AssertionError('expected unallowlisted dynamic execution rejection')
  runtime=config/'operator-runtime.json'; runtime.write_text('{}\n'); runtime_runner=root/'scripts/runtime-runner.mjs'; runtime_runner.write_text("const path='config/operator-runtime.json';\n")
  runtime_payload=validate_source(root,'scripts/runtime-runner.mjs')
  verify_local_closure(root,['scripts/runtime-runner.mjs'],{'scripts/runtime-runner.mjs':runtime_payload},['config/operator-runtime.json'])
  try: verify_local_closure(root,['scripts/runtime-runner.mjs'],{'scripts/runtime-runner.mjs':runtime_payload},['config/operator-runtime.json','config/stale-runtime.json'])
  except SystemExit as error: assert 'unreferenced excluded runtime input' in str(error)
  else: raise AssertionError('expected stale excluded runtime input rejection')
  python_helper=root/'scripts/helper.py'; python_helper.write_text('VALUE=1\n'); python_entry=root/'scripts/entry.py'; python_entry.write_text('import scripts.helper\n')
  python_payload=validate_source(root,'scripts/entry.py')
  try: verify_local_closure(root,['scripts/entry.py'],{'scripts/entry.py':python_payload})
  except SystemExit as error: assert 'scripts/helper.py' in str(error)
  else: raise AssertionError('expected omitted Python dependency rejection')
  try: verify_hash_pins(root,{'sdk/helper.mjs':'0'*64})
  except SystemExit as error: assert 'differs from pinned inventory' in str(error)
  else: raise AssertionError('expected changed repository source rejection')
  try: strict_json_bytes(b'{"schema":1,"schema":2}','test inventory')
  except SystemExit as error: assert 'duplicate JSON key' in str(error)
  else: raise AssertionError('expected duplicate JSON inventory rejection')
  duplicate_manifest=b'0'*64+b'  scripts/good.sh\n'+b'1'*64+b'  scripts/good.sh\n'
  try: parse_source_manifest(duplicate_manifest)
  except SystemExit as error: assert 'duplicate source manifest path' in str(error)
  else: raise AssertionError('expected duplicate source manifest rejection')
  cargo=root/'cargo'; (cargo/'crates/dom-usdom-checkpoint-proof-host/src').mkdir(parents=True); (cargo/'crates/helper/src').mkdir(parents=True)
  (cargo/'Cargo.toml').write_text('[workspace]\nmembers=["crates/dom-usdom-checkpoint-proof-host","crates/helper"]\n[workspace.dependencies]\nhelper={path="crates/helper"}\n')
  (cargo/'Cargo.lock').write_text('# lock\n'); (cargo/'crates/dom-usdom-checkpoint-proof-host/Cargo.toml').write_text('[package]\nname="host"\nversion="0.1.0"\n[dependencies]\nhelper.workspace=true\n'); cargo_library=cargo/'crates/dom-usdom-checkpoint-proof-host/src/lib.rs'; cargo_library.write_text('const DATA:&[u8]=include_bytes!("fixture.bin");\nconst VERSION:&str=env!("CARGO_PKG_VERSION");\n'); (cargo/'crates/dom-usdom-checkpoint-proof-host/src/fixture.bin').write_bytes(b'fixture'); (cargo/'crates/helper/Cargo.toml').write_text('[package]\nname="helper"\nversion="0.1.0"\n'); (cargo/'crates/helper/src/lib.rs').write_text('pub fn helper(){}\n')
  cargo_closure,cargo_environment=derive_cargo_source_closure(cargo)
  assert 'crates/helper/Cargo.toml' in cargo_closure and 'crates/helper/src/lib.rs' in cargo_closure and 'crates/dom-usdom-checkpoint-proof-host/src/fixture.bin' in cargo_closure and 'Cargo.lock' in cargo_closure
  assert cargo_environment=={'CARGO_PKG_VERSION'}
  cargo_library.write_text('const DATA:&[u8]=include_bytes!(concat!("fixture",".bin"));\n')
  try: derive_cargo_source_closure(cargo)
  except SystemExit as error: assert 'dynamic Rust include resource is forbidden' in str(error)
  else: raise AssertionError('expected dynamic Rust resource rejection')
 print('PASS: publication boundary adversarial self-test')
def main():
 if sys.argv[1:]==['--self-test']: self_test(); return
 if sys.argv[1:] not in ([],['--inventory-only']): fail('usage: check-rebuild-v3-publication-boundary.py [--inventory-only|--self-test]')
 required,payloads,runtime_inputs=load_inventory(); source=payloads['scripts/source-manifest.py'].decode('utf-8')
 policy=load_policy(payloads['config/verify-rebuild-receipt-build-policy.json'].decode('utf-8')); host=tomllib.loads(direct_source(ROOT.parents[1],'crates/dom-usdom-checkpoint-proof-host/Cargo.toml')[0].decode('utf-8')); bins={item['name']:item for item in host.get('bin',[])}
 inventory=strict_json_bytes(payloads['config/rebuild-v3-critical-source-inventory.json'],'critical inventory'); closure_commitment=hashlib.sha256(json.dumps(inventory['repositoryCriticalSources'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if policy['sourceClosureSha256']!=closure_commitment: fail('verify-only build policy source closure commitment is stale')
 risc0=host.get('dependencies',{}).get('risc0-zkvm',{}); bincode=host.get('dependencies',{}).get('bincode',{})
 if host.get('features',{}).get('default')!=[] or host.get('features',{}).get('verify')!=['dep:bincode','dep:risc0-zkvm'] or host.get('features',{}).get('prove')!=['verify','risc0-zkvm/client','risc0-zkvm/prove'] or bins.get(policy['binary'],{}).get('required-features')!=['verify'] or risc0!={'version':'=3.0.6','default-features':False,'features':['std','disable-dev-mode'],'optional':True} or bincode!={'workspace':True,'optional':True}: fail('verify-only Cargo feature graph differs from reviewed minimum')
 workspace=tomllib.loads(direct_source(ROOT.parents[1],'Cargo.toml')[0].decode('utf-8')); toolchain=tomllib.loads(direct_source(ROOT.parents[1],'rust-toolchain.toml')[0].decode('utf-8'))
 if workspace.get('workspace',{}).get('resolver')!='2' or toolchain.get('toolchain',{}).get('channel')!=policy['rustcVersion']: fail('verify-only resolver/toolchain selection differs from policy')
 for key in ('cargo','rustc'):
  path=Path(policy[key+'Path']); payload=direct_source(Path('/'),path.relative_to('/').as_posix(),MAX_CARGO_RESOURCE_BYTES)[0]
  if hashlib.sha256(payload).hexdigest()!=policy[key+'Sha256']: fail(f'verify-only {key} executable differs from policy pin')
 for config in (ROOT.parents[1]/'.cargo/config',ROOT.parents[1]/'.cargo/config.toml'):
  if config.exists(): fail('repository Cargo config override is forbidden for verify-only build')
 cargo_home=Path(policy['requiredEnvironment']['CARGO_HOME'])
 for config in (cargo_home/'config',cargo_home/'config.toml'):
  if config.exists(): fail('isolated verify-only CARGO_HOME contains a config override')
 for token in ['"evidence"','"out"','top.startswith("results-stage")','top == "results"']:
  if token not in source: fail(f'source manifest no longer excludes generated publication class {token}')
 if sys.argv[1:]==['--inventory-only']:
  print(f'PASS: {len(required)} critical publication sources are direct, bounded, secret-free and inventory-bound'); return
 entries=parse_source_manifest(validate_source(ROOT,'MANIFEST.sha256'))
 for name in runtime_inputs:
  if name in entries: fail(f'operator runtime input leaked into source manifest: {name}')
 for name,payload in payloads.items():
  if entries.get(name)!=hashlib.sha256(payload).hexdigest(): fail(f'critical source missing or differs from source manifest: {name}')
 print(f'PASS: {len(required)} critical sources are safely and uniquely bound; generated artifacts/evidence excluded')
if __name__=='__main__': main()

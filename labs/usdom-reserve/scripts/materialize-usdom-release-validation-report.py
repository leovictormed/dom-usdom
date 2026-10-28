#!/usr/bin/python3
"""Authenticate three supervised release vectors and publish one release-bound report."""
import argparse, datetime as dt, hashlib, json, os, re, stat, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from durable_create_once import install_create_once

H64=re.compile(r"[0-9a-f]{64}\Z"); COMMIT=re.compile(r"[0-9a-f]{40}\Z")
TAG=re.compile(r"usdom-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z")
IDENT=re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
KINDS=("checkpoint390","randomxCache","nativePrivacy")
EXPECTED={
 "checkpoint390":("dom-usdom-checkpoint-program","full_360_plus_30_v2_checkpoint_extension_is_recomputed",
  "test full_360_plus_30_v2_checkpoint_extension_is_recomputed ... ok"),
 "randomxCache":("dom-usdom-randomx-portable","dataset::tests::upstream_randomx_argon2d_cache_vector_matches",
  "test dataset::tests::upstream_randomx_argon2d_cache_vector_matches ... ok"),
 "nativePrivacy":("dom-usdom-privacy","phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs",
  "test phase1::tests::production_specialization_matches_real_prover_and_all_public_inputs ... ok"),
}
COMMON_INPUTS={"Cargo.toml","Cargo.lock","rust-toolchain.toml",
 "labs/usdom-reserve/config/mainnet-toolchain-lock.json"}
KIND_INPUTS={
 "checkpoint390":{
  "crates/dom-usdom-checkpoint-program/Cargo.toml",
  "crates/dom-usdom-checkpoint-program/src/economic_chunks.rs",
  "crates/dom-usdom-checkpoint-program/src/lib.rs",
  "crates/dom-usdom-checkpoint-program/src/outer.rs",
  "crates/dom-usdom-checkpoint-program/src/portable.rs",
  "crates/dom-usdom-checkpoint-program/src/reference.rs",
  "crates/dom-usdom-checkpoint-program/src/source.rs",
  "crates/dom-usdom-checkpoint-program/src/sync_attestation.rs",
  "crates/dom-usdom-checkpoint-program/tests/v2_checkpoint_extension.rs",
  "crates/dom-usdom-checkpoint-statement/Cargo.toml",
  "crates/dom-usdom-checkpoint-statement/src/lib.rs",
  "crates/dom-usdom-state/Cargo.toml","crates/dom-usdom-state/src/lib.rs",
  "crates/dom-usdom-state/src/sparse.rs"},
 "randomxCache":{
  "crates/dom-usdom-randomx-portable/Cargo.toml",
  "crates/dom-usdom-randomx-portable/src/bytecode.rs",
  "crates/dom-usdom-randomx-portable/src/dataset.rs",
  "crates/dom-usdom-randomx-portable/src/lib.rs",
  "crates/dom-usdom-randomx-portable/src/superscalar.rs"},
 "nativePrivacy":{
  "crates/dom-usdom-privacy/Cargo.toml","crates/dom-usdom-privacy/MANIFEST.sha256",
  "crates/dom-usdom-privacy/src/circuit.rs","crates/dom-usdom-privacy/src/ceremony.rs",
  "crates/dom-usdom-privacy/src/lib.rs","crates/dom-usdom-privacy/src/phase1.rs",
  "crates/dom-usdom-privacy/src/verifier.rs"},
}
BAD_EVENTS={"resource-limit","bound-input-drift","required-output-mismatch","supervisor-signal",
 "child-start-refused-after-signal","termination-grace-expired","stray-descendants",
 "stray-descendants-killed","stray-child-process-group","stray-child-process-group-killed"}

def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def strict(raw):
 def pairs(items):
  out={}
  for k,v in items:
   if k in out: raise ValueError(f"duplicate JSON key: {k}")
   out[k]=v
  return out
 return json.loads(raw.decode("utf-8","strict"),object_pairs_hook=pairs)
def read_direct(path,maximum,private=False):
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd); out=bytearray()
 try:
  if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid()
      or before.st_size<1 or before.st_size>maximum or private and before.st_mode&0o077):
   raise ValueError(f"unsafe evidence file: {path}")
  while len(out)<=maximum:
   part=os.read(fd,min(65536,maximum+1-len(out)))
   if not part: break
   out.extend(part)
  after=os.fstat(fd)
 finally: os.close(fd)
 if len(out)>maximum or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
  raise ValueError(f"evidence changed or exceeded its bound: {path}")
 return bytes(out)
def record(path,maximum,keys,schema,private=False):
 raw=read_direct(path,maximum,private); value=strict(raw)
 if not isinstance(value,dict) or set(value)!=set(keys) or value.get("schema")!=schema or canonical(value)!=raw:
  raise ValueError(f"invalid canonical record: {path}")
 return value,hashlib.sha256(raw).hexdigest()
def private_dir(path):
 info=path.lstat()
 if path.is_symlink() or path.resolve(strict=True)!=path or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
  raise ValueError(f"unsafe private directory: {path}")
def digest(path,maximum=64*1024*1024): return hashlib.sha256(read_direct(path,maximum)).hexdigest()
def iso(value):
 if not isinstance(value,str) or not value.endswith("Z"): raise ValueError("invalid UTC timestamp")
 return dt.datetime.fromisoformat(value[:-1]+"+00:00")
def write_new_or_equal(path,raw):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 install_create_once(path,raw,mode=0o600,maximum=4*1024*1024,
                     private_parent=True,allow_equal=True)

def authenticate(kind,run_id,jobs,state,repo,identity,cargo,rustc):
 if not H64.fullmatch(run_id): raise ValueError(f"invalid {kind} run ID")
 job,job_sha=record(jobs/f"{run_id}.json",1024*1024,
  {"schema","nonce","createdUnix","argv","cwd","executableSha256","environment","inputs","limits","requiredOutput"},
  "usdom-supervised-proof-command-v2",True)
 if job_sha!=run_id or job["cwd"]!=str(repo) or job["executableSha256"]!=cargo["sha256"] or job["argv"][0]!=cargo["realpath"]:
  raise ValueError(f"{kind} command identity mismatch")
 environment=job["environment"]
 expected_environment={"CARGO_HOME":str(Path.home()/".cargo"),"RUSTUP_HOME":str(Path.home()/".rustup"),
  "RUSTC":rustc["realpath"],"CARGO_TARGET_DIR":str(Path.home()/".local/state/usdom-proof/target-release-validation"),
  "CARGO_INCREMENTAL":"0","USDOM_RELEASE_ID":identity["releaseId"],
  "USDOM_SOURCE_COMMIT":identity["sourceCommit"],"USDOM_SOURCE_TAG":identity["sourceTag"]}
 if not isinstance(environment,dict) or set(environment)!=set(expected_environment):
  raise ValueError(f"{kind} environment schema mismatch")
 for key,value in expected_environment.items():
  if environment.get(key)!=value: raise ValueError(f"{kind} release/toolchain environment mismatch")
 package,test,success=EXPECTED[kind]; argv=job["argv"]
 middle={
  "checkpoint390":["-p",package,"--features","host-reference","--test","v2_checkpoint_extension",test],
  "randomxCache":["-p",package,test],
  "nativePrivacy":["-p",package,test],
 }[kind]
 expected_argv=[cargo["realpath"],"test","--profile","release-validation","--locked","--offline","-j1",*middle,
                "--","--exact","--ignored","--nocapture","--test-threads=1"]
 if argv!=expected_argv: raise ValueError(f"{kind} command selection mismatch")
 expected_result="test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"
 if job["requiredOutput"]!=[success,expected_result]: raise ValueError(f"{kind} output policy mismatch")
 inputs=job["inputs"]
 if not isinstance(inputs,list) or not inputs: raise ValueError(f"{kind} inputs are absent")
 seen=set()
 for item in inputs:
  if not isinstance(item,dict) or set(item)!={"path","sha256","maxBytes"}: raise ValueError(f"{kind} input schema invalid")
  relative=Path(item["path"])
  if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in seen: raise ValueError(f"{kind} input path invalid")
  if not H64.fullmatch(str(item["sha256"])) or not isinstance(item["maxBytes"],int) or not 1<=item["maxBytes"]<=64*1024*1024:
   raise ValueError(f"{kind} input bound invalid")
  seen.add(relative.as_posix()); target=repo/relative
  if target.resolve(strict=True)!=target or digest(target,item["maxBytes"])!=item["sha256"]: raise ValueError(f"{kind} input drift: {relative}")
 expected_inputs=COMMON_INPUTS|KIND_INPUTS[kind]
 if seen!=expected_inputs:
  raise ValueError(f"{kind} input closure mismatch: missing={sorted(expected_inputs-seen)} extra={sorted(seen-expected_inputs)}")
 expected_limits={"maxLogBytes":67108864,"maxRuntimeSeconds":14400 if kind=="randomxCache" else 43200,
                  "minFreeBytes":21474836480}
 if job["limits"]!=expected_limits: raise ValueError(f"{kind} resource policy mismatch")
 run_dir=state/"runs"/run_id; private_dir(run_dir)
 run,run_sha=record(run_dir/"run.json",1024*1024,
  {"schema","runId","commandManifestSha256","runnerPid","runnerStartTicks","startedAt","bootId","systemdInvocationId","supervisorSha256","supervisorPath"},
  "usdom-supervised-proof-run-v1",True)
 terminal,terminal_sha=record(run_dir/"terminal.json",1024*1024,
  {"schema","runId","runSha256","processLogSha256","eventsSha256","finishedAt","exitStatus","childSignal","supervisorSignal","signalSender","stopRequestSha256"},
  "usdom-supervised-proof-terminal-v1",True)
 log=read_direct(run_dir/"process.log",job["limits"]["maxLogBytes"],True); events_raw=read_direct(run_dir/"events.jsonl",64*1024*1024,True)
 if run["runId"]!=run_id or run["commandManifestSha256"]!=run_id or terminal["runId"]!=run_id or terminal["runSha256"]!=run_sha:
  raise ValueError(f"{kind} run/terminal binding mismatch")
 expected_supervisor=repo/"labs/usdom-reserve/scripts/run-supervised-long-proof.py"
 if (not H64.fullmatch(str(run["supervisorSha256"])) or run["supervisorPath"]!=str(expected_supervisor)
     or digest(expected_supervisor,2*1024*1024)!=run["supervisorSha256"]
     or not isinstance(run["runnerPid"],int) or run["runnerPid"]<=1
     or not isinstance(run["runnerStartTicks"],str) or not run["runnerStartTicks"].isdigit()
     or not re.fullmatch(r"[0-9a-f]{32}",str(run["systemdInvocationId"]))):
  raise ValueError(f"{kind} supervisor/systemd identity mismatch")
 if terminal["processLogSha256"]!=hashlib.sha256(log).hexdigest() or terminal["eventsSha256"]!=hashlib.sha256(events_raw).hexdigest():
  raise ValueError(f"{kind} log/event authentication mismatch")
 if terminal["exitStatus"]!=0 or terminal["childSignal"] is not None or terminal["supervisorSignal"] is not None or terminal["stopRequestSha256"] is not None:
  raise ValueError(f"{kind} did not complete uninterrupted")
 if terminal["signalSender"] is not None: raise ValueError(f"{kind} contains unexpected signal attribution")
 if iso(terminal["finishedAt"])<iso(run["startedAt"]): raise ValueError(f"{kind} terminal predates start")
 text=log.decode("utf-8","strict")
 if "\0" in text or any(text.count(marker)!=1 for marker in job["requiredOutput"]): raise ValueError(f"{kind} output is truncated or ambiguous")
 lines=events_raw.decode("utf-8","strict").splitlines()
 if not lines or not events_raw.endswith(b"\n"): raise ValueError(f"{kind} events are truncated")
 events=[]
 for line in lines:
  raw_line=(line+"\n").encode(); entry=strict(raw_line)
  if canonical(entry)!=raw_line: raise ValueError(f"{kind} event is noncanonical")
  events.append(entry)
 names=[entry.get("event") for entry in events]
 if names!=["runner-started","child-started","runner-terminal"]:
  raise ValueError(f"{kind} event history is incomplete or failed")
 runner_event,child_event,terminal_event=events
 if (set(runner_event)!={"at","event","runnerPid","systemdInvocationId"}
     or runner_event["runnerPid"]!=run["runnerPid"]
     or runner_event["systemdInvocationId"]!=run["systemdInvocationId"]
     or set(child_event)!={"at","event","childPid","childStartTicks"}
     or not isinstance(child_event["childPid"],int) or child_event["childPid"]<=1
     or not isinstance(child_event["childStartTicks"],str) or not child_event["childStartTicks"].isdigit()
     or set(terminal_event)!={"at","event","exitStatus","childSignal","supervisorSignal","stopRequestSha256"}
     or terminal_event["exitStatus"]!=terminal["exitStatus"]
     or terminal_event["childSignal"]!=terminal["childSignal"]
     or terminal_event["supervisorSignal"]!=terminal["supervisorSignal"]
     or terminal_event["stopRequestSha256"]!=terminal["stopRequestSha256"]):
  raise ValueError(f"{kind} event schema or run binding is invalid")
 event_times=[iso(entry["at"]) for entry in events]
 if not (iso(run["startedAt"])<=event_times[0]<=event_times[1]<=event_times[2]<=iso(terminal["finishedAt"])):
  raise ValueError(f"{kind} event chronology is invalid")
 return {"kind":kind,"runId":run_id,"commandManifestSha256":job_sha,"runSha256":run_sha,
  "terminalSha256":terminal_sha,"processLogSha256":terminal["processLogSha256"],"eventsSha256":terminal["eventsSha256"],
  "supervisorSha256":run["supervisorSha256"],"startedAt":run["startedAt"],"finishedAt":terminal["finishedAt"]}

def main():
 p=argparse.ArgumentParser(); p.add_argument("--repository",type=Path,required=True); p.add_argument("--jobs-directory",type=Path,required=True)
 p.add_argument("--state-root",type=Path,required=True); p.add_argument("--release-evidence",type=Path,required=True); p.add_argument("--output",type=Path,required=True)
 for kind in KINDS: p.add_argument(f"--{kind}-run-id",required=True)
 a=p.parse_args(); repo=a.repository
 if not repo.is_absolute() or repo.resolve(strict=True)!=repo: raise ValueError("repository must be canonical and absolute")
 private_dir(a.jobs_directory); private_dir(a.state_root); private_dir(a.state_root/"runs")
 evidence,_=record(a.release_evidence,4*1024*1024,set(strict(read_direct(a.release_evidence,4*1024*1024)).keys()),1)
 identity={key:evidence.get(key) for key in ("releaseId","sourceCommit","sourceTag")}
 if not IDENT.fullmatch(identity["releaseId"] or "") or not COMMIT.fullmatch(identity["sourceCommit"] or "") or not TAG.fullmatch(identity["sourceTag"] or ""):
  raise ValueError("release identity is incomplete")
 lock_raw=read_direct(repo/"labs/usdom-reserve/config/mainnet-toolchain-lock.json",1024*1024); lock=strict(lock_raw)
 tools={item.get("name"):item for item in lock.get("executables",[]) if isinstance(item,dict)}
 cargo,rustc=tools.get("cargo"),tools.get("rustc")
 if not cargo or not rustc or digest(Path(cargo["realpath"]),1024*1024*1024)!=cargo["sha256"] or digest(Path(rustc["realpath"]),1024*1024*1024)!=rustc["sha256"]:
  raise ValueError("cargo/rustc toolchain identity mismatch")
 ids={kind:getattr(a,f"{kind}_run_id") for kind in KINDS}
 if len(set(ids.values()))!=3: raise ValueError("release-vector run IDs must be distinct")
 runs=[authenticate(kind,ids[kind],a.jobs_directory,a.state_root,repo,identity,cargo,rustc) for kind in KINDS]
 if len({run["supervisorSha256"] for run in runs})!=1: raise ValueError("release vectors used different supervisor generations")
 report={"schema":"usdom-release-validation-report/v1","status":"passed","releaseId":identity["releaseId"],
  "sourceCommit":identity["sourceCommit"],"sourceTag":identity["sourceTag"],
  "toolchainLockSha256":hashlib.sha256(lock_raw).hexdigest(),"cargoLockSha256":digest(repo/"Cargo.lock",64*1024*1024),"runs":runs}
 write_new_or_equal(a.output,canonical(report)); print(hashlib.sha256(canonical(report)).hexdigest())
if __name__=="__main__":
 try: main()
 except Exception as error: print(f"release-vector materialization refused: {error}",file=sys.stderr); raise SystemExit(125)

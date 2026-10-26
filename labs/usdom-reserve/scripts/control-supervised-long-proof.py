#!/usr/bin/python3
"""Fail-closed status/stop control for a user-scoped supervised proof unit."""

import argparse, datetime as dt, hashlib, json, os, re, signal, stat, subprocess, sys
from pathlib import Path

RUN_ID = re.compile(r"[0-9a-f]{64}\Z")

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def strict_json(raw):
    def pairs(items):
        value={}
        for key,item in items:
            if key in value: raise ValueError(f"duplicate JSON key: {key}")
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs)

def process_start_ticks(pid):
    text=Path(f"/proc/{pid}/stat").read_text()
    return text[text.rfind(")")+2:].split()[19]

def direct_record(path, maximum, fields, schema):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd)
    try:
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid()
                or before.st_size>maximum): raise ValueError(f"unsafe record: {path}")
        chunks=[]; total=0
        while True:
            part=os.read(fd,min(65536,maximum+1-total))
            if not part: break
            chunks.append(part); total+=len(part)
            if total>maximum: raise ValueError(f"oversized record: {path}")
        after=os.fstat(fd)
    finally: os.close(fd)
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise ValueError(f"record changed while reading: {path}")
    raw=b"".join(chunks); value=strict_json(raw.decode("utf-8","strict"))
    if not isinstance(value,dict) or set(value)!=set(fields) or value.get("schema")!=schema or canonical(value)!=raw:
        raise ValueError(f"invalid canonical record: {path}")
    return value,hashlib.sha256(raw).hexdigest()

def direct_hash(path, maximum):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd); digest=hashlib.sha256(); total=0
    try:
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid()
                or before.st_size>maximum): raise ValueError(f"unsafe evidence file: {path}")
        while True:
            part=os.read(fd,min(1024*1024,maximum+1-total))
            if not part: break
            total+=len(part)
            if total>maximum: raise ValueError(f"oversized evidence file: {path}")
            digest.update(part)
        after=os.fstat(fd)
    finally: os.close(fd)
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise ValueError(f"evidence file changed while hashing: {path}")
    return digest.hexdigest()

def write_all(fd,data):
    view=memoryview(data)
    while view:
        try: written=os.write(fd,view)
        except InterruptedError: continue
        if written<=0: raise OSError("short write while publishing stop request")
        view=view[written:]

def private_directory(path):
    if not path.is_absolute() or path.resolve(strict=True)!=path or path.is_symlink():
        raise ValueError(f"unsafe state directory: {path}")
    info=path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise ValueError(f"state directory is not private: {path}")

def unit_show(unit):
    proc = subprocess.run(["/usr/bin/systemctl", "--user", "show", unit,
        "--no-pager", "--property=ActiveState,SubState,MainPID,InvocationID,Result,ExecMainStatus"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env={"HOME":str(Path.home()),"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"})
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or "systemctl show failed")
    return dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)

def durable_request(path, value):
    temporary=path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    try:
        write_all(fd,canonical(value)); os.fsync(fd)
    except Exception:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    finally: os.close(fd)
    try: os.link(temporary,path,follow_symlinks=False)
    finally: os.unlink(temporary)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(dfd)
    finally: os.close(dfd)

def adjacent(cmdline,key,value):
    needle=key.encode(); expected=value.encode()
    return any(cmdline[index:index+2]==[needle,expected] for index in range(len(cmdline)-1))

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("action",choices=("status","stop"))
    parser.add_argument("--state-root",required=True); parser.add_argument("--run-id",required=True)
    args=parser.parse_args()
    if not RUN_ID.fullmatch(args.run_id): raise ValueError("invalid run-id")
    unit=f"usdom-proof@{args.run_id}.service"; state=unit_show(unit)
    state_root=Path(args.state_root)
    private_directory(state_root); private_directory(state_root/"runs")
    run_dir=state_root/"runs"/args.run_id
    run_present=(run_dir/"run.json").is_file(); terminal_present=(run_dir/"terminal.json").is_file()
    run=None; run_sha=None; terminal=None
    if run_present:
        private_directory(run_dir)
        run,run_sha=direct_record(run_dir/"run.json",1024*1024,
            {"schema","runId","commandManifestSha256","runnerPid","runnerStartTicks","startedAt","bootId","systemdInvocationId","supervisorSha256","supervisorPath"},
            "usdom-supervised-proof-run-v1")
        if (run["runId"]!=args.run_id or not RUN_ID.fullmatch(str(run["commandManifestSha256"]))
                or not RUN_ID.fullmatch(str(run["supervisorSha256"]))
                or not isinstance(run["supervisorPath"],str) or not Path(run["supervisorPath"]).is_absolute()
                or not isinstance(run["runnerPid"],int) or run["runnerPid"]<=1
                or not isinstance(run["runnerStartTicks"],str) or not run["runnerStartTicks"].isdigit()
                or not isinstance(run["startedAt"],str) or not run["startedAt"].endswith("Z")
                or not isinstance(run["bootId"],str) or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",run["bootId"])
                or run["systemdInvocationId"] is not None and not re.fullmatch(r"[0-9a-f]{32}",str(run["systemdInvocationId"]))):
            raise ValueError("run identity fields are invalid")
    if terminal_present:
        if run is None: raise ValueError("terminal exists without authenticated run")
        terminal,_=direct_record(run_dir/"terminal.json",1024*1024,
            {"schema","runId","runSha256","processLogSha256","eventsSha256","finishedAt","exitStatus","childSignal","supervisorSignal","signalSender","stopRequestSha256"},
            "usdom-supervised-proof-terminal-v1")
        if terminal["runId"]!=args.run_id or terminal["runSha256"]!=run_sha:
            raise ValueError("terminal does not bind the authenticated run")
        if (not isinstance(terminal["finishedAt"],str) or not terminal["finishedAt"].endswith("Z")
                or not isinstance(terminal["exitStatus"],int) or not 0<=terminal["exitStatus"]<=255
                or terminal["childSignal"] is not None and not re.fullmatch(r"SIG[A-Z0-9]+",str(terminal["childSignal"]))
                or terminal["supervisorSignal"] is not None and not re.fullmatch(r"SIG(?:TERM|INT|HUP)",str(terminal["supervisorSignal"]))
                or terminal["signalSender"] is not None and not isinstance(terminal["signalSender"],str)
                or not RUN_ID.fullmatch(str(terminal["processLogSha256"]))
                or not RUN_ID.fullmatch(str(terminal["eventsSha256"]))
                or terminal["processLogSha256"] != direct_hash(run_dir / "process.log", 1024 * 1024 * 1024)
                or terminal["eventsSha256"] != direct_hash(run_dir / "events.jsonl", 64 * 1024 * 1024)
                or terminal["stopRequestSha256"] is not None and not RUN_ID.fullmatch(str(terminal["stopRequestSha256"]))):
            raise ValueError("terminal identity fields are invalid")
    active=state.get("ActiveState") in ("active","activating")
    process_authenticated=False
    cmdline=[]
    if active and run is not None and state.get("MainPID","").isdigit() and int(state["MainPID"])>1:
        pid=int(state["MainPID"])
        try:
            cmdline=Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            expected_manifest=str(Path.home()/".config/usdom-proof/jobs"/f"{args.run_id}.json")
            process_authenticated=(pid==run["runnerPid"]
                and process_start_ticks(pid)==run["runnerStartTicks"]
                and Path("/proc/sys/kernel/random/boot_id").read_text().strip()==run["bootId"]
                and state.get("InvocationID")==run["systemdInvocationId"]
                and len(cmdline)>1 and cmdline[1].decode("utf-8","strict")==run["supervisorPath"]
                and adjacent(cmdline,"--run-id",args.run_id)
                and adjacent(cmdline,"--state-root",str(state_root))
                and adjacent(cmdline,"--command-manifest",expected_manifest)
                and adjacent(cmdline,"--expected-supervisor-sha256",run["supervisorSha256"]))
        except (FileNotFoundError,ProcessLookupError,PermissionError):
            process_authenticated=False
    report={"schema":"usdom-proof-service-status-v1","runId":args.run_id,"unit":unit,
            "unitState":state,"runPresent":run_present,"runAuthenticated":run is not None,
            "terminalPresent":terminal_present,"terminalAuthenticated":terminal is not None,
            "activeProcessAuthenticated":process_authenticated}
    if args.action=="status": print(canonical(report).decode(),end=""); return 0
    if not active or not process_authenticated:
        raise RuntimeError("refusing stop: exact active process identity is not authenticated")
    durable_request(run_dir/"stop-request.json", {"schema":"usdom-proof-stop-request-v1",
        "runId":args.run_id,"requestedAt":dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z"),
        "requestingUid":os.getuid(),"requestingPid":os.getpid(),"unitInvocationId":run["systemdInvocationId"]})
    proc=subprocess.run(["/usr/bin/systemctl","--user","stop",unit],check=False,
        env={"HOME":str(Path.home()),"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"})
    return proc.returncode

if __name__=="__main__":
    try: raise SystemExit(main())
    except Exception as error:
        print(f"proof control refused: {error}",file=sys.stderr); raise SystemExit(125)

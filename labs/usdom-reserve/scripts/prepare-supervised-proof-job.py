#!/usr/bin/python3
"""Create a one-use canonical proof command manifest and print its run ID."""
import argparse, hashlib, json, os, re, secrets, stat, sys, time
from pathlib import Path

ENV_NAME=re.compile(r"[A-Z_][A-Z0-9_]{0,63}\Z")
DENIED_ENV={"PATH","PYTHONPATH","PYTHONHOME","BASH_ENV","ENV","CDPATH","GLOBIGNORE"}
DENIED_PREFIXES=("LD_","DYLD_")

def canonical(v): return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def write_all(fd,data):
    view=memoryview(data)
    while view:
        try: written=os.write(fd,view)
        except InterruptedError: continue
        if written<=0: raise OSError("short write while publishing proof job")
        view=view[written:]
def hash_file(path):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd); digest=hashlib.sha256()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>1024*1024*1024
            or before.st_mode&(stat.S_ISUID|stat.S_ISGID)): raise ValueError("unsafe executable")
    try:
        while True:
            part=os.read(fd,1024*1024)
            if not part: break
            digest.update(part)
        after=os.fstat(fd)
    finally: os.close(fd)
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): raise ValueError("executable changed while hashing")
    return digest.hexdigest()
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--jobs-directory",default=str(Path.home()/".config/usdom-proof/jobs")); parser.add_argument("--cwd",required=True); parser.add_argument("--env",action="append",default=[])
    parser.add_argument("--bind-input",action="append",default=[]); parser.add_argument("--require-output",action="append",default=[])
    parser.add_argument("--max-runtime-seconds",type=int); parser.add_argument("--max-log-bytes",type=int); parser.add_argument("--min-free-bytes",type=int)
    parser.add_argument("argv",nargs=argparse.REMAINDER)
    args=parser.parse_args(); argv=args.argv[1:] if args.argv[:1]==["--"] else args.argv
    if not argv or not Path(argv[0]).is_absolute(): raise ValueError("command after -- must start with an absolute executable")
    environment={}
    for item in args.env:
        key,separator,value=item.partition("=")
        if not separator or key in environment: raise ValueError("each --env must be unique NAME=value")
        environment[key]=value
    for key,value in environment.items():
        if (not ENV_NAME.fullmatch(key) or key in DENIED_ENV or key.startswith(DENIED_PREFIXES)
                or "\0" in value or len(value)>65536): raise ValueError(f"unsafe environment entry: {key}")
    cwd_path=Path(args.cwd)
    if not cwd_path.is_absolute() or cwd_path.resolve(strict=True)!=cwd_path or not cwd_path.is_dir():
        raise ValueError("cwd must be an absolute canonical directory")
    cwd=str(cwd_path); spec={"argv":argv,"createdUnix":int(time.time()),"cwd":cwd,"environment":environment,"executableSha256":hash_file(argv[0]),"nonce":secrets.token_hex(16),"schema":"usdom-supervised-proof-command-v1"}
    v2_requested=bool(args.bind_input or args.require_output or args.max_runtime_seconds is not None or args.max_log_bytes is not None or args.min_free_bytes is not None)
    if v2_requested:
        if (not args.bind_input or not args.require_output or args.max_runtime_seconds is None
                or args.max_log_bytes is None or args.min_free_bytes is None):
            raise ValueError("v2 jobs require bound inputs, output assertions and all resource limits")
        inputs=[]; seen=set()
        for name in args.bind_input:
            relative=Path(name)
            if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in seen:
                raise ValueError("bound inputs must be unique canonical relative paths")
            target=cwd_path/relative; info=target.lstat()
            if (target.resolve(strict=True)!=target or not target.is_file() or target.is_symlink()
                    or info.st_nlink!=1 or info.st_size<=0 or info.st_size>64*1024*1024):
                raise ValueError(f"unsafe bound input: {name}")
            seen.add(relative.as_posix()); inputs.append({"maxBytes":info.st_size,"path":relative.as_posix(),"sha256":hash_file(target)})
        spec.update({"inputs":inputs,"limits":{"maxLogBytes":args.max_log_bytes,"maxRuntimeSeconds":args.max_runtime_seconds,"minFreeBytes":args.min_free_bytes},"requiredOutput":args.require_output,"schema":"usdom-supervised-proof-command-v2"})
    raw=canonical(spec); run_id=hashlib.sha256(raw).hexdigest(); directory=Path(args.jobs_directory)
    if not directory.is_absolute(): raise ValueError("jobs directory must be absolute")
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    if directory.resolve(strict=True)!=directory or directory.is_symlink(): raise ValueError("jobs directory is indirect")
    info=directory.stat()
    if info.st_uid!=os.getuid() or info.st_mode&0o077: raise ValueError("jobs directory is not private")
    parent_fd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    target=directory/f"{run_id}.json"
    temporary=directory/f".{run_id}.{os.getpid()}.tmp"
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o400)
    try:
        write_all(fd,raw); os.fsync(fd)
    except Exception:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    finally: os.close(fd)
    try: os.link(temporary,target,follow_symlinks=False)
    finally: os.unlink(temporary)
    dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try: os.fsync(dfd)
    finally: os.close(dfd)
    print(run_id)
if __name__=="__main__":
    try: main()
    except Exception as error:
        print(f"job preparation refused: {error}",file=sys.stderr); raise SystemExit(125)

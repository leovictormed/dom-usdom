#!/usr/bin/python3
"""Materialize the user service with the canonical absolute repository path."""
import argparse, hashlib, os, re, stat, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from durable_create_once import install_create_once

def write_all(fd,data):
    view=memoryview(data)
    while view:
        try: written=os.write(fd,view)
        except InterruptedError: continue
        if written<=0: raise OSError("short write while installing proof service")
        view=view[written:]

def direct_file(path):
    info=path.lstat()
    return path.is_file() and not path.is_symlink() and info.st_nlink==1 and info.st_uid==os.getuid()

def direct_bytes(path,maximum=2*1024*1024):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd)
    try:
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>maximum: raise ValueError(f"unsafe service source: {path}")
        data=bytearray()
        while len(data)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(data)))
            if not part: break
            data.extend(part)
        after=os.fstat(fd)
    finally: os.close(fd)
    if len(data)>maximum or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
        raise ValueError(f"service source changed or is oversized: {path}")
    return bytes(data)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--repository")
    args=parser.parse_args()
    requested=Path(args.repository) if args.repository else Path(__file__).resolve().parents[3]
    repository=requested.resolve(strict=True)
    if args.repository and (not requested.is_absolute() or repository!=requested or requested.is_symlink()):
        raise ValueError("repository must be an absolute canonical direct path")
    template=repository/"labs/usdom-reserve/systemd/usdom-proof@.service.in"
    runner=repository/"labs/usdom-reserve/scripts/run-supervised-long-proof.py"
    if not direct_file(template) or not direct_file(runner) or re.search(r'[\x00-\x20"\\%]',str(repository)):
        raise ValueError("invalid repository or missing service sources")
    runner_sha=hashlib.sha256(direct_bytes(runner)).hexdigest()
    rendered=direct_bytes(template).decode("utf-8","strict").replace("@REPOSITORY@",str(repository)).replace("@SUPERVISOR_SHA256@",runner_sha)
    if "@REPOSITORY@" in rendered or "@SUPERVISOR_SHA256@" in rendered:
        raise ValueError("unresolved repository placeholder")
    target=Path.home()/".config/systemd/user/usdom-proof@.service"
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    parent=target.parent
    parent_info=parent.lstat()
    if parent.is_symlink() or parent.resolve(strict=True)!=parent or parent_info.st_uid!=os.getuid() or parent_info.st_mode&0o022:
        raise ValueError("systemd user-unit directory is writable by another identity or indirect")
    with tempfile.NamedTemporaryFile(mode="w",prefix="usdom-proof-",suffix=".service",delete=True) as check:
        check.write(rendered); check.flush()
        subprocess.run(["/usr/bin/systemd-analyze","--user","verify",check.name],check=True)
    install_create_once(target,rendered.encode(),mode=0o600,maximum=2*1024*1024,
                        private_parent=False,allow_equal=True)
    subprocess.run(["/usr/bin/systemctl","--user","daemon-reload"],check=True,
        env={"HOME":str(Path.home()),"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8"})
    print(target)
if __name__=="__main__":
    try: main()
    except Exception as error:
        print(f"service installation refused: {error}",file=sys.stderr); raise SystemExit(125)

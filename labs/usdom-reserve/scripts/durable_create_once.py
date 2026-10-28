"""Descriptor-bound, crash-recoverable create-once file publication."""
import hashlib, os, re, secrets, signal, stat
from pathlib import Path

MAX_ORPHANS = 64

def _identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,
            value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)

def _alive(pid):
    try: os.kill(pid,0); return True
    except ProcessLookupError: return False

def _read(fd,maximum):
    chunks=[]; size=0
    while True:
        chunk=os.read(fd,min(1024*1024,maximum+1-size))
        if not chunk: return b''.join(chunks)
        chunks.append(chunk); size+=len(chunk)
        if size>maximum: raise ValueError('durable file exceeds its size bound')

def install_create_once(path,data,*,mode=0o600,maximum=16*1024*1024,
                        private_parent=True,allow_equal=False,fault_injection=None):
    path=Path(path)
    if not path.is_absolute() or not data or len(data)>maximum:
        raise ValueError('invalid durable create-once request')
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    temporary=None; target_fd=None
    try:
        parent_before=os.fstat(parent); uid=os.getuid()
        if (not stat.S_ISDIR(parent_before.st_mode) or parent_before.st_uid!=uid
                or parent_before.st_mode&0o022
                or private_parent and stat.S_IMODE(parent_before.st_mode)!=0o700
                or os.path.realpath(f'/proc/self/fd/{parent}')!=str(path.parent)):
            raise ValueError('durable parent directory is unsafe')
        if fault_injection: fault_injection('after-parent-validation')
        escaped=re.escape(path.name)
        pattern=re.compile(rf'^\.{escaped}\.([1-9][0-9]*)\.([0-9a-f]{{24}})\.tmp$')
        orphans=sorted(name for name in os.listdir(parent) if pattern.fullmatch(name))
        if len(orphans)>MAX_ORPHANS: raise ValueError('too many durable temporary files')
        changed=False
        for name in orphans:
            pid=int(pattern.fullmatch(name).group(1))
            if _alive(pid): continue
            info=os.stat(name,dir_fd=parent,follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=uid
                    or info.st_nlink not in (1,2) or stat.S_IMODE(info.st_mode)!=mode
                    or info.st_size<1 or info.st_size>maximum):
                raise ValueError('durable temporary file is unsafe')
            if info.st_nlink==2:
                try: named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:
                    raise ValueError('durable temporary hardlink has no target')
                if ((named.st_dev,named.st_ino)!=(info.st_dev,info.st_ino)
                        or named.st_nlink!=2 or not stat.S_ISREG(named.st_mode)
                        or named.st_uid!=uid or stat.S_IMODE(named.st_mode)!=mode):
                    raise ValueError('durable temporary hardlink is not the target')
            os.unlink(name,dir_fd=parent); changed=True
        if changed: os.fsync(parent)
        try:
            target_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        except FileNotFoundError: target_fd=None
        if target_fd is not None:
            before=os.fstat(target_fd); installed=_read(target_fd,maximum); after=os.fstat(target_fd)
            named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or before.st_nlink!=1
                    or stat.S_IMODE(before.st_mode)!=mode or _identity(before)!=_identity(after)
                    or (before.st_dev,before.st_ino)!=(named.st_dev,named.st_ino)):
                raise ValueError('durable target is unsafe')
            if fault_injection: fault_injection('after-existing-target-validation')
            named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            if (before.st_dev,before.st_ino)!=(named.st_dev,named.st_ino):
                raise ValueError('durable target changed after validation')
            if allow_equal and installed==data: return
            raise FileExistsError(f'durable target already exists: {path}')
        temporary=f'.{path.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp'
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                   mode,dir_fd=parent)
        try:
            view=memoryview(data)
            while view:
                count=os.write(fd,view)
                if count<=0: raise OSError('short durable write')
                view=view[count:]
            os.fchmod(fd,mode); os.fsync(fd)
        finally: os.close(fd)
        fault=os.environ.get('USDOM_TEST_DURABLE_CREATE_ONCE_FAULT')
        if fault:
            if not str(path.parent).startswith('/tmp/usdom-') or fault not in ('after-temporary-fsync','after-create-once-link'):
                raise ValueError('invalid durable fault injection')
            if fault=='after-temporary-fsync': os.kill(os.getpid(),signal.SIGKILL)
        os.link(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        if fault=='after-create-once-link': os.kill(os.getpid(),signal.SIGKILL)
        os.unlink(temporary,dir_fd=parent); temporary=None; os.fsync(parent)
        target_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        installed=_read(target_fd,maximum); final=os.fstat(target_fd)
        named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        if (not stat.S_ISREG(final.st_mode) or final.st_uid!=uid or final.st_nlink!=1
                or stat.S_IMODE(final.st_mode)!=mode or installed!=data
                or (final.st_dev,final.st_ino)!=(named.st_dev,named.st_ino)):
            raise ValueError('durable installed target is invalid')
        named_parent=os.stat(path.parent,follow_symlinks=False)
        if (named_parent.st_dev,named_parent.st_ino,named_parent.st_mode,named_parent.st_uid)!=(
                parent_before.st_dev,parent_before.st_ino,parent_before.st_mode,parent_before.st_uid):
            raise ValueError('durable parent changed during publication')
    finally:
        if target_fd is not None: os.close(target_fd)
        if temporary is not None:
            try: os.unlink(temporary,dir_fd=parent); os.fsync(parent)
            except FileNotFoundError: pass
        os.close(parent)

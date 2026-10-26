#!/usr/bin/env python3
"""Install a reviewed Cargo binary as one exclusive, durable single-link executable."""
import argparse,hashlib,os,secrets,stat,sys
from pathlib import Path
from rebuild_v3_build_policy import load_policy,verify_attestation
H64=__import__('re').compile(r'[0-9a-f]{64}'); MAX=128*1024*1024
def fail(x): raise ValueError(x)
def control(path,expected,label):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid() or before.st_size<=0 or before.st_size>1024*1024 or before.st_mode&0o022: fail(f'{label} is not a direct owner-controlled file')
  data=os.read(fd,1024*1024+1);after=os.fstat(fd)
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or len(data)!=before.st_size or hashlib.sha256(data).hexdigest()!=expected: fail(f'{label} differs from reviewed hash')
  return data
 finally:os.close(fd)
def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--expected-sha256',required=True);p.add_argument('--build-policy',type=Path,required=True);p.add_argument('--expected-build-policy-sha256',required=True);p.add_argument('--build-attestation',type=Path,required=True);p.add_argument('--expected-build-attestation-sha256',required=True);p.add_argument('--destination',type=Path,required=True);a=p.parse_args()
 if not all(H64.fullmatch(value or '') for value in (a.expected_sha256,a.expected_build_policy_sha256,a.expected_build_attestation_sha256)): fail('expected SHA-256 is malformed')
 policy=load_policy(control(a.build_policy,a.expected_build_policy_sha256,'build policy').decode());attestation=control(a.build_attestation,a.expected_build_attestation_sha256,'build attestation').decode()
 source=os.open(a.source,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(source)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or not before.st_mode&0o100 or before.st_size<=0 or before.st_size>MAX or before.st_mode&0o022: fail('source is not an eligible owner-controlled Cargo executable')
  data=b''
  while len(data)<=MAX:
   chunk=os.read(source,min(1024*1024,MAX+1-len(data)))
   if not chunk: break
   data+=chunk
  after=os.fstat(source)
  identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_nlink,x.st_mtime_ns,x.st_ctime_ns)
  if identity(before)!=identity(after) or len(data)!=before.st_size or hashlib.sha256(data).hexdigest()!=a.expected_sha256: fail('Cargo executable changed or differs from reviewed hash')
 finally: os.close(source)
 verify_attestation(attestation,policy,a.expected_build_policy_sha256,a.expected_sha256,len(data))
 parent_path=a.destination.parent or Path('.'); parent=os.open(parent_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 temporary=f'.{a.destination.name}.{secrets.token_hex(16)}.tmp'
 try:
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
  try:
   written=0
   while written<len(data):
    count=os.write(fd,data[written:])
    if count<=0: fail('short write while installing verifier')
    written+=count
   os.fsync(fd);os.fchmod(fd,0o500);os.fsync(fd)
  finally:os.close(fd)
  os.link(temporary,a.destination.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
  os.unlink(temporary,dir_fd=parent);os.fsync(parent)
  installed=os.stat(a.destination.name,dir_fd=parent,follow_symlinks=False)
  if not stat.S_ISREG(installed.st_mode) or installed.st_nlink!=1 or stat.S_IMODE(installed.st_mode)!=0o500: fail('installed verifier identity is invalid')
 finally:
  try: os.unlink(temporary,dir_fd=parent)
  except FileNotFoundError: pass
  os.close(parent)
 print(a.expected_sha256)
if __name__=='__main__':
 try: main()
 except (OSError,ValueError) as e: print(f'verifier installation failed: {e}',file=sys.stderr);raise SystemExit(1)

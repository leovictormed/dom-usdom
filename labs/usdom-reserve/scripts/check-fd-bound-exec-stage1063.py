#!/usr/bin/env python3
from pathlib import Path
r=Path(__file__).resolve().parents[3]
c=(r/'labs/usdom-reserve/tools/usdom-fd-exec.c').read_text()
for x in ('SYS_openat2','RESOLVE_BENEATH','RESOLVE_NO_SYMLINKS','RESOLVE_NO_MAGICLINKS','RESOLVE_NO_XDEV','SYS_execveat','AT_EMPTY_PATH','EVP_sha256','SYS_memfd_create','F_ADD_SEALS','F_SEAL_WRITE','PR_SET_NO_NEW_PRIVS'):
    assert x in c,x
for n in ('prepare-native-receiving-wallet.sh','drill-closed-mainnet-wallet-recovery.sh'):
    assert 'usdom-fd-exec' in (r/'labs/usdom-reserve/scripts'/n).read_text()
print('stage1063 fd-bound exec gate: PASS')

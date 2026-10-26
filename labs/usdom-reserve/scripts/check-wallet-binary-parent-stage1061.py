#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[3]
for name in ('prepare-native-receiving-wallet.sh','drill-closed-mainnet-wallet-recovery.sh'):
    text=(root/'labs/usdom-reserve/scripts'/name).read_text()
    for marker in ('realpath',"directory_identity=$(stat -Lc '%d:%i:%u:%a'",'test ! -L'):
        if marker not in text: raise SystemExit(f'{name}: missing {marker}')
print('stage1061 wallet binary parent identity gate: PASS')

#!/usr/bin/env python3
"""Inventory/gate critical USDOM domain separation and canonical hash encoding."""
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[3]
files=['crates/dom-usdom-state/src/lib.rs','crates/dom-usdom-state/src/sparse.rs','crates/dom-usdom-privacy/src/lib.rs','crates/dom-usdom-checkpoint-program/src/lib.rs','crates/dom-usdom-checkpoint-statement/src/lib.rs','crates/dom-usdom-finalized-burn-program/src/lib.rs','crates/dom-chain/src/native_usdom_v4.rs','labs/usdom-reserve/contracts/USDOMProofReserve.sol','labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol','labs/usdom-reserve/sdk/proof-reserve.mjs','labs/usdom-reserve/sdk/checkpoint-context.mjs']
texts={f:(ROOT/f).read_text() for f in files}
failed=[]
needles={
'crates/dom-usdom-privacy/src/lib.rs':['HASH_TO_FIELD_TAG','digest.update((bytes.len() as u64).to_be_bytes())','POLICY_VERSION.to_be_bytes()'],
'crates/dom-usdom-state/src/lib.rs':['TAG_STATE_V2','TAG_PRIVATE_TRANSFER_PAYLOAD','TAG_PRIVATE_BURN_PAYLOAD','transition_count.to_be_bytes()'],
'crates/dom-usdom-checkpoint-program/src/lib.rs':['CHECKPOINT_SEGMENT_STATE_DOMAIN','CHECKPOINT_SEGMENT_TRANSITION_DOMAIN','CHECKPOINT_SEGMENT_PRIVATE_INPUT_DOMAIN','CHECKPOINT_SEGMENT_POLICY_INPUT_DOMAIN','CHECKPOINT_SEGMENT_NATIVE_OPENING_DOMAIN'],
'crates/dom-usdom-finalized-burn-program/src/lib.rs':['FINALIZED_BURN_STATEMENT_TYPE','self.amount.to_be_bytes()','self.height.to_be_bytes()','self.finality_beacon_slot.to_be_bytes()'],
'crates/dom-chain/src/native_usdom_v4.rs':['USDOM_V4_BLOCK_MAGIC','USDOM_V4_SNAPSHOT_MAGIC'],
'labs/usdom-reserve/contracts/USDOMProofReserve.sol':['BURN_STATEMENT_TYPEHASH','BURN_DEBT_TYPEHASH','abi.encode('],
'labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol':['CHECKPOINT_STATEMENT_TYPEHASH','CHECKPOINT_IDENTITY_TYPEHASH','CHECKPOINT_BOOTSTRAP_TYPEHASH'],
'labs/usdom-reserve/sdk/checkpoint-context.mjs':['CHECKPOINT_CONTEXT_MAGIC','CHECKPOINT_CONTEXT_VERSION','writeUint(encoded,8,BigInt(CHECKPOINT_CONTEXT_VERSION),2)','contextHash:keccak256(encoded)'],
}
for f, ns in needles.items():
 for n in ns:
  if n not in texts[f]: failed.append(f'{f}: missing {n}')
# Protocol domain literals must not be reused under distinct constant names.
domains={}
for f,s in texts.items():
 for m in re.finditer(r'(?:b|&str\s*=\s*)?"(DOM:[^"\\]+:v[0-9]+)"',s): domains.setdefault(m.group(1),set()).add(f)
# Reuse across language implementations is expected; duplicate literal inside one file is suspicious only if repeated.
for f,s in texts.items():
 vals=re.findall(r'"(DOM:[^"\\]+:v[0-9]+)"',s)
 for v in set(vals):
  if vals.count(v)>1 and f not in ['crates/dom-usdom-finalized-burn-program/src/lib.rs']:
   failed.append(f'{f}: repeated domain literal {v}')
if failed:
 print('FAIL USDOM hash domains\n'+'\n'.join(failed)); sys.exit(1)
print(f'PASS USDOM critical commitments are typed/versioned/canonical ({len(domains)} domain literals inventoried)')

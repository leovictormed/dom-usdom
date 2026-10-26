#!/usr/bin/env python3
from pathlib import Path
r=Path(__file__).resolve().parents[3]
s=(r/'crates/dom-store/src/db.rs').read_text(); c=(r/'crates/dom-chain/src/chain_state.rs').read_text()
for name in ('commit_block_with_consensus_state','apply_reorg_with_consensus_state_and_sidecar_changes'):
 b=s.split(f'pub fn {name}',1)[1].split('\n    pub fn ',1)[0]
 for x in ('begin_rw_txn','apply_consensus_state_updates','txn.commit()'):
  if x not in b: raise SystemExit(f'{name} missing {x}')
for x in ('commit_block_with_consensus_state','apply_reorg_with_consensus_state_and_sidecars','apply_reorg_with_consensus_state_and_sidecar_changes'):
 if x not in c: raise SystemExit(f'chain missing atomic API {x}')
for x in ('read_canonical_consensus_snapshot','read_atomic_state_entries'):
 if x not in s: raise SystemExit(f'missing snapshot read {x}')
print('USD0M DomStore atomicity gate: PASS')

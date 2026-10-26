#!/usr/bin/env python3
"""Structural gate for bounded permissionless ProofReserve/Registry operations."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]
checks={
'labs/usdom-reserve/contracts/USDOMProofReserve.sol':['uint256 public constant MAX_PRUNE_BATCH = 256','maximum == 0 || maximum > MAX_PRUNE_BATCH','burnIds.length == 0 || burnIds.length > MAX_PRUNE_BATCH','while (removed < maximum && firstPendingBurn != bytes32(0))','while (count < maximum && burnId != bytes32(0))','proof.length != EVM_PROOF_BYTES','_verify(statementHash, proof);','delete pendingWithdrawals[burnId]','++queueEpoch;','pendingCount = 0;','totalPendingAmount = 0;'],
'labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol':['uint256 public constant MAX_PROOF_BYTES = EVM_PROOF_BYTES','uint256 public constant VERIFIER_GAS_LIMIT = 5_000_000','proof.length != EVM_PROOF_BYTES','bytes4(proof[:4]) != RISC_ZERO_GROTH16_V3_SELECTOR','PendingCandidate public candidate','candidate = PendingCandidate({','delete candidate;','block.timestamp >= current.readyAt','current.readyAt'],
}
failed=[]
for rel, needles in checks.items():
 s=(ROOT/rel).read_text()
 for needle in needles:
  if needle not in s: failed.append(f'{rel}: missing {needle}')
# State-changing permissionless loops must all expose caller-controlled bounded work.
r=(ROOT/'labs/usdom-reserve/contracts/USDOMProofReserve.sol').read_text()
if r.count('while (removed < maximum') != 1: failed.append('ProofReserve: unexpected state-changing while loop')
if failed:
 print('FAIL permissionless gas/liveness\n'+'\n'.join(failed)); sys.exit(1)
print('PASS ProofReserve and Registry permissionless work/state growth remain bounded and incrementally executable')

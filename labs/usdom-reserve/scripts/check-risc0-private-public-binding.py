#!/usr/bin/env python3
"""Structural gate for complete private-input -> RISC0 journal -> Solidity binding."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]
checks={
 'crates/dom-usdom-finalized-burn-risc0-guest/src/main.rs':['execute_with_checkpoint_assumption(&input)','checkpoint.image_id()','checkpoint.journal().as_slice()','env::commit_slice(execution.output().as_bytes())'],
 'crates/dom-usdom-finalized-burn-program/src/lib.rs':['if checkpoint_end != bytes.len()','input.to_bytes()?.as_slice() != bytes','output.as_bytes() != input.statement_hash.as_bytes()','image_id: CHECKPOINT_OUTER_IMAGE_ID','FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)'],
 'crates/dom-usdom-checkpoint-segment-risc0-guest/src/main.rs':['execute_checkpoint_segment_portable(&transition, &private_input, &policy, &opening)','env::commit_slice(&executed.transition_commitment())'],
 'crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs':['validate_checkpoint_outer_chain(&statement, &chain, &policy, &opening, SEGMENT_IMAGE_ID)','env::commit_slice(&executed.statement_hash())'],
 'crates/dom-usdom-checkpoint-program/src/lib.rs':['if cursor != bytes.len()','input.to_bytes()?.as_slice() != bytes','input_commitment != transition.private_input_commitment','private_input.blocks.len() != usize::from(transition.block_count)'],
 'crates/dom-usdom-checkpoint-statement/src/lib.rs':['bytes.len() != CHECKPOINT_STATEMENT_V4_BYTES','value.to_bytes()?.as_slice() != bytes','Keccak256::digest(V4_TYPE_STRING.as_bytes())'],
 'labs/usdom-reserve/contracts/USDOMProofReserve.sol':['BURN_STATEMENT_TYPEHASH','function burnStatementHash(FinalizedBurn calldata burn)','activationScheduleCommitment','_verify(statementHash, proof)'],
}
failed=[]
texts={}
for rel, needles in checks.items():
 p=(ROOT/rel).resolve(); s=p.read_text(); texts[rel]=s
 for needle in needles:
  if needle not in s: failed.append(f'{rel}: missing {needle}')
for rel in ['crates/dom-usdom-finalized-burn-risc0-guest/src/main.rs','crates/dom-usdom-checkpoint-segment-risc0-guest/src/main.rs','crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs']:
 lines=[line.strip() for line in texts[rel].splitlines() if 'env::commit' in line]
 if len(lines)!=1: failed.append(f'{rel}: expected exactly one journal commit, found {len(lines)}')
 if lines and any(word in lines[0] for word in ['input','witness','policy','opening','chain_bytes']): failed.append(f'{rel}: private material reaches journal')
if failed:
 print('FAIL RISC0 private/public binding\n'+'\n'.join(failed)); sys.exit(1)
print('PASS RISC0 burn/checkpoint private inputs bind canonical 32-byte journals and Solidity statement')

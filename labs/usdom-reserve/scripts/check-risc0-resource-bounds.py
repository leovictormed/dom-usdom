#!/usr/bin/env python3
"""Structural resource-bound gate for production RISC0 guests and proof hosts."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3]
checks={
'crates/dom-usdom-finalized-burn-risc0-guest/src/main.rs':['input_len > 0 && input_len <= MAX_FINALIZED_BURN_PROVER_INPUT_BYTES','let mut input = vec![0u8; input_len]','execute_with_checkpoint_assumption(&input)'],
'crates/dom-usdom-checkpoint-segment-risc0-guest/src/main.rs':['length > 0 && length <= maximum','MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES','MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES','MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES'],
'crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs':['length > 0 && length <= maximum','MAX_CHECKPOINT_OUTER_CHAIN_BYTES','MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES','MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES'],
'crates/dom-usdom-checkpoint-program/src/lib.rs':['pub const MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES','count > usize::from(MAX_CHECKPOINT_SEGMENT_BLOCKS)','checked_mul(CHECKPOINT_SEGMENT_PRIVATE_BLOCK_HEADER_BYTES)','if cursor != bytes.len()','MAX_CHECKPOINT_OUTER_SEGMENTS'],
'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs':['with_limit(MAX_RECEIPT_BYTES as u64)','reject_trailing_bytes()','with_limit(MAX_COMPOSITE_RECEIPT_BYTES as u64)','MAX_FINALIZED_BURN_PROVER_INPUT_BYTES'],
'crates/dom-usdom-checkpoint-proof-host/src/lib.rs':['with_limit(MAX_RECEIPT_BYTES as u64)','reject_trailing_bytes()','receipt_count > MAX_BLOCKS','segment_count > MAX_BLOCKS','MAX_CHECKPOINT_OUTER_CHAIN_BYTES'],
'crates/dom-usdom-randomx-proof-host/src/lib.rs':['with_limit(MAX_RECEIPT_BYTES as u64)','reject_trailing_bytes()'],
'crates/dom-usdom-economic-proof-host/src/lib.rs':['with_limit(MAX_RECEIPT_BYTES as u64)','reject_trailing_bytes()','block_count > MAX_BLOCKS'],
}
failed=[]
for rel, needles in checks.items():
 s=(ROOT/rel).read_text()
 for needle in needles:
  if needle not in s: failed.append(f'{rel}: missing {needle}')
if failed:
 print('FAIL RISC0 resource bounds\n'+'\n'.join(failed)); sys.exit(1)
print('PASS RISC0 guests/hosts bound allocation, decoding, counts, recursion and canonical framing')

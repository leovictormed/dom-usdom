#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
core="$repo/crates/dom-ethereum-consensus-core/src"
finality="$repo/labs/usdom-ethereum-finality/src"

if rg -n 'point_opt\.unwrap\(\)|hex_to_scalar\(CURVE_ORDER\)\.unwrap\(\)|next_sync_committee\.(as_ref\(\)|clone\(\))\.unwrap\(\)|finalized_header\.clone\(\)\.unwrap\(\)' \
    "$core/consensus_core.rs" "$core/types/bls.rs"; then
  echo "panic-capable Ethereum light-client dependency unwrap remains" >&2
  exit 1
fi

rg -q 'Option::<G1Affine>::from\(point_opt\).*ok_or_else' "$core/types/bls.rs"
rg -q 'Option::<G2Affine>::from\(point_opt\).*ok_or_else' "$core/types/bls.rs"
rg -q 'ok_or\(ConsensusError::InvalidPeriod\)' "$core/consensus_core.rs"
rg -q 'malformed_compressed_points_fail_closed' "$core/types/bls.rs"
rg -q 'rejects_next_period_without_next_committee_without_panicking' "$core/consensus_core.rs"

# Every externally supplied JSON/RLP envelope is bounded before the third-party
# decoder and canonicalized after it. MPT internals belong to ETAPA981.
rg -q 'bytes\.len\(\) <= MAX_TRANSCRIPT_BYTES' "$finality/lib.rs"
rg -q 'evidence_len <= MAX_CHECKPOINT_EVIDENCE_BYTES' "$finality/checkpoints.rs"
rg -q 'evidence_len <= MAX_DEPOSIT_EVIDENCE_BYTES' "$finality/deposits.rs"
rg -q 'raw\.len\(\) <= MAX_HEADER_BYTES' "$finality/ancestry.rs"
rg -q 'alloy_rlp::encode\(&header\)\.as_slice\(\) == raw\.as_ref\(\)' "$finality/ancestry.rs"
rg -q 'bytes\.len\(\) <= MAX_RECEIPT_BYTES' "$finality/receipts.rs"
rg -q 'receipt\.encoded_2718\(\)\.as_slice\(\) == bytes' "$finality/receipts.rs"

echo "ethereum-decoder-panic-boundary: PASS"

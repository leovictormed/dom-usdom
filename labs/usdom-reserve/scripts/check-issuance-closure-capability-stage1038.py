#!/usr/bin/env python3
"""Structural gate for the Ethereum-authenticated issuance-closure capability."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
MODULE = (ROOT / "labs/usdom-ethereum-finality/src/closures.rs").read_text()
LIB = (ROOT / "labs/usdom-ethereum-finality/src/lib.rs").read_text()
RESERVE = (ROOT / "labs/usdom-reserve/contracts/USDOMProofReserve.sol").read_text()

assert "pub mod closures;" in LIB
assert 'b"DepositsClosedV2(uint256,bytes32,bytes32,bytes32)"' in MODULE
assert "pub struct IssuanceClosurePolicy" in MODULE
for identity in (
    "ethereum_chain_id", "ethereum_genesis_validators_root", "reserve",
    "runtime_code_hash", "reserve_config_hash", "activation_schedule_commitment",
    "bridge_domain", "deposits_closed_storage_slot", "total_deposited_storage_slot",
):
    assert identity in MODULE
assert "pub struct StaticIssuanceClosureTrustPolicy" in MODULE
assert "pub fn at_max_current_slot" in MODULE

capability = MODULE[MODULE.index("pub struct VerifiedIssuanceClosure") :]
capability = capability[: capability.index("/// Encode the unique")]
for field in (
    "locator", "reserve", "total_deposited", "reserve_config_hash",
    "activation_schedule_commitment", "bridge_domain", "finalized", "trust_policy_hash",
):
    assert not re.search(rf"pub\s+{field}\s*:", capability)

verify = MODULE[MODULE.index("pub fn verify_issuance_closure_witness") :]
verify = verify[: verify.index("/// Return the deterministic")]
for required in (
    "restore_transcript_bounded", "verify_execution_ancestry", "verify_receipt_at",
    "verify_account_at", "receipt.log", "is_emitter_post_state_for",
    "check_contract_code", "verify_storage", "deposits_closed(closed.value())",
    "deposited.value() == total_deposited", "policy.closure.reserve_config_hash",
    "policy.closure.activation_schedule_commitment", "policy.closure.bridge_domain",
):
    assert required in verify
assert "VerifiedDeposit" not in MODULE

decode = MODULE[MODULE.index("fn decode_witness") : MODULE.index("fn validate_finalized")]
for required in (
    "MAX_ISSUANCE_CLOSURE_WITNESS_BYTES", "MAX_EVIDENCE_BYTES",
    "preflight_transcript_json", "preflight_evidence_json",
    "validate_ancestry_allocation_bounds", "validate_receipt_allocation_bounds",
    "validate_account_allocation_bounds", "validate_runtime_code_allocation_bounds",
    "validate_storage_allocation_bounds", "noncanonical closure evidence",
):
    assert required in decode

assert "packed_closure_flag_is_exact_and_independent_of_neighbor_fields" in MODULE
assert "depositsClosed = true;" in RESERVE
assert "emit DepositsClosedV2(totalDeposited, reserveConfigHash, activationScheduleCommitment, domDomain);" in RESERVE

print("stage1038 opaque issuance-closure capability gate: ok")

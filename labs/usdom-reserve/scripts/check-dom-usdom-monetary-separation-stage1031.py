#!/usr/bin/env python3
"""Static regression gate for strict DOM/USDOM monetary separation."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
MINER = (ROOT / "crates/dom-node/src/miner.rs").read_text()
CONSENSUS = (ROOT / "crates/dom-consensus/src/block_full.rs").read_text()
TX = (ROOT / "crates/dom-consensus/src/transaction.rs").read_text()
STATE = (ROOT / "crates/dom-usdom-state/src/lib.rs").read_text()
CHAIN = (ROOT / "crates/dom-chain/src/native_usdom_v4.rs").read_text()


def body(source: str, name: str) -> str:
    match = re.search(rf"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{name}\s*\(", source)
    assert match, f"missing function {name}"
    start = source.index("{", match.end())
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : index + 1]
    raise AssertionError(f"unterminated function {name}")


mine = body(MINER, "mine_one_attempt")
fees = mine.index("let total_tx_fees")
coinbase = mine.index("let coinbase")
native = mine.index("native_usdom_mining_template")
assert fees < coinbase < native
assert "selected_txs.iter().try_fold" in mine
assert ".build_coinbase(BlockHeight(new_height), total_tx_fees)" in mine
assert "template.batch_header_commitment()" in mine

coinbase_validation = body(TX, "validate_explicit_value")
assert "dom_core::block_reward(block_height).noms()" in coinbase_validation
assert "total_tx_fees" in coinbase_validation
assert "usdom" not in coinbase_validation.lower()

v4_validation = body(CONSENSUS, "validate_block_v4_scheduled")
common_validation = body(CONSENSUS, "validate_block_after_header")
assert "validate_block_after_header" in v4_validation
assert "let total_fees = block.total_fees()?" in common_validation
assert "validate_block_transactions" in common_validation
assert "block.coinbase" in common_validation
assert "dom_core::block_reward(block.header.height).noms()" in common_validation

issuance = CHAIN[CHAIN.index("UsdomV4ProofKind::Issuance => {") :]
issuance = issuance[: issuance.index("UsdomV4ProofKind::EthereumCheckpoint => {")]
assert issuance.index("verify_deposit_witness") < issuance.index("ethereum_deposit_transition")

capability = STATE[STATE.index("pub struct VerifiedIssuance") :]
capability = capability[: capability.index("pub struct VerifiedTransfer")]
for private_field in ("domain", "deposit_id", "note_commitment", "amount", "ethereum_anchor"):
    assert not re.search(rf"pub\s+{private_field}\s*:", capability)
assert '#[cfg(all(feature = "unsafe-test-oracle", not(debug_assertions)))]' in STATE
assert 'compile_error!("unsafe-test-oracle is forbidden in release builds")' in STATE

monetary = body(STATE, "expected_monetary_totals")
assert "VerifiedTransition::Issue" in monetary
assert "VerifiedTransition::Burn" in monetary
assert "VerifiedTransition::Transfer(_) | VerifiedTransition::EthereumCheckpoint(_)" in monetary
for apply_name in ("apply_v2", "apply"):
    apply = body(STATE, apply_name)
    assert "expected_monetary_totals" in apply
    assert "MonetarySeparationInvariant" in apply

apply_issuance = body(STATE, "apply_issuance")
assert "consumed_deposits.contains_key" in apply_issuance
assert "DepositAlreadyConsumed" in apply_issuance
assert "consumed_deposits.insert" in apply_issuance
assert "total_issued" in apply_issuance

restore = body(STATE, "restore_entries")
assert "computed_issued != total_issued || computed_burned != total_burned" in restore

print("stage1031 DOM/USDOM monetary separation gate: ok")

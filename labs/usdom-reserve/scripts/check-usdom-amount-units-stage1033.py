#!/usr/bin/env python3
"""Static regression gate for exact six-decimal USDOM/USDT base-unit accounting."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RESERVE = (ROOT / "labs/usdom-reserve/contracts/USDOMProofReserve.sol").read_text()
DEPOSITS = (ROOT / "labs/usdom-ethereum-finality/src/deposits.rs").read_text()
STATE = (ROOT / "crates/dom-usdom-state/src/lib.rs").read_text()
PRIVACY = (ROOT / "crates/dom-usdom-privacy/src/circuit.rs").read_text()
WALLET = (ROOT / "crates/dom-usdom-wallet/src/builder.rs").read_text()
BURN = (ROOT / "crates/dom-usdom-finalized-burn-program/src/lib.rs").read_text()
BUILDER = (ROOT / "crates/dom-node/src/bin/dom-usdom-build-finalized-deposit-witness.rs").read_text()

# Ethereum ingress fixes the collateral denomination and transfers the exact
# uint64 event value without scaling or fee/rebase tolerance.
assert "IERC20Metadata.decimals" in RESERVE and "bytes32(uint256(6))" in RESERVE
assert "function deposit(uint64 amount" in RESERVE
assert "Deposited(bytes32 indexed id, address indexed funder, uint64 amount" in RESERVE
assert "reserveBefore + amount" in RESERVE and "funderBefore" in RESERVE
assert "totalDeposited += amount" in RESERVE

# The authenticated ABI word must be a canonical uint64 and remains a u64
# through verified deposit and native occurrence construction.
assert 'const DEPOSIT_EVENT: &[u8] = b"Deposited(bytes32,address,uint64,bytes32)"' in DEPOSITS
assert 'ensure!(data[..24] == [0; 24], "noncanonical uint64 amount")' in DEPOSITS
assert 'let amount = read_u64_be(data, 24, "reserve deposit amount")?' in DEPOSITS
assert "amount != 0 && amount <= policy.max_amount" in DEPOSITS
assert "pub fn amount(&self) -> u64" in DEPOSITS
assert "deposit_amount_is_one_exact_canonical_uint64_base_unit_value" in DEPOSITS

# Native notes, transfers and burns use the same integer u64. Aggregate supply
# uses u128 and only checked widening additions; there is no decimal conversion.
assert "pub amount: u64" in STATE
assert "pub value: u64" in PRIVACY
assert "pub fn amount(&self) -> u64" in WALLET
assert ".checked_add(value)" in WALLET and ".checked_sub(amount)" in WALLET
assert "previous_issued.checked_add" not in STATE  # formatting separates the call
assert ".checked_add(u128::from(value.amount))" in STATE
assert ".checked_add(u128::from(value.record.amount))" in STATE

# Public redemption and Solidity payout agree on uint64 and exact base units.
assert "pub amount: u64" in BURN
assert "uint64 amount" in RESERVE
assert "totalReleased += burn.amount" in RESERVE
assert "IERC20.transfer, (burn.recipient, burn.amount)" in RESERVE
assert "recipientBefore + burn.amount" in RESERVE

# JSON handoff represents amounts as canonical decimal strings and parses them
# directly to u64; floating point and human-unit parsing remain absent.
assert "parse_decimal_u64(&source.amount_base_units" in BUILDER
assert "value.bytes().all(|byte| byte.is_ascii_digit())" in BUILDER
assert "(value.len() > 1 && value.starts_with('0'))" in BUILDER
assert '"amount_base_units": verified.amount().to_string()' in BUILDER
for forbidden in ("f32", "f64", "parse_units", "format_units", "10u64.pow", "1_000_000 *"):
    assert forbidden not in BUILDER

print("stage1033 USDOM/USDT exact amount-unit gate: ok")

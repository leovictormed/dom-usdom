#!/usr/bin/env python3
"""Static regression gate for USDOM/USDT time and height authorities."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FINALITY = (ROOT / "labs/usdom-ethereum-finality/src/lib.rs").read_text()
DEPOSITS = (ROOT / "labs/usdom-ethereum-finality/src/deposits.rs").read_text()
CHAIN = (ROOT / "crates/dom-chain/src/native_usdom_v4.rs").read_text()
STATE = (ROOT / "crates/dom-usdom-state/src/lib.rs").read_text()
WALLET = (ROOT / "crates/dom-usdom-wallet/src/burn_builder.rs").read_text()
RESERVE = (ROOT / "labs/usdom-reserve/contracts/USDOMProofReserve.sol").read_text()
REGISTRY = (ROOT / "labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol").read_text()
CONSENSUS = (ROOT / "crates/dom-consensus/src/block.rs").read_text()

# Ethereum evidence is bounded by an authenticated Beacon slot ceiling and an
# authenticated execution timestamp freshness window relative to the DOM block.
assert "witness.expected_finalized.beacon_slot <= policy.max_current_slot" in DEPOSITS
assert "replay_slot >= witness.expected_finalized.beacon_slot" in DEPOSITS
assert CHAIN.count("validate_finalized_time_window(") >= 2
assert "finalized_timestamp.checked_add" not in FINALITY  # rustfmt places the receiver above
assert ".checked_add(maximum_age_seconds)" in FINALITY
assert "consensus_timestamp.saturating_sub(maximum_future_lead_seconds)" in FINALITY
assert ".checked_add(maximum_future_lead_seconds)" in FINALITY
assert "finalized_time_window_has_exact_inclusive_bounds_and_checked_overflow" in FINALITY

# DOM timestamps are strictly monotonic on their own ancestry and bounded in
# the future; native burn admission uses that authenticated header timestamp.
assert "header.timestamp.0 <= parent.timestamp.0" in CONSENSUS
assert "MAX_FUTURE_BLOCK_TIME" in CONSENSUS
assert "context.timestamp.saturating_sub" not in STATE  # formatting separates the call
assert ".saturating_sub(self.burn_timing.max_dom_clock_lead_secs)" in STATE
assert ".checked_add(self.burn_timing.max_certificate_lifetime_secs)" in STATE
assert "value.record.valid_until < earliest || value.record.valid_until > latest" in STATE
assert ".checked_add(bridge.burn_timing.max_certificate_lifetime_secs)" in WALLET

# Checkpoint confirmation time is derived from the proved suffix tip, committed
# in the statement, and cannot claim a future Ethereum time at registration.
assert ".recent_headers" in (ROOT / "crates/dom-usdom-checkpoint-program/src/outer.rs").read_text()
assert "confirmationTimestamp > block.timestamp" in REGISTRY
assert "block.timestamp < current.readyAt" in REGISTRY

# Queue leases are inclusive at expiry, become collectible only afterwards,
# while the proved burn debt remains renewable. Rate refill uses only the EVM
# consensus timestamp and caps at capacity.
assert "if (block.timestamp > pending.expiresAt) revert StaleCertificate();" in RESERVE
assert "if (block.timestamp < pending.readyAt) revert TooEarly();" in RESERVE
assert "block.timestamp <= pending.expiresAt" in RESERVE
assert "provedBurnDebts[burn.burnId]" in RESERVE
assert "uint256 elapsed = block.timestamp - bucketUpdatedAt" in RESERVE
assert "if (elapsed >= REFILL_PERIOD) return outflowCapacity" in RESERVE
assert "available > outflowCapacity ? outflowCapacity : available" in RESERVE

# Beacon recency is computed from Ethereum genesis/slot cadence, rejects future
# slots, and includes the exact maximum-age boundary.
assert "block.timestamp - ETHEREUM_MAINNET_GENESIS_TIME" in RESERVE
assert "finalityBeaconSlot > currentSlot" in RESERVE
assert "currentSlot - finalityBeaconSlot > MAX_FINALITY_AGE_SLOTS" in RESERVE
assert "block.timestamp > type(uint64).max - delay" in RESERVE

print("stage1037 USDOM time-authority gate: ok")

#!/usr/bin/env python3
"""Static fail-closed gate for native USDOM orderly termination."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
STATE = (ROOT / "crates/dom-usdom-state/src/lib.rs").read_text()
CHAIN = (ROOT / "crates/dom-chain/src/native_usdom_v4.rs").read_text()
CHECKPOINT = (ROOT / "crates/dom-usdom-checkpoint-statement/src/lib.rs").read_text()
SEGMENT = (ROOT / "crates/dom-usdom-checkpoint-program/src/lib.rs").read_text()
PORTABLE = (ROOT / "crates/dom-usdom-checkpoint-program/src/portable.rs").read_text()
OUTER = (ROOT / "crates/dom-usdom-checkpoint-program/src/outer.rs").read_text()
OUTER_GUEST = (ROOT / "crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs").read_text()
FINALIZED_BURN = (ROOT / "crates/dom-usdom-finalized-burn-program/src/lib.rs").read_text()
REGISTRY_SDK = (ROOT / "labs/usdom-reserve/sdk/checkpoint-registry.mjs").read_text()
SUBMISSION_SDK = (ROOT / "labs/usdom-reserve/sdk/checkpoint-submission.mjs").read_text()
VERIFIER_CONFIG = (ROOT / "labs/usdom-reserve/config/checkpoint-verifier.unconfigured.json").read_text()
REGISTRY = (ROOT / "labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol").read_text()
RESERVE = (ROOT / "labs/usdom-reserve/contracts/USDOMProofReserve.sol").read_text()

required_state = (
    "GracefulShutdown(VerifiedGracefulShutdown)",
    "previous.issuance_closure.is_none()",
    "previous.total_burned != previous.total_issued",
    "candidate.gracefully_shutdown = true",
    'state_key(b"meta/graceful-shutdown")',
    "prior_gracefully_shutdown",
    "BURN_WITNESS_SHUTDOWN_MAGIC",
    "TransitionKind::GracefulShutdown",
    "graceful_shutdown_requires_closure_and_complete_burn_and_is_reversible",
)
required_chain = (
    "UsdomV4ProofKind::GracefulShutdown",
    "pub fn graceful_shutdown(dom_domain: [u8; 32])",
    "graceful shutdown payload must be the exact native domain",
    "graceful_shutdown_transition(domain)",
)
missing = [f"state:{x}" for x in required_state if x not in STATE]
missing += [f"chain:{x}" for x in required_chain if x not in CHAIN]
required_checkpoint = (
    'b"UDCPST06"',
    "DOMCheckpointV4(bytes32 bridgeDomain",
    "pub issuance_closed: bool",
    "CHECKPOINT_NATIVE_STATE_V6_VERSION: u16 = 3",
    "encoded[575] = u8::from(self.issuance_closed)",
    "v6_binds_canonical_issuance_closure_and_rejects_v5_replay",
)
required_segment = (
    'b"UDCSTN04"',
    'b"DOM:checkpoint-segment-transition:v4"',
    "pub previous_issuance_closed: bool",
    "pub new_issuance_closed: bool",
    "self.previous_issuance_closed && !self.new_issuance_closed",
)
required_outer = (
    "target_issuance_closed",
    "derive_checkpoint_statement_v6",
    "validate_checkpoint_outer_chain_v6",
)
missing += [f"checkpoint:{x}" for x in required_checkpoint if x not in CHECKPOINT]
missing += [f"segment:{x}" for x in required_segment if x not in SEGMENT]
missing += [f"portable:{x}" for x in (
    "native_state.issuance_closure.is_some() != transition.previous_issuance_closed",
    "native_state.issuance_closure.is_some() != transition.new_issuance_closed",
) if x not in PORTABLE]
missing += [f"outer:{x}" for x in required_outer if x not in OUTER]
missing += [f"outer-guest:{x}" for x in (
    "CheckpointStatementV6", "validate_checkpoint_outer_chain_v6",
) if x not in OUTER_GUEST]
missing += [f"burn:{x}" for x in ("CheckpointStatementV6", "CHECKPOINT_STATEMENT_V6_BYTES") if x not in FINALIZED_BURN]
missing += [f"registry-sdk:{x}" for x in (
    "DOMCheckpointV4(bytes32 bridgeDomain", "'uint128','uint128','bool'",
    "checkpoint.issuanceClosed",
) if x not in REGISTRY_SDK]
missing += [f"submission-sdk:{x}" for x in (
    "UDCPST06", "statementBytes=551", "issuanceClosed:bytes[550]===1",
) if x not in SUBMISSION_SDK]
missing += [f"verifier-config:{x}" for x in (
    '"statementVersion": "6"', '"publicStatementBytes": "551"',
    '"segmentTransitionVersion": "4"', '"segmentTransitionBytes": "2320"',
) if x not in VERIFIER_CONFIG]
missing += [f"registry:{x}" for x in (
    "DOMCheckpointV4(bytes32 bridgeDomain", "bool issuanceClosed;",
    "latestIssuanceClosed && !checkpoint.issuanceClosed",
    "!latestIssuanceClosed || latestTotalBurned != latestTotalIssued",
    "function finalizeGracefulShutdown() external",
) if x not in REGISTRY]
missing += [f"reserve:{x}" for x in (
    "interface IDOMGracefulShutdownRegistry", "function finalizeGracefulShutdown() external nonReentrant",
    "totalDeposited != totalReleased", "totalProvedDebtAmount != 0", "pendingCount != 0", "outstanding() != 0",
    "IDOMGracefulShutdownRegistry.gracefullyShutdown",
) if x not in RESERVE]
if missing:
    raise SystemExit("stage1045 graceful-shutdown gate missing: " + ", ".join(missing))
print("stage1045 graceful shutdown gate: ok")

#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def require(path: str, *needles: str) -> None:
    text = (ROOT / path).read_text()
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{path}: missing {missing}")

require("crates/dom-chain/src/native_usdom_v4.rs",
        "Self::IssuanceClosure => 5",
        "MAX_ISSUANCE_CLOSURES_PER_ENVELOPE: usize = 1",
        "MAX_ISSUANCE_CLOSURE_WITNESS_BYTES",
        "verify_issuance_closure_witness",
        "ethereum_issuance_closure_transition",
        "closure_policy: Option<&StaticIssuanceClosureTrustPolicy>")
require("crates/dom-chain/src/chain_state.rs",
        "StaticIssuanceClosureTrustPolicy",
        "closure_policy,")
require("crates/dom-node/src/native_usdom_config.rs",
        "ISSUANCE_CLOSURE_SCHEMA_VERSION: u16 = 3",
        "issuance_closure: Option<IssuanceClosureManifest>",
        "issuance_closure_policy: Option<StaticIssuanceClosureTrustPolicy>")
require("crates/dom-usdom-checkpoint-program/src/portable.rs",
        "5 => Ok(Self::IssuanceClosure)",
        "issuance_closures > 1",
        "verify_issuance_closure_witness")
require("crates/dom-usdom-checkpoint-program/src/lib.rs",
        'b"UDCSPOL1"', 'b"UDCSPOL2"',
        "new_with_issuance_closure",
        "issuance_closure_policy: Option<StaticIssuanceClosureTrustPolicy>")
require("labs/usdom-ethereum-finality/src/closures.rs",
        "STATIC_ISSUANCE_CLOSURE_POLICY_BYTES: usize = 422",
        "pub fn to_bytes(&self) -> Vec<u8>",
        "pub fn from_bytes(bytes: &[u8]) -> Result<Self>")
print("stage1041 issuance closure ingress gate: ok")

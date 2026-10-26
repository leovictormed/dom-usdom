#!/usr/bin/env python3
"""Fail closed if private USDOM telemetry/RPC/relay boundaries regress."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise SystemExit(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise SystemExit(f"forbidden {label}: {needle!r}")


rpc = read("crates/dom-rpc/src/lib.rs")
middleware = read("crates/dom-rpc/src/middleware.rs")
node = read("crates/dom-node/src/node.rs")
node_production = node.split("#[cfg(test)]\nmod tests {", 1)[0]
handle = read("crates/dom-node/src/node_handle.rs")
metrics = read("crates/dom-node/src/metrics.rs")
wallet_rpc = read("crates/dom-usdom-wallet/src/rpc_client.rs")

# Private submissions and authenticated history stay behind the same bearer
# boundary; public browser CORS remains confined to confirmed chain GETs.
for route in (
    '"/usdom/v4/transfer/submit/v1"',
    '"/usdom/v4/burn/submit/v1"',
    '"/usdom/v4/history/scan/v1"',
):
    require(rpc, route, "USD0M RPC route")
require(rpc, "middleware::require_bearer_token", "bearer route middleware")
require(middleware, "private USDOM history, transfer and burn operations", "private RPC CORS invariant")
require(wallet_rpc, "ip.is_loopback()", "literal loopback wallet RPC policy")
require(wallet_rpc, ".bearer_auth(self.bearer_token.as_str())", "wallet RPC authentication")

# Submission receipts expose identifiers only. Raw payloads are accepted as
# requests but are not echoed in responses or formatted into validation errors.
require(rpc, "pub struct UsdomV4TransferSubmissionV1", "private submission receipt")
receipt = rpc.split("pub struct UsdomV4TransferSubmissionV1", 1)[1].split("}", 1)[0]
require(receipt, "transition_id", "transition receipt identifier")
require(receipt, "candidate_id", "candidate receipt identifier")
receipt_fields = set(re.findall(r"pub\s+([a-zA-Z0-9_]+)\s*:", receipt))
for forbidden in ("payload", "recipient", "nullifier", "memo", "burn_id"):
    if forbidden in receipt_fields:
        raise SystemExit(f"forbidden private submission receipt field: {forbidden!r}")
for forbidden in ("hex::encode(&payload)", "{:?}, payload", "payload = ?payload"):
    forbid(handle, forbidden, "raw private payload formatting")

# History must return the encrypted canonical payload needed for owner scanning;
# no wallet viewing/spending key is accepted by or returned from the node.
require(rpc, "pub private_payload: Option<Vec<u8>>", "encrypted history payload")
for forbidden in ("viewing_key", "spending_key", "note_secret", "memo_plaintext"):
    forbid(rpc, forbidden, "wallet secret in RPC schema")

# Dandelion stem routing must not disclose the chosen hop through normal logs or
# error strings. Fluff and stem lag warnings intentionally omit peer/count.
require(node_production, "return Err(redact_stem_send_err(e));", "redacted stem send failure")
require(node_production, '"private transaction relay write failed"', "generic stem error")
require(node_production, 'tracing::warn!("transaction stem relay receiver lagged")', "redacted stem lag log")
for forbidden in ('annotate_send_err("stem", peer_addr', "tx_stem lagged by {n} for {peer_addr}"):
    forbid(node_production, forbidden, "stem-hop telemetry")

# The unauthenticated loopback metrics endpoint must not export exact pending
# transaction or private mining-pool cardinality/byte gauges.
export = metrics.split("pub fn export_prometheus", 1)[1]
for forbidden in (
    '"dom_mempool_size"',
    '"dom_txs_received"',
    '"dom_txs_relayed"',
    '"dom_native_usdom_v4_mining_candidates"',
    '"dom_native_usdom_v4_mining_candidate_bytes"',
):
    forbid(export.split("#[cfg(test)]", 1)[0], forbidden, "privacy-sensitive metric export")

print("USD0M metadata-boundary gate: PASS")

#!/usr/bin/env python3
"""Lightweight source gate for native USDOM node concurrency invariants."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
NODE = (ROOT / "crates/dom-node/src/node.rs").read_text()
MINER = (ROOT / "crates/dom-node/src/miner.rs").read_text()


def body(source: str, name: str) -> str:
    match = re.search(rf"(?:async\s+)?fn\s+{re.escape(name)}\s*\(", source)
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


for version in ("v4", "v2"):
    cleanup = body(NODE, f"complete_native_usdom_{version}_mining_candidate")
    assert "canonical_height: u64" in cleanup
    assert "canonical_block_hash: Hash256" in cleanup
    chain_lock = cleanup.index('trace_lock("chain"')
    canonical_check = cleanup.index("is_exact_canonical_block")
    runtime_lock = cleanup.index(f'trace_lock("native_usdom_{version}_runtime"')
    removal = cleanup.index("complete_mining_candidate")
    assert chain_lock < canonical_check < runtime_lock < removal, (
        f"{version} cleanup must authenticate the current canonical block under "
        "chain-before-runtime lock order before removing the candidate"
    )

    finalize = body(MINER, f"finalize_mined_native_usdom_{version}_block")
    assert "canonical_block_hash" in finalize
    assert f"complete_native_usdom_{version}_mining_candidate(" in finalize
    assert "new_height," in finalize and "canonical_block_hash," in finalize

capacity = body(NODE, "is_native_proof_capacity_error")
assert "native USDOM proof admission is at global capacity" in capacity
assert "duplicate native USDOM proof package is already in flight" in capacity

for ingress_name in (
    "submit_native_usdom_v4_mining_envelope",
    "submit_native_usdom_v2_mining_candidate",
    "native_usdom_v4_mining_template",
):
    ingress = body(NODE, ingress_name)
    assert ingress.index("chain.clone().lock_owned().await") < ingress.index(
        "runtime.clone().lock_owned().await"
    ), f"{ingress_name} inverted chain/runtime lock order"

print("stage1026 native USDOM concurrency source gate: ok")

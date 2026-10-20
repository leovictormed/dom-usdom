"""Read-only historical account/storage witnesses; untrusted until Rust verification."""
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RPC = "https://eth.drpc.org"
SECONDARY = "https://rpc.flashbots.net"
NUMBER = 17923026
BLOCK_HASH = "0xbc8499537876e5406c7a65e25f99063f1cd85a17014a3aa5ade38271b1fbf64f"
STATE_ROOT = "0x226f5ff47ab3725b5a4a3afc74b1e79e4aa3a29704561eccce590e58900baec3"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"


def rpc(endpoint, method, params):
    assert method in {"eth_chainId", "eth_getBlockByNumber", "eth_getProof", "eth_getCode"}
    query = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    request = urllib.request.Request(endpoint, data=json.dumps(query).encode(), headers={
        "Content-Type": "application/json", "User-Agent": "USDOM-research-readonly/1.0",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("oversized response")
    value = json.loads(data)
    if "error" in value or value.get("result") is None:
        raise ValueError(json.dumps(value.get("error", "missing result")))
    return value["result"]


def main():
    if rpc(RPC, "eth_chainId", []) != "0x1":
        raise ValueError("wrong reported chain")
    block = rpc(RPC, "eth_getBlockByNumber", [hex(NUMBER), False])
    if block["hash"] != BLOCK_HASH or block["stateRoot"] != STATE_ROOT:
        raise ValueError("wrong historical block")
    zero_slot = "0x" + "00" * 32
    high_slot = "0x" + "ff" * 32
    absent = "0x" + hashlib.sha256(b"USDOM-state-proof-absent-account-fixture/v1").hexdigest()[:40]
    targets = [
        ("usdt", USDT, [zero_slot, high_slot]),
        ("zero_address", "0x" + "00" * 20, [zero_slot]),
        ("expected_absent", absent, []),
    ]
    accounts = []
    for label, address, slots in targets:
        proof = rpc(RPC, "eth_getProof", [address, slots, hex(NUMBER)])
        code = rpc(RPC, "eth_getCode", [address, hex(NUMBER)])
        if proof["address"].lower() != address:
            raise ValueError("wrong reported address")
        accounts.append({"label": label, "proof": proof, "code": code})
    try:
        rpc(SECONDARY, "eth_getProof", [USDT, [], hex(NUMBER)])
        secondary = {"supported": True}
    except Exception as error:
        secondary = {"supported": False, "error": str(error)}
    fixture = {
        "scope": "Untrusted public historical RPC witnesses; verify BLS/SSZ and MPT before use",
        "collected_at": datetime.now(timezone.utc).isoformat(), "source": RPC,
        "blockHash": BLOCK_HASH, "blockNumber": NUMBER, "reportedStateRoot": STATE_ROOT,
        "secondary": {"endpoint": SECONDARY, **secondary}, "accounts": accounts,
    }
    (ROOT / "fixtures/account-state.json").write_text(json.dumps(fixture, indent=2) + "\n")
    print(json.dumps({"accounts": len(accounts), "code_bytes": len(accounts[0]["code"][2:]) // 2,
        "storage_claims": [item["proof"]["storageProof"] and [entry["value"] for entry in item["proof"]["storageProof"]] for item in accounts],
        "secondary": secondary}))


if __name__ == "__main__":
    main()

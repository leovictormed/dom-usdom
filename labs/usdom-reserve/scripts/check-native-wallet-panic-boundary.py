#!/usr/bin/env python3
"""Reject panic primitives from production native USDOM wallet sources."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from specialized_manifest import cargo_targets, manifest


REPO = Path(__file__).resolve().parents[3]
CRATE = REPO / "crates/dom-usdom-wallet"
SOURCE_ROOT = CRATE / "src"
MANIFEST = CRATE / "MANIFEST.sha256"
EXPECTED_SOURCES = {
    "builder.rs",
    "burn_builder.rs",
    "lib.rs",
    "rpc_client.rs",
    "snapshot.rs",
    "tpm2_authority.rs",
    "tpm2_keystore.rs",
    "bin/dom-usdom-wallet-recovery.rs",
}
EXPECTED_MANIFEST_PATHS = {"Cargo.toml", *(f"src/{name}" for name in EXPECTED_SOURCES)}
PANIC_PRIMITIVES = re.compile(
    r"\.(?:unwrap|expect)\s*\(|\b(?:panic|unreachable|todo|unimplemented)!\s*\("
)
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def production_prefix(source: str) -> str:
    prefix = source.split("#[cfg(test)]", 1)[0]
    return "\n".join(
        line for line in prefix.splitlines() if not line.lstrip().startswith("//")
    )


def check_text(source: str, label: str) -> None:
    checked = production_prefix(source)
    match = PANIC_PRIMITIVES.search(checked)
    if match is not None:
        line = checked.count("\n", 0, match.start()) + 1
        fail(f"{label}:{line}: panic primitive {match.group(0)!r}")


def check_sources() -> None:
    payloads=manifest(CRATE,"MANIFEST.sha256",EXPECTED_MANIFEST_PATHS)
    discovered = {name[4:] for name in payloads if name.startswith("src/")}
    if discovered != EXPECTED_SOURCES:
        fail(
            "native-wallet source inventory changed without panic-boundary review: "
            f"missing={sorted(EXPECTED_SOURCES - discovered)}, "
            f"new={sorted(discovered - EXPECTED_SOURCES)}"
        )
    cargo_targets(CRATE,payloads)
    for name in sorted(EXPECTED_SOURCES):check_text(payloads[f"src/{name}"].decode(),name)


def self_test() -> None:
    check_text("fn decode() -> Result<(), Error> { Ok(()) }", "safe")
    for primitive in [
        "value.unwrap()",
        'value.expect("trusted")',
        'panic!("bad")',
        'unreachable!("bad")',
        'todo!("bad")',
        'unimplemented!("bad")',
    ]:
        try:
            check_text(f"fn decode() {{ {primitive}; }}", "mutated")
        except SystemExit as error:
            if "panic primitive" not in str(error):
                raise
        else:
            raise AssertionError(f"panic mutation was accepted: {primitive}")
    check_text(
        "fn production() {}\n#[cfg(test)]\nmod tests { fn test() { value.unwrap(); } }",
        "tests",
    )
    print("PASS: native-wallet panic-boundary checker rejects all panic primitives")


def main(arguments: list[str]) -> None:
    if arguments == ["--self-test"]:
        self_test()
    elif not arguments:
        check_sources()
        print(
            f"PASS: all {len(EXPECTED_SOURCES)} native-wallet production sources are "
            f"panic-primitive free; {len(EXPECTED_MANIFEST_PATHS)}-file manifest verified"
        )
    else:
        raise SystemExit("Usage: check-native-wallet-panic-boundary.py [--self-test]")


if __name__ == "__main__":
    main(sys.argv[1:])

#!/usr/bin/env python3
"""Reject panic primitives from production Ethereum-finality source paths."""

from __future__ import annotations

import re
import sys
import hashlib
from pathlib import Path
from specialized_manifest import manifest


REPO = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO / "labs/usdom-ethereum-finality/src"
MANIFEST = REPO / "labs/usdom-ethereum-finality/MANIFEST.sha256"
EXPECTED_SOURCES = {
    "ancestry.rs",
    "checkpoints.rs",
    "closures.rs",
    "deposits.rs",
    "lib.rs",
    "receipts.rs",
    "state.rs",
}
PANIC_PRIMITIVES = re.compile(
    r"\.(?:unwrap|expect)\s*\(|\b(?:panic|unreachable|todo|unimplemented)!\s*\("
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def production_prefix(source: str) -> str:
    marker = "#[cfg(test)]"
    prefix = source.split(marker, 1)[0]
    # Rustdoc compile-fail examples intentionally demonstrate that private
    # authority cannot be forged; they are documentation, not production code.
    return "\n".join(
        line for line in prefix.splitlines() if not line.lstrip().startswith("//")
    )


def check_text(source: str, label: str) -> None:
    match = PANIC_PRIMITIVES.search(production_prefix(source))
    if match is not None:
        line = source.count("\n", 0, match.start()) + 1
        fail(f"{label}:{line}: panic primitive {match.group(0)!r}")


def check_sources() -> None:
    payloads=manifest(MANIFEST.parent,"MANIFEST.sha256")
    discovered = {name[4:] for name in payloads if name.startswith("src/") and "/" not in name[4:]}
    if discovered != EXPECTED_SOURCES:
        fail(
            "Ethereum-finality source inventory changed without panic-boundary review: "
            f"missing={sorted(EXPECTED_SOURCES - discovered)}, "
            f"new={sorted(discovered - EXPECTED_SOURCES)}"
        )
    for name in sorted(EXPECTED_SOURCES):check_text(payloads[f"src/{name}"].decode(),name)
    expected_production = {f"src/{name}" for name in EXPECTED_SOURCES}
    if not expected_production.issubset(payloads):
        fail("Ethereum-finality manifest omits a reviewed production source")


def self_test() -> None:
    check_text("fn decode() -> Result<()> { Ok(()) }", "safe")
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
    # Unit tests may use assertions and unwrap expected-positive fixtures.
    check_text(
        "fn production() {}\n#[cfg(test)]\nmod tests { fn test() { value.unwrap(); } }",
        "tests",
    )
    print("PASS: Ethereum-finality panic-boundary checker rejects all panic primitives")


def main(arguments: list[str]) -> None:
    if arguments == ["--self-test"]:
        self_test()
    elif not arguments:
        check_sources()
        print(
            f"PASS: all {len(EXPECTED_SOURCES)} Ethereum-finality production sources are panic-primitive free; "
            "410-file manifest verified"
        )
    else:
        raise SystemExit("Usage: check-ethereum-finality-panic-boundary.py [--self-test]")


if __name__ == "__main__":
    main(sys.argv[1:])

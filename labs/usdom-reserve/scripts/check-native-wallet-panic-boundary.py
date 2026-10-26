#!/usr/bin/env python3
"""Reject panic primitives from production native USDOM wallet sources."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


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
    discovered = {path.name for path in SOURCE_ROOT.glob("*.rs")}
    if discovered != EXPECTED_SOURCES:
        fail(
            "native-wallet source inventory changed without panic-boundary review: "
            f"missing={sorted(EXPECTED_SOURCES - discovered)}, "
            f"new={sorted(discovered - EXPECTED_SOURCES)}"
        )
    for name in sorted(EXPECTED_SOURCES):
        check_text((SOURCE_ROOT / name).read_text(encoding="utf-8"), name)

    listed: dict[str, str] = {}
    crate_root = CRATE.resolve()
    for number, line in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        match = MANIFEST_LINE.fullmatch(line)
        if match is None or match.group(2) in listed:
            fail(f"malformed or duplicate native-wallet manifest line {number}")
        relative = match.group(2)
        candidate = CRATE / relative
        path = candidate.resolve()
        if candidate.is_symlink() or not path.is_relative_to(crate_root) or not path.is_file():
            fail(f"invalid native-wallet manifest path: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != match.group(1):
            fail(f"native-wallet manifest digest mismatch: {relative}")
        listed[relative] = actual
    if set(listed) != EXPECTED_MANIFEST_PATHS:
        fail(
            "native-wallet manifest inventory mismatch: "
            f"missing={sorted(EXPECTED_MANIFEST_PATHS - set(listed))}, "
            f"extra={sorted(set(listed) - EXPECTED_MANIFEST_PATHS)}"
        )


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

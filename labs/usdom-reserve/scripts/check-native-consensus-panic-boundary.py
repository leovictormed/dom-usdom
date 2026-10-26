#!/usr/bin/env python3
"""Reject panic primitives and fixed-offset checkpoint decoding in native consensus."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
CHAIN = REPO / "crates/dom-chain/src"
SOURCES = {
    "ethereum_checkpoint_poc.rs": CHAIN / "ethereum_checkpoint_poc.rs",
    "native_usdom_v4.rs": CHAIN / "native_usdom_v4.rs",
}
PANIC_PRIMITIVES = re.compile(
    r"\.(?:unwrap|expect)\s*\(|\b(?:panic|unreachable|todo|unimplemented)!\s*\("
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def production_source(name: str, source: str) -> str:
    if name == "native_usdom_v4.rs":
        marker = "\nmod tests {"
        if marker not in source:
            fail("native USDOM test-module boundary is missing")
        source = source.split(marker, 1)[0]
    # Rustdoc compile-fail snippets deliberately contain impossible constructors.
    return "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("//")
    )


def check_panic_primitives(name: str, source: str) -> None:
    production = production_source(name, source)
    match = PANIC_PRIMITIVES.search(production)
    if match is not None:
        line = production.count("\n", 0, match.start()) + 1
        fail(f"{name}:{line}: panic primitive {match.group(0)!r}")


def function_body(source: str, signature: str, next_signature: str) -> str:
    start = source.find(signature)
    end = source.find(next_signature, start + len(signature))
    if start < 0 or end < 0:
        fail(f"cannot locate reviewed function boundary: {signature}")
    return source[start:end]


def check_checkpoint_reader(checkpoint_source: str, native_source: str) -> None:
    decoder = function_body(
        checkpoint_source,
        "pub fn decode_test_oracle_v2",
        "fn validate_identity",
    )
    required_decoder_markers = (
        "let mut reader = Reader::new(bytes);",
        "reader.read_array::<20>()?",
        "reader.finish()?;",
    )
    for marker in required_decoder_markers:
        if marker not in decoder:
            fail(f"checkpoint decoder lost bounded Reader marker: {marker}")
    if re.search(r"bytes\s*\[[^\]]*\.\.[^\]]*\]", decoder):
        fail("checkpoint decoder reintroduced fixed-offset byte slicing")

    binding = function_body(
        native_source,
        "pub fn bind_verified_ethereum_checkpoint_to_native_burn",
        "pub(crate) struct NativeCheckpointTarget",
    )
    if "decode_test_oracle_v2(checkpoint.record())?" not in binding:
        fail("native burn binding no longer uses the canonical checkpoint decoder")
    if re.search(r"checkpoint\.record\(\)\s*\[", binding) or "fixed checkpoint record" in binding:
        fail("native burn binding reintroduced manual checkpoint offsets")


def check_persisted_readers(native_source: str) -> None:
    reviewed = (
        (
            "fn decode_persisted_usdom_v4_tip",
            "fn restore_persisted_usdom_v2_activation_state_at_tip",
            ("let mut reader = Reader::new(bytes);", "reader.finish()?;"),
            r"bytes\s*\[[^\]]*\.\.[^\]]*\]",
        ),
        (
            "fn decode_v2_burn_archive_value",
            "fn load_v2_burn_archive_at_height",
            ("let mut reader = Reader::new(value);", "reader.finish()?;"),
            r"value\s*\[[^\]]*\.\.[^\]]*\]",
        ),
        (
            "fn decode_v2_prune_cursor",
            "fn decode_persisted_chunk_metadata",
            ("let mut reader = Reader::new(value);", "reader.finish()?;"),
            r"value\s*\[[^\]]*\.\.[^\]]*\]",
        ),
        (
            "fn decode_persisted_chunk_metadata",
            "fn chunk_count_from_meta",
            ("let mut reader = Reader::new(meta);", "reader.finish()?;"),
            r"meta\s*\[[^\]]*\.\.[^\]]*\]",
        ),
    )
    for signature, next_signature, markers, forbidden in reviewed:
        body = function_body(native_source, signature, next_signature)
        for marker in markers:
            if marker not in body:
                fail(f"persisted decoder lost bounded Reader marker: {signature}: {marker}")
        if re.search(forbidden, body):
            fail(f"persisted decoder reintroduced fixed-offset slicing: {signature}")

    witness_loader = function_body(
        native_source,
        "pub fn load_persisted_usdom_v2_execution_witnesses",
        "fn load_persisted_usdom_v2_block_record",
    )
    package_loader = function_body(
        native_source,
        "pub fn load_persisted_usdom_v4_package",
        "pub fn load_authenticated_usdom_v4_history_block",
    )
    for label, body in (("witness", witness_loader), ("package", package_loader)):
        if "decode_persisted_chunk_metadata(" not in body:
            fail(f"persisted {label} loader bypasses canonical metadata decoder")
        if re.search(r"meta\s*\[[^\]]*\.\.[^\]]*\]", body):
            fail(f"persisted {label} loader reintroduced manual metadata offsets")


def self_test() -> None:
    check_panic_primitives("safe.rs", "fn decode() -> Result<(), E> { Ok(()) }")
    for primitive in (
        "value.unwrap()",
        'value.expect("trusted")',
        'panic!("bad")',
        'unreachable!("bad")',
        'todo!("bad")',
        'unimplemented!("bad")',
    ):
        try:
            check_panic_primitives("mutated.rs", f"fn decode() {{ {primitive}; }}")
        except SystemExit as error:
            if "panic primitive" not in str(error):
                raise
        else:
            raise AssertionError(f"panic mutation was accepted: {primitive}")
    check_panic_primitives(
        "native_usdom_v4.rs",
        "fn production() {}\nmod tests { fn test() { value.unwrap(); } }",
    )
    safe = """
fn decode_persisted_usdom_v4_tip() {
 let mut reader = Reader::new(bytes); reader.finish()?;
}
fn restore_persisted_usdom_v2_activation_state_at_tip() {}
fn decode_v2_burn_archive_value() {
 let mut reader = Reader::new(value); reader.finish()?;
}
fn load_v2_burn_archive_at_height() {}
fn decode_v2_prune_cursor() {
 let mut reader = Reader::new(value); reader.finish()?;
}
fn decode_persisted_chunk_metadata() {
 let mut reader = Reader::new(meta); reader.finish()?;
}
fn chunk_count_from_meta() {}
pub fn load_persisted_usdom_v2_execution_witnesses() {
 decode_persisted_chunk_metadata();
}
fn load_persisted_usdom_v2_block_record() {}
pub fn load_persisted_usdom_v4_package() {
 decode_persisted_chunk_metadata();
}
pub fn load_authenticated_usdom_v4_history_block() {}
"""
    check_persisted_readers(safe)
    try:
        check_persisted_readers(safe.replace("reader.finish()?;", "let _ = value[8..16];", 1))
    except SystemExit as error:
        if "bounded Reader marker" not in str(error):
            raise
    else:
        raise AssertionError("fixed-offset persisted-decoder mutation was accepted")
    print("PASS: native-consensus panic-boundary checker rejects all panic primitives")


def main(arguments: list[str]) -> None:
    if arguments == ["--self-test"]:
        self_test()
        return
    if arguments:
        fail("usage: check-native-consensus-panic-boundary.py [--self-test]")
    sources = {name: path.read_text(encoding="utf-8") for name, path in SOURCES.items()}
    for name, source in sources.items():
        check_panic_primitives(name, source)
    check_checkpoint_reader(
        sources["ethereum_checkpoint_poc.rs"], sources["native_usdom_v4.rs"]
    )
    check_persisted_readers(sources["native_usdom_v4.rs"])
    print(
        "PASS: native checkpoint and persisted-state decoding use bounded Reader, "
        "the burn binding uses the canonical decoder, and both production modules "
        "are panic-primitive free"
    )


if __name__ == "__main__":
    main(sys.argv[1:])

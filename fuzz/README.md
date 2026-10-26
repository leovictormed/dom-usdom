# Protocol parser fuzzing

These standalone cargo-fuzz targets exercise only the production V2 Bitcoin
evidence APIs. They do not import the legacy evidence types or the F5 harness,
and no decoder falls back to the frozen V1 format.

`fuzz_bitcoin_evidence_decode` submits arbitrary bytes directly to the exact V2
decoder. It also mutates a constructor-produced canonical V2 container so the
fuzzer can reach bounded length fields, discriminants, full-block bytes,
confirmation headers, trailing-byte rejection, and canonical round trips
without relying on a stale corpus.

`fuzz_witness_parser` constructs a complete canonical Regtest block around a
bounded fuzz-generated witness, recomputes the SegWit commitment and transaction
Merkle root, mines the easy local headers, authenticates them through
`RegtestHeaderAuthorityV2`, and calls `verify_evidence_v2`. This keeps the full
block, mutation scan, 64-byte ambiguity check, exact witness commitment, txid,
wtxid, outpoint, and claim/refund witness-shape checks on the real V2 path.

Run bounded local campaigns from this directory with a cargo-fuzz-compatible
nightly toolchain:

```text
cargo fuzz run fuzz_bitcoin_evidence_decode -- -max_total_time=60
cargo fuzz run fuzz_witness_parser -- -max_len=2048 -max_total_time=60
```

A bounded campaign is evidence only for that platform, toolchain, and duration;
it does not replace the deterministic V2 vectors or full package tests.

## Native USDOM block framing

`usdombl4` submits arbitrary bytes directly to
`UsdomV4BlockPackage::from_bytes`. Every successfully decoded package must
round-trip to the exact input bytes and decode identically a second time. The
checked-in corpus includes a constructor-produced canonical package so the
fuzzer starts beyond the outer framing and exercises the ordinary block and
proof-envelope parsers. The `dom-chain` unit suite separately rejects every
proper prefix of that canonical package, which makes complete truncation
coverage deterministic rather than dependent on a time-bounded fuzz run.

Regenerate the canonical corpus seed only from the source-built test helper:

```text
DOM_USDOMBL4_CORPUS_OUT="$PWD/fuzz/corpus/usdombl4/canonical-empty-v4-package" \
  cargo test --locked -p dom-chain --features native-usdom-v4-poc \
  native_usdom_v4::tests::block_package_roundtrips_and_rejects_split_or_ambiguous_framing \
  -- --exact
```

Run a bounded local campaign from `fuzz/` with the protocol dictionary and the
checked-in corpus:

```text
cargo fuzz run usdombl4 corpus/usdombl4 -- \
  -dict=usdombl4.dict -max_len=4194304 -max_total_time=300
```

The seed regeneration command mutates only the named corpus file. The fuzz
campaign must run with sanitizers on a dedicated development machine; it does
not grant release authority or replace the deterministic parser, consensus and
canonical-encoding tests.

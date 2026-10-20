# Pinned Ethereum tree hash

The Rust sources are the published `tree_hash` 0.10.0 sources from Sigma Prime,
copied without consensus-semantic changes. The unused `arbitrary` feature was
removed from this proof-only copy. The manifest explicitly selects the local
pure-Rust `ethereum_hashing` crate so the proof path cannot silently resolve to
the upstream `ring` backend. `UPSTREAM-README.md` and the Apache-2.0 `LICENSE`
are retained. The local manifest and this notice are DOM modifications.

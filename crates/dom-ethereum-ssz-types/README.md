# Pinned Ethereum SSZ types

The Rust sources are the published `ssz_types` 0.11.0 sources from Sigma Prime,
copied without changes. Its optional fuzzing API remains available without the
unused derive macro. The manifest explicitly selects the local `tree_hash`
crate, which selects the pure-Rust SHA-256 boundary.
`UPSTREAM-README.md` and the Apache-2.0 `LICENSE` are retained. The local
manifest and this notice are DOM modifications.

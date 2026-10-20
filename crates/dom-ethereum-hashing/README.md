# DOM Ethereum hashing boundary

This crate is an explicit, path-pinned replacement for the `ethereum_hashing`
0.7.0 API used by `tree_hash` 0.10.0 in the USDOM finalized-burn proof path.
It always uses RustCrypto SHA-256 and contains no runtime CPU dispatch, `ring`,
C, assembly, filesystem, network, clock or randomness.

The API and zero-hash semantics originate from Sigma Prime's
`ethereum_hashing` 0.7.0, licensed under Apache-2.0. This modified implementation
was written for DOM and preserves that license in `LICENSE`. The semantic output
is checked against NIST SHA-256 vectors, frozen Ethereum zero hashes, the
upstream `tree_hash` tests, and the repository's historical Helios fixtures.

This crate does not select or certify a zkVM. Its purpose is to make the hashing
dependency explicit and portable enough to compile inside a future guest.

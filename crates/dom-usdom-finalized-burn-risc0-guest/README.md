# Finalized USDOM burn RISC Zero guest

This crate is the backend-specific wrapper around
`dom-usdom-finalized-burn-program`. It is pinned to RISC Zero 3.0.6 and commits
the relation's exact 32-byte output to the receipt journal.

The private host transport is:

1. one `u32` input length encoded by the RISC Zero codec;
2. exactly that many raw `UDFINL04` bytes written with `write_slice`.

After decoding, the guest verifies the recursively supplied checkpoint-outer
receipt against its pinned ImageID and the exact V4 checkpoint-statement hash.
Only then may it commit the finalized-burn statement hash.

The length must be nonzero and no greater than
`MAX_FINALIZED_BURN_PROVER_INPUT_BYTES`. Invalid lengths, encodings, witnesses,
bindings or checkpoints abort the guest and cannot produce a successful
receipt. The journal never contains the private input or intermediate state.

The checked-in `UDFINL04` ProgramBinary was built twice from the same locked
source snapshot in isolated targets. Both builds produced SHA-256
`bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511`
and ImageID
`f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae`.
`PROVENANCE.json` records the builder, locks and source-manifest identities.

The current deterministic execution-only benchmark consumes the canonical
64,815-byte `UDFINL04` input in 581,398,127 user cycles and 590 segments at a
`2^20` segment limit. The executor resolves the exact checkpoint-outer claim as
an explicit unresolved assumption, so this benchmark proves guest execution
and output binding but does not claim a cryptographically proven recursive
receipt. That receipt remains a separate release gate.

These artifacts do not authorize production. A production proof/receipt,
mainnet-configured immutable EVM verifier, finalized registry deployment and
release-specific operational evidence remain required.

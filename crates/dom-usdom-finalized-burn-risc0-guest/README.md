# Finalized USDOM burn RISC Zero guest

This crate is the backend-specific wrapper around
`dom-usdom-finalized-burn-program`. It is pinned to RISC Zero 3.0.6 and commits
the relation's exact 32-byte output to the receipt journal.

The private host transport is:

1. one `u32` input length encoded by the RISC Zero codec;
2. exactly that many raw `UDFINL02` bytes written with `write_slice`.

The length must be nonzero and no greater than
`MAX_FINALIZED_BURN_PROVER_INPUT_BYTES`. Invalid lengths, encodings, witnesses,
bindings or checkpoints abort the guest and cannot produce a successful
receipt. The journal never contains the private input or intermediate state.

The checked-in program binary was reproduced with the RISC Zero 1.97 guest
builder selected by immutable image digest. Its SHA-256 is
`438adf4a9a50832da0dfbb77c0b8588d9ba1fbb41d216875e874dfa1db5dfcb0` and its
ImageID is
`3975a5f01dc85b6e89925913c5555ade4aefb951c65261142384fd829a70f88a`.
`PROVENANCE.json` records the complete builder identity and lock-file binding.

The deterministic positive raw-checkpoint vector executes successfully in the
official 3.0.6 executor. With a `2^20` segment limit it consumes 562,418,750
user cycles in 570 segments and commits the expected 32-byte journal. This is
an execution benchmark, not a generated proof or a proving-time estimate.

These artifacts do not authorize production. A production proof/receipt,
mainnet-configured immutable EVM verifier, finalized registry deployment and
release-specific operational evidence remain required.

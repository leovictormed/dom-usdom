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
`883ec39b03e3a0703e592026fc7d92a15ce7d949cb937551c5dd8360184cde21`
and ImageID
`2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea`.
`PROVENANCE.json` records the builder, locks and source-manifest identities.

The historical deterministic benchmark (571,308,757 user cycles in 580
segments at a `2^20` segment limit) covers only UDFINL03. It is not evidence for
the recursive UDFINL04 relation and cannot satisfy the current release gate.

These artifacts do not authorize production. A production proof/receipt,
mainnet-configured immutable EVM verifier, finalized registry deployment and
release-specific operational evidence remain required.

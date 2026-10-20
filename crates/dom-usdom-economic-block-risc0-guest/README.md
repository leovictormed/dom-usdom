# USDOM complete economic-block RISC Zero guest

This recursive guest composes the canonical `UDECTN01` receipts for every
ordinary economic effect in one exact DOM block. The `UDECCH01` chain must
start at cursor zero, follow the unique UTXO-then-kernel order without gaps or
root discontinuities, and finish at the exact counts derived independently by
the checkpoint segment executor. It commits the 32-byte `UDECBT01` journal.

The executable pins the economic-chunk ImageID
`67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350`.
At most 80 chunks are accepted. The complete checkpoint segment guest pins this
block guest's ImageID, so a receipt from another program cannot be substituted.
The candidate artifacts and reproducibility record are in `elfs/` and
`PROVENANCE.json`.

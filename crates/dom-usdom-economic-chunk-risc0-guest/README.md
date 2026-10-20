# USDOM economic-chunk RISC Zero guest

This guest proves one canonical `UDECTN01` transition over at most 512 ordered
ordinary DOM economic effects. It parses the exact committed v4 package,
derives its block identity and complete effect counts, verifies the bounded
`UDECCW01` sparse witness, and commits only the 32-byte transition journal.

The block-level recursive guest pins this program's ImageID and composes up to
80 chunks in the only valid UTXO-then-kernel order. The candidate artifacts and
byte-identical clean-rebuild record are in `elfs/` and `PROVENANCE.json`.

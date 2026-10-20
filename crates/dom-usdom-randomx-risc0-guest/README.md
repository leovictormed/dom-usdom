# Complete RandomX RISC Zero guest

This component validates one fixed-width canonical `UDCRXST1` DOM RandomX
statement and evaluates its exact RandomX v1 light-mode relation. It validates
network and chain identity, height and seed schedule, header preimage, compact
target expansion, and proof-of-work threshold before executing RandomX. It
constructs the canonical 256 MiB Argon2d cache from `seed_hash`, derives all
eight superscalar programs, executes the eight chained VM programs, and rejects
a computed hash that differs from the header's claimed digest.

The journal is exactly the 32-byte
`keccak256("DOM:checkpoint-randomx-statement:v1" || UDCRXST1)` commitment
already required by the recursive checkpoint aggregate. The aggregate derives
that statement from the canonical private DOM block package, authenticates its
seed block, pins this guest's ImageID in the segment policy, and verifies this
exact journal as a receipt assumption.

Compilation alone does not establish production proving cost. The guest must
produce a positive receipt and its cycle, memory, proving-time, and receipt-size
measurements must fit the operational checkpoint policy before activation.

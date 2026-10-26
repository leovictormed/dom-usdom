# Native USDOM verification and retention policy

Status: implemented and regression-tested for the isolated candidate. This is
an engineering control, not an authorization to activate or fund mainnet.

## Groth16 verification

`SpendVerifier::verify` is the canonical BN254 Groth16 boundary. On the current
development host, an optimized deterministic benchmark measured 2,309,296 ns
per proof (433.03 proofs/second, eight timed repetitions; setup and proving
excluded). Sixteen serial private spends therefore account for about 36.95 ms
before block and state checks.

When an envelope contains at least two private spends, their proof and payload
verification runs through Rayon's bounded work sharing. Results are collected
into their original canonical entry slots before any state execution. Ethereum
proofs, transition ordering, nullifier and duplicate checks, header validation,
fork choice and persistence remain serial and deterministic. A zero- or
one-spend envelope stays on the serial path.

## Rollback records

The consensus rolling-finality limit is 360 blocks. A V1 direct extension now
deletes, in the same atomic database transaction, the single undo record that
has moved beyond that window. A V1 reorganization deletes undo records for the
disconnected canonical branch and regenerates records for the promoted branch.
Consequently `usdom-v4/undo/` cannot grow indefinitely during normal extension
or repeated shallow reorganization.

The package bytes are deliberately not deleted with V1 undo records. They are
immutable proof/history material and may be copied into a verified archive.
The mutable consensus database promises authenticated V1 rollback projections
only within the rolling-finality window.

## Candidate-V2 history

Candidate V2 does not persist a full mutable-state undo object. Its per-block
record stores the previous and next compact state commitments, while package
and execution-witness bytes permit deterministic branch replay.

Every accepted burn is also stored in a fixed-width `UDBURN01` archive entry
bound to its canonical block height and identifier. Activation imports the
already existing V1 burn set at the activation parent. A direct V2 extension
adds its burns in the same transaction as the block and compact state. A reorg
deletes burns from the disconnected branch and installs burns from the promoted
branch atomically. Archive loading rejects malformed records, key/record
identity mismatches and entries whose origin is no longer canonical.

`UDFINL04` reconstruction no longer replays the complete V2 chain. It validates
the retained checkpoint block and compact record, rebuilds the burn and request
sparse sets from the archive entries at or below that height, and requires the
resulting roots, counts and total burned amount to equal the checkpointed
`StateCommitmentV2`. This preserves burn membership proofs without retaining
all historical Groth16 payloads and execution openings.

Replay data is eligible for deletion only below both boundaries:

1. the current Ethereum-recognized DOM checkpoint; and
2. the 360-block rolling-finality window.

The checkpoint block record itself remains. Each direct commit deletes at most
64 eligible heights and advances a versioned prune cursor in the same LMDB
transaction, so a backlog is bounded per block and catches up incrementally.
For each compacted height the package metadata/chunks, execution-witness
metadata/chunks and compact V2 block record are removed. The fixed burn archive
is retained because it represents live reserve obligations rather than replay
history.

When a retained side branch is promoted, its authenticated package and witness
data move into canonical consensus-state keys and the redundant sidecars are
deleted in the same reorganization transaction. Conflicting insert/delete
requests abort before the chain tip or consensus state changes.

Tests cover the exact rolling/checkpoint boundary, atomic sidecar promotion and
rollback on conflicting changes, restart/reorg persistence, successful
finalized-burn reconstruction after older replay data is deleted, retained burn
archive membership, and fail-closed rejection of a checkpoint whose record was
compacted.

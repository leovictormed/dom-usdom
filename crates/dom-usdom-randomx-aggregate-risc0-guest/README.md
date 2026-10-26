# USDOM RandomX aggregate RISC Zero guest

This component guest parses one exact `UDCSTN04` transition and its committed
`UDCSPI01` private input, derives one state-pinned `UDCRXST1` receipt requirement
for every consecutive header, and verifies all inner receipts in order. Its
journal is only the 32-byte commitment of the distinct `UDCRXAG1` aggregate.

`UDCRXAG1` is deliberately not a checkpoint transition proof. This guest does
not validate ordinary DOM economic state or execute native USDOM transitions,
and its ImageID must never be configured as the Ethereum checkpoint verifier's
outer ImageID. A complete outer guest must compose this component with those
missing relations before it can authorize a checkpoint.

The committed ProgramBinary and ImageID are candidate evidence only. The local
RISC Zero 3.0.6 build is pinned in `PROVENANCE.json` and reproduced by
`labs/usdom-reserve/scripts/build-randomx-aggregate-risc0-guest.sh`. Production
approval remains false until an independently reproduced, reviewed build and a
complete positive receipt path exist.

# USDOM complete checkpoint-segment RISC Zero guest

This guest proves one bounded `UDCSTN02` transition of at most 32 consecutive
DOM blocks. It authenticates `UDCSPOL1` policy preimages and the `UDCSNS01`
previous native-state opening, executes native USDOM candidate-v2 state, verifies ordinary DOM economics either directly or through the pinned complete economic-block receipt, and verifies one state-pinned complete RandomX receipt per header. Its journal is the exact 32-byte transition commitment.

The receipt is a recursive segment building block. The outer guest pins this segment ImageID and binds the resulting chain to the Ethereum `CheckpointStatement`. Positive receipt and proving-cost measurements, plus ratified production configuration, remain outstanding. This crate does not authorize deployment or real funds by itself.

`elfs/usdom-checkpoint-segment.elf` is the candidate user ELF built with the
pinned RISC Zero toolchain. `elfs/usdom-checkpoint-segment.bin` is the v1
compatibility `ProgramBinary`, whose ImageID is recorded in the adjacent `.iid`
file. The build uses LLVM's `lower-atomic` pass because the zkVM RV32 target
does not provide native atomics. Randomness remains fail-closed: the guest uses
the custom getrandom backend without enabling RISC Zero host randomness.

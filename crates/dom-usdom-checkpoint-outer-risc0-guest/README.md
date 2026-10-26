# USDOM outer checkpoint RISC Zero guest

This guest composes the complete checkpoint-segment receipts into the exact
`UDCPST06` statement consumed by `DOMCheckpointRegistry`. It authenticates the
previous registry state and policy, requires exact segment boundaries at the
target height and confirmation tip, and verifies every segment receipt under
the complete-segment ImageID frozen in `src/main.rs`. Segment sizes may vary
from 1 to 32 blocks so byte-bounded private inputs can use smaller segments;
the public 720-block context span bounds the chain to at most 720 receipts.

Its journal is only the 32-byte Solidity statement hash. This source is a
candidate until its own reproducible artifact, ImageID, positive recursive
receipt, proving-cost measurements, verifier adapter, and production
configuration are completed and ratified.

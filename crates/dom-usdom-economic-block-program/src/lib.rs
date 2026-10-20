//! Recursive composition of bounded ordinary-DOM economic chunk receipts.

#![deny(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
use dom_usdom_checkpoint_program::EconomicRoots;
pub use dom_usdom_checkpoint_program::{EconomicBlockTransition, ECONOMIC_BLOCK_TRANSITION_BYTES};
use dom_usdom_checkpoint_program::{
    EconomicChunkTransition, ECONOMIC_CHUNK_TRANSITION_BYTES, MAX_ECONOMIC_BLOCK_CHUNKS,
};
use thiserror::Error;

const CHAIN_MAGIC: &[u8; 8] = b"UDECCH01";
const CHAIN_VERSION: u16 = 1;
const CHAIN_HEADER_BYTES: usize = 12;
/// Maximum canonical bytes of one complete economic chunk chain.
pub const MAX_ECONOMIC_CHUNK_CHAIN_BYTES: usize =
    CHAIN_HEADER_BYTES + MAX_ECONOMIC_BLOCK_CHUNKS * ECONOMIC_CHUNK_TRANSITION_BYTES;

/// Failure to frame or compose one economic block proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EconomicBlockError {
    /// Fixed or chain framing is malformed or noncanonical.
    #[error("invalid economic block framing")]
    InvalidFraming,
    /// The public block transition violates a bounded invariant.
    #[error("invalid economic block transition")]
    InvalidTransition,
    /// Chunk ordering, identity, cursor or roots do not match.
    #[error("invalid economic chunk chain")]
    InvalidChain,
    /// The pinned chunk guest ImageID is zero.
    #[error("invalid economic chunk ImageID")]
    InvalidImageId,
}

fn array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], EconomicBlockError> {
    bytes
        .get(start..start + N)
        .ok_or(EconomicBlockError::InvalidFraming)?
        .try_into()
        .map_err(|_| EconomicBlockError::InvalidFraming)
}

/// Canonically encoded ordered chunk statements for one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicChunkChain {
    transitions: Vec<EconomicChunkTransition>,
}

impl EconomicChunkChain {
    /// Construct a bounded ordered chunk chain.
    pub fn new(transitions: Vec<EconomicChunkTransition>) -> Result<Self, EconomicBlockError> {
        if transitions.is_empty() || transitions.len() > MAX_ECONOMIC_BLOCK_CHUNKS {
            return Err(EconomicBlockError::InvalidFraming);
        }
        for transition in &transitions {
            transition
                .validate()
                .map_err(|_| EconomicBlockError::InvalidChain)?;
        }
        Ok(Self { transitions })
    }

    /// Ordered public chunk transitions.
    pub fn transitions(&self) -> &[EconomicChunkTransition] {
        &self.transitions
    }

    /// Encode the unique bounded `UDECCH01` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EconomicBlockError> {
        let mut bytes = Vec::with_capacity(
            CHAIN_HEADER_BYTES + self.transitions.len() * ECONOMIC_CHUNK_TRANSITION_BYTES,
        );
        bytes.extend_from_slice(CHAIN_MAGIC);
        bytes.extend_from_slice(&CHAIN_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &u16::try_from(self.transitions.len())
                .map_err(|_| EconomicBlockError::InvalidFraming)?
                .to_be_bytes(),
        );
        for transition in &self.transitions {
            bytes.extend_from_slice(
                &transition
                    .to_bytes()
                    .map_err(|_| EconomicBlockError::InvalidChain)?,
            );
        }
        Ok(bytes)
    }

    /// Decode and canonically revalidate one complete chain.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EconomicBlockError> {
        if bytes.len() < CHAIN_HEADER_BYTES + ECONOMIC_CHUNK_TRANSITION_BYTES
            || bytes.len() > MAX_ECONOMIC_CHUNK_CHAIN_BYTES
            || bytes.get(..8) != Some(CHAIN_MAGIC.as_slice())
            || u16::from_be_bytes(array(bytes, 8)?) != CHAIN_VERSION
        {
            return Err(EconomicBlockError::InvalidFraming);
        }
        let count = usize::from(u16::from_be_bytes(array(bytes, 10)?));
        let expected = CHAIN_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(ECONOMIC_CHUNK_TRANSITION_BYTES)
                    .ok_or(EconomicBlockError::InvalidFraming)?,
            )
            .ok_or(EconomicBlockError::InvalidFraming)?;
        if count == 0 || count > MAX_ECONOMIC_BLOCK_CHUNKS || bytes.len() != expected {
            return Err(EconomicBlockError::InvalidFraming);
        }
        let mut transitions = Vec::with_capacity(count);
        let mut cursor = CHAIN_HEADER_BYTES;
        for _ in 0..count {
            let end = cursor + ECONOMIC_CHUNK_TRANSITION_BYTES;
            transitions.push(
                EconomicChunkTransition::from_bytes(&bytes[cursor..end])
                    .map_err(|_| EconomicBlockError::InvalidChain)?,
            );
            cursor = end;
        }
        let chain = Self::new(transitions)?;
        if chain.to_bytes()?.as_slice() != bytes {
            return Err(EconomicBlockError::InvalidFraming);
        }
        Ok(chain)
    }
}

/// Exact receipt required for one bounded chunk statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicChunkReceiptAssumption {
    image_id: [u8; 32],
    journal: [u8; 32],
}

impl EconomicChunkReceiptAssumption {
    /// Pinned chunk guest ImageID.
    pub const fn image_id(&self) -> &[u8; 32] {
        &self.image_id
    }

    /// Exact transition journal.
    pub const fn journal(&self) -> &[u8; 32] {
        &self.journal
    }
}

/// Validated block journal and its ordered recursive assumptions.
pub struct EconomicBlockExecution {
    block_commitment: [u8; 32],
    chunk_receipts: Vec<EconomicChunkReceiptAssumption>,
}

impl EconomicBlockExecution {
    /// Complete block transition journal.
    pub const fn block_commitment(&self) -> [u8; 32] {
        self.block_commitment
    }

    /// Exact ordered chunk receipts required by this block.
    pub fn chunk_receipts(&self) -> &[EconomicChunkReceiptAssumption] {
        &self.chunk_receipts
    }
}

/// Compose every bounded chunk into one exact block transition.
pub fn validate_economic_block_chain(
    block: &EconomicBlockTransition,
    chain: &EconomicChunkChain,
    expected_chunk_image_id: [u8; 32],
) -> Result<EconomicBlockExecution, EconomicBlockError> {
    block
        .validate()
        .map_err(|_| EconomicBlockError::InvalidTransition)?;
    if expected_chunk_image_id == [0; 32] {
        return Err(EconomicBlockError::InvalidImageId);
    }
    let mut cursor = 0u32;
    let mut roots = block.previous_roots;
    let mut receipts = Vec::with_capacity(chain.transitions.len());
    for transition in &chain.transitions {
        transition
            .validate()
            .map_err(|_| EconomicBlockError::InvalidChain)?;
        if transition.network_magic != block.network_magic
            || transition.package_commitment != block.package_commitment
            || transition.block_hash != block.block_hash
            || transition.block_height != block.block_height
            || transition.utxo_effects != block.utxo_effects
            || transition.kernel_effects != block.kernel_effects
            || transition.cursor != cursor
            || transition.previous_roots != roots
        {
            return Err(EconomicBlockError::InvalidChain);
        }
        receipts.push(EconomicChunkReceiptAssumption {
            image_id: expected_chunk_image_id,
            journal: transition
                .commitment()
                .map_err(|_| EconomicBlockError::InvalidChain)?,
        });
        cursor = transition.next_cursor;
        roots = transition.next_roots;
    }
    let total = block
        .utxo_effects
        .checked_add(block.kernel_effects)
        .ok_or(EconomicBlockError::InvalidTransition)?;
    if cursor != total || roots != block.next_roots {
        return Err(EconomicBlockError::InvalidChain);
    }
    Ok(EconomicBlockExecution {
        block_commitment: block
            .commitment()
            .map_err(|_| EconomicBlockError::InvalidTransition)?,
        chunk_receipts: receipts,
    })
}

/// Verify every pinned chunk receipt inside the block aggregation guest.
#[cfg(all(feature = "risc0-recursion", target_os = "zkvm"))]
pub fn verify_economic_chunk_receipts_in_guest(
    assumptions: &[EconomicChunkReceiptAssumption],
) -> Result<(), core::convert::Infallible> {
    for assumption in assumptions {
        risc0_zkvm::guest::env::verify(
            risc0_zkvm::sha::Digest::from(*assumption.image_id()),
            assumption.journal().as_slice(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn roots(byte: u8) -> EconomicRoots {
        EconomicRoots {
            utxo_root: [byte; 32],
            kernel_root: [byte.wrapping_add(1); 32],
        }
    }

    #[test]
    fn three_chunks_compose_exact_block_and_reject_discontinuity() {
        let r0 = roots(1);
        let r1 = EconomicRoots {
            utxo_root: [3; 32],
            kernel_root: r0.kernel_root,
        };
        let r2 = EconomicRoots {
            utxo_root: [4; 32],
            kernel_root: r0.kernel_root,
        };
        let r3 = EconomicRoots {
            utxo_root: r2.utxo_root,
            kernel_root: [5; 32],
        };
        let common = ([7; 32], [8; 32]);
        let chunk = |cursor, next_cursor, previous_roots, next_roots| EconomicChunkTransition {
            network_magic: dom_core::NETWORK_MAGIC_REGTEST,
            package_commitment: common.0,
            block_hash: common.1,
            block_height: 42,
            utxo_effects: 600,
            kernel_effects: 1,
            cursor,
            next_cursor,
            previous_roots,
            next_roots,
        };
        let chunks = vec![
            chunk(0, 512, r0, r1),
            chunk(512, 600, r1, r2),
            chunk(600, 601, r2, r3),
        ];
        let chain = EconomicChunkChain::new(chunks.clone()).expect("chain");
        assert_eq!(
            EconomicChunkChain::from_bytes(&chain.to_bytes().expect("bytes")).expect("decode"),
            chain
        );
        let block = EconomicBlockTransition {
            network_magic: dom_core::NETWORK_MAGIC_REGTEST,
            package_commitment: common.0,
            block_hash: common.1,
            block_height: 42,
            utxo_effects: 600,
            kernel_effects: 1,
            previous_roots: r0,
            next_roots: r3,
        };
        let execution = validate_economic_block_chain(&block, &chain, [9; 32]).expect("compose");
        assert_eq!(execution.chunk_receipts().len(), 3);
        assert_eq!(
            execution.block_commitment(),
            block.commitment().expect("journal")
        );

        let mut broken = chunks;
        broken[1].previous_roots.utxo_root = [99; 32];
        let broken = EconomicChunkChain::new(broken).expect("framed chain");
        assert!(matches!(
            validate_economic_block_chain(&block, &broken, [9; 32]),
            Err(EconomicBlockError::InvalidChain)
        ));
        assert!(matches!(
            validate_economic_block_chain(&block, &chain, [0; 32]),
            Err(EconomicBlockError::InvalidImageId)
        ));
    }
}

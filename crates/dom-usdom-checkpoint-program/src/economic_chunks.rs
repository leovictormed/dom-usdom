//! Bounded recursive decomposition of ordinary DOM block economics.

#[cfg(feature = "host-reference")]
use super::EconomicState;
use super::{
    economic_array, economic_block_effects, keccak, EconomicMultiProof, EconomicRoots,
    EconomicStateError, EconomicUtxo, KERNEL_TREE, MAX_ECONOMIC_CHUNK_KEYS,
    MAX_ECONOMIC_CHUNK_WITNESS_BYTES, UTXO_TREE,
};
#[cfg(any(feature = "host-reference", feature = "portable-execution"))]
use dom_consensus::Block;
#[cfg(feature = "portable-execution")]
use dom_serialization::DomSerialize;
use sha3::{Digest, Keccak256};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"UDECCW01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + 4 + 4 + 4;
const TRANSITION_MAGIC: &[u8; 8] = b"UDECTN01";
const TRANSITION_VERSION: u16 = 1;
/// Fixed canonical byte length of one `UDECTN01` statement.
pub const ECONOMIC_CHUNK_TRANSITION_BYTES: usize = 230;
const TRANSITION_DOMAIN: &[u8] = b"DOM:checkpoint-economic-chunk-transition:v1";
const PACKAGE_DOMAIN: &[u8] = b"DOM:checkpoint-economic-chunk-package:v1";
const BLOCK_TRANSITION_MAGIC: &[u8; 8] = b"UDECBT01";
const BLOCK_TRANSITION_VERSION: u16 = 1;
/// Fixed canonical byte length of one `UDECBT01` statement.
pub const ECONOMIC_BLOCK_TRANSITION_BYTES: usize = 222;
const BLOCK_TRANSITION_DOMAIN: &[u8] = b"DOM:checkpoint-economic-block-transition:v1";

fn transition_array<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], EconomicChunkTransitionError> {
    bytes
        .get(start..start + N)
        .ok_or(EconomicChunkTransitionError::InvalidFraming)?
        .try_into()
        .map_err(|_| EconomicChunkTransitionError::InvalidFraming)
}

/// Exact public statement for one bounded economic chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicChunkTransition {
    /// DOM network whose maturity policy applies.
    pub network_magic: u32,
    /// Domain-separated commitment to the exact canonical v4 package.
    pub package_commitment: [u8; 32],
    /// Canonical block-header identifier.
    pub block_hash: [u8; 32],
    /// Height copied from the parsed block.
    pub block_height: u64,
    /// Number of ordered UTXO effects in the parsed block.
    pub utxo_effects: u32,
    /// Number of ordered historical-kernel effects in the parsed block.
    pub kernel_effects: u32,
    /// Combined effect cursor before this chunk.
    pub cursor: u32,
    /// Combined effect cursor after this chunk.
    pub next_cursor: u32,
    /// Authenticated economic roots before this chunk.
    pub previous_roots: EconomicRoots,
    /// Authenticated economic roots after this chunk.
    pub next_roots: EconomicRoots,
}

/// Failure to encode, decode or execute an economic chunk statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EconomicChunkTransitionError {
    /// The fixed representation is malformed or noncanonical.
    #[error("invalid economic chunk transition framing")]
    InvalidFraming,
    /// Network, block, counts, cursor or root relations are invalid.
    #[error("invalid economic chunk transition")]
    InvalidTransition,
    /// The package does not parse canonically.
    #[error("invalid economic chunk package")]
    InvalidPackage,
    /// The private witness does not prove the claimed root transition.
    #[error("invalid economic chunk witness")]
    InvalidWitness,
}

impl EconomicChunkTransition {
    /// Whether this statement finishes every economic effect in the block.
    pub fn is_terminal(&self) -> bool {
        self.utxo_effects
            .checked_add(self.kernel_effects)
            .is_some_and(|total| self.next_cursor == total)
    }

    /// Validate all public invariants and the canonical chunk boundary.
    pub fn validate(&self) -> Result<(), EconomicChunkTransitionError> {
        let total = self
            .utxo_effects
            .checked_add(self.kernel_effects)
            .ok_or(EconomicChunkTransitionError::InvalidTransition)?;
        let expected_next = if self.cursor < self.utxo_effects {
            self.cursor
                .saturating_add(MAX_ECONOMIC_CHUNK_KEYS as u32)
                .min(self.utxo_effects)
        } else {
            self.cursor
                .saturating_add(MAX_ECONOMIC_CHUNK_KEYS as u32)
                .min(total)
        };
        let known_network = matches!(
            self.network_magic,
            dom_core::NETWORK_MAGIC_MAINNET
                | dom_core::NETWORK_MAGIC_TESTNET
                | dom_core::NETWORK_MAGIC_REGTEST
        );
        if !known_network
            || self.package_commitment == [0; 32]
            || self.block_hash == [0; 32]
            || self.block_height == 0
            || self.utxo_effects == 0
            || self.kernel_effects == 0
            || total > dom_core::MAX_BLOCK_WEIGHT
            || self.cursor >= total
            || self.next_cursor != expected_next
            || self.previous_roots.context_root().is_err()
            || self.next_roots.context_root().is_err()
            || (self.cursor < self.utxo_effects
                && self.previous_roots.kernel_root != self.next_roots.kernel_root)
            || (self.cursor >= self.utxo_effects
                && self.previous_roots.utxo_root != self.next_roots.utxo_root)
        {
            return Err(EconomicChunkTransitionError::InvalidTransition);
        }
        Ok(())
    }

    /// Encode the fixed 230-byte `UDECTN01` statement.
    pub fn to_bytes(
        self,
    ) -> Result<[u8; ECONOMIC_CHUNK_TRANSITION_BYTES], EconomicChunkTransitionError> {
        self.validate()?;
        let mut bytes = [0u8; ECONOMIC_CHUNK_TRANSITION_BYTES];
        bytes[..8].copy_from_slice(TRANSITION_MAGIC);
        bytes[8..10].copy_from_slice(&TRANSITION_VERSION.to_be_bytes());
        bytes[10..14].copy_from_slice(&self.network_magic.to_be_bytes());
        bytes[14..46].copy_from_slice(&self.package_commitment);
        bytes[46..78].copy_from_slice(&self.block_hash);
        bytes[78..86].copy_from_slice(&self.block_height.to_be_bytes());
        bytes[86..90].copy_from_slice(&self.utxo_effects.to_be_bytes());
        bytes[90..94].copy_from_slice(&self.kernel_effects.to_be_bytes());
        bytes[94..98].copy_from_slice(&self.cursor.to_be_bytes());
        bytes[98..102].copy_from_slice(&self.next_cursor.to_be_bytes());
        bytes[102..134].copy_from_slice(&self.previous_roots.utxo_root);
        bytes[134..166].copy_from_slice(&self.previous_roots.kernel_root);
        bytes[166..198].copy_from_slice(&self.next_roots.utxo_root);
        bytes[198..230].copy_from_slice(&self.next_roots.kernel_root);
        Ok(bytes)
    }

    /// Decode and canonically revalidate one fixed statement.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EconomicChunkTransitionError> {
        if bytes.len() != ECONOMIC_CHUNK_TRANSITION_BYTES
            || bytes.get(..8) != Some(TRANSITION_MAGIC.as_slice())
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| EconomicChunkTransitionError::InvalidFraming)?,
            ) != TRANSITION_VERSION
        {
            return Err(EconomicChunkTransitionError::InvalidFraming);
        }
        let transition = Self {
            network_magic: u32::from_be_bytes(transition_array(bytes, 10)?),
            package_commitment: transition_array(bytes, 14)?,
            block_hash: transition_array(bytes, 46)?,
            block_height: u64::from_be_bytes(transition_array(bytes, 78)?),
            utxo_effects: u32::from_be_bytes(transition_array(bytes, 86)?),
            kernel_effects: u32::from_be_bytes(transition_array(bytes, 90)?),
            cursor: u32::from_be_bytes(transition_array(bytes, 94)?),
            next_cursor: u32::from_be_bytes(transition_array(bytes, 98)?),
            previous_roots: EconomicRoots {
                utxo_root: transition_array(bytes, 102)?,
                kernel_root: transition_array(bytes, 134)?,
            },
            next_roots: EconomicRoots {
                utxo_root: transition_array(bytes, 166)?,
                kernel_root: transition_array(bytes, 198)?,
            },
        };
        transition.validate()?;
        if transition.to_bytes()?.as_slice() != bytes {
            return Err(EconomicChunkTransitionError::InvalidFraming);
        }
        Ok(transition)
    }

    /// Domain-separated journal committed by an economic chunk guest.
    pub fn commitment(self) -> Result<[u8; 32], EconomicChunkTransitionError> {
        let mut hasher = Keccak256::new();
        hasher.update(TRANSITION_DOMAIN);
        hasher.update(self.to_bytes()?);
        Ok(hasher.finalize().into())
    }
}

/// Exact public result of all economic effects in one DOM block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicBlockTransition {
    /// DOM network whose consensus rules apply.
    pub network_magic: u32,
    /// Commitment to the exact canonical v4 package.
    pub package_commitment: [u8; 32],
    /// Canonical block-header identifier.
    pub block_hash: [u8; 32],
    /// Parsed block height.
    pub block_height: u64,
    /// Exact number of UTXO effects.
    pub utxo_effects: u32,
    /// Exact number of historical-kernel effects.
    pub kernel_effects: u32,
    /// Authenticated roots before the block.
    pub previous_roots: EconomicRoots,
    /// Authenticated roots after the block.
    pub next_roots: EconomicRoots,
}

impl EconomicBlockTransition {
    /// Validate public identity, effect counts and both economic roots.
    pub fn validate(&self) -> Result<(), EconomicChunkTransitionError> {
        let total = self
            .utxo_effects
            .checked_add(self.kernel_effects)
            .ok_or(EconomicChunkTransitionError::InvalidTransition)?;
        if !matches!(
            self.network_magic,
            dom_core::NETWORK_MAGIC_MAINNET
                | dom_core::NETWORK_MAGIC_TESTNET
                | dom_core::NETWORK_MAGIC_REGTEST
        ) || self.package_commitment == [0; 32]
            || self.block_hash == [0; 32]
            || self.block_height == 0
            || self.utxo_effects == 0
            || self.kernel_effects == 0
            || total > dom_core::MAX_BLOCK_WEIGHT
            || self.previous_roots.context_root().is_err()
            || self.next_roots.context_root().is_err()
        {
            return Err(EconomicChunkTransitionError::InvalidTransition);
        }
        Ok(())
    }

    /// Encode the fixed `UDECBT01` representation.
    pub fn to_bytes(
        self,
    ) -> Result<[u8; ECONOMIC_BLOCK_TRANSITION_BYTES], EconomicChunkTransitionError> {
        self.validate()?;
        let mut bytes = [0u8; ECONOMIC_BLOCK_TRANSITION_BYTES];
        bytes[..8].copy_from_slice(BLOCK_TRANSITION_MAGIC);
        bytes[8..10].copy_from_slice(&BLOCK_TRANSITION_VERSION.to_be_bytes());
        bytes[10..14].copy_from_slice(&self.network_magic.to_be_bytes());
        bytes[14..46].copy_from_slice(&self.package_commitment);
        bytes[46..78].copy_from_slice(&self.block_hash);
        bytes[78..86].copy_from_slice(&self.block_height.to_be_bytes());
        bytes[86..90].copy_from_slice(&self.utxo_effects.to_be_bytes());
        bytes[90..94].copy_from_slice(&self.kernel_effects.to_be_bytes());
        bytes[94..126].copy_from_slice(&self.previous_roots.utxo_root);
        bytes[126..158].copy_from_slice(&self.previous_roots.kernel_root);
        bytes[158..190].copy_from_slice(&self.next_roots.utxo_root);
        bytes[190..222].copy_from_slice(&self.next_roots.kernel_root);
        Ok(bytes)
    }

    /// Decode and canonically revalidate one exact block statement.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EconomicChunkTransitionError> {
        if bytes.len() != ECONOMIC_BLOCK_TRANSITION_BYTES
            || bytes.get(..8) != Some(BLOCK_TRANSITION_MAGIC.as_slice())
            || u16::from_be_bytes(transition_array(bytes, 8)?) != BLOCK_TRANSITION_VERSION
        {
            return Err(EconomicChunkTransitionError::InvalidFraming);
        }
        let transition = Self {
            network_magic: u32::from_be_bytes(transition_array(bytes, 10)?),
            package_commitment: transition_array(bytes, 14)?,
            block_hash: transition_array(bytes, 46)?,
            block_height: u64::from_be_bytes(transition_array(bytes, 78)?),
            utxo_effects: u32::from_be_bytes(transition_array(bytes, 86)?),
            kernel_effects: u32::from_be_bytes(transition_array(bytes, 90)?),
            previous_roots: EconomicRoots {
                utxo_root: transition_array(bytes, 94)?,
                kernel_root: transition_array(bytes, 126)?,
            },
            next_roots: EconomicRoots {
                utxo_root: transition_array(bytes, 158)?,
                kernel_root: transition_array(bytes, 190)?,
            },
        };
        transition.validate()?;
        if transition.to_bytes()?.as_slice() != bytes {
            return Err(EconomicChunkTransitionError::InvalidFraming);
        }
        Ok(transition)
    }

    /// Domain-separated journal for the complete economic block receipt.
    pub fn commitment(self) -> Result<[u8; 32], EconomicChunkTransitionError> {
        let mut hasher = Keccak256::new();
        hasher.update(BLOCK_TRANSITION_DOMAIN);
        hasher.update(self.to_bytes()?);
        Ok(hasher.finalize().into())
    }
}

/// Commitment to the exact package parsed by an economic chunk guest.
pub fn economic_chunk_package_commitment(package_bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(PACKAGE_DOMAIN.len() + package_bytes.len());
    input.extend_from_slice(PACKAGE_DOMAIN);
    input.extend_from_slice(package_bytes);
    keccak(&input)
}

/// Execute one bounded chunk from canonical package bytes.
#[cfg(feature = "portable-execution")]
pub fn execute_economic_chunk_portable(
    package_bytes: &[u8],
    witness: &EconomicChunkWitness,
    network_magic: u32,
    previous_roots: EconomicRoots,
) -> Result<EconomicChunkTransition, EconomicChunkTransitionError> {
    let block = super::portable::parse_checkpoint_package_block(package_bytes)
        .map_err(|_| EconomicChunkTransitionError::InvalidPackage)?;
    let header_bytes = DomSerialize::to_bytes(&block.header)
        .map_err(|_| EconomicChunkTransitionError::InvalidPackage)?;
    let block_hash = *dom_core::blake2b_256(&header_bytes).as_bytes();
    let (effects, kernels) =
        economic_block_effects(&block).map_err(|_| EconomicChunkTransitionError::InvalidPackage)?;
    let maturity = if network_magic == dom_core::NETWORK_MAGIC_REGTEST {
        dom_core::REGTEST_COINBASE_MATURITY
    } else {
        dom_core::COINBASE_MATURITY
    };
    let executed = witness
        .apply(previous_roots, &block, maturity)
        .map_err(|_| EconomicChunkTransitionError::InvalidWitness)?;
    let transition = EconomicChunkTransition {
        network_magic,
        package_commitment: economic_chunk_package_commitment(package_bytes),
        block_hash,
        block_height: block.header.height.0,
        utxo_effects: u32::try_from(effects.len())
            .map_err(|_| EconomicChunkTransitionError::InvalidTransition)?,
        kernel_effects: u32::try_from(kernels.len())
            .map_err(|_| EconomicChunkTransitionError::InvalidTransition)?,
        cursor: witness.cursor(),
        next_cursor: executed.next_cursor,
        previous_roots,
        next_roots: executed.roots,
    };
    transition.validate()?;
    Ok(transition)
}

/// Bounded authenticated subset of one block's ordinary economic effects.
///
/// Chunks use one deterministic order: all UTXO effects in sparse-path order,
/// followed by all historical-kernel insertions in sparse-path order. This
/// permits a block with a large full multiproof to be advanced through bounded
/// recursive receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicChunkWitness {
    cursor: u32,
    proof: EconomicMultiProof,
    old_utxos: Vec<Option<EconomicUtxo>>,
}

/// Public result of applying one bounded economic chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EconomicChunkExecution {
    /// Authenticated roots after this chunk.
    pub roots: EconomicRoots,
    /// Cursor at which the next chunk must begin.
    pub next_cursor: u32,
    /// Exact number of ordered UTXO and kernel effects in the block.
    pub total_effects: u32,
}

impl EconomicChunkWitness {
    /// Build the next deterministic chunk from a complete host snapshot.
    #[cfg(feature = "host-reference")]
    pub fn from_state(
        state: &EconomicState,
        block: &Block,
        cursor: u32,
    ) -> Result<Self, EconomicStateError> {
        let (effects, kernels) = economic_block_effects(block)?;
        let cursor = usize::try_from(cursor).map_err(|_| EconomicStateError::InvalidProof)?;
        let total = effects
            .len()
            .checked_add(kernels.len())
            .ok_or(EconomicStateError::InvalidProof)?;
        if cursor >= total {
            return Err(EconomicStateError::InvalidProof);
        }
        let (proof, old_utxos) = if cursor < effects.len() {
            let end = cursor
                .saturating_add(MAX_ECONOMIC_CHUNK_KEYS)
                .min(effects.len());
            let proof = EconomicMultiProof::from_state(
                state,
                true,
                effects[cursor..end].iter().map(|(key, _)| *key),
            )?;
            let old = proof
                .keys()
                .iter()
                .map(|key| state.utxos.get(key).copied())
                .collect();
            (proof, old)
        } else {
            let start = cursor - effects.len();
            let end = start
                .saturating_add(MAX_ECONOMIC_CHUNK_KEYS)
                .min(kernels.len());
            (
                EconomicMultiProof::from_state(state, false, kernels[start..end].iter().copied())?,
                Vec::new(),
            )
        };
        let witness = Self {
            cursor: u32::try_from(cursor).map_err(|_| EconomicStateError::InvalidProof)?,
            proof,
            old_utxos,
        };
        witness.validate()?;
        Ok(witness)
    }

    /// Cursor at which this chunk begins.
    pub const fn cursor(&self) -> u32 {
        self.cursor
    }

    /// Verify and advance exactly the deterministic subset selected by cursor.
    #[cfg(any(feature = "host-reference", feature = "portable-execution"))]
    pub fn apply(
        &self,
        roots: EconomicRoots,
        block: &Block,
        coinbase_maturity: u64,
    ) -> Result<EconomicChunkExecution, EconomicStateError> {
        self.validate()?;
        let (effects, kernels) = economic_block_effects(block)?;
        let cursor = usize::try_from(self.cursor).map_err(|_| EconomicStateError::InvalidProof)?;
        let total = effects
            .len()
            .checked_add(kernels.len())
            .ok_or(EconomicStateError::InvalidProof)?;
        if cursor >= total {
            return Err(EconomicStateError::InvalidProof);
        }

        let (next_roots, next_cursor) = if cursor < effects.len() {
            let end = cursor
                .saturating_add(MAX_ECONOMIC_CHUNK_KEYS)
                .min(effects.len());
            let expected: Vec<_> = effects[cursor..end].iter().map(|(key, _)| *key).collect();
            if self.proof.tree != UTXO_TREE
                || self.proof.keys() != expected
                || self.old_utxos.len() != end - cursor
            {
                return Err(EconomicStateError::InvalidProof);
            }
            let mut new = Vec::with_capacity(end - cursor);
            for ((_, effect), opened) in effects[cursor..end].iter().zip(&self.old_utxos) {
                if effect.spent {
                    let value = opened.ok_or(EconomicStateError::MissingInput)?;
                    if value.is_coinbase
                        && block.header.height.0.saturating_sub(value.created_height)
                            < coinbase_maturity
                    {
                        return Err(EconomicStateError::ImmatureCoinbase);
                    }
                    new.push(None);
                } else {
                    if opened.is_some() {
                        return Err(EconomicStateError::DuplicateOutput);
                    }
                    new.push(Some(EconomicUtxo {
                        created_height: block.header.height.0,
                        is_coinbase: effect.coinbase,
                    }));
                }
            }
            (
                EconomicRoots {
                    utxo_root: self.proof.update_utxo_root(
                        roots.utxo_root,
                        &self.old_utxos,
                        &new,
                    )?,
                    kernel_root: roots.kernel_root,
                },
                end,
            )
        } else {
            let start = cursor - effects.len();
            let end = start
                .saturating_add(MAX_ECONOMIC_CHUNK_KEYS)
                .min(kernels.len());
            if self.proof.tree != KERNEL_TREE
                || !self.old_utxos.is_empty()
                || self.proof.keys() != &kernels[start..end]
            {
                return Err(EconomicStateError::InvalidProof);
            }
            let absent = vec![false; end - start];
            let present = vec![true; end - start];
            (
                EconomicRoots {
                    utxo_root: roots.utxo_root,
                    kernel_root: self.proof.update_kernel_root(
                        roots.kernel_root,
                        &absent,
                        &present,
                    )?,
                },
                effects.len() + end,
            )
        };
        Ok(EconomicChunkExecution {
            roots: next_roots,
            next_cursor: u32::try_from(next_cursor)
                .map_err(|_| EconomicStateError::InvalidProof)?,
            total_effects: u32::try_from(total).map_err(|_| EconomicStateError::InvalidProof)?,
        })
    }

    /// Encode the unique bounded `UDECCW01` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EconomicStateError> {
        self.validate()?;
        let proof = self.proof.to_bytes()?;
        let mut bytes = Vec::with_capacity(HEADER_BYTES + proof.len() + self.old_utxos.len() * 10);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.cursor.to_be_bytes());
        bytes.extend_from_slice(
            &u32::try_from(proof.len())
                .map_err(|_| EconomicStateError::InvalidProof)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.old_utxos.len())
                .map_err(|_| EconomicStateError::InvalidProof)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&proof);
        for value in &self.old_utxos {
            match value {
                Some(value) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&value.created_height.to_be_bytes());
                    bytes.push(u8::from(value.is_coinbase));
                }
                None => bytes.push(0),
            }
        }
        if bytes.len() > MAX_ECONOMIC_CHUNK_WITNESS_BYTES {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(bytes)
    }

    /// Decode and canonically revalidate one exact `UDECCW01` witness.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EconomicStateError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > MAX_ECONOMIC_CHUNK_WITNESS_BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || u16::from_be_bytes(economic_array(bytes, 8)?) != VERSION
        {
            return Err(EconomicStateError::InvalidProof);
        }
        let cursor = u32::from_be_bytes(economic_array(bytes, 10)?);
        let proof_len = usize::try_from(u32::from_be_bytes(economic_array(bytes, 14)?))
            .map_err(|_| EconomicStateError::InvalidProof)?;
        let old_count = usize::try_from(u32::from_be_bytes(economic_array(bytes, 18)?))
            .map_err(|_| EconomicStateError::InvalidProof)?;
        if old_count > MAX_ECONOMIC_CHUNK_KEYS {
            return Err(EconomicStateError::InvalidProof);
        }
        let proof_end = HEADER_BYTES
            .checked_add(proof_len)
            .ok_or(EconomicStateError::InvalidProof)?;
        let proof = EconomicMultiProof::from_bytes(
            bytes
                .get(HEADER_BYTES..proof_end)
                .ok_or(EconomicStateError::InvalidProof)?,
        )?;
        let mut old_utxos = Vec::with_capacity(old_count);
        let mut position = proof_end;
        for _ in 0..old_count {
            let flag = *bytes
                .get(position)
                .ok_or(EconomicStateError::InvalidProof)?;
            position += 1;
            old_utxos.push(match flag {
                0 => None,
                1 => {
                    let created_height = u64::from_be_bytes(economic_array(bytes, position)?);
                    let coinbase = *bytes
                        .get(position + 8)
                        .ok_or(EconomicStateError::InvalidProof)?;
                    if coinbase > 1 {
                        return Err(EconomicStateError::InvalidProof);
                    }
                    position += 9;
                    Some(EconomicUtxo {
                        created_height,
                        is_coinbase: coinbase == 1,
                    })
                }
                _ => return Err(EconomicStateError::InvalidProof),
            });
        }
        if position != bytes.len() {
            return Err(EconomicStateError::InvalidProof);
        }
        let witness = Self {
            cursor,
            proof,
            old_utxos,
        };
        witness.validate()?;
        if witness.to_bytes()?.as_slice() != bytes {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(witness)
    }

    fn validate(&self) -> Result<(), EconomicStateError> {
        self.proof.validate()?;
        if self.proof.keys.is_empty()
            || self.proof.keys.len() > MAX_ECONOMIC_CHUNK_KEYS
            || (self.proof.tree == UTXO_TREE && self.old_utxos.len() != self.proof.keys.len())
            || (self.proof.tree == KERNEL_TREE && !self.old_utxos.is_empty())
        {
            return Err(EconomicStateError::InvalidProof);
        }
        Ok(())
    }
}

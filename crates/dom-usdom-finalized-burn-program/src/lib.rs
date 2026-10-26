//! Deterministic proving-program boundary for one finalized native USDOM burn.
//!
//! `UDFINL04` composes two proof responsibilities. The mandatory recursive
//! checkpoint-outer receipt proves the DOM consensus transition and confirmation
//! suffix. The Ethereum witness independently authenticates that the pinned
//! registry published the same checkpoint under Ethereum finality. This program
//! then proves that one exact burn obligation is included in that native USDOM
//! state root. It deliberately has no node database, network, clock, filesystem,
//! randomness or prover-backend API.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::{error::Error, fmt};

use dom_core::{
    blake2b_256_tagged, Hash256, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST,
    NETWORK_MAGIC_TESTNET,
};
use dom_usdom_checkpoint_statement::CHECKPOINT_STATEMENT_V6_BYTES;
pub use dom_usdom_checkpoint_statement::{CheckpointStatement, CheckpointStatementV6};
use dom_usdom_privacy::privacy_policy_hash;
use dom_usdom_state::{
    BridgeIdentity, BurnStateWitnessV2, NativeUsdomState, MAX_BURN_STATE_WITNESS_V2_BYTES,
};
use sha3::{Digest, Keccak256};
use usdom_ethereum_finality_experiment::checkpoints::{
    checkpoint_witness_replay_slot, verify_checkpoint_witness, StaticCheckpointTrustPolicy,
    VerifiedCheckpoint, MAX_CHECKPOINT_WITNESS_BYTES, STATIC_CHECKPOINT_TRUST_POLICY_BYTES,
};

const FINALIZED_BURN_PROVER_MAGIC: &[u8; 8] = b"UDFINL04";
const FINALIZED_BURN_PROVER_HEADER_BYTES: usize = 8
    + 2
    + 32
    + 8
    + ACTIVATION_SCHEDULE_BYTES
    + CHECKPOINT_STATEMENT_V6_BYTES
    + STATIC_CHECKPOINT_TRUST_POLICY_BYTES
    + 4
    + 4;
const ACTIVATION_SCHEDULE_MAGIC: &[u8; 8] = b"UDACTV01";
const ACTIVATION_SCHEDULE_VERSION: u16 = 1;
const ACTIVATION_SCHEDULE_BYTES: usize = 86;
const ACTIVATION_SCHEDULE_TAG: &str = "DOM:usdom-v4-activation-schedule:v1";
const FINALIZED_BURN_STATEMENT_TYPE: &str = "FinalizedBurn(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil,uint256 ethereumChainId,address reserve,bytes32 activationScheduleCommitment)";

/// Canonical `UDFINL04` finalized-burn private-input version.
pub const FINALIZED_BURN_PROVER_INPUT_VERSION: u16 = 4;
/// Exact byte length committed as the public output of the proving program.
pub const FINALIZED_BURN_PUBLIC_OUTPUT_BYTES: usize = 32;
/// Semantic version of the exact unframed 32-byte public output.
pub const FINALIZED_BURN_PUBLIC_OUTPUT_VERSION: u16 = 1;
/// Maximum canonical `UDFINL04` input.
pub const MAX_FINALIZED_BURN_PROVER_INPUT_BYTES: usize = FINALIZED_BURN_PROVER_HEADER_BYTES
    + MAX_BURN_STATE_WITNESS_V2_BYTES
    + MAX_CHECKPOINT_WITNESS_BYTES;

/// Pinned ImageID of the reviewed checkpoint-outer guest whose receipt proves
/// the complete DOM consensus transition and confirmation suffix.
pub const CHECKPOINT_OUTER_IMAGE_ID: [u8; 32] = [
    0xe5, 0x9d, 0x68, 0x48, 0x73, 0x86, 0x93, 0x9b, 0x2a, 0xc3, 0x79, 0xf0, 0x45, 0x28, 0xac, 0xb6,
    0xb3, 0x13, 0x86, 0x97, 0xe1, 0x7a, 0xdf, 0xda, 0x3a, 0xd2, 0x3e, 0xbe, 0x19, 0x5a, 0xf3, 0xdf,
];

/// Failure to decode or execute the fixed finalized-burn relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramError {
    /// The private input is empty or exceeds its fixed byte limit.
    InvalidInputLength,
    /// The private input framing, lengths or canonical encoding are invalid.
    InvalidEncoding,
    /// The activation schedule is invalid or does not commit the bridge state.
    InvalidActivationSchedule,
    /// The burn inclusion witness is invalid.
    InvalidBurnWitness,
    /// The Ethereum checkpoint witness or opaque verified checkpoint is invalid.
    InvalidCheckpoint,
    /// The burn, checkpoint, bridge and public statement do not bind together.
    InvalidBinding,
    /// A public output is not exactly one nonzero 32-byte statement hash.
    InvalidPublicOutput,
}

impl fmt::Display for ProgramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInputLength => "invalid finalized-burn program input length",
            Self::InvalidEncoding => "invalid finalized-burn program encoding",
            Self::InvalidActivationSchedule => "invalid finalized-burn activation schedule",
            Self::InvalidBurnWitness => "invalid finalized-burn state witness",
            Self::InvalidCheckpoint => "invalid finalized-burn checkpoint witness",
            Self::InvalidBinding => "finalized-burn relations do not bind",
            Self::InvalidPublicOutput => "invalid finalized-burn program public output",
        })
    }
}

impl Error for ProgramError {}

/// The exact native activation schedule committed by the reserve release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationSchedule {
    network_magic: u32,
    chain_id: Hash256,
    first_v4_height: u64,
    empty_state_root: Hash256,
}

impl ActivationSchedule {
    /// Construct the canonical schedule and bind its empty root to `bridge`.
    pub fn new(
        network_magic: u32,
        chain_id: Hash256,
        first_v4_height: u64,
        bridge: BridgeIdentity,
    ) -> Result<Self, ProgramError> {
        let empty_state_root = NativeUsdomState::new(bridge)
            .map_err(|_| ProgramError::InvalidActivationSchedule)?
            .state_root();
        let schedule = Self {
            network_magic,
            chain_id,
            first_v4_height,
            empty_state_root,
        };
        schedule.validate_fields()?;
        schedule.validate_bridge(bridge)?;
        Ok(schedule)
    }

    /// DOM network magic fixed by this schedule.
    pub const fn network_magic(self) -> u32 {
        self.network_magic
    }

    /// DOM chain identity fixed by this schedule.
    pub const fn chain_id(self) -> Hash256 {
        self.chain_id
    }

    /// First height governed by the native USDOM v4 rules.
    pub const fn first_v4_height(self) -> u64 {
        self.first_v4_height
    }

    /// Empty native state root fixed at activation.
    pub const fn empty_state_root(self) -> Hash256 {
        self.empty_state_root
    }

    /// Domain-separated commitment consumed by the Ethereum reserve.
    pub fn commitment(self) -> Hash256 {
        blake2b_256_tagged(ACTIVATION_SCHEDULE_TAG, &self.to_bytes())
    }

    /// Encode the exact fixed-width `UDACTV01` schedule.
    pub fn to_bytes(self) -> [u8; ACTIVATION_SCHEDULE_BYTES] {
        let mut bytes = [0u8; ACTIVATION_SCHEDULE_BYTES];
        bytes[..8].copy_from_slice(ACTIVATION_SCHEDULE_MAGIC);
        bytes[8..10].copy_from_slice(&ACTIVATION_SCHEDULE_VERSION.to_be_bytes());
        bytes[10..14].copy_from_slice(&self.network_magic.to_be_bytes());
        bytes[14..46].copy_from_slice(self.chain_id.as_bytes());
        bytes[46..54].copy_from_slice(&self.first_v4_height.to_be_bytes());
        bytes[54..86].copy_from_slice(self.empty_state_root.as_bytes());
        bytes
    }

    /// Decode the exact fixed-width `UDACTV01` schedule.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() != ACTIVATION_SCHEDULE_BYTES
            || &bytes[..8] != ACTIVATION_SCHEDULE_MAGIC
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidEncoding)?,
            ) != ACTIVATION_SCHEDULE_VERSION
        {
            return Err(ProgramError::InvalidActivationSchedule);
        }
        let schedule = Self {
            network_magic: u32::from_be_bytes(
                bytes[10..14]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidEncoding)?,
            ),
            chain_id: Hash256::from_bytes(
                bytes[14..46]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidEncoding)?,
            ),
            first_v4_height: u64::from_be_bytes(
                bytes[46..54]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidEncoding)?,
            ),
            empty_state_root: Hash256::from_bytes(
                bytes[54..86]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidEncoding)?,
            ),
        };
        schedule.validate_fields()?;
        if schedule.to_bytes().as_slice() != bytes {
            return Err(ProgramError::InvalidActivationSchedule);
        }
        Ok(schedule)
    }

    fn validate_fields(self) -> Result<(), ProgramError> {
        if !matches!(
            self.network_magic,
            NETWORK_MAGIC_MAINNET | NETWORK_MAGIC_TESTNET | NETWORK_MAGIC_REGTEST
        ) || self.chain_id == Hash256::ZERO
            || self.first_v4_height == 0
            || self.empty_state_root == Hash256::ZERO
        {
            return Err(ProgramError::InvalidActivationSchedule);
        }
        Ok(())
    }

    fn validate_bridge(self, bridge: BridgeIdentity) -> Result<(), ProgramError> {
        if bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes()
            || NativeUsdomState::new(bridge)
                .map_err(|_| ProgramError::InvalidActivationSchedule)?
                .state_root()
                != self.empty_state_root
        {
            return Err(ProgramError::InvalidActivationSchedule);
        }
        Ok(())
    }
}

/// The sole public value committed by a successful finalized-burn proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FinalizedBurnPublicOutput([u8; FINALIZED_BURN_PUBLIC_OUTPUT_BYTES]);

impl FinalizedBurnPublicOutput {
    /// Parse the exact nonzero public output with no framing or trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        let value: [u8; FINALIZED_BURN_PUBLIC_OUTPUT_BYTES] = bytes
            .try_into()
            .map_err(|_| ProgramError::InvalidPublicOutput)?;
        if value.iter().all(|byte| *byte == 0) {
            return Err(ProgramError::InvalidPublicOutput);
        }
        Ok(Self(value))
    }

    /// Return the exact bytes an EVM verifier must compare with its statement.
    pub const fn as_bytes(&self) -> &[u8; FINALIZED_BURN_PUBLIC_OUTPUT_BYTES] {
        &self.0
    }

    /// Consume the value and return its exact unframed bytes.
    pub const fn into_bytes(self) -> [u8; FINALIZED_BURN_PUBLIC_OUTPUT_BYTES] {
        self.0
    }
}

/// Exact recursive checkpoint receipt required by the finalized-burn guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointOuterReceiptAssumption {
    image_id: [u8; 32],
    journal: [u8; 32],
}

impl CheckpointOuterReceiptAssumption {
    /// Pinned checkpoint-outer guest ImageID.
    pub const fn image_id(&self) -> &[u8; 32] {
        &self.image_id
    }

    /// Exact checkpoint statement hash required as the recursive journal.
    pub const fn journal(&self) -> &[u8; 32] {
        &self.journal
    }
}

/// Fully checked host relation plus its mandatory recursive receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedBurnExecution {
    output: FinalizedBurnPublicOutput,
    checkpoint_receipt: CheckpointOuterReceiptAssumption,
}

impl FinalizedBurnExecution {
    /// Public finalized-burn statement committed by the guest.
    pub const fn output(&self) -> FinalizedBurnPublicOutput {
        self.output
    }

    /// Recursive checkpoint proof that the guest must verify before commit.
    pub const fn checkpoint_receipt(&self) -> CheckpointOuterReceiptAssumption {
        self.checkpoint_receipt
    }
}

/// Exact public values consumed by the immutable Ethereum reserve. This value
/// exposes no note openings, sender, source deposit or private transfer path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalizedBurnStatement {
    /// Native nullifier-derived burn identifier.
    pub burn_id: [u8; 32],
    /// Wallet-selected globally unique reserve request identifier.
    pub request_id: [u8; 32],
    /// Immutable Ethereum payout address.
    pub recipient: [u8; 20],
    /// Public payout amount in six-decimal token base units.
    pub amount: u64,
    /// Native bridge domain committed by the activation state.
    pub dom_domain: [u8; 32],
    /// Height of the authenticated DOM block containing the burn.
    pub height: u64,
    /// Canonical DOM block identifier.
    pub block_hash: Hash256,
    /// Native USDOM state root after the containing transition batch.
    pub state_root: Hash256,
    /// Latest authenticated Ethereum-finalized Beacon slot.
    pub finality_beacon_slot: u64,
    /// Last Ethereum timestamp at which the reserve may admit the proof.
    pub valid_until: u64,
    /// Target EVM chain identifier as one uint256 big-endian ABI word.
    pub ethereum_chain_id: [u8; 32],
    /// Immutable target reserve address.
    pub reserve: [u8; 20],
    /// Exact activation schedule selected by the verifier release.
    pub activation_schedule_commitment: Hash256,
}

impl FinalizedBurnStatement {
    /// Compute `keccak256(abi.encode(...))` byte-for-byte as Solidity does.
    pub fn statement_hash(self) -> Hash256 {
        let type_hash = Keccak256::digest(FINALIZED_BURN_STATEMENT_TYPE.as_bytes());
        let mut encoded = Vec::with_capacity(14 * 32);
        encoded.extend_from_slice(&type_hash);
        encoded.extend_from_slice(&self.burn_id);
        encoded.extend_from_slice(&self.request_id);
        encoded.extend_from_slice(&[0; 12]);
        encoded.extend_from_slice(&self.recipient);
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.amount.to_be_bytes());
        encoded.extend_from_slice(&self.dom_domain);
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.height.to_be_bytes());
        encoded.extend_from_slice(self.block_hash.as_bytes());
        encoded.extend_from_slice(self.state_root.as_bytes());
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.finality_beacon_slot.to_be_bytes());
        encoded.extend_from_slice(&[0; 24]);
        encoded.extend_from_slice(&self.valid_until.to_be_bytes());
        encoded.extend_from_slice(&self.ethereum_chain_id);
        encoded.extend_from_slice(&[0; 12]);
        encoded.extend_from_slice(&self.reserve);
        encoded.extend_from_slice(self.activation_schedule_commitment.as_bytes());
        Hash256::from_bytes(Keccak256::digest(encoded).into())
    }
}

/// Canonical private input for the portable finalized-burn program.
#[derive(Debug, Clone)]
pub struct FinalizedBurnProverInput {
    statement_hash: Hash256,
    max_current_slot: u64,
    activation_schedule: ActivationSchedule,
    checkpoint_statement: CheckpointStatementV6,
    checkpoint_policy: StaticCheckpointTrustPolicy,
    burn_witness_bytes: Vec<u8>,
    checkpoint_witness_bytes: Vec<u8>,
}

impl FinalizedBurnProverInput {
    /// Build and fully verify one canonical `UDFINL04` input.
    pub fn new(
        activation_schedule: ActivationSchedule,
        checkpoint_policy: StaticCheckpointTrustPolicy,
        checkpoint_statement: CheckpointStatementV6,
        burn_witness_bytes: Vec<u8>,
        checkpoint_witness_bytes: Vec<u8>,
    ) -> Result<Self, ProgramError> {
        let max_current_slot = checkpoint_witness_replay_slot(&checkpoint_witness_bytes)
            .map_err(|_| ProgramError::InvalidCheckpoint)?;
        let mut input = Self {
            statement_hash: Hash256::ZERO,
            max_current_slot,
            activation_schedule,
            checkpoint_statement,
            checkpoint_policy,
            burn_witness_bytes,
            checkpoint_witness_bytes,
        };
        let output = input.verify_raw_checkpoint()?;
        input.statement_hash = Hash256::from_bytes(output.into_bytes());
        input.to_bytes()?;
        Ok(input)
    }

    /// Exact Solidity-compatible public statement hash.
    pub const fn statement_hash(&self) -> Hash256 {
        self.statement_hash
    }

    /// Complete DOM consensus statement whose outer receipt is mandatory.
    pub const fn checkpoint_statement(&self) -> &CheckpointStatementV6 {
        &self.checkpoint_statement
    }

    /// Reexecute the raw checkpoint and native-state relation and return only
    /// the exact public burn fields required to build Ethereum calldata.
    pub fn public_statement(&self) -> Result<FinalizedBurnStatement, ProgramError> {
        let dynamic_policy = self
            .checkpoint_policy
            .at_max_current_slot(self.max_current_slot)
            .map_err(|_| ProgramError::InvalidCheckpoint)?;
        let checkpoint = verify_checkpoint_witness(&self.checkpoint_witness_bytes, &dynamic_policy)
            .map_err(|_| ProgramError::InvalidCheckpoint)?;
        let burn_witness = BurnStateWitnessV2::from_bytes(&self.burn_witness_bytes)
            .map_err(|_| ProgramError::InvalidBurnWitness)?;
        finalized_burn_statement(
            self.activation_schedule,
            &self.checkpoint_policy,
            &self.checkpoint_statement,
            &burn_witness,
            &checkpoint,
        )
    }

    /// Encode the unique bounded `UDFINL04` transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProgramError> {
        if self.statement_hash == Hash256::ZERO || self.max_current_slot == 0 {
            return Err(ProgramError::InvalidEncoding);
        }
        let burn_len: u32 = self
            .burn_witness_bytes
            .len()
            .try_into()
            .map_err(|_| ProgramError::InvalidInputLength)?;
        let checkpoint_len: u32 = self
            .checkpoint_witness_bytes
            .len()
            .try_into()
            .map_err(|_| ProgramError::InvalidInputLength)?;
        let total = FINALIZED_BURN_PROVER_HEADER_BYTES
            .checked_add(self.burn_witness_bytes.len())
            .and_then(|value| value.checked_add(self.checkpoint_witness_bytes.len()))
            .ok_or(ProgramError::InvalidInputLength)?;
        if total > MAX_FINALIZED_BURN_PROVER_INPUT_BYTES
            || self.burn_witness_bytes.len() > MAX_BURN_STATE_WITNESS_V2_BYTES
            || self.checkpoint_witness_bytes.len() > MAX_CHECKPOINT_WITNESS_BYTES
        {
            return Err(ProgramError::InvalidInputLength);
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(FINALIZED_BURN_PROVER_MAGIC);
        bytes.extend_from_slice(&FINALIZED_BURN_PROVER_INPUT_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.statement_hash.as_bytes());
        bytes.extend_from_slice(&self.max_current_slot.to_be_bytes());
        bytes.extend_from_slice(&self.activation_schedule.to_bytes());
        bytes.extend_from_slice(
            &self
                .checkpoint_statement
                .to_bytes()
                .map_err(|_| ProgramError::InvalidCheckpoint)?,
        );
        bytes.extend_from_slice(&self.checkpoint_policy.to_bytes());
        bytes.extend_from_slice(&burn_len.to_be_bytes());
        bytes.extend_from_slice(&checkpoint_len.to_be_bytes());
        bytes.extend_from_slice(&self.burn_witness_bytes);
        bytes.extend_from_slice(&self.checkpoint_witness_bytes);
        Ok(bytes)
    }

    /// Decode, canonically re-encode and fully reexecute one `UDFINL04` input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() < FINALIZED_BURN_PROVER_HEADER_BYTES
            || bytes.len() > MAX_FINALIZED_BURN_PROVER_INPUT_BYTES
            || &bytes[..8] != FINALIZED_BURN_PROVER_MAGIC
        {
            return Err(ProgramError::InvalidEncoding);
        }
        let version = u16::from_be_bytes(
            bytes[8..10]
                .try_into()
                .map_err(|_| ProgramError::InvalidEncoding)?,
        );
        if version != FINALIZED_BURN_PROVER_INPUT_VERSION {
            return Err(ProgramError::InvalidEncoding);
        }
        let statement_hash = Hash256::from_bytes(
            bytes[10..42]
                .try_into()
                .map_err(|_| ProgramError::InvalidEncoding)?,
        );
        let max_current_slot = u64::from_be_bytes(
            bytes[42..50]
                .try_into()
                .map_err(|_| ProgramError::InvalidEncoding)?,
        );
        if statement_hash == Hash256::ZERO || max_current_slot == 0 {
            return Err(ProgramError::InvalidEncoding);
        }
        let schedule_end = 50 + ACTIVATION_SCHEDULE_BYTES;
        let activation_schedule = ActivationSchedule::from_bytes(&bytes[50..schedule_end])?;
        let statement_end = schedule_end + CHECKPOINT_STATEMENT_V6_BYTES;
        let checkpoint_statement = CheckpointStatementV6::from_bytes(
            bytes
                .get(schedule_end..statement_end)
                .ok_or(ProgramError::InvalidEncoding)?,
        )
        .map_err(|_| ProgramError::InvalidCheckpoint)?;
        let policy_end = statement_end + STATIC_CHECKPOINT_TRUST_POLICY_BYTES;
        let checkpoint_policy =
            StaticCheckpointTrustPolicy::from_bytes(&bytes[statement_end..policy_end])
                .map_err(|_| ProgramError::InvalidEncoding)?;
        let burn_len_end = policy_end + 4;
        let burn_len = u32::from_be_bytes(
            bytes[policy_end..burn_len_end]
                .try_into()
                .map_err(|_| ProgramError::InvalidEncoding)?,
        ) as usize;
        let checkpoint_len_end = burn_len_end + 4;
        let checkpoint_len = u32::from_be_bytes(
            bytes[burn_len_end..checkpoint_len_end]
                .try_into()
                .map_err(|_| ProgramError::InvalidEncoding)?,
        ) as usize;
        if burn_len > MAX_BURN_STATE_WITNESS_V2_BYTES
            || checkpoint_len > MAX_CHECKPOINT_WITNESS_BYTES
        {
            return Err(ProgramError::InvalidInputLength);
        }
        let burn_end = checkpoint_len_end
            .checked_add(burn_len)
            .ok_or(ProgramError::InvalidInputLength)?;
        let checkpoint_end = burn_end
            .checked_add(checkpoint_len)
            .ok_or(ProgramError::InvalidInputLength)?;
        if checkpoint_end != bytes.len() {
            return Err(ProgramError::InvalidEncoding);
        }
        let input = Self {
            statement_hash,
            max_current_slot,
            activation_schedule,
            checkpoint_statement,
            checkpoint_policy,
            burn_witness_bytes: bytes[checkpoint_len_end..burn_end].to_vec(),
            checkpoint_witness_bytes: bytes[burn_end..checkpoint_end].to_vec(),
        };
        if checkpoint_witness_replay_slot(&input.checkpoint_witness_bytes)
            .map_err(|_| ProgramError::InvalidCheckpoint)?
            != input.max_current_slot
        {
            return Err(ProgramError::InvalidCheckpoint);
        }
        let output = input.verify_raw_checkpoint()?;
        if output.as_bytes() != input.statement_hash.as_bytes()
            || input.to_bytes()?.as_slice() != bytes
        {
            return Err(ProgramError::InvalidBinding);
        }
        Ok(input)
    }

    fn verify_raw_checkpoint(&self) -> Result<FinalizedBurnPublicOutput, ProgramError> {
        let dynamic_policy = self
            .checkpoint_policy
            .at_max_current_slot(self.max_current_slot)
            .map_err(|_| ProgramError::InvalidCheckpoint)?;
        let checkpoint = verify_checkpoint_witness(&self.checkpoint_witness_bytes, &dynamic_policy)
            .map_err(|_| ProgramError::InvalidCheckpoint)?;
        let burn_witness = BurnStateWitnessV2::from_bytes(&self.burn_witness_bytes)
            .map_err(|_| ProgramError::InvalidBurnWitness)?;
        verify_finalized_burn_inclusion(
            self.activation_schedule,
            &self.checkpoint_policy,
            &self.checkpoint_statement,
            &burn_witness,
            &checkpoint,
        )
    }
}

/// Verify the deterministic burn, event and checkpoint-statement binding.
/// Recursive receipt authority is deliberately added only by
/// [`execute_with_checkpoint_assumption`] and discharged by the zkVM guest.
fn verify_finalized_burn_inclusion(
    activation_schedule: ActivationSchedule,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    checkpoint_statement: &CheckpointStatementV6,
    burn_witness: &BurnStateWitnessV2,
    checkpoint: &VerifiedCheckpoint,
) -> Result<FinalizedBurnPublicOutput, ProgramError> {
    let statement = finalized_burn_statement(
        activation_schedule,
        checkpoint_policy,
        checkpoint_statement,
        burn_witness,
        checkpoint,
    )?;
    FinalizedBurnPublicOutput::from_bytes(statement.statement_hash().as_bytes())
}

fn finalized_burn_statement(
    activation_schedule: ActivationSchedule,
    checkpoint_policy: &StaticCheckpointTrustPolicy,
    checkpoint_statement: &CheckpointStatementV6,
    burn_witness: &BurnStateWitnessV2,
    checkpoint: &VerifiedCheckpoint,
) -> Result<FinalizedBurnStatement, ProgramError> {
    let state = &burn_witness.state;
    let state_root = state.root();
    if state_root == Hash256::ZERO || !burn_witness.verify(state_root) {
        return Err(ProgramError::InvalidBurnWitness);
    }
    let bridge = BridgeIdentity {
        dom_domain: state.domain,
        ethereum_genesis_validators_root: state.ethereum_genesis_validators_root,
        ethereum_chain_id: state.ethereum_chain_id,
        ethereum_checkpoint_policy_hash: state.ethereum_checkpoint_policy_hash,
        ethereum_deposit_policy_hash: state.ethereum_deposit_policy_hash,
        privacy_policy_hash: state.privacy_policy_hash,
        privacy_verifier_config_hash: state.privacy_verifier_config_hash,
        reserve: state.reserve,
        burn_timing: state.burn_timing,
    };
    activation_schedule.validate_fields()?;
    activation_schedule.validate_bridge(bridge)?;

    let policy = checkpoint_policy.checkpoint();
    let policy_hash: [u8; 32] = checkpoint_policy.policy_hash().into();
    let mut chain_id_word = [0u8; 32];
    chain_id_word[24..].copy_from_slice(&policy.ethereum_chain_id.to_be_bytes());
    if policy.dom_network_magic != activation_schedule.network_magic
        || policy.bridge_domain.as_slice() != state.domain
        || policy.ethereum_genesis_validators_root.as_slice()
            != state.ethereum_genesis_validators_root
        || chain_id_word != state.ethereum_chain_id
        || policy_hash != state.ethereum_checkpoint_policy_hash
    {
        return Err(ProgramError::InvalidBinding);
    }

    let record = checkpoint.record();
    let dom_height = u64::from_be_bytes(
        record[1..9]
            .try_into()
            .map_err(|_| ProgramError::InvalidCheckpoint)?,
    );
    let dom_network_magic = u32::from_be_bytes(
        record[73..77]
            .try_into()
            .map_err(|_| ProgramError::InvalidCheckpoint)?,
    );
    let ethereum_chain_id = u64::from_be_bytes(
        record[77..85]
            .try_into()
            .map_err(|_| ProgramError::InvalidCheckpoint)?,
    );
    let event_execution_block = u64::from_be_bytes(
        record[85..93]
            .try_into()
            .map_err(|_| ProgramError::InvalidCheckpoint)?,
    );
    let event_beacon_slot = u64::from_be_bytes(
        record[189..197]
            .try_into()
            .map_err(|_| ProgramError::InvalidCheckpoint)?,
    );
    let finalized = checkpoint.finalized_execution();
    checkpoint_statement
        .validate()
        .map_err(|_| ProgramError::InvalidCheckpoint)?;
    let consensus = &checkpoint_statement.checkpoint;
    let registry: [u8; 20] = policy
        .registry
        .as_slice()
        .try_into()
        .map_err(|_| ProgramError::InvalidCheckpoint)?;
    if record[0] != 2
        || dom_height < activation_schedule.first_v4_height
        || record[9..41].iter().all(|byte| *byte == 0)
        || record[41..73] != state_root.as_bytes()[..]
        || dom_network_magic != activation_schedule.network_magic
        || ethereum_chain_id != policy.ethereum_chain_id
        || record[229..261] != state.ethereum_genesis_validators_root
        || record[269..289] != policy.registry.as_slice()[..]
        || record[289..321] != policy.runtime_code_hash.as_slice()[..]
        || record[321..353] != policy.checkpoint_config_hash.as_slice()[..]
        || record[353..385] != state.domain
        || record[385..417].iter().all(|byte| *byte == 0)
        || checkpoint.trust_policy_hash().as_slice() != state.ethereum_checkpoint_policy_hash
        || event_execution_block == 0
        || event_beacon_slot == 0
        || record[93..125].iter().all(|byte| *byte == 0)
        || finalized.block_number < event_execution_block
        || finalized.beacon_slot < event_beacon_slot
        || finalized
            .block_hash
            .as_slice()
            .iter()
            .all(|byte| *byte == 0)
        || finalized
            .beacon_root
            .as_slice()
            .iter()
            .all(|byte| *byte == 0)
        || finalized.timestamp == 0
        || consensus.bridge_domain != state.domain
        || consensus.dom_network_magic != dom_network_magic
        || consensus.height != dom_height
        || consensus.block.as_slice() != &record[9..41]
        || consensus.state_root != *state_root.as_bytes()
        || checkpoint_statement.total_issued != state.total_issued
        || checkpoint_statement.total_burned != state.total_burned
        || checkpoint_statement.issuance_closed != state.issuance_closure.is_some()
        || consensus.ethereum_chain_id != state.ethereum_chain_id
        || consensus.registry != registry
        || consensus.activation_schedule_commitment != *activation_schedule.commitment().as_bytes()
        || consensus.checkpoint_config_hash.as_slice() != &record[321..353]
    {
        return Err(ProgramError::InvalidCheckpoint);
    }

    let burn = burn_witness.burn;
    if burn.burn_id == [0; 32]
        || burn.request_id == [0; 32]
        || burn.recipient == [0; 20]
        || burn.amount == 0
        || burn.valid_until == 0
        || burn.ethereum_chain_id != state.ethereum_chain_id
        || burn.reserve != state.reserve
        || burn.obligation_commitment != burn.expected_obligation_commitment(state.domain)
    {
        return Err(ProgramError::InvalidBinding);
    }
    let statement = FinalizedBurnStatement {
        burn_id: burn.burn_id,
        request_id: burn.request_id,
        recipient: burn.recipient,
        amount: burn.amount,
        dom_domain: state.domain,
        height: dom_height,
        block_hash: Hash256::from_bytes(
            record[9..41]
                .try_into()
                .map_err(|_| ProgramError::InvalidCheckpoint)?,
        ),
        state_root,
        finality_beacon_slot: finalized.beacon_slot,
        valid_until: burn.valid_until,
        ethereum_chain_id: state.ethereum_chain_id,
        reserve: state.reserve,
        activation_schedule_commitment: activation_schedule.commitment(),
    };
    Ok(statement)
}

/// Reexecute one complete portable `UDFINL04` input and derive the mandatory
/// recursive checkpoint receipt. A proving guest must verify the returned
/// assumption before committing the burn output.
pub fn execute_with_checkpoint_assumption(
    input: &[u8],
) -> Result<FinalizedBurnExecution, ProgramError> {
    if input.is_empty() || input.len() > MAX_FINALIZED_BURN_PROVER_INPUT_BYTES {
        return Err(ProgramError::InvalidInputLength);
    }
    let verified = FinalizedBurnProverInput::from_bytes(input)?;
    let output = FinalizedBurnPublicOutput::from_bytes(verified.statement_hash().as_bytes())?;
    Ok(FinalizedBurnExecution {
        output,
        checkpoint_receipt: checkpoint_receipt_assumption(&verified.checkpoint_statement)?,
    })
}

fn checkpoint_receipt_assumption(
    statement: &CheckpointStatementV6,
) -> Result<CheckpointOuterReceiptAssumption, ProgramError> {
    let journal = statement
        .statement_hash()
        .map_err(|_| ProgramError::InvalidCheckpoint)?;
    Ok(CheckpointOuterReceiptAssumption {
        image_id: CHECKPOINT_OUTER_IMAGE_ID,
        journal,
    })
}

/// Host-reference execution of the deterministic relation.
///
/// This validates the exact recursive assumption but cannot discharge it.
/// Production proving must call [`execute_with_checkpoint_assumption`] inside
/// the zkVM and verify its receipt before committing this output.
pub fn execute(input: &[u8]) -> Result<FinalizedBurnPublicOutput, ProgramError> {
    Ok(execute_with_checkpoint_assumption(input)?.output())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::MAX_FUTURE_BLOCK_TIME;
    use dom_usdom_state::{
        derive_private_burn_id, unsafe_test_only_burn, unsafe_test_only_issuance, BlockContext,
        BurnRecord, BurnTimingPolicy, EthereumAnchor, IssuanceClosureRecord, VerifiedTransition,
    };
    use usdom_ethereum_finality_experiment::{
        checkpoints::{
            unsafe_test_only_verified_checkpoint,
            unsafe_test_only_verified_checkpoint_with_finality, CheckpointPolicy,
            CheckpointTrustPolicy,
        },
        EthereumFork, EthereumForks,
    };

    const DOMAIN: [u8; 32] = [0x11; 32];

    fn forks() -> EthereumForks {
        let fork = |epoch, version| EthereumFork {
            epoch,
            fork_version: [version, 0, 0, 0].into(),
        };
        EthereumForks {
            genesis: fork(0, 0),
            altair: fork(1, 1),
            bellatrix: fork(2, 2),
            capella: fork(3, 3),
            deneb: fork(4, 4),
            electra: fork(5, 5),
            fulu: fork(6, 6),
            gloas: fork(u64::MAX, 7),
        }
    }

    fn policy() -> StaticCheckpointTrustPolicy {
        StaticCheckpointTrustPolicy::from_trust_policy(&CheckpointTrustPolicy {
            trusted_checkpoint: [0x41; 32].into(),
            ethereum_genesis_validators_root: [0x22; 32].into(),
            forks: forks(),
            max_current_slot: 1,
            checkpoint: CheckpointPolicy {
                ethereum_chain_id: 1,
                ethereum_genesis_validators_root: [0x22; 32].into(),
                registry: [0x42; 20].into(),
                runtime_code_hash: [0x43; 32].into(),
                config_storage_slot: [0; 32].into(),
                checkpoint_config_hash: [0x45; 32].into(),
                bridge_domain: DOMAIN.into(),
                dom_network_magic: NETWORK_MAGIC_REGTEST,
            },
        })
        .unwrap()
    }

    fn bridge(policy: &StaticCheckpointTrustPolicy) -> BridgeIdentity {
        let mut chain_id = [0; 32];
        chain_id[31] = 1;
        BridgeIdentity {
            dom_domain: DOMAIN,
            ethereum_genesis_validators_root: [0x22; 32],
            ethereum_chain_id: chain_id,
            ethereum_checkpoint_policy_hash: policy.policy_hash().into(),
            ethereum_deposit_policy_hash: [0x46; 32],
            privacy_policy_hash: *privacy_policy_hash().as_bytes(),
            privacy_verifier_config_hash: [0x48; 32],
            reserve: [0x33; 20],
            burn_timing: BurnTimingPolicy {
                withdrawal_delay_secs: 86_400,
                min_execution_window_secs: 3_600,
                max_certificate_lifetime_secs: 604_800,
                relay_safety_margin_secs: 3_600,
                max_ethereum_anchor_age_secs: 1_800,
                max_dom_clock_lead_secs: MAX_FUTURE_BLOCK_TIME,
            },
        }
    }

    fn burn_witness(policy: &StaticCheckpointTrustPolicy) -> BurnStateWitnessV2 {
        let bridge = bridge(policy);
        let timestamp = 1_700_000_120;
        let mut state = NativeUsdomState::new(bridge).unwrap();
        let issuance = VerifiedTransition::Issue(unsafe_test_only_issuance(
            DOMAIN,
            [0x44; 32],
            [0x15; 32],
            1_000_000,
            EthereumAnchor {
                genesis_validators_root: [0x22; 32],
                execution_block_number: 20_000_000,
                execution_block_hash: [0x66; 32],
                execution_block_timestamp: 1_700_000_000,
                beacon_slot: 16_000_000,
                beacon_root: [0x77; 32],
            },
        ));
        state
            .apply_batch(BlockContext { timestamp }, &[issuance])
            .unwrap();
        let nullifiers = vec![[0x14; 32]];
        let burn_id = derive_private_burn_id(
            bridge,
            &nullifiers,
            [0x73; 20],
            250_000,
            timestamp + 100_000,
        )
        .unwrap();
        let mut record = BurnRecord {
            burn_id,
            request_id: [0x72; 32],
            amount: 250_000,
            recipient: [0x73; 20],
            ethereum_chain_id: bridge.ethereum_chain_id,
            reserve: bridge.reserve,
            valid_until: timestamp + 100_000,
            obligation_commitment: [0; 32],
        };
        record.obligation_commitment = record.expected_obligation_commitment(DOMAIN);
        let burn = VerifiedTransition::Burn(unsafe_test_only_burn(
            DOMAIN,
            state.note_anchor(),
            nullifiers,
            vec![[0x17; 32]],
            [0x0e; 32],
            record,
        ));
        state
            .apply_batch(BlockContext { timestamp }, &[burn])
            .unwrap();
        state.burn_state_witness_v2(&burn_id).unwrap().unwrap()
    }

    fn checkpoint(
        policy: &StaticCheckpointTrustPolicy,
        witness: &BurnStateWitnessV2,
    ) -> VerifiedCheckpoint {
        let mut record = [0u8; 417];
        record[0] = 2;
        record[1..9].copy_from_slice(&2u64.to_be_bytes());
        record[9..41].copy_from_slice(&[0x61; 32]);
        record[41..73].copy_from_slice(witness.state.root().as_bytes());
        record[73..77].copy_from_slice(&NETWORK_MAGIC_REGTEST.to_be_bytes());
        record[77..85].copy_from_slice(&1u64.to_be_bytes());
        record[85..93].copy_from_slice(&20_000_010u64.to_be_bytes());
        record[93..125].copy_from_slice(&[0xa1; 32]);
        record[125..157].copy_from_slice(&[0xa2; 32]);
        record[157..189].copy_from_slice(&[0xa3; 32]);
        record[189..197].copy_from_slice(&16_000_010u64.to_be_bytes());
        record[197..229].copy_from_slice(&[0xa4; 32]);
        record[229..261].copy_from_slice(&witness.state.ethereum_genesis_validators_root);
        record[261..265].copy_from_slice(&7u32.to_be_bytes());
        record[265..269].copy_from_slice(&3u32.to_be_bytes());
        let checkpoint = policy.checkpoint();
        record[269..289].copy_from_slice(checkpoint.registry.as_slice());
        record[289..321].copy_from_slice(checkpoint.runtime_code_hash.as_slice());
        record[321..353].copy_from_slice(checkpoint.checkpoint_config_hash.as_slice());
        record[353..385].copy_from_slice(&witness.state.domain);
        record[385..417].copy_from_slice(&[0xa8; 32]);
        unsafe_test_only_verified_checkpoint(record, 1_700_000_240, policy.policy_hash())
    }

    fn checkpoint_statement(
        policy: &StaticCheckpointTrustPolicy,
        witness: &BurnStateWitnessV2,
        schedule: ActivationSchedule,
    ) -> CheckpointStatementV6 {
        let mut previous_work = [0u8; 32];
        previous_work[31] = 1;
        let mut target_work = [0u8; 32];
        target_work[31] = 2;
        let mut confirmation_work = [0u8; 32];
        confirmation_work[31] = 3;
        let policy = policy.checkpoint();
        CheckpointStatementV6 {
            checkpoint: dom_usdom_checkpoint_statement::CheckpointStatement {
                bridge_domain: witness.state.domain,
                dom_network_magic: NETWORK_MAGIC_REGTEST,
                previous_height: 1,
                previous_block: [0x51; 32],
                previous_state_root: [0x52; 32],
                previous_context_hash: [0x53; 32],
                previous_total_difficulty: previous_work,
                height: 2,
                block: [0x61; 32],
                state_root: *witness.state.root().as_bytes(),
                context_hash: [0x62; 32],
                total_difficulty: target_work,
                confirmation_height: 3,
                confirmation_block: [0x63; 32],
                confirmation_total_difficulty: confirmation_work,
                confirmation_timestamp: 1_700_000_240,
                ethereum_chain_id: witness.state.ethereum_chain_id,
                registry: policy.registry.as_slice().try_into().unwrap(),
                activation_schedule_commitment: *schedule.commitment().as_bytes(),
                checkpoint_config_hash: policy
                    .checkpoint_config_hash
                    .as_slice()
                    .try_into()
                    .unwrap(),
            },
            total_issued: witness.state.total_issued,
            total_burned: witness.state.total_burned,
            issuance_closed: witness.state.issuance_closure.is_some(),
        }
    }

    fn with_valid_issuance_closure(
        mut witness: BurnStateWitnessV2,
        schedule: ActivationSchedule,
    ) -> BurnStateWitnessV2 {
        witness.state.issuance_closure = Some(IssuanceClosureRecord {
            reserve: witness.state.reserve,
            total_deposited: witness.state.total_issued,
            reserve_config_hash: [0xc1; 32],
            activation_schedule_commitment: *schedule.commitment().as_bytes(),
            ethereum_anchor: witness.state.ethereum_anchor.unwrap(),
            closure_policy_hash: [0xc2; 32],
        });
        assert!(witness.verify(witness.state.root()));
        witness
    }

    #[test]
    fn inclusion_relation_derives_exact_nonzero_statement_without_node_dependencies() {
        let policy = policy();
        let witness = burn_witness(&policy);
        let schedule = ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0x55; 32]),
            1,
            bridge(&policy),
        )
        .unwrap();
        let checkpoint = checkpoint(&policy, &witness);
        let statement = checkpoint_statement(&policy, &witness, schedule);
        let output =
            verify_finalized_burn_inclusion(schedule, &policy, &statement, &witness, &checkpoint)
                .unwrap();
        assert_ne!(output.as_bytes(), &[0; 32]);
        assert_eq!(
            hex::encode(output.as_bytes()),
            "5e5e60060758ff196baa0e169f3eaa91f8c25e7859f375f0c8f3308b44a5c022"
        );
    }

    #[test]
    fn recursive_checkpoint_assumption_pins_image_and_exact_statement_hash() {
        let policy = policy();
        let witness = burn_witness(&policy);
        let schedule = ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0x55; 32]),
            1,
            bridge(&policy),
        )
        .unwrap();
        let statement = checkpoint_statement(&policy, &witness, schedule);
        let assumption = checkpoint_receipt_assumption(&statement).unwrap();
        assert_eq!(assumption.image_id(), &CHECKPOINT_OUTER_IMAGE_ID);
        assert_eq!(assumption.journal(), &statement.statement_hash().unwrap());

        let mut changed = statement;
        changed.checkpoint.confirmation_block[0] ^= 1;
        let changed_assumption = checkpoint_receipt_assumption(&changed).unwrap();
        assert_ne!(changed_assumption.journal(), assumption.journal());
    }

    #[test]
    fn irreversible_historical_burn_remains_provable_under_later_finality() {
        let policy = policy();
        let witness = burn_witness(&policy);
        let schedule = ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0x55; 32]),
            1,
            bridge(&policy),
        )
        .unwrap();
        let original = checkpoint(&policy, &witness);
        let statement = checkpoint_statement(&policy, &witness, schedule);
        let original_output =
            verify_finalized_burn_inclusion(schedule, &policy, &statement, &witness, &original)
                .unwrap();

        let mut later_finality = original.finalized_execution().clone();
        later_finality.timestamp = witness.burn.valid_until + 30 * 86_400;
        later_finality.beacon_slot += 216_000;
        later_finality.block_number += 216_000;
        later_finality.block_hash = [0xb1; 32].into();
        later_finality.beacon_root = [0xb2; 32].into();
        later_finality.receipts_root = [0xb3; 32].into();
        later_finality.state_root = [0xb4; 32].into();
        let renewed = unsafe_test_only_verified_checkpoint_with_finality(
            *original.record(),
            later_finality.clone(),
            policy.policy_hash(),
        );

        assert!(later_finality.timestamp > witness.burn.valid_until);
        let renewed_output =
            verify_finalized_burn_inclusion(schedule, &policy, &statement, &witness, &renewed)
                .unwrap();
        assert_ne!(renewed_output, original_output);

        let expected = FinalizedBurnStatement {
            burn_id: witness.burn.burn_id,
            request_id: witness.burn.request_id,
            recipient: witness.burn.recipient,
            amount: witness.burn.amount,
            dom_domain: witness.state.domain,
            height: 2,
            block_hash: Hash256::from_bytes([0x61; 32]),
            state_root: witness.state.root(),
            finality_beacon_slot: later_finality.beacon_slot,
            valid_until: witness.burn.valid_until,
            ethereum_chain_id: witness.state.ethereum_chain_id,
            reserve: witness.state.reserve,
            activation_schedule_commitment: schedule.commitment(),
        };
        assert_eq!(
            renewed_output.as_bytes(),
            expected.statement_hash().as_bytes()
        );
    }

    #[test]
    fn finalized_burn_statement_hash_matches_solidity_vector() {
        let statement = FinalizedBurnStatement {
            burn_id: [0x11; 32],
            request_id: [0x22; 32],
            recipient: [0x33; 20],
            amount: 250_000,
            dom_domain: [0x44; 32],
            height: 100_360,
            block_hash: Hash256::from_bytes([0x55; 32]),
            state_root: Hash256::from_bytes([0x66; 32]),
            finality_beacon_slot: 16_000_010,
            valid_until: 1_700_100_120,
            ethereum_chain_id: {
                let mut word = [0; 32];
                word[31] = 1;
                word
            },
            reserve: [0x77; 20],
            activation_schedule_commitment: Hash256::from_bytes([0x88; 32]),
        };
        assert_eq!(
            statement.statement_hash(),
            Hash256::from_bytes([
                0xd0, 0xfb, 0xa5, 0xe6, 0xbd, 0x8c, 0x34, 0xe9, 0xf7, 0x30, 0xbd, 0x6b, 0x19, 0x8d,
                0x65, 0xf1, 0x62, 0x79, 0xd7, 0xc8, 0x5f, 0x93, 0x4e, 0xb0, 0x3b, 0x44, 0x97, 0x63,
                0x1d, 0xd8, 0x8d, 0x43,
            ])
        );
    }

    #[test]
    fn inclusion_relation_rejects_checkpoint_policy_schedule_and_state_substitution() {
        let policy = policy();
        let witness = burn_witness(&policy);
        let schedule = ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0x55; 32]),
            1,
            bridge(&policy),
        )
        .unwrap();
        let good = checkpoint(&policy, &witness);
        let statement = checkpoint_statement(&policy, &witness, schedule);
        assert!(
            verify_finalized_burn_inclusion(schedule, &policy, &statement, &witness, &good).is_ok()
        );

        let too_late = ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0x55; 32]),
            3,
            bridge(&policy),
        )
        .unwrap();
        assert_eq!(
            verify_finalized_burn_inclusion(too_late, &policy, &statement, &witness, &good),
            Err(ProgramError::InvalidCheckpoint)
        );

        let wrong_policy = StaticCheckpointTrustPolicy::from_trust_policy(&CheckpointTrustPolicy {
            trusted_checkpoint: [0x91; 32].into(),
            ethereum_genesis_validators_root: [0x22; 32].into(),
            forks: forks(),
            max_current_slot: 1,
            checkpoint: policy.checkpoint().clone(),
        })
        .unwrap();
        assert!(verify_finalized_burn_inclusion(
            schedule,
            &wrong_policy,
            &statement,
            &witness,
            &good
        )
        .is_err());

        let mut wrong_consensus = statement.clone();
        wrong_consensus.checkpoint.block[0] ^= 1;
        assert_eq!(
            verify_finalized_burn_inclusion(schedule, &policy, &wrong_consensus, &witness, &good),
            Err(ProgramError::InvalidCheckpoint)
        );
        let mut wrong_height = statement.clone();
        wrong_height.checkpoint.height += 1;
        wrong_height.checkpoint.confirmation_height += 1;
        assert_eq!(
            verify_finalized_burn_inclusion(schedule, &policy, &wrong_height, &witness, &good),
            Err(ProgramError::InvalidCheckpoint)
        );
        let mut wrong_state = statement.clone();
        wrong_state.checkpoint.state_root[0] ^= 1;
        assert_eq!(
            verify_finalized_burn_inclusion(schedule, &policy, &wrong_state, &witness, &good),
            Err(ProgramError::InvalidCheckpoint)
        );
        let mut wrong_registry = statement.clone();
        wrong_registry.checkpoint.registry[0] ^= 1;
        assert_eq!(
            verify_finalized_burn_inclusion(schedule, &policy, &wrong_registry, &witness, &good),
            Err(ProgramError::InvalidCheckpoint)
        );

        let mut encoded = witness.to_bytes().unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(BurnStateWitnessV2::from_bytes(&encoded).is_err());
    }

    #[test]
    fn inclusion_relation_binds_v6_issuance_closed_in_both_directions() {
        let policy = policy();
        let open_witness = burn_witness(&policy);
        let schedule = ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0x55; 32]),
            1,
            bridge(&policy),
        )
        .unwrap();

        let open_checkpoint = checkpoint(&policy, &open_witness);
        let mut falsely_closed = checkpoint_statement(&policy, &open_witness, schedule);
        assert!(!falsely_closed.issuance_closed);
        falsely_closed.issuance_closed = true;
        assert_eq!(
            verify_finalized_burn_inclusion(
                schedule,
                &policy,
                &falsely_closed,
                &open_witness,
                &open_checkpoint,
            ),
            Err(ProgramError::InvalidCheckpoint)
        );

        let closed_witness = with_valid_issuance_closure(open_witness, schedule);
        let closed_checkpoint = checkpoint(&policy, &closed_witness);
        let closed_statement = checkpoint_statement(&policy, &closed_witness, schedule);
        assert!(closed_statement.issuance_closed);
        assert!(verify_finalized_burn_inclusion(
            schedule,
            &policy,
            &closed_statement,
            &closed_witness,
            &closed_checkpoint,
        )
        .is_ok());

        let mut falsely_open = closed_statement;
        falsely_open.issuance_closed = false;
        assert_eq!(
            verify_finalized_burn_inclusion(
                schedule,
                &policy,
                &falsely_open,
                &closed_witness,
                &closed_checkpoint,
            ),
            Err(ProgramError::InvalidCheckpoint)
        );
    }

    #[test]
    fn public_output_is_exact_nonzero_and_unframed() {
        assert_eq!(FINALIZED_BURN_PROVER_INPUT_VERSION, 4);
        assert_eq!(FINALIZED_BURN_PUBLIC_OUTPUT_VERSION, 1);
        let expected = [0x51; FINALIZED_BURN_PUBLIC_OUTPUT_BYTES];
        let output = FinalizedBurnPublicOutput::from_bytes(&expected).unwrap();
        assert_eq!(output.as_bytes(), &expected);
        assert_eq!(output.into_bytes(), expected);
        assert_eq!(
            FinalizedBurnPublicOutput::from_bytes(&[0; FINALIZED_BURN_PUBLIC_OUTPUT_BYTES]),
            Err(ProgramError::InvalidPublicOutput)
        );
        assert_eq!(
            FinalizedBurnPublicOutput::from_bytes(&expected[..31]),
            Err(ProgramError::InvalidPublicOutput)
        );
        let mut trailing = expected.to_vec();
        trailing.push(0);
        assert_eq!(
            FinalizedBurnPublicOutput::from_bytes(&trailing),
            Err(ProgramError::InvalidPublicOutput)
        );
    }

    #[test]
    fn malformed_empty_legacy_and_oversized_private_inputs_fail_closed() {
        assert_eq!(execute(&[]), Err(ProgramError::InvalidInputLength));
        assert_eq!(execute(b"UDFINL01"), Err(ProgramError::InvalidEncoding));
        assert_eq!(execute(b"UDFINL03"), Err(ProgramError::InvalidEncoding));
        assert_eq!(execute(b"UDFINL04"), Err(ProgramError::InvalidEncoding));
        assert_eq!(
            execute(&vec![0; MAX_FINALIZED_BURN_PROVER_INPUT_BYTES + 1]),
            Err(ProgramError::InvalidInputLength)
        );
    }

    #[test]
    fn activation_schedule_round_trip_binds_bridge_and_rejects_wrong_policy() {
        let policy = policy();
        let schedule = ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            Hash256::from_bytes([0x55; 32]),
            1,
            bridge(&policy),
        )
        .unwrap();
        assert_eq!(
            ActivationSchedule::from_bytes(&schedule.to_bytes()).unwrap(),
            schedule
        );
        assert_ne!(schedule.commitment(), Hash256::ZERO);
        let mut changed = schedule.to_bytes();
        changed[10..14].copy_from_slice(&0u32.to_be_bytes());
        assert!(ActivationSchedule::from_bytes(&changed).is_err());
        let mut wrong_bridge = bridge(&policy);
        wrong_bridge.privacy_policy_hash = [0x99; 32];
        assert_eq!(
            ActivationSchedule::new(
                NETWORK_MAGIC_REGTEST,
                Hash256::from_bytes([0x55; 32]),
                1,
                wrong_bridge
            ),
            Err(ProgramError::InvalidActivationSchedule)
        );
    }
}

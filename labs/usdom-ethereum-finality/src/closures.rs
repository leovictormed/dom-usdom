//! Opaque verification capability for the reserve's irreversible deposit closure.
//!
//! A relayer supplies only bounded proof material. Ethereum finality, receipt,
//! log, account, runtime bytecode and both storage words are authenticated at
//! one exact execution state before this module constructs the capability.

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{
    ancestry::ExecutionAncestryEvidence,
    read_u32_be, read_u64_be,
    receipts::{LogLocator, LogPolicy, ReceiptEvidence},
    state::{AccountEvidence, StorageEvidence},
    EthereumForks, FinalizedExecution, HistoricalCapellaClient,
};

const EVENT: &[u8] = b"DepositsClosedV2(uint256,bytes32,bytes32,bytes32)";
const MAINNET_CHAIN_ID: u64 = 1;
const MAGIC: &[u8; 8] = b"UDOMCLW1";
const POLICY_MAGIC: &[u8; 8] = b"UDOMCLP1";
const POLICY_VERSION: u16 = 1;
/// Exact canonical encoding size of an immutable issuance-closure policy.
pub const STATIC_ISSUANCE_CLOSURE_POLICY_BYTES: usize = 422;
const HEADER_BYTES: usize = 168;
const MAX_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum canonical closure witness size.
pub const MAX_ISSUANCE_CLOSURE_WITNESS_BYTES: usize = 4 * 1024 * 1024;

/// Immutable reserve and storage-layout identity selected by consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceClosurePolicy {
    /// EVM chain identifier; production accepts Ethereum Mainnet only.
    pub ethereum_chain_id: u64,
    /// Beacon genesis root pinning the exact Ethereum consensus chain.
    pub ethereum_genesis_validators_root: B256,
    /// Immutable proof-reserve address.
    pub reserve: Address,
    /// Expected runtime bytecode hash of that reserve.
    pub runtime_code_hash: B256,
    /// Exact immutable reserve configuration committed by the closure event.
    pub reserve_config_hash: B256,
    /// Native activation schedule committed by the closure event.
    pub activation_schedule_commitment: B256,
    /// Native USDOM bridge domain committed by the closure event.
    pub bridge_domain: B256,
    /// Solidity storage slot containing the packed `depositsClosed` flag.
    pub deposits_closed_storage_slot: B256,
    /// Solidity storage slot containing `totalDeposited`.
    pub total_deposited_storage_slot: B256,
}

/// Consensus-owned finality policy. The slot ceiling is derived from the DOM
/// block that carries the witness and is never accepted from the relayer.
#[derive(Debug, Clone)]
pub struct IssuanceClosureTrustPolicy {
    /// Trusted Beacon bootstrap root.
    pub trusted_checkpoint: B256,
    /// Beacon genesis root, repeated to prevent cross-policy composition.
    pub ethereum_genesis_validators_root: B256,
    /// Exact supported Ethereum fork schedule.
    pub forks: EthereumForks,
    /// Consensus-derived maximum Beacon slot for the containing DOM block.
    pub max_current_slot: u64,
    /// Immutable reserve closure identity.
    pub closure: IssuanceClosurePolicy,
}

/// Immutable closure policy retained by the runtime. The dynamic slot ceiling
/// is deliberately absent and must be derived again for every DOM block.
#[derive(Debug, Clone)]
pub struct StaticIssuanceClosureTrustPolicy {
    trusted_checkpoint: B256,
    ethereum_genesis_validators_root: B256,
    forks: EthereumForks,
    closure: IssuanceClosurePolicy,
}

impl StaticIssuanceClosureTrustPolicy {
    /// Freeze all immutable fields while discarding the caller's dynamic slot.
    pub fn from_trust_policy(policy: &IssuanceClosureTrustPolicy) -> Result<Self> {
        validate_policy(policy)?;
        Ok(Self {
            trusted_checkpoint: policy.trusted_checkpoint,
            ethereum_genesis_validators_root: policy.ethereum_genesis_validators_root,
            forks: policy.forks.clone(),
            closure: policy.closure.clone(),
        })
    }

    /// Materialize a fresh verifier policy with a consensus-derived slot cap.
    pub fn at_max_current_slot(&self, max_current_slot: u64) -> Result<IssuanceClosureTrustPolicy> {
        let policy = IssuanceClosureTrustPolicy {
            trusted_checkpoint: self.trusted_checkpoint,
            ethereum_genesis_validators_root: self.ethereum_genesis_validators_root,
            forks: self.forks.clone(),
            max_current_slot,
            closure: self.closure.clone(),
        };
        validate_policy(&policy)?;
        Ok(policy)
    }

    /// Domain-separated commitment to every immutable closure trust input.
    pub fn policy_hash(&self) -> B256 {
        policy_hash(&IssuanceClosureTrustPolicy {
            trusted_checkpoint: self.trusted_checkpoint,
            ethereum_genesis_validators_root: self.ethereum_genesis_validators_root,
            forks: self.forks.clone(),
            max_current_slot: 1,
            closure: self.closure.clone(),
        })
    }

    /// Immutable reserve closure identity.
    pub fn closure(&self) -> &IssuanceClosurePolicy {
        &self.closure
    }

    /// Encode every immutable verifier input in one canonical fixed-size form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(STATIC_ISSUANCE_CLOSURE_POLICY_BYTES);
        bytes.extend_from_slice(POLICY_MAGIC);
        bytes.extend_from_slice(&POLICY_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.trusted_checkpoint.as_slice());
        bytes.extend_from_slice(self.ethereum_genesis_validators_root.as_slice());
        bytes.extend_from_slice(&self.closure.ethereum_chain_id.to_be_bytes());
        bytes.extend_from_slice(self.closure.ethereum_genesis_validators_root.as_slice());
        bytes.extend_from_slice(self.closure.reserve.as_slice());
        bytes.extend_from_slice(self.closure.runtime_code_hash.as_slice());
        bytes.extend_from_slice(self.closure.reserve_config_hash.as_slice());
        bytes.extend_from_slice(self.closure.activation_schedule_commitment.as_slice());
        bytes.extend_from_slice(self.closure.bridge_domain.as_slice());
        bytes.extend_from_slice(self.closure.deposits_closed_storage_slot.as_slice());
        bytes.extend_from_slice(self.closure.total_deposited_storage_slot.as_slice());
        for fork in [
            &self.forks.genesis,
            &self.forks.altair,
            &self.forks.bellatrix,
            &self.forks.capella,
            &self.forks.deneb,
            &self.forks.electra,
            &self.forks.fulu,
            &self.forks.gloas,
        ] {
            bytes.extend_from_slice(&fork.epoch.to_be_bytes());
            bytes.extend_from_slice(fork.fork_version.as_slice());
        }
        debug_assert_eq!(bytes.len(), STATIC_ISSUANCE_CLOSURE_POLICY_BYTES);
        bytes
    }

    /// Decode and validate the unique fixed-size policy representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == STATIC_ISSUANCE_CLOSURE_POLICY_BYTES
                && &bytes[..8] == POLICY_MAGIC
                && u16::from_be_bytes(bytes[8..10].try_into()?) == POLICY_VERSION,
            "closure policy framing"
        );
        let mut cursor = 10usize;
        let mut take = |length: usize| -> Result<&[u8]> {
            let end = cursor
                .checked_add(length)
                .ok_or_else(|| eyre::eyre!("closure policy size overflow"))?;
            let value = bytes
                .get(cursor..end)
                .ok_or_else(|| eyre::eyre!("truncated closure policy"))?;
            cursor = end;
            Ok(value)
        };
        let trusted_checkpoint = B256::from_slice(take(32)?);
        let ethereum_genesis_validators_root = B256::from_slice(take(32)?);
        let ethereum_chain_id = u64::from_be_bytes(take(8)?.try_into()?);
        let closure_genesis = B256::from_slice(take(32)?);
        let reserve = Address::from_slice(take(20)?);
        let runtime_code_hash = B256::from_slice(take(32)?);
        let reserve_config_hash = B256::from_slice(take(32)?);
        let activation_schedule_commitment = B256::from_slice(take(32)?);
        let bridge_domain = B256::from_slice(take(32)?);
        let deposits_closed_storage_slot = B256::from_slice(take(32)?);
        let total_deposited_storage_slot = B256::from_slice(take(32)?);
        let mut read_fork = || -> Result<crate::EthereumFork> {
            Ok(crate::EthereumFork {
                epoch: u64::from_be_bytes(take(8)?.try_into()?),
                fork_version: <[u8; 4]>::try_from(take(4)?)?.into(),
            })
        };
        let forks = EthereumForks {
            genesis: read_fork()?,
            altair: read_fork()?,
            bellatrix: read_fork()?,
            capella: read_fork()?,
            deneb: read_fork()?,
            electra: read_fork()?,
            fulu: read_fork()?,
            gloas: read_fork()?,
        };
        ensure!(cursor == bytes.len(), "trailing closure policy bytes");
        let dynamic = IssuanceClosureTrustPolicy {
            trusted_checkpoint,
            ethereum_genesis_validators_root,
            forks,
            max_current_slot: 1,
            closure: IssuanceClosurePolicy {
                ethereum_chain_id,
                ethereum_genesis_validators_root: closure_genesis,
                reserve,
                runtime_code_hash,
                reserve_config_hash,
                activation_schedule_commitment,
                bridge_domain,
                deposits_closed_storage_slot,
                total_deposited_storage_slot,
            },
        };
        let policy = Self::from_trust_policy(&dynamic)?;
        ensure!(policy.to_bytes() == bytes, "noncanonical closure policy");
        Ok(policy)
    }
}

/// Untrusted proof bundle for one closure transaction and its post-state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceClosureEvidence {
    /// Authenticated route from an older transaction block to retained finality.
    #[serde(default)]
    pub execution_ancestry: Option<ExecutionAncestryEvidence>,
    /// Receipt inclusion proof for the closure transaction.
    pub receipt: ReceiptEvidence,
    /// Exact closure-log position inside the verified receipt.
    pub receipt_log_index: u32,
    /// Reserve post-state account proof.
    pub reserve_account: AccountEvidence,
    /// Runtime bytecode whose hash must equal the authenticated account code hash.
    pub runtime_bytecode: Bytes,
    /// Proof for the packed `depositsClosed` storage word.
    pub deposits_closed_storage: StorageEvidence,
    /// Proof for the exact cumulative deposited collateral word.
    pub total_deposited_storage: StorageEvidence,
}

#[derive(Debug)]
struct ClosureWitness {
    transcript: Vec<u8>,
    expected_finalized: FinalizedExecution,
    evidence: IssuanceClosureEvidence,
}

/// Proof-authenticated irreversible issuance-closure fact. Every field is
/// private; only the verifier in this module can construct this capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIssuanceClosure {
    locator: LogLocator,
    reserve: Address,
    total_deposited: U256,
    reserve_config_hash: B256,
    activation_schedule_commitment: B256,
    bridge_domain: B256,
    finalized: FinalizedExecution,
    trust_policy_hash: B256,
}

/// Encode the unique bounded witness representation.
pub fn encode_issuance_closure_witness(
    transcript: &[u8],
    expected_finalized: &FinalizedExecution,
    evidence: &IssuanceClosureEvidence,
) -> Result<Vec<u8>> {
    ensure!(!transcript.is_empty(), "empty finality transcript");
    validate_finalized(expected_finalized)?;
    let evidence_bytes = serde_json::to_vec(evidence)?;
    ensure!(
        !evidence_bytes.is_empty() && evidence_bytes.len() <= MAX_EVIDENCE_BYTES,
        "closure evidence byte limit"
    );
    let total = HEADER_BYTES
        .checked_add(transcript.len())
        .and_then(|value| value.checked_add(evidence_bytes.len()))
        .ok_or_else(|| eyre::eyre!("closure witness size overflow"))?;
    ensure!(
        total <= MAX_ISSUANCE_CLOSURE_WITNESS_BYTES
            && transcript.len() <= u32::MAX as usize
            && evidence_bytes.len() <= u32::MAX as usize,
        "closure witness byte limit"
    );
    let mut wire = Vec::with_capacity(total);
    wire.extend_from_slice(MAGIC);
    wire.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
    wire.extend_from_slice(&(evidence_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&expected_finalized.beacon_slot.to_be_bytes());
    wire.extend_from_slice(expected_finalized.beacon_root.as_slice());
    wire.extend_from_slice(&expected_finalized.block_number.to_be_bytes());
    wire.extend_from_slice(expected_finalized.block_hash.as_slice());
    wire.extend_from_slice(&expected_finalized.timestamp.to_be_bytes());
    wire.extend_from_slice(expected_finalized.receipts_root.as_slice());
    wire.extend_from_slice(expected_finalized.state_root.as_slice());
    wire.extend_from_slice(transcript);
    wire.extend_from_slice(&evidence_bytes);
    Ok(wire)
}

/// Replay finality and authenticate the exact closure log and post-state.
pub fn verify_issuance_closure_witness(
    bytes: &[u8],
    policy: &IssuanceClosureTrustPolicy,
) -> Result<VerifiedIssuanceClosure> {
    validate_policy(policy)?;
    let witness = decode_witness(bytes)?;
    ensure!(
        witness.expected_finalized.beacon_slot <= policy.max_current_slot,
        "finalized slot exceeds consensus limit"
    );
    let client = HistoricalCapellaClient::restore_transcript_bounded(
        &witness.transcript,
        policy.trusted_checkpoint,
        policy.ethereum_genesis_validators_root,
        policy.forks.clone(),
        &witness.expected_finalized,
        policy.max_current_slot,
    )?;
    let (receipt, account, execution) = if let Some(ancestry) = &witness.evidence.execution_ancestry
    {
        let authenticated = client.verify_execution_ancestry(ancestry)?;
        let header = authenticated.finalized_execution();
        (
            crate::receipts::verify_receipt_at(
                policy.ethereum_genesis_validators_root,
                header,
                &witness.evidence.receipt,
            )?,
            crate::state::verify_account_at(
                policy.ethereum_genesis_validators_root,
                header,
                &witness.evidence.reserve_account,
            )?,
            header.clone(),
        )
    } else {
        let header = client.finalized_execution(
            witness.evidence.receipt.block_hash,
            witness.evidence.receipt.block_number,
        )?;
        (
            client.verify_receipt(&witness.evidence.receipt)?,
            client.verify_account(&witness.evidence.reserve_account)?,
            header.clone(),
        )
    };
    let event = receipt.log(
        witness.evidence.receipt_log_index,
        &LogPolicy {
            emitter: policy.closure.reserve,
            topic0: keccak256(EVENT),
            topic_count: 1,
        },
    )?;
    let account = account.ok_or_else(|| eyre::eyre!("reserve account is absent"))?;
    ensure!(
        account.is_emitter_post_state_for(&event),
        "closure state/log mismatch"
    );
    account.check_contract_code(
        policy.closure.runtime_code_hash,
        &witness.evidence.runtime_bytecode,
    )?;
    ensure!(
        witness.evidence.deposits_closed_storage.slot
            == policy.closure.deposits_closed_storage_slot
            && witness.evidence.total_deposited_storage.slot
                == policy.closure.total_deposited_storage_slot,
        "closure storage slot mismatch"
    );
    let closed = account.verify_storage(&witness.evidence.deposits_closed_storage)?;
    let deposited = account.verify_storage(&witness.evidence.total_deposited_storage)?;
    // Solidity packs queueEpoch (bits 0..63), paused (bit 64) and
    // depositsClosed (bit 72) into this word.
    ensure!(deposits_closed(closed.value()), "deposits are not closed");

    let data = event.data();
    ensure!(data.len() == 128, "closure event data length");
    let total_deposited = U256::from_be_slice(&data[..32]);
    let reserve_config_hash = B256::from_slice(&data[32..64]);
    let activation_schedule_commitment = B256::from_slice(&data[64..96]);
    let bridge_domain = B256::from_slice(&data[96..128]);
    ensure!(
        deposited.value() == total_deposited
            && reserve_config_hash == policy.closure.reserve_config_hash
            && activation_schedule_commitment == policy.closure.activation_schedule_commitment
            && bridge_domain == policy.closure.bridge_domain,
        "closure event/storage/policy mismatch"
    );
    ensure!(
        execution.block_hash == event.locator().block_hash
            && execution.block_number == event.locator().block_number
            && client.finalized().beacon_slot >= execution.beacon_slot
            && client.finalized().block_number >= execution.block_number
            && client.finalized().timestamp >= execution.timestamp,
        "invalid closure execution/finality identity"
    );
    Ok(VerifiedIssuanceClosure {
        locator: event.locator().clone(),
        reserve: policy.closure.reserve,
        total_deposited,
        reserve_config_hash,
        activation_schedule_commitment,
        bridge_domain,
        finalized: client.finalized(),
        trust_policy_hash: policy_hash(policy),
    })
}

/// Return the deterministic transcript replay slot required by one canonical
/// witness without granting closure authority.
pub fn issuance_closure_witness_replay_slot(bytes: &[u8]) -> Result<u64> {
    let witness = decode_witness(bytes)?;
    let replay_slot = crate::canonical_transcript_replay_slot(&witness.transcript)?;
    ensure!(
        replay_slot >= witness.expected_finalized.beacon_slot,
        "transcript replay slot precedes finalized closure slot"
    );
    Ok(replay_slot)
}

fn deposits_closed(word: U256) -> bool {
    ((word >> 72) & U256::from(1u8)) == U256::from(1u8)
}

fn decode_witness(bytes: &[u8]) -> Result<ClosureWitness> {
    ensure!(
        bytes.len() >= HEADER_BYTES
            && bytes.len() <= MAX_ISSUANCE_CLOSURE_WITNESS_BYTES
            && &bytes[..8] == MAGIC,
        "closure witness framing"
    );
    let transcript_len = usize::try_from(read_u32_be(bytes, 8, "closure transcript length")?)?;
    let evidence_len = usize::try_from(read_u32_be(bytes, 12, "closure evidence length")?)?;
    let expected = HEADER_BYTES
        .checked_add(transcript_len)
        .and_then(|value| value.checked_add(evidence_len))
        .ok_or_else(|| eyre::eyre!("closure witness size overflow"))?;
    ensure!(
        transcript_len != 0
            && evidence_len != 0
            && evidence_len <= MAX_EVIDENCE_BYTES
            && expected == bytes.len(),
        "closure witness lengths"
    );
    let expected_finalized = FinalizedExecution {
        beacon_slot: read_u64_be(bytes, 16, "closure finalized slot")?,
        beacon_root: B256::from_slice(&bytes[24..56]),
        block_number: read_u64_be(bytes, 56, "closure finalized block")?,
        block_hash: B256::from_slice(&bytes[64..96]),
        timestamp: read_u64_be(bytes, 96, "closure finalized timestamp")?,
        receipts_root: B256::from_slice(&bytes[104..136]),
        state_root: B256::from_slice(&bytes[136..168]),
    };
    validate_finalized(&expected_finalized)?;
    let split = HEADER_BYTES + transcript_len;
    let transcript = bytes[HEADER_BYTES..split].to_vec();
    let evidence_bytes = &bytes[split..];
    crate::preflight_transcript_json(&transcript)?;
    crate::preflight_evidence_json(evidence_bytes)?;
    let evidence: IssuanceClosureEvidence = serde_json::from_slice(evidence_bytes)?;
    if let Some(ancestry) = &evidence.execution_ancestry {
        crate::ancestry::validate_ancestry_allocation_bounds(ancestry)?;
    }
    crate::receipts::validate_receipt_allocation_bounds(&evidence.receipt)?;
    crate::state::validate_account_allocation_bounds(&evidence.reserve_account)?;
    crate::state::validate_runtime_code_allocation_bounds(&evidence.runtime_bytecode)?;
    crate::state::validate_storage_allocation_bounds(&evidence.deposits_closed_storage)?;
    crate::state::validate_storage_allocation_bounds(&evidence.total_deposited_storage)?;
    ensure!(
        serde_json::to_vec(&evidence)?.as_slice() == evidence_bytes,
        "noncanonical closure evidence"
    );
    Ok(ClosureWitness {
        transcript,
        expected_finalized,
        evidence,
    })
}

fn validate_finalized(value: &FinalizedExecution) -> Result<()> {
    ensure!(
        value.beacon_slot != 0
            && value.beacon_root != B256::ZERO
            && value.block_number != 0
            && value.block_hash != B256::ZERO
            && value.timestamp != 0
            && value.receipts_root != B256::ZERO
            && value.state_root != B256::ZERO,
        "zero closure finality identity"
    );
    Ok(())
}

fn validate_policy(policy: &IssuanceClosureTrustPolicy) -> Result<()> {
    crate::validate_fork_schedule(&policy.forks)?;
    let value = &policy.closure;
    ensure!(
        policy.trusted_checkpoint != B256::ZERO
            && policy.max_current_slot != 0
            && policy.ethereum_genesis_validators_root == value.ethereum_genesis_validators_root
            && value.ethereum_chain_id == MAINNET_CHAIN_ID
            && value.ethereum_genesis_validators_root != B256::ZERO
            && value.reserve != Address::ZERO
            && value.runtime_code_hash != B256::ZERO
            && value.reserve_config_hash != B256::ZERO
            && value.activation_schedule_commitment != B256::ZERO
            && value.bridge_domain != B256::ZERO
            && value.deposits_closed_storage_slot != value.total_deposited_storage_slot,
        "invalid issuance closure policy"
    );
    Ok(())
}

fn policy_hash(policy: &IssuanceClosureTrustPolicy) -> B256 {
    let value = &policy.closure;
    let mut bytes = Vec::with_capacity(370);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(policy.trusted_checkpoint.as_slice());
    bytes.extend_from_slice(policy.ethereum_genesis_validators_root.as_slice());
    bytes.extend_from_slice(&value.ethereum_chain_id.to_be_bytes());
    bytes.extend_from_slice(value.reserve.as_slice());
    bytes.extend_from_slice(value.runtime_code_hash.as_slice());
    bytes.extend_from_slice(value.reserve_config_hash.as_slice());
    bytes.extend_from_slice(value.activation_schedule_commitment.as_slice());
    bytes.extend_from_slice(value.bridge_domain.as_slice());
    bytes.extend_from_slice(value.deposits_closed_storage_slot.as_slice());
    bytes.extend_from_slice(value.total_deposited_storage_slot.as_slice());
    for fork in [
        &policy.forks.genesis,
        &policy.forks.altair,
        &policy.forks.bellatrix,
        &policy.forks.capella,
        &policy.forks.deneb,
        &policy.forks.electra,
        &policy.forks.fulu,
        &policy.forks.gloas,
    ] {
        bytes.extend_from_slice(&fork.epoch.to_be_bytes());
        bytes.extend_from_slice(fork.fork_version.as_slice());
    }
    B256::from_slice(
        dom_core::blake2b_256_tagged("DOM:usdom-issuance-closure-policy:v1", &bytes).as_bytes(),
    )
}

impl VerifiedIssuanceClosure {
    /// Location of the authenticated closure log.
    pub fn locator(&self) -> &LogLocator {
        &self.locator
    }
    /// Reserve that emitted the event and owns the proven post-state.
    pub fn reserve(&self) -> Address {
        self.reserve
    }
    /// Exact cumulative collateral admitted before irreversible closure.
    pub fn total_deposited(&self) -> U256 {
        self.total_deposited
    }
    /// Immutable reserve configuration committed by the event.
    pub fn reserve_config_hash(&self) -> B256 {
        self.reserve_config_hash
    }
    /// Native activation schedule committed by the event.
    pub fn activation_schedule_commitment(&self) -> B256 {
        self.activation_schedule_commitment
    }
    /// Native bridge domain committed by the event.
    pub fn bridge_domain(&self) -> B256 {
        self.bridge_domain
    }
    /// Finalized Ethereum execution identity authenticating the capability.
    pub fn finalized_execution(&self) -> &FinalizedExecution {
        &self.finalized
    }
    /// Commitment to the immutable verifier policy used for this proof.
    pub fn trust_policy_hash(&self) -> B256 {
        self.trust_policy_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_closure_flag_is_exact_and_independent_of_neighbor_fields() {
        assert!(!deposits_closed(U256::ZERO));
        assert!(!deposits_closed(U256::from(1u8) << 64));
        assert!(deposits_closed(U256::from(1u8) << 72));
        assert!(deposits_closed(
            (U256::from(u64::MAX))
                | (U256::from(1u8) << 64)
                | (U256::from(1u8) << 72)
                | (U256::from(u64::MAX) << 80)
        ));
        assert!(!deposits_closed(U256::from(2u8) << 72));
    }
}

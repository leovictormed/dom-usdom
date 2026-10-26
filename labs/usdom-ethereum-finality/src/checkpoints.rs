//! Composition boundary for an Ethereum-finalized DOM checkpoint event.
//!
//! The untrusted witness is accepted only when one authenticated execution
//! header proves the receipt, registry account, runtime code, and configuration
//! storage word. The result is opaque and serializes to the exact bounded record
//! consumed by the experimental DOM reorganization barrier.

use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{
    ancestry::ExecutionAncestryEvidence,
    read_u32_be, read_u64_be,
    receipts::{LogLocator, LogPolicy, ReceiptEvidence, VerifiedLog, VerifiedReceipt},
    state::{
        AccountEvidence, CheckedCodeSnapshot, StorageEvidence, VerifiedAccount, VerifiedStorageWord,
    },
    EthereumFork, EthereumForks, FinalizedExecution, HistoricalCapellaClient,
};

const CHECKPOINT_EVENT: &[u8] = b"Checkpoint(bytes32,uint32,uint64,bytes32,bytes32,bytes32)";
const CHECKPOINT_STRUCT: &[u8] = b"Checkpoint(bytes32 bridgeDomain,uint32 domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)";
const MAINNET_CHAIN_ID: u64 = 1;
/// Versioned handoff size consumed by `dom-chain`'s checkpoint decoder.
pub const CHECKPOINT_RECORD_LENGTH: usize = 417;
/// A checkpoint witness must fit well below DOM's 16 MiB serialized block cap.
pub const MAX_CHECKPOINT_WITNESS_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHECKPOINT_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
const CHECKPOINT_WITNESS_MAGIC: &[u8; 8] = b"UDOMCPW1";
const CHECKPOINT_WITNESS_HEADER_BYTES: usize = 168;
const STATIC_CHECKPOINT_POLICY_MAGIC: &[u8; 8] = b"UDCPSP01";
const STATIC_CHECKPOINT_POLICY_PAYLOAD_BYTES: usize = 354;
/// Exact bounded encoding of every immutable Ethereum checkpoint trust input.
pub const STATIC_CHECKPOINT_TRUST_POLICY_BYTES: usize =
    STATIC_CHECKPOINT_POLICY_MAGIC.len() + STATIC_CHECKPOINT_POLICY_PAYLOAD_BYTES;

/// Immutable protocol policy. None of these identities may come from a relayer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPolicy {
    pub ethereum_chain_id: u64,
    pub ethereum_genesis_validators_root: B256,
    pub registry: Address,
    pub runtime_code_hash: B256,
    pub config_storage_slot: B256,
    pub checkpoint_config_hash: B256,
    pub bridge_domain: B256,
    pub dom_network_magic: u32,
}

/// Consensus-selected trust and time inputs. These values are deliberately
/// absent from the relayer-supplied witness bytes.
#[derive(Debug, Clone)]
pub struct CheckpointTrustPolicy {
    pub trusted_checkpoint: B256,
    pub ethereum_genesis_validators_root: B256,
    pub forks: EthereumForks,
    /// Upper bound derived by the DOM consensus rule for the containing block.
    pub max_current_slot: u64,
    pub checkpoint: CheckpointPolicy,
}

/// Immutable checkpoint trust inputs owned by consensus/runtime configuration.
///
/// The dynamic slot ceiling is deliberately absent. Callers derive it from the
/// containing DOM block timestamp through [`Self::at_max_current_slot`], so a
/// relayer or node-local clock cannot smuggle a looser limit into verification.
#[derive(Debug, Clone)]
pub struct StaticCheckpointTrustPolicy {
    trusted_checkpoint: B256,
    ethereum_genesis_validators_root: B256,
    forks: EthereumForks,
    checkpoint: CheckpointPolicy,
}

impl StaticCheckpointTrustPolicy {
    fn materialize(&self, max_current_slot: u64) -> CheckpointTrustPolicy {
        CheckpointTrustPolicy {
            trusted_checkpoint: self.trusted_checkpoint,
            ethereum_genesis_validators_root: self.ethereum_genesis_validators_root,
            forks: self.forks.clone(),
            max_current_slot,
            checkpoint: self.checkpoint.clone(),
        }
    }

    /// Freeze only the immutable fields of an existing policy. The supplied
    /// dynamic `max_current_slot` is ignored and a minimal nonzero ceiling is
    /// used solely to run the common structural policy validation.
    pub fn from_trust_policy(policy: &CheckpointTrustPolicy) -> Result<Self> {
        let candidate = Self {
            trusted_checkpoint: policy.trusted_checkpoint,
            ethereum_genesis_validators_root: policy.ethereum_genesis_validators_root,
            forks: policy.forks.clone(),
            checkpoint: policy.checkpoint.clone(),
        };
        validate_trust_policy(&candidate.at_max_current_slot(1)?)?;
        Ok(candidate)
    }

    /// Materialize the verifier input with a consensus-derived nonzero slot
    /// ceiling. The returned value is fresh and cannot mutate this policy.
    pub fn at_max_current_slot(&self, max_current_slot: u64) -> Result<CheckpointTrustPolicy> {
        ensure!(max_current_slot != 0, "zero consensus slot ceiling");
        Ok(self.materialize(max_current_slot))
    }

    /// Domain-separated commitment over every immutable trust input.
    pub fn policy_hash(&self) -> B256 {
        checkpoint_trust_policy_hash(&self.materialize(1))
    }

    /// Immutable registry and DOM binding policy.
    pub fn checkpoint(&self) -> &CheckpointPolicy {
        &self.checkpoint
    }

    /// Encode the complete immutable policy in one canonical bounded transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        let dynamic = self.materialize(1);
        let mut bytes = Vec::with_capacity(STATIC_CHECKPOINT_TRUST_POLICY_BYTES);
        bytes.extend_from_slice(STATIC_CHECKPOINT_POLICY_MAGIC);
        bytes.extend_from_slice(&checkpoint_trust_policy_preimage(&dynamic));
        debug_assert_eq!(bytes.len(), STATIC_CHECKPOINT_TRUST_POLICY_BYTES);
        bytes
    }

    /// Decode, validate and canonically re-encode the immutable policy. The
    /// dynamic slot ceiling remains absent and must be supplied by consensus or
    /// by a public statement checked against the Ethereum protocol clock.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == STATIC_CHECKPOINT_TRUST_POLICY_BYTES
                && &bytes[..8] == STATIC_CHECKPOINT_POLICY_MAGIC,
            "invalid static checkpoint policy framing"
        );
        let payload = &bytes[8..];
        let mut cursor = 0usize;
        let version = u16::from_be_bytes(take_policy(payload, &mut cursor)?);
        ensure!(version == 1, "unsupported static checkpoint policy version");
        let trusted_checkpoint = B256::from(take_policy(payload, &mut cursor)?);
        let ethereum_genesis_validators_root = B256::from(take_policy(payload, &mut cursor)?);
        let ethereum_chain_id = u64::from_be_bytes(take_policy(payload, &mut cursor)?);
        let checkpoint_genesis = B256::from(take_policy(payload, &mut cursor)?);
        let registry = Address::from(take_policy(payload, &mut cursor)?);
        let runtime_code_hash = B256::from(take_policy(payload, &mut cursor)?);
        let config_storage_slot = B256::from(take_policy(payload, &mut cursor)?);
        let checkpoint_config_hash = B256::from(take_policy(payload, &mut cursor)?);
        let bridge_domain = B256::from(take_policy(payload, &mut cursor)?);
        let dom_network_magic = u32::from_be_bytes(take_policy(payload, &mut cursor)?);
        let mut next_fork = || -> Result<EthereumFork> {
            Ok(EthereumFork {
                epoch: u64::from_be_bytes(take_policy(payload, &mut cursor)?),
                fork_version: take_policy::<4>(payload, &mut cursor)?.into(),
            })
        };
        let forks = EthereumForks {
            genesis: next_fork()?,
            altair: next_fork()?,
            bellatrix: next_fork()?,
            capella: next_fork()?,
            deneb: next_fork()?,
            electra: next_fork()?,
            fulu: next_fork()?,
            gloas: next_fork()?,
        };
        ensure!(
            cursor == payload.len(),
            "trailing static checkpoint policy bytes"
        );
        let dynamic = CheckpointTrustPolicy {
            trusted_checkpoint,
            ethereum_genesis_validators_root,
            forks,
            max_current_slot: 1,
            checkpoint: CheckpointPolicy {
                ethereum_chain_id,
                ethereum_genesis_validators_root: checkpoint_genesis,
                registry,
                runtime_code_hash,
                config_storage_slot,
                checkpoint_config_hash,
                bridge_domain,
                dom_network_magic,
            },
        };
        let policy = Self::from_trust_policy(&dynamic)?;
        ensure!(
            policy.to_bytes() == bytes,
            "noncanonical static checkpoint policy"
        );
        Ok(policy)
    }
}

fn take_policy<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| eyre::eyre!("static checkpoint policy length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| eyre::eyre!("truncated static checkpoint policy"))?
        .try_into()
        .map_err(|_| eyre::eyre!("invalid static checkpoint policy field"))?;
    *cursor = end;
    Ok(value)
}

/// Untrusted witness for one finalized checkpoint registry event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointEvidence {
    /// Required when the event block predates the retained finalized execution
    /// header. The last RLP header must be that authenticated finality anchor.
    #[serde(default)]
    pub execution_ancestry: Option<ExecutionAncestryEvidence>,
    pub receipt: ReceiptEvidence,
    pub receipt_log_index: u32,
    pub registry_account: AccountEvidence,
    pub config_storage: StorageEvidence,
    pub runtime_bytecode: Bytes,
}

/// Bounded, versioned, untrusted bytes propagated for deterministic replay.
/// Decoding this object grants no authority; `verify_checkpoint_witness` must
/// reconstruct finality and every execution proof under consensus policy.
#[derive(Debug)]
struct CheckpointWitness {
    transcript: Vec<u8>,
    expected_finalized: FinalizedExecution,
    evidence: CheckpointEvidence,
}

/// Fully composed result. Private fields prevent treating decoded JSON or a
/// caller-supplied root as authenticated checkpoint authority.
///
/// ```compile_fail
/// use usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint;
/// fn forge(bytes: [u8; 417]) -> VerifiedCheckpoint {
///     VerifiedCheckpoint { record: bytes, finalized: todo!() }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    record: [u8; CHECKPOINT_RECORD_LENGTH],
    finalized: FinalizedExecution,
    trust_policy_hash: B256,
}

struct AuthenticationBundle {
    receipt: VerifiedReceipt,
    account: VerifiedAccount,
    execution: FinalizedExecution,
}

impl HistoricalCapellaClient {
    /// Authenticate every Ethereum component and emit one canonical handoff.
    /// This does not establish that the DOM block/state root is valid; the DOM
    /// consensus layer must independently match both fields before installation.
    pub fn verify_dom_checkpoint(
        &self,
        evidence: &CheckpointEvidence,
        policy: &CheckpointPolicy,
    ) -> Result<VerifiedCheckpoint> {
        validate_policy(policy)?;
        let bundle = if let Some(ancestry) = &evidence.execution_ancestry {
            let authenticated = self.verify_execution_ancestry(ancestry)?;
            let header = authenticated.finalized_execution();
            AuthenticationBundle {
                receipt: crate::receipts::verify_receipt_at(
                    self.genesis_root,
                    header,
                    &evidence.receipt,
                )?,
                account: crate::state::verify_account_at(
                    self.genesis_root,
                    header,
                    &evidence.registry_account,
                )?
                .ok_or_else(|| eyre::eyre!("checkpoint registry account is absent"))?,
                execution: header.clone(),
            }
        } else {
            let header = self
                .finalized_execution(evidence.receipt.block_hash, evidence.receipt.block_number)?
                .clone();
            AuthenticationBundle {
                receipt: self.verify_receipt(&evidence.receipt)?,
                account: self
                    .verify_account(&evidence.registry_account)?
                    .ok_or_else(|| eyre::eyre!("checkpoint registry account is absent"))?,
                execution: header,
            }
        };
        let event = bundle.receipt.log(
            evidence.receipt_log_index,
            &LogPolicy {
                emitter: policy.registry,
                topic0: keccak256(CHECKPOINT_EVENT),
                topic_count: 3,
            },
        )?;
        ensure!(
            bundle.account.is_emitter_post_state_for(&event),
            "registry account and event are from different finalized states"
        );
        let code = bundle
            .account
            .check_contract_code(policy.runtime_code_hash, &evidence.runtime_bytecode)?;
        let config = bundle.account.verify_storage(&evidence.config_storage)?;
        let finality_head = self.finalized();
        compose_checkpoint(
            &event,
            &code,
            &config,
            &bundle.execution,
            &finality_head,
            policy,
        )
    }
}

/// Encode the canonical witness form that every DOM node can replay. The
/// transcript itself is checked for canonicality during cryptographic replay;
/// evidence JSON is canonicalized here and required byte-for-byte on decode.
pub fn encode_checkpoint_witness(
    transcript: &[u8],
    expected_finalized: &FinalizedExecution,
    evidence: &CheckpointEvidence,
) -> Result<Vec<u8>> {
    ensure!(!transcript.is_empty(), "empty finality transcript");
    validate_expected_finalized(expected_finalized)?;
    let evidence_bytes = serde_json::to_vec(evidence)?;
    ensure!(
        !evidence_bytes.is_empty() && evidence_bytes.len() <= MAX_CHECKPOINT_EVIDENCE_BYTES,
        "checkpoint evidence byte limit"
    );
    let total = CHECKPOINT_WITNESS_HEADER_BYTES
        .checked_add(transcript.len())
        .and_then(|value| value.checked_add(evidence_bytes.len()))
        .ok_or_else(|| eyre::eyre!("checkpoint witness size overflow"))?;
    ensure!(
        total <= MAX_CHECKPOINT_WITNESS_BYTES
            && transcript.len() <= u32::MAX as usize
            && evidence_bytes.len() <= u32::MAX as usize,
        "checkpoint witness byte limit"
    );

    let mut wire = Vec::with_capacity(total);
    wire.extend_from_slice(CHECKPOINT_WITNESS_MAGIC);
    wire.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
    wire.extend_from_slice(&(evidence_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&expected_finalized.beacon_slot.to_be_bytes());
    wire.extend_from_slice(expected_finalized.beacon_root.as_slice());
    wire.extend_from_slice(&expected_finalized.block_number.to_be_bytes());
    wire.extend_from_slice(expected_finalized.block_hash.as_slice());
    wire.extend_from_slice(&expected_finalized.timestamp.to_be_bytes());
    wire.extend_from_slice(expected_finalized.receipts_root.as_slice());
    wire.extend_from_slice(expected_finalized.state_root.as_slice());
    debug_assert_eq!(wire.len(), CHECKPOINT_WITNESS_HEADER_BYTES);
    wire.extend_from_slice(transcript);
    wire.extend_from_slice(&evidence_bytes);
    Ok(wire)
}

/// Rebuild Ethereum finality from the exact witness bytes, enforce the
/// consensus-provided slot ceiling, and compose the opaque checkpoint result.
pub fn verify_checkpoint_witness(
    bytes: &[u8],
    policy: &CheckpointTrustPolicy,
) -> Result<VerifiedCheckpoint> {
    validate_trust_policy(policy)?;
    let witness = decode_checkpoint_witness(bytes)?;
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
    let mut checkpoint = client.verify_dom_checkpoint(&witness.evidence, &policy.checkpoint)?;
    checkpoint.trust_policy_hash = checkpoint_trust_policy_hash(policy);
    Ok(checkpoint)
}

/// Return the exact finalized Beacon slot declared by a canonical bounded
/// checkpoint witness. This parses the complete framing/evidence but grants no
/// finality authority; [`verify_checkpoint_witness`] must still authenticate it.
pub fn checkpoint_witness_finalized_slot(bytes: &[u8]) -> Result<u64> {
    let slot = decode_checkpoint_witness(bytes)?
        .expected_finalized
        .beacon_slot;
    ensure!(slot != 0, "zero checkpoint witness finalized slot");
    Ok(slot)
}

/// Return the exact minimal slot ceiling needed to replay a canonical
/// checkpoint transcript. This is distinct from the finalized slot because a
/// valid finality update is signed strictly after the header it finalizes.
pub fn checkpoint_witness_replay_slot(bytes: &[u8]) -> Result<u64> {
    let witness = decode_checkpoint_witness(bytes)?;
    let replay_slot = crate::canonical_transcript_replay_slot(&witness.transcript)?;
    ensure!(
        replay_slot >= witness.expected_finalized.beacon_slot,
        "transcript replay slot precedes finalized slot"
    );
    Ok(replay_slot)
}

/// Commit every immutable trust input used to replay a checkpoint witness.
/// The dynamic `max_current_slot` is excluded because native consensus derives
/// it from the containing DOM block timestamp.
pub fn checkpoint_trust_policy_hash(policy: &CheckpointTrustPolicy) -> B256 {
    B256::from_slice(
        dom_core::blake2b_256_tagged(
            dom_core::TAG_USDOM_ETHEREUM_POLICY,
            &checkpoint_trust_policy_preimage(policy),
        )
        .as_bytes(),
    )
}

fn checkpoint_trust_policy_preimage(policy: &CheckpointTrustPolicy) -> Vec<u8> {
    let checkpoint = &policy.checkpoint;
    let mut bytes = Vec::with_capacity(354);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(policy.trusted_checkpoint.as_slice());
    bytes.extend_from_slice(policy.ethereum_genesis_validators_root.as_slice());
    bytes.extend_from_slice(&checkpoint.ethereum_chain_id.to_be_bytes());
    bytes.extend_from_slice(checkpoint.ethereum_genesis_validators_root.as_slice());
    bytes.extend_from_slice(checkpoint.registry.as_slice());
    bytes.extend_from_slice(checkpoint.runtime_code_hash.as_slice());
    bytes.extend_from_slice(checkpoint.config_storage_slot.as_slice());
    bytes.extend_from_slice(checkpoint.checkpoint_config_hash.as_slice());
    bytes.extend_from_slice(checkpoint.bridge_domain.as_slice());
    bytes.extend_from_slice(&checkpoint.dom_network_magic.to_be_bytes());
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
    debug_assert_eq!(bytes.len(), STATIC_CHECKPOINT_POLICY_PAYLOAD_BYTES);
    bytes
}

fn decode_checkpoint_witness(bytes: &[u8]) -> Result<CheckpointWitness> {
    ensure!(
        bytes.len() >= CHECKPOINT_WITNESS_HEADER_BYTES
            && bytes.len() <= MAX_CHECKPOINT_WITNESS_BYTES
            && &bytes[..8] == CHECKPOINT_WITNESS_MAGIC,
        "checkpoint witness framing"
    );
    let transcript_len = usize::try_from(read_u32_be(bytes, 8, "checkpoint transcript length")?)
        .map_err(|_| eyre::eyre!("checkpoint transcript length does not fit usize"))?;
    let evidence_len = usize::try_from(read_u32_be(bytes, 12, "checkpoint evidence length")?)
        .map_err(|_| eyre::eyre!("checkpoint evidence length does not fit usize"))?;
    let expected_len = CHECKPOINT_WITNESS_HEADER_BYTES
        .checked_add(transcript_len)
        .and_then(|value| value.checked_add(evidence_len))
        .ok_or_else(|| eyre::eyre!("checkpoint witness size overflow"))?;
    ensure!(
        transcript_len != 0
            && evidence_len != 0
            && evidence_len <= MAX_CHECKPOINT_EVIDENCE_BYTES
            && expected_len == bytes.len(),
        "checkpoint witness lengths"
    );

    let expected_finalized = FinalizedExecution {
        beacon_slot: read_u64_be(bytes, 16, "checkpoint finalized beacon slot")?,
        beacon_root: B256::from_slice(&bytes[24..56]),
        block_number: read_u64_be(bytes, 56, "checkpoint finalized block number")?,
        block_hash: B256::from_slice(&bytes[64..96]),
        timestamp: read_u64_be(bytes, 96, "checkpoint finalized timestamp")?,
        receipts_root: B256::from_slice(&bytes[104..136]),
        state_root: B256::from_slice(&bytes[136..168]),
    };
    validate_expected_finalized(&expected_finalized)?;
    let transcript_end = CHECKPOINT_WITNESS_HEADER_BYTES + transcript_len;
    let transcript_bytes = &bytes[CHECKPOINT_WITNESS_HEADER_BYTES..transcript_end];
    let evidence_bytes = &bytes[transcript_end..];
    crate::preflight_transcript_json(transcript_bytes)?;
    crate::preflight_evidence_json(evidence_bytes)?;
    let transcript = transcript_bytes.to_vec();
    let evidence: CheckpointEvidence = serde_json::from_slice(evidence_bytes)?;
    if let Some(ancestry) = &evidence.execution_ancestry {
        crate::ancestry::validate_ancestry_allocation_bounds(ancestry)?;
    }
    crate::receipts::validate_receipt_allocation_bounds(&evidence.receipt)?;
    crate::state::validate_account_allocation_bounds(&evidence.registry_account)?;
    crate::state::validate_storage_allocation_bounds(&evidence.config_storage)?;
    crate::state::validate_runtime_code_allocation_bounds(&evidence.runtime_bytecode)?;
    ensure!(
        serde_json::to_vec(&evidence)?.as_slice() == evidence_bytes,
        "noncanonical checkpoint evidence encoding"
    );
    Ok(CheckpointWitness {
        transcript,
        expected_finalized,
        evidence,
    })
}

fn validate_expected_finalized(expected: &FinalizedExecution) -> Result<()> {
    ensure!(
        expected.beacon_slot != 0
            && expected.beacon_root != B256::ZERO
            && expected.block_number != 0
            && expected.block_hash != B256::ZERO
            && expected.timestamp != 0
            && expected.receipts_root != B256::ZERO
            && expected.state_root != B256::ZERO,
        "zero expected finalized identity"
    );
    Ok(())
}

fn validate_trust_policy(policy: &CheckpointTrustPolicy) -> Result<()> {
    validate_policy(&policy.checkpoint)?;
    crate::validate_fork_schedule(&policy.forks)?;
    ensure!(
        policy.trusted_checkpoint != B256::ZERO
            && policy.ethereum_genesis_validators_root
                == policy.checkpoint.ethereum_genesis_validators_root
            && policy.max_current_slot != 0,
        "invalid checkpoint trust policy"
    );
    Ok(())
}

fn validate_policy(policy: &CheckpointPolicy) -> Result<()> {
    ensure!(
        policy.ethereum_chain_id == MAINNET_CHAIN_ID
            && policy.ethereum_genesis_validators_root != B256::ZERO
            && policy.registry != Address::ZERO
            && policy.runtime_code_hash != B256::ZERO
            && policy.checkpoint_config_hash != B256::ZERO
            && policy.bridge_domain != B256::ZERO
            && policy.dom_network_magic != 0,
        "invalid checkpoint policy"
    );
    Ok(())
}

fn compose_checkpoint(
    event: &VerifiedLog,
    code: &CheckedCodeSnapshot,
    config: &VerifiedStorageWord,
    execution: &FinalizedExecution,
    finality_head: &FinalizedExecution,
    policy: &CheckpointPolicy,
) -> Result<VerifiedCheckpoint> {
    validate_policy(policy)?;
    let locator = event.locator();
    ensure!(
        locator.genesis_validators_root == policy.ethereum_genesis_validators_root
            && event.emitter() == policy.registry
            && code.location().address == policy.registry
            && config.location().address == policy.registry
            && code.code_hash() == policy.runtime_code_hash,
        "checkpoint registry identity mismatch"
    );
    ensure!(
        code.location() == config.location()
            && code.location().genesis_validators_root == locator.genesis_validators_root
            && code.location().block_hash == locator.block_hash
            && code.location().block_number == locator.block_number,
        "checkpoint evidence spans different execution states"
    );
    ensure!(
        execution.block_hash == locator.block_hash
            && execution.block_number == locator.block_number
            && execution.receipts_root != B256::ZERO
            && execution.state_root != B256::ZERO
            && execution.beacon_slot != 0
            && execution.beacon_root != B256::ZERO,
        "checkpoint execution identity mismatch"
    );
    ensure!(
        finality_head.beacon_slot >= execution.beacon_slot
            && finality_head.block_number >= execution.block_number
            && finality_head.timestamp >= execution.timestamp
            && finality_head.block_hash != B256::ZERO
            && finality_head.beacon_root != B256::ZERO,
        "checkpoint finality head regressed"
    );
    ensure!(
        config.slot() == policy.config_storage_slot
            && config.value() == U256::from_be_bytes(*policy.checkpoint_config_hash),
        "checkpoint configuration storage mismatch"
    );

    let topics = event.topics();
    ensure!(topics.len() == 3, "checkpoint event topic count");
    ensure!(
        topics[1] == policy.bridge_domain,
        "checkpoint bridge domain mismatch"
    );
    let network_word = topics[2].as_slice();
    ensure!(
        network_word[..28] == [0; 28]
            && read_u32_be(network_word, 28, "checkpoint DOM network")? == policy.dom_network_magic,
        "checkpoint DOM network mismatch"
    );

    let data = event.data();
    ensure!(data.len() == 128, "checkpoint event data length");
    ensure!(data[..24] == [0; 24], "noncanonical checkpoint height");
    let dom_height = read_u64_be(data, 24, "checkpoint DOM height")?;
    let dom_block = B256::from_slice(&data[32..64]);
    let dom_state_root = B256::from_slice(&data[64..96]);
    let event_config_hash = B256::from_slice(&data[96..128]);
    ensure!(
        dom_height != 0 && dom_block != B256::ZERO && dom_state_root != B256::ZERO,
        "zero DOM checkpoint identity"
    );
    ensure!(
        event_config_hash == policy.checkpoint_config_hash,
        "checkpoint event configuration mismatch"
    );

    let event_digest = checkpoint_struct_digest(
        policy.bridge_domain,
        policy.dom_network_magic,
        dom_height,
        dom_block,
        dom_state_root,
        policy.checkpoint_config_hash,
    );
    let record = encode_record(
        dom_height,
        dom_block,
        dom_state_root,
        execution,
        locator,
        policy,
        event_digest,
    );
    Ok(VerifiedCheckpoint {
        record,
        finalized: finality_head.clone(),
        trust_policy_hash: B256::ZERO,
    })
}

fn checkpoint_struct_digest(
    bridge_domain: B256,
    dom_network_magic: u32,
    dom_height: u64,
    dom_block: B256,
    dom_state_root: B256,
    checkpoint_config_hash: B256,
) -> B256 {
    let mut encoded = [0u8; 224];
    encoded[..32].copy_from_slice(keccak256(CHECKPOINT_STRUCT).as_slice());
    encoded[32..64].copy_from_slice(bridge_domain.as_slice());
    encoded[92..96].copy_from_slice(&dom_network_magic.to_be_bytes());
    encoded[120..128].copy_from_slice(&dom_height.to_be_bytes());
    encoded[128..160].copy_from_slice(dom_block.as_slice());
    encoded[160..192].copy_from_slice(dom_state_root.as_slice());
    encoded[192..224].copy_from_slice(checkpoint_config_hash.as_slice());
    keccak256(encoded)
}

#[allow(clippy::too_many_arguments)]
fn encode_record(
    dom_height: u64,
    dom_block: B256,
    dom_state_root: B256,
    execution: &FinalizedExecution,
    locator: &LogLocator,
    policy: &CheckpointPolicy,
    event_digest: B256,
) -> [u8; CHECKPOINT_RECORD_LENGTH] {
    let mut record = [0u8; CHECKPOINT_RECORD_LENGTH];
    record[0] = 2;
    record[1..9].copy_from_slice(&dom_height.to_be_bytes());
    record[9..41].copy_from_slice(dom_block.as_slice());
    record[41..73].copy_from_slice(dom_state_root.as_slice());
    record[73..77].copy_from_slice(&policy.dom_network_magic.to_be_bytes());
    record[77..85].copy_from_slice(&policy.ethereum_chain_id.to_be_bytes());
    record[85..93].copy_from_slice(&execution.block_number.to_be_bytes());
    record[93..125].copy_from_slice(execution.block_hash.as_slice());
    record[125..157].copy_from_slice(execution.receipts_root.as_slice());
    record[157..189].copy_from_slice(execution.state_root.as_slice());
    record[189..197].copy_from_slice(&execution.beacon_slot.to_be_bytes());
    record[197..229].copy_from_slice(execution.beacon_root.as_slice());
    record[229..261].copy_from_slice(policy.ethereum_genesis_validators_root.as_slice());
    record[261..265].copy_from_slice(&locator.transaction_index.to_be_bytes());
    record[265..269].copy_from_slice(&locator.receipt_log_index.to_be_bytes());
    record[269..289].copy_from_slice(policy.registry.as_slice());
    record[289..321].copy_from_slice(policy.runtime_code_hash.as_slice());
    record[321..353].copy_from_slice(policy.checkpoint_config_hash.as_slice());
    record[353..385].copy_from_slice(policy.bridge_domain.as_slice());
    record[385..417].copy_from_slice(event_digest.as_slice());
    record
}

impl VerifiedCheckpoint {
    /// Exact bounded v2 record. Decoding alone must never recreate this type.
    pub fn record(&self) -> &[u8; CHECKPOINT_RECORD_LENGTH] {
        &self.record
    }

    /// Exact finalized Ethereum execution identity reconstructed by replaying
    /// the authenticated light-client transcript. This includes the execution
    /// timestamp required by native burn-deadline admission.
    pub fn finalized_execution(&self) -> &FinalizedExecution {
        &self.finalized
    }

    /// Immutable trust-policy commitment used by witness replay. Direct local
    /// composition has no full light-client trust policy and returns zero;
    /// native conversion rejects that form.
    pub fn trust_policy_hash(&self) -> B256 {
        self.trust_policy_hash
    }
}

/// Build a fixture capability without Ethereum verification. This function is
/// absent unless the explicitly unsafe test-only feature is enabled.
#[cfg(feature = "unsafe-test-oracle")]
pub fn unsafe_test_only_verified_checkpoint(
    record: [u8; CHECKPOINT_RECORD_LENGTH],
    timestamp: u64,
    trust_policy_hash: B256,
) -> VerifiedCheckpoint {
    let mut block_number = [0u8; 8];
    block_number.copy_from_slice(&record[85..93]);
    let mut beacon_slot = [0u8; 8];
    beacon_slot.copy_from_slice(&record[189..197]);
    let finalized = FinalizedExecution {
        block_number: u64::from_be_bytes(block_number),
        block_hash: B256::from_slice(&record[93..125]),
        timestamp,
        receipts_root: B256::from_slice(&record[125..157]),
        state_root: B256::from_slice(&record[157..189]),
        beacon_slot: u64::from_be_bytes(beacon_slot),
        beacon_root: B256::from_slice(&record[197..229]),
    };
    VerifiedCheckpoint {
        record,
        finalized,
        trust_policy_hash,
    }
}

/// Build a fixture whose checkpoint event predates the authenticated finality
/// head. This constructor is absent from production builds.
#[cfg(feature = "unsafe-test-oracle")]
pub fn unsafe_test_only_verified_checkpoint_with_finality(
    record: [u8; CHECKPOINT_RECORD_LENGTH],
    finalized: FinalizedExecution,
    trust_policy_hash: B256,
) -> VerifiedCheckpoint {
    VerifiedCheckpoint {
        record,
        finalized,
        trust_policy_hash,
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, b256, Log};

    use super::*;
    use crate::{
        receipts::test_verified_log,
        state::{test_checked_code_snapshot, test_verified_storage_word, AccountLocation},
    };

    const REGISTRY: Address = address!("1111111111111111111111111111111111111111");
    const GENESIS: B256 = b256!("2222222222222222222222222222222222222222222222222222222222222222");
    const EXECUTION: B256 =
        b256!("3333333333333333333333333333333333333333333333333333333333333333");
    const RECEIPTS: B256 =
        b256!("4444444444444444444444444444444444444444444444444444444444444444");
    const STATE: B256 = b256!("5555555555555555555555555555555555555555555555555555555555555555");
    const BEACON: B256 = b256!("6666666666666666666666666666666666666666666666666666666666666666");
    const CODE: B256 = b256!("7777777777777777777777777777777777777777777777777777777777777777");
    const CONFIG: B256 = b256!("8888888888888888888888888888888888888888888888888888888888888888");
    const DOMAIN: B256 = b256!("9999999999999999999999999999999999999999999999999999999999999999");
    const DOM_BLOCK: B256 =
        b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const DOM_STATE: B256 =
        b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    fn supported_forks() -> EthereumForks {
        let fork = |epoch, version| EthereumFork {
            epoch,
            fork_version: [version, 0, 0, 0].into(),
        };
        EthereumForks {
            genesis: fork(0, 0),
            altair: fork(74_240, 1),
            bellatrix: fork(144_896, 2),
            capella: fork(194_048, 3),
            deneb: fork(269_568, 4),
            electra: fork(364_032, 5),
            fulu: fork(411_392, 6),
            gloas: fork(u64::MAX, 7),
        }
    }
    const SLOT: B256 = b256!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    const NETWORK: u32 = 0x4450_4d52;

    fn policy() -> CheckpointPolicy {
        CheckpointPolicy {
            ethereum_chain_id: 1,
            ethereum_genesis_validators_root: GENESIS,
            registry: REGISTRY,
            runtime_code_hash: CODE,
            config_storage_slot: SLOT,
            checkpoint_config_hash: CONFIG,
            bridge_domain: DOMAIN,
            dom_network_magic: NETWORK,
        }
    }

    fn location() -> AccountLocation {
        AccountLocation {
            genesis_validators_root: GENESIS,
            block_hash: EXECUTION,
            block_number: 20_000_000,
            address: REGISTRY,
        }
    }

    fn execution() -> FinalizedExecution {
        FinalizedExecution {
            beacon_slot: 16_000_000,
            beacon_root: BEACON,
            block_number: 20_000_000,
            block_hash: EXECUTION,
            timestamp: 1_700_000_000,
            receipts_root: RECEIPTS,
            state_root: STATE,
        }
    }

    fn event_with_data(data: Bytes) -> VerifiedLog {
        let mut network = [0u8; 32];
        network[28..].copy_from_slice(&NETWORK.to_be_bytes());
        let log = Log::new(
            REGISTRY,
            vec![keccak256(CHECKPOINT_EVENT), DOMAIN, network.into()],
            data,
        )
        .expect("valid checkpoint log");
        test_verified_log(
            LogLocator {
                genesis_validators_root: GENESIS,
                block_hash: EXECUTION,
                block_number: 20_000_000,
                transaction_index: 7,
                receipt_log_index: 2,
            },
            log,
        )
    }

    fn event() -> VerifiedLog {
        let mut data = [0u8; 128];
        data[24..32].copy_from_slice(&42u64.to_be_bytes());
        data[32..64].copy_from_slice(DOM_BLOCK.as_slice());
        data[64..96].copy_from_slice(DOM_STATE.as_slice());
        data[96..128].copy_from_slice(CONFIG.as_slice());
        event_with_data(Bytes::copy_from_slice(&data))
    }

    fn composed(policy: &CheckpointPolicy) -> Result<VerifiedCheckpoint> {
        compose_checkpoint(
            &event(),
            &test_checked_code_snapshot(location(), CODE, 4096),
            &test_verified_storage_word(location(), SLOT, U256::from_be_bytes(*CONFIG)),
            &execution(),
            &execution(),
            policy,
        )
    }

    fn untrusted_evidence() -> CheckpointEvidence {
        CheckpointEvidence {
            execution_ancestry: None,
            receipt: ReceiptEvidence {
                block_hash: EXECUTION,
                block_number: 20_000_000,
                transaction_index: 7,
                receipt_bytes: Bytes::from(vec![1, 2, 3]),
                proof: vec![Bytes::from(vec![4, 5, 6])],
            },
            receipt_log_index: 2,
            registry_account: AccountEvidence {
                block_hash: EXECUTION,
                block_number: 20_000_000,
                address: REGISTRY,
                account_rlp: Some(Bytes::from(vec![7, 8, 9])),
                proof: vec![Bytes::from(vec![10, 11])],
            },
            config_storage: StorageEvidence {
                slot: SLOT,
                value: U256::from_be_bytes(*CONFIG),
                proof: vec![Bytes::from(vec![12, 13])],
            },
            runtime_bytecode: Bytes::from(vec![0x60, 0x00]),
        }
    }

    #[test]
    fn exact_composition_emits_dom_chain_v2_wire_record() {
        let verified = composed(&policy()).unwrap();
        assert_eq!(verified.trust_policy_hash(), B256::ZERO);
        let bytes = verified.record();
        assert_eq!(verified.finalized_execution(), &execution());
        assert_eq!(
            alloy::primitives::hex::encode(bytes),
            include_str!("../fixtures/checkpoint-handoff-v2.hex").trim()
        );
        assert_eq!(bytes.len(), CHECKPOINT_RECORD_LENGTH);
        assert_eq!(bytes[0], 2);
        assert_eq!(&bytes[1..9], &42u64.to_be_bytes());
        assert_eq!(&bytes[9..41], DOM_BLOCK.as_slice());
        assert_eq!(&bytes[41..73], DOM_STATE.as_slice());
        assert_eq!(&bytes[73..77], &NETWORK.to_be_bytes());
        assert_eq!(&bytes[77..85], &1u64.to_be_bytes());
        assert_eq!(&bytes[85..93], &20_000_000u64.to_be_bytes());
        assert_eq!(&bytes[93..125], EXECUTION.as_slice());
        assert_eq!(&bytes[125..157], RECEIPTS.as_slice());
        assert_eq!(&bytes[157..189], STATE.as_slice());
        assert_eq!(&bytes[189..197], &16_000_000u64.to_be_bytes());
        assert_eq!(&bytes[197..229], BEACON.as_slice());
        assert_eq!(&bytes[229..261], GENESIS.as_slice());
        assert_eq!(&bytes[261..265], &7u32.to_be_bytes());
        assert_eq!(&bytes[265..269], &2u32.to_be_bytes());
        assert_eq!(&bytes[269..289], REGISTRY.as_slice());
        assert_eq!(&bytes[289..321], CODE.as_slice());
        assert_eq!(&bytes[321..353], CONFIG.as_slice());
        assert_eq!(&bytes[353..385], DOMAIN.as_slice());
        assert_eq!(
            &bytes[385..417],
            checkpoint_struct_digest(DOMAIN, NETWORK, 42, DOM_BLOCK, DOM_STATE, CONFIG).as_slice()
        );
    }

    #[test]
    fn trust_policy_hash_binds_immutable_inputs_but_not_dynamic_slot_ceiling() {
        let trust = CheckpointTrustPolicy {
            trusted_checkpoint: B256::repeat_byte(0x41),
            ethereum_genesis_validators_root: GENESIS,
            forks: supported_forks(),
            max_current_slot: 17_000_000,
            checkpoint: policy(),
        };
        let expected = checkpoint_trust_policy_hash(&trust);
        let mut later_slot = trust.clone();
        later_slot.max_current_slot += 1;
        assert_eq!(checkpoint_trust_policy_hash(&later_slot), expected);

        let mut other_registry = trust.clone();
        other_registry.checkpoint.registry = Address::repeat_byte(0x42);
        assert_ne!(checkpoint_trust_policy_hash(&other_registry), expected);
        let mut other_bootstrap = trust.clone();
        other_bootstrap.trusted_checkpoint = B256::repeat_byte(0x43);
        assert_ne!(checkpoint_trust_policy_hash(&other_bootstrap), expected);
        let mut other_forks = trust;
        other_forks.forks.fulu.epoch += 1;
        assert_ne!(checkpoint_trust_policy_hash(&other_forks), expected);
    }

    #[test]
    fn static_policy_discards_caller_slot_and_materializes_only_explicit_ceiling() {
        let dynamic = CheckpointTrustPolicy {
            trusted_checkpoint: B256::repeat_byte(0x41),
            ethereum_genesis_validators_root: GENESIS,
            forks: supported_forks(),
            max_current_slot: u64::MAX,
            checkpoint: policy(),
        };
        let frozen = StaticCheckpointTrustPolicy::from_trust_policy(&dynamic).unwrap();
        assert_eq!(frozen.policy_hash(), checkpoint_trust_policy_hash(&dynamic));
        assert_eq!(frozen.checkpoint(), &dynamic.checkpoint);
        let encoded = frozen.to_bytes();
        assert_eq!(encoded.len(), STATIC_CHECKPOINT_TRUST_POLICY_BYTES);
        let decoded = StaticCheckpointTrustPolicy::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.to_bytes(), encoded);
        assert_eq!(decoded.policy_hash(), frozen.policy_hash());
        for end in 0..STATIC_CHECKPOINT_TRUST_POLICY_BYTES {
            assert!(StaticCheckpointTrustPolicy::from_bytes(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(StaticCheckpointTrustPolicy::from_bytes(&trailing).is_err());
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(StaticCheckpointTrustPolicy::from_bytes(&wrong_magic).is_err());
        let mut wrong_version = encoded.clone();
        wrong_version[9] ^= 1;
        assert!(StaticCheckpointTrustPolicy::from_bytes(&wrong_version).is_err());
        let mut substituted_registry = encoded;
        substituted_registry[8 + 106] ^= 1;
        let substituted = StaticCheckpointTrustPolicy::from_bytes(&substituted_registry).unwrap();
        assert_ne!(substituted.policy_hash(), frozen.policy_hash());
        assert_eq!(
            frozen.at_max_current_slot(123).unwrap().max_current_slot,
            123
        );
        assert!(frozen.at_max_current_slot(0).is_err());

        let mut invalid = dynamic;
        invalid.trusted_checkpoint = B256::ZERO;
        assert!(StaticCheckpointTrustPolicy::from_trust_policy(&invalid).is_err());
    }

    #[test]
    fn historical_event_record_retains_newer_authenticated_finality_head() {
        let mut head = execution();
        head.block_number += 10;
        head.block_hash = B256::repeat_byte(0xd1);
        head.timestamp += 120;
        head.receipts_root = B256::repeat_byte(0xd2);
        head.state_root = B256::repeat_byte(0xd3);
        head.beacon_slot += 10;
        head.beacon_root = B256::repeat_byte(0xd4);
        let verified = compose_checkpoint(
            &event(),
            &test_checked_code_snapshot(location(), CODE, 4096),
            &test_verified_storage_word(location(), SLOT, U256::from_be_bytes(*CONFIG)),
            &execution(),
            &head,
            &policy(),
        )
        .unwrap();
        assert_eq!(verified.finalized_execution(), &head);
        assert_eq!(
            &verified.record()[85..93],
            &execution().block_number.to_be_bytes()
        );

        let mut regressed = head;
        regressed.timestamp = execution().timestamp - 1;
        assert!(compose_checkpoint(
            &event(),
            &test_checked_code_snapshot(location(), CODE, 4096),
            &test_verified_storage_word(location(), SLOT, U256::from_be_bytes(*CONFIG)),
            &execution(),
            &regressed,
            &policy(),
        )
        .is_err());
    }

    #[test]
    fn any_policy_or_event_identity_mismatch_fails_closed() {
        let mut cases = Vec::new();
        let mut p = policy();
        p.ethereum_chain_id = 31337;
        cases.push(p);
        let mut p = policy();
        p.ethereum_genesis_validators_root = B256::repeat_byte(1);
        cases.push(p);
        let mut p = policy();
        p.registry = Address::repeat_byte(1);
        cases.push(p);
        let mut p = policy();
        p.runtime_code_hash = B256::repeat_byte(1);
        cases.push(p);
        let mut p = policy();
        p.config_storage_slot = B256::repeat_byte(1);
        cases.push(p);
        let mut p = policy();
        p.checkpoint_config_hash = B256::repeat_byte(1);
        cases.push(p);
        let mut p = policy();
        p.bridge_domain = B256::repeat_byte(1);
        cases.push(p);
        let mut p = policy();
        p.dom_network_magic ^= 1;
        cases.push(p);
        for bad in cases {
            assert!(composed(&bad).is_err());
        }
    }

    #[test]
    fn malformed_or_zero_checkpoint_payload_fails_closed() {
        let code = test_checked_code_snapshot(location(), CODE, 4096);
        let storage = test_verified_storage_word(location(), SLOT, U256::from_be_bytes(*CONFIG));
        let malformed = event_with_data(Bytes::from(vec![0u8; 127]));
        assert!(compose_checkpoint(
            &malformed,
            &code,
            &storage,
            &execution(),
            &execution(),
            &policy()
        )
        .is_err());

        let mut data = [0u8; 128];
        data[32..64].copy_from_slice(DOM_BLOCK.as_slice());
        data[64..96].copy_from_slice(DOM_STATE.as_slice());
        data[96..128].copy_from_slice(CONFIG.as_slice());
        let zero = event_with_data(Bytes::copy_from_slice(&data));
        assert!(compose_checkpoint(
            &zero,
            &code,
            &storage,
            &execution(),
            &execution(),
            &policy()
        )
        .is_err());
    }

    #[test]
    fn witness_wire_is_bounded_canonical_and_exactly_framed() {
        let transcript = br#"{"bootstrap":{},"updates":[],"version":1}"#;
        let wire = encode_checkpoint_witness(transcript, &execution(), &untrusted_evidence())
            .expect("bounded witness");
        let decoded = decode_checkpoint_witness(&wire).expect("canonical witness");
        assert_eq!(decoded.transcript, transcript);
        assert_eq!(decoded.expected_finalized, execution());
        assert_eq!(decoded.evidence, untrusted_evidence());
        assert!(wire.len() < MAX_CHECKPOINT_WITNESS_BYTES);

        for end in 0..CHECKPOINT_WITNESS_HEADER_BYTES {
            assert!(
                decode_checkpoint_witness(&wire[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(decode_checkpoint_witness(&trailing).is_err());
        let mut wrong_magic = wire.clone();
        wrong_magic[0] ^= 1;
        assert!(decode_checkpoint_witness(&wrong_magic).is_err());

        let mut noncanonical = wire.clone();
        noncanonical.push(b' ');
        let evidence_len =
            u32::from_be_bytes(noncanonical[12..16].try_into().expect("fixed word")) + 1;
        noncanonical[12..16].copy_from_slice(&evidence_len.to_be_bytes());
        assert!(decode_checkpoint_witness(&noncanonical)
            .unwrap_err()
            .to_string()
            .contains("noncanonical checkpoint evidence"));
    }

    #[test]
    fn witness_encoder_rejects_zero_identity_and_oversize() {
        let transcript = b"{}";
        let mut zero = execution();
        zero.state_root = B256::ZERO;
        assert!(encode_checkpoint_witness(transcript, &zero, &untrusted_evidence()).is_err());
        let mut zero_timestamp = execution();
        zero_timestamp.timestamp = 0;
        assert!(
            encode_checkpoint_witness(transcript, &zero_timestamp, &untrusted_evidence()).is_err()
        );
        assert!(encode_checkpoint_witness(
            &vec![0; MAX_CHECKPOINT_WITNESS_BYTES],
            &execution(),
            &untrusted_evidence(),
        )
        .is_err());
    }
}

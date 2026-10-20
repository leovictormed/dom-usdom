//! Composition boundary for a finalized reserve deposit.
//!
//! This module does not make an arbitrary event a mint authorization. It accepts
//! only opaque results produced by receipt and finalized-state verification, then
//! applies a caller-configured immutable reserve/code/domain policy and canonical
//! ABI decoding. The resulting type remains evidence of a deposit; native DOM
//! consensus must still consume its identity atomically with USDOM issuance.

use alloy::primitives::{keccak256, Address, Bytes, B256};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{
    ancestry::ExecutionAncestryEvidence,
    read_u32_be, read_u64_be,
    receipts::{LogLocator, LogPolicy, ReceiptEvidence, VerifiedLog, VerifiedReceipt},
    state::{AccountEvidence, CheckedCodeSnapshot, VerifiedAccount},
    EthereumForks, FinalizedExecution, HistoricalCapellaClient,
};

const DEPOSIT_EVENT: &[u8] = b"Deposited(bytes32,address,uint64,bytes32)";
const STATIC_DEPOSIT_POLICY_MAGIC: &[u8; 8] = b"UDDPSP01";
const STATIC_DEPOSIT_POLICY_PAYLOAD_BYTES: usize =
    2 + 32 + 32 + 8 + 32 + 20 + 32 + 32 + 8 + 8 * (8 + 4);
/// Exact canonical byte length of one immutable deposit trust policy.
pub const STATIC_DEPOSIT_TRUST_POLICY_BYTES: usize =
    STATIC_DEPOSIT_POLICY_MAGIC.len() + STATIC_DEPOSIT_POLICY_PAYLOAD_BYTES;
// Exact scalar-field bound enforced by USDOMProofReserve.deposit. Rechecking it
// here keeps an authenticated Ethereum event from becoming a partially valid
// consensus capability that fails only in the later native-state conversion.
const BN254_SCALAR_FIELD: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];
const MAINNET_CHAIN_ID: u64 = 1;
const DEPOSIT_WITNESS_MAGIC: &[u8; 8] = b"UDOMDPW1";
const DEPOSIT_WITNESS_HEADER_BYTES: usize = 168;
const MAX_DEPOSIT_EVIDENCE_BYTES: usize = 2 * 1024 * 1024;
/// A deposit witness must fit below the native v4 per-entry ceiling.
pub const MAX_DEPOSIT_WITNESS_BYTES: usize = 4 * 1024 * 1024;

/// Fixed by the protocol/configuration, never selected by the proof relayer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveDepositPolicy {
    pub ethereum_chain_id: u64,
    pub ethereum_genesis_validators_root: B256,
    pub reserve: Address,
    pub runtime_code_hash: B256,
    pub bridge_domain: B256,
    pub max_amount: u64,
}

/// Consensus-selected trust, time, and reserve inputs for one deposit replay.
#[derive(Debug, Clone)]
pub struct DepositTrustPolicy {
    pub trusted_checkpoint: B256,
    pub ethereum_genesis_validators_root: B256,
    pub forks: EthereumForks,
    pub max_current_slot: u64,
    pub deposit: ReserveDepositPolicy,
}

/// Immutable deposit trust inputs owned by runtime configuration.
#[derive(Debug, Clone)]
pub struct StaticDepositTrustPolicy {
    trusted_checkpoint: B256,
    ethereum_genesis_validators_root: B256,
    forks: EthereumForks,
    deposit: ReserveDepositPolicy,
}

impl StaticDepositTrustPolicy {
    fn materialize(&self, max_current_slot: u64) -> DepositTrustPolicy {
        DepositTrustPolicy {
            trusted_checkpoint: self.trusted_checkpoint,
            ethereum_genesis_validators_root: self.ethereum_genesis_validators_root,
            forks: self.forks.clone(),
            max_current_slot,
            deposit: self.deposit.clone(),
        }
    }

    pub fn from_trust_policy(policy: &DepositTrustPolicy) -> Result<Self> {
        let candidate = Self {
            trusted_checkpoint: policy.trusted_checkpoint,
            ethereum_genesis_validators_root: policy.ethereum_genesis_validators_root,
            forks: policy.forks.clone(),
            deposit: policy.deposit.clone(),
        };
        validate_trust_policy(&candidate.at_max_current_slot(1)?)?;
        Ok(candidate)
    }

    pub fn at_max_current_slot(&self, max_current_slot: u64) -> Result<DepositTrustPolicy> {
        ensure!(max_current_slot != 0, "zero consensus slot ceiling");
        Ok(self.materialize(max_current_slot))
    }

    pub fn policy_hash(&self) -> B256 {
        deposit_trust_policy_hash(&self.materialize(1))
    }

    pub fn deposit(&self) -> &ReserveDepositPolicy {
        &self.deposit
    }

    /// Encode every immutable Ethereum-finality and reserve binding in one
    /// fixed-width canonical transport. The dynamic slot ceiling is excluded.
    pub fn to_bytes(&self) -> Vec<u8> {
        let dynamic = self.materialize(1);
        let mut bytes = Vec::with_capacity(STATIC_DEPOSIT_TRUST_POLICY_BYTES);
        bytes.extend_from_slice(STATIC_DEPOSIT_POLICY_MAGIC);
        bytes.extend_from_slice(&deposit_trust_policy_preimage(&dynamic));
        debug_assert_eq!(bytes.len(), STATIC_DEPOSIT_TRUST_POLICY_BYTES);
        bytes
    }

    /// Decode, validate and canonically re-encode one immutable deposit policy.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == STATIC_DEPOSIT_TRUST_POLICY_BYTES
                && &bytes[..8] == STATIC_DEPOSIT_POLICY_MAGIC,
            "invalid static deposit policy framing"
        );
        let payload = &bytes[8..];
        let mut cursor = 0usize;
        let version = u16::from_be_bytes(take_deposit_policy(payload, &mut cursor)?);
        ensure!(version == 1, "unsupported static deposit policy version");
        let trusted_checkpoint = B256::from(take_deposit_policy(payload, &mut cursor)?);
        let ethereum_genesis_validators_root =
            B256::from(take_deposit_policy(payload, &mut cursor)?);
        let ethereum_chain_id = u64::from_be_bytes(take_deposit_policy(payload, &mut cursor)?);
        let deposit_genesis = B256::from(take_deposit_policy(payload, &mut cursor)?);
        let reserve = Address::from(take_deposit_policy(payload, &mut cursor)?);
        let runtime_code_hash = B256::from(take_deposit_policy(payload, &mut cursor)?);
        let bridge_domain = B256::from(take_deposit_policy(payload, &mut cursor)?);
        let max_amount = u64::from_be_bytes(take_deposit_policy(payload, &mut cursor)?);
        let mut next_fork = || -> Result<crate::EthereumFork> {
            Ok(crate::EthereumFork {
                epoch: u64::from_be_bytes(take_deposit_policy(payload, &mut cursor)?),
                fork_version: take_deposit_policy::<4>(payload, &mut cursor)?.into(),
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
            "trailing static deposit policy bytes"
        );
        let dynamic = DepositTrustPolicy {
            trusted_checkpoint,
            ethereum_genesis_validators_root,
            forks,
            max_current_slot: 1,
            deposit: ReserveDepositPolicy {
                ethereum_chain_id,
                ethereum_genesis_validators_root: deposit_genesis,
                reserve,
                runtime_code_hash,
                bridge_domain,
                max_amount,
            },
        };
        let policy = Self::from_trust_policy(&dynamic)?;
        ensure!(
            policy.to_bytes() == bytes,
            "noncanonical static deposit policy"
        );
        Ok(policy)
    }
}

fn take_deposit_policy<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| eyre::eyre!("static deposit policy length overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| eyre::eyre!("truncated static deposit policy"))?
        .try_into()
        .map_err(|_| eyre::eyre!("invalid static deposit policy field"))?;
    *cursor = end;
    Ok(value)
}

/// Untrusted witness for one reserve deposit. Both Merkle proofs and the runtime
/// bytecode are checked against the same finalized execution header held by the
/// light client; the relayer cannot choose either authenticated root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReserveDepositEvidence {
    /// None is accepted only when the transaction block itself is a retained
    /// finalized execution header. Earlier blocks require an authenticated chain.
    #[serde(default)]
    pub execution_ancestry: Option<ExecutionAncestryEvidence>,
    pub receipt: ReceiptEvidence,
    pub receipt_log_index: u32,
    pub reserve_account: AccountEvidence,
    pub runtime_bytecode: Bytes,
}

#[derive(Debug)]
struct DepositWitness {
    transcript: Vec<u8>,
    expected_finalized: FinalizedExecution,
    evidence: ReserveDepositEvidence,
}

/// A successful finalized log from the pinned reserve code, decoded canonically.
/// Fields are private so callers cannot fabricate monetary evidence directly.
/// This is not yet a native mint capability or proof of DOM consensus acceptance.
/// ```compile_fail
/// use alloy::primitives::{Address, B256};
/// use usdom_ethereum_finality_experiment::deposits::VerifiedDeposit;
/// fn forge() -> VerifiedDeposit {
///     VerifiedDeposit {
///         locator: todo!(), reserve: Address::ZERO, runtime_code_hash: B256::ZERO,
///         bridge_domain: B256::ZERO, deposit_id: B256::ZERO, funder: Address::ZERO,
///         amount: 1, receiving_commitment: B256::ZERO, finality_beacon_slot: 1,
///         finality_beacon_root: B256::ZERO,
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDeposit {
    locator: LogLocator,
    reserve: Address,
    runtime_code_hash: B256,
    bridge_domain: B256,
    deposit_id: B256,
    funder: Address,
    amount: u64,
    receiving_commitment: B256,
    finalized: FinalizedExecution,
    trust_policy_hash: B256,
}

/// Compose two opaque verification results from the exact same finalized block.
/// The runtime code snapshot is post-state evidence. This is sufficient only for
/// a reviewed non-upgradeable reserve whose event-time semantics cannot change.
fn compose_reserve_deposit(
    event: &VerifiedLog,
    code: &CheckedCodeSnapshot,
    policy: &ReserveDepositPolicy,
    execution: &FinalizedExecution,
    finalized: &FinalizedExecution,
) -> Result<VerifiedDeposit> {
    validate_policy(policy)?;
    ensure!(
        execution.block_hash == event.locator().block_hash
            && execution.block_number == event.locator().block_number
            && finalized.beacon_slot >= execution.beacon_slot
            && finalized.block_number >= execution.block_number
            && finalized.timestamp >= execution.timestamp
            && finalized.block_hash != B256::ZERO
            && finalized.beacon_root != B256::ZERO,
        "invalid deposit execution/finality identity"
    );
    let event_location = event.locator();
    let code_location = code.location();
    ensure!(
        event_location.genesis_validators_root == policy.ethereum_genesis_validators_root
            && event.emitter() == policy.reserve
            && code_location.address == policy.reserve
            && code.code_hash() == policy.runtime_code_hash,
        "reserve identity mismatch"
    );
    ensure!(
        code_location.genesis_validators_root == event_location.genesis_validators_root
            && code_location.block_hash == event_location.block_hash
            && code_location.block_number == event_location.block_number,
        "receipt and code snapshot are from different finalized states"
    );

    let topics = event.topics();
    ensure!(
        topics.len() == 3 && topics[0] == keccak256(DEPOSIT_EVENT),
        "wrong reserve deposit event"
    );
    let deposit_id = topics[1];
    ensure!(deposit_id != B256::ZERO, "zero deposit ID");
    let funder_word = topics[2].as_slice();
    ensure!(funder_word[..12] == [0; 12], "noncanonical indexed funder");
    let funder = Address::from_slice(&funder_word[12..]);
    ensure!(funder != Address::ZERO, "zero deposit funder");

    let data = event.data();
    ensure!(data.len() == 64, "reserve deposit data length");
    ensure!(data[..24] == [0; 24], "noncanonical uint64 amount");
    let amount = read_u64_be(data, 24, "reserve deposit amount")?;
    ensure!(
        amount != 0 && amount <= policy.max_amount,
        "deposit amount outside policy"
    );
    let receiving_commitment = B256::from_slice(&data[32..64]);
    ensure!(
        receiving_commitment != B256::ZERO
            && receiving_commitment.as_slice() < BN254_SCALAR_FIELD.as_slice(),
        "noncanonical receiving commitment"
    );

    Ok(VerifiedDeposit {
        locator: event_location.clone(),
        reserve: policy.reserve,
        runtime_code_hash: policy.runtime_code_hash,
        bridge_domain: policy.bridge_domain,
        deposit_id,
        funder,
        amount,
        receiving_commitment,
        finalized: finalized.clone(),
        trust_policy_hash: B256::ZERO,
    })
}

impl HistoricalCapellaClient {
    /// Verify receipt inclusion, the reserve account, its runtime bytecode, and
    /// the canonical deposit event against one finalized Ethereum block.
    pub fn verify_reserve_deposit(
        &self,
        evidence: &ReserveDepositEvidence,
        policy: &ReserveDepositPolicy,
    ) -> Result<VerifiedDeposit> {
        validate_policy(policy)?;
        let (receipt, account, execution) = if let Some(ancestry) = &evidence.execution_ancestry {
            let authenticated = self.verify_execution_ancestry(ancestry)?;
            let header = authenticated.finalized_execution();
            (
                crate::receipts::verify_receipt_at(self.genesis_root, header, &evidence.receipt)?,
                crate::state::verify_account_at(
                    self.genesis_root,
                    header,
                    &evidence.reserve_account,
                )?,
                header.clone(),
            )
        } else {
            let header = self
                .finalized_execution(evidence.receipt.block_hash, evidence.receipt.block_number)?;
            (
                self.verify_receipt(&evidence.receipt)?,
                self.verify_account(&evidence.reserve_account)?,
                header.clone(),
            )
        };
        finish_verified_reserve_deposit(
            receipt,
            evidence.receipt_log_index,
            account,
            &evidence.runtime_bytecode,
            policy,
            &execution,
            &self.finalized(),
        )
    }
}

fn finish_verified_reserve_deposit(
    receipt: VerifiedReceipt,
    receipt_log_index: u32,
    account: Option<VerifiedAccount>,
    runtime_bytecode: &[u8],
    policy: &ReserveDepositPolicy,
    execution: &FinalizedExecution,
    finalized: &FinalizedExecution,
) -> Result<VerifiedDeposit> {
    let event = receipt.log(
        receipt_log_index,
        &LogPolicy {
            emitter: policy.reserve,
            topic0: keccak256(DEPOSIT_EVENT),
            topic_count: 3,
        },
    )?;
    let account = account.ok_or_else(|| eyre::eyre!("reserve account is absent"))?;
    ensure!(
        account.is_emitter_post_state_for(&event),
        "reserve account and event are from different finalized states"
    );
    let code = account.check_contract_code(policy.runtime_code_hash, runtime_bytecode)?;
    compose_reserve_deposit(&event, &code, policy, execution, finalized)
}

/// Encode the canonical, bounded witness replayed independently by every node.
pub fn encode_deposit_witness(
    transcript: &[u8],
    expected_finalized: &FinalizedExecution,
    evidence: &ReserveDepositEvidence,
) -> Result<Vec<u8>> {
    ensure!(!transcript.is_empty(), "empty finality transcript");
    validate_expected_finalized(expected_finalized)?;
    let evidence_bytes = serde_json::to_vec(evidence)?;
    ensure!(
        !evidence_bytes.is_empty() && evidence_bytes.len() <= MAX_DEPOSIT_EVIDENCE_BYTES,
        "deposit evidence byte limit"
    );
    let total = DEPOSIT_WITNESS_HEADER_BYTES
        .checked_add(transcript.len())
        .and_then(|value| value.checked_add(evidence_bytes.len()))
        .ok_or_else(|| eyre::eyre!("deposit witness size overflow"))?;
    ensure!(
        total <= MAX_DEPOSIT_WITNESS_BYTES
            && transcript.len() <= u32::MAX as usize
            && evidence_bytes.len() <= u32::MAX as usize,
        "deposit witness byte limit"
    );
    let mut wire = Vec::with_capacity(total);
    wire.extend_from_slice(DEPOSIT_WITNESS_MAGIC);
    wire.extend_from_slice(&(transcript.len() as u32).to_be_bytes());
    wire.extend_from_slice(&(evidence_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&expected_finalized.beacon_slot.to_be_bytes());
    wire.extend_from_slice(expected_finalized.beacon_root.as_slice());
    wire.extend_from_slice(&expected_finalized.block_number.to_be_bytes());
    wire.extend_from_slice(expected_finalized.block_hash.as_slice());
    wire.extend_from_slice(&expected_finalized.timestamp.to_be_bytes());
    wire.extend_from_slice(expected_finalized.receipts_root.as_slice());
    wire.extend_from_slice(expected_finalized.state_root.as_slice());
    debug_assert_eq!(wire.len(), DEPOSIT_WITNESS_HEADER_BYTES);
    wire.extend_from_slice(transcript);
    wire.extend_from_slice(&evidence_bytes);
    Ok(wire)
}

/// Replay Ethereum finality and all reserve proofs under consensus-owned policy.
pub fn verify_deposit_witness(
    bytes: &[u8],
    policy: &DepositTrustPolicy,
) -> Result<VerifiedDeposit> {
    validate_trust_policy(policy)?;
    let witness = decode_deposit_witness(bytes)?;
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
    let mut deposit = client.verify_reserve_deposit(&witness.evidence, &policy.deposit)?;
    deposit.trust_policy_hash = deposit_trust_policy_hash(policy);
    Ok(deposit)
}

/// Commit all immutable finality and reserve-verification inputs.
pub fn deposit_trust_policy_hash(policy: &DepositTrustPolicy) -> B256 {
    B256::from_slice(
        dom_core::blake2b_256_tagged(
            "DOM:usdom-deposit-policy:v1",
            &deposit_trust_policy_preimage(policy),
        )
        .as_bytes(),
    )
}

fn deposit_trust_policy_preimage(policy: &DepositTrustPolicy) -> Vec<u8> {
    let deposit = &policy.deposit;
    let mut bytes = Vec::with_capacity(STATIC_DEPOSIT_POLICY_PAYLOAD_BYTES);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(policy.trusted_checkpoint.as_slice());
    bytes.extend_from_slice(policy.ethereum_genesis_validators_root.as_slice());
    bytes.extend_from_slice(&deposit.ethereum_chain_id.to_be_bytes());
    bytes.extend_from_slice(deposit.ethereum_genesis_validators_root.as_slice());
    bytes.extend_from_slice(deposit.reserve.as_slice());
    bytes.extend_from_slice(deposit.runtime_code_hash.as_slice());
    bytes.extend_from_slice(deposit.bridge_domain.as_slice());
    bytes.extend_from_slice(&deposit.max_amount.to_be_bytes());
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
    debug_assert_eq!(bytes.len(), STATIC_DEPOSIT_POLICY_PAYLOAD_BYTES);
    bytes
}

fn decode_deposit_witness(bytes: &[u8]) -> Result<DepositWitness> {
    ensure!(
        bytes.len() >= DEPOSIT_WITNESS_HEADER_BYTES
            && bytes.len() <= MAX_DEPOSIT_WITNESS_BYTES
            && &bytes[..8] == DEPOSIT_WITNESS_MAGIC,
        "deposit witness framing"
    );
    let transcript_len = usize::try_from(read_u32_be(bytes, 8, "deposit transcript length")?)
        .map_err(|_| eyre::eyre!("deposit transcript length does not fit usize"))?;
    let evidence_len = usize::try_from(read_u32_be(bytes, 12, "deposit evidence length")?)
        .map_err(|_| eyre::eyre!("deposit evidence length does not fit usize"))?;
    let expected_len = DEPOSIT_WITNESS_HEADER_BYTES
        .checked_add(transcript_len)
        .and_then(|value| value.checked_add(evidence_len))
        .ok_or_else(|| eyre::eyre!("deposit witness size overflow"))?;
    ensure!(
        transcript_len != 0
            && evidence_len != 0
            && evidence_len <= MAX_DEPOSIT_EVIDENCE_BYTES
            && expected_len == bytes.len(),
        "deposit witness lengths"
    );
    let expected_finalized = FinalizedExecution {
        beacon_slot: read_u64_be(bytes, 16, "deposit finalized beacon slot")?,
        beacon_root: B256::from_slice(&bytes[24..56]),
        block_number: read_u64_be(bytes, 56, "deposit finalized block number")?,
        block_hash: B256::from_slice(&bytes[64..96]),
        timestamp: read_u64_be(bytes, 96, "deposit finalized timestamp")?,
        receipts_root: B256::from_slice(&bytes[104..136]),
        state_root: B256::from_slice(&bytes[136..168]),
    };
    validate_expected_finalized(&expected_finalized)?;
    let transcript_end = DEPOSIT_WITNESS_HEADER_BYTES + transcript_len;
    let transcript = bytes[DEPOSIT_WITNESS_HEADER_BYTES..transcript_end].to_vec();
    let evidence_bytes = &bytes[transcript_end..];
    let evidence: ReserveDepositEvidence = serde_json::from_slice(evidence_bytes)?;
    ensure!(
        serde_json::to_vec(&evidence)?.as_slice() == evidence_bytes,
        "noncanonical deposit evidence encoding"
    );
    Ok(DepositWitness {
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

fn validate_trust_policy(policy: &DepositTrustPolicy) -> Result<()> {
    validate_policy(&policy.deposit)?;
    ensure!(
        policy.trusted_checkpoint != B256::ZERO
            && policy.ethereum_genesis_validators_root
                == policy.deposit.ethereum_genesis_validators_root
            && policy.max_current_slot != 0,
        "invalid deposit trust policy"
    );
    Ok(())
}

fn validate_policy(policy: &ReserveDepositPolicy) -> Result<()> {
    ensure!(
        policy.ethereum_chain_id == MAINNET_CHAIN_ID
            && policy.ethereum_genesis_validators_root != B256::ZERO
            && policy.reserve != Address::ZERO
            && policy.runtime_code_hash != B256::ZERO
            && policy.bridge_domain != B256::ZERO
            && policy.max_amount != 0,
        "invalid reserve deposit policy"
    );
    Ok(())
}

impl VerifiedDeposit {
    pub fn locator(&self) -> &LogLocator {
        &self.locator
    }
    pub fn reserve(&self) -> Address {
        self.reserve
    }
    pub fn runtime_code_hash(&self) -> B256 {
        self.runtime_code_hash
    }
    pub fn bridge_domain(&self) -> B256 {
        self.bridge_domain
    }
    pub fn deposit_id(&self) -> B256 {
        self.deposit_id
    }
    pub fn funder(&self) -> Address {
        self.funder
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
    pub fn receiving_commitment(&self) -> B256 {
        self.receiving_commitment
    }
    pub fn finality_beacon_slot(&self) -> u64 {
        self.finalized.beacon_slot
    }
    pub fn finality_beacon_root(&self) -> B256 {
        self.finalized.beacon_root
    }
    pub fn finalized_execution(&self) -> &FinalizedExecution {
        &self.finalized
    }
    pub fn trust_policy_hash(&self) -> B256 {
        self.trust_policy_hash
    }
}

/// Builds fixture evidence without Ethereum verification. This symbol does not
/// exist unless an explicitly unsafe test-only feature is enabled.
#[cfg(feature = "unsafe-test-oracle")]
pub struct UnsafeTestDeposit {
    pub genesis_validators_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub block_number: u64,
    pub transaction_index: u32,
    pub receipt_log_index: u32,
    pub reserve: [u8; 20],
    pub runtime_code_hash: [u8; 32],
    pub bridge_domain: [u8; 32],
    pub deposit_id: [u8; 32],
    pub funder: [u8; 20],
    pub amount: u64,
    pub receiving_commitment: [u8; 32],
    pub finality_beacon_slot: u64,
    pub finality_beacon_root: [u8; 32],
    pub finality_execution_block_number: u64,
    pub finality_execution_block_hash: [u8; 32],
    pub finality_execution_timestamp: u64,
    pub trust_policy_hash: [u8; 32],
}

#[cfg(feature = "unsafe-test-oracle")]
pub fn unsafe_test_only_verified_deposit(fixture: UnsafeTestDeposit) -> VerifiedDeposit {
    VerifiedDeposit {
        locator: LogLocator {
            genesis_validators_root: fixture.genesis_validators_root.into(),
            block_hash: fixture.block_hash.into(),
            block_number: fixture.block_number,
            transaction_index: fixture.transaction_index,
            receipt_log_index: fixture.receipt_log_index,
        },
        reserve: fixture.reserve.into(),
        runtime_code_hash: fixture.runtime_code_hash.into(),
        bridge_domain: fixture.bridge_domain.into(),
        deposit_id: fixture.deposit_id.into(),
        funder: fixture.funder.into(),
        amount: fixture.amount,
        receiving_commitment: fixture.receiving_commitment.into(),
        finalized: FinalizedExecution {
            beacon_slot: fixture.finality_beacon_slot,
            beacon_root: fixture.finality_beacon_root.into(),
            block_number: fixture.finality_execution_block_number,
            block_hash: fixture.finality_execution_block_hash.into(),
            timestamp: fixture.finality_execution_timestamp,
            receipts_root: fixture.block_hash.into(),
            state_root: fixture.finality_beacon_root.into(),
        },
        trust_policy_hash: fixture.trust_policy_hash.into(),
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, b256, Bytes, Log, U256};
    use alloy_trie::TrieAccount;
    use serde_json::Value;

    use super::*;
    use crate::{
        receipts::{test_verified_log, test_verify_receipt, ReceiptEvidence},
        state::{test_checked_code_snapshot, test_verify_account, AccountLocation},
        FinalizedExecution,
    };

    const RESERVE: Address = address!("1111111111111111111111111111111111111111");
    const FUNDER: Address = address!("2222222222222222222222222222222222222222");
    const CODE_HASH: B256 =
        b256!("3333333333333333333333333333333333333333333333333333333333333333");
    const DOMAIN: B256 = b256!("4444444444444444444444444444444444444444444444444444444444444444");
    const GENESIS: B256 = b256!("5555555555555555555555555555555555555555555555555555555555555555");
    const BLOCK: B256 = b256!("6666666666666666666666666666666666666666666666666666666666666666");
    const DEPOSIT_ID: B256 =
        b256!("7777777777777777777777777777777777777777777777777777777777777777");
    const COMMITMENT: B256 =
        b256!("1818181818181818181818181818181818181818181818181818181818181818");

    fn locator() -> LogLocator {
        LogLocator {
            genesis_validators_root: GENESIS,
            block_hash: BLOCK,
            block_number: 19_000_000,
            transaction_index: 7,
            receipt_log_index: 1,
        }
    }

    fn policy() -> ReserveDepositPolicy {
        ReserveDepositPolicy {
            ethereum_chain_id: 1,
            ethereum_genesis_validators_root: GENESIS,
            reserve: RESERVE,
            runtime_code_hash: CODE_HASH,
            bridge_domain: DOMAIN,
            max_amount: 100_000_000_000,
        }
    }

    fn code() -> CheckedCodeSnapshot {
        test_checked_code_snapshot(
            AccountLocation {
                genesis_validators_root: GENESIS,
                block_hash: BLOCK,
                block_number: 19_000_000,
                address: RESERVE,
            },
            CODE_HASH,
            12_345,
        )
    }

    fn event(amount: u64) -> VerifiedLog {
        let mut funder = [0u8; 32];
        funder[12..].copy_from_slice(FUNDER.as_slice());
        let mut data = [0u8; 64];
        data[24..32].copy_from_slice(&amount.to_be_bytes());
        data[32..].copy_from_slice(COMMITMENT.as_slice());
        let log = Log::new(
            RESERVE,
            vec![keccak256(DEPOSIT_EVENT), DEPOSIT_ID, funder.into()],
            Bytes::copy_from_slice(&data),
        )
        .expect("valid test log");
        test_verified_log(locator(), log)
    }

    fn raw_event(emitter: Address, topics: Vec<B256>, data: Vec<u8>) -> VerifiedLog {
        test_verified_log(
            locator(),
            Log::new(emitter, topics, Bytes::from(data)).expect("valid raw test log"),
        )
    }

    fn compose(
        event: &VerifiedLog,
        code: &CheckedCodeSnapshot,
        policy: &ReserveDepositPolicy,
    ) -> Result<VerifiedDeposit> {
        let finalized = FinalizedExecution {
            beacon_slot: 1,
            beacon_root: B256::repeat_byte(1),
            block_number: 19_000_000,
            block_hash: BLOCK,
            timestamp: 1,
            receipts_root: B256::repeat_byte(2),
            state_root: B256::repeat_byte(3),
        };
        compose_reserve_deposit(event, code, policy, &finalized, &finalized)
    }

    #[test]
    fn exact_event_and_code_snapshot_create_opaque_deposit() {
        let deposit = compose(&event(1_000_000), &code(), &policy()).unwrap();
        assert_eq!(deposit.locator(), &locator());
        assert_eq!(deposit.reserve(), RESERVE);
        assert_eq!(deposit.runtime_code_hash(), CODE_HASH);
        assert_eq!(deposit.bridge_domain(), DOMAIN);
        assert_eq!(deposit.deposit_id(), DEPOSIT_ID);
        assert_eq!(deposit.funder(), FUNDER);
        assert_eq!(deposit.amount(), 1_000_000);
        assert_eq!(deposit.receiving_commitment(), COMMITMENT);
        assert_eq!(deposit.finality_beacon_slot(), 1);
        assert_eq!(deposit.finality_beacon_root(), B256::repeat_byte(1));
    }

    fn local_bundle(
        vector_index: usize,
    ) -> (
        Value,
        FinalizedExecution,
        ReserveDepositEvidence,
        ReserveDepositPolicy,
    ) {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/local-reserve-receipts.json")).unwrap();
        let block = &fixture["block"];
        let block_hash: B256 = block["hash"].as_str().unwrap().parse().unwrap();
        let block_number = u64::from_str_radix(
            block["number"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let timestamp = u64::from_str_radix(
            block["timestamp"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let finalized = FinalizedExecution {
            beacon_slot: 1,
            beacon_root: B256::repeat_byte(1),
            block_number,
            block_hash,
            timestamp,
            receipts_root: block["receiptsRoot"].as_str().unwrap().parse().unwrap(),
            state_root: block["stateRoot"].as_str().unwrap().parse().unwrap(),
        };
        let reserve: Address = fixture["reserve"].as_str().unwrap().parse().unwrap();
        let account = &fixture["reserveAccount"];
        let runtime_bytecode: Bytes = account["code"].as_str().unwrap().parse().unwrap();
        let runtime_code_hash: B256 = account["codeHash"].as_str().unwrap().parse().unwrap();
        assert_eq!(keccak256(&runtime_bytecode), runtime_code_hash);
        let claimed_account = TrieAccount::new(
            account["nonce"]
                .as_str()
                .unwrap()
                .parse::<U256>()
                .unwrap()
                .try_into()
                .unwrap(),
            account["balance"].as_str().unwrap().parse().unwrap(),
            account["storageHash"].as_str().unwrap().parse().unwrap(),
            runtime_code_hash,
        );
        let account_evidence = AccountEvidence {
            block_hash,
            block_number,
            address: reserve,
            account_rlp: Some(alloy_rlp::encode(claimed_account).into()),
            proof: account["accountProof"]
                .as_array()
                .unwrap()
                .iter()
                .map(|node| node.as_str().unwrap().parse().unwrap())
                .collect(),
        };
        let vector = &fixture["fixtures"][vector_index];
        let evidence = ReserveDepositEvidence {
            execution_ancestry: None,
            receipt: ReceiptEvidence {
                block_hash,
                block_number,
                transaction_index: vector["transactionIndex"]
                    .as_u64()
                    .unwrap()
                    .try_into()
                    .unwrap(),
                receipt_bytes: vector["receipt"].as_str().unwrap().parse().unwrap(),
                proof: vector["proof"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|node| node.as_str().unwrap().parse().unwrap())
                    .collect(),
            },
            receipt_log_index: vector["receiptLogIndex"].as_u64().unwrap() as u32,
            reserve_account: account_evidence,
            runtime_bytecode,
        };
        let policy = ReserveDepositPolicy {
            ethereum_chain_id: 1,
            ethereum_genesis_validators_root: GENESIS,
            reserve,
            runtime_code_hash,
            bridge_domain: DOMAIN,
            max_amount: 100_000_000_000,
        };
        (fixture, finalized, evidence, policy)
    }

    fn verify_local_bundle(
        finalized: &FinalizedExecution,
        evidence: &ReserveDepositEvidence,
        policy: &ReserveDepositPolicy,
    ) -> Result<VerifiedDeposit> {
        // Only beacon finality is synthetic. Both MPT proofs and the actual
        // local reserve bytecode are authenticated against this block header.
        let receipt = test_verify_receipt(GENESIS, finalized, &evidence.receipt)?;
        let account = test_verify_account(GENESIS, finalized, &evidence.reserve_account)?;
        finish_verified_reserve_deposit(
            receipt,
            evidence.receipt_log_index,
            account,
            &evidence.runtime_bytecode,
            policy,
            finalized,
            finalized,
        )
    }

    #[test]
    fn local_receipt_account_and_code_proofs_compose_into_a_verified_deposit() {
        for vector_index in 0..2 {
            let (fixture, finalized, evidence, policy) = local_bundle(vector_index);
            let encoded = serde_json::to_vec(&evidence).unwrap();
            let decoded: ReserveDepositEvidence = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, evidence);
            let deposit = verify_local_bundle(&finalized, &decoded, &policy).unwrap();
            let expected = &fixture["fixtures"][vector_index]["deposit"];
            assert_eq!(
                deposit.deposit_id(),
                expected["depositId"]
                    .as_str()
                    .unwrap()
                    .parse::<B256>()
                    .unwrap()
            );
            assert_eq!(
                deposit.funder(),
                expected["funder"]
                    .as_str()
                    .unwrap()
                    .parse::<Address>()
                    .unwrap()
            );
            assert_eq!(
                deposit.amount(),
                expected["amount"].as_str().unwrap().parse::<u64>().unwrap()
            );
            assert_eq!(
                deposit.receiving_commitment(),
                expected["receivingCommitment"]
                    .as_str()
                    .unwrap()
                    .parse::<B256>()
                    .unwrap()
            );
            assert_eq!(deposit.finality_beacon_slot(), finalized.beacon_slot);
            assert_eq!(deposit.finality_beacon_root(), finalized.beacon_root);
        }
    }

    #[test]
    fn full_local_deposit_evidence_fails_closed_when_any_authenticated_part_changes() {
        let (_, finalized, evidence, policy) = local_bundle(0);
        assert!(verify_local_bundle(&finalized, &evidence, &policy).is_ok());

        let mut bad_account_proof = evidence.clone();
        let mut node = bad_account_proof.reserve_account.proof[0].to_vec();
        let last = node.len() - 1;
        node[last] ^= 1;
        bad_account_proof.reserve_account.proof[0] = node.into();
        assert!(verify_local_bundle(&finalized, &bad_account_proof, &policy).is_err());

        let mut bad_receipt_proof = evidence.clone();
        let mut node = bad_receipt_proof.receipt.proof[0].to_vec();
        let last = node.len() - 1;
        node[last] ^= 1;
        bad_receipt_proof.receipt.proof[0] = node.into();
        assert!(verify_local_bundle(&finalized, &bad_receipt_proof, &policy).is_err());

        let mut bad_code = evidence.clone();
        let mut bytecode = bad_code.runtime_bytecode.to_vec();
        bytecode[0] ^= 1;
        bad_code.runtime_bytecode = bytecode.into();
        assert!(verify_local_bundle(&finalized, &bad_code, &policy).is_err());

        let mut bad_state_root = finalized.clone();
        bad_state_root.state_root = B256::repeat_byte(0xa5);
        assert!(verify_local_bundle(&bad_state_root, &evidence, &policy).is_err());

        let mut mixed_block = evidence.clone();
        mixed_block.reserve_account.block_number += 1;
        assert!(verify_local_bundle(&finalized, &mixed_block, &policy).is_err());
    }

    #[test]
    fn policy_and_finalized_state_identity_are_bound() {
        let valid = event(1_000_000);
        let mut changed = policy();
        changed.reserve = Address::repeat_byte(9);
        assert!(compose(&valid, &code(), &changed).is_err());
        let mut changed = policy();
        changed.runtime_code_hash = B256::repeat_byte(9);
        assert!(compose(&valid, &code(), &changed).is_err());
        let mut changed = policy();
        changed.ethereum_genesis_validators_root = B256::repeat_byte(9);
        assert!(compose(&valid, &code(), &changed).is_err());
        let wrong_block = test_checked_code_snapshot(
            AccountLocation {
                block_hash: B256::repeat_byte(9),
                ..code().location().clone()
            },
            CODE_HASH,
            12_345,
        );
        assert!(compose(&valid, &wrong_block, &policy()).is_err());
        let good = FinalizedExecution {
            beacon_slot: 1,
            beacon_root: B256::repeat_byte(1),
            block_number: 19_000_000,
            block_hash: BLOCK,
            timestamp: 1,
            receipts_root: B256::repeat_byte(2),
            state_root: B256::repeat_byte(3),
        };
        let mut bad = good.clone();
        bad.beacon_slot = 0;
        assert!(compose_reserve_deposit(&valid, &code(), &policy(), &good, &bad).is_err());
        bad = good.clone();
        bad.beacon_root = B256::ZERO;
        assert!(compose_reserve_deposit(&valid, &code(), &policy(), &good, &bad).is_err());
    }

    #[test]
    fn malformed_or_out_of_policy_event_fields_fail_closed() {
        assert!(compose(&event(0), &code(), &policy()).is_err());
        assert!(compose(&event(policy().max_amount + 1), &code(), &policy()).is_err());

        let mut data = event(1).data().to_vec();
        data[0] = 1;
        let bad_amount = Log::new(RESERVE, event(1).topics().to_vec(), Bytes::from(data)).unwrap();
        assert!(compose(
            &test_verified_log(locator(), bad_amount),
            &code(),
            &policy()
        )
        .is_err());

        let wrong_event = Log::new(
            RESERVE,
            vec![
                keccak256(b"Transfer(address,address,uint256)"),
                DEPOSIT_ID,
                B256::ZERO,
            ],
            Bytes::from(vec![0; 64]),
        )
        .unwrap();
        assert!(compose(
            &test_verified_log(locator(), wrong_event),
            &code(),
            &policy()
        )
        .is_err());

        let valid_topics = event(1).topics().to_vec();
        let valid_data = event(1).data().to_vec();
        let mut zero_id = valid_topics.clone();
        zero_id[1] = B256::ZERO;
        assert!(compose(
            &raw_event(RESERVE, zero_id, valid_data.clone()),
            &code(),
            &policy()
        )
        .is_err());
        let mut noncanonical_funder = valid_topics.clone();
        noncanonical_funder[2].as_mut_slice()[0] = 1;
        assert!(compose(
            &raw_event(RESERVE, noncanonical_funder, valid_data.clone()),
            &code(),
            &policy()
        )
        .is_err());
        let mut zero_funder = valid_topics.clone();
        zero_funder[2] = B256::ZERO;
        assert!(compose(
            &raw_event(RESERVE, zero_funder, valid_data.clone()),
            &code(),
            &policy()
        )
        .is_err());
        let mut zero_commitment = valid_data.clone();
        zero_commitment[32..].fill(0);
        assert!(compose(
            &raw_event(RESERVE, valid_topics.clone(), zero_commitment),
            &code(),
            &policy()
        )
        .is_err());
        for noncanonical in [BN254_SCALAR_FIELD, [0xff; 32]] {
            let mut data = valid_data.clone();
            data[32..].copy_from_slice(&noncanonical);
            assert!(compose(
                &raw_event(RESERVE, valid_topics.clone(), data),
                &code(),
                &policy()
            )
            .is_err());
        }
        let mut largest_canonical = valid_data.clone();
        let mut field_minus_one = BN254_SCALAR_FIELD;
        field_minus_one[31] -= 1;
        largest_canonical[32..].copy_from_slice(&field_minus_one);
        assert!(compose(
            &raw_event(RESERVE, valid_topics.clone(), largest_canonical),
            &code(),
            &policy()
        )
        .is_ok());
        assert!(compose(
            &raw_event(RESERVE, valid_topics.clone(), valid_data[..63].to_vec()),
            &code(),
            &policy()
        )
        .is_err());
        assert!(compose(
            &raw_event(Address::repeat_byte(9), valid_topics, valid_data),
            &code(),
            &policy()
        )
        .is_err());
    }

    #[test]
    fn deposit_witness_wire_is_bounded_canonical_and_exactly_framed() {
        let (_, finalized, evidence, _) = local_bundle(0);
        let encoded =
            encode_deposit_witness(b"canonical-transcript", &finalized, &evidence).unwrap();
        let decoded = decode_deposit_witness(&encoded).unwrap();
        assert_eq!(decoded.transcript, b"canonical-transcript");
        assert_eq!(decoded.expected_finalized, finalized);
        assert_eq!(decoded.evidence, evidence);

        for end in 0..DEPOSIT_WITNESS_HEADER_BYTES {
            assert!(
                decode_deposit_witness(&encoded[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_deposit_witness(&trailing).is_err());
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(decode_deposit_witness(&wrong_magic).is_err());
        let mut wrong_length = encoded.clone();
        wrong_length[11] ^= 1;
        assert!(decode_deposit_witness(&wrong_length).is_err());
        let mut oversized_lengths = encoded;
        oversized_lengths[8..16].fill(0xff);
        assert!(decode_deposit_witness(&oversized_lengths).is_err());
    }

    #[test]
    fn deposit_witness_encoder_rejects_zero_identity_and_oversize() {
        let (_, finalized, evidence, _) = local_bundle(0);
        let mut zero = finalized.clone();
        zero.state_root = B256::ZERO;
        assert!(encode_deposit_witness(b"x", &zero, &evidence).is_err());
        assert!(encode_deposit_witness(&[], &finalized, &evidence).is_err());
        assert!(decode_deposit_witness(&vec![0; MAX_DEPOSIT_WITNESS_BYTES + 1]).is_err());
    }

    #[test]
    fn deposit_policy_hash_binds_immutable_inputs_but_not_slot_ceiling() {
        let dynamic = DepositTrustPolicy {
            trusted_checkpoint: B256::repeat_byte(0x91),
            ethereum_genesis_validators_root: GENESIS,
            forks: EthereumForks::default(),
            max_current_slot: 10,
            deposit: policy(),
        };
        let original = deposit_trust_policy_hash(&dynamic);
        let mut changed = dynamic.clone();
        changed.max_current_slot = 20;
        assert_eq!(deposit_trust_policy_hash(&changed), original);
        changed = dynamic.clone();
        changed.deposit.runtime_code_hash = B256::repeat_byte(0x92);
        assert_ne!(deposit_trust_policy_hash(&changed), original);
        changed = dynamic.clone();
        changed.deposit.max_amount -= 1;
        assert_ne!(deposit_trust_policy_hash(&changed), original);

        let frozen = StaticDepositTrustPolicy::from_trust_policy(&dynamic).unwrap();
        assert_eq!(frozen.policy_hash(), original);
        assert_eq!(frozen.at_max_current_slot(99).unwrap().max_current_slot, 99);
        assert!(frozen.at_max_current_slot(0).is_err());

        let encoded = frozen.to_bytes();
        assert_eq!(encoded.len(), STATIC_DEPOSIT_TRUST_POLICY_BYTES);
        let decoded = StaticDepositTrustPolicy::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.to_bytes(), encoded);
        assert_eq!(decoded.policy_hash(), original);
        for end in 0..STATIC_DEPOSIT_TRUST_POLICY_BYTES {
            assert!(StaticDepositTrustPolicy::from_bytes(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(StaticDepositTrustPolicy::from_bytes(&trailing).is_err());
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(StaticDepositTrustPolicy::from_bytes(&wrong_magic).is_err());
        let mut wrong_version = encoded.clone();
        wrong_version[9] = 2;
        assert!(StaticDepositTrustPolicy::from_bytes(&wrong_version).is_err());
        let mut zero_checkpoint = encoded;
        zero_checkpoint[10..42].fill(0);
        assert!(StaticDepositTrustPolicy::from_bytes(&zero_checkpoint).is_err());
    }
}

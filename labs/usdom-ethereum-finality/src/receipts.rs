//! In-process Rust composition of finalized headers and receipt MPT verification.
//! Finality experiment only. These opaque results authenticate Ethereum data,
//! not reserve code/configuration, issuance eligibility, DOM validity, or finality.
use alloy::{
    consensus::{Eip658Value, ReceiptEnvelope, TxType},
    eips::eip2718::{Decodable2718, Encodable2718},
    primitives::{Address, Bytes, Log, B256},
};
use alloy_trie::{proof::ProofRetainer, root::adjust_index_for_rlp, HashBuilder, Nibbles};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{state::verify_mpt_proof, FinalizedExecution, HistoricalCapellaClient};

const MAX_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_PROOF_NODES: usize = 32;
const MAX_PROOF_BYTES: usize = 512 * 1024;
const MAX_LOGS: usize = 4096;
const MAX_LOG_DATA_BYTES: usize = 65536;

/// Untrusted witness. No root field: the method derives it from private client state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptEvidence {
    pub block_hash: B256,
    pub block_number: u64,
    pub transaction_index: u32,
    pub receipt_bytes: Bytes,
    pub proof: Vec<Bytes>,
}

pub(crate) fn validate_receipt_allocation_bounds(evidence: &ReceiptEvidence) -> Result<()> {
    ensure!(
        !evidence.receipt_bytes.is_empty() && evidence.receipt_bytes.len() <= MAX_RECEIPT_BYTES,
        "receipt byte limit"
    );
    ensure!(
        !evidence.proof.is_empty() && evidence.proof.len() <= MAX_PROOF_NODES,
        "proof node count"
    );
    let total = evidence.proof.iter().try_fold(0usize, |total, node| {
        ensure!(
            !node.is_empty() && node.len() <= MAX_RECEIPT_BYTES,
            "proof node size"
        );
        total
            .checked_add(node.len())
            .ok_or_else(|| eyre::eyre!("proof size overflow"))
    })?;
    ensure!(total <= MAX_PROOF_BYTES, "proof byte limit");
    Ok(())
}

/// Deterministically construct and independently root-check one receipt proof
/// from a complete ordered block receipt set. The output remains untrusted
/// until verified against a finalized header.
pub fn build_receipt_evidence(
    block_hash: B256,
    block_number: u64,
    transaction_index: u32,
    receipts: &[Bytes],
) -> Result<(B256, ReceiptEvidence)> {
    ensure!(
        block_hash != B256::ZERO && block_number != 0,
        "zero receipt block identity"
    );
    ensure!(
        !receipts.is_empty() && receipts.len() <= 4096,
        "receipt set count"
    );
    let target = transaction_index as usize;
    ensure!(target < receipts.len(), "receipt transaction index");
    for receipt in receipts {
        ensure!(
            !receipt.is_empty() && receipt.len() <= MAX_RECEIPT_BYTES,
            "receipt byte limit"
        );
        decode_ethereum_receipt(receipt)?;
    }
    let target_key = Nibbles::unpack(alloy_rlp::encode(transaction_index as u64));
    let retainer = ProofRetainer::new(vec![target_key]);
    let mut builder = HashBuilder::default().with_proof_retainer(retainer);
    for index in 0..receipts.len() {
        let adjusted = adjust_index_for_rlp(index, receipts.len());
        builder.add_leaf(
            Nibbles::unpack(alloy_rlp::encode(adjusted as u64)),
            receipts[adjusted].as_ref(),
        );
    }
    let root = builder.root();
    let proof: Vec<Bytes> = builder
        .take_proof_nodes()
        .into_nodes_sorted()
        .into_iter()
        .map(|(_, node)| node)
        .collect();
    let evidence = ReceiptEvidence {
        block_hash,
        block_number,
        transaction_index,
        receipt_bytes: receipts[target].clone(),
        proof,
    };
    ensure!(
        !evidence.proof.is_empty() && evidence.proof.len() <= MAX_PROOF_NODES,
        "proof node count"
    );
    Ok((root, evidence))
}

/// Position is receipt-relative. A transaction hash/global log index is not proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLocator {
    pub genesis_validators_root: B256,
    pub block_hash: B256,
    pub block_number: u64,
    pub transaction_index: u32,
    pub receipt_log_index: u32,
}

/// The protocol caller fixes this policy. It must not be selected by the relayer.
#[derive(Debug, Clone)]
pub struct LogPolicy {
    pub emitter: Address,
    pub topic0: B256,
    pub topic_count: usize,
}

/// Cannot be built from caller-supplied JSON, a public root, or a public constructor.
/// The client bootstrap/network configuration remains a separate trust boundary.
/// ```compile_fail
/// use alloy::{consensus::ReceiptEnvelope, primitives::B256};
/// use usdom_ethereum_finality_experiment::receipts::VerifiedReceipt;
/// fn forge(receipt: ReceiptEnvelope) -> VerifiedReceipt {
///     VerifiedReceipt { genesis_validators_root: B256::ZERO,
///         block_hash: B256::ZERO, block_number: 1, transaction_index: 0, receipt }
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedReceipt {
    genesis_validators_root: B256,
    block_hash: B256,
    block_number: u64,
    transaction_index: u32,
    receipt: ReceiptEnvelope,
}

/// Evidence of a particular successful log, never a mint authorization by itself.
/// ```compile_fail
/// use alloy::primitives::Log;
/// use usdom_ethereum_finality_experiment::receipts::{LogLocator, VerifiedLog};
/// fn forge(locator: LogLocator, log: Log) -> VerifiedLog {
///     VerifiedLog { locator, log }
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedLog {
    locator: LogLocator,
    log: Log,
}

impl HistoricalCapellaClient {
    pub fn verify_receipt(&self, evidence: &ReceiptEvidence) -> Result<VerifiedReceipt> {
        let header = self.finalized_execution(evidence.block_hash, evidence.block_number)?;
        verify_receipt_at(self.genesis_root, header, evidence)
    }
}

pub(crate) fn verify_receipt_at(
    genesis_validators_root: B256,
    header: &FinalizedExecution,
    evidence: &ReceiptEvidence,
) -> Result<VerifiedReceipt> {
    ensure!(
        evidence.block_hash == header.block_hash && evidence.block_number == header.block_number,
        "receipt block is not the finalized header"
    );
    ensure!(
        !evidence.receipt_bytes.is_empty() && evidence.receipt_bytes.len() <= MAX_RECEIPT_BYTES,
        "receipt byte limit"
    );
    ensure!(
        !evidence.proof.is_empty() && evidence.proof.len() <= MAX_PROOF_NODES,
        "proof node count"
    );
    let mut total = 0usize;
    for node in &evidence.proof {
        ensure!(
            !node.is_empty() && node.len() <= MAX_RECEIPT_BYTES,
            "proof node size"
        );
        total = total
            .checked_add(node.len())
            .ok_or_else(|| eyre::eyre!("proof size overflow"))?;
        ensure!(total <= MAX_PROOF_BYTES, "proof byte limit");
    }
    // Receipt keys are RLP(index), NOT keccak(index), unlike account/storage keys.
    let key = alloy_rlp::encode(evidence.transaction_index as u64);
    verify_mpt_proof(
        header.receipts_root,
        Nibbles::unpack(key),
        Some(evidence.receipt_bytes.to_vec()),
        &evidence.proof,
    )?;
    let receipt = decode_ethereum_receipt(&evidence.receipt_bytes)?;
    Ok(VerifiedReceipt {
        genesis_validators_root,
        block_hash: header.block_hash,
        block_number: header.block_number,
        transaction_index: evidence.transaction_index,
        receipt,
    })
}

fn decode_ethereum_receipt(bytes: &[u8]) -> Result<ReceiptEnvelope> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RECEIPT_BYTES,
        "receipt byte limit"
    );
    let mut input = bytes;
    let receipt = ReceiptEnvelope::decode_2718(&mut input)?;
    ensure!(input.is_empty(), "trailing receipt bytes");
    ensure!(
        matches!(
            receipt.tx_type(),
            TxType::Legacy | TxType::Eip2930 | TxType::Eip1559 | TxType::Eip4844 | TxType::Eip7702
        ),
        "unsupported Ethereum receipt type"
    );
    let decoded = receipt
        .as_receipt()
        .ok_or_else(|| eyre::eyre!("unsupported Ethereum receipt envelope"))?;
    ensure!(
        matches!(decoded.status, Eip658Value::Eip658(_)),
        "pre-Byzantium post-state receipt unsupported"
    );
    ensure!(
        receipt.encoded_2718().as_slice() == bytes,
        "noncanonical receipt encoding"
    );
    ensure!(receipt.logs().len() <= MAX_LOGS, "log count limit");
    for log in receipt.logs() {
        ensure!(
            log.topics().len() <= 4 && log.data.data.len() <= MAX_LOG_DATA_BYTES,
            "log size limit"
        );
    }
    Ok(receipt)
}

impl VerifiedReceipt {
    pub fn is_success(&self) -> bool {
        self.receipt.is_success()
    }
    pub fn log_count(&self) -> usize {
        self.receipt.logs().len()
    }

    pub fn log(&self, receipt_log_index: u32, policy: &LogPolicy) -> Result<VerifiedLog> {
        ensure!(
            self.is_success(),
            "unsuccessful receipt cannot authorize an event"
        );
        ensure!((1..=4).contains(&policy.topic_count), "invalid log policy");
        let log = self
            .receipt
            .logs()
            .get(receipt_log_index as usize)
            .ok_or_else(|| eyre::eyre!("receipt-relative log index"))?;
        ensure!(log.address == policy.emitter, "wrong event emitter");
        ensure!(
            log.topics().len() == policy.topic_count
                && log.topics().first() == Some(&policy.topic0),
            "wrong event signature"
        );
        Ok(VerifiedLog {
            locator: LogLocator {
                genesis_validators_root: self.genesis_validators_root,
                block_hash: self.block_hash,
                block_number: self.block_number,
                transaction_index: self.transaction_index,
                receipt_log_index,
            },
            log: log.clone(),
        })
    }
}

impl VerifiedLog {
    pub fn locator(&self) -> &LogLocator {
        &self.locator
    }
    pub fn emitter(&self) -> Address {
        self.log.address
    }
    pub fn topics(&self) -> &[B256] {
        self.log.topics()
    }
    pub fn data(&self) -> &[u8] {
        &self.log.data.data
    }
}

#[cfg(test)]
pub(crate) fn test_verified_log(locator: LogLocator, log: Log) -> VerifiedLog {
    VerifiedLog { locator, log }
}

#[cfg(test)]
pub(crate) fn test_verify_receipt(
    genesis_validators_root: B256,
    header: &FinalizedExecution,
    evidence: &ReceiptEvidence,
) -> Result<VerifiedReceipt> {
    verify_receipt_at(genesis_validators_root, header, evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ReceiptEnvelope {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/receipt-vectors.json")).unwrap();
        let raw: Bytes = vectors["vectors"][50]["receipt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        decode_ethereum_receipt(&raw).unwrap()
    }

    #[test]
    fn codec_accepts_all_transaction_receipts_through_fulu() {
        // Synthetic envelope variants exercise codec policy only. They are not
        // inclusion proofs and are never presented as authenticated receipts.
        let r = sample().as_receipt_with_bloom().unwrap().clone();
        for ty in [
            TxType::Legacy,
            TxType::Eip2930,
            TxType::Eip1559,
            TxType::Eip4844,
            TxType::Eip7702,
        ] {
            let encoded = ReceiptEnvelope::from_typed(ty, r.clone()).encoded_2718();
            assert_eq!(decode_ethereum_receipt(&encoded).unwrap().tx_type(), ty);
        }
    }

    #[test]
    fn codec_rejects_truncation_trailing_bytes_zero_tag_and_post_state() {
        let original = sample();
        let encoded = original.encoded_2718();
        for end in 0..encoded.len() {
            assert!(
                decode_ethereum_receipt(&encoded[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_ethereum_receipt(&trailing).is_err());
        let legacy = ReceiptEnvelope::from_typed(
            TxType::Legacy,
            original.as_receipt_with_bloom().unwrap().clone(),
        )
        .encoded_2718();
        let mut tagged_zero = vec![0];
        tagged_zero.extend_from_slice(&legacy);
        assert!(decode_ethereum_receipt(&tagged_zero).is_err());
        let mut pre_byzantium = original.as_receipt_with_bloom().unwrap().clone();
        pre_byzantium.receipt.status = Eip658Value::PostState(B256::repeat_byte(7));
        let encoded = ReceiptEnvelope::from_typed(TxType::Legacy, pre_byzantium).encoded_2718();
        assert!(decode_ethereum_receipt(&encoded).is_err());
    }

    #[test]
    fn codec_rejects_noncanonical_status_and_oversized_logs() {
        let original = sample();
        let mut legacy = ReceiptEnvelope::from_typed(
            TxType::Legacy,
            original.as_receipt_with_bloom().unwrap().clone(),
        )
        .encoded_2718();
        let mut remaining = legacy.as_slice();
        alloy_rlp::Header::decode(&mut remaining).unwrap();
        let status_offset = legacy.len() - remaining.len();
        assert_eq!(legacy[status_offset], 1);
        legacy[status_offset] = 2;
        assert!(decode_ethereum_receipt(&legacy).is_err());
        let mut oversized = original.as_receipt_with_bloom().unwrap().clone();
        oversized.receipt.logs[0].data.data = Bytes::from(vec![0; MAX_LOG_DATA_BYTES + 1]);
        let encoded = ReceiptEnvelope::from_typed(TxType::Legacy, oversized).encoded_2718();
        assert!(decode_ethereum_receipt(&encoded)
            .unwrap_err()
            .to_string()
            .contains("log size limit"));
        let mut oversized = original.as_receipt_with_bloom().unwrap().clone();
        oversized.receipt.logs = vec![Log::default(); MAX_LOGS + 1];
        let encoded = ReceiptEnvelope::from_typed(TxType::Legacy, oversized).encoded_2718();
        assert!(decode_ethereum_receipt(&encoded)
            .unwrap_err()
            .to_string()
            .contains("log count limit"));
    }
}

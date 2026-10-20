//! Bounded execution-header ancestry from a transaction block to an execution
//! block already authenticated by Ethereum light-client finality.

use alloy::{
    consensus::Header,
    primitives::{Bytes, B256},
};
use alloy_rlp::Decodable;
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{EthereumFinalityClient, FinalizedExecution};

const MAX_ANCESTRY_HEADERS: usize = 256;
const MAX_HEADER_BYTES: usize = 4 * 1024;
const MAX_ANCESTRY_BYTES: usize = 1024 * 1024;

/// Headers are ordered from the target transaction block through the retained
/// finalized anchor, inclusive. The last header must hash to the anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAncestryEvidence {
    pub anchor_block_hash: B256,
    pub anchor_block_number: u64,
    pub headers_rlp: Vec<Bytes>,
}

/// Opaque execution header proven canonical under a retained finalized anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedExecutionHeader {
    anchor_block_hash: B256,
    anchor_block_number: u64,
    header: FinalizedExecution,
}

impl EthereumFinalityClient {
    pub fn verify_execution_ancestry(
        &self,
        evidence: &ExecutionAncestryEvidence,
    ) -> Result<AuthenticatedExecutionHeader> {
        let anchor =
            self.finalized_execution(evidence.anchor_block_hash, evidence.anchor_block_number)?;
        verify_ancestry(anchor, evidence)
    }
}

fn verify_ancestry(
    anchor: &FinalizedExecution,
    evidence: &ExecutionAncestryEvidence,
) -> Result<AuthenticatedExecutionHeader> {
    ensure!(
        !evidence.headers_rlp.is_empty() && evidence.headers_rlp.len() <= MAX_ANCESTRY_HEADERS,
        "execution ancestry header count"
    );
    let mut total = 0usize;
    let mut decoded = Vec::with_capacity(evidence.headers_rlp.len());
    for raw in &evidence.headers_rlp {
        ensure!(
            !raw.is_empty() && raw.len() <= MAX_HEADER_BYTES,
            "execution header byte limit"
        );
        total = total
            .checked_add(raw.len())
            .ok_or_else(|| eyre::eyre!("execution ancestry size overflow"))?;
        ensure!(total <= MAX_ANCESTRY_BYTES, "execution ancestry byte limit");
        let mut input = raw.as_ref();
        let header = Header::decode(&mut input)?;
        ensure!(input.is_empty(), "trailing execution header bytes");
        ensure!(
            alloy_rlp::encode(&header).as_slice() == raw.as_ref(),
            "noncanonical execution header RLP"
        );
        decoded.push(header);
    }

    for pair in decoded.windows(2) {
        let parent = &pair[0];
        let child = &pair[1];
        ensure!(
            child.number
                == parent
                    .number
                    .checked_add(1)
                    .ok_or_else(|| eyre::eyre!("execution block number overflow"))?
                && child.parent_hash == parent.hash_slow(),
            "broken execution ancestry"
        );
    }

    let target = decoded
        .first()
        .ok_or_else(|| eyre::eyre!("execution ancestry header count"))?;
    let last = decoded
        .last()
        .ok_or_else(|| eyre::eyre!("execution ancestry header count"))?;
    ensure!(
        last.number == anchor.block_number
            && last.hash_slow() == anchor.block_hash
            && last.receipts_root == anchor.receipts_root
            && last.state_root == anchor.state_root,
        "execution ancestry does not end at finalized anchor"
    );
    let target_hash = target.hash_slow();
    Ok(AuthenticatedExecutionHeader {
        anchor_block_hash: anchor.block_hash,
        anchor_block_number: anchor.block_number,
        header: FinalizedExecution {
            beacon_slot: anchor.beacon_slot,
            beacon_root: anchor.beacon_root,
            block_number: target.number,
            block_hash: target_hash,
            timestamp: target.timestamp,
            receipts_root: target.receipts_root,
            state_root: target.state_root,
        },
    })
}

impl AuthenticatedExecutionHeader {
    pub fn anchor_block_hash(&self) -> B256 {
        self.anchor_block_hash
    }

    pub fn anchor_block_number(&self) -> u64 {
        self.anchor_block_number
    }

    pub fn block_hash(&self) -> B256 {
        self.header.block_hash
    }

    pub fn block_number(&self) -> u64 {
        self.header.block_number
    }

    pub fn receipts_root(&self) -> B256 {
        self.header.receipts_root
    }

    pub fn state_root(&self) -> B256 {
        self.header.state_root
    }

    pub(crate) fn finalized_execution(&self) -> &FinalizedExecution {
        &self.header
    }
}

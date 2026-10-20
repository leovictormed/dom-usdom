//! Historical finalized post-state proofs. Code snapshots do NOT prove which
//! code/configuration ran during an earlier transaction in the same block.
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{proof::verify_proof, Nibbles, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::{receipts::VerifiedLog, HistoricalCapellaClient};

const MAX_NODES: usize = 32;
const MAX_NODE_BYTES: usize = 256 * 1024;
const MAX_PROOF_BYTES: usize = 512 * 1024;
const MAX_ACCOUNT_BYTES: usize = 128;
const MAX_CODE_BYTES: usize = 24576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountEvidence {
    pub block_hash: B256,
    pub block_number: u64,
    pub address: Address,
    /// None requests a proof of absence, never a default zero account.
    pub account_rlp: Option<Bytes>,
    pub proof: Vec<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEvidence {
    /// Full 32-byte big-endian storage key, before secure-trie hashing.
    pub slot: B256,
    pub value: U256,
    pub proof: Vec<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLocation {
    pub genesis_validators_root: B256,
    pub block_hash: B256,
    pub block_number: u64,
    pub address: Address,
}

/// Constructed only by verification against the client's finalized state root.
/// ```compile_fail
/// use alloy_trie::TrieAccount;
/// use usdom_ethereum_finality_experiment::state::{AccountLocation, VerifiedAccount};
/// fn forge(location: AccountLocation, account: TrieAccount) -> VerifiedAccount {
///     VerifiedAccount { location, account }
/// }
/// ```
#[derive(Debug)]
pub struct VerifiedAccount {
    location: AccountLocation,
    account: TrieAccount,
}

/// Code matched an authenticated post-state account AND a caller's configured pin.
/// It is not evidence of immutable behavior, proxy implementation, or event-time code.
#[derive(Debug)]
pub struct CheckedCodeSnapshot {
    location: AccountLocation,
    code_hash: B256,
    code_length: usize,
}

#[derive(Debug)]
pub struct VerifiedStorageWord {
    location: AccountLocation,
    slot: B256,
    value: U256,
}

fn check_proof_size(proof: &[Bytes], allow_empty: bool) -> Result<()> {
    ensure!(
        (allow_empty || !proof.is_empty()) && proof.len() <= MAX_NODES,
        "state proof node count"
    );
    let mut total = 0usize;
    for node in proof {
        ensure!(
            !node.is_empty() && node.len() <= MAX_NODE_BYTES,
            "state proof node size"
        );
        total = total
            .checked_add(node.len())
            .ok_or_else(|| eyre::eyre!("state proof size overflow"))?;
        ensure!(total <= MAX_PROOF_BYTES, "state proof byte limit");
    }
    Ok(())
}

impl HistoricalCapellaClient {
    pub fn verify_account(&self, evidence: &AccountEvidence) -> Result<Option<VerifiedAccount>> {
        let header = self.finalized_execution(evidence.block_hash, evidence.block_number)?;
        verify_account_at(self.genesis_root, header, evidence)
    }
}

pub(crate) fn verify_account_at(
    genesis_validators_root: B256,
    header: &crate::FinalizedExecution,
    evidence: &AccountEvidence,
) -> Result<Option<VerifiedAccount>> {
    ensure!(
        evidence.block_hash == header.block_hash && evidence.block_number == header.block_number,
        "account block is not the finalized header"
    );
    check_proof_size(&evidence.proof, header.state_root == EMPTY_ROOT_HASH)?;
    if let Some(raw) = &evidence.account_rlp {
        ensure!(
            !raw.is_empty() && raw.len() <= MAX_ACCOUNT_BYTES,
            "account byte limit"
        );
    }
    // Account keys are keccak(address), unlike receipt keys RLP(index).
    verify_proof(
        header.state_root,
        Nibbles::unpack(keccak256(evidence.address)),
        evidence.account_rlp.as_ref().map(|raw| raw.to_vec()),
        evidence.proof.iter(),
    )?;
    let Some(raw) = &evidence.account_rlp else {
        return Ok(None);
    };
    let mut input = raw.as_ref();
    let account = TrieAccount::decode(&mut input)?;
    ensure!(
        input.is_empty() && alloy_rlp::encode(account) == raw.as_ref(),
        "noncanonical account RLP"
    );
    Ok(Some(VerifiedAccount {
        location: AccountLocation {
            genesis_validators_root,
            block_hash: header.block_hash,
            block_number: header.block_number,
            address: evidence.address,
        },
        account,
    }))
}

impl VerifiedAccount {
    pub fn location(&self) -> &AccountLocation {
        &self.location
    }
    pub fn nonce(&self) -> u64 {
        self.account.nonce
    }
    pub fn balance(&self) -> U256 {
        self.account.balance
    }
    pub fn code_hash(&self) -> B256 {
        self.account.code_hash
    }
    pub fn storage_root(&self) -> B256 {
        self.account.storage_root
    }

    pub fn verify_storage(&self, evidence: &StorageEvidence) -> Result<VerifiedStorageWord> {
        check_proof_size(
            &evidence.proof,
            self.account.storage_root == EMPTY_ROOT_HASH,
        )?;
        // Zero values are represented by absence, not by a leaf containing RLP(0).
        let expected = if evidence.value.is_zero() {
            None
        } else {
            Some(alloy_rlp::encode(evidence.value))
        };
        verify_proof(
            self.account.storage_root,
            Nibbles::unpack(keccak256(evidence.slot)),
            expected,
            evidence.proof.iter(),
        )?;
        Ok(VerifiedStorageWord {
            location: self.location.clone(),
            slot: evidence.slot,
            value: evidence.value,
        })
    }

    pub fn check_contract_code(
        &self,
        expected_code_hash: B256,
        bytecode: &[u8],
    ) -> Result<CheckedCodeSnapshot> {
        ensure!(
            !bytecode.is_empty() && bytecode.len() <= MAX_CODE_BYTES,
            "contract code size"
        );
        ensure!(
            self.account.code_hash != KECCAK_EMPTY && self.account.code_hash == expected_code_hash,
            "contract code pin mismatch"
        );
        ensure!(
            keccak256(bytecode) == self.account.code_hash,
            "bytecode hash mismatch"
        );
        Ok(CheckedCodeSnapshot {
            location: self.location.clone(),
            code_hash: self.account.code_hash,
            code_length: bytecode.len(),
        })
    }

    /// Same network/block/address only. Does not establish code/configuration at
    /// the exact point when the transaction emitted this log.
    pub fn is_emitter_post_state_for(&self, event: &VerifiedLog) -> bool {
        let log = event.locator();
        self.location.genesis_validators_root == log.genesis_validators_root
            && self.location.block_hash == log.block_hash
            && self.location.block_number == log.block_number
            && self.location.address == event.emitter()
    }
}

impl CheckedCodeSnapshot {
    pub fn location(&self) -> &AccountLocation {
        &self.location
    }
    pub fn code_hash(&self) -> B256 {
        self.code_hash
    }
    pub fn code_length(&self) -> usize {
        self.code_length
    }
}

impl VerifiedStorageWord {
    pub fn location(&self) -> &AccountLocation {
        &self.location
    }
    pub fn slot(&self) -> B256 {
        self.slot
    }
    pub fn value(&self) -> U256 {
        self.value
    }
}

#[cfg(test)]
pub(crate) fn test_checked_code_snapshot(
    location: AccountLocation,
    code_hash: B256,
    code_length: usize,
) -> CheckedCodeSnapshot {
    CheckedCodeSnapshot {
        location,
        code_hash,
        code_length,
    }
}

#[cfg(test)]
pub(crate) fn test_verified_storage_word(
    location: AccountLocation,
    slot: B256,
    value: U256,
) -> VerifiedStorageWord {
    VerifiedStorageWord {
        location,
        slot,
        value,
    }
}

#[cfg(test)]
pub(crate) fn test_verify_account(
    genesis_validators_root: B256,
    header: &crate::FinalizedExecution,
    evidence: &AccountEvidence,
) -> Result<Option<VerifiedAccount>> {
    verify_account_at(genesis_validators_root, header, evidence)
}

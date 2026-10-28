use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use alloy::{
    consensus::Header,
    primitives::{Address, Bytes, B256, U256},
};
use dom_usdom_checkpoint_statement::CheckpointStatementV6;
use eyre::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use usdom_ethereum_finality_experiment::{
    ancestry::build_execution_ancestry,
    checkpoints::{
        encode_checkpoint_witness, verify_checkpoint_witness, CheckpointEvidence,
        StaticCheckpointTrustPolicy, MAX_CHECKPOINT_WITNESS_BYTES,
    },
    receipts::build_receipt_evidence,
    state::{account_evidence_from_rpc_claim, RpcAccountClaim, StorageEvidence},
    verified_transcript_from_rest,
};

const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Source {
    static_policy_hex: String,
    max_current_slot: u64,
    bootstrap: Value,
    updates: Vec<Value>,
    finality: Value,
    execution_headers: Vec<Header>,
    receipts: Vec<Bytes>,
    transaction_index: u32,
    receipt_log_index: u32,
    registry_account: RpcAccount,
    config_storage: RpcStorage,
    runtime_bytecode: Bytes,
    source_catalog: Vec<SourceIdentity>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceIdentity {
    execution_operator_id: String,
    execution_origin_keccak256: B256,
    beacon_operator_id: String,
    beacon_origin_keccak256: B256,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcAccount {
    block_hash: B256,
    block_number: u64,
    address: Address,
    nonce: u64,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
    proof: Vec<Bytes>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RpcStorage {
    slot: B256,
    value: U256,
    proof: Vec<Bytes>,
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    let value = input
        .strip_prefix("0x")
        .ok_or_else(|| eyre::eyre!("policy must use 0x-prefixed hex"))?;
    ensure!(
        value.len() % 2 == 0 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid policy hex"
    );
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).map_err(Into::into))
        .collect()
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    // Linux O_NOFOLLOW: the operational target is explicitly Linux and a path
    // swap to a symlink must fail before any bytes are consumed.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(0x20_000)
        .open(path)?;
    let metadata = file.metadata().wrap_err("source metadata")?;
    ensure!(
        metadata.file_type().is_file(),
        "source must be a regular non-symlink file"
    );
    ensure!(
        metadata.len() > 0 && metadata.len() <= maximum,
        "source size limit"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .wrap_err("read source")?;
    ensure!(
        bytes.len() as u64 == metadata.len() && file.metadata()?.len() == metadata.len(),
        "source changed while reading"
    );
    Ok(bytes)
}

fn bind_statement(verified: &[u8; 417], statement: &CheckpointStatementV6) -> Result<()> {
    let checkpoint = &statement.checkpoint;
    ensure!(
        verified[1..9] == checkpoint.height.to_be_bytes(),
        "statement/checkpoint height mismatch"
    );
    ensure!(
        verified[9..41] == checkpoint.block,
        "statement/checkpoint block mismatch"
    );
    ensure!(
        verified[41..73] == checkpoint.state_root,
        "statement/checkpoint state root mismatch"
    );
    ensure!(
        verified[73..77] == checkpoint.dom_network_magic.to_be_bytes(),
        "statement/checkpoint network mismatch"
    );
    ensure!(
        verified[353..385] == checkpoint.bridge_domain,
        "statement/checkpoint bridge domain mismatch"
    );
    Ok(())
}

fn main() -> Result<()> {
    let arguments: Vec<_> = env::args_os().collect();
    ensure!(
        arguments.len() == 4,
        "usage: usdom-build-checkpoint-witness SOURCE_JSON STATEMENT_V6 OUTPUT"
    );
    let source_path = Path::new(&arguments[1]);
    let statement_path = Path::new(&arguments[2]);
    let output_path = Path::new(&arguments[3]);
    ensure!(!output_path.exists(), "output already exists");
    let parent = output_path
        .parent()
        .ok_or_else(|| eyre::eyre!("output has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent).wrap_err("output parent metadata")?;
    ensure!(
        parent_metadata.file_type().is_dir()
            && !parent_metadata.file_type().is_symlink()
            && parent_metadata.uid() == rustix::process::geteuid().as_raw()
            && parent_metadata.permissions().mode() & 0o077 == 0,
        "output parent is unsafe"
    );

    let source_bytes = read_bounded(source_path, MAX_SOURCE_BYTES)?;
    let source: Source = serde_json::from_slice(&source_bytes).wrap_err("decode source")?;
    ensure!(
        (2..=5).contains(&source.source_catalog.len()),
        "source catalog count"
    );
    let mut execution_ids = std::collections::BTreeSet::new();
    let mut beacon_ids = std::collections::BTreeSet::new();
    let mut previous = "";
    for item in &source.source_catalog {
        ensure!(
            !item.execution_operator_id.is_empty()
                && item.execution_operator_id.len() <= 128
                && !item.beacon_operator_id.is_empty()
                && item.beacon_operator_id.len() <= 128
                && item.execution_origin_keccak256 != B256::ZERO
                && item.beacon_origin_keccak256 != B256::ZERO
                && execution_ids.insert(&item.execution_operator_id)
                && beacon_ids.insert(&item.beacon_operator_id)
                && item.execution_operator_id.as_str() > previous,
            "source catalog identity"
        );
        previous = &item.execution_operator_id;
    }
    let policy = StaticCheckpointTrustPolicy::from_bytes(&decode_hex(&source.static_policy_hex)?)?;
    let dynamic = policy.at_max_current_slot(source.max_current_slot)?;
    let (transcript, finalized, replay_slot) = verified_transcript_from_rest(
        source.bootstrap,
        source.updates,
        source.finality,
        policy.trusted_checkpoint(),
        policy.ethereum_genesis_validators_root(),
        policy.forks().clone(),
    )?;
    ensure!(
        replay_slot <= source.max_current_slot,
        "Beacon replay exceeds the authorized slot ceiling"
    );
    let ancestry = if source.execution_headers.is_empty() {
        None
    } else {
        Some(build_execution_ancestry(&source.execution_headers)?)
    };
    let receipt_block_hash = source.registry_account.block_hash;
    let receipt_block_number = source.registry_account.block_number;
    let (receipts_root, receipt) = build_receipt_evidence(
        receipt_block_hash,
        receipt_block_number,
        source.transaction_index,
        &source.receipts,
    )?;
    if ancestry.is_none() {
        ensure!(
            finalized.block_hash == receipt_block_hash
                && finalized.block_number == receipt_block_number,
            "event block needs an execution ancestry proof"
        );
        ensure!(
            finalized.receipts_root == receipts_root,
            "receipt set root differs from finalized header"
        );
    }
    let account = source.registry_account;
    let evidence = CheckpointEvidence {
        execution_ancestry: ancestry,
        receipt,
        receipt_log_index: source.receipt_log_index,
        registry_account: account_evidence_from_rpc_claim(RpcAccountClaim {
            block_hash: account.block_hash,
            block_number: account.block_number,
            address: account.address,
            nonce: account.nonce,
            balance: account.balance,
            storage_root: account.storage_root,
            code_hash: account.code_hash,
            proof: account.proof,
        })?,
        config_storage: StorageEvidence {
            slot: source.config_storage.slot,
            value: source.config_storage.value,
            proof: source.config_storage.proof,
        },
        runtime_bytecode: source.runtime_bytecode,
    };
    let witness = encode_checkpoint_witness(&transcript, &finalized, &evidence)?;
    ensure!(
        witness.len() <= MAX_CHECKPOINT_WITNESS_BYTES,
        "checkpoint witness size limit"
    );
    let verified = verify_checkpoint_witness(&witness, &dynamic)?;
    let statement_bytes = read_bounded(statement_path, 64 * 1024)?;
    let statement = CheckpointStatementV6::from_bytes(&statement_bytes)
        .map_err(|_| eyre::eyre!("invalid checkpoint statement V6"))?;
    bind_statement(verified.record(), &statement)?;

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output_path)?;
    output.write_all(&witness)?;
    output.sync_all()?;
    ensure!(
        output.metadata()?.permissions().mode() & 0o777 == 0o600 && output.metadata()?.nlink() == 1,
        "unsafe output mode"
    );
    drop(output);
    let reread = read_bounded(output_path, MAX_CHECKPOINT_WITNESS_BYTES as u64)?;
    ensure!(reread == witness, "published witness changed");
    let reverified = verify_checkpoint_witness(&reread, &dynamic)?;
    bind_statement(reverified.record(), &statement)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()?;
    println!("checkpoint witness verified and published");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_usdom_checkpoint_statement::CheckpointStatement;

    fn statement() -> CheckpointStatementV6 {
        let mut work1 = [0u8; 32];
        work1[31] = 1;
        let mut work2 = [0u8; 32];
        work2[31] = 2;
        let mut work3 = [0u8; 32];
        work3[31] = 3;
        let mut chain = [0u8; 32];
        chain[31] = 1;
        CheckpointStatementV6 {
            checkpoint: CheckpointStatement {
                bridge_domain: [0x11; 32],
                dom_network_magic: 0xd0_4d_00_01,
                previous_height: 1,
                previous_block: [0x21; 32],
                previous_state_root: [0x22; 32],
                previous_context_hash: [0x23; 32],
                previous_total_difficulty: work1,
                height: 2,
                block: [0x31; 32],
                state_root: [0x32; 32],
                context_hash: [0x33; 32],
                total_difficulty: work2,
                confirmation_height: 3,
                confirmation_block: [0x41; 32],
                confirmation_total_difficulty: work3,
                confirmation_timestamp: 1_700_000_000,
                ethereum_chain_id: chain,
                registry: [0x51; 20],
                activation_schedule_commitment: [0x61; 32],
                checkpoint_config_hash: [0x71; 32],
            },
            total_issued: 10,
            total_burned: 1,
            issuance_closed: false,
        }
    }

    fn record(value: &CheckpointStatementV6) -> [u8; 417] {
        let mut record = [0u8; 417];
        record[0] = 2;
        record[1..9].copy_from_slice(&value.checkpoint.height.to_be_bytes());
        record[9..41].copy_from_slice(&value.checkpoint.block);
        record[41..73].copy_from_slice(&value.checkpoint.state_root);
        record[73..77].copy_from_slice(&value.checkpoint.dom_network_magic.to_be_bytes());
        record[353..385].copy_from_slice(&value.checkpoint.bridge_domain);
        record
    }

    #[test]
    fn outer_statement_binding_rejects_every_mutated_identity() {
        let statement = statement();
        let authentic = record(&statement);
        bind_statement(&authentic, &statement).unwrap();
        for offset in [1usize, 9, 41, 73, 353] {
            let mut mutated = authentic;
            mutated[offset] ^= 1;
            assert!(
                bind_statement(&mutated, &statement).is_err(),
                "accepted mutation at {offset}"
            );
        }
    }

    #[test]
    fn policy_hex_is_strict_and_bounded_by_decoder() {
        assert_eq!(decode_hex("0x00ff").unwrap(), [0, 255]);
        for invalid in ["00", "0x0", "0xzz", "0x 00"] {
            assert!(decode_hex(invalid).is_err());
        }
    }
}

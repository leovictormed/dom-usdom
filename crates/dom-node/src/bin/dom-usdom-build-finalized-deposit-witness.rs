//! Authenticate one collected Ethereum deposit and emit canonical UDOMDPW1.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use alloy::{
    consensus::Header,
    primitives::{Address, Bytes, B256, U256},
};
use dom_config::Network;
use dom_node::{
    native_usdom_config::{load_native_usdom_v4_node_bundle, sha256_hex},
    private_staging_directory::PrivateDirectoryAuthority,
};
use serde::Deserialize;
use serde_json::Value;
use usdom_ethereum_finality_experiment::{
    ancestry::build_execution_ancestry,
    deposits::{
        deposit_witness_replay_slot, encode_deposit_witness, verify_deposit_witness,
        ReserveDepositEvidence, MAX_DEPOSIT_WITNESS_BYTES,
    },
    receipts::build_receipt_evidence,
    state::{account_evidence_from_rpc_claim, RpcAccountClaim},
    verified_transcript_from_rest,
};

const SOURCE_SCHEMA: &str = "usdom-finalized-deposit-source-v1";
const WITNESS_NAME: &str = "finalized-deposit-witness.bin";
const INDEX_NAME: &str = "finalized-deposit-witness-index.json";
const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    source_file: PathBuf,
    output_dir: PathBuf,
    network: Network,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    schema: String,
    release_config_sha256: String,
    native_manifest_sha256: String,
    transaction_hash: B256,
    chain_id: String,
    reserve: Address,
    deposit_id: B256,
    funder: Address,
    amount_base_units: String,
    receiving_commitment: B256,
    transaction_index: u32,
    receipt_log_index: u32,
    deposit_block_number: String,
    deposit_block_hash: B256,
    bootstrap: Value,
    updates: Vec<Value>,
    finality: Value,
    headers: Vec<Value>,
    receipts: Vec<Bytes>,
    reserve_account: RpcAccount,
    runtime_bytecode: Bytes,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RpcAccount {
    address: Address,
    balance: String,
    code_hash: B256,
    nonce: String,
    storage_hash: B256,
    account_proof: Vec<Bytes>,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    require_directory(
        &arguments.output_dir,
        "finalized-deposit witness output directory",
    )?;
    let source_bytes = read_regular_file(&arguments.source_file, MAX_SOURCE_BYTES, "source")?;
    let source: Source = serde_json::from_slice(&source_bytes)?;
    if source.schema != SOURCE_SCHEMA
        || source.native_manifest_sha256 != arguments.manifest_sha256
        || source.chain_id != "1"
        || !is_raw_sha256(&source.release_config_sha256)
        || !is_raw_sha256(&source.native_manifest_sha256)
        || source.transaction_hash == B256::ZERO
        || source.updates.len() > 128
        || source.headers.is_empty()
        || source.headers.len() > 256
        || source.receipts.is_empty()
        || source.receipts.len() > 4096
    {
        anyhow::bail!("finalized-deposit source identity is invalid");
    }
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        arguments.network.magic(),
    )?;
    let policy = bundle.deposit_policy.deposit();
    if arguments.network != Network::Mainnet
        || policy.ethereum_chain_id != 1
        || source.reserve != policy.reserve
        || source.reserve_account.address != policy.reserve
        || source.reserve_account.code_hash != policy.runtime_code_hash
    {
        anyhow::bail!("source differs from the immutable native deposit policy");
    }

    let (transcript, finalized, replay_slot) = verified_transcript_from_rest(
        source.bootstrap,
        source.updates,
        source.finality,
        bundle.ethereum_trusted_checkpoint,
        policy.ethereum_genesis_validators_root,
        bundle.ethereum_forks.clone(),
    )
    .map_err(|error| anyhow::anyhow!("Beacon transcript authentication failed: {error:#}"))?;
    let mut headers = Vec::with_capacity(source.headers.len());
    for value in source.headers {
        let reported: B256 = value
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("execution header has no reported hash"))?
            .parse()?;
        let header: Header = serde_json::from_value(value)?;
        if header.hash_slow() != reported {
            anyhow::bail!("execution header reported hash mismatch");
        }
        headers.push(header);
    }
    let ancestry = build_execution_ancestry(&headers)
        .map_err(|error| anyhow::anyhow!("execution ancestry construction failed: {error:#}"))?;
    let first = headers
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty execution ancestry"))?;
    let last = headers
        .last()
        .ok_or_else(|| anyhow::anyhow!("empty execution ancestry"))?;
    let deposit_block_number =
        parse_decimal_u64(&source.deposit_block_number, "deposit block number")?;
    if first.number != deposit_block_number
        || first.hash_slow() != source.deposit_block_hash
        || last.number != finalized.block_number
        || last.hash_slow() != finalized.block_hash
        || last.receipts_root != finalized.receipts_root
        || last.state_root != finalized.state_root
    {
        anyhow::bail!("execution ancestry endpoints differ from source or Beacon finality");
    }
    let (receipts_root, receipt) = build_receipt_evidence(
        source.deposit_block_hash,
        deposit_block_number,
        source.transaction_index,
        &source.receipts,
    )
    .map_err(|error| anyhow::anyhow!("receipt proof construction failed: {error:#}"))?;
    if receipts_root != first.receipts_root {
        anyhow::bail!("complete receipt set does not reproduce the deposit block root");
    }
    let nonce = parse_quantity_u64(&source.reserve_account.nonce, "reserve nonce")?;
    let balance = parse_quantity_u256(&source.reserve_account.balance, "reserve balance")?;
    let account = account_evidence_from_rpc_claim(RpcAccountClaim {
        block_hash: source.deposit_block_hash,
        block_number: deposit_block_number,
        address: source.reserve_account.address,
        nonce,
        balance,
        storage_root: source.reserve_account.storage_hash,
        code_hash: source.reserve_account.code_hash,
        proof: source.reserve_account.account_proof,
    })
    .map_err(|error| anyhow::anyhow!("account proof construction failed: {error:#}"))?;
    let evidence = ReserveDepositEvidence {
        execution_ancestry: Some(ancestry),
        receipt,
        receipt_log_index: source.receipt_log_index,
        reserve_account: account,
        runtime_bytecode: source.runtime_bytecode,
    };
    let witness = encode_deposit_witness(&transcript, &finalized, &evidence)
        .map_err(|error| anyhow::anyhow!("deposit witness encoding failed: {error:#}"))?;
    let decoded_replay_slot = deposit_witness_replay_slot(&witness)
        .map_err(|error| anyhow::anyhow!("deposit witness replay slot failed: {error:#}"))?;
    if witness.len() > MAX_DEPOSIT_WITNESS_BYTES || decoded_replay_slot != replay_slot {
        anyhow::bail!("deposit witness replay identity is invalid");
    }
    let dynamic = bundle
        .deposit_policy
        .at_max_current_slot(replay_slot)
        .map_err(|error| anyhow::anyhow!("deposit replay policy failed: {error:#}"))?;
    let verified = verify_deposit_witness(&witness, &dynamic)
        .map_err(|error| anyhow::anyhow!("deposit witness verification failed: {error:#}"))?;
    let amount = parse_decimal_u64(&source.amount_base_units, "deposit amount")?;
    if verified.deposit_id() != source.deposit_id
        || verified.funder() != source.funder
        || verified.amount() != amount
        || verified.receiving_commitment() != source.receiving_commitment
        || verified.locator().transaction_index != source.transaction_index
        || verified.locator().receipt_log_index != source.receipt_log_index
        || verified.finalized_execution() != &finalized
    {
        anyhow::bail!("verified deposit differs from the collected public identity");
    }

    let witness_sha256 = sha256_hex(&witness);
    let witness_bytes = witness.len();
    let index = serde_json::json!({
        "schema": "usdom-finalized-deposit-witness-v1",
        "source_file": arguments.source_file.file_name().and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("source filename is invalid"))?,
        "source_sha256": sha256_hex(&source_bytes),
        "native_manifest_sha256": arguments.manifest_sha256,
        "release_config_sha256": source.release_config_sha256,
        "source_transaction_hash": source.transaction_hash,
        "deposit_id": verified.deposit_id(),
        "funder": verified.funder(),
        "amount_base_units": verified.amount().to_string(),
        "receiving_commitment": verified.receiving_commitment(),
        "deposit_block_number": verified.locator().block_number.to_string(),
        "deposit_block_hash": verified.locator().block_hash,
        "finalized_beacon_slot": finalized.beacon_slot.to_string(),
        "finalized_beacon_root": finalized.beacon_root,
        "finalized_execution_block_number": finalized.block_number.to_string(),
        "finalized_execution_block_hash": finalized.block_hash,
        "replay_slot": replay_slot.to_string(),
        "deposit_policy_hash": verified.trust_policy_hash(),
        "witness_file": WITNESS_NAME,
        "witness_sha256": witness_sha256.clone(),
        "witness_bytes": witness_bytes,
        "relation_executed": true,
        "witness_verified": true,
        "mines": false,
        "broadcasts": false
    });
    let mut index_bytes = serde_json::to_vec_pretty(&index)?;
    index_bytes.push(b'\n');
    publish(
        &arguments.output_dir,
        &[
            (WITNESS_NAME.to_owned(), witness),
            (INDEX_NAME.to_owned(), index_bytes),
        ],
    )?;
    println!("status: verified");
    println!("witness_bytes: {witness_bytes}");
    println!("finalized_beacon_slot: {}", finalized.beacon_slot);
    println!("replay_slot: {replay_slot}");
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Arguments> {
    let mut values = arguments.into_iter();
    let _program = values.next();
    let remaining: Vec<OsString> = values.collect();
    let (pairs, tail) = remaining.as_chunks::<2>();
    if !tail.is_empty() {
        anyhow::bail!("every option requires exactly one value");
    }
    let mut manifest_file = None;
    let mut manifest_sha256 = None;
    let mut source_file = None;
    let mut output_dir = None;
    let mut network = None;
    for [flag, value] in pairs {
        match flag.to_str() {
            Some("--manifest-file") if manifest_file.is_none() => {
                manifest_file = Some(value.into())
            }
            Some("--manifest-sha256") if manifest_sha256.is_none() => {
                manifest_sha256 = Some(value.to_string_lossy().into_owned())
            }
            Some("--source-file") if source_file.is_none() => source_file = Some(value.into()),
            Some("--output-dir") if output_dir.is_none() => output_dir = Some(value.into()),
            Some("--network") if network.is_none() => {
                network = Some(match value.to_str() {
                    Some("mainnet") => Network::Mainnet,
                    _ => anyhow::bail!("finalized deposits require mainnet"),
                })
            }
            _ => anyhow::bail!("unknown or duplicate argument {flag:?}"),
        }
    }
    Ok(Arguments {
        manifest_file: manifest_file.ok_or_else(|| anyhow::anyhow!("--manifest-file required"))?,
        manifest_sha256: manifest_sha256
            .ok_or_else(|| anyhow::anyhow!("--manifest-sha256 required"))?,
        source_file: source_file.ok_or_else(|| anyhow::anyhow!("--source-file required"))?,
        output_dir: output_dir.ok_or_else(|| anyhow::anyhow!("--output-dir required"))?,
        network: network.ok_or_else(|| anyhow::anyhow!("--network required"))?,
    })
}

fn read_regular_file(path: &Path, maximum: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    dom_wallet_crypto::read_captured_bytes(path, maximum)
        .map_err(|error| anyhow::anyhow!("cannot capture {label}: {error}"))
}

fn require_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("{label} must be a direct directory");
    }
    Ok(())
}

fn publish(directory: &Path, files: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
    PrivateDirectoryAuthority::open(directory)?.replace_files(files, &[INDEX_NAME])
}

fn parse_quantity_u64(value: &str, label: &str) -> anyhow::Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("{label} prefix"))?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        anyhow::bail!("{label} is noncanonical");
    }
    Ok(u64::from_str_radix(digits, 16)?)
}

fn parse_quantity_u256(value: &str, label: &str) -> anyhow::Result<U256> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("{label} prefix"))?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        anyhow::bail!("{label} is noncanonical");
    }
    U256::from_str_radix(digits, 16).map_err(|error| anyhow::anyhow!("invalid {label}: {error}"))
}

fn parse_decimal_u64(value: &str, label: &str) -> anyhow::Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        anyhow::bail!("{label} is noncanonical");
    }
    Ok(value.parse()?)
}

fn is_raw_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_indirect_and_multiply_linked_sources() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.json");
        fs::write(&source, b"exact").unwrap();
        assert_eq!(read_regular_file(&source, 5, "source").unwrap(), b"exact");

        let linked = directory.path().join("linked.json");
        fs::hard_link(&source, &linked).unwrap();
        assert!(read_regular_file(&source, 5, "source").is_err());
        fs::remove_file(&linked).unwrap();

        let indirect = directory.path().join("indirect.json");
        symlink(&source, &indirect).unwrap();
        assert!(read_regular_file(&indirect, 5, "source").is_err());
        assert!(read_regular_file(&source, 4, "source").is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("finalized-deposit witness build failed");
        std::process::exit(1);
    }
}

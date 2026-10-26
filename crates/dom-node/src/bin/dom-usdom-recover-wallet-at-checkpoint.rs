//! Reconstruct a native USDOM wallet from its portable recovery backup.
//!
//! The command does not trust or read an existing operational snapshot. It
//! authenticates the exact Ethereum deposit, verifies an Ethereum-finalized
//! DOM checkpoint, downloads the complete header- and state-bound DOM history
//! ending at that checkpoint, and publishes a fresh encrypted snapshot.

use std::{
    ffi::OsString,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use dom_core::{configured_genesis_hash_for_network_magic, Hash256, NETWORK_MAGIC_MAINNET};
use dom_node::{
    native_usdom_config::{load_native_usdom_v4_node_bundle, sha256_hex},
    private_staging_directory::PrivateStagingDirectory,
    secret_file::load_owner_only_utf8_secret_file,
};
use dom_usdom_privacy::{chain_scalar, privacy_policy_hash};
use dom_usdom_state::EthereumDepositOccurrence;
use dom_usdom_wallet::{
    AuthenticatedHistoryAnchor, AuthenticatedHistoryRequest, UsdomRpcClient,
    VerifiedCheckpointHistoryAnchor, WalletPassphrase, WalletRecoverySeed, WalletState,
    MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES,
};
use serde_json::Value;
use usdom_ethereum_finality_experiment::{
    checkpoints::{
        checkpoint_witness_replay_slot, verify_checkpoint_witness, MAX_CHECKPOINT_WITNESS_BYTES,
    },
    deposits::{deposit_witness_replay_slot, verify_deposit_witness, MAX_DEPOSIT_WITNESS_BYTES},
};

const MAX_JSON_BYTES: u64 = 128 * 1024;
const SNAPSHOT_NAME: &str = "wallet-state.usdom";
const SEAL_NAME: &str = "wallet-state.seal";
const EVIDENCE_NAME: &str = "wallet-recovery-drill.json";

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    deposit_witness_file: PathBuf,
    deposit_witness_index_file: PathBuf,
    checkpoint_witness_file: PathBuf,
    recovery_file: PathBuf,
    recovery_password_file: PathBuf,
    state_password_file: PathBuf,
    rpc_token_file: PathBuf,
    output_directory: PathBuf,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    if arguments.output_directory.exists() {
        anyhow::bail!("recovery-drill output already exists; refusing to replace it");
    }
    validate_secure_parent(&arguments.output_directory)?;
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        NETWORK_MAGIC_MAINNET,
    )?;
    if bundle.schedule.first_v4_height() != 1
        || bundle.bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes()
    {
        anyhow::bail!("wallet recovery requires the exact closed-Mainnet runtime");
    }

    let deposit_witness = read_direct_file(
        &arguments.deposit_witness_file,
        MAX_DEPOSIT_WITNESS_BYTES as u64,
        "finalized deposit witness",
        false,
    )?;
    let deposit_index_bytes = read_direct_file(
        &arguments.deposit_witness_index_file,
        MAX_JSON_BYTES,
        "finalized deposit witness index",
        false,
    )?;
    let deposit_index: Value = serde_json::from_slice(&deposit_index_bytes)?;
    require_deposit_index(&deposit_index, &arguments.manifest_sha256, &deposit_witness)?;
    let deposit_slot = deposit_witness_replay_slot(&deposit_witness)
        .map_err(|error| anyhow::anyhow!("invalid deposit replay slot: {error:#}"))?;
    let deposit_policy = bundle
        .deposit_policy
        .at_max_current_slot(deposit_slot)
        .map_err(|error| anyhow::anyhow!("invalid deposit replay policy: {error:#}"))?;
    let deposit = verify_deposit_witness(&deposit_witness, &deposit_policy)
        .map_err(|error| anyhow::anyhow!("deposit authentication failed: {error:#}"))?;
    let locator = deposit.locator();
    let occurrence = EthereumDepositOccurrence {
        genesis_validators_root: locator.genesis_validators_root.into(),
        block_hash: locator.block_hash.into(),
        block_number: locator.block_number,
        transaction_index: u64::from(locator.transaction_index),
        receipt_log_index: u64::from(locator.receipt_log_index),
        deposit_id: deposit.deposit_id().into(),
        funder: deposit.funder().into(),
        amount: deposit.amount(),
        receiving_commitment: deposit.receiving_commitment().into(),
    };
    if occurrence.amount != 1_000_000 {
        anyhow::bail!("closed-Mainnet recovery drill requires the exact 1 USDT deposit");
    }

    let checkpoint_witness = read_direct_file(
        &arguments.checkpoint_witness_file,
        MAX_CHECKPOINT_WITNESS_BYTES as u64,
        "Ethereum checkpoint witness",
        false,
    )?;
    let checkpoint_slot = checkpoint_witness_replay_slot(&checkpoint_witness)
        .map_err(|error| anyhow::anyhow!("invalid checkpoint replay slot: {error:#}"))?;
    let checkpoint_policy = bundle
        .checkpoint_policy
        .at_max_current_slot(checkpoint_slot)
        .map_err(|error| anyhow::anyhow!("invalid checkpoint replay policy: {error:#}"))?;
    let verified_checkpoint = verify_checkpoint_witness(&checkpoint_witness, &checkpoint_policy)
        .map_err(|error| anyhow::anyhow!("checkpoint authentication failed: {error:#}"))?;
    let checkpoint_anchor = VerifiedCheckpointHistoryAnchor::from_verified_checkpoint(
        &verified_checkpoint,
        NETWORK_MAGIC_MAINNET,
        Hash256::from_bytes(bundle.bridge.dom_domain),
        Hash256::from_bytes(bundle.bridge.ethereum_checkpoint_policy_hash),
    )?;
    if checkpoint_anchor.trusted_tip().0 < bundle.schedule.first_v4_height() {
        anyhow::bail!("verified checkpoint predates native USDOM activation");
    }

    let recovery_passphrase = WalletPassphrase::new(load_owner_only_utf8_secret_file(
        &arguments.recovery_password_file,
        "native USDOM recovery password",
        MIN_WALLET_PASSPHRASE_BYTES as u64,
        MAX_WALLET_PASSPHRASE_BYTES as u64,
    )?)?;
    let state_passphrase = WalletPassphrase::new(load_owner_only_utf8_secret_file(
        &arguments.state_password_file,
        "TPM-derived native USDOM operational password",
        MIN_WALLET_PASSPHRASE_BYTES as u64,
        MAX_WALLET_PASSPHRASE_BYTES as u64,
    )?)?;
    let policy_hash = *privacy_policy_hash().as_bytes();
    let chain = chain_scalar(bundle.bridge.dom_domain, policy_hash);
    let seed = WalletRecoverySeed::load_encrypted_backup(
        &arguments.recovery_file,
        chain,
        &recovery_passphrase,
    )?;
    let wallet = dom_usdom_wallet::WalletSecrets::from_recovery_seed(chain, &seed)?;
    if wallet.address()?.owner().to_bytes() != occurrence.receiving_commitment {
        anyhow::bail!("recovery backup does not control the authenticated deposit");
    }

    let genesis = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_MAINNET)?;
    let mut state = WalletState::new_empty(chain, 0, genesis)?;
    let client =
        UsdomRpcClient::from_token_file("http://127.0.0.1:33372/", &arguments.rpc_token_file)?;
    let note_commitment = client.recover_historical_deposit_at_verified_checkpoint(
        &mut state,
        &wallet,
        AuthenticatedHistoryRequest {
            network_magic: NETWORK_MAGIC_MAINNET,
            chain_id: bundle.schedule.chain_id(),
            dom_domain: Hash256::from_bytes(bundle.bridge.dom_domain),
            trusted_tip: checkpoint_anchor.trusted_tip(),
            start_height: bundle.schedule.first_v4_height(),
            max_blocks: 16,
            anchor: Some(AuthenticatedHistoryAnchor {
                height: 0,
                block_hash: genesis,
                state_root: bundle.schedule.empty_state_root(),
            }),
        },
        checkpoint_anchor,
        bundle.bridge,
        occurrence,
    )?;
    let expected = state.expected_issuances();
    let note = state
        .note_summaries()
        .into_iter()
        .find(|note| note.commitment == note_commitment)
        .ok_or_else(|| anyhow::anyhow!("recovered deposit note is absent from wallet state"))?;
    if state.tip_height() != checkpoint_anchor.trusted_tip().0
        || state.tip_identifier() != checkpoint_anchor.trusted_tip().1
        || expected.len() != 1
        || expected[0].deposit_id != occurrence.deposit_id
        || expected[0].note_commitment != note_commitment
        || expected[0].amount != occurrence.amount
        || !expected[0].canonical
        || note.value != occurrence.amount
    {
        anyhow::bail!(
            "reconstructed wallet does not match the authenticated deposit and checkpoint"
        );
    }

    let staging = PrivateStagingDirectory::create(&arguments.output_directory)?;
    let temporary = staging.path();
    let seal = state.save_encrypted_snapshot(
        &wallet,
        &temporary.join(SNAPSHOT_NAME),
        &state_passphrase,
        1,
        None,
    )?;
    staging.write_child_noclobber(SEAL_NAME, &seal.to_bytes())?;
    let evidence = serde_json::json!({
        "schema": "usdom-wallet-recovery-drill-v1",
        "native_manifest_sha256": arguments.manifest_sha256,
        "network_magic": format!("{NETWORK_MAGIC_MAINNET:08x}"),
        "chain_id": bundle.schedule.chain_id().to_string(),
        "wallet_address": hex::encode(wallet.address()?.to_bytes()),
        "deposit_id": hex::encode(occurrence.deposit_id),
        "deposit_amount_base_units": occurrence.amount.to_string(),
        "deposit_witness_sha256": sha256_hex(&deposit_witness),
        "checkpoint_witness_sha256": sha256_hex(&checkpoint_witness),
        "checkpoint_event_digest": checkpoint_anchor.checkpoint_event_digest().to_string(),
        "checkpoint_height": checkpoint_anchor.trusted_tip().0.to_string(),
        "checkpoint_block": checkpoint_anchor.trusted_tip().1.to_string(),
        "checkpoint_state_root": checkpoint_anchor.state_root().to_string(),
        "note_commitment": hex::encode(note_commitment.to_bytes()),
        "note_spent_at_checkpoint": note.spent,
        "available_balance_at_checkpoint": state.available_balance().to_string(),
        "snapshot_generation": seal.generation.to_string(),
        "snapshot_seal": hex::encode(seal.to_bytes()),
        "existing_operational_snapshot_read": false,
        "ethereum_broadcasts": false,
        "submits": false,
        "mines": false
    });
    let mut evidence_bytes = serde_json::to_vec_pretty(&evidence)?;
    evidence_bytes.push(b'\n');
    staging.write_child_noclobber(EVIDENCE_NAME, &evidence_bytes)?;
    staging.publish()?;

    println!("status: recovered-at-verified-checkpoint");
    println!("checkpoint_height: {}", checkpoint_anchor.trusted_tip().0);
    println!("checkpoint_block: {}", checkpoint_anchor.trusted_tip().1);
    println!("existing_operational_snapshot_read: false");
    println!("ethereum_broadcasts: false");
    println!("submits: false");
    println!("mines: false");
    Ok(())
}

fn require_deposit_index(
    index: &Value,
    manifest_sha256: &str,
    witness: &[u8],
) -> anyhow::Result<()> {
    let string = |name: &str| {
        index
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("deposit index field {name} is missing"))
    };
    if string("schema")? != "usdom-finalized-deposit-witness-v1"
        || string("native_manifest_sha256")? != manifest_sha256
        || string("witness_sha256")? != sha256_hex(witness)
        || index.get("witness_bytes").and_then(Value::as_u64) != Some(witness.len() as u64)
        || index.get("witness_verified").and_then(Value::as_bool) != Some(true)
        || index.get("relation_executed").and_then(Value::as_bool) != Some(true)
        || index.get("broadcasts").and_then(Value::as_bool) != Some(false)
        || index.get("mines").and_then(Value::as_bool) != Some(false)
    {
        anyhow::bail!("deposit witness index does not bind the exact verified input");
    }
    Ok(())
}

fn read_direct_file(
    path: &Path,
    maximum: u64,
    description: &str,
    require_owner_only: bool,
) -> anyhow::Result<Vec<u8>> {
    let maximum = usize::try_from(maximum)?;
    if require_owner_only {
        let mut captured = dom_wallet_crypto::read_private_bytes(path, maximum)?;
        return Ok(std::mem::take(&mut *captured));
    }
    dom_wallet_crypto::read_captured_bytes(path, maximum)
        .map_err(|error| anyhow::anyhow!("cannot capture {description}: {error}"))
}

fn validate_secure_parent(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("recovery output must have a parent"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!("recovery output parent must be a direct owner-only directory");
    }
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
    let mut map = std::collections::BTreeMap::new();
    for [flag, value] in pairs {
        let flag = flag
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("option name is not UTF-8"))?;
        if map.insert(flag.to_owned(), value.clone()).is_some() {
            anyhow::bail!("duplicate option {flag}");
        }
    }
    const EXPECTED: [&str; 10] = [
        "--manifest-file",
        "--manifest-sha256",
        "--deposit-witness-file",
        "--deposit-witness-index-file",
        "--checkpoint-witness-file",
        "--recovery-file",
        "--recovery-password-file",
        "--state-password-file",
        "--rpc-token-file",
        "--output-directory",
    ];
    if map.keys().any(|key| !EXPECTED.contains(&key.as_str())) || map.len() != EXPECTED.len() {
        anyhow::bail!("recovery requires each documented option exactly once");
    }
    let path = |name: &str| -> anyhow::Result<PathBuf> {
        map.get(name)
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("{name} is required"))
    };
    let manifest_sha256 = map
        .get("--manifest-sha256")
        .and_then(|value| value.to_str())
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| anyhow::anyhow!("--manifest-sha256 must be lowercase SHA-256"))?
        .to_owned();
    Ok(Arguments {
        manifest_file: path("--manifest-file")?,
        manifest_sha256,
        deposit_witness_file: path("--deposit-witness-file")?,
        deposit_witness_index_file: path("--deposit-witness-index-file")?,
        checkpoint_witness_file: path("--checkpoint-witness-file")?,
        recovery_file: path("--recovery-file")?,
        recovery_password_file: path("--recovery-password-file")?,
        state_password_file: path("--state-password-file")?,
        rpc_token_file: path("--rpc-token-file")?,
        output_directory: path("--output-directory")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_missing_duplicate_unknown_and_uppercase_hash() {
        let base = [
            "recover",
            "--manifest-file",
            "/manifest",
            "--manifest-sha256",
            "ab3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1e",
            "--deposit-witness-file",
            "/deposit",
            "--deposit-witness-index-file",
            "/deposit-index",
            "--checkpoint-witness-file",
            "/checkpoint",
            "--recovery-file",
            "/recovery",
            "--recovery-password-file",
            "/recovery-password",
            "--state-password-file",
            "/state-password",
            "--rpc-token-file",
            "/token",
            "--output-directory",
            "/output",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        assert!(parse_arguments(base.clone()).is_ok());
        assert!(parse_arguments(base[..base.len() - 2].to_vec()).is_err());
        let mut duplicate = base.clone();
        duplicate.extend([
            OsString::from("--output-directory"),
            OsString::from("/other"),
        ]);
        assert!(parse_arguments(duplicate).is_err());
        let mut unknown = base.clone();
        unknown[1] = OsString::from("--unknown");
        assert!(parse_arguments(unknown).is_err());
        let mut uppercase = base;
        uppercase[4] =
            OsString::from("AB3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1eab3c2d1e");
        assert!(parse_arguments(uppercase).is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("checkpoint wallet recovery failed");
        std::process::exit(1);
    }
}

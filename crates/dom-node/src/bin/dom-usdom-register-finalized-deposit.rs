//! Register one verified Ethereum deposit in the encrypted native USDOM wallet.
//!
//! The command performs no network request and never submits or mines. It
//! verifies UDOMDPW1 under the hash-pinned native manifest, restores the exact
//! recovery wallet, records the deterministic expected issuance, and atomically
//! publishes the first encrypted wallet-state directory before any submission.

use std::{
    ffi::OsString,
    os::unix::fs::PermissionsExt,
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
    WalletPassphrase, WalletRecoverySeed, WalletSnapshotSeal, WalletState,
    MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES, WALLET_SNAPSHOT_SEAL_BYTES,
};
use serde::Deserialize;
use serde_json::Value;
use usdom_ethereum_finality_experiment::deposits::{
    deposit_witness_replay_slot, verify_deposit_witness, MAX_DEPOSIT_WITNESS_BYTES,
};

const MAX_JSON_BYTES: u64 = 128 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const SNAPSHOT_NAME: &str = "wallet-state.usdom";
const SEAL_NAME: &str = "wallet-state.seal";
const REGISTRATION_NAME: &str = "expected-deposit-registration.json";

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    witness_file: PathBuf,
    witness_index_file: PathBuf,
    recovery_file: PathBuf,
    recovery_password_file: PathBuf,
    state_password_file: PathBuf,
    node_identity_file: PathBuf,
    state_directory: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeIdentity {
    rpc_api_version: u32,
    protocol_version: u32,
    network: String,
    network_magic: String,
    chain_id: String,
    genesis_hash: String,
    tip_height: u64,
    tip_hash: String,
    max_scan_range: u64,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        NETWORK_MAGIC_MAINNET,
    )?;
    let witness = read_direct_file(
        &arguments.witness_file,
        MAX_DEPOSIT_WITNESS_BYTES as u64,
        "finalized deposit witness",
        false,
    )?;
    if witness.is_empty() {
        anyhow::bail!("finalized deposit witness is empty");
    }
    let index_bytes = read_direct_file(
        &arguments.witness_index_file,
        MAX_JSON_BYTES,
        "finalized deposit witness index",
        false,
    )?;
    let index: Value = serde_json::from_slice(&index_bytes)?;
    require_index(&index, &arguments.manifest_sha256, &witness)?;

    let replay_slot = deposit_witness_replay_slot(&witness)
        .map_err(|error| anyhow::anyhow!("deposit replay slot verification failed: {error:#}"))?;
    let policy = bundle
        .deposit_policy
        .at_max_current_slot(replay_slot)
        .map_err(|error| anyhow::anyhow!("deposit replay policy failed: {error:#}"))?;
    let deposit = verify_deposit_witness(&witness, &policy)
        .map_err(|error| anyhow::anyhow!("deposit witness verification failed: {error:#}"))?;
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
        anyhow::bail!("closed mainnet registration requires exactly 1 USDT");
    }

    let policy_hash = *privacy_policy_hash().as_bytes();
    if policy_hash != bundle.bridge.privacy_policy_hash {
        anyhow::bail!("compiled privacy policy differs from the native manifest");
    }
    let chain = chain_scalar(bundle.bridge.dom_domain, policy_hash);
    if chain.is_zero() {
        anyhow::bail!("native wallet chain identity is invalid");
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
    let seed = WalletRecoverySeed::load_encrypted_backup(
        &arguments.recovery_file,
        chain,
        &recovery_passphrase,
    )?;
    let wallet = dom_usdom_wallet::WalletSecrets::from_recovery_seed(chain, &seed)?;
    if wallet.address()?.owner().to_bytes() != occurrence.receiving_commitment {
        anyhow::bail!("finalized deposit receiver differs from the recovery wallet");
    }

    let identity_bytes = read_direct_file(
        &arguments.node_identity_file,
        MAX_JSON_BYTES,
        "DOM node identity",
        false,
    )?;
    let identity: NodeIdentity = serde_json::from_slice(&identity_bytes)?;
    validate_node_identity(
        &identity,
        *bundle.schedule.chain_id().as_bytes(),
        *configured_genesis_hash_for_network_magic(NETWORK_MAGIC_MAINNET)?.as_bytes(),
    )?;
    let tip_hash = decode_hex_array::<32>(&identity.tip_hash, "DOM tip hash")?;
    let tip_identifier = Hash256::from_bytes(tip_hash);

    validate_secure_parent(&arguments.state_directory)?;
    if arguments.state_directory.exists() {
        validate_existing(
            &arguments.state_directory,
            &state_passphrase,
            occurrence,
            wallet.address()?.to_bytes(),
            &arguments.manifest_sha256,
            &witness,
        )?;
        println!("status: already-registered");
        println!("submits: false");
        println!("mines: false");
        return Ok(());
    }

    let mut state = WalletState::new_empty(chain, identity.tip_height, tip_identifier)?;
    let note_commitment = state.register_expected_deposit(&wallet, bundle.bridge, occurrence)?;
    let staging = PrivateStagingDirectory::create(&arguments.state_directory)?;
    let temporary = staging.path();
    let snapshot = temporary.join(SNAPSHOT_NAME);
    let seal = state.save_encrypted_snapshot(&wallet, &snapshot, &state_passphrase, 1, None)?;
    staging.write_child_noclobber(SEAL_NAME, &seal.to_bytes())?;
    let registration = serde_json::json!({
        "schema": "usdom-expected-deposit-registration-v1",
        "native_manifest_sha256": arguments.manifest_sha256,
        "witness_sha256": sha256_hex(&witness),
        "deposit_id": hex::encode(occurrence.deposit_id),
        "amount_base_units": occurrence.amount.to_string(),
        "receiving_commitment": hex::encode(occurrence.receiving_commitment),
        "note_commitment": hex::encode(note_commitment.to_bytes()),
        "wallet_address": hex::encode(wallet.address()?.to_bytes()),
        "registered_tip_height": identity.tip_height.to_string(),
        "registered_tip_hash": identity.tip_hash,
        "snapshot_generation": seal.generation.to_string(),
        "snapshot_seal": hex::encode(seal.to_bytes()),
        "submits": false,
        "mines": false
    });
    let mut registration_bytes = serde_json::to_vec_pretty(&registration)?;
    registration_bytes.push(b'\n');
    staging.write_child_noclobber(REGISTRATION_NAME, &registration_bytes)?;
    staging.publish()?;

    println!("status: registered");
    println!("registered_tip_height: {}", identity.tip_height);
    println!("submits: false");
    println!("mines: false");
    Ok(())
}

fn require_index(index: &Value, manifest_sha256: &str, witness: &[u8]) -> anyhow::Result<()> {
    let string = |name: &str| {
        index
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("witness index field {name} is missing"))
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
        anyhow::bail!("finalized deposit witness index does not bind the exact verified input");
    }
    Ok(())
}

fn validate_node_identity(
    identity: &NodeIdentity,
    expected_chain_id: [u8; 32],
    expected_genesis_hash: [u8; 32],
) -> anyhow::Result<()> {
    if identity.rpc_api_version != 1
        || identity.protocol_version == 0
        || identity.network != "mainnet"
        || identity.network_magic != format!("{NETWORK_MAGIC_MAINNET:08x}")
        || decode_hex_array::<32>(&identity.chain_id, "DOM chain id")? != expected_chain_id
        || decode_hex_array::<32>(&identity.genesis_hash, "DOM genesis hash")?
            != expected_genesis_hash
        || identity.tip_height != 0
        || decode_hex_array::<32>(&identity.tip_hash, "DOM tip hash")? != expected_genesis_hash
        || identity.max_scan_range == 0
    {
        anyhow::bail!("DOM node identity is not a valid mainnet snapshot");
    }
    Ok(())
}

fn validate_existing(
    directory: &Path,
    passphrase: &WalletPassphrase,
    occurrence: EthereumDepositOccurrence,
    expected_address: [u8; dom_usdom_wallet::RECIPIENT_ADDRESS_BYTES],
    manifest_sha256: &str,
    witness: &[u8],
) -> anyhow::Result<()> {
    validate_direct_directory(directory, "wallet state directory")?;
    let seal_bytes = read_direct_file(
        &directory.join(SEAL_NAME),
        WALLET_SNAPSHOT_SEAL_BYTES as u64,
        "wallet snapshot seal",
        true,
    )?;
    let seal = WalletSnapshotSeal::from_bytes(&seal_bytes)?;
    let snapshot_bytes = read_direct_file(
        &directory.join(SNAPSHOT_NAME),
        MAX_SNAPSHOT_BYTES,
        "encrypted wallet snapshot",
        true,
    )?;
    let loaded = WalletState::load_encrypted_snapshot_bytes(&snapshot_bytes, passphrase, seal)?;
    let expected = loaded.state.expected_issuances();
    if loaded.wallet.address()?.to_bytes() != expected_address
        || expected.len() != 1
        || expected[0].deposit_id != occurrence.deposit_id
        || expected[0].amount != occurrence.amount
        || expected[0].canonical
    {
        anyhow::bail!("existing wallet state differs from the finalized deposit");
    }
    let registration_bytes = read_direct_file(
        &directory.join(REGISTRATION_NAME),
        MAX_JSON_BYTES,
        "expected deposit registration",
        true,
    )?;
    let registration: Value = serde_json::from_slice(&registration_bytes)?;
    let witness_sha256 = sha256_hex(witness);
    let deposit_id = hex::encode(occurrence.deposit_id);
    if registration.get("schema").and_then(Value::as_str)
        != Some("usdom-expected-deposit-registration-v1")
        || registration
            .get("native_manifest_sha256")
            .and_then(Value::as_str)
            != Some(manifest_sha256)
        || registration.get("witness_sha256").and_then(Value::as_str)
            != Some(witness_sha256.as_str())
        || registration.get("deposit_id").and_then(Value::as_str) != Some(deposit_id.as_str())
    {
        anyhow::bail!("existing registration metadata differs from the verified witness");
    }
    Ok(())
}

fn read_direct_file(
    path: &Path,
    maximum: u64,
    description: &str,
    owner_only: bool,
) -> anyhow::Result<Vec<u8>> {
    let maximum = usize::try_from(maximum)?;
    if owner_only {
        let mut captured = dom_wallet_crypto::read_private_bytes(path, maximum)?;
        return Ok(std::mem::take(&mut *captured));
    }
    dom_wallet_crypto::read_captured_bytes(path, maximum)
        .map_err(|error| anyhow::anyhow!("cannot capture {description}: {error}"))
}

fn validate_secure_parent(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("state directory must have a parent"))?;
    validate_direct_directory(parent, "wallet state parent")
}

fn validate_direct_directory(path: &Path, description: &str) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!("{description} must be a direct owner-only directory");
    }
    Ok(())
}

fn decode_hex_array<const N: usize>(value: &str, description: &str) -> anyhow::Result<[u8; N]> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(raw).map_err(|_| anyhow::anyhow!("invalid {description}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {description} length"))
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
    let take_path = |name: &str| -> anyhow::Result<PathBuf> {
        map.get(name)
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("{name} is required"))
    };
    let manifest_sha256 = map
        .get("--manifest-sha256")
        .and_then(|value| value.to_str())
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow::anyhow!("--manifest-sha256 is invalid"))?
        .to_owned();
    const EXPECTED: [&str; 9] = [
        "--manifest-file",
        "--manifest-sha256",
        "--witness-file",
        "--witness-index-file",
        "--recovery-file",
        "--recovery-password-file",
        "--state-password-file",
        "--node-identity-file",
        "--state-directory",
    ];
    if map.len() != EXPECTED.len() || map.keys().any(|name| !EXPECTED.contains(&name.as_str())) {
        anyhow::bail!("unknown or missing registration option");
    }
    Ok(Arguments {
        manifest_file: take_path("--manifest-file")?,
        manifest_sha256,
        witness_file: take_path("--witness-file")?,
        witness_index_file: take_path("--witness-index-file")?,
        recovery_file: take_path("--recovery-file")?,
        recovery_password_file: take_path("--recovery-password-file")?,
        state_password_file: take_path("--state-password-file")?,
        node_identity_file: take_path("--node-identity-file")?,
        state_directory: take_path("--state-directory")?,
    })
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("finalized-deposit registration failed");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_node_identity, NodeIdentity};
    use dom_core::NETWORK_MAGIC_MAINNET;

    fn identity(chain_id: [u8; 32], genesis_hash: [u8; 32]) -> NodeIdentity {
        NodeIdentity {
            rpc_api_version: 1,
            protocol_version: 1,
            network: "mainnet".into(),
            network_magic: format!("{NETWORK_MAGIC_MAINNET:08x}"),
            chain_id: hex::encode(chain_id),
            genesis_hash: hex::encode(genesis_hash),
            tip_height: 0,
            tip_hash: hex::encode(genesis_hash),
            max_scan_range: 256,
        }
    }

    #[test]
    fn node_identity_must_match_manifest_chain_id() {
        let expected = [0x11; 32];
        let genesis = [0x22; 32];
        validate_node_identity(&identity(expected, genesis), expected, genesis).unwrap();

        let error =
            validate_node_identity(&identity([0x44; 32], genesis), expected, genesis).unwrap_err();
        assert!(error
            .to_string()
            .contains("DOM node identity is not a valid mainnet snapshot"));

        let error =
            validate_node_identity(&identity(expected, [0x55; 32]), expected, genesis).unwrap_err();
        assert!(error
            .to_string()
            .contains("DOM node identity is not a valid mainnet snapshot"));

        let mut wrong_height = identity(expected, genesis);
        wrong_height.tip_height = 1;
        assert!(validate_node_identity(&wrong_height, expected, genesis).is_err());

        let mut wrong_tip = identity(expected, genesis);
        wrong_tip.tip_hash = "66".repeat(32);
        assert!(validate_node_identity(&wrong_tip, expected, genesis).is_err());
    }
}

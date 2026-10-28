//! Authenticate the one-block closed-Mainnet history and publish an observed
//! encrypted wallet snapshot containing the exact expected deposit note.

use std::{
    ffi::OsString,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use dom_core::{configured_genesis_hash_for_network_magic, Hash256, NETWORK_MAGIC_MAINNET};
use dom_node::{
    native_usdom_config::load_native_usdom_v4_node_bundle,
    private_staging_directory::PrivateStagingDirectory,
    secret_file::load_owner_only_utf8_secret_file,
};
use dom_usdom_wallet::{
    AuthenticatedHistoryAnchor, AuthenticatedHistoryRequest, UsdomRpcClient, WalletPassphrase,
    WalletSnapshotSeal, WalletState, MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES,
    WALLET_SNAPSHOT_SEAL_BYTES,
};
use serde::Deserialize;
use serde_json::Value;

const MAX_JSON_BYTES: u64 = 128 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const SNAPSHOT_NAME: &str = "wallet-state.usdom";
const SEAL_NAME: &str = "wallet-state.seal";
const REGISTRATION_NAME: &str = "expected-deposit-registration.json";
const OBSERVATION_NAME: &str = "canonical-deposit-observation.json";

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    password_file: PathBuf,
    rpc_token_file: PathBuf,
    node_identity_file: PathBuf,
    registered_state_directory: PathBuf,
    observed_state_directory: PathBuf,
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
    if arguments.observed_state_directory.exists() {
        anyhow::bail!("observed wallet state already exists; refusing to replace it");
    }
    validate_direct_directory(
        &arguments.registered_state_directory,
        "registered wallet state directory",
    )?;
    validate_secure_parent(&arguments.observed_state_directory)?;
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        NETWORK_MAGIC_MAINNET,
    )?;
    if bundle.schedule.first_v4_height() != 1 {
        anyhow::bail!(
            "closed Mainnet deposit observation requires native activation at height one"
        );
    }
    let passphrase = WalletPassphrase::new(load_owner_only_utf8_secret_file(
        &arguments.password_file,
        "native USDOM wallet password",
        MIN_WALLET_PASSPHRASE_BYTES as u64,
        MAX_WALLET_PASSPHRASE_BYTES as u64,
    )?)?;
    let registered_snapshot = arguments.registered_state_directory.join(SNAPSHOT_NAME);
    let snapshot_bytes = read_direct_file(
        &registered_snapshot,
        MAX_SNAPSHOT_BYTES,
        "registered encrypted wallet snapshot",
        true,
    )?;
    let seal_bytes = read_direct_file(
        &arguments.registered_state_directory.join(SEAL_NAME),
        WALLET_SNAPSHOT_SEAL_BYTES as u64,
        "registered wallet snapshot seal",
        true,
    )?;
    let previous_seal = WalletSnapshotSeal::from_bytes(&seal_bytes)?;
    let mut loaded =
        WalletState::load_encrypted_snapshot_bytes(&snapshot_bytes, &passphrase, previous_seal)?;
    if previous_seal.generation != 1 || loaded.state.tip_height() != 0 {
        anyhow::bail!("registered wallet is not the exact generation-one genesis state");
    }
    let registration_bytes = read_direct_file(
        &arguments.registered_state_directory.join(REGISTRATION_NAME),
        MAX_JSON_BYTES,
        "expected deposit registration",
        true,
    )?;
    let registration: Value = serde_json::from_slice(&registration_bytes)?;
    let expected_deposit_id = required_hex::<32>(&registration, "deposit_id")?;
    let expected_note = required_hex::<32>(&registration, "note_commitment")?;
    let expected_address = required_hex::<{ dom_usdom_wallet::RECIPIENT_ADDRESS_BYTES }>(
        &registration,
        "wallet_address",
    )?;
    let registered_tip_hash = hex::encode(loaded.state.tip_identifier().as_bytes());
    let registered_seal = hex::encode(previous_seal.to_bytes());
    if registration.get("schema").and_then(Value::as_str)
        != Some("usdom-expected-deposit-registration-v1")
        || registration
            .get("native_manifest_sha256")
            .and_then(Value::as_str)
            != Some(arguments.manifest_sha256.as_str())
        || registration
            .get("amount_base_units")
            .and_then(Value::as_str)
            != Some("1000000")
        || registration
            .get("registered_tip_height")
            .and_then(Value::as_str)
            != Some("0")
        || registration
            .get("registered_tip_hash")
            .and_then(Value::as_str)
            != Some(registered_tip_hash.as_str())
        || registration
            .get("snapshot_generation")
            .and_then(Value::as_str)
            != Some("1")
        || registration.get("snapshot_seal").and_then(Value::as_str)
            != Some(registered_seal.as_str())
        || registration.get("submits").and_then(Value::as_bool) != Some(false)
        || registration.get("mines").and_then(Value::as_bool) != Some(false)
        || loaded.wallet.address()?.to_bytes() != expected_address
    {
        anyhow::bail!("registered metadata does not bind the exact closed deposit state");
    }
    let expected = loaded.state.expected_issuances();
    if expected.len() != 1
        || expected[0].deposit_id != expected_deposit_id
        || expected[0].note_commitment.to_bytes() != expected_note
        || expected[0].amount != 1_000_000
        || expected[0].canonical
        || loaded.state.available_balance() != 0
    {
        anyhow::bail!("registered wallet does not contain one exact pending issuance");
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
    if identity.tip_height != 1 {
        anyhow::bail!("closed deposit observation requires the exactly-one-block height-one tip");
    }
    if decode_hex_array::<32>(&identity.genesis_hash, "genesis hash")?
        != *loaded.state.tip_identifier().as_bytes()
    {
        anyhow::bail!("closed Mainnet genesis differs from the registered wallet anchor");
    }
    let chain_id = Hash256::from_bytes(decode_hex_array::<32>(&identity.chain_id, "chain id")?);
    let tip_hash = Hash256::from_bytes(decode_hex_array::<32>(&identity.tip_hash, "tip hash")?);
    let client =
        UsdomRpcClient::from_token_file("http://127.0.0.1:33372/", &arguments.rpc_token_file)?;
    let scan = client.scan_authenticated_history_to_trusted_tip(AuthenticatedHistoryRequest {
        network_magic: NETWORK_MAGIC_MAINNET,
        chain_id,
        dom_domain: Hash256::from_bytes(bundle.bridge.dom_domain),
        trusted_tip: (identity.tip_height, tip_hash),
        start_height: 1,
        max_blocks: 1,
        anchor: Some(AuthenticatedHistoryAnchor {
            height: 0,
            block_hash: loaded.state.tip_identifier(),
            state_root: bundle.schedule.empty_state_root(),
        }),
    })?;
    if scan.blocks().len() != 1 {
        anyhow::bail!("authenticated history did not return exactly one block");
    }
    loaded
        .state
        .apply_authenticated_history(&loaded.wallet, scan.blocks().to_vec())?;
    let observed = loaded.state.expected_issuances();
    if loaded.state.tip_height() != 1
        || loaded.state.tip_identifier() != tip_hash
        || observed.len() != 1
        || observed[0].deposit_id != expected_deposit_id
        || observed[0].note_commitment.to_bytes() != expected_note
        || observed[0].amount != 1_000_000
        || !observed[0].canonical
        || loaded.state.available_balance() != 1_000_000
    {
        anyhow::bail!("expected 1 USDT issuance is absent from authenticated canonical history");
    }

    let staging = PrivateStagingDirectory::create(&arguments.observed_state_directory)?;
    let temporary = staging.path();
    let output_snapshot = temporary.join(SNAPSHOT_NAME);
    staging.write_child_noclobber(SNAPSHOT_NAME, &snapshot_bytes)?;
    let generation = previous_seal
        .generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("wallet snapshot generation exhausted"))?;
    let seal = loaded.state.save_encrypted_snapshot(
        &loaded.wallet,
        &output_snapshot,
        &passphrase,
        generation,
        Some(previous_seal),
    )?;
    staging.write_child_noclobber(SEAL_NAME, &seal.to_bytes())?;
    let observation = serde_json::json!({
        "schema": "usdom-canonical-deposit-observation-v1",
        "native_manifest_sha256": arguments.manifest_sha256,
        "deposit_id": hex::encode(expected_deposit_id),
        "note_commitment": hex::encode(expected_note),
        "amount_base_units": "1000000",
        "available_balance_base_units": "1000000",
        "canonical": true,
        "dom_chain_id": identity.chain_id,
        "block_height": "1",
        "block_hash": identity.tip_hash,
        "snapshot_generation": seal.generation.to_string(),
        "snapshot_seal": hex::encode(seal.to_bytes()),
        "history_authenticated": true,
        "broadcasts": false,
        "mines": false
    });
    let mut observation_bytes = serde_json::to_vec_pretty(&observation)?;
    observation_bytes.push(b'\n');
    staging.write_child_noclobber(OBSERVATION_NAME, &observation_bytes)?;
    staging.publish()?;
    println!("status: observed");
    println!("block_height: 1");
    println!("block_hash: {}", identity.tip_hash);
    println!("history_authenticated: true");
    println!("broadcasts: false");
    println!("mines: false");
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
        || decode_hex_array::<32>(&identity.chain_id, "chain id")? != expected_chain_id
        || decode_hex_array::<32>(&identity.genesis_hash, "genesis hash")? != expected_genesis_hash
        || decode_hex_array::<32>(&identity.tip_hash, "tip hash")? == [0; 32]
        || identity.max_scan_range == 0
    {
        anyhow::bail!("DOM node identity is not a valid mainnet snapshot");
    }
    Ok(())
}

fn required_hex<const N: usize>(value: &Value, name: &str) -> anyhow::Result<[u8; N]> {
    let text = value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("registration field {name} is missing"))?;
    decode_hex_array(text, name)
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
    validate_direct_directory(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("observed state directory has no parent"))?,
        "wallet state parent",
    )
}

fn validate_direct_directory(path: &Path, description: &str) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!("{description} must be a direct current-user owner-only directory");
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
    const EXPECTED: [&str; 7] = [
        "--manifest-file",
        "--manifest-sha256",
        "--password-file",
        "--rpc-token-file",
        "--node-identity-file",
        "--registered-state-directory",
        "--observed-state-directory",
    ];
    if map.len() != EXPECTED.len() || map.keys().any(|name| !EXPECTED.contains(&name.as_str())) {
        anyhow::bail!("unknown or missing observation option");
    }
    Ok(Arguments {
        manifest_file: take_path("--manifest-file")?,
        manifest_sha256,
        password_file: take_path("--password-file")?,
        rpc_token_file: take_path("--rpc-token-file")?,
        node_identity_file: take_path("--node-identity-file")?,
        registered_state_directory: take_path("--registered-state-directory")?,
        observed_state_directory: take_path("--observed-state-directory")?,
    })
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("finalized-deposit observation failed");
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
            tip_height: 1,
            tip_hash: "33".repeat(32),
            max_scan_range: 256,
        }
    }

    #[test]
    fn observed_identity_must_match_manifest_chain_id() {
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
    }
}

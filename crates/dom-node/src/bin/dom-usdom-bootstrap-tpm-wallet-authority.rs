//! Ratify the complete closed-Mainnet wallet snapshot chain into TPM2 NV.
//!
//! This command performs no network request, proof, mining or submission. It
//! authenticates generations one through three before initializing the fixed
//! production wallet seal authority at generation three.

use std::{
    ffi::OsString,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use dom_core::NETWORK_MAGIC_MAINNET;
use dom_node::{
    native_usdom_config::{load_native_usdom_v4_node_bundle, sha256_hex},
    secret_file::load_owner_only_utf8_secret_file,
};
use dom_usdom_privacy::{chain_scalar, privacy_policy_hash};
use dom_usdom_state::private_burn_payload_id;
use dom_usdom_wallet::{
    save_private_bytes_noclobber, EnvelopeError, LoadedWalletSnapshot, Tpm2AuthorityBinding,
    Tpm2NvAuthorization, Tpm2NvSealAuthority, WalletPassphrase, WalletSnapshotSeal,
    WalletSnapshotSealAuthority, WalletState, MAX_WALLET_PASSPHRASE_BYTES,
    MIN_WALLET_PASSPHRASE_BYTES, USDOM_TPM2_NV_INDEX, WALLET_SNAPSHOT_SEAL_BYTES,
};
use serde::Deserialize;
use zeroize::Zeroizing;

const MAX_JSON_BYTES: u64 = 128 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const SNAPSHOT_NAME: &str = "wallet-state.usdom";
const SEAL_NAME: &str = "wallet-state.seal";
const PAYLOAD_NAME: &str = "private-burn-payload.bin";
const INDEX_NAME: &str = "private-burn-index.json";

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    registered_state_directory: PathBuf,
    observed_state_directory: PathBuf,
    prepared_state_directory: PathBuf,
    password_file: PathBuf,
    owner_auth_file: PathBuf,
    credential_file: PathBuf,
    authority_lock_file: PathBuf,
    evidence_file: PathBuf,
}

struct ValidatedCredential {
    authorization: Tpm2NvAuthorization,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BurnIndex {
    schema: String,
    native_manifest_sha256: String,
    deposit_witness_sha256: String,
    proving_key_sha256: String,
    proving_key_id: String,
    source_snapshot_generation: String,
    source_snapshot_seal: String,
    snapshot_generation: String,
    snapshot_seal: String,
    transition_id: String,
    payload_file: String,
    payload_sha256: String,
    payload_bytes: usize,
    burn: BurnIndexRecord,
    authenticated_ethereum_timestamp: String,
    exact_value_burn: bool,
    submission_authorized: bool,
    submits: bool,
    mines: bool,
    broadcasts: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BurnIndexRecord {
    #[serde(rename = "burnId")]
    burn_id: String,
    #[serde(rename = "requestId")]
    request_id: String,
    recipient: String,
    amount: String,
    #[serde(rename = "ethereumChainId")]
    ethereum_chain_id: String,
    reserve: String,
    #[serde(rename = "validUntil")]
    valid_until: String,
    #[serde(rename = "obligationCommitment")]
    obligation_commitment: String,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        NETWORK_MAGIC_MAINNET,
    )?;
    if bundle.schedule.first_v4_height() != 1
        || bundle.bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes()
    {
        anyhow::bail!("TPM authority bootstrap requires the exact closed-Mainnet runtime");
    }
    let passphrase = WalletPassphrase::new(load_owner_only_utf8_secret_file(
        &arguments.password_file,
        "native USDOM wallet password",
        MIN_WALLET_PASSPHRASE_BYTES as u64,
        MAX_WALLET_PASSPHRASE_BYTES as u64,
    )?)?;
    let registered = load_state(
        &arguments.registered_state_directory,
        &passphrase,
        "registered wallet state",
    )?;
    let observed = load_state(
        &arguments.observed_state_directory,
        &passphrase,
        "observed wallet state",
    )?;
    let prepared = load_state(
        &arguments.prepared_state_directory,
        &passphrase,
        "prepared burn wallet state",
    )?;
    validate_snapshot_chain(&registered, &observed, &prepared)?;

    let address = registered.wallet.address()?;
    if observed.wallet.address()? != address || prepared.wallet.address()? != address {
        anyhow::bail!("wallet public identity changed across the snapshot chain");
    }
    let expected_chain = chain_scalar(bundle.bridge.dom_domain, bundle.bridge.privacy_policy_hash);
    if address.chain() != expected_chain {
        anyhow::bail!("wallet chain identity differs from the release manifest");
    }
    validate_closed_states(&registered, &observed, &prepared)?;
    let (burn_index, payload, preparation_index_bytes) = validate_prepared_burn(
        &arguments.prepared_state_directory,
        &arguments.manifest_sha256,
        observed.seal,
        prepared.seal,
        &prepared,
    )?;

    let manifest_hash = decode_hex_array::<32>(&arguments.manifest_sha256, "manifest SHA-256")?;
    let binding = Tpm2AuthorityBinding::derive(
        NETWORK_MAGIC_MAINNET,
        *bundle.schedule.chain_id().as_bytes(),
        manifest_hash,
        address.to_bytes(),
    )?;
    validate_private_parent(&arguments.credential_file, "TPM credential")?;
    validate_private_parent(&arguments.evidence_file, "TPM bootstrap evidence")?;
    let credential = match std::fs::symlink_metadata(&arguments.credential_file) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                anyhow::bail!("TPM credential path is not a direct regular file");
            }
            read_credential(&arguments.credential_file, binding, &passphrase)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let _created = Tpm2NvAuthorization::create_encrypted(
                &arguments.credential_file,
                USDOM_TPM2_NV_INDEX,
                binding,
                &passphrase,
            )?;
            read_credential(&arguments.credential_file, binding, &passphrase)?
        }
        Err(error) => return Err(error.into()),
    };
    let owner_authorization = read_owner_authorization(&arguments.owner_auth_file)?;
    let mut authority = Tpm2NvSealAuthority::initialize(
        USDOM_TPM2_NV_INDEX,
        binding,
        credential.authorization,
        owner_authorization,
        prepared.seal,
        &arguments.authority_lock_file,
    )?;
    let authority_state = authority.state()?;
    if authority_state.committed != Some(prepared.seal) || authority_state.prepared.is_some() {
        anyhow::bail!("TPM authority did not retain the exact prepared-burn snapshot seal");
    }

    let expected_evidence = serde_json::json!({
        "schema": "usdom-tpm2-wallet-authority-bootstrap-v1",
        "native_manifest_sha256": arguments.manifest_sha256,
        "network_magic": format!("{NETWORK_MAGIC_MAINNET:08x}"),
        "dom_chain_id": hex::encode(bundle.schedule.chain_id().as_bytes()),
        "wallet_address": hex::encode(address.to_bytes()),
        "authority_binding": hex::encode(binding.as_bytes()),
        "tpm_nv_index": format!("0x{USDOM_TPM2_NV_INDEX:08x}"),
        "registered_snapshot_seal": hex::encode(registered.seal.to_bytes()),
        "observed_snapshot_seal": hex::encode(observed.seal.to_bytes()),
        "prepared_snapshot_seal": hex::encode(prepared.seal.to_bytes()),
        "committed_generation": prepared.seal.generation.to_string(),
        "transition_id": burn_index.transition_id,
        "payload_sha256": sha256_hex(&payload),
        "preparation_index_sha256": sha256_hex(&preparation_index_bytes),
        "credential_sha256": credential.sha256,
        "complete_snapshot_chain_authenticated": true,
        "tpm_state_reread": true,
        "submission_authorized": false,
        "submits": false,
        "mines": false,
        "ethereum_broadcasts": false
    });
    let mut evidence_bytes = serde_json::to_vec_pretty(&expected_evidence)?;
    evidence_bytes.push(b'\n');
    publish_or_validate(&arguments.evidence_file, &evidence_bytes)?;

    println!("status: tpm-authority-initialized");
    println!("tpm_nv_index: 0x{USDOM_TPM2_NV_INDEX:08x}");
    println!("authority_binding: {}", hex::encode(binding.as_bytes()));
    println!("committed_generation: {}", prepared.seal.generation);
    println!("submission_authorized: false");
    println!("submits: false");
    println!("mines: false");
    println!("ethereum_broadcasts: false");
    Ok(())
}

fn load_state(
    directory: &Path,
    passphrase: &WalletPassphrase,
    description: &str,
) -> anyhow::Result<LoadedWalletSnapshot> {
    validate_direct_directory(directory, description)?;
    let snapshot_path = directory.join(SNAPSHOT_NAME);
    let snapshot_before = read_direct_file(
        &snapshot_path,
        MAX_SNAPSHOT_BYTES,
        "encrypted wallet snapshot",
        true,
        false,
    )?;
    let seal = WalletSnapshotSeal::from_bytes(&read_direct_file(
        &directory.join(SEAL_NAME),
        WALLET_SNAPSHOT_SEAL_BYTES as u64,
        "wallet snapshot seal",
        true,
        false,
    )?)?;
    let loaded = WalletState::load_encrypted_snapshot_bytes(&snapshot_before, passphrase, seal)?;
    Ok(loaded)
}

fn validate_snapshot_chain(
    registered: &LoadedWalletSnapshot,
    observed: &LoadedWalletSnapshot,
    prepared: &LoadedWalletSnapshot,
) -> anyhow::Result<()> {
    if registered.seal.generation != 1
        || registered.previous_seal.is_some()
        || observed.seal.generation != 2
        || observed.previous_seal != Some(registered.seal)
        || prepared.seal.generation != 3
        || prepared.previous_seal != Some(observed.seal)
    {
        anyhow::bail!("wallet snapshots do not form the exact generation 1 -> 2 -> 3 chain");
    }
    Ok(())
}

fn validate_closed_states(
    registered: &LoadedWalletSnapshot,
    observed: &LoadedWalletSnapshot,
    prepared: &LoadedWalletSnapshot,
) -> anyhow::Result<()> {
    let registered_issuance = registered.state.expected_issuances();
    let observed_issuance = observed.state.expected_issuances();
    let prepared_issuance = prepared.state.expected_issuances();
    if registered.state.tip_height() != 0
        || registered.state.available_balance() != 0
        || registered_issuance.len() != 1
        || registered_issuance[0].canonical
        || !registered.state.pending_private_burns().is_empty()
        || observed.state.tip_height() != 1
        || observed.state.available_balance() != 1_000_000
        || observed_issuance.len() != 1
        || !observed_issuance[0].canonical
        || observed_issuance[0].deposit_id != registered_issuance[0].deposit_id
        || observed_issuance[0].note_commitment != registered_issuance[0].note_commitment
        || observed_issuance[0].amount != 1_000_000
        || !observed.state.pending_private_burns().is_empty()
        || prepared.state.tip_height() != observed.state.tip_height()
        || prepared.state.tip_identifier() != observed.state.tip_identifier()
        || prepared.state.available_balance() != 0
        || prepared_issuance != observed_issuance
    {
        anyhow::bail!("wallet snapshots do not encode the exact closed 1-USDT lifecycle");
    }
    Ok(())
}

fn validate_prepared_burn(
    directory: &Path,
    manifest_sha256: &str,
    observed_seal: WalletSnapshotSeal,
    prepared_seal: WalletSnapshotSeal,
    prepared: &LoadedWalletSnapshot,
) -> anyhow::Result<(BurnIndex, Zeroizing<Vec<u8>>, Vec<u8>)> {
    let index_bytes = read_direct_file(
        &directory.join(INDEX_NAME),
        MAX_JSON_BYTES,
        "private burn index",
        true,
        false,
    )?;
    let index: BurnIndex = serde_json::from_slice(&index_bytes)?;
    let payload = Zeroizing::new(read_direct_file(
        &directory.join(PAYLOAD_NAME),
        4 * 1024 * 1024,
        "private burn payload",
        true,
        false,
    )?);
    let pending = prepared.state.pending_private_burns();
    let transition_id = private_burn_payload_id(&payload);
    if pending.len() != 1
        || pending[0].transition_id != transition_id
        || prepared.state.pending_private_burn_payload(transition_id) != Some(payload.as_slice())
        || pending[0].record.amount != 1_000_000
        || pending[0].selected_commitments.len() != 1
        || pending[0].nullifiers.len() != 1
        || pending[0].canonical_nullifier_count != 0
        || pending[0].all_inputs_canonically_spent
        || pending[0].exact_payload_canonical
        || pending[0].submission_authorized
        || index.schema != "usdom-closed-mainnet-private-burn-v1"
        || index.native_manifest_sha256 != manifest_sha256
        || !canonical_hash(&index.deposit_witness_sha256)
        || !canonical_hash(&index.proving_key_sha256)
        || !canonical_hash(&index.proving_key_id)
        || index.source_snapshot_generation != "2"
        || index.source_snapshot_seal != hex::encode(observed_seal.to_bytes())
        || index.snapshot_generation != "3"
        || index.snapshot_seal != hex::encode(prepared_seal.to_bytes())
        || index.transition_id != hex::encode(transition_id.as_bytes())
        || index.payload_file != PAYLOAD_NAME
        || index.payload_sha256 != sha256_hex(&payload)
        || index.payload_bytes != payload.len()
        || index
            .authenticated_ethereum_timestamp
            .parse::<u64>()
            .ok()
            .is_none_or(|v| v == 0)
        || !index.exact_value_burn
        || index.submission_authorized
        || index.submits
        || index.mines
        || index.broadcasts
        || index.burn.burn_id != format!("0x{}", hex::encode(pending[0].record.burn_id))
        || index.burn.request_id != format!("0x{}", hex::encode(pending[0].record.request_id))
        || index.burn.recipient != format!("0x{}", hex::encode(pending[0].record.recipient))
        || index.burn.amount != "1000000"
        || index.burn.ethereum_chain_id != "1"
        || index.burn.reserve != format!("0x{}", hex::encode(pending[0].record.reserve))
        || index.burn.valid_until != pending[0].record.valid_until.to_string()
        || index.burn.obligation_commitment
            != format!("0x{}", hex::encode(pending[0].record.obligation_commitment))
    {
        anyhow::bail!("prepared burn index, payload and wallet snapshot do not match exactly");
    }
    Ok((index, payload, index_bytes))
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn read_owner_authorization(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let bytes = read_direct_file(path, 64, "TPM owner authorization", true, true)?;
    Ok(Zeroizing::new(bytes))
}

fn read_credential(
    path: &Path,
    binding: Tpm2AuthorityBinding,
    passphrase: &WalletPassphrase,
) -> anyhow::Result<ValidatedCredential> {
    let bytes = read_direct_file(path, 4096, "encrypted TPM credential", true, false)?;
    let authorization = Tpm2NvAuthorization::load_encrypted_bytes(
        &bytes,
        USDOM_TPM2_NV_INDEX,
        binding,
        passphrase,
    )?;
    Ok(ValidatedCredential {
        authorization,
        sha256: sha256_hex(&bytes),
    })
}

fn publish_or_validate(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    match save_private_bytes_noclobber(path, bytes) {
        Ok(()) => {
            if read_direct_file(path, MAX_JSON_BYTES, "TPM bootstrap evidence", true, false)?
                != bytes
            {
                anyhow::bail!("created TPM bootstrap evidence differs from the exact state");
            }
            Ok(())
        }
        Err(EnvelopeError::DestinationExists) => {
            if read_direct_file(path, MAX_JSON_BYTES, "TPM bootstrap evidence", true, false)?
                != bytes
            {
                anyhow::bail!("existing TPM bootstrap evidence differs from the exact state");
            }
            Ok(())
        }
        Err(error) => Err(anyhow::anyhow!(error)),
    }
}

fn read_direct_file(
    path: &Path,
    maximum: u64,
    description: &str,
    owner_only: bool,
    allow_empty: bool,
) -> anyhow::Result<Vec<u8>> {
    let maximum = usize::try_from(maximum)?;
    if owner_only {
        let mut captured = if allow_empty {
            dom_wallet_crypto::read_private_bytes_allow_empty(path, maximum)?
        } else {
            dom_wallet_crypto::read_private_bytes(path, maximum)?
        };
        return Ok(std::mem::take(&mut *captured));
    }
    let result = if allow_empty {
        dom_wallet_crypto::read_captured_bytes_allow_empty(path, maximum)
    } else {
        dom_wallet_crypto::read_captured_bytes(path, maximum)
    };
    result.map_err(|error| anyhow::anyhow!("cannot capture {description}: {error}"))
}

fn validate_direct_directory(path: &Path, description: &str) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        anyhow::bail!("{description} must be a direct current-user owner-only directory");
    }
    Ok(())
}

fn validate_private_parent(path: &Path, description: &str) -> anyhow::Result<()> {
    validate_direct_directory(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("{description} path has no parent"))?,
        description,
    )
}

fn decode_hex_array<const N: usize>(value: &str, description: &str) -> anyhow::Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("{description} is not canonical lowercase hex");
    }
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{description} has the wrong length"))
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
        "--registered-state-directory",
        "--observed-state-directory",
        "--prepared-state-directory",
        "--password-file",
        "--owner-auth-file",
        "--credential-file",
        "--authority-lock-file",
        "--evidence-file",
    ];
    if map.len() != EXPECTED.len() || map.keys().any(|name| !EXPECTED.contains(&name.as_str())) {
        anyhow::bail!("unknown or missing TPM authority bootstrap option");
    }
    let path = |name: &str| -> anyhow::Result<PathBuf> {
        map.get(name)
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("{name} is required"))
    };
    let manifest_sha256 = map
        .get("--manifest-sha256")
        .and_then(|value| value.to_str())
        .filter(|value| canonical_hash(value))
        .ok_or_else(|| anyhow::anyhow!("--manifest-sha256 is invalid"))?
        .to_owned();
    Ok(Arguments {
        manifest_file: path("--manifest-file")?,
        manifest_sha256,
        registered_state_directory: path("--registered-state-directory")?,
        observed_state_directory: path("--observed-state-directory")?,
        prepared_state_directory: path("--prepared-state-directory")?,
        password_file: path("--password-file")?,
        owner_auth_file: path("--owner-auth-file")?,
        credential_file: path("--credential-file")?,
        authority_lock_file: path("--authority-lock-file")?,
        evidence_file: path("--evidence-file")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_the_complete_fixed_surface() {
        let hash = "11".repeat(32);
        let arguments = vec![
            "tool",
            "--manifest-file",
            "m",
            "--manifest-sha256",
            &hash,
            "--registered-state-directory",
            "r",
            "--observed-state-directory",
            "o",
            "--prepared-state-directory",
            "p",
            "--password-file",
            "s",
            "--owner-auth-file",
            "a",
            "--credential-file",
            "c",
            "--authority-lock-file",
            "l",
            "--evidence-file",
            "e",
        ];
        assert!(parse_arguments(arguments.into_iter().map(OsString::from)).is_ok());
        assert!(parse_arguments(
            ["tool", "--manifest-file", "m"]
                .into_iter()
                .map(OsString::from)
        )
        .is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("TPM wallet authority bootstrap failed");
        std::process::exit(1);
    }
}

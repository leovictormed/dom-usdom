//! Provision or unlock the TPM2 second factor for operational wallet state.
//!
//! The portable recovery seed remains encrypted by the human recovery
//! password. The operational snapshot password is derived only after the same
//! password authenticates the exact wallet and unlocks its TPM-bound record.

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
use dom_usdom_wallet::{
    save_private_bytes_noclobber, EnvelopeError, Tpm2AuthorityBinding, Tpm2NvAuthorization,
    Tpm2WalletKeystore, WalletPassphrase, WalletRecoverySeed, WalletSecrets,
    MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES, RECIPIENT_ADDRESS_BYTES,
    USDOM_TPM2_KEYSTORE_NV_INDEX,
};
use serde::Deserialize;
use zeroize::Zeroizing;

const MAX_JSON_BYTES: u64 = 128 * 1024;
const MAX_BACKUP_BYTES: u64 = 4 * 1024 * 1024;

enum Action {
    Provision,
    Unlock,
}

struct Arguments {
    action: Action,
    manifest_file: PathBuf,
    manifest_sha256: String,
    recovery_file: PathBuf,
    public_identity_file: PathBuf,
    recovery_password_file: PathBuf,
    owner_auth_file: Option<PathBuf>,
    credential_file: PathBuf,
    keystore_lock_file: PathBuf,
    evidence_file: PathBuf,
    output_password_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PublicIdentity {
    schema: String,
    dom_domain: String,
    privacy_policy_hash: String,
    chain_scalar: String,
    receiving_commitment: String,
    recipient_address: String,
    backup_path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeystoreEvidence {
    schema: String,
    native_manifest_sha256: String,
    network_magic: String,
    dom_chain_id: String,
    wallet_address: String,
    authority_binding: String,
    tpm_nv_index: String,
    record_commitment: String,
    recovery_backup_sha256: String,
    public_identity_sha256: String,
    credential_sha256: String,
    tpm_state_reread: bool,
    operational_password_exported: bool,
    submits: bool,
    mines: bool,
    ethereum_broadcasts: bool,
}

struct ValidatedWallet {
    recovery_password: WalletPassphrase,
    address: [u8; RECIPIENT_ADDRESS_BYTES],
    binding: Tpm2AuthorityBinding,
    chain_id: [u8; 32],
    recovery_backup_sha256: String,
    public_identity_sha256: String,
}

struct ValidatedCredential {
    authorization: Tpm2NvAuthorization,
    sha256: String,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    let wallet = validate_wallet(&arguments)?;
    match arguments.action {
        Action::Provision => provision(&arguments, wallet),
        Action::Unlock => unlock(&arguments, wallet),
    }
}

fn validate_wallet(arguments: &Arguments) -> anyhow::Result<ValidatedWallet> {
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        NETWORK_MAGIC_MAINNET,
    )?;
    if bundle.schedule.first_v4_height() != 1
        || bundle.bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes()
    {
        anyhow::bail!("TPM wallet keystore requires the exact closed-Mainnet runtime");
    }
    let recovery_password = WalletPassphrase::new(load_owner_only_utf8_secret_file(
        &arguments.recovery_password_file,
        "native USDOM recovery password",
        MIN_WALLET_PASSPHRASE_BYTES as u64,
        MAX_WALLET_PASSPHRASE_BYTES as u64,
    )?)?;
    let backup = read_direct_file(
        &arguments.recovery_file,
        MAX_BACKUP_BYTES,
        "encrypted wallet recovery backup",
        true,
        false,
    )?;
    let identity_bytes = read_direct_file(
        &arguments.public_identity_file,
        MAX_JSON_BYTES,
        "wallet public identity",
        true,
        false,
    )?;
    let identity: PublicIdentity = serde_json::from_slice(&identity_bytes)?;
    let policy_hash = *privacy_policy_hash().as_bytes();
    let chain = chain_scalar(bundle.bridge.dom_domain, policy_hash);
    let expected_backup_path = arguments
        .recovery_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("recovery backup path is not UTF-8"))?;
    if identity.schema != "usdom-native-receiving-wallet-public-v1"
        || identity.dom_domain != format!("0x{}", hex::encode(bundle.bridge.dom_domain))
        || identity.privacy_policy_hash != format!("0x{}", hex::encode(policy_hash))
        || identity.chain_scalar != format!("0x{}", hex::encode(chain.to_bytes()))
        || identity.backup_path != expected_backup_path
    {
        anyhow::bail!("wallet public identity differs from the release or backup path");
    }
    let seed = WalletRecoverySeed::load_encrypted_backup_bytes(&backup, chain, &recovery_password)?;
    let wallet_secrets = WalletSecrets::from_recovery_seed(chain, &seed)?;
    let address = wallet_secrets.address()?;
    if identity.receiving_commitment != format!("0x{}", hex::encode(address.owner().to_bytes()))
        || identity.recipient_address != hex::encode(address.to_bytes())
    {
        anyhow::bail!("restored recovery seed differs from the public wallet identity");
    }
    let manifest_hash = decode_hex_array::<32>(&arguments.manifest_sha256, "manifest SHA-256")?;
    let binding = Tpm2AuthorityBinding::derive(
        NETWORK_MAGIC_MAINNET,
        *bundle.schedule.chain_id().as_bytes(),
        manifest_hash,
        address.to_bytes(),
    )?;
    Ok(ValidatedWallet {
        recovery_password,
        address: address.to_bytes(),
        binding,
        chain_id: *bundle.schedule.chain_id().as_bytes(),
        recovery_backup_sha256: sha256_hex(&backup),
        public_identity_sha256: sha256_hex(&identity_bytes),
    })
}

fn provision(arguments: &Arguments, wallet: ValidatedWallet) -> anyhow::Result<()> {
    let owner_auth_file = arguments
        .owner_auth_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("provision requires the TPM owner authorization file"))?;
    if arguments.output_password_file.is_some() {
        anyhow::bail!("provision cannot export an operational password");
    }
    validate_private_parent(&arguments.credential_file, "TPM keystore credential")?;
    validate_private_parent(&arguments.evidence_file, "TPM keystore evidence")?;
    let credential = load_or_create_credential(arguments, &wallet)?;
    let owner_authorization = Zeroizing::new(read_direct_file(
        owner_auth_file,
        64,
        "TPM owner authorization",
        true,
        true,
    )?);
    let mut keystore = Tpm2WalletKeystore::initialize(
        USDOM_TPM2_KEYSTORE_NV_INDEX,
        wallet.binding,
        credential.authorization,
        owner_authorization,
        &arguments.keystore_lock_file,
    )?;
    let commitment = keystore.record_commitment()?;
    // Exercise the complete KDF while retaining the result only in zeroizing
    // memory; provisioning never exports an operational password.
    let _operational = keystore.operational_passphrase(&wallet.recovery_password)?;
    let evidence = expected_evidence(arguments, &wallet, commitment, &credential.sha256)?;
    publish_or_validate(&arguments.evidence_file, &evidence)?;
    println!("status: tpm-wallet-keystore-provisioned");
    println!("tpm_nv_index: 0x{USDOM_TPM2_KEYSTORE_NV_INDEX:08x}");
    println!(
        "authority_binding: {}",
        hex::encode(wallet.binding.as_bytes())
    );
    println!("record_commitment: {}", hex::encode(commitment));
    println!("operational_password_exported: false");
    println!("submits: false");
    println!("mines: false");
    println!("ethereum_broadcasts: false");
    Ok(())
}

fn unlock(arguments: &Arguments, wallet: ValidatedWallet) -> anyhow::Result<()> {
    if arguments.owner_auth_file.is_some() {
        anyhow::bail!("unlock does not accept TPM owner authorization");
    }
    let output = arguments
        .output_password_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("unlock requires an output password file"))?;
    validate_ephemeral_output(output)?;
    let evidence_bytes = read_direct_file(
        &arguments.evidence_file,
        MAX_JSON_BYTES,
        "TPM keystore evidence",
        true,
        false,
    )?;
    let evidence: KeystoreEvidence = serde_json::from_slice(&evidence_bytes)?;
    let credential = read_credential(arguments, &wallet)?;
    let mut keystore = Tpm2WalletKeystore::open(
        USDOM_TPM2_KEYSTORE_NV_INDEX,
        wallet.binding,
        credential.authorization,
        &arguments.keystore_lock_file,
    )?;
    let commitment = keystore.record_commitment()?;
    validate_evidence(
        &evidence,
        arguments,
        &wallet,
        commitment,
        &credential.sha256,
    )?;
    keystore.write_operational_passphrase_create_only(&wallet.recovery_password, output)?;
    println!("status: tpm-wallet-keystore-unlocked");
    println!("tpm_nv_index: 0x{USDOM_TPM2_KEYSTORE_NV_INDEX:08x}");
    println!(
        "authority_binding: {}",
        hex::encode(wallet.binding.as_bytes())
    );
    println!("record_commitment: {}", hex::encode(commitment));
    println!("operational_password_exported: true");
    println!("submits: false");
    println!("mines: false");
    println!("ethereum_broadcasts: false");
    Ok(())
}

fn load_or_create_credential(
    arguments: &Arguments,
    wallet: &ValidatedWallet,
) -> anyhow::Result<ValidatedCredential> {
    match std::fs::symlink_metadata(&arguments.credential_file) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o600
                || metadata.nlink() != 1
            {
                anyhow::bail!("existing TPM keystore credential is not a direct owner-only file");
            }
            read_credential(arguments, wallet)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let _created = Tpm2NvAuthorization::create_encrypted(
                &arguments.credential_file,
                USDOM_TPM2_KEYSTORE_NV_INDEX,
                wallet.binding,
                &wallet.recovery_password,
            )?;
            read_credential(arguments, wallet)
        }
        Err(error) => Err(error.into()),
    }
}

fn read_credential(
    arguments: &Arguments,
    wallet: &ValidatedWallet,
) -> anyhow::Result<ValidatedCredential> {
    let bytes = read_direct_file(
        &arguments.credential_file,
        4096,
        "encrypted TPM keystore credential",
        true,
        false,
    )?;
    let authorization = Tpm2NvAuthorization::load_encrypted_bytes(
        &bytes,
        USDOM_TPM2_KEYSTORE_NV_INDEX,
        wallet.binding,
        &wallet.recovery_password,
    )?;
    Ok(ValidatedCredential {
        authorization,
        sha256: sha256_hex(&bytes),
    })
}

fn expected_evidence(
    arguments: &Arguments,
    wallet: &ValidatedWallet,
    commitment: [u8; 32],
    credential_sha256: &str,
) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::json!({
        "schema": "usdom-tpm2-wallet-keystore-v1",
        "native_manifest_sha256": arguments.manifest_sha256,
        "network_magic": format!("{NETWORK_MAGIC_MAINNET:08x}"),
        "dom_chain_id": hex::encode(wallet.chain_id),
        "wallet_address": hex::encode(wallet.address),
        "authority_binding": hex::encode(wallet.binding.as_bytes()),
        "tpm_nv_index": format!("0x{USDOM_TPM2_KEYSTORE_NV_INDEX:08x}"),
        "record_commitment": hex::encode(commitment),
        "recovery_backup_sha256": wallet.recovery_backup_sha256,
        "public_identity_sha256": wallet.public_identity_sha256,
        "credential_sha256": credential_sha256,
        "tpm_state_reread": true,
        "operational_password_exported": false,
        "submits": false,
        "mines": false,
        "ethereum_broadcasts": false
    });
    let mut bytes = serde_json::to_vec_pretty(&value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_evidence(
    evidence: &KeystoreEvidence,
    arguments: &Arguments,
    wallet: &ValidatedWallet,
    commitment: [u8; 32],
    credential_sha256: &str,
) -> anyhow::Result<()> {
    if evidence.schema != "usdom-tpm2-wallet-keystore-v1"
        || evidence.native_manifest_sha256 != arguments.manifest_sha256
        || evidence.network_magic != format!("{NETWORK_MAGIC_MAINNET:08x}")
        || evidence.dom_chain_id != hex::encode(wallet.chain_id)
        || evidence.wallet_address != hex::encode(wallet.address)
        || evidence.authority_binding != hex::encode(wallet.binding.as_bytes())
        || evidence.tpm_nv_index != format!("0x{USDOM_TPM2_KEYSTORE_NV_INDEX:08x}")
        || evidence.record_commitment != hex::encode(commitment)
        || evidence.recovery_backup_sha256 != wallet.recovery_backup_sha256
        || evidence.public_identity_sha256 != wallet.public_identity_sha256
        || evidence.credential_sha256 != credential_sha256
        || !evidence.tpm_state_reread
        || evidence.operational_password_exported
        || evidence.submits
        || evidence.mines
        || evidence.ethereum_broadcasts
    {
        anyhow::bail!("TPM wallet keystore evidence differs from the exact live record");
    }
    Ok(())
}

fn publish_or_validate(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    match save_private_bytes_noclobber(path, bytes) {
        Ok(()) => {
            if read_direct_file(path, MAX_JSON_BYTES, "TPM keystore evidence", true, false)?
                != bytes
            {
                anyhow::bail!("created TPM keystore evidence differs from the live record");
            }
            Ok(())
        }
        Err(EnvelopeError::DestinationExists) => {
            if read_direct_file(path, MAX_JSON_BYTES, "TPM keystore evidence", true, false)?
                != bytes
            {
                anyhow::bail!("existing TPM keystore evidence differs from the live record");
            }
            Ok(())
        }
        Err(error) => Err(anyhow::anyhow!(error)),
    }
}

fn validate_ephemeral_output(path: &Path) -> anyhow::Result<()> {
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        anyhow::bail!("operational password output must not already exist");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("operational password path has no parent"))?;
    validate_direct_directory(parent, "operational password directory")?;
    if parent.parent() != Some(Path::new("/dev/shm")) {
        anyhow::bail!("operational password must be created in a direct /dev/shm child directory");
    }
    Ok(())
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
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        anyhow::bail!("{description} must be a direct current-user mode 0700 directory");
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
    let action = match values.next().and_then(|value| value.into_string().ok()) {
        Some(value) if value == "provision" => Action::Provision,
        Some(value) if value == "unlock" => Action::Unlock,
        _ => anyhow::bail!("first argument must be provision or unlock"),
    };
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
    let mut expected = vec![
        "--manifest-file",
        "--manifest-sha256",
        "--recovery-file",
        "--public-identity-file",
        "--recovery-password-file",
        "--credential-file",
        "--keystore-lock-file",
        "--evidence-file",
    ];
    expected.push(match action {
        Action::Provision => "--owner-auth-file",
        Action::Unlock => "--output-password-file",
    });
    if map.len() != expected.len() || map.keys().any(|key| !expected.contains(&key.as_str())) {
        anyhow::bail!("unknown or missing TPM wallet-keystore option");
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
        action,
        manifest_file: path("--manifest-file")?,
        manifest_sha256,
        recovery_file: path("--recovery-file")?,
        public_identity_file: path("--public-identity-file")?,
        recovery_password_file: path("--recovery-password-file")?,
        owner_auth_file: map.get("--owner-auth-file").map(PathBuf::from),
        credential_file: path("--credential-file")?,
        keystore_lock_file: path("--keystore-lock-file")?,
        evidence_file: path("--evidence-file")?,
        output_password_file: map.get("--output-password-file").map(PathBuf::from),
    })
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common(action: &str, special: (&str, &str)) -> Vec<OsString> {
        let hash = "11".repeat(32);
        [
            "tool",
            action,
            "--manifest-file",
            "m",
            "--manifest-sha256",
            &hash,
            "--recovery-file",
            "r",
            "--public-identity-file",
            "i",
            "--recovery-password-file",
            "p",
            "--credential-file",
            "c",
            "--keystore-lock-file",
            "l",
            "--evidence-file",
            "e",
            special.0,
            special.1,
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn parser_separates_provision_and_unlock_secret_surfaces() {
        assert!(parse_arguments(common("provision", ("--owner-auth-file", "o"))).is_ok());
        assert!(parse_arguments(common("unlock", ("--output-password-file", "x"))).is_ok());
        assert!(parse_arguments(common("provision", ("--output-password-file", "x"))).is_err());
        assert!(parse_arguments(common("unlock", ("--owner-auth-file", "o"))).is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("TPM wallet keystore operation failed");
        std::process::exit(1);
    }
}

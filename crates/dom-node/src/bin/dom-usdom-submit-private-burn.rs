//! Durably authorize and submit one exact closed-Mainnet private burn.
//!
//! Submission is restricted by `UsdomRpcClient` to authenticated literal
//! loopback HTTP. This command never mines, contacts Ethereum, signs a public
//! transaction or moves Ethereum funds.

use std::{
    ffi::OsString,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use dom_core::{Hash256, NETWORK_MAGIC_MAINNET};
use dom_node::{
    native_usdom_config::{load_native_usdom_v4_node_bundle, sha256_hex},
    secret_file::load_owner_only_utf8_secret_file,
};
use dom_usdom_privacy::{chain_scalar, privacy_policy_hash};
use dom_usdom_state::private_burn_payload_id;
use dom_usdom_wallet::{
    RecipientAddress, Tpm2AuthorityBinding, Tpm2NvAuthorization, Tpm2NvSealAuthority,
    UsdomRpcClient, WalletPassphrase, WalletSnapshotSeal, WalletSnapshotSealAuthority, WalletState,
    MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES, USDOM_TPM2_NV_INDEX,
    WALLET_SNAPSHOT_SEAL_BYTES,
};
use dom_wallet_crypto::{save_private_bytes, save_private_bytes_noclobber, EnvelopeError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_JSON_BYTES: u64 = 128 * 1024;
const MAX_PAYLOAD_BYTES: u64 = 4 * 1024 * 1024;
const SNAPSHOT_NAME: &str = "wallet-state.usdom";
const SEAL_NAME: &str = "wallet-state.seal";
const PAYLOAD_NAME: &str = "private-burn-payload.bin";
const INDEX_NAME: &str = "private-burn-index.json";
const LOOPBACK_RPC: &str = "http://127.0.0.1:33372/";

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    prepared_state_directory: PathBuf,
    password_file: PathBuf,
    rpc_token_file: PathBuf,
    credential_file: PathBuf,
    authority_lock_file: PathBuf,
    bootstrap_evidence_file: PathBuf,
    receipt_file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapEvidence {
    schema: String,
    native_manifest_sha256: String,
    network_magic: String,
    dom_chain_id: String,
    wallet_address: String,
    authority_binding: String,
    tpm_nv_index: String,
    registered_snapshot_seal: String,
    observed_snapshot_seal: String,
    prepared_snapshot_seal: String,
    committed_generation: String,
    transition_id: String,
    payload_sha256: String,
    preparation_index_sha256: String,
    credential_sha256: String,
    complete_snapshot_chain_authenticated: bool,
    tpm_state_reread: bool,
    submission_authorized: bool,
    submits: bool,
    mines: bool,
    ethereum_broadcasts: bool,
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

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SubmissionReceipt {
    schema: String,
    native_manifest_sha256: String,
    authority_binding: String,
    tpm_nv_index: String,
    authorized_snapshot_generation: String,
    authorized_snapshot_seal: String,
    transition_id: String,
    candidate_id: String,
    payload_sha256: String,
    endpoint: String,
    accepted: bool,
    state: String,
    durable_authorization_reissued_each_run: bool,
    submits_to_dom_loopback: bool,
    mines: bool,
    ethereum_broadcasts: bool,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    validate_direct_directory(
        &arguments.prepared_state_directory,
        "prepared private-burn state directory",
    )?;
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        NETWORK_MAGIC_MAINNET,
    )?;
    if bundle.schedule.first_v4_height() != 1
        || bundle.bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes()
    {
        anyhow::bail!("private-burn submission requires the exact closed-Mainnet runtime");
    }
    let passphrase = WalletPassphrase::new(load_owner_only_utf8_secret_file(
        &arguments.password_file,
        "native USDOM wallet password",
        MIN_WALLET_PASSPHRASE_BYTES as u64,
        MAX_WALLET_PASSPHRASE_BYTES as u64,
    )?)?;
    let bootstrap: BootstrapEvidence = serde_json::from_slice(&read_direct_file(
        &arguments.bootstrap_evidence_file,
        MAX_JSON_BYTES,
        "TPM bootstrap evidence",
        true,
    )?)?;
    let address_bytes = decode_hex_array::<{ dom_usdom_wallet::RECIPIENT_ADDRESS_BYTES }>(
        &bootstrap.wallet_address,
        "bootstrap wallet address",
    )?;
    let address = RecipientAddress::from_bytes(&address_bytes)?;
    let manifest_hash = decode_hex_array::<32>(&arguments.manifest_sha256, "manifest SHA-256")?;
    let binding = Tpm2AuthorityBinding::derive(
        NETWORK_MAGIC_MAINNET,
        *bundle.schedule.chain_id().as_bytes(),
        manifest_hash,
        address_bytes,
    )?;
    let credential_bytes = read_direct_file(
        &arguments.credential_file,
        4096,
        "encrypted TPM credential",
        true,
    )?;
    validate_bootstrap(
        &bootstrap,
        &arguments,
        *bundle.schedule.chain_id().as_bytes(),
        binding,
        &credential_bytes,
    )?;
    let authorization = Tpm2NvAuthorization::load_encrypted_bytes(
        &credential_bytes,
        USDOM_TPM2_NV_INDEX,
        binding,
        &passphrase,
    )?;
    let mut authority = Tpm2NvSealAuthority::open(
        USDOM_TPM2_NV_INDEX,
        binding,
        authorization,
        &arguments.authority_lock_file,
    )?;
    let snapshot_path = arguments.prepared_state_directory.join(SNAPSHOT_NAME);
    let mut loaded = WalletState::reconcile_encrypted_snapshot_authority(
        &snapshot_path,
        &passphrase,
        &mut authority,
    )?
    .ok_or_else(|| anyhow::anyhow!("TPM authority has no committed wallet snapshot"))?;
    let observed_bootstrap_seal = decode_snapshot_seal(&bootstrap.observed_snapshot_seal, 2)?;
    let prepared_bootstrap_seal = decode_snapshot_seal(&bootstrap.prepared_snapshot_seal, 3)?;
    match loaded.seal.generation {
        3 if loaded.seal == prepared_bootstrap_seal
            && loaded.previous_seal == Some(observed_bootstrap_seal) => {}
        4 if loaded.previous_seal == Some(prepared_bootstrap_seal) => {}
        _ => anyhow::bail!(
            "TPM-bound wallet is not the exact prepared snapshot or its authorized successor"
        ),
    }
    if loaded.wallet.address()? != address
        || address.chain()
            != chain_scalar(bundle.bridge.dom_domain, bundle.bridge.privacy_policy_hash)
    {
        anyhow::bail!("TPM-bound wallet differs from the release and bootstrap identity");
    }

    let payload = Zeroizing::new(read_direct_file(
        &arguments.prepared_state_directory.join(PAYLOAD_NAME),
        MAX_PAYLOAD_BYTES,
        "private burn payload",
        true,
    )?);
    let index_bytes = read_direct_file(
        &arguments.prepared_state_directory.join(INDEX_NAME),
        MAX_JSON_BYTES,
        "private burn index",
        true,
    )?;
    let index: BurnIndex = serde_json::from_slice(&index_bytes)?;
    let transition_id = private_burn_payload_id(&payload);
    validate_prepared_index(
        &index,
        &arguments.manifest_sha256,
        &payload,
        transition_id,
        &bootstrap,
        &loaded.state,
    )?;
    if bootstrap.preparation_index_sha256 != sha256_hex(&index_bytes) {
        anyhow::bail!("private burn preparation index differs from the TPM bootstrap evidence");
    }
    validate_pending(
        &loaded.state,
        transition_id,
        &payload,
        loaded.seal.generation,
    )?;

    let (authorized_seal, permit) = match loaded.seal.generation {
        3 => {
            if loaded.state.pending_private_burns()[0].submission_authorized {
                anyhow::bail!("generation-three burn cannot already be submission-authorized");
            }
            loaded.state.persist_pending_burn_for_submission(
                &loaded.wallet,
                transition_id,
                &snapshot_path,
                &passphrase,
                Some(loaded.seal),
                &mut authority,
            )?
        }
        4 => {
            let permit = loaded.pending_burn_submission_permit(transition_id, &mut authority)?;
            (loaded.seal, permit)
        }
        _ => anyhow::bail!("TPM wallet is outside the exact generation-three/four submission flow"),
    };
    if authorized_seal.generation != 4 {
        anyhow::bail!("durable burn authorization did not commit generation four");
    }
    write_seal_atomic(
        &arguments.prepared_state_directory.join(SEAL_NAME),
        authorized_seal,
    )?;
    let committed = authority.state()?;
    if committed.committed != Some(authorized_seal) || committed.prepared.is_some() {
        anyhow::bail!("TPM authority differs after durable burn authorization");
    }

    let client = UsdomRpcClient::from_token_file(LOOPBACK_RPC, &arguments.rpc_token_file)?;
    let submission = client.submit_pending_private_burn(&loaded.state, &permit)?;
    if submission.transition_id != transition_id {
        anyhow::bail!("DOM node acknowledged a different private burn");
    }
    let receipt = SubmissionReceipt {
        schema: "usdom-closed-mainnet-private-burn-submission-v1".into(),
        native_manifest_sha256: arguments.manifest_sha256,
        authority_binding: hex::encode(binding.as_bytes()),
        tpm_nv_index: format!("0x{USDOM_TPM2_NV_INDEX:08x}"),
        authorized_snapshot_generation: authorized_seal.generation.to_string(),
        authorized_snapshot_seal: hex::encode(authorized_seal.to_bytes()),
        transition_id: hex::encode(transition_id.as_bytes()),
        candidate_id: hex::encode(submission.candidate_id.as_bytes()),
        payload_sha256: sha256_hex(&payload),
        endpoint: LOOPBACK_RPC.into(),
        accepted: true,
        state: "queued".into(),
        durable_authorization_reissued_each_run: true,
        submits_to_dom_loopback: true,
        mines: false,
        ethereum_broadcasts: false,
    };
    publish_or_validate_receipt(&arguments.receipt_file, &receipt)?;

    println!("status: queued");
    println!("transition_id: {}", receipt.transition_id);
    println!("candidate_id: {}", receipt.candidate_id);
    println!("authorized_snapshot_generation: 4");
    println!("submits_to_dom_loopback: true");
    println!("mines: false");
    println!("ethereum_broadcasts: false");
    Ok(())
}

fn validate_bootstrap(
    evidence: &BootstrapEvidence,
    arguments: &Arguments,
    chain_id: [u8; 32],
    binding: Tpm2AuthorityBinding,
    credential: &[u8],
) -> anyhow::Result<()> {
    if evidence.schema != "usdom-tpm2-wallet-authority-bootstrap-v1"
        || evidence.native_manifest_sha256 != arguments.manifest_sha256
        || evidence.network_magic != format!("{NETWORK_MAGIC_MAINNET:08x}")
        || evidence.dom_chain_id != hex::encode(chain_id)
        || evidence.authority_binding != hex::encode(binding.as_bytes())
        || evidence.tpm_nv_index != format!("0x{USDOM_TPM2_NV_INDEX:08x}")
        || decode_snapshot_seal(&evidence.registered_snapshot_seal, 1).is_err()
        || decode_snapshot_seal(&evidence.observed_snapshot_seal, 2).is_err()
        || decode_snapshot_seal(&evidence.prepared_snapshot_seal, 3).is_err()
        || evidence.committed_generation != "3"
        || !canonical_hash(&evidence.transition_id)
        || !canonical_hash(&evidence.payload_sha256)
        || !canonical_hash(&evidence.preparation_index_sha256)
        || evidence.credential_sha256 != sha256_hex(credential)
        || !evidence.complete_snapshot_chain_authenticated
        || !evidence.tpm_state_reread
        || evidence.submission_authorized
        || evidence.submits
        || evidence.mines
        || evidence.ethereum_broadcasts
    {
        anyhow::bail!("TPM bootstrap evidence does not bind the exact closed wallet");
    }
    Ok(())
}

fn validate_prepared_index(
    index: &BurnIndex,
    manifest_sha256: &str,
    payload: &[u8],
    transition_id: Hash256,
    bootstrap: &BootstrapEvidence,
    state: &WalletState,
) -> anyhow::Result<()> {
    let pending = state.pending_private_burns();
    if index.schema != "usdom-closed-mainnet-private-burn-v1"
        || index.native_manifest_sha256 != manifest_sha256
        || !canonical_hash(&index.deposit_witness_sha256)
        || !canonical_hash(&index.proving_key_sha256)
        || !canonical_hash(&index.proving_key_id)
        || index.source_snapshot_generation != "2"
        || index.source_snapshot_seal != bootstrap.observed_snapshot_seal
        || index.snapshot_generation != "3"
        || index.snapshot_seal != bootstrap.prepared_snapshot_seal
        || index.transition_id != hex::encode(transition_id.as_bytes())
        || index.transition_id != bootstrap.transition_id
        || index.payload_file != PAYLOAD_NAME
        || index.payload_sha256 != sha256_hex(payload)
        || index.payload_sha256 != bootstrap.payload_sha256
        || index.payload_bytes != payload.len()
        || pending.len() != 1
        || index.burn.burn_id != format!("0x{}", hex::encode(pending[0].record.burn_id))
        || index.burn.request_id != format!("0x{}", hex::encode(pending[0].record.request_id))
        || index.burn.recipient != format!("0x{}", hex::encode(pending[0].record.recipient))
        || index.burn.amount != pending[0].record.amount.to_string()
        || index.burn.ethereum_chain_id != "1"
        || index.burn.reserve != format!("0x{}", hex::encode(pending[0].record.reserve))
        || index.burn.valid_until != pending[0].record.valid_until.to_string()
        || index.burn.obligation_commitment
            != format!("0x{}", hex::encode(pending[0].record.obligation_commitment))
        || index
            .authenticated_ethereum_timestamp
            .parse::<u64>()
            .ok()
            .is_none_or(|value| value == 0)
        || !index.exact_value_burn
        || index.submission_authorized
        || index.submits
        || index.mines
        || index.broadcasts
    {
        anyhow::bail!("private burn preparation index does not match the TPM-bound payload");
    }
    Ok(())
}

fn validate_pending(
    state: &WalletState,
    transition_id: Hash256,
    payload: &[u8],
    generation: u64,
) -> anyhow::Result<()> {
    let pending = state.pending_private_burns();
    if pending.len() != 1
        || pending[0].transition_id != transition_id
        || state.pending_private_burn_payload(transition_id) != Some(payload)
        || pending[0].record.amount != 1_000_000
        || pending[0].selected_commitments.len() != 1
        || pending[0].nullifiers.len() != 1
        || pending[0].canonical_nullifier_count != 0
        || pending[0].all_inputs_canonically_spent
        || pending[0].exact_payload_canonical
        || pending[0].submission_authorized != (generation == 4)
        || state.tip_height() != 1
        || state.available_balance() != 0
    {
        anyhow::bail!("TPM-bound wallet does not retain one exact pending 1-USDT burn");
    }
    Ok(())
}

fn write_seal_atomic(path: &Path, seal: WalletSnapshotSeal) -> anyhow::Result<()> {
    save_private_bytes(path, &seal.to_bytes())?;
    if WalletSnapshotSeal::from_bytes(&read_direct_file(
        path,
        WALLET_SNAPSHOT_SEAL_BYTES as u64,
        "authorized wallet snapshot seal",
        true,
    )?)? != seal
    {
        anyhow::bail!("authorized wallet seal changed after atomic publication");
    }
    Ok(())
}

fn publish_or_validate_receipt(path: &Path, receipt: &SubmissionReceipt) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(receipt)?;
    bytes.push(b'\n');
    match save_private_bytes_noclobber(path, &bytes) {
        Ok(()) => {
            if read_direct_file(
                path,
                MAX_JSON_BYTES,
                "private burn submission receipt",
                true,
            )? != bytes
            {
                anyhow::bail!("created private burn receipt changed after publication");
            }
            Ok(())
        }
        Err(EnvelopeError::DestinationExists) => {
            let existing: SubmissionReceipt = serde_json::from_slice(&read_direct_file(
                path,
                MAX_JSON_BYTES,
                "private burn submission receipt",
                true,
            )?)?;
            if existing != *receipt {
                anyhow::bail!(
                    "existing private burn receipt differs from the node acknowledgement"
                );
            }
            Ok(())
        }
        Err(error) => Err(anyhow::anyhow!(error)),
    }
}

fn canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
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

fn decode_snapshot_seal(value: &str, generation: u64) -> anyhow::Result<WalletSnapshotSeal> {
    let bytes = decode_hex_array::<WALLET_SNAPSHOT_SEAL_BYTES>(value, "wallet snapshot seal")?;
    let seal = WalletSnapshotSeal::from_bytes(&bytes)?;
    if seal.generation != generation {
        anyhow::bail!("wallet snapshot seal has the wrong generation");
    }
    Ok(seal)
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
    const EXPECTED: [&str; 9] = [
        "--manifest-file",
        "--manifest-sha256",
        "--prepared-state-directory",
        "--password-file",
        "--rpc-token-file",
        "--credential-file",
        "--authority-lock-file",
        "--bootstrap-evidence-file",
        "--receipt-file",
    ];
    if map.len() != EXPECTED.len() || map.keys().any(|name| !EXPECTED.contains(&name.as_str())) {
        anyhow::bail!("unknown or missing private-burn submission option");
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
        prepared_state_directory: path("--prepared-state-directory")?,
        password_file: path("--password-file")?,
        rpc_token_file: path("--rpc-token-file")?,
        credential_file: path("--credential-file")?,
        authority_lock_file: path("--authority-lock-file")?,
        bootstrap_evidence_file: path("--bootstrap-evidence-file")?,
        receipt_file: path("--receipt-file")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_the_complete_fixed_submission_surface() {
        let hash = "11".repeat(32);
        let arguments = vec![
            "tool",
            "--manifest-file",
            "m",
            "--manifest-sha256",
            &hash,
            "--prepared-state-directory",
            "p",
            "--password-file",
            "s",
            "--rpc-token-file",
            "t",
            "--credential-file",
            "c",
            "--authority-lock-file",
            "l",
            "--bootstrap-evidence-file",
            "b",
            "--receipt-file",
            "r",
        ];
        assert!(parse_arguments(arguments.into_iter().map(OsString::from)).is_ok());
        assert!(parse_arguments(
            ["tool", "--manifest-file", "m"]
                .into_iter()
                .map(OsString::from)
        )
        .is_err());
    }

    #[test]
    fn snapshot_seals_use_their_full_canonical_encoding_and_generation() {
        let seal = WalletSnapshotSeal {
            generation: 3,
            digest: Hash256::from_bytes([0x5a; 32]),
        };
        let encoded = hex::encode(seal.to_bytes());
        assert_eq!(encoded.len(), WALLET_SNAPSHOT_SEAL_BYTES * 2);
        assert_eq!(decode_snapshot_seal(&encoded, 3).expect("seal"), seal);
        assert!(decode_snapshot_seal(&encoded, 2).is_err());
        assert!(decode_snapshot_seal(&encoded[..64], 3).is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("private-burn submission failed");
        std::process::exit(1);
    }
}

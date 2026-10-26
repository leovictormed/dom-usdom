//! Build one exact closed-Mainnet private burn from the observed deposit wallet.
//!
//! This command is offline with respect to DOM and Ethereum. It authenticates
//! every input, produces and self-verifies the native Groth16 spend proof, then
//! publishes a new encrypted wallet snapshot plus the exact burn payload. It
//! never authorizes submission, contacts a node, mines, signs an Ethereum
//! transaction or moves funds.

use std::{
    ffi::OsString,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dom_core::{Hash256, NETWORK_MAGIC_MAINNET};
use dom_node::{
    native_usdom_config::{load_native_usdom_v4_node_bundle, sha256_hex},
    private_staging_directory::PrivateStagingDirectory,
    secret_file::load_owner_only_utf8_secret_file,
};
use dom_usdom_prover::SpendProver;
use dom_usdom_wallet::{
    PrivateBurnRequest, WalletPassphrase, WalletSnapshotSeal, WalletState,
    MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES, WALLET_SNAPSHOT_SEAL_BYTES,
};
use serde::Deserialize;
use usdom_ethereum_finality_experiment::deposits::{
    deposit_witness_replay_slot, verify_deposit_witness, MAX_DEPOSIT_WITNESS_BYTES,
};
use zeroize::Zeroizing;

const AMOUNT_BASE_UNITS: u64 = 1_000_000;
const ETHEREUM_MAINNET_USDT: [u8; 20] = [
    0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45, 0x97, 0xc1,
    0x3d, 0x83, 0x1e, 0xc7,
];
const MAX_JSON_BYTES: u64 = 128 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROVING_KEY_BYTES: u64 = 64 * 1024 * 1024;
const SNAPSHOT_NAME: &str = "wallet-state.usdom";
const SEAL_NAME: &str = "wallet-state.seal";
const OBSERVATION_NAME: &str = "canonical-deposit-observation.json";
const PAYLOAD_NAME: &str = "private-burn-payload.bin";
const INDEX_NAME: &str = "private-burn-index.json";

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    deposit_witness_file: PathBuf,
    wallet_state_directory: PathBuf,
    password_file: PathBuf,
    proving_key_file: PathBuf,
    proving_key_sha256: String,
    recipient_file: PathBuf,
    output_directory: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositObservation {
    schema: String,
    native_manifest_sha256: String,
    deposit_id: String,
    note_commitment: String,
    amount_base_units: String,
    available_balance_base_units: String,
    canonical: bool,
    dom_chain_id: String,
    block_height: String,
    block_hash: String,
    snapshot_generation: String,
    snapshot_seal: String,
    history_authenticated: bool,
    broadcasts: bool,
    mines: bool,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    if arguments.output_directory.exists()
        || std::fs::symlink_metadata(&arguments.output_directory).is_ok()
    {
        anyhow::bail!("prepared private-burn state already exists; refusing to replace it");
    }
    validate_direct_directory(
        &arguments.wallet_state_directory,
        "observed wallet state directory",
    )?;
    validate_secure_parent(&arguments.output_directory)?;

    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        NETWORK_MAGIC_MAINNET,
    )?;
    if bundle.schedule.first_v4_height() != 1 {
        anyhow::bail!("closed Mainnet private burn requires native activation at height one");
    }

    let witness = read_direct_file(
        &arguments.deposit_witness_file,
        MAX_DEPOSIT_WITNESS_BYTES as u64,
        "finalized deposit witness",
        false,
    )?;
    let replay_slot = deposit_witness_replay_slot(&witness)
        .map_err(|error| anyhow::anyhow!("deposit replay slot verification failed: {error:#}"))?;
    let deposit_policy = bundle
        .deposit_policy
        .at_max_current_slot(replay_slot)
        .map_err(|error| anyhow::anyhow!("deposit replay policy failed: {error:#}"))?;
    let deposit = verify_deposit_witness(&witness, &deposit_policy)
        .map_err(|error| anyhow::anyhow!("deposit witness verification failed: {error:#}"))?;
    if deposit.amount() != AMOUNT_BASE_UNITS || deposit.finalized_execution().timestamp == 0 {
        anyhow::bail!("closed Mainnet burn requires the exact verified 1-USDT deposit witness");
    }

    let passphrase = WalletPassphrase::new(load_owner_only_utf8_secret_file(
        &arguments.password_file,
        "native USDOM wallet password",
        MIN_WALLET_PASSPHRASE_BYTES as u64,
        MAX_WALLET_PASSPHRASE_BYTES as u64,
    )?)?;
    let snapshot_path = arguments.wallet_state_directory.join(SNAPSHOT_NAME);
    let snapshot_bytes = read_direct_file(
        &snapshot_path,
        MAX_SNAPSHOT_BYTES,
        "observed encrypted wallet snapshot",
        true,
    )?;
    let seal_bytes = read_direct_file(
        &arguments.wallet_state_directory.join(SEAL_NAME),
        WALLET_SNAPSHOT_SEAL_BYTES as u64,
        "observed wallet snapshot seal",
        true,
    )?;
    let previous_seal = WalletSnapshotSeal::from_bytes(&seal_bytes)?;
    let mut loaded =
        WalletState::load_encrypted_snapshot_bytes(&snapshot_bytes, &passphrase, previous_seal)?;
    let observation_bytes = read_direct_file(
        &arguments.wallet_state_directory.join(OBSERVATION_NAME),
        MAX_JSON_BYTES,
        "canonical deposit observation",
        true,
    )?;
    let observation: DepositObservation = serde_json::from_slice(&observation_bytes)?;
    validate_observed_wallet(
        &observation,
        &arguments.manifest_sha256,
        previous_seal,
        &loaded.state,
        deposit.deposit_id().into(),
        *bundle.schedule.chain_id().as_bytes(),
    )?;

    let proving_key = Zeroizing::new(read_direct_file(
        &arguments.proving_key_file,
        MAX_PROVING_KEY_BYTES,
        "native USDOM spend proving key",
        true,
    )?);
    if sha256_hex(&proving_key) != arguments.proving_key_sha256 {
        anyhow::bail!("native USDOM spend proving key differs from its external SHA-256 pin");
    }
    let prover = SpendProver::from_bytes(
        &proving_key,
        Hash256::from_bytes(bundle.bridge.privacy_verifier_config_hash),
    )?;
    let recipient = read_recipient(&arguments.recipient_file)?;
    validate_redemption_recipient(recipient, bundle.bridge.reserve)?;

    let authenticated_ethereum_timestamp = deposit.finalized_execution().timestamp;
    validate_burn_clock(authenticated_ethereum_timestamp, bundle.bridge.burn_timing)?;
    let built = loaded.state.build_private_burn(
        &loaded.wallet,
        &prover,
        PrivateBurnRequest {
            bridge: bundle.bridge,
            recipient,
            amount: AMOUNT_BASE_UNITS,
            authenticated_ethereum_timestamp,
        },
        &mut rand::rngs::OsRng,
    )?;
    if built.change() != 0
        || !built.change_commitments().is_empty()
        || built.selected_commitments().len() != 1
        || built.nullifiers().len() != 1
        || loaded.state.available_balance() != 0
        || loaded.state.pending_private_burns().len() != 1
    {
        anyhow::bail!("closed Mainnet private burn did not consume the exact 1-USDT note");
    }

    let staging = PrivateStagingDirectory::create(&arguments.output_directory)?;
    let temporary = staging.path();
    let output_snapshot = temporary.join(SNAPSHOT_NAME);
    let result = (|| -> anyhow::Result<()> {
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
        staging.write_child_noclobber(PAYLOAD_NAME, built.payload())?;
        let record = built.record();
        let index = serde_json::json!({
            "schema": "usdom-closed-mainnet-private-burn-v1",
            "native_manifest_sha256": arguments.manifest_sha256,
            "deposit_witness_sha256": sha256_hex(&witness),
            "proving_key_sha256": arguments.proving_key_sha256,
            "proving_key_id": hex::encode(prover.proving_key_id().as_bytes()),
            "source_snapshot_generation": previous_seal.generation.to_string(),
            "source_snapshot_seal": hex::encode(previous_seal.to_bytes()),
            "snapshot_generation": seal.generation.to_string(),
            "snapshot_seal": hex::encode(seal.to_bytes()),
            "transition_id": hex::encode(built.transition_id().as_bytes()),
            "payload_file": PAYLOAD_NAME,
            "payload_sha256": sha256_hex(built.payload()),
            "payload_bytes": built.payload().len(),
            "burn": {
                "burnId": format!("0x{}", hex::encode(record.burn_id)),
                "requestId": format!("0x{}", hex::encode(record.request_id)),
                "recipient": format!("0x{}", hex::encode(record.recipient)),
                "amount": record.amount.to_string(),
                "ethereumChainId": u64::from_be_bytes(
                    record.ethereum_chain_id[24..]
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid Ethereum chain identifier"))?
                ).to_string(),
                "reserve": format!("0x{}", hex::encode(record.reserve)),
                "validUntil": record.valid_until.to_string(),
                "obligationCommitment": format!(
                    "0x{}", hex::encode(record.obligation_commitment)
                )
            },
            "authenticated_ethereum_timestamp": authenticated_ethereum_timestamp.to_string(),
            "exact_value_burn": true,
            "submission_authorized": false,
            "submits": false,
            "mines": false,
            "broadcasts": false
        });
        let mut index_bytes = serde_json::to_vec_pretty(&index)?;
        index_bytes.push(b'\n');
        staging.write_child_noclobber(INDEX_NAME, &index_bytes)?;
        staging.publish()?;
        println!("status: prepared");
        println!("valid_until: {}", record.valid_until);
        println!("submission_authorized: false");
        println!("submits: false");
        println!("mines: false");
        println!("broadcasts: false");
        Ok(())
    })();
    result
}

fn validate_observed_wallet(
    observation: &DepositObservation,
    manifest_sha256: &str,
    seal: WalletSnapshotSeal,
    state: &WalletState,
    deposit_id: [u8; 32],
    dom_chain_id: [u8; 32],
) -> anyhow::Result<()> {
    let expected = state.expected_issuances();
    if observation.schema != "usdom-canonical-deposit-observation-v1"
        || observation.native_manifest_sha256 != manifest_sha256
        || observation.deposit_id != hex::encode(deposit_id)
        || observation.note_commitment.len() != 64
        || observation.amount_base_units != "1000000"
        || observation.available_balance_base_units != "1000000"
        || !observation.canonical
        || observation.dom_chain_id != hex::encode(dom_chain_id)
        || observation.block_height != "1"
        || observation.block_hash != hex::encode(state.tip_identifier().as_bytes())
        || observation.snapshot_generation != "2"
        || observation.snapshot_seal != hex::encode(seal.to_bytes())
        || !observation.history_authenticated
        || observation.broadcasts
        || observation.mines
        || seal.generation != 2
        || state.tip_height() != 1
        || state.available_balance() != u128::from(AMOUNT_BASE_UNITS)
        || !state.pending_private_transfers().is_empty()
        || !state.pending_private_burns().is_empty()
        || expected.len() != 1
        || expected[0].deposit_id != deposit_id
        || expected[0].note_commitment.to_bytes().as_slice()
            != hex::decode(&observation.note_commitment)?.as_slice()
        || expected[0].amount != AMOUNT_BASE_UNITS
        || !expected[0].canonical
    {
        anyhow::bail!("observed wallet is not the exact authenticated 1-USDT state");
    }
    Ok(())
}

fn validate_burn_clock(
    anchor_timestamp: u64,
    timing: dom_usdom_state::BurnTimingPolicy,
) -> anyhow::Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if anchor_timestamp
        > now
            .checked_add(timing.max_dom_clock_lead_secs)
            .ok_or_else(|| anyhow::anyhow!("burn clock bound overflow"))?
        || now
            > anchor_timestamp
                .checked_add(timing.max_ethereum_anchor_age_secs)
                .ok_or_else(|| anyhow::anyhow!("Ethereum anchor age overflow"))?
    {
        anyhow::bail!("verified Ethereum timestamp is outside the native burn clock policy");
    }
    let valid_until = anchor_timestamp
        .checked_add(timing.max_certificate_lifetime_secs)
        .ok_or_else(|| anyhow::anyhow!("burn deadline overflow"))?;
    let minimum = now
        .checked_add(timing.withdrawal_delay_secs)
        .and_then(|value| value.checked_add(timing.min_execution_window_secs))
        .and_then(|value| value.checked_add(timing.relay_safety_margin_secs))
        .ok_or_else(|| anyhow::anyhow!("burn execution window overflow"))?;
    if valid_until < minimum {
        anyhow::bail!("verified Ethereum timestamp leaves no safe redemption window");
    }
    Ok(())
}

fn read_recipient(path: &Path) -> anyhow::Result<[u8; 20]> {
    let bytes = read_direct_file(path, 64, "Ethereum burn recipient", true)?;
    let text = std::str::from_utf8(&bytes)?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let raw = text
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("Ethereum burn recipient requires 0x prefix"))?;
    if raw.len() != 40 || !raw.bytes().all(|value| value.is_ascii_hexdigit()) {
        anyhow::bail!("Ethereum burn recipient is not an exact address");
    }
    let recipient: [u8; 20] = hex::decode(raw)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ethereum burn recipient has the wrong length"))?;
    if recipient == [0; 20] {
        anyhow::bail!("Ethereum burn recipient cannot be zero");
    }
    Ok(recipient)
}

fn validate_redemption_recipient(recipient: [u8; 20], reserve: [u8; 20]) -> anyhow::Result<()> {
    if recipient == reserve {
        anyhow::bail!("Ethereum burn recipient cannot be the reserve itself");
    }
    if recipient == ETHEREUM_MAINNET_USDT {
        anyhow::bail!("Ethereum burn recipient cannot be the Mainnet USDT contract");
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
        .ok_or_else(|| anyhow::anyhow!("output directory must have a parent"))?;
    validate_direct_directory(parent, "prepared-burn state parent")
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
        "--deposit-witness-file",
        "--wallet-state-directory",
        "--password-file",
        "--proving-key-file",
        "--proving-key-sha256",
        "--recipient-file",
        "--output-directory",
    ];
    if map.len() != EXPECTED.len() || map.keys().any(|name| !EXPECTED.contains(&name.as_str())) {
        anyhow::bail!("unknown or missing private-burn option");
    }
    let take_path = |name: &str| -> anyhow::Result<PathBuf> {
        map.get(name)
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("{name} is required"))
    };
    let take_hash = |name: &str| -> anyhow::Result<String> {
        map.get(name)
            .and_then(|value| value.to_str())
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("{name} is invalid"))
    };
    Ok(Arguments {
        manifest_file: take_path("--manifest-file")?,
        manifest_sha256: take_hash("--manifest-sha256")?,
        deposit_witness_file: take_path("--deposit-witness-file")?,
        wallet_state_directory: take_path("--wallet-state-directory")?,
        password_file: take_path("--password-file")?,
        proving_key_file: take_path("--proving-key-file")?,
        proving_key_sha256: take_hash("--proving-key-sha256")?,
        recipient_file: take_path("--recipient-file")?,
        output_directory: take_path("--output-directory")?,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        parse_arguments, read_recipient, validate_redemption_recipient, ETHEREUM_MAINNET_USDT,
    };
    use std::{ffi::OsString, os::unix::fs::PermissionsExt};

    fn args(values: &[&str]) -> Vec<OsString> {
        std::iter::once("dom-usdom-build-private-burn")
            .chain(values.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parser_requires_the_exact_fixed_input_set() {
        let hash = "11".repeat(32);
        let values = [
            "--manifest-file",
            "m",
            "--manifest-sha256",
            &hash,
            "--deposit-witness-file",
            "w",
            "--wallet-state-directory",
            "s",
            "--password-file",
            "p",
            "--proving-key-file",
            "k",
            "--proving-key-sha256",
            &hash,
            "--recipient-file",
            "r",
            "--output-directory",
            "o",
        ];
        assert!(parse_arguments(args(&values)).is_ok());
        assert!(parse_arguments(args(&values[..16])).is_err());
        let mut duplicate = values.to_vec();
        duplicate.extend(["--output-directory", "again"]);
        assert!(parse_arguments(args(&duplicate)).is_err());
    }

    #[test]
    fn recipient_file_is_owner_only_exact_and_nonzero() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("recipient");
        std::fs::write(&path, format!("0x{}\n", "12".repeat(20))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_recipient(&path).unwrap(), [0x12; 20]);
        std::fs::write(&path, format!("0x{}\n", "00".repeat(20))).unwrap();
        assert!(read_recipient(&path).is_err());
    }

    #[test]
    fn redemption_recipient_rejects_unpayable_contract_destinations() {
        let reserve = [0x44; 20];
        assert_eq!(
            hex::encode(ETHEREUM_MAINNET_USDT),
            "dac17f958d2ee523a2206206994597c13d831ec7"
        );
        assert!(validate_redemption_recipient([0x33; 20], reserve).is_ok());
        assert!(validate_redemption_recipient(reserve, reserve).is_err());
        assert!(validate_redemption_recipient(ETHEREUM_MAINNET_USDT, reserve).is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("private-burn build failed");
        std::process::exit(1);
    }
}

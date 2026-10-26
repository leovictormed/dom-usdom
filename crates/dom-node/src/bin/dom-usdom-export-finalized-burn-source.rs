//! Offline export of one canonical `UDFINL04` finalized-burn proof input.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use dom_config::{Network, NodeConfig};
use dom_node::{
    native_usdom_config::{load_native_usdom_v4_node_bundle, sha256_hex},
    node::DomNode,
    private_staging_directory::PrivateDirectoryAuthority,
};
use usdom_ethereum_finality_experiment::checkpoints::{
    checkpoint_witness_replay_slot, verify_checkpoint_witness, MAX_CHECKPOINT_WITNESS_BYTES,
};

const INPUT_NAME: &str = "finalized-burn-input.bin";
const INDEX_NAME: &str = "finalized-burn-source-index.json";

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    data_dir: PathBuf,
    checkpoint_statement_file: PathBuf,
    checkpoint_witness_file: PathBuf,
    burn_id_file: PathBuf,
    output_dir: PathBuf,
    network: Network,
}

async fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    require_existing_directory(&arguments.data_dir, "DOM data directory")?;
    require_existing_directory(
        &arguments.output_dir,
        "finalized-burn source output directory",
    )?;
    invalidate_outputs(&arguments.output_dir)?;

    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        arguments.network.magic(),
    )?;
    let first_v2_height = bundle
        .candidate_v2_first_height
        .ok_or_else(|| anyhow::anyhow!("native manifest does not enable candidate V2"))?;
    let checkpoint_witness = read_regular_file(
        &arguments.checkpoint_witness_file,
        MAX_CHECKPOINT_WITNESS_BYTES,
        "raw Ethereum checkpoint witness",
    )?;
    let checkpoint_statement_bytes = read_regular_file(
        &arguments.checkpoint_statement_file,
        1024,
        "checkpoint outer statement",
    )?;
    let checkpoint_statement =
        dom_chain::CheckpointStatementV6::from_bytes(&checkpoint_statement_bytes)
            .map_err(|error| anyhow::anyhow!("invalid checkpoint outer statement: {error}"))?;
    let burn_id = read_burn_id(&arguments.burn_id_file)?;
    let replay_slot = checkpoint_witness_replay_slot(&checkpoint_witness)
        .map_err(|error| anyhow::anyhow!("invalid checkpoint witness replay slot: {error:#}"))?;
    let dynamic_policy = bundle
        .checkpoint_policy
        .at_max_current_slot(replay_slot)
        .map_err(|error| anyhow::anyhow!("invalid checkpoint replay policy: {error:#}"))?;
    let verified_checkpoint = verify_checkpoint_witness(&checkpoint_witness, &dynamic_policy)
        .map_err(|error| anyhow::anyhow!("checkpoint authentication failed: {error:#}"))?;
    let checkpoint =
        dom_chain::ethereum_checkpoint_poc::decode_test_oracle_v2(verified_checkpoint.record())?;
    if checkpoint.dom_network_magic != arguments.network.magic() {
        anyhow::bail!("authenticated checkpoint belongs to another DOM network");
    }

    let mut config = match arguments.network {
        Network::Mainnet => NodeConfig::mainnet(),
        Network::Testnet => NodeConfig::testnet(),
        Network::Regtest => NodeConfig::regtest(),
    };
    config.data_dir = arguments.data_dir.to_string_lossy().into_owned();
    config.mine = false;
    config.wallet_path = None;
    config.wallet_password = None;
    let v1_schedule = bundle.schedule;
    let node = DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier(
        config,
        bundle.bridge,
        bundle.checkpoint_policy,
        bundle.deposit_policy,
        bundle.issuance_closure_policy,
        &bundle.spend_verifying_key,
        v1_schedule,
        first_v2_height,
    )?;
    let input = node
        .build_finalized_burn_prover_input(
            v1_schedule,
            checkpoint.dom_block,
            burn_id,
            checkpoint_statement,
            checkpoint_witness.clone(),
        )
        .await?;
    let input_bytes = input.to_bytes()?;
    let decoded = dom_chain::FinalizedBurnProverInput::from_bytes(&input_bytes)?;
    let public_statement = decoded.public_statement()?;
    if decoded.statement_hash() != input.statement_hash()
        || public_statement.statement_hash() != decoded.statement_hash()
        || decoded.to_bytes()?.as_slice() != input_bytes
    {
        anyhow::bail!("finalized-burn source changed during canonical round trip");
    }
    if public_statement.ethereum_chain_id[..24] != [0; 24] {
        anyhow::bail!("finalized-burn Ethereum chain ID exceeds the supported uint64 boundary");
    }
    let ethereum_chain_id =
        u64::from_be_bytes(public_statement.ethereum_chain_id[24..].try_into()?);

    let index = serde_json::json!({
        "schema": "usdom-finalized-burn-source-v3",
        "network": network_name(arguments.network),
        "manifest_sha256": arguments.manifest_sha256,
        "candidate_v2_first_height": first_v2_height,
        "burn_id": hex::encode(burn_id),
        "checkpoint_dom_height": checkpoint.height,
        "checkpoint_dom_block": checkpoint.dom_block.to_string(),
        "checkpoint_dom_state_root": checkpoint.dom_state_root.to_string(),
        "checkpoint_ethereum_block_number": checkpoint.ethereum_block_number,
        "checkpoint_ethereum_block": checkpoint.ethereum_block.to_string(),
        "checkpoint_beacon_slot": checkpoint.ethereum_beacon_slot,
        "checkpoint_witness_sha256": sha256_hex(&checkpoint_witness),
        "statement_hash": input.statement_hash().to_string(),
        "burn": {
            "burnId": format!("0x{}", hex::encode(public_statement.burn_id)),
            "requestId": format!("0x{}", hex::encode(public_statement.request_id)),
            "recipient": format!("0x{}", hex::encode(public_statement.recipient)),
            "amount": public_statement.amount.to_string(),
            "domDomain": format!("0x{}", hex::encode(public_statement.dom_domain)),
            "height": public_statement.height.to_string(),
            "blockHash": format!("0x{}", hex::encode(public_statement.block_hash.as_bytes())),
            "stateRoot": format!("0x{}", hex::encode(public_statement.state_root.as_bytes())),
            "finalityBeaconSlot": public_statement.finality_beacon_slot.to_string(),
            "validUntil": public_statement.valid_until.to_string()
        },
        "ethereum_chain_id": ethereum_chain_id.to_string(),
        "reserve": format!("0x{}", hex::encode(public_statement.reserve)),
        "activation_schedule_commitment": format!(
            "0x{}",
            hex::encode(public_statement.activation_schedule_commitment.as_bytes())
        ),
        "input_file": INPUT_NAME,
        "input_sha256": sha256_hex(&input_bytes),
        "input_length": input_bytes.len()
    });
    let mut index_bytes = serde_json::to_vec_pretty(&index)?;
    index_bytes.push(b'\n');
    publish_outputs(
        &arguments.output_dir,
        &[
            (INPUT_NAME.to_owned(), input_bytes),
            (INDEX_NAME.to_owned(), index_bytes),
        ],
    )?;

    println!("status: exported");
    println!("network: {}", network_name(arguments.network));
    println!("burn_id: {}", hex::encode(burn_id));
    println!("checkpoint_dom_height: {}", checkpoint.height);
    println!("checkpoint_dom_block: {}", checkpoint.dom_block);
    println!("statement_hash: {}", input.statement_hash());
    println!("{INPUT_NAME}_sha256: {}", sha256_hex(&decoded.to_bytes()?));
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Arguments> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let remaining: Vec<OsString> = arguments.collect();
    let mut manifest_file = None;
    let mut manifest_sha256 = None;
    let mut data_dir = None;
    let mut checkpoint_statement_file = None;
    let mut checkpoint_witness_file = None;
    let mut burn_id_file = None;
    let mut output_dir = None;
    let mut network = None;
    let (pairs, remainder) = remaining.as_chunks::<2>();
    for pair in pairs {
        let flag = &pair[0];
        let value = &pair[1];
        match flag.to_str() {
            Some("--manifest-file") if manifest_file.is_none() => {
                manifest_file = Some(PathBuf::from(value))
            }
            Some("--manifest-sha256") if manifest_sha256.is_none() => {
                manifest_sha256 = Some(
                    value
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("manifest SHA-256 is not valid UTF-8"))?
                        .to_owned(),
                )
            }
            Some("--data-dir") if data_dir.is_none() => data_dir = Some(PathBuf::from(value)),
            Some("--checkpoint-statement-file") if checkpoint_statement_file.is_none() => {
                checkpoint_statement_file = Some(PathBuf::from(value))
            }
            Some("--checkpoint-witness-file") if checkpoint_witness_file.is_none() => {
                checkpoint_witness_file = Some(PathBuf::from(value))
            }
            Some("--burn-id-file") if burn_id_file.is_none() => {
                burn_id_file = Some(PathBuf::from(value))
            }
            Some("--output-dir") if output_dir.is_none() => output_dir = Some(PathBuf::from(value)),
            Some("--network") if network.is_none() => {
                network = Some(match value.to_str() {
                    Some("mainnet") => Network::Mainnet,
                    Some("testnet") => Network::Testnet,
                    Some("regtest") => Network::Regtest,
                    _ => anyhow::bail!("network must be mainnet, testnet, or regtest"),
                })
            }
            Some(
                "--manifest-file"
                | "--manifest-sha256"
                | "--data-dir"
                | "--checkpoint-statement-file"
                | "--checkpoint-witness-file"
                | "--burn-id-file"
                | "--output-dir"
                | "--network",
            ) => anyhow::bail!("duplicate argument {flag:?}"),
            _ => anyhow::bail!("unknown argument {flag:?}"),
        }
    }
    if !remainder.is_empty() {
        anyhow::bail!("every option requires exactly one value");
    }
    Ok(Arguments {
        manifest_file: manifest_file
            .ok_or_else(|| anyhow::anyhow!("--manifest-file is required"))?,
        manifest_sha256: manifest_sha256
            .ok_or_else(|| anyhow::anyhow!("--manifest-sha256 is required"))?,
        data_dir: data_dir.ok_or_else(|| anyhow::anyhow!("--data-dir is required"))?,
        checkpoint_statement_file: checkpoint_statement_file
            .ok_or_else(|| anyhow::anyhow!("--checkpoint-statement-file is required"))?,
        checkpoint_witness_file: checkpoint_witness_file
            .ok_or_else(|| anyhow::anyhow!("--checkpoint-witness-file is required"))?,
        burn_id_file: burn_id_file.ok_or_else(|| anyhow::anyhow!("--burn-id-file is required"))?,
        output_dir: output_dir.ok_or_else(|| anyhow::anyhow!("--output-dir is required"))?,
        network: network.ok_or_else(|| anyhow::anyhow!("--network is required"))?,
    })
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

fn require_existing_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot inspect {label}: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("{label} must be an existing non-symlink directory");
    }
    Ok(())
}

fn read_regular_file(path: &Path, maximum: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    dom_wallet_crypto::read_captured_bytes(path, maximum)
        .map_err(|error| anyhow::anyhow!("cannot capture {label}: {error}"))
}

fn read_burn_id(path: &Path) -> anyhow::Result<[u8; 32]> {
    let bytes = read_regular_file(path, 65, "burn ID")?;
    if bytes.len() != 65
        || bytes[64] != b'\n'
        || !bytes[..64]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        anyhow::bail!("burn ID file must contain exactly 64 lowercase hex characters and newline");
    }
    let mut burn_id = [0u8; 32];
    hex::decode_to_slice(&bytes[..64], &mut burn_id)?;
    if burn_id == [0; 32] {
        anyhow::bail!("burn ID must be nonzero");
    }
    Ok(burn_id)
}

fn invalidate_outputs(output_dir: &Path) -> anyhow::Result<()> {
    PrivateDirectoryAuthority::open(output_dir)?
        .invalidate_where(|name| matches!(name, INPUT_NAME | INDEX_NAME))
}

fn publish_outputs(output_dir: &Path, files: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
    PrivateDirectoryAuthority::open(output_dir)?.replace_files(files, &[INDEX_NAME])
}

#[cfg(test)]
mod tests {
    use super::{
        invalidate_outputs, parse_arguments, publish_outputs, read_burn_id, INDEX_NAME, INPUT_NAME,
    };
    use dom_config::Network;
    use std::{ffi::OsString, fs};
    use tempfile::TempDir;

    fn args(values: &[&str]) -> Vec<OsString> {
        std::iter::once("dom-usdom-export-finalized-burn-source")
            .chain(values.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parser_accepts_only_complete_fixed_source_arguments() {
        let parsed = parse_arguments(args(&[
            "--manifest-file",
            "/srv/dom/native.json",
            "--manifest-sha256",
            &"ab".repeat(32),
            "--data-dir",
            "/srv/dom/mainnet",
            "--checkpoint-statement-file",
            "/srv/dom/checkpoint-statement-v6.bin",
            "--checkpoint-witness-file",
            "/srv/dom/checkpoint-witness.bin",
            "--burn-id-file",
            "/srv/dom/burn-id.hex",
            "--output-dir",
            "/srv/dom/finalized-burn-source",
            "--network",
            "mainnet",
        ]))
        .unwrap();
        assert_eq!(parsed.network, Network::Mainnet);
        assert_eq!(parsed.manifest_sha256, "ab".repeat(32));
    }

    #[test]
    fn parser_rejects_partial_duplicate_unknown_and_identity_overrides() {
        assert!(parse_arguments(args(&["--network", "mainnet"])).is_err());
        assert!(parse_arguments(args(&["--burn-id-file", "a", "--burn-id-file", "b"])).is_err());
        assert!(parse_arguments(args(&[
            "--checkpoint-statement-file",
            "a",
            "--checkpoint-statement-file",
            "b",
        ]))
        .is_err());
        assert!(parse_arguments(args(&["--checkpoint-block", &"11".repeat(32)])).is_err());
        assert!(parse_arguments(args(&["--network"])).is_err());
    }

    #[test]
    fn burn_id_file_is_exact_lowercase_hex() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("burn-id.hex");
        fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
        assert_eq!(read_burn_id(&path).unwrap(), [0xab; 32]);
        fs::write(&path, format!("{}\n", "AB".repeat(32))).unwrap();
        assert!(read_burn_id(&path).is_err());
        fs::write(&path, "00".repeat(32)).unwrap();
        assert!(read_burn_id(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn burn_id_file_rejects_symlinks_and_hard_links() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().unwrap();
        let source = directory.path().join("burn-id.hex");
        fs::write(&source, format!("{}\n", "ab".repeat(32))).unwrap();
        let indirect = directory.path().join("indirect.hex");
        symlink(&source, &indirect).unwrap();
        assert!(read_burn_id(&indirect).is_err());

        let linked = directory.path().join("linked.hex");
        fs::hard_link(&source, &linked).unwrap();
        assert!(read_burn_id(&source).is_err());
        assert!(read_burn_id(&linked).is_err());
    }

    #[test]
    fn stale_output_invalidation_preserves_source_and_unrelated_files() {
        let directory = TempDir::new().unwrap();
        for (name, value) in [
            (INPUT_NAME, b"stale-input".as_slice()),
            (INDEX_NAME, b"stale-index".as_slice()),
            ("checkpoint-witness.bin", b"witness".as_slice()),
            ("burn-id.hex", b"burn-id".as_slice()),
            ("operator-notes.txt", b"preserve".as_slice()),
        ] {
            fs::write(directory.path().join(name), value).unwrap();
        }

        invalidate_outputs(directory.path()).unwrap();

        assert!(!directory.path().join(INPUT_NAME).exists());
        assert!(!directory.path().join(INDEX_NAME).exists());
        assert_eq!(
            fs::read(directory.path().join("checkpoint-witness.bin")).unwrap(),
            b"witness"
        );
        assert_eq!(
            fs::read(directory.path().join("burn-id.hex")).unwrap(),
            b"burn-id"
        );
        assert_eq!(
            fs::read(directory.path().join("operator-notes.txt")).unwrap(),
            b"preserve"
        );
    }

    #[test]
    fn invalid_publication_preserves_previous_generation_and_source_files() {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join(INPUT_NAME), b"stale-input").unwrap();
        fs::write(directory.path().join(INDEX_NAME), b"stale-index").unwrap();
        fs::write(directory.path().join("checkpoint-witness.bin"), b"witness").unwrap();
        assert!(publish_outputs(
            directory.path(),
            &[
                (INPUT_NAME.to_owned(), b"new-input".to_vec()),
                ("../invalid-index".to_owned(), b"new-index".to_vec()),
            ],
        )
        .is_err());

        assert_eq!(
            fs::read(directory.path().join(INPUT_NAME)).unwrap(),
            b"stale-input"
        );
        assert_eq!(
            fs::read(directory.path().join(INDEX_NAME)).unwrap(),
            b"stale-index"
        );
        assert_eq!(
            fs::read(directory.path().join("checkpoint-witness.bin")).unwrap(),
            b"witness"
        );
        assert!(!directory
            .path()
            .parent()
            .unwrap()
            .join("invalid-index")
            .exists());
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(_error) = run().await {
        eprintln!("finalized-burn source export failed");
        std::process::exit(1);
    }
}

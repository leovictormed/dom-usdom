//! Offline export of the latest authenticated candidate-v2 checkpoint source set.

use std::{
    ffi::OsString,
    fs::{self},
    path::{Path, PathBuf},
};

use dom_config::{Network, NodeConfig};
use dom_node::{
    native_usdom_config::{load_native_usdom_v4_node_bundle, sha256_hex},
    node::DomNode,
    private_staging_directory::PrivateDirectoryAuthority,
};
use dom_usdom_checkpoint_program::CheckpointSegmentTransition;

const INDEX_NAME: &str = "checkpoint-source-set-index.json";
const ECONOMIC_INDEX_NAME: &str = "checkpoint-economic-source-set-index.json";
const OUTPUT_SUFFIXES: [&str; 4] = [
    "transition.bin",
    "private-input.bin",
    "policy-input.bin",
    "native-state-opening.bin",
];

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    data_dir: PathBuf,
    output_dir: PathBuf,
    network: Network,
}

async fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    require_existing_directory(&arguments.data_dir, "DOM data directory")?;
    require_existing_directory(&arguments.output_dir, "checkpoint source output directory")?;

    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        arguments.network.magic(),
    )?;
    let first_v2_height = bundle
        .candidate_v2_first_height
        .ok_or_else(|| anyhow::anyhow!("native manifest does not enable candidate V2"))?;
    let randomx_receipt_image_id = bundle
        .randomx_receipt_image_id
        .ok_or_else(|| anyhow::anyhow!("native manifest does not pin a RandomX receipt ImageID"))?;
    let checkpoint_interval_blocks = bundle
        .checkpoint_interval_blocks
        .ok_or_else(|| anyhow::anyhow!("native manifest does not pin a checkpoint interval"))?;
    let checkpoint_confirmation_depth_blocks = bundle
        .checkpoint_confirmation_depth_blocks
        .ok_or_else(|| anyhow::anyhow!("native manifest does not pin a confirmation depth"))?;

    invalidate_outputs(&arguments.output_dir)?;
    let mut config = match arguments.network {
        Network::Mainnet => NodeConfig::mainnet(),
        Network::Testnet => NodeConfig::testnet(),
        Network::Regtest => NodeConfig::regtest(),
    };
    config.data_dir = arguments.data_dir.to_string_lossy().into_owned();
    config.mine = false;
    config.wallet_path = None;
    config.wallet_password = None;
    let node = DomNode::init_native_usdom_candidate_for_schedule_with_spend_verifier(
        config,
        bundle.bridge,
        bundle.checkpoint_policy,
        bundle.deposit_policy,
        bundle.issuance_closure_policy,
        &bundle.spend_verifying_key,
        bundle.schedule,
        first_v2_height,
    )?;
    let source_set = node
        .build_latest_v2_checkpoint_sources(
            randomx_receipt_image_id,
            checkpoint_interval_blocks,
            checkpoint_confirmation_depth_blocks,
        )
        .await?;
    let files = source_set_files(
        &source_set,
        &arguments.manifest_sha256,
        randomx_receipt_image_id,
        checkpoint_interval_blocks,
        checkpoint_confirmation_depth_blocks,
    )?;
    publish_outputs(&arguments.output_dir, &files)?;

    println!("status: exported");
    println!("network: {:?}", arguments.network);
    println!("manifest_sha256: {}", arguments.manifest_sha256);
    println!("candidate_v2_first_height: {first_v2_height}");
    println!("previous_height: {}", source_set.previous_height());
    println!("target_height: {}", source_set.target_height());
    println!("confirmation_height: {}", source_set.confirmation_height());
    println!("segment_count: {}", source_set.segments().len());
    println!(
        "randomx_receipt_image_id: {}",
        hex::encode(randomx_receipt_image_id)
    );
    for (name, value) in &files {
        println!("{name}_sha256: {}", sha256_hex(value));
    }
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Arguments> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let remaining: Vec<OsString> = arguments.collect();
    let mut manifest_file = None;
    let mut manifest_sha256 = None;
    let mut data_dir = None;
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
                "--manifest-file" | "--manifest-sha256" | "--data-dir" | "--output-dir"
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
        output_dir: output_dir.ok_or_else(|| anyhow::anyhow!("--output-dir is required"))?,
        network: network.ok_or_else(|| anyhow::anyhow!("--network is required"))?,
    })
}

fn require_existing_directory(path: &Path, label: &str) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot inspect {label}: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!("{label} must be an existing non-symlink directory");
    }
    Ok(())
}

fn source_set_files(
    source_set: &dom_usdom_checkpoint_program::AuthenticatedCheckpointSourceSet,
    manifest_sha256: &str,
    randomx_receipt_image_id: [u8; 32],
    checkpoint_interval_blocks: u32,
    checkpoint_confirmation_depth_blocks: u32,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::with_capacity(source_set.segments().len() * OUTPUT_SUFFIXES.len() + 2);
    let mut index_segments = Vec::with_capacity(source_set.segments().len());
    let mut economic_records = Vec::new();
    for (index, source) in source_set.segments().iter().enumerate() {
        let transition = CheckpointSegmentTransition::from_bytes(source.transition_bytes())?;
        let values = [
            source.transition_bytes().as_slice(),
            source.private_input_bytes(),
            source.policy_input_bytes(),
            source.native_state_opening_bytes(),
        ];
        let mut names = Vec::with_capacity(OUTPUT_SUFFIXES.len());
        let mut hashes = Vec::with_capacity(OUTPUT_SUFFIXES.len());
        for (suffix, value) in OUTPUT_SUFFIXES.iter().zip(values) {
            let name = segment_name(index, suffix);
            names.push(name.clone());
            hashes.push(sha256_hex(value));
            files.push((name, value.to_vec()));
        }
        index_segments.push(serde_json::json!({
            "index": index,
            "previous_height": transition.previous.height,
            "next_height": transition.next.height,
            "block_count": transition.block_count,
            "transition_file": names[0],
            "transition_sha256": hashes[0],
            "private_input_file": names[1],
            "private_input_sha256": hashes[1],
            "policy_input_file": names[2],
            "policy_input_sha256": hashes[2],
            "native_state_opening_file": names[3],
            "native_state_opening_sha256": hashes[3]
        }));
        for block in source.economic_blocks() {
            let block_index = block.block_index();
            let transition_name = format!(
                "checkpoint-segment-{index:04}-economic-block-{block_index:04}-transition.bin"
            );
            let transition = block.source().transition_bytes().to_vec();
            let transition_sha256 = sha256_hex(&transition);
            files.push((transition_name.clone(), transition));
            let mut chunks = Vec::with_capacity(block.source().chunks().len());
            for (chunk_index, chunk) in block.source().chunks().iter().enumerate() {
                let transition_file = format!(
                    "checkpoint-segment-{index:04}-economic-block-{block_index:04}-chunk-{chunk_index:04}-transition.bin"
                );
                let witness_file = format!(
                    "checkpoint-segment-{index:04}-economic-block-{block_index:04}-chunk-{chunk_index:04}-witness.bin"
                );
                let chunk_transition = chunk.transition_bytes().to_vec();
                let chunk_witness = chunk.witness_bytes().to_vec();
                chunks.push(serde_json::json!({
                    "index": chunk_index,
                    "transition_file": transition_file,
                    "transition_sha256": sha256_hex(&chunk_transition),
                    "witness_file": witness_file,
                    "witness_sha256": sha256_hex(&chunk_witness)
                }));
                files.push((transition_file, chunk_transition));
                files.push((witness_file, chunk_witness));
            }
            economic_records.push(serde_json::json!({
                "segment_index": index,
                "block_index": block_index,
                "block_transition_file": transition_name,
                "block_transition_sha256": transition_sha256,
                "chunk_count": chunks.len(),
                "chunks": chunks
            }));
        }
    }
    let index = serde_json::json!({
        "schema": "usdom-canonical-checkpoint-source-set-v1",
        "manifest_sha256": manifest_sha256,
        "randomx_receipt_image_id": hex::encode(randomx_receipt_image_id),
        "checkpoint_interval_blocks": checkpoint_interval_blocks,
        "checkpoint_confirmation_depth_blocks": checkpoint_confirmation_depth_blocks,
        "previous_height": source_set.previous_height(),
        "target_height": source_set.target_height(),
        "confirmation_height": source_set.confirmation_height(),
        "segment_count": source_set.segments().len(),
        "segments": index_segments
    });
    let mut index_bytes = serde_json::to_vec_pretty(&index)?;
    index_bytes.push(b'\n');
    let source_index_sha256 = sha256_hex(&index_bytes);
    files.push((INDEX_NAME.to_owned(), index_bytes));
    let economic_index = serde_json::json!({
        "schema": "usdom-economic-proof-source-set-v1",
        "checkpoint_source_index_path": "evidence/checkpoint-source-set/checkpoint-source-set-index.json",
        "checkpoint_source_index_sha256": source_index_sha256,
        "block_count": economic_records.len(),
        "blocks": economic_records
    });
    let mut economic_index_bytes = serde_json::to_vec_pretty(&economic_index)?;
    economic_index_bytes.push(b'\n');
    files.push((ECONOMIC_INDEX_NAME.to_owned(), economic_index_bytes));
    Ok(files)
}

fn segment_name(index: usize, suffix: &str) -> String {
    format!("checkpoint-segment-{index:04}-{suffix}")
}

fn is_source_set_name(name: &str) -> bool {
    if matches!(name, INDEX_NAME | ECONOMIC_INDEX_NAME) {
        return true;
    }
    let Some(rest) = name.strip_prefix("checkpoint-segment-") else {
        return false;
    };
    if rest.len() > 5
        && rest.as_bytes()[..4].iter().all(u8::is_ascii_digit)
        && rest.as_bytes()[4] == b'-'
        && OUTPUT_SUFFIXES.iter().any(|suffix| &rest[5..] == *suffix)
    {
        return true;
    }
    let Some(rest) = rest.get(5..) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix("economic-block-") else {
        return false;
    };
    if rest.len() < 5 || !rest.as_bytes()[..4].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let tail = &rest[4..];
    if tail == "-transition.bin" {
        return true;
    }
    let Some(chunk) = tail.strip_prefix("-chunk-") else {
        return false;
    };
    chunk.len() > 5
        && chunk.as_bytes()[..4].iter().all(u8::is_ascii_digit)
        && matches!(&chunk[4..], "-transition.bin" | "-witness.bin")
}

fn invalidate_outputs(output_dir: &Path) -> anyhow::Result<()> {
    PrivateDirectoryAuthority::open(output_dir)?.invalidate_where(is_source_set_name)
}

fn publish_outputs(output_dir: &Path, files: &[(String, Vec<u8>)]) -> anyhow::Result<()> {
    PrivateDirectoryAuthority::open(output_dir)?
        .replace_files(files, &[INDEX_NAME, ECONOMIC_INDEX_NAME])
}

#[cfg(test)]
mod tests {
    use super::{is_source_set_name, parse_arguments, segment_name};
    use dom_config::Network;
    use std::ffi::OsString;

    fn args(values: &[&str]) -> Vec<OsString> {
        std::iter::once("dom-usdom-export-checkpoint-source-set")
            .chain(values.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parser_accepts_only_complete_path_and_identity_arguments() {
        let parsed = parse_arguments(args(&[
            "--manifest-file",
            "/srv/dom/native.json",
            "--manifest-sha256",
            &"ab".repeat(32),
            "--data-dir",
            "/srv/dom/mainnet",
            "--output-dir",
            "/srv/dom/checkpoint-source",
            "--network",
            "mainnet",
        ]))
        .unwrap();
        assert_eq!(parsed.network, Network::Mainnet);
        assert_eq!(parsed.manifest_sha256, "ab".repeat(32));
    }

    #[test]
    fn parser_rejects_partial_duplicate_unknown_and_source_overrides() {
        assert!(parse_arguments(args(&["--network", "mainnet"])).is_err());
        assert!(parse_arguments(args(&["--manifest-file", "a", "--manifest-file", "b",])).is_err());
        assert!(parse_arguments(args(&["--block", "11"])).is_err());
        assert!(parse_arguments(args(&["--randomx-image-id", &"17".repeat(32)])).is_err());
        assert!(parse_arguments(args(&["--network"])).is_err());
    }

    #[test]
    fn output_names_are_exact_and_do_not_capture_unrelated_files() {
        assert_eq!(
            segment_name(3, "transition.bin"),
            "checkpoint-segment-0003-transition.bin"
        );
        assert!(is_source_set_name("checkpoint-source-set-index.json"));
        assert!(is_source_set_name(
            "checkpoint-economic-source-set-index.json"
        ));
        assert!(is_source_set_name("checkpoint-segment-0003-transition.bin"));
        assert!(is_source_set_name(
            "checkpoint-segment-0003-economic-block-0002-transition.bin"
        ));
        assert!(is_source_set_name(
            "checkpoint-segment-0003-economic-block-0002-chunk-0001-witness.bin"
        ));
        assert!(!is_source_set_name("checkpoint-segment-003-transition.bin"));
        assert!(!is_source_set_name(
            "checkpoint-segment-0003-transition.bin.bak"
        ));
        assert!(!is_source_set_name("operator-notes.txt"));
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(_error) = run().await {
        eprintln!("checkpoint source-set export failed");
        std::process::exit(1);
    }
}

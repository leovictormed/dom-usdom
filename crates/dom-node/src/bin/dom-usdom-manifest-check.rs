//! Offline validator for one exact native USDOM runtime manifest.
//!
//! The tool exercises the same hash, network, schedule, Ethereum-policy,
//! bridge and Groth16-verifier checks as `dom-node`, then prints only public
//! commitments. It never opens node storage, listeners, a wallet or a miner.

use std::{ffi::OsString, path::PathBuf};

use dom_config::Network;
use dom_node::native_usdom_config::{hash_hex, load_native_usdom_v4_node_bundle, sha256_hex};

enum Action {
    Help,
    Check(Arguments),
}

struct Arguments {
    manifest_file: PathBuf,
    manifest_sha256: String,
    network: Network,
}

fn run() -> anyhow::Result<()> {
    match parse_arguments(std::env::args_os())? {
        Action::Help => {
            print_help();
            Ok(())
        }
        Action::Check(arguments) => check(arguments),
    }
}

fn check(arguments: Arguments) -> anyhow::Result<()> {
    let bundle = load_native_usdom_v4_node_bundle(
        &arguments.manifest_file,
        &arguments.manifest_sha256,
        arguments.network.magic(),
    )?;
    println!("status: valid");
    println!("network: {:?}", arguments.network);
    println!("network_magic: {:08x}", bundle.schedule.network_magic());
    println!("manifest_sha256: {}", arguments.manifest_sha256);
    println!("chain_id: {}", hash_hex(bundle.schedule.chain_id()));
    println!("first_v4_height: {}", bundle.schedule.first_v4_height());
    println!(
        "candidate_v2_first_height: {}",
        bundle
            .candidate_v2_first_height
            .map_or_else(|| "disabled".to_owned(), |height| height.to_string())
    );
    println!(
        "checkpoint_interval_blocks: {}",
        bundle
            .checkpoint_interval_blocks
            .map_or_else(|| "disabled".to_owned(), |value| value.to_string())
    );
    println!(
        "checkpoint_confirmation_depth_blocks: {}",
        bundle
            .checkpoint_confirmation_depth_blocks
            .map_or_else(|| "disabled".to_owned(), |value| value.to_string())
    );
    println!(
        "randomx_receipt_image_id: {}",
        bundle
            .randomx_receipt_image_id
            .map_or_else(|| "disabled".to_owned(), hex::encode)
    );
    println!(
        "empty_state_root: {}",
        hash_hex(bundle.schedule.empty_state_root())
    );
    println!(
        "activation_schedule_commitment: {}",
        hash_hex(bundle.schedule.commitment())
    );
    println!("dom_domain: {}", hex::encode(bundle.bridge.dom_domain));
    println!(
        "ethereum_genesis_validators_root: {}",
        hex::encode(bundle.bridge.ethereum_genesis_validators_root)
    );
    println!(
        "ethereum_trusted_checkpoint: {}",
        hex::encode(bundle.ethereum_trusted_checkpoint)
    );
    for (name, fork) in [
        ("genesis", &bundle.ethereum_forks.genesis),
        ("altair", &bundle.ethereum_forks.altair),
        ("bellatrix", &bundle.ethereum_forks.bellatrix),
        ("capella", &bundle.ethereum_forks.capella),
        ("deneb", &bundle.ethereum_forks.deneb),
        ("electra", &bundle.ethereum_forks.electra),
        ("fulu", &bundle.ethereum_forks.fulu),
        ("gloas", &bundle.ethereum_forks.gloas),
    ] {
        println!("ethereum_fork_{name}_epoch: {}", fork.epoch);
        println!(
            "ethereum_fork_{name}_version: {}",
            hex::encode(fork.fork_version)
        );
    }
    println!(
        "ethereum_chain_id_uint256: {}",
        hex::encode(bundle.bridge.ethereum_chain_id)
    );
    println!("reserve: {}", hex::encode(bundle.bridge.reserve));
    let checkpoint = bundle.checkpoint_policy.checkpoint();
    println!("checkpoint_registry: {}", hex::encode(checkpoint.registry));
    println!(
        "checkpoint_runtime_code_hash: {}",
        hex::encode(checkpoint.runtime_code_hash)
    );
    println!(
        "checkpoint_config_storage_slot: {}",
        hex::encode(checkpoint.config_storage_slot)
    );
    println!(
        "checkpoint_config_hash: {}",
        hex::encode(checkpoint.checkpoint_config_hash)
    );
    println!(
        "checkpoint_bridge_domain: {}",
        hex::encode(checkpoint.bridge_domain)
    );
    println!(
        "ethereum_checkpoint_policy_hash: {}",
        hex::encode(bundle.bridge.ethereum_checkpoint_policy_hash)
    );
    let deposit = bundle.deposit_policy.deposit();
    println!("deposit_reserve: {}", hex::encode(deposit.reserve));
    println!(
        "deposit_runtime_code_hash: {}",
        hex::encode(deposit.runtime_code_hash)
    );
    println!(
        "deposit_bridge_domain: {}",
        hex::encode(deposit.bridge_domain)
    );
    println!("deposit_max_amount: {}", deposit.max_amount);
    println!(
        "ethereum_deposit_policy_hash: {}",
        hex::encode(bundle.bridge.ethereum_deposit_policy_hash)
    );
    println!(
        "privacy_policy_hash: {}",
        hex::encode(bundle.bridge.privacy_policy_hash)
    );
    println!(
        "privacy_verifier_config_hash: {}",
        hex::encode(bundle.bridge.privacy_verifier_config_hash)
    );
    println!(
        "withdrawal_delay_secs: {}",
        bundle.bridge.burn_timing.withdrawal_delay_secs
    );
    println!(
        "min_execution_window_secs: {}",
        bundle.bridge.burn_timing.min_execution_window_secs
    );
    println!(
        "max_certificate_lifetime_secs: {}",
        bundle.bridge.burn_timing.max_certificate_lifetime_secs
    );
    println!(
        "relay_safety_margin_secs: {}",
        bundle.bridge.burn_timing.relay_safety_margin_secs
    );
    println!(
        "max_ethereum_anchor_age_secs: {}",
        bundle.bridge.burn_timing.max_ethereum_anchor_age_secs
    );
    println!(
        "max_dom_clock_lead_secs: {}",
        bundle.bridge.burn_timing.max_dom_clock_lead_secs
    );
    println!(
        "spend_verifying_key_sha256: {}",
        sha256_hex(&bundle.spend_verifying_key)
    );
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Action> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let remaining: Vec<OsString> = arguments.collect();
    if remaining.len() == 1 && matches!(remaining[0].to_str(), Some("-h" | "--help")) {
        return Ok(Action::Help);
    }
    let mut manifest_file = None;
    let mut manifest_sha256 = None;
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
            Some("--network") if network.is_none() => {
                network = Some(match value.to_str() {
                    Some("mainnet") => Network::Mainnet,
                    Some("testnet") => Network::Testnet,
                    Some("regtest") => Network::Regtest,
                    _ => anyhow::bail!("network must be mainnet, testnet, or regtest"),
                })
            }
            Some("--manifest-file" | "--manifest-sha256" | "--network") => {
                anyhow::bail!("duplicate argument {flag:?}")
            }
            _ => anyhow::bail!("unknown argument {flag:?}"),
        }
    }
    if !remainder.is_empty() {
        anyhow::bail!("every option requires exactly one value");
    }
    Ok(Action::Check(Arguments {
        manifest_file: manifest_file
            .ok_or_else(|| anyhow::anyhow!("--manifest-file is required"))?,
        manifest_sha256: manifest_sha256
            .ok_or_else(|| anyhow::anyhow!("--manifest-sha256 is required"))?,
        network: network.ok_or_else(|| anyhow::anyhow!("--network is required"))?,
    }))
}

fn print_help() {
    println!(
        "Validate one hash-pinned native USDOM runtime manifest without opening node state.\n\nUsage:\n  dom-usdom-manifest-check --manifest-file PATH --manifest-sha256 HEX --network <mainnet|testnet|regtest>"
    );
}

#[cfg(test)]
mod tests {
    use super::{parse_arguments, Action};
    use dom_config::Network;
    use std::{ffi::OsString, path::PathBuf};

    fn args(values: &[&str]) -> Vec<OsString> {
        std::iter::once("dom-usdom-manifest-check")
            .chain(values.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parser_accepts_only_complete_unique_nonsecret_arguments() {
        let action = parse_arguments(args(&[
            "--manifest-file",
            "/tmp/native.json",
            "--manifest-sha256",
            &"ab".repeat(32),
            "--network",
            "mainnet",
        ]))
        .unwrap();
        let Action::Check(arguments) = action else {
            panic!("expected check action")
        };
        assert_eq!(arguments.manifest_file, PathBuf::from("/tmp/native.json"));
        assert_eq!(arguments.network, Network::Mainnet);
        assert_eq!(arguments.manifest_sha256, "ab".repeat(32));
    }

    #[test]
    fn parser_rejects_partial_duplicate_unknown_and_invalid_network_arguments() {
        assert!(parse_arguments(args(&["--manifest-file", "/tmp/native.json"])).is_err());
        assert!(parse_arguments(args(&[
            "--manifest-file",
            "a",
            "--manifest-file",
            "b",
            "--manifest-sha256",
            &"ab".repeat(32),
            "--network",
            "mainnet",
        ]))
        .is_err());
        assert!(parse_arguments(args(&["--unknown", "value"])).is_err());
        assert!(parse_arguments(args(&["--network", "other"])).is_err());
        assert!(parse_arguments(args(&["--network"])).is_err());
    }

    #[test]
    fn help_is_the_only_valueless_action() {
        assert!(matches!(
            parse_arguments(args(&["--help"])).unwrap(),
            Action::Help
        ));
        assert!(parse_arguments(args(&["--help", "extra"])).is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("USDOM manifest validation failed");
        std::process::exit(1);
    }
}

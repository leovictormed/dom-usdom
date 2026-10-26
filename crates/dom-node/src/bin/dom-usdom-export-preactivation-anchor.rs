//! Offline export of the authenticated DOM predecessor used by USDOM activation.

use std::{
    ffi::OsString,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use dom_chain::{ChainState, IBD_SESSION_METADATA_KEY, LEGACY_IBD_SESSION_METADATA_KEY};
use dom_config::Network;
use dom_consensus::derive_chain_id;
use dom_store::DomStore;
use dom_usdom_checkpoint_program::{
    authenticated_checkpoint_bootstrap_anchor, SyncAttestation, SyncAttestationPolicy, SyncTip,
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
struct Arguments {
    data_dir: PathBuf,
    network: Network,
    max_span: u32,
    sync_policy: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SyncPolicyFile {
    schema: String,
    trusted_peer_ids: Vec<String>,
    threshold: String,
    minimum_stability_seconds: String,
    maximum_age_seconds: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    schema: &'static str,
    network: &'static str,
    network_magic: String,
    chain_id: String,
    activation_predecessor_height: String,
    activation_predecessor_block: String,
    activation_predecessor_context_hash: String,
    activation_predecessor_total_difficulty: String,
    checkpoint_max_span: String,
    sync_policy_hash: String,
    sync_observed_from: String,
    sync_observed_until: String,
    sync_peer_count: String,
}

fn run() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    if !arguments.data_dir.is_dir() {
        anyhow::bail!("DOM data directory does not exist or is not a directory");
    }
    let network_magic = arguments.network.magic();
    let genesis = dom_core::startup_genesis_hash_for_network_magic(network_magic)?;
    let store = DomStore::open(&arguments.data_dir)?;
    if store.get_metadata(IBD_SESSION_METADATA_KEY)?.is_some()
        || store
            .get_metadata(LEGACY_IBD_SESSION_METADATA_KEY)?
            .is_some()
    {
        anyhow::bail!(
            "DOM store has an incomplete or interrupted IBD session; synchronized export refused"
        );
    }
    let policy = load_sync_policy(&arguments.sync_policy)?;
    let attestation = SyncAttestation::load(&store)?.ok_or_else(|| {
        anyhow::anyhow!(
            "durable multi-peer sync attestation is missing; local tip alone does not prove synchronization"
        )
    })?;
    let chain = ChainState::open(store, genesis, network_magic)?;
    let anchor = authenticated_checkpoint_bootstrap_anchor(&chain, arguments.max_span)?;
    let chain_id = derive_chain_id(network_magic, &chain.genesis_hash);
    let expected_tip = SyncTip {
        network_magic,
        chain_id: *chain_id.as_bytes(),
        height: anchor.height,
        block: anchor.block,
        total_difficulty: anchor.total_difficulty,
    };
    if attestation.tip != expected_tip {
        anyhow::bail!("sync attestation does not bind the exported atomic DOM tip");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock precedes Unix epoch"))?
        .as_secs();
    attestation.verify(&policy, now)?;
    let sync_policy_hash = policy.commitment()?;
    let export = Export {
        schema: "usdom-dom-preactivation-anchor-v1",
        network: arguments.network.as_str(),
        network_magic: network_magic.to_string(),
        chain_id: prefixed(chain_id.as_bytes()),
        activation_predecessor_height: anchor.height.to_string(),
        activation_predecessor_block: prefixed(&anchor.block),
        activation_predecessor_context_hash: prefixed(&anchor.context_hash),
        activation_predecessor_total_difficulty: decimal_be(&anchor.total_difficulty),
        checkpoint_max_span: arguments.max_span.to_string(),
        sync_policy_hash: prefixed(&sync_policy_hash),
        sync_observed_from: attestation.observed_from.to_string(),
        sync_observed_until: attestation.observed_until.to_string(),
        sync_peer_count: attestation.observations.len().to_string(),
    };
    println!("{}", serde_json::to_string_pretty(&export)?);
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Arguments> {
    let mut values = arguments.into_iter();
    let _program = values.next();
    let remaining: Vec<OsString> = values.collect();
    let (pairs, remainder) = remaining.as_chunks::<2>();
    if !remainder.is_empty() {
        anyhow::bail!("arguments must be exact --flag value pairs");
    }
    let mut data_dir = None;
    let mut network = None;
    let mut max_span = None;
    let mut sync_policy = None;
    for pair in pairs {
        let value = pair[1]
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("argument value is not valid UTF-8"))?;
        match pair[0].to_str() {
            Some("--data-dir") if data_dir.is_none() => data_dir = Some(PathBuf::from(&pair[1])),
            Some("--network") if network.is_none() => network = Some(parse_network(value)?),
            Some("--max-span") if max_span.is_none() => {
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("--max-span must be a canonical positive u32"))?;
                if parsed == 0 || parsed > 720 || parsed.to_string() != value {
                    anyhow::bail!("--max-span must be a canonical decimal in 1..=720");
                }
                max_span = Some(parsed)
            }
            Some("--sync-policy") if sync_policy.is_none() => {
                sync_policy = Some(PathBuf::from(&pair[1]))
            }
            Some(flag) => anyhow::bail!("unknown or duplicate argument: {flag}"),
            None => anyhow::bail!("argument flag is not valid UTF-8"),
        }
    }
    Ok(Arguments {
        data_dir: data_dir.ok_or_else(|| anyhow::anyhow!("--data-dir is required"))?,
        network: network.ok_or_else(|| anyhow::anyhow!("--network is required"))?,
        max_span: max_span.ok_or_else(|| anyhow::anyhow!("--max-span is required"))?,
        sync_policy: sync_policy.ok_or_else(|| anyhow::anyhow!("--sync-policy is required"))?,
    })
}

fn load_sync_policy(path: &PathBuf) -> anyhow::Result<SyncAttestationPolicy> {
    let bytes = dom_wallet_crypto::read_captured_bytes(path, 16 * 1024)
        .map_err(|_| anyhow::anyhow!("cannot securely capture sync policy"))?;
    let document: SyncPolicyFile = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid sync policy JSON: {error}"))?;
    if document.schema != "usdom-dom-sync-attestation-policy-v1" {
        anyhow::bail!("unsupported sync policy schema");
    }
    let trusted_peer_ids = document
        .trusted_peer_ids
        .iter()
        .map(|value| parse_hash(value, "trustedPeerIds"))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let policy = SyncAttestationPolicy {
        trusted_peer_ids,
        threshold: canonical_decimal(&document.threshold, "threshold")?,
        minimum_stability_seconds: canonical_decimal(
            &document.minimum_stability_seconds,
            "minimumStabilitySeconds",
        )?,
        maximum_age_seconds: canonical_decimal(&document.maximum_age_seconds, "maximumAgeSeconds")?,
    };
    policy.commitment()?;
    Ok(policy)
}

fn canonical_decimal<T>(value: &str, label: &str) -> anyhow::Result<T>
where
    T: std::str::FromStr + ToString,
{
    let parsed = value
        .parse::<T>()
        .map_err(|_| anyhow::anyhow!("{label} must be a canonical decimal"))?;
    if parsed.to_string() != value {
        anyhow::bail!("{label} must be a canonical decimal");
    }
    Ok(parsed)
}

fn parse_hash(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let raw = value
        .strip_prefix("0x")
        .filter(|raw| {
            raw.len() == 64
                && raw
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| anyhow::anyhow!("{label} entries must be exact 0x-prefixed bytes32"))?;
    let bytes = hex::decode(raw)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} entry is not bytes32"))
}

fn parse_network(value: &str) -> anyhow::Result<Network> {
    match value {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        _ => anyhow::bail!("--network must be exactly mainnet, testnet, or regtest"),
    }
}

fn prefixed(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn decimal_be(bytes: &[u8; 32]) -> String {
    primitive_types::U256::from_big_endian(bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> anyhow::Result<Arguments> {
        parse_arguments(values.iter().map(OsString::from))
    }

    #[test]
    fn parser_rejects_missing_duplicate_and_noncanonical_arguments() {
        assert!(arguments(&["tool", "--network", "mainnet"]).is_err());
        assert!(arguments(&[
            "tool",
            "--data-dir",
            "/tmp/dom",
            "--network",
            "mainnet",
            "--network",
            "regtest",
            "--max-span",
            "390"
        ])
        .is_err());
        assert!(arguments(&[
            "tool",
            "--data-dir",
            "/tmp/dom",
            "--network",
            "mainnet",
            "--max-span",
            "0720"
        ])
        .is_err());
        assert!(arguments(&[
            "tool",
            "--data-dir",
            "/tmp/dom",
            "--network",
            "mainnet",
            "--max-span",
            "721"
        ])
        .is_err());
        assert!(arguments(&[
            "tool",
            "--data-dir",
            "/tmp/dom",
            "--network",
            "Mainnet",
            "--max-span",
            "390"
        ])
        .is_err());
        let parsed = arguments(&[
            "tool",
            "--data-dir",
            "/tmp/dom",
            "--network",
            "mainnet",
            "--max-span",
            "720",
            "--sync-policy",
            "/tmp/sync-policy.json",
        ])
        .expect("complete arguments");
        assert_eq!(parsed.sync_policy, PathBuf::from("/tmp/sync-policy.json"));
    }

    #[test]
    fn big_endian_difficulty_is_emitted_as_canonical_decimal() {
        let mut value = [0u8; 32];
        value[31] = 42;
        assert_eq!(decimal_be(&value), "42");
    }

    #[test]
    fn policy_scalars_and_identities_have_one_canonical_text_form() {
        assert_eq!(canonical_decimal::<u64>("42", "value").unwrap(), 42);
        assert!(canonical_decimal::<u64>("042", "value").is_err());
        assert_eq!(
            parse_hash(&format!("0x{}", "ab".repeat(32)), "peer").unwrap(),
            [0xab; 32]
        );
        assert!(parse_hash(&format!("0x{}", "AB".repeat(32)), "peer").is_err());
        assert!(parse_hash(&"ab".repeat(32), "peer").is_err());
    }

    #[test]
    fn policy_file_is_bounded_schema_strict_and_committed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let peers = (1u8..=4)
            .map(|byte| format!("\"0x{}\"", hex::encode([byte; 32])))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(
            &path,
            format!(
                "{{\"schema\":\"usdom-dom-sync-attestation-policy-v1\",\"trustedPeerIds\":[{peers}],\"threshold\":\"3\",\"minimumStabilitySeconds\":\"600\",\"maximumAgeSeconds\":\"300\"}}"
            ),
        )
        .unwrap();
        assert_ne!(
            load_sync_policy(&path).unwrap().commitment().unwrap(),
            [0; 32]
        );

        std::fs::write(
            &path,
            "{\"schema\":\"usdom-dom-sync-attestation-policy-v1\",\"trustedPeerIds\":[],\"threshold\":\"0\",\"minimumStabilitySeconds\":\"0\",\"maximumAgeSeconds\":\"0\",\"extra\":true}",
        )
        .unwrap();
        assert!(load_sync_policy(&path).is_err());
        std::fs::write(&path, vec![b' '; 16 * 1024 + 1]).unwrap();
        assert!(load_sync_policy(&path).is_err());
    }
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("preactivation anchor export failed");
        std::process::exit(1);
    }
}

//! Hash-pinned, versioned startup configuration for scheduled native USDOM.

use std::{
    fs::File,
    io::{Read, Take},
    path::{Component, Path, PathBuf},
};

use alloy::primitives::{Address, B256};
use dom_core::{DomError, Hash256, NETWORK_MAGIC_MAINNET};
use dom_usdom_privacy::verifier::SpendVerifier;
use dom_usdom_state::{BridgeIdentity, BurnTimingPolicy};
use rustix::fs::{open, Mode, OFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use usdom_ethereum_finality_experiment::{
    checkpoints::{
        checkpoint_witness_replay_slot, verify_checkpoint_witness, CheckpointPolicy,
        CheckpointTrustPolicy, StaticCheckpointTrustPolicy, VerifiedCheckpoint,
        MAX_CHECKPOINT_WITNESS_BYTES,
    },
    closures::{
        IssuanceClosurePolicy, IssuanceClosureTrustPolicy, StaticIssuanceClosureTrustPolicy,
    },
    deposits::{DepositTrustPolicy, ReserveDepositPolicy, StaticDepositTrustPolicy},
    EthereumFork, EthereumForks,
};

const LEGACY_SCHEMA_VERSION: u16 = 1;
const CANDIDATE_V2_SCHEMA_VERSION: u16 = 2;
const ISSUANCE_CLOSURE_SCHEMA_VERSION: u16 = 3;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
// Keep the startup read boundary aligned with SpendVerifier's canonical key
// limit. A Groth16 verifying key is small; the larger proving key never belongs
// in a validating node.
const MAX_SPEND_VERIFYING_KEY_BYTES: u64 = 4 * 1024;

/// Fully parsed immutable inputs required by the scheduled node constructor.
pub struct NativeUsdomV4NodeBundle {
    /// Exact bridge identity committed by the empty native state.
    pub bridge: BridgeIdentity,
    /// Immutable Ethereum checkpoint verification policy.
    pub checkpoint_policy: StaticCheckpointTrustPolicy,
    /// Immutable finalized reserve-deposit policy.
    pub deposit_policy: StaticDepositTrustPolicy,
    /// Immutable closure verifier. Absent only for historical schemas 1/2,
    /// which reject proof kind 5 at ingress.
    pub issuance_closure_policy: Option<StaticIssuanceClosureTrustPolicy>,
    /// Exact weak-subjectivity checkpoint selected by the manifest.
    pub ethereum_trusted_checkpoint: B256,
    /// Exact Ethereum fork schedule selected by the manifest.
    pub ethereum_forks: EthereumForks,
    /// Exact canonical Groth16 verifying key bytes.
    pub spend_verifying_key: Vec<u8>,
    /// Exact activation schedule selected by the manifest.
    pub schedule: dom_chain::NativeUsdomV4ActivationSchedule,
    /// First height interpreted under candidate state-v2, when the hash-pinned
    /// manifest explicitly ratifies the live migration phase.
    pub candidate_v2_first_height: Option<u64>,
    /// Canonical DOM distance between checkpoint targets under candidate V2.
    pub checkpoint_interval_blocks: Option<u32>,
    /// Canonical DOM work-confirmation suffix after each checkpoint target.
    pub checkpoint_confirmation_depth_blocks: Option<u32>,
    /// RandomX receipt ImageID committed by candidate-v2 checkpoint states.
    ///
    /// Legacy V1 manifests do not select a recursive checkpoint runtime.
    pub randomx_receipt_image_id: Option<[u8; 32]>,
    /// Independently retained and fully replay-verified restart floor. The
    /// manifest pins both its file name and SHA-256; raw decoded checkpoints
    /// never cross this startup boundary.
    pub restart_checkpoint: Option<VerifiedCheckpoint>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u16,
    network_magic: u32,
    activation_schedule_hex: String,
    candidate_v2: Option<CandidateV2Manifest>,
    spend_verifying_key_file: String,
    spend_verifying_key_sha256: String,
    ethereum: EthereumManifest,
    checkpoint: CheckpointManifest,
    deposit: DepositManifest,
    #[serde(default)]
    issuance_closure: Option<IssuanceClosureManifest>,
    bridge: BridgeManifest,
    #[serde(default)]
    restart_checkpoint: Option<RestartCheckpointManifest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartCheckpointManifest {
    witness_file: String,
    witness_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateV2Manifest {
    first_height: u64,
    checkpoint_interval_blocks: u32,
    checkpoint_confirmation_depth_blocks: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EthereumManifest {
    trusted_checkpoint: String,
    genesis_validators_root: String,
    forks: ForksManifest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForksManifest {
    genesis: ForkManifest,
    altair: ForkManifest,
    bellatrix: ForkManifest,
    capella: ForkManifest,
    deneb: ForkManifest,
    electra: ForkManifest,
    fulu: ForkManifest,
    gloas: ForkManifest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForkManifest {
    epoch: u64,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointManifest {
    ethereum_chain_id: u64,
    registry: String,
    runtime_code_hash: String,
    config_storage_slot: String,
    checkpoint_config_hash: String,
    bridge_domain: String,
    randomx_receipt_image_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DepositManifest {
    ethereum_chain_id: u64,
    reserve: String,
    runtime_code_hash: String,
    bridge_domain: String,
    max_amount: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuanceClosureManifest {
    ethereum_chain_id: u64,
    reserve: String,
    runtime_code_hash: String,
    reserve_config_hash: String,
    bridge_domain: String,
    deposits_closed_storage_slot: String,
    total_deposited_storage_slot: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeManifest {
    dom_domain: String,
    ethereum_chain_id_uint256: String,
    privacy_policy_hash: String,
    privacy_verifier_config_hash: String,
    reserve: String,
    burn_timing: BurnTimingManifest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BurnTimingManifest {
    withdrawal_delay_secs: u64,
    min_execution_window_secs: u64,
    max_certificate_lifetime_secs: u64,
    relay_safety_margin_secs: u64,
    max_ethereum_anchor_age_secs: u64,
    max_dom_clock_lead_secs: u64,
}

/// Load an exact manifest only when its complete bytes match the externally
/// ratified SHA-256 and its network equals the already selected DOM network.
pub fn load_native_usdom_v4_node_bundle(
    manifest_path: &Path,
    expected_manifest_sha256: &str,
    expected_network_magic: u32,
) -> Result<NativeUsdomV4NodeBundle, DomError> {
    let expected_manifest_hash =
        decode_hex_array::<32>(expected_manifest_sha256, "native USDOM manifest SHA-256")?;
    let manifest_bytes = read_regular_file(manifest_path, MAX_MANIFEST_BYTES, "manifest")?;
    let computed_manifest_hash: [u8; 32] = Sha256::digest(&manifest_bytes).into();
    if computed_manifest_hash != expected_manifest_hash {
        return Err(rejected("native USDOM manifest SHA-256 mismatch"));
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| rejected(format!("invalid native USDOM manifest JSON: {error}")))?;
    if !matches!(
        manifest.schema_version,
        LEGACY_SCHEMA_VERSION | CANDIDATE_V2_SCHEMA_VERSION | ISSUANCE_CLOSURE_SCHEMA_VERSION
    ) || manifest.network_magic != expected_network_magic
    {
        return Err(rejected(
            "native USDOM manifest schema or network does not match startup",
        ));
    }

    let schedule_bytes = decode_hex_vec(&manifest.activation_schedule_hex, "activation schedule")?;
    let schedule = dom_chain::NativeUsdomV4ActivationSchedule::from_bytes(&schedule_bytes)?;
    if schedule.network_magic() != expected_network_magic {
        return Err(rejected(
            "native USDOM activation schedule belongs to another network",
        ));
    }
    let (
        candidate_v2_first_height,
        checkpoint_interval_blocks,
        checkpoint_confirmation_depth_blocks,
    ) = match (manifest.schema_version, manifest.candidate_v2) {
        (LEGACY_SCHEMA_VERSION, None) => (None, None, None),
        (CANDIDATE_V2_SCHEMA_VERSION | ISSUANCE_CLOSURE_SCHEMA_VERSION, Some(candidate))
            if candidate.first_height > schedule.first_v4_height()
                && candidate.checkpoint_interval_blocks > 0
                && candidate.checkpoint_interval_blocks <= 360
                && candidate.checkpoint_confirmation_depth_blocks > 0
                && candidate.checkpoint_confirmation_depth_blocks
                    <= candidate.checkpoint_interval_blocks
                && candidate
                    .checkpoint_interval_blocks
                    .checked_add(candidate.checkpoint_confirmation_depth_blocks)
                    .is_some_and(|span| span <= 720)
                && candidate
                    .checkpoint_interval_blocks
                    .checked_mul(2)
                    .and_then(|span| {
                        span.checked_add(candidate.checkpoint_confirmation_depth_blocks)
                    })
                    .and_then(|span| span.checked_sub(1))
                    .is_some_and(|maximum_rewind| {
                        u64::from(maximum_rewind) <= dom_core::MAX_REORG_DEPTH_POLICY
                    }) =>
        {
            (
                Some(candidate.first_height),
                Some(candidate.checkpoint_interval_blocks),
                Some(candidate.checkpoint_confirmation_depth_blocks),
            )
        }
        _ => {
            return Err(rejected(
                "native USDOM manifest schema and candidate-v2 activation disagree",
            ))
        }
    };
    let randomx_receipt_image_id = match (
        manifest.schema_version,
        manifest.checkpoint.randomx_receipt_image_id.as_deref(),
    ) {
        (LEGACY_SCHEMA_VERSION, None) => None,
        (CANDIDATE_V2_SCHEMA_VERSION | ISSUANCE_CLOSURE_SCHEMA_VERSION, Some(value)) => {
            let image_id = decode_hex_array::<32>(value, "RandomX receipt ImageID")?;
            if image_id == [0; 32] {
                return Err(rejected("RandomX receipt ImageID must be nonzero"));
            }
            Some(image_id)
        }
        _ => {
            return Err(rejected(
                "native USDOM manifest schema and RandomX receipt ImageID disagree",
            ))
        }
    };

    let forks = decode_forks(manifest.ethereum.forks)?;
    let trusted_checkpoint = b256(&manifest.ethereum.trusted_checkpoint, "trusted checkpoint")?;
    let genesis_root = b256(
        &manifest.ethereum.genesis_validators_root,
        "Ethereum genesis validators root",
    )?;
    validate_ethereum_network_identity(expected_network_magic, genesis_root, &forks)?;
    let checkpoint_dynamic = CheckpointTrustPolicy {
        trusted_checkpoint,
        ethereum_genesis_validators_root: genesis_root,
        forks: forks.clone(),
        max_current_slot: 1,
        checkpoint: CheckpointPolicy {
            ethereum_chain_id: manifest.checkpoint.ethereum_chain_id,
            ethereum_genesis_validators_root: genesis_root,
            registry: address(&manifest.checkpoint.registry, "checkpoint registry")?,
            runtime_code_hash: b256(
                &manifest.checkpoint.runtime_code_hash,
                "checkpoint runtime code hash",
            )?,
            config_storage_slot: b256(
                &manifest.checkpoint.config_storage_slot,
                "checkpoint configuration storage slot",
            )?,
            checkpoint_config_hash: b256(
                &manifest.checkpoint.checkpoint_config_hash,
                "checkpoint configuration hash",
            )?,
            bridge_domain: b256(
                &manifest.checkpoint.bridge_domain,
                "checkpoint bridge domain",
            )?,
            dom_network_magic: expected_network_magic,
        },
    };
    let checkpoint_policy = StaticCheckpointTrustPolicy::from_trust_policy(&checkpoint_dynamic)
        .map_err(|error| rejected(format!("invalid checkpoint policy: {error}")))?;
    let deposit_dynamic = DepositTrustPolicy {
        trusted_checkpoint,
        ethereum_genesis_validators_root: genesis_root,
        forks: forks.clone(),
        max_current_slot: 1,
        deposit: ReserveDepositPolicy {
            ethereum_chain_id: manifest.deposit.ethereum_chain_id,
            ethereum_genesis_validators_root: genesis_root,
            reserve: address(&manifest.deposit.reserve, "deposit reserve")?,
            runtime_code_hash: b256(
                &manifest.deposit.runtime_code_hash,
                "reserve runtime code hash",
            )?,
            bridge_domain: b256(&manifest.deposit.bridge_domain, "deposit bridge domain")?,
            max_amount: manifest.deposit.max_amount,
        },
    };
    let deposit_policy = StaticDepositTrustPolicy::from_trust_policy(&deposit_dynamic)
        .map_err(|error| rejected(format!("invalid deposit policy: {error}")))?;
    let issuance_closure_policy = match (manifest.schema_version, manifest.issuance_closure) {
        (LEGACY_SCHEMA_VERSION | CANDIDATE_V2_SCHEMA_VERSION, None) => None,
        (ISSUANCE_CLOSURE_SCHEMA_VERSION, Some(closure)) => {
            let dynamic = IssuanceClosureTrustPolicy {
                trusted_checkpoint,
                ethereum_genesis_validators_root: genesis_root,
                forks: forks.clone(),
                max_current_slot: 1,
                closure: IssuanceClosurePolicy {
                    ethereum_chain_id: closure.ethereum_chain_id,
                    ethereum_genesis_validators_root: genesis_root,
                    reserve: address(&closure.reserve, "closure reserve")?,
                    runtime_code_hash: b256(
                        &closure.runtime_code_hash,
                        "closure runtime code hash",
                    )?,
                    reserve_config_hash: b256(
                        &closure.reserve_config_hash,
                        "closure reserve configuration hash",
                    )?,
                    activation_schedule_commitment: B256::from_slice(
                        schedule.commitment().as_bytes(),
                    ),
                    bridge_domain: b256(&closure.bridge_domain, "closure bridge domain")?,
                    deposits_closed_storage_slot: b256(
                        &closure.deposits_closed_storage_slot,
                        "closure deposits-closed storage slot",
                    )?,
                    total_deposited_storage_slot: b256(
                        &closure.total_deposited_storage_slot,
                        "closure total-deposited storage slot",
                    )?,
                },
            };
            Some(
                StaticIssuanceClosureTrustPolicy::from_trust_policy(&dynamic).map_err(|error| {
                    rejected(format!("invalid issuance closure policy: {error}"))
                })?,
            )
        }
        _ => {
            return Err(rejected(
                "native USDOM manifest schema and issuance closure policy disagree",
            ))
        }
    };

    let reserve = decode_hex_array::<20>(&manifest.bridge.reserve, "bridge reserve")?;
    let checkpoint_hash: [u8; 32] = checkpoint_policy.policy_hash().into();
    let deposit_hash: [u8; 32] = deposit_policy.policy_hash().into();
    let bridge = BridgeIdentity {
        dom_domain: decode_hex_array(&manifest.bridge.dom_domain, "DOM domain")?,
        ethereum_genesis_validators_root: genesis_root.into(),
        ethereum_chain_id: decode_hex_array(
            &manifest.bridge.ethereum_chain_id_uint256,
            "Ethereum chain ID uint256",
        )?,
        ethereum_checkpoint_policy_hash: checkpoint_hash,
        ethereum_deposit_policy_hash: deposit_hash,
        privacy_policy_hash: decode_hex_array(
            &manifest.bridge.privacy_policy_hash,
            "privacy policy hash",
        )?,
        privacy_verifier_config_hash: decode_hex_array(
            &manifest.bridge.privacy_verifier_config_hash,
            "privacy verifier configuration hash",
        )?,
        reserve,
        burn_timing: BurnTimingPolicy {
            withdrawal_delay_secs: manifest.bridge.burn_timing.withdrawal_delay_secs,
            min_execution_window_secs: manifest.bridge.burn_timing.min_execution_window_secs,
            max_certificate_lifetime_secs: manifest
                .bridge
                .burn_timing
                .max_certificate_lifetime_secs,
            relay_safety_margin_secs: manifest.bridge.burn_timing.relay_safety_margin_secs,
            max_ethereum_anchor_age_secs: manifest.bridge.burn_timing.max_ethereum_anchor_age_secs,
            max_dom_clock_lead_secs: manifest.bridge.burn_timing.max_dom_clock_lead_secs,
        },
    };
    let mut expected_ethereum_chain_id = [0u8; 32];
    expected_ethereum_chain_id[24..]
        .copy_from_slice(&manifest.checkpoint.ethereum_chain_id.to_be_bytes());
    if manifest.checkpoint.ethereum_chain_id != manifest.deposit.ethereum_chain_id
        || bridge.ethereum_chain_id != expected_ethereum_chain_id
        || manifest.checkpoint.bridge_domain != manifest.deposit.bridge_domain
        || bridge.dom_domain
            != decode_hex_array::<32>(&manifest.checkpoint.bridge_domain, "bridge domain")?
        || reserve != decode_hex_array::<20>(&manifest.deposit.reserve, "deposit reserve")?
    {
        return Err(rejected(
            "native USDOM manifest contains inconsistent bridge policies",
        ));
    }
    if issuance_closure_policy.as_ref().is_some_and(|policy| {
        policy.closure().ethereum_chain_id != manifest.deposit.ethereum_chain_id
            || policy.closure().reserve.as_slice() != bridge.reserve
            || policy.closure().bridge_domain.as_slice() != bridge.dom_domain
    }) {
        return Err(rejected(
            "native USDOM closure policy does not match the bridge policies",
        ));
    }
    let empty_state = dom_usdom_state::NativeUsdomState::new(bridge)
        .map_err(|error| rejected(format!("invalid native USDOM bridge identity: {error}")))?;
    if empty_state.state_root() != schedule.empty_state_root() {
        return Err(rejected(
            "activation schedule empty state does not match the manifest bridge",
        ));
    }

    let key_name = one_relative_filename(&manifest.spend_verifying_key_file)?;
    let key_path = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(key_name);
    let spend_verifying_key = read_regular_file(
        &key_path,
        MAX_SPEND_VERIFYING_KEY_BYTES,
        "spend verifying key",
    )?;
    let expected_key_hash = decode_hex_array::<32>(
        &manifest.spend_verifying_key_sha256,
        "spend verifying key SHA-256",
    )?;
    let computed_key_hash: [u8; 32] = Sha256::digest(&spend_verifying_key).into();
    if computed_key_hash != expected_key_hash {
        return Err(rejected("spend verifying key SHA-256 mismatch"));
    }
    let spend_verifier = SpendVerifier::from_bytes(&spend_verifying_key)
        .map_err(|error| rejected(format!("invalid spend verifying key: {error}")))?;
    if spend_verifier.config_hash().as_bytes() != &bridge.privacy_verifier_config_hash {
        return Err(rejected(
            "spend verifying key does not match the bridge commitment",
        ));
    }

    let restart_checkpoint = manifest
        .restart_checkpoint
        .map(|restart| {
            let witness_name = one_relative_filename(&restart.witness_file)?;
            let witness_path = manifest_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(witness_name);
            let witness = read_regular_file(
                &witness_path,
                MAX_CHECKPOINT_WITNESS_BYTES as u64,
                "restart checkpoint witness",
            )?;
            let expected_hash = decode_hex_array::<32>(
                &restart.witness_sha256,
                "restart checkpoint witness SHA-256",
            )?;
            let observed_hash: [u8; 32] = Sha256::digest(&witness).into();
            if observed_hash != expected_hash {
                return Err(rejected("restart checkpoint witness SHA-256 mismatch"));
            }
            let replay_slot = checkpoint_witness_replay_slot(&witness).map_err(|error| {
                rejected(format!(
                    "invalid restart checkpoint witness framing: {error}"
                ))
            })?;
            let policy = checkpoint_policy
                .at_max_current_slot(replay_slot)
                .map_err(|error| rejected(format!("invalid restart checkpoint policy: {error}")))?;
            verify_checkpoint_witness(&witness, &policy).map_err(|error| {
                rejected(format!(
                    "restart checkpoint witness verification failed: {error}"
                ))
            })
        })
        .transpose()?;

    Ok(NativeUsdomV4NodeBundle {
        bridge,
        checkpoint_policy,
        deposit_policy,
        issuance_closure_policy,
        ethereum_trusted_checkpoint: trusted_checkpoint,
        ethereum_forks: forks,
        spend_verifying_key,
        schedule,
        candidate_v2_first_height,
        checkpoint_interval_blocks,
        checkpoint_confirmation_depth_blocks,
        randomx_receipt_image_id,
        restart_checkpoint,
    })
}

fn supported_mainnet_forks() -> EthereumForks {
    let fork = |epoch, version: [u8; 4]| EthereumFork {
        epoch,
        fork_version: version.into(),
    };
    EthereumForks {
        genesis: fork(0, [0x00, 0x00, 0x00, 0x00]),
        altair: fork(74_240, [0x01, 0x00, 0x00, 0x00]),
        bellatrix: fork(144_896, [0x02, 0x00, 0x00, 0x00]),
        capella: fork(194_048, [0x03, 0x00, 0x00, 0x00]),
        deneb: fork(269_568, [0x04, 0x00, 0x00, 0x00]),
        electra: fork(364_032, [0x05, 0x00, 0x00, 0x00]),
        fulu: fork(411_392, [0x06, 0x00, 0x00, 0x00]),
        gloas: fork(u64::MAX, [0x07, 0x00, 0x00, 0x00]),
    }
}

fn same_fork(observed: &EthereumFork, expected: &EthereumFork) -> bool {
    observed.epoch == expected.epoch && observed.fork_version == expected.fork_version
}

fn validate_ethereum_network_identity(
    expected_network_magic: u32,
    genesis_root: B256,
    forks: &EthereumForks,
) -> Result<(), DomError> {
    if expected_network_magic != NETWORK_MAGIC_MAINNET {
        return Ok(());
    }
    let canonical_genesis = b256(
        "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
        "canonical Ethereum mainnet genesis validators root",
    )?;
    let expected = supported_mainnet_forks();
    if genesis_root != canonical_genesis
        || !same_fork(&forks.genesis, &expected.genesis)
        || !same_fork(&forks.altair, &expected.altair)
        || !same_fork(&forks.bellatrix, &expected.bellatrix)
        || !same_fork(&forks.capella, &expected.capella)
        || !same_fork(&forks.deneb, &expected.deneb)
        || !same_fork(&forks.electra, &expected.electra)
        || !same_fork(&forks.fulu, &expected.fulu)
        || !same_fork(&forks.gloas, &expected.gloas)
    {
        return Err(rejected(
            "native USDOM mainnet manifest has an unsupported Ethereum identity or fork schedule",
        ));
    }
    Ok(())
}

fn decode_forks(raw: ForksManifest) -> Result<EthereumForks, DomError> {
    Ok(EthereumForks {
        genesis: decode_fork(raw.genesis, "genesis")?,
        altair: decode_fork(raw.altair, "altair")?,
        bellatrix: decode_fork(raw.bellatrix, "bellatrix")?,
        capella: decode_fork(raw.capella, "capella")?,
        deneb: decode_fork(raw.deneb, "deneb")?,
        electra: decode_fork(raw.electra, "electra")?,
        fulu: decode_fork(raw.fulu, "fulu")?,
        gloas: decode_fork(raw.gloas, "gloas")?,
    })
}

fn decode_fork(raw: ForkManifest, name: &str) -> Result<EthereumFork, DomError> {
    Ok(EthereumFork {
        epoch: raw.epoch,
        fork_version: decode_hex_array::<4>(&raw.version, &format!("{name} fork version"))?.into(),
    })
}

fn b256(value: &str, label: &str) -> Result<B256, DomError> {
    Ok(B256::from(decode_hex_array::<32>(value, label)?))
}

fn address(value: &str, label: &str) -> Result<Address, DomError> {
    Ok(Address::from(decode_hex_array::<20>(value, label)?))
}

fn decode_hex_vec(value: &str, label: &str) -> Result<Vec<u8>, DomError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(rejected(format!("{label} must be canonical lowercase hex")));
    }
    hex::decode(value).map_err(|error| rejected(format!("invalid {label}: {error}")))
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], DomError> {
    if value.len() != N * 2 {
        return Err(rejected(format!("{label} has the wrong length")));
    }
    let bytes = decode_hex_vec(value, label)?;
    bytes
        .try_into()
        .map_err(|_| rejected(format!("{label} has the wrong length")))
}

fn one_relative_filename(value: &str) -> Result<PathBuf, DomError> {
    let path = Path::new(value);
    let mut components = path.components();
    let valid = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && !value.is_empty();
    if !valid {
        return Err(rejected(
            "spend verifying key path must be one relative filename",
        ));
    }
    Ok(path.to_path_buf())
}

fn read_regular_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, DomError> {
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| rejected(format!("cannot inspect {label}: {error}")))?;
    if !named.file_type().is_file() || named.file_type().is_symlink() || named.len() == 0 {
        return Err(rejected(format!("{label} is not a nonempty regular file")));
    }
    // Keep the no-symlink condition on the open operation itself.  A separate
    // `symlink_metadata` check is insufficient because an attacker able to
    // replace the leaf between inspection and `File::open` could redirect the
    // read.  The inode comparison below additionally rejects any replacement
    // by a different regular file during that interval.
    let file = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| rejected(format!("cannot open {label}: {error}")))?;
    let opened = file
        .metadata()
        .map_err(|error| rejected(format!("cannot inspect opened {label}: {error}")))?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > limit {
        return Err(rejected(format!("{label} exceeds its fixed size policy")));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if named.dev() != opened.dev() || named.ino() != opened.ino() || opened.nlink() != 1 {
            return Err(rejected(format!("{label} changed or has multiple links")));
        }
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    let mut bounded: Take<File> = file.take(limit + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| rejected(format!("cannot read {label}: {error}")))?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(rejected(format!("{label} exceeds its fixed size policy")));
    }
    Ok(bytes)
}

fn rejected(message: impl Into<String>) -> DomError {
    DomError::PolicyRejected(message.into())
}

/// SHA-256 of exact bytes, encoded as canonical lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Convert one canonical schedule to manifest hex.
pub fn activation_schedule_hex(schedule: dom_chain::NativeUsdomV4ActivationSchedule) -> String {
    hex::encode(schedule.to_bytes())
}

/// Convert a hash to canonical lowercase hex for manifest tooling.
pub fn hash_hex(hash: Hash256) -> String {
    hex::encode(hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use dom_consensus::derive_chain_id;
    use dom_core::NETWORK_MAGIC_REGTEST;
    use dom_usdom_privacy::circuit::SpendCircuit;
    use dom_usdom_state::NativeUsdomState;
    use rand::{rngs::StdRng, SeedableRng};
    use serde_json::{json, Value};
    use std::sync::OnceLock;

    fn fork(epoch: u64, version: &str) -> Value {
        json!({"epoch": epoch, "version": version})
    }

    fn test_verifying_key() -> &'static [u8] {
        static KEY: OnceLock<Vec<u8>> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = StdRng::from_seed([0x91; 32]);
            let parameters = Groth16::<Bn254>::generate_random_parameters_with_reduction(
                SpendCircuit::default(),
                &mut rng,
            )
            .unwrap();
            let mut bytes = Vec::new();
            parameters.vk.serialize_compressed(&mut bytes).unwrap();
            bytes
        })
    }

    fn fixture(directory: &Path) -> (Vec<u8>, String) {
        let checkpoint_dynamic = CheckpointTrustPolicy {
            trusted_checkpoint: B256::from([0x41; 32]),
            ethereum_genesis_validators_root: B256::from([0x22; 32]),
            forks: supported_mainnet_forks(),
            max_current_slot: 1,
            checkpoint: CheckpointPolicy {
                ethereum_chain_id: 1,
                ethereum_genesis_validators_root: B256::from([0x22; 32]),
                registry: Address::from([0x42; 20]),
                runtime_code_hash: B256::from([0x43; 32]),
                config_storage_slot: B256::from([0x44; 32]),
                checkpoint_config_hash: B256::from([0x45; 32]),
                bridge_domain: B256::from([0x11; 32]),
                dom_network_magic: NETWORK_MAGIC_REGTEST,
            },
        };
        let checkpoint =
            StaticCheckpointTrustPolicy::from_trust_policy(&checkpoint_dynamic).unwrap();
        let deposit_dynamic = DepositTrustPolicy {
            trusted_checkpoint: B256::from([0x41; 32]),
            ethereum_genesis_validators_root: B256::from([0x22; 32]),
            forks: supported_mainnet_forks(),
            max_current_slot: 1,
            deposit: ReserveDepositPolicy {
                ethereum_chain_id: 1,
                ethereum_genesis_validators_root: B256::from([0x22; 32]),
                reserve: Address::from([0x33; 20]),
                runtime_code_hash: B256::from([0x46; 32]),
                bridge_domain: B256::from([0x11; 32]),
                max_amount: 100_000_000_000,
            },
        };
        let deposit = StaticDepositTrustPolicy::from_trust_policy(&deposit_dynamic).unwrap();
        let mut ethereum_chain_id = [0u8; 32];
        ethereum_chain_id[31] = 1;
        let key = test_verifying_key().to_vec();
        let verifier = SpendVerifier::from_bytes(&key).unwrap();
        let bridge = BridgeIdentity {
            dom_domain: [0x11; 32],
            ethereum_genesis_validators_root: [0x22; 32],
            ethereum_chain_id,
            ethereum_checkpoint_policy_hash: checkpoint.policy_hash().into(),
            ethereum_deposit_policy_hash: deposit.policy_hash().into(),
            privacy_policy_hash: *dom_chain::native_usdom_v4::native_usdom_privacy_policy_hash()
                .as_bytes(),
            privacy_verifier_config_hash: *verifier.config_hash().as_bytes(),
            reserve: [0x33; 20],
            burn_timing: BurnTimingPolicy {
                withdrawal_delay_secs: 86_400,
                min_execution_window_secs: 3_600,
                max_certificate_lifetime_secs: 604_800,
                relay_safety_margin_secs: 3_600,
                max_ethereum_anchor_age_secs: 1_800,
                max_dom_clock_lead_secs: 7_200,
            },
        };
        let genesis =
            dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
        let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
        let schedule = dom_chain::NativeUsdomV4ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            chain_id,
            1,
            bridge,
        )
        .unwrap();
        assert_eq!(
            NativeUsdomState::new(bridge).unwrap().state_root(),
            schedule.empty_state_root()
        );
        std::fs::write(directory.join("spend.vk"), &key).unwrap();
        let forks = json!({
            "genesis": fork(0, "00000000"),
            "altair": fork(0, "00000000"),
            "bellatrix": fork(0, "00000000"),
            "capella": fork(0, "00000000"),
            "deneb": fork(0, "00000000"),
            "electra": fork(0, "00000000"),
            "fulu": fork(0, "00000000"),
            "gloas": fork(u64::MAX, "00000000")
        });
        let manifest = json!({
            "schema_version": 1,
            "network_magic": NETWORK_MAGIC_REGTEST,
            "activation_schedule_hex": activation_schedule_hex(schedule),
            "spend_verifying_key_file": "spend.vk",
            "spend_verifying_key_sha256": sha256_hex(&key),
            "ethereum": {
                "trusted_checkpoint": "41".repeat(32),
                "genesis_validators_root": "22".repeat(32),
                "forks": forks
            },
            "checkpoint": {
                "ethereum_chain_id": 1,
                "registry": "42".repeat(20),
                "runtime_code_hash": "43".repeat(32),
                "config_storage_slot": "44".repeat(32),
                "checkpoint_config_hash": "45".repeat(32),
                "bridge_domain": "11".repeat(32)
            },
            "deposit": {
                "ethereum_chain_id": 1,
                "reserve": "33".repeat(20),
                "runtime_code_hash": "46".repeat(32),
                "bridge_domain": "11".repeat(32),
                "max_amount": 100_000_000_000u64
            },
            "bridge": {
                "dom_domain": "11".repeat(32),
                "ethereum_chain_id_uint256": format!("{}01", "00".repeat(31)),
                "privacy_policy_hash": hex::encode(bridge.privacy_policy_hash),
                "privacy_verifier_config_hash": hex::encode(bridge.privacy_verifier_config_hash),
                "reserve": "33".repeat(20),
                "burn_timing": {
                    "withdrawal_delay_secs": 86_400,
                    "min_execution_window_secs": 3_600,
                    "max_certificate_lifetime_secs": 604_800,
                    "relay_safety_margin_secs": 3_600,
                    "max_ethereum_anchor_age_secs": 1_800,
                    "max_dom_clock_lead_secs": 7_200
                }
            }
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let digest = sha256_hex(&bytes);
        (bytes, digest)
    }

    #[test]
    fn manifest_is_hash_network_schedule_bridge_policy_and_key_bound() {
        let directory = tempfile::tempdir().unwrap();
        let (bytes, digest) = fixture(directory.path());
        let manifest = directory.path().join("native-usdom-v4.json");
        std::fs::write(&manifest, &bytes).unwrap();
        let loaded =
            load_native_usdom_v4_node_bundle(&manifest, &digest, NETWORK_MAGIC_REGTEST).unwrap();
        assert_eq!(loaded.schedule.first_v4_height(), 1);
        assert_eq!(loaded.spend_verifying_key, test_verifying_key());
        assert_eq!(loaded.candidate_v2_first_height, None);
        assert_eq!(loaded.checkpoint_interval_blocks, None);
        assert_eq!(loaded.checkpoint_confirmation_depth_blocks, None);
        assert_eq!(loaded.randomx_receipt_image_id, None);
        assert!(loaded.restart_checkpoint.is_none());

        let mut v2_manifest: Value = serde_json::from_slice(&bytes).unwrap();
        v2_manifest["schema_version"] = Value::from(2);
        v2_manifest["candidate_v2"] = json!({
            "first_height": 720u64,
            "checkpoint_interval_blocks": 360u32,
            "checkpoint_confirmation_depth_blocks": 30u32
        });
        v2_manifest["checkpoint"]["randomx_receipt_image_id"] = Value::String("17".repeat(32));
        let v2_bytes = serde_json::to_vec(&v2_manifest).unwrap();
        std::fs::write(&manifest, &v2_bytes).unwrap();
        let v2_loaded = load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&v2_bytes),
            NETWORK_MAGIC_REGTEST,
        )
        .unwrap();
        assert_eq!(v2_loaded.candidate_v2_first_height, Some(720));
        assert_eq!(v2_loaded.checkpoint_interval_blocks, Some(360));
        assert_eq!(v2_loaded.checkpoint_confirmation_depth_blocks, Some(30));
        assert_eq!(v2_loaded.randomx_receipt_image_id, Some([0x17; 32]));

        v2_manifest["candidate_v2"]["first_height"] = Value::from(1);
        let invalid_v2 = serde_json::to_vec(&v2_manifest).unwrap();
        std::fs::write(&manifest, &invalid_v2).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&invalid_v2),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());

        v2_manifest["candidate_v2"]["first_height"] = Value::from(720);
        v2_manifest["candidate_v2"]["checkpoint_confirmation_depth_blocks"] = Value::from(361);
        let invalid_checkpoint_span = serde_json::to_vec(&v2_manifest).unwrap();
        std::fs::write(&manifest, &invalid_checkpoint_span).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&invalid_checkpoint_span),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());

        v2_manifest["candidate_v2"]["checkpoint_confirmation_depth_blocks"] = Value::from(300);
        let invalid_rewind_bound = serde_json::to_vec(&v2_manifest).unwrap();
        std::fs::write(&manifest, &invalid_rewind_bound).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&invalid_rewind_bound),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());

        v2_manifest["candidate_v2"]["checkpoint_confirmation_depth_blocks"] = Value::from(30);
        v2_manifest["checkpoint"]["randomx_receipt_image_id"] = Value::String("00".repeat(32));
        let zero_image_id = serde_json::to_vec(&v2_manifest).unwrap();
        std::fs::write(&manifest, &zero_image_id).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&zero_image_id),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());

        v2_manifest["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("randomx_receipt_image_id");
        let missing_image_id = serde_json::to_vec(&v2_manifest).unwrap();
        std::fs::write(&manifest, &missing_image_id).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&missing_image_id),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());

        std::fs::write(&manifest, &bytes).unwrap();

        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &"00".repeat(32),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &digest,
            dom_core::NETWORK_MAGIC_MAINNET,
        )
        .is_err());

        let mut changed: Value = serde_json::from_slice(&bytes).unwrap();
        changed["deposit"]["reserve"] = Value::String("34".repeat(20));
        let changed_bytes = serde_json::to_vec(&changed).unwrap();
        std::fs::write(&manifest, &changed_bytes).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&changed_bytes),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());
    }

    #[test]
    fn restart_floor_accepts_only_manifest_pinned_replay_witnesses() {
        let directory = tempfile::tempdir().unwrap();
        let (bytes, _) = fixture(directory.path());
        let manifest_path = directory.path().join("native-usdom-v4.json");
        std::fs::write(
            directory.path().join("restart.witness"),
            b"opaque-checkpoint",
        )
        .unwrap();
        let mut manifest: Value = serde_json::from_slice(&bytes).unwrap();
        manifest["restart_checkpoint"] = json!({
            "witness_file": "restart.witness",
            "witness_sha256": sha256_hex(b"different")
        });
        let hash_mismatch = serde_json::to_vec(&manifest).unwrap();
        std::fs::write(&manifest_path, &hash_mismatch).unwrap();
        let error = load_native_usdom_v4_node_bundle(
            &manifest_path,
            &sha256_hex(&hash_mismatch),
            NETWORK_MAGIC_REGTEST,
        )
        .err()
        .expect("hash mismatch must fail");
        assert!(error.to_string().contains("witness SHA-256 mismatch"));

        manifest["restart_checkpoint"]["witness_sha256"] =
            Value::String(sha256_hex(b"opaque-checkpoint"));
        let opaque = serde_json::to_vec(&manifest).unwrap();
        std::fs::write(&manifest_path, &opaque).unwrap();
        let error = load_native_usdom_v4_node_bundle(
            &manifest_path,
            &sha256_hex(&opaque),
            NETWORK_MAGIC_REGTEST,
        )
        .err()
        .expect("opaque bytes must fail");
        assert!(error
            .to_string()
            .contains("invalid restart checkpoint witness framing"));

        manifest["restart_checkpoint"]["witness_file"] = Value::String("../escape".into());
        let traversal = serde_json::to_vec(&manifest).unwrap();
        std::fs::write(&manifest_path, &traversal).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest_path,
            &sha256_hex(&traversal),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());
    }

    #[test]
    fn manifest_rejects_noncanonical_hex_and_escaping_key_paths() {
        let directory = tempfile::tempdir().unwrap();
        let (bytes, _) = fixture(directory.path());
        let manifest = directory.path().join("native-usdom-v4.json");
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["bridge"]["dom_domain"] = Value::String("AA".repeat(32));
        let uppercase = serde_json::to_vec(&value).unwrap();
        std::fs::write(&manifest, &uppercase).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&uppercase),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());

        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["spend_verifying_key_file"] = Value::String("../spend.vk".into());
        let escaping = serde_json::to_vec(&value).unwrap();
        std::fs::write(&manifest, &escaping).unwrap();
        assert!(load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&escaping),
            NETWORK_MAGIC_REGTEST,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn startup_authority_rejects_symlinked_and_hardlinked_inputs() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let (bytes, digest) = fixture(directory.path());
        let manifest = directory.path().join("native-usdom-v4.json");
        let manifest_target = directory.path().join("manifest-target.json");
        std::fs::write(&manifest_target, &bytes).unwrap();
        symlink(&manifest_target, &manifest).unwrap();
        let error = load_native_usdom_v4_node_bundle(&manifest, &digest, NETWORK_MAGIC_REGTEST)
            .err()
            .expect("a symlinked manifest must fail closed");
        assert!(error.to_string().contains("manifest"));

        std::fs::remove_file(&manifest).unwrap();
        std::fs::write(&manifest, &bytes).unwrap();
        let key = directory.path().join("spend.vk");
        let key_target = directory.path().join("spend-target.vk");
        std::fs::rename(&key, &key_target).unwrap();
        symlink(&key_target, &key).unwrap();
        let error = load_native_usdom_v4_node_bundle(&manifest, &digest, NETWORK_MAGIC_REGTEST)
            .err()
            .expect("a symlinked verifying key must fail closed");
        assert!(error.to_string().contains("spend verifying key"));

        std::fs::remove_file(&key).unwrap();
        std::fs::hard_link(&key_target, &key).unwrap();
        let error = load_native_usdom_v4_node_bundle(&manifest, &digest, NETWORK_MAGIC_REGTEST)
            .err()
            .expect("a multiply-linked verifying key must fail closed");
        assert!(error.to_string().contains("multiple links"));
    }

    #[test]
    fn mainnet_identity_requires_the_exact_supported_ethereum_fork_schedule() {
        let genesis = b256(
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            "test genesis",
        )
        .unwrap();
        let forks = supported_mainnet_forks();
        validate_ethereum_network_identity(NETWORK_MAGIC_MAINNET, genesis, &forks).unwrap();

        let mut stale = supported_mainnet_forks();
        stale.fulu.epoch -= 1;
        assert!(
            validate_ethereum_network_identity(NETWORK_MAGIC_MAINNET, genesis, &stale).is_err()
        );

        let mut substituted = supported_mainnet_forks();
        substituted.electra.fork_version = [0x99, 0, 0, 0].into();
        assert!(
            validate_ethereum_network_identity(NETWORK_MAGIC_MAINNET, genesis, &substituted)
                .is_err()
        );
        assert!(validate_ethereum_network_identity(
            NETWORK_MAGIC_MAINNET,
            B256::from([0x22; 32]),
            &forks,
        )
        .is_err());
        validate_ethereum_network_identity(
            NETWORK_MAGIC_REGTEST,
            B256::ZERO,
            &EthereumForks::default(),
        )
        .unwrap();
    }

    #[test]
    fn manifest_rejects_hash_pinned_but_invalid_spend_key() {
        let directory = tempfile::tempdir().unwrap();
        let (bytes, _) = fixture(directory.path());
        let manifest = directory.path().join("native-usdom-v4.json");
        let invalid_key = b"hash-pinned but not a canonical Groth16 verifying key";
        std::fs::write(directory.path().join("spend.vk"), invalid_key).unwrap();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["spend_verifying_key_sha256"] = Value::String(sha256_hex(invalid_key));
        let changed = serde_json::to_vec(&value).unwrap();
        std::fs::write(&manifest, &changed).unwrap();
        let error = load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&changed),
            NETWORK_MAGIC_REGTEST,
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("invalid spend verifying key"));
    }

    #[test]
    fn manifest_rejects_valid_spend_key_with_different_bridge_commitment() {
        let directory = tempfile::tempdir().unwrap();
        let (bytes, digest) = fixture(directory.path());
        let manifest = directory.path().join("native-usdom-v4.json");
        std::fs::write(&manifest, &bytes).unwrap();
        let loaded =
            load_native_usdom_v4_node_bundle(&manifest, &digest, NETWORK_MAGIC_REGTEST).unwrap();

        let mut wrong_bridge = loaded.bridge;
        wrong_bridge.privacy_verifier_config_hash[0] ^= 1;
        let configured =
            dom_core::configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST).unwrap();
        let chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &configured);
        let wrong_schedule = dom_chain::NativeUsdomV4ActivationSchedule::new(
            NETWORK_MAGIC_REGTEST,
            chain_id,
            loaded.schedule.first_v4_height(),
            wrong_bridge,
        )
        .unwrap();
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["bridge"]["privacy_verifier_config_hash"] =
            Value::String(hex::encode(wrong_bridge.privacy_verifier_config_hash));
        value["activation_schedule_hex"] = Value::String(activation_schedule_hex(wrong_schedule));
        let changed = serde_json::to_vec(&value).unwrap();
        std::fs::write(&manifest, &changed).unwrap();
        let error = load_native_usdom_v4_node_bundle(
            &manifest,
            &sha256_hex(&changed),
            NETWORK_MAGIC_REGTEST,
        )
        .err()
        .unwrap();
        assert!(error
            .to_string()
            .contains("does not match the bridge commitment"));
    }
}

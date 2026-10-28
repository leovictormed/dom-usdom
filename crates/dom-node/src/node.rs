//! Full node orchestration.

#[cfg(feature = "native-usdom-v4-poc")]
use crate::future_block_queue::{
    DeferredNativeUsdomV4Package, FutureBlockAdmission, NativeUsdomV4FutureQueue,
};
use crate::metrics::Metrics;
use crate::miner::mining_loop;
use crate::missing_block_tracker::MissingBlockTracker;
#[cfg(feature = "native-usdom-v4-poc")]
use crate::orphan_pool::{
    NativeUsdomV4OrphanPackage, OrphanInsertOutcome, RuntimeNativeUsdomV4OrphanPool,
};
use crate::orphan_pool::{
    OrphanBlock, RuntimeOrphanPool, DEFAULT_MAX_ORPHANS_PER_PARENT, DEFAULT_MAX_ORPHAN_BLOCKS,
};
use crate::task_supervisor::{NodeTaskSupervisor, ShutdownToken, TaskKind};
use crate::time_health::{check_clock_health, DriftStatus};
use dom_chain::ChainState;
use dom_config::NodeConfig;
use dom_consensus::derive_chain_id;
use dom_consensus::Transaction;
use dom_core::DomError;
use dom_core::Hash256;
use dom_core::PeerMisbehavior;
use dom_core::Timestamp;
use dom_mempool::Mempool;
use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;
use dom_wallet::WalletDir;
use dom_wire::dandelion::DandelionRouter;
use dom_wire::manager::PeerManager;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};
use zeroize::Zeroizing;

/// One already-validated canonical native-USDOM package queued for peer fan-out.
/// `exclude_peer` prevents immediate echo on the connection that delivered it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeUsdomV4Relay {
    /// Exact tagged `UDOMV4W1` bytes accepted by the native runtime.
    pub wire_payload: Vec<u8>,
    /// Origin connection to skip, or `None` for local package injection.
    pub exclude_peer: Option<std::net::SocketAddr>,
}

/// One already-validated candidate-V2 package plus witness bundle queued for
/// peer fan-out. The command remains distinct from V1 on every connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeUsdomV2Relay {
    /// Exact tagged `UDOMV2W1` bytes accepted by the V2 runtime.
    pub wire_payload: Vec<u8>,
    /// Origin connection to skip, or `None` for local package injection.
    pub exclude_peer: Option<std::net::SocketAddr>,
}

#[cfg(feature = "native-usdom-v4-poc")]
pub(crate) enum NativeUsdomMiningTemplate {
    V1(dom_chain::NativeUsdomV4MiningTemplate),
    V2(dom_chain::NativeUsdomV2MiningTemplate),
}

#[cfg(feature = "native-usdom-v4-poc")]
impl NativeUsdomMiningTemplate {
    pub(crate) fn batch_header_commitment(&self) -> Hash256 {
        match self {
            Self::V1(template) => template.batch_header_commitment(),
            Self::V2(template) => template.batch_header_commitment(),
        }
    }
}

async fn receive_native_usdom_v4_relay(
    receiver: &mut Option<tokio::sync::broadcast::Receiver<NativeUsdomV4Relay>>,
) -> Result<NativeUsdomV4Relay, tokio::sync::broadcast::error::RecvError> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

async fn receive_native_usdom_v2_relay(
    receiver: &mut Option<tokio::sync::broadcast::Receiver<NativeUsdomV2Relay>>,
) -> Result<NativeUsdomV2Relay, tokio::sync::broadcast::error::RecvError> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// The full DOM node.
pub struct DomNode {
    /// Node configuration.
    pub config: NodeConfig,
    /// Chain state.
    pub chain: Arc<Mutex<ChainState>>,
    /// Transaction mempool.
    pub mempool: Arc<Mutex<Mempool>>,
    /// Peer manager.
    pub peers: Arc<Mutex<PeerManager>>,
    /// Dandelion++ router.
    pub dandelion: Arc<Mutex<DandelionRouter>>,
    /// Node's Noise static keypair private key.
    pub noise_privkey: Zeroizing<[u8; 32]>,
    /// Broadcast channel for relaying newly-mined or received blocks to all peers.
    /// Senders: miner after connect_block; message_loop after accepting a relayed Block.
    /// Receivers: one per connected peer task.
    pub block_relay_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Exact tagged wire payloads accepted by the isolated native USDOM v4
    /// runtime. Each live peer task consumes this channel only when its own
    /// authenticated session negotiated native-v4, and skips its origin peer.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_relay_tx: tokio::sync::broadcast::Sender<NativeUsdomV4Relay>,
    /// Exact candidate-V2 package/witness envelopes accepted by the V2
    /// runtime. Only bilateral V2 sessions consume this channel.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_relay_tx: tokio::sync::broadcast::Sender<NativeUsdomV2Relay>,
    /// Restored, audited native USDOM v4 runtime. `None` for every ordinary
    /// node constructor; it can only be installed by an explicit constructor
    /// that supplies the bridge policies and activation authority.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub(crate) native_usdom_v4_runtime: Option<Arc<Mutex<dom_chain::NativeUsdomV4Runtime>>>,
    /// Exact ratified schedule used by runtime, IBD and package ingress.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_schedule: Option<dom_chain::NativeUsdomV4ActivationSchedule>,
    /// Restored candidate-V2 runtime. It is mutually exclusive with the V1
    /// runtime and is installed only after an atomically persisted migration.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_runtime: Option<Arc<Mutex<dom_chain::NativeUsdomV2Runtime>>>,
    /// Global fail-fast admission gate shared by every peer/RPC/IBD native
    /// proof path. The consensus locks serialize commits already; admitting a
    /// queue of proof jobs only retains attacker-controlled payloads.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_proof_admission: Arc<NativeProofAdmission>,
    /// Exact persisted candidate-V2 migration selected at startup.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_schedule: Option<dom_chain::NativeUsdomV2ActivationSchedule>,
    /// Hash-pinned first candidate-V2 height while this process still owns V1.
    /// The preceding V1 package must commit the migration marker atomically.
    #[cfg(feature = "native-usdom-v4-poc")]
    candidate_v2_first_height: Option<u64>,
    /// Optional ratified multi-peer sync collector. Every v4-capable build can
    /// announce tips, but `None` ignores observations and therefore cannot
    /// create durable preactivation evidence.
    #[cfg(feature = "native-usdom-v4-poc")]
    sync_attestation_collector:
        Option<Arc<Mutex<dom_usdom_checkpoint_program::SyncAttestationCollector>>>,
    /// Broadcast channel for Dandelion++ Fluff-phase transactions.
    /// Every connected peer task forwards every Fluff envelope to its peer.
    /// Senders: submit_tx (local origination) and Command::Tx handler when
    /// process_stem_tx returns Fluff. Also the periodic stem-timeout task.
    pub tx_fluff_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Broadcast channel for Dandelion++ Stem-phase transactions.
    /// Every peer task receives the envelope but only the one whose peer_addr
    /// matches StemEnvelope.target_peer actually forwards to its peer.
    /// Senders: submit_tx and Command::Tx handler when route decides Stem.
    pub tx_stem_tx: tokio::sync::broadcast::Sender<dom_wire::dandelion::StemEnvelope>,
    /// Optional wallet for mining rewards, held as an opened [`WalletDir`] —
    /// the canonical on-disk format the CLI (`dom-wallet init`) and the
    /// desktop wallet create — so the directory's exclusive lock and WAL
    /// journal stay alive for the node's lifetime.
    /// If Some, miner uses wallet.build_coinbase() for deterministic blinding.
    /// If None, mining on public networks stays disabled (DOM-SEC-004
    /// fail-closed).
    pub wallet: Option<Arc<Mutex<WalletDir>>>,
    /// Node metrics for Prometheus export.
    pub metrics: Arc<Metrics>,
    /// Future block queue for soft buffer (Doc 4.5 mitigation 1).
    pub future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    /// Exact native-v4 packages held by the future-timestamp soft buffer.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_future_queue: Arc<NativeUsdomV4FutureQueue>,
    /// Runtime-only orphan/missing-parent tracker for deterministic re-requests.
    pub missing_blocks: Arc<Mutex<MissingBlockTracker>>,
    /// Bounded runtime orphan bytes retained for parent-arrival reprocessing.
    pub orphan_pool: Arc<Mutex<RuntimeOrphanPool>>,
    /// Exact native-v4 packages retained for missing-parent replay.
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_orphan_pool: Arc<Mutex<RuntimeNativeUsdomV4OrphanPool>>,
    /// Live runtime task supervisor and shutdown coordinator.
    pub task_supervisor: NodeTaskSupervisor,
    /// Test/runtime observers wait here for chain, mempool, or peer-state changes.
    pub state_events: Arc<Notify>,
    /// Number of peer synchronization sessions currently rebuilding the
    /// canonical chain. Mining remains paused until this reaches zero.
    pub(crate) ibd_active_sessions: Arc<AtomicU64>,
    /// Serializes the authenticated bounded regtest mining control. This is
    /// distinct from the continuous miner, which must be disabled for RPC
    /// mining so height-sensitive laboratory tests remain deterministic.
    pub(crate) bounded_rpc_mining_active: Arc<AtomicBool>,
    /// Peer Exchange state: known peer addresses learned from seeds and Addr
    /// gossip, plus GetAddr cooldown tracking (RFC-0005 §6).
    pub pex: Arc<Mutex<crate::pex::PexManager>>,
    /// Which Noise prologue version to lead with per peer (spec A1,
    /// Strategy B). Shared by the dial loop and the inbound acceptor so a
    /// version learned in one direction serves the other.
    pub(crate) prologue_prefs: Arc<crate::prologue_prefs::ProloguePreferences>,
    /// Admission control for reachability dial-backs (spec A4, R-A4.1).
    pub(crate) dialback: Arc<crate::dialback::DialbackLimiter>,
    /// Live externally-reachable port to announce in Hello (spec A1/A3).
    /// Starts from configuration and is updated by the port-mapping task; 0
    /// means "not reachable", which is what an expired or unusable mapping
    /// reverts to.
    pub(crate) live_advertised_port: Arc<AtomicU64>,
}

/// Per-connection I/O context passed into message_loop.
struct PeerConn<'a> {
    stream: &'a mut tokio::net::TcpStream,
    codec: &'a mut dom_wire::codec::NoiseCodec,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_negotiated: bool,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_negotiated: bool,
    #[cfg(feature = "native-usdom-v4-poc")]
    sync_tip_v1_negotiated: bool,
}

#[derive(Clone, Copy)]
struct HelloSession {
    advertised_port: u16,
    wire_version: u32,
    local_capabilities: u64,
}

/// Shared node services passed into per-connection tasks.
/// Groups mempool, dandelion router, peer manager, and wallet to stay under
/// clippy's function-argument limit (max 7).
#[derive(Clone)]
struct NodeServices {
    mempool: Arc<Mutex<dom_mempool::Mempool>>,
    dandelion: Arc<Mutex<dom_wire::dandelion::DandelionRouter>>,
    peers: Arc<Mutex<dom_wire::manager::PeerManager>>,
    metrics: Arc<Metrics>,
    future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_future_queue: Arc<NativeUsdomV4FutureQueue>,
    missing_blocks: Arc<Mutex<MissingBlockTracker>>,
    orphan_pool: Arc<Mutex<RuntimeOrphanPool>>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_orphan_pool: Arc<Mutex<RuntimeNativeUsdomV4OrphanPool>>,
    wallet: Option<Arc<Mutex<dom_wallet::WalletDir>>>,
    state_events: Arc<Notify>,
    ibd_active_sessions: Arc<AtomicU64>,
    pex: Arc<Mutex<crate::pex::PexManager>>,
    prologue_prefs: Arc<crate::prologue_prefs::ProloguePreferences>,
    dialback: Arc<crate::dialback::DialbackLimiter>,
    live_advertised_port: Arc<AtomicU64>,
    task_supervisor: NodeTaskSupervisor,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_enabled: bool,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_runtime: Option<Arc<Mutex<dom_chain::NativeUsdomV4Runtime>>>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_schedule: Option<dom_chain::NativeUsdomV4ActivationSchedule>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_enabled: bool,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_runtime: Option<Arc<Mutex<dom_chain::NativeUsdomV2Runtime>>>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_proof_admission: Arc<NativeProofAdmission>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_schedule: Option<dom_chain::NativeUsdomV2ActivationSchedule>,
    #[cfg(feature = "native-usdom-v4-poc")]
    candidate_v2_first_height: Option<u64>,
    #[cfg(feature = "native-usdom-v4-poc")]
    sync_attestation_collector:
        Option<Arc<Mutex<dom_usdom_checkpoint_program::SyncAttestationCollector>>>,
}

/// Broadcast channels shared across connection tasks.
///
/// Consolidates the three broadcast senders that were previously passed
/// individually to connect_outbound / handle_inbound / message_loop,
/// keeping each function under the clippy::too_many_arguments threshold.
#[derive(Clone)]
struct BroadcastChannels {
    block_relay_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v4_relay_tx: tokio::sync::broadcast::Sender<NativeUsdomV4Relay>,
    #[cfg(feature = "native-usdom-v4-poc")]
    native_usdom_v2_relay_tx: tokio::sync::broadcast::Sender<NativeUsdomV2Relay>,
    tx_fluff_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    tx_stem_tx: tokio::sync::broadcast::Sender<dom_wire::dandelion::StemEnvelope>,
}

/// All state participating in one native-USDOM package transition.
///
/// Keeping these handles together gives local injection and authenticated P2P
/// ingress the same parser, lock order and post-commit side effects. The
/// runtime itself performs the atomic chain/native-state store transaction.
#[cfg(feature = "native-usdom-v4-poc")]
#[derive(Clone)]
struct NativeUsdomV4Ingress {
    chain: Arc<Mutex<ChainState>>,
    mempool: Arc<Mutex<Mempool>>,
    runtime: Arc<Mutex<dom_chain::NativeUsdomV4Runtime>>,
    relay_tx: tokio::sync::broadcast::Sender<NativeUsdomV4Relay>,
    relay_exclude_peer: Option<std::net::SocketAddr>,
    wallet: Option<Arc<Mutex<WalletDir>>>,
    metrics: Arc<Metrics>,
    future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    native_future_queue: Arc<NativeUsdomV4FutureQueue>,
    state_events: Arc<Notify>,
    orphan_pool: Arc<Mutex<RuntimeNativeUsdomV4OrphanPool>>,
    candidate_v2_first_height: Option<u64>,
    migration_shutdown: Option<NodeTaskSupervisor>,
    proof_admission: Arc<NativeProofAdmission>,
}

#[cfg(feature = "native-usdom-v4-poc")]
struct NativeProofAdmission {
    capacity: Arc<tokio::sync::Semaphore>,
    inflight: std::sync::Mutex<std::collections::HashSet<[u8; 32]>>,
}

#[cfg(feature = "native-usdom-v4-poc")]
impl NativeProofAdmission {
    fn new() -> Self {
        Self {
            capacity: Arc::new(tokio::sync::Semaphore::new(1)),
            inflight: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
struct NativeProofPermit {
    _capacity: tokio::sync::OwnedSemaphorePermit,
    digest: [u8; 32],
    admission: Arc<NativeProofAdmission>,
}

#[cfg(feature = "native-usdom-v4-poc")]
impl Drop for NativeProofPermit {
    fn drop(&mut self) {
        if let Ok(mut inflight) = self.admission.inflight.lock() {
            inflight.remove(&self.digest);
        }
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn is_exact_canonical_block(
    chain: &ChainState,
    height: u64,
    block_hash: Hash256,
) -> Result<bool, DomError> {
    Ok(chain.store.get_hash_at_height(height)? == Some(*block_hash.as_bytes()))
}

#[cfg(feature = "native-usdom-v4-poc")]
fn try_acquire_native_proof_permit(
    admission: &Arc<NativeProofAdmission>,
    wire_payload: &[u8],
) -> Result<NativeProofPermit, DomError> {
    let digest = *dom_crypto::hash::blake2b_256(wire_payload).as_bytes();
    {
        let mut inflight = admission
            .inflight
            .lock()
            .map_err(|_| DomError::Internal("native proof admission lock poisoned".into()))?;
        if !inflight.insert(digest) {
            return Err(DomError::PolicyRejected(
                "duplicate native USDOM proof package is already in flight".into(),
            ));
        }
    }
    match admission.capacity.clone().try_acquire_owned() {
        Ok(capacity) => Ok(NativeProofPermit {
            _capacity: capacity,
            digest,
            admission: admission.clone(),
        }),
        Err(_) => {
            admission
                .inflight
                .lock()
                .map_err(|_| DomError::Internal("native proof admission lock poisoned".into()))?
                .remove(&digest);
            Err(DomError::PolicyRejected(
                "native USDOM proof admission is at global capacity".into(),
            ))
        }
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn is_native_proof_capacity_error(error: &DomError) -> bool {
    matches!(
        error,
        DomError::PolicyRejected(message)
            if message == "native USDOM proof admission is at global capacity"
                || message == "duplicate native USDOM proof package is already in flight"
    )
}

#[cfg(feature = "native-usdom-v4-poc")]
impl NativeUsdomV4Ingress {
    async fn ingest(
        &self,
        wire_payload: &[u8],
        now: Timestamp,
    ) -> Result<dom_chain::ConnectResult, DomError> {
        let proof_permit = Arc::new(try_acquire_native_proof_permit(
            &self.proof_admission,
            wire_payload,
        )?);
        let metadata = native_usdom_v4_package_metadata(wire_payload)?;
        use dom_consensus::block::{
            validate_future_timestamp_with_buffer_limits, TimestampDecision,
        };
        match validate_future_timestamp_with_buffer_limits(
            &metadata.header,
            now,
            dom_core::MAX_FUTURE_BLOCK_TIME,
            dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS,
        )? {
            TimestampDecision::Accept => {
                if self
                    .native_future_queue
                    .remove(&metadata.block_hash)
                    .await
                    .is_some()
                {
                    self.refresh_queue_metrics().await;
                }
            }
            TimestampDecision::Defer => {
                let admission = self
                    .native_future_queue
                    .admit(DeferredNativeUsdomV4Package {
                        block_hash: metadata.block_hash,
                        block_height: metadata.height,
                        timestamp: metadata.header.timestamp.0,
                        queued_at: std::time::Instant::now(),
                        wire_payload: wire_payload.to_vec(),
                        exclude_peer: self.relay_exclude_peer,
                    })
                    .await;
                record_native_future_admission(&self.metrics, admission);
                self.refresh_queue_metrics().await;
                tracing::debug!(
                    block_hash = %hex::encode(metadata.block_hash),
                    height = metadata.height,
                    ?admission,
                    "native USDOM v4 future-package admission decided"
                );
                return Err(DomError::TemporarilyInvalid(format!(
                    "native USDOM v4 package deferred by timestamp soft buffer: {admission:?}"
                )));
            }
        }
        let result = match Box::pin(self.ingest_once(
            wire_payload,
            now,
            self.relay_exclude_peer,
            proof_permit.clone(),
        ))
        .await
        {
            Ok(result) => result,
            Err(error @ DomError::Orphan(_)) => {
                self.queue_orphan(wire_payload, metadata, self.relay_exclude_peer)
                    .await;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        Box::pin(self.reprocess_orphan_descendants(metadata.block_hash, now, proof_permit)).await;
        Ok(result)
    }

    async fn ingest_once(
        &self,
        wire_payload: &[u8],
        now: Timestamp,
        relay_exclude_peer: Option<std::net::SocketAddr>,
        proof_permit: Arc<NativeProofPermit>,
    ) -> Result<dom_chain::ConnectResult, DomError> {
        use dom_wire::message::UsdomV4PackagePayload;
        let framed = UsdomV4PackagePayload::from_bytes(wire_payload)?;
        let package = dom_chain::UsdomV4BlockPackage::from_bytes(&framed.package_bytes)?;
        let connected_txs = package.block().transactions.clone();
        let connected_height = package.block().header.height.0;
        let connected_hash = block_hash(package.block())?;
        let activates_v2 = self
            .candidate_v2_first_height
            .is_some_and(|height| connected_height.checked_add(1) == Some(height));

        // Consensus lock ordering is globally fixed: chain before native
        // runtime. Parsing and wallet/mempool work happen outside both locks.
        let chain = self.chain.clone().lock_owned().await;
        let runtime = self.runtime.clone().lock_owned().await;
        let package_bytes = framed.package_bytes;
        let candidate_v2_first_height = self.candidate_v2_first_height;
        let result = tokio::task::spawn_blocking(move || {
            // Keep global admission occupied even if the async caller is
            // cancelled while Tokio cannot cancel this blocking job.
            let _proof_permit = proof_permit;
            // Expensive Ethereum/Groth16 verification belongs on Tokio's
            // blocking pool. The consensus lock order remains chain first.
            let mut chain = chain;
            let mut runtime = runtime;
            match candidate_v2_first_height {
                Some(first_v2_height)
                    if connected_height.checked_add(1) == Some(first_v2_height) =>
                {
                    runtime
                        .ingest_and_activate_v2(&mut chain, &package_bytes, now, first_v2_height)
                        .map(|(result, _)| result)
                }
                Some(first_v2_height) if connected_height >= first_v2_height => {
                    Err(DomError::PolicyRejected(
                        "native USDOM V1 package reached the candidate-V2 height".into(),
                    ))
                }
                _ => runtime.ingest(&mut chain, &package_bytes, now),
            }
        })
        .await
        .map_err(|error| DomError::Internal(format!("native V1 ingress task failed: {error}")))??;

        if matches!(
            result,
            dom_chain::ConnectResult::BestChain | dom_chain::ConnectResult::Reorg(_)
        ) {
            // The consensus/native-state transaction has committed at this
            // point. Auxiliary mempool persistence must never turn that
            // accepted transition into a peer-visible rejection or suppress
            // its relay; log and continue exactly as the ordinary block path.
            if let Err(e) =
                reconcile_mempool_after_connect(&self.chain, &self.mempool, &result, &connected_txs)
                    .await
            {
                warn!("mempool reconciliation failed after native-USDOM package: {e}");
            }
            apply_wallet_after_canonical_connect(
                self.wallet.as_ref(),
                &result,
                &connected_txs,
                connected_height,
                connected_hash,
            )
            .await;
            DomNode::refresh_runtime_metrics(
                &self.chain,
                &self.mempool,
                &self.future_block_queue,
                &self.metrics,
            )
            .await;
            let _ = self.relay_tx.send(NativeUsdomV4Relay {
                wire_payload: wire_payload.to_vec(),
                exclude_peer: relay_exclude_peer,
            });
            self.state_events.notify_waiters();
            if activates_v2 {
                if let Some(supervisor) = self.migration_shutdown.as_ref() {
                    tracing::info!(
                        first_v2_height = self.candidate_v2_first_height,
                        "native USDOM V2 boundary committed; requesting coordinated restart into V2 phase"
                    );
                    supervisor.request_shutdown().await;
                }
            }
        }
        Ok(result)
    }

    async fn queue_orphan(
        &self,
        wire_payload: &[u8],
        metadata: NativeUsdomV4PackageMetadata,
        exclude_peer: Option<std::net::SocketAddr>,
    ) {
        let (outcome, retained_packages, retained_bytes) = {
            let mut pool = self.orphan_pool.lock().await;
            let outcome = pool.insert(NativeUsdomV4OrphanPackage {
                block_hash: metadata.block_hash,
                parent_hash: metadata.parent_hash,
                height: metadata.height,
                wire_payload: wire_payload.to_vec(),
                exclude_peer,
            });
            (outcome, pool.len(), pool.total_bytes())
        };
        self.metrics.native_usdom_v4_orphan_packages.store(
            u64::try_from(retained_packages).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_orphan_bytes.store(
            u64::try_from(retained_bytes).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        record_native_orphan_admission(&self.metrics, outcome);
        tracing::debug!(
            child = %hex::encode(metadata.block_hash),
            parent = %hex::encode(metadata.parent_hash),
            height = metadata.height,
            ?outcome,
            "native USDOM v4 orphan package admission decided"
        );
    }

    async fn reprocess_orphan_descendants(
        &self,
        parent_hash: [u8; 32],
        now: Timestamp,
        proof_permit: Arc<NativeProofPermit>,
    ) {
        let mut ready_parents = vec![parent_hash];
        while let Some(available_parent) = ready_parents.pop() {
            let children = self
                .orphan_pool
                .lock()
                .await
                .take_children(&available_parent);
            if !children.is_empty() {
                self.refresh_queue_metrics().await;
            }
            for child in children {
                let metadata = match native_usdom_v4_package_metadata(&child.wire_payload) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        tracing::warn!(
                            child = %hex::encode(child.block_hash),
                            "dropping malformed native orphan package during replay: {error}"
                        );
                        continue;
                    }
                };
                if metadata.block_hash != child.block_hash
                    || metadata.parent_hash != child.parent_hash
                    || metadata.height != child.height
                {
                    tracing::warn!(
                        child = %hex::encode(child.block_hash),
                        "dropping native orphan whose exact payload no longer matches its index"
                    );
                    continue;
                }
                match Box::pin(self.ingest_once(
                    &child.wire_payload,
                    now,
                    child.exclude_peer,
                    proof_permit.clone(),
                ))
                .await
                {
                    Ok(_) => ready_parents.push(child.block_hash),
                    Err(DomError::Orphan(error)) => {
                        tracing::debug!(
                            child = %hex::encode(child.block_hash),
                            "native orphan still lacks a parent during replay: {error}"
                        );
                        self.queue_orphan(&child.wire_payload, metadata, child.exclude_peer)
                            .await;
                    }
                    Err(error) => {
                        tracing::debug!(
                            child = %hex::encode(child.block_hash),
                            "dropping rejected native orphan during replay: {error}"
                        );
                    }
                }
            }
        }
    }

    async fn refresh_queue_metrics(&self) {
        let future_packages = self.native_future_queue.size().await;
        let future_bytes = self.native_future_queue.retained_bytes().await;
        let (orphan_packages, orphan_bytes) = {
            let pool = self.orphan_pool.lock().await;
            (pool.len(), pool.total_bytes())
        };
        let ordering = std::sync::atomic::Ordering::Relaxed;
        self.metrics
            .native_usdom_v4_future_packages
            .store(u64::try_from(future_packages).unwrap_or(u64::MAX), ordering);
        self.metrics
            .native_usdom_v4_future_bytes
            .store(u64::try_from(future_bytes).unwrap_or(u64::MAX), ordering);
        self.metrics
            .native_usdom_v4_orphan_packages
            .store(u64::try_from(orphan_packages).unwrap_or(u64::MAX), ordering);
        self.metrics
            .native_usdom_v4_orphan_bytes
            .store(u64::try_from(orphan_bytes).unwrap_or(u64::MAX), ordering);
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
#[derive(Clone)]
struct NativeUsdomV2Ingress {
    chain: Arc<Mutex<ChainState>>,
    mempool: Arc<Mutex<Mempool>>,
    runtime: Arc<Mutex<dom_chain::NativeUsdomV2Runtime>>,
    relay_tx: tokio::sync::broadcast::Sender<NativeUsdomV2Relay>,
    relay_exclude_peer: Option<std::net::SocketAddr>,
    wallet: Option<Arc<Mutex<WalletDir>>>,
    metrics: Arc<Metrics>,
    future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    native_future_queue: Arc<NativeUsdomV4FutureQueue>,
    state_events: Arc<Notify>,
    orphan_pool: Arc<Mutex<RuntimeNativeUsdomV4OrphanPool>>,
    proof_admission: Arc<NativeProofAdmission>,
}

#[cfg(feature = "native-usdom-v4-poc")]
impl NativeUsdomV2Ingress {
    async fn ingest(
        &self,
        wire_payload: &[u8],
        now: Timestamp,
    ) -> Result<dom_chain::ConnectResult, DomError> {
        let proof_permit = Arc::new(try_acquire_native_proof_permit(
            &self.proof_admission,
            wire_payload,
        )?);
        let metadata = native_usdom_v2_package_metadata(wire_payload)?;
        use dom_consensus::block::{
            validate_future_timestamp_with_buffer_limits, TimestampDecision,
        };
        match validate_future_timestamp_with_buffer_limits(
            &metadata.header,
            now,
            dom_core::MAX_FUTURE_BLOCK_TIME,
            dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS,
        )? {
            TimestampDecision::Accept => {
                if self
                    .native_future_queue
                    .remove(&metadata.block_hash)
                    .await
                    .is_some()
                {
                    self.refresh_queue_metrics().await;
                }
            }
            TimestampDecision::Defer => {
                let admission = self
                    .native_future_queue
                    .admit(DeferredNativeUsdomV4Package {
                        block_hash: metadata.block_hash,
                        block_height: metadata.height,
                        timestamp: metadata.header.timestamp.0,
                        queued_at: std::time::Instant::now(),
                        wire_payload: wire_payload.to_vec(),
                        exclude_peer: self.relay_exclude_peer,
                    })
                    .await;
                record_native_future_admission(&self.metrics, admission);
                self.refresh_queue_metrics().await;
                return Err(DomError::TemporarilyInvalid(format!(
                    "native USDOM V2 package deferred by timestamp soft buffer: {admission:?}"
                )));
            }
        }
        let result = match Box::pin(self.ingest_once(
            wire_payload,
            now,
            self.relay_exclude_peer,
            proof_permit.clone(),
        ))
        .await
        {
            Ok(result) => result,
            Err(error @ DomError::Orphan(_)) => {
                self.queue_orphan(wire_payload, metadata, self.relay_exclude_peer)
                    .await;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        Box::pin(self.reprocess_orphan_descendants(metadata.block_hash, now, proof_permit)).await;
        Ok(result)
    }

    async fn ingest_once(
        &self,
        wire_payload: &[u8],
        now: Timestamp,
        relay_exclude_peer: Option<std::net::SocketAddr>,
        proof_permit: Arc<NativeProofPermit>,
    ) -> Result<dom_chain::ConnectResult, DomError> {
        let framed = dom_wire::message::UsdomV2PackagePayload::from_bytes(wire_payload)?;
        let package = dom_chain::UsdomV4BlockPackage::from_bytes(&framed.package_bytes)?;
        let witnesses = dom_chain::UsdomV2ExecutionWitnesses::from_bytes(&framed.witness_bytes)?;
        let connected_txs = package.block().transactions.clone();
        let connected_height = package.block().header.height.0;
        let connected_hash = block_hash(package.block())?;
        let chain = self.chain.clone().lock_owned().await;
        let runtime = self.runtime.clone().lock_owned().await;
        let package_bytes = framed.package_bytes;
        let result = tokio::task::spawn_blocking(move || {
            // `spawn_blocking` is not cancellable once running. Owning a
            // permit clone here prevents early readmission on caller abort.
            let _proof_permit = proof_permit;
            // Package proofs and stateless witnesses can be CPU-intensive;
            // keep them away from peer/RPC executor threads.
            let mut chain = chain;
            let mut runtime = runtime;
            runtime.ingest(&mut chain, &package_bytes, &witnesses, now)
        })
        .await
        .map_err(|error| DomError::Internal(format!("native V2 ingress task failed: {error}")))??;
        if matches!(
            result,
            dom_chain::ConnectResult::BestChain | dom_chain::ConnectResult::Reorg(_)
        ) {
            if let Err(error) =
                reconcile_mempool_after_connect(&self.chain, &self.mempool, &result, &connected_txs)
                    .await
            {
                warn!("mempool reconciliation failed after native-USDOM V2 package: {error}");
            }
            apply_wallet_after_canonical_connect(
                self.wallet.as_ref(),
                &result,
                &connected_txs,
                connected_height,
                connected_hash,
            )
            .await;
            DomNode::refresh_runtime_metrics(
                &self.chain,
                &self.mempool,
                &self.future_block_queue,
                &self.metrics,
            )
            .await;
            let _ = self.relay_tx.send(NativeUsdomV2Relay {
                wire_payload: wire_payload.to_vec(),
                exclude_peer: relay_exclude_peer,
            });
            self.state_events.notify_waiters();
        }
        Ok(result)
    }

    async fn queue_orphan(
        &self,
        wire_payload: &[u8],
        metadata: NativeUsdomV4PackageMetadata,
        exclude_peer: Option<std::net::SocketAddr>,
    ) {
        let (outcome, retained_packages, retained_bytes) = {
            let mut pool = self.orphan_pool.lock().await;
            let outcome = pool.insert(NativeUsdomV4OrphanPackage {
                block_hash: metadata.block_hash,
                parent_hash: metadata.parent_hash,
                height: metadata.height,
                wire_payload: wire_payload.to_vec(),
                exclude_peer,
            });
            (outcome, pool.len(), pool.total_bytes())
        };
        self.metrics.native_usdom_v4_orphan_packages.store(
            u64::try_from(retained_packages).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_orphan_bytes.store(
            u64::try_from(retained_bytes).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        record_native_orphan_admission(&self.metrics, outcome);
    }

    async fn reprocess_orphan_descendants(
        &self,
        parent_hash: [u8; 32],
        now: Timestamp,
        proof_permit: Arc<NativeProofPermit>,
    ) {
        let mut ready_parents = vec![parent_hash];
        while let Some(available_parent) = ready_parents.pop() {
            let children = self
                .orphan_pool
                .lock()
                .await
                .take_children(&available_parent);
            if !children.is_empty() {
                self.refresh_queue_metrics().await;
            }
            for child in children {
                let metadata = match native_usdom_v2_package_metadata(&child.wire_payload) {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        tracing::warn!(
                            child = %hex::encode(child.block_hash),
                            "dropping malformed native V2 orphan during replay: {error}"
                        );
                        continue;
                    }
                };
                if metadata.block_hash != child.block_hash
                    || metadata.parent_hash != child.parent_hash
                    || metadata.height != child.height
                {
                    tracing::warn!(
                        child = %hex::encode(child.block_hash),
                        "dropping native V2 orphan whose payload no longer matches its index"
                    );
                    continue;
                }
                match Box::pin(self.ingest_once(
                    &child.wire_payload,
                    now,
                    child.exclude_peer,
                    proof_permit.clone(),
                ))
                .await
                {
                    Ok(_) => ready_parents.push(child.block_hash),
                    Err(DomError::Orphan(_)) => {
                        self.queue_orphan(&child.wire_payload, metadata, child.exclude_peer)
                            .await;
                    }
                    Err(error) => tracing::debug!(
                        child = %hex::encode(child.block_hash),
                        "dropping rejected native V2 orphan during replay: {error}"
                    ),
                }
            }
        }
    }

    async fn refresh_queue_metrics(&self) {
        let future_packages = self.native_future_queue.size().await;
        let future_bytes = self.native_future_queue.retained_bytes().await;
        let (orphan_packages, orphan_bytes) = {
            let pool = self.orphan_pool.lock().await;
            (pool.len(), pool.total_bytes())
        };
        let ordering = std::sync::atomic::Ordering::Relaxed;
        self.metrics
            .native_usdom_v4_future_packages
            .store(u64::try_from(future_packages).unwrap_or(u64::MAX), ordering);
        self.metrics
            .native_usdom_v4_future_bytes
            .store(u64::try_from(future_bytes).unwrap_or(u64::MAX), ordering);
        self.metrics
            .native_usdom_v4_orphan_packages
            .store(u64::try_from(orphan_packages).unwrap_or(u64::MAX), ordering);
        self.metrics
            .native_usdom_v4_orphan_bytes
            .store(u64::try_from(orphan_bytes).unwrap_or(u64::MAX), ordering);
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn record_native_future_admission(metrics: &Metrics, admission: FutureBlockAdmission) {
    match admission {
        FutureBlockAdmission::QueuedAfterEviction => {
            metrics
                .native_usdom_v4_future_evictions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        FutureBlockAdmission::RejectedOversized
        | FutureBlockAdmission::RejectedCapacity
        | FutureBlockAdmission::RejectedArithmetic => {
            metrics
                .native_usdom_v4_future_admission_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        FutureBlockAdmission::Queued | FutureBlockAdmission::Replaced => {}
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn record_native_orphan_admission(metrics: &Metrics, outcome: OrphanInsertOutcome) {
    match outcome {
        OrphanInsertOutcome::EvictedOldest => {
            metrics
                .native_usdom_v4_orphan_evictions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        OrphanInsertOutcome::RejectedParentLimit | OrphanInsertOutcome::RejectedTooLarge => {
            metrics
                .native_usdom_v4_orphan_admission_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        OrphanInsertOutcome::Inserted | OrphanInsertOutcome::Duplicate => {}
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn record_native_future_expiration(metrics: &Metrics, evicted: usize) {
    if evicted > 0 {
        metrics.native_usdom_v4_future_expired.fetch_add(
            u64::try_from(evicted).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
#[derive(Clone)]
struct NativeUsdomV4PackageMetadata {
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    height: u64,
    header: dom_consensus::BlockHeader,
}

#[cfg(feature = "native-usdom-v4-poc")]
fn native_usdom_v4_package_metadata(
    wire_payload: &[u8],
) -> Result<NativeUsdomV4PackageMetadata, DomError> {
    use dom_wire::message::UsdomV4PackagePayload;

    let framed = UsdomV4PackagePayload::from_bytes(wire_payload)?;
    let package = dom_chain::UsdomV4BlockPackage::from_bytes(&framed.package_bytes)?;
    Ok(NativeUsdomV4PackageMetadata {
        block_hash: block_hash(package.block())?,
        parent_hash: *package.block().header.prev_hash.as_bytes(),
        height: package.block().header.height.0,
        header: package.block().header.clone(),
    })
}

#[cfg(feature = "native-usdom-v4-poc")]
fn native_usdom_v2_package_metadata(
    wire_payload: &[u8],
) -> Result<NativeUsdomV4PackageMetadata, DomError> {
    let framed = dom_wire::message::UsdomV2PackagePayload::from_bytes(wire_payload)?;
    // Parse the witness bundle here as part of metadata admission so malformed
    // witness bytes never consume future/orphan retention capacity.
    dom_chain::UsdomV2ExecutionWitnesses::from_bytes(&framed.witness_bytes)?;
    let package = dom_chain::UsdomV4BlockPackage::from_bytes(&framed.package_bytes)?;
    Ok(NativeUsdomV4PackageMetadata {
        block_hash: block_hash(package.block())?,
        parent_hash: *package.block().header.prev_hash.as_bytes(),
        height: package.block().header.height.0,
        header: package.block().header.clone(),
    })
}

#[cfg(feature = "native-usdom-v4-poc")]
async fn drain_native_usdom_v4_future_packages(
    queue: &Arc<NativeUsdomV4FutureQueue>,
    ingress_template: Option<&NativeUsdomV4Ingress>,
    now_secs: u64,
    now: Timestamp,
) {
    let evicted = queue.evict_expired(FUTURE_BLOCK_QUEUE_MAX_AGE_SECS).await;
    let ready = queue
        .drain_ready(now_secs, dom_core::MAX_FUTURE_BLOCK_TIME)
        .await;
    if let Some(template) = ingress_template {
        record_native_future_expiration(&template.metrics, evicted);
        if evicted > 0 || !ready.is_empty() {
            template.refresh_queue_metrics().await;
        }
        for deferred in ready {
            let mut ingress = template.clone();
            ingress.relay_exclude_peer = deferred.exclude_peer;
            match Box::pin(ingress.ingest(&deferred.wire_payload, now)).await {
                Ok(_) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "accepted deferred native USDOM v4 package"
                ),
                Err(DomError::TemporarilyInvalid(error)) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "native USDOM v4 package remains deferred: {error}"
                ),
                Err(DomError::Orphan(error)) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "deferred native USDOM v4 package moved to orphan retention: {error}"
                ),
                Err(error) if is_native_proof_capacity_error(&error) => {
                    let admission = queue.admit(deferred).await;
                    record_native_future_admission(&template.metrics, admission);
                    template.refresh_queue_metrics().await;
                    tracing::debug!(
                        ?admission,
                        "native USDOM v4 future package retained while proof gate is busy"
                    );
                }
                Err(error) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "dropping rejected deferred native USDOM v4 package: {error}"
                ),
            }
        }
    }
    if evicted > 0 {
        tracing::debug!("evicted {evicted} expired native USDOM v4 future package(s)");
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
async fn drain_native_usdom_v2_future_packages(
    queue: &Arc<NativeUsdomV4FutureQueue>,
    ingress_template: Option<&NativeUsdomV2Ingress>,
    now_secs: u64,
    now: Timestamp,
) {
    let evicted = queue.evict_expired(FUTURE_BLOCK_QUEUE_MAX_AGE_SECS).await;
    let ready = queue
        .drain_ready(now_secs, dom_core::MAX_FUTURE_BLOCK_TIME)
        .await;
    if let Some(template) = ingress_template {
        record_native_future_expiration(&template.metrics, evicted);
        if evicted > 0 || !ready.is_empty() {
            template.refresh_queue_metrics().await;
        }
        for deferred in ready {
            let mut ingress = template.clone();
            ingress.relay_exclude_peer = deferred.exclude_peer;
            match Box::pin(ingress.ingest(&deferred.wire_payload, now)).await {
                Ok(_) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "accepted deferred native USDOM V2 package"
                ),
                Err(DomError::TemporarilyInvalid(error)) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "native USDOM V2 package remains deferred: {error}"
                ),
                Err(DomError::Orphan(error)) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "deferred native USDOM V2 package moved to orphan retention: {error}"
                ),
                Err(error) if is_native_proof_capacity_error(&error) => {
                    let admission = queue.admit(deferred).await;
                    record_native_future_admission(&template.metrics, admission);
                    template.refresh_queue_metrics().await;
                    tracing::debug!(
                        ?admission,
                        "native USDOM V2 future package retained while proof gate is busy"
                    );
                }
                Err(error) => tracing::debug!(
                    block_hash = %hex::encode(deferred.block_hash),
                    "dropping rejected deferred native USDOM V2 package: {error}"
                ),
            }
        }
    }
    if evicted > 0 {
        tracing::debug!("evicted {evicted} expired native USDOM V2 future package(s)");
    }
}

fn future_block_ready_window(network: dom_config::Network) -> u64 {
    if network == dom_config::Network::Testnet {
        dom_core::TESTNET_MAX_FUTURE_BLOCK_TIME
    } else {
        dom_core::MAX_FUTURE_BLOCK_TIME
    }
}

struct IbdActiveGuard {
    sessions: Arc<AtomicU64>,
    state_events: Arc<Notify>,
}

#[derive(Clone, Copy)]
enum IbdHeaderValidationMode {
    Ordinary,
    #[cfg(feature = "native-usdom-v4-poc")]
    NativeUsdomV4(dom_chain::NativeUsdomV4ActivationSchedule),
    #[cfg(feature = "native-usdom-v4-poc")]
    NativeUsdomV2(dom_chain::NativeUsdomV2ActivationSchedule),
}

fn ibd_header_validation_mode(
    native_usdom_v4_negotiated: bool,
    native_usdom_v2_negotiated: bool,
    svc: &NodeServices,
) -> Result<IbdHeaderValidationMode, DomError> {
    if native_usdom_v4_negotiated && native_usdom_v2_negotiated {
        return Err(DomError::PolicyRejected(
            "IBD session negotiated mutually exclusive native USDOM phases".into(),
        ));
    }
    if native_usdom_v2_negotiated {
        #[cfg(feature = "native-usdom-v4-poc")]
        {
            return svc
                .native_usdom_v2_schedule
                .map(IbdHeaderValidationMode::NativeUsdomV2)
                .ok_or_else(|| {
                    DomError::Internal(
                        "native USDOM V2 IBD negotiated without an installed schedule".into(),
                    )
                });
        }
        #[cfg(not(feature = "native-usdom-v4-poc"))]
        {
            return Err(DomError::PolicyRejected(
                "native USDOM V2 IBD is not compiled".into(),
            ));
        }
    }
    if !native_usdom_v4_negotiated {
        return Ok(IbdHeaderValidationMode::Ordinary);
    }
    #[cfg(feature = "native-usdom-v4-poc")]
    {
        svc.native_usdom_v4_schedule
            .map(IbdHeaderValidationMode::NativeUsdomV4)
            .ok_or_else(|| {
                DomError::Internal(
                    "native USDOM IBD negotiated without an installed activation schedule".into(),
                )
            })
    }
    #[cfg(not(feature = "native-usdom-v4-poc"))]
    {
        let _ = svc;
        Err(DomError::PolicyRejected(
            "native USDOM v4 IBD is not compiled".into(),
        ))
    }
}

impl IbdActiveGuard {
    fn try_new(sessions: Arc<AtomicU64>, state_events: Arc<Notify>) -> Option<Self> {
        sessions
            .compare_exchange(
                0,
                1,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .ok()?;
        state_events.notify_waiters();
        Some(Self {
            sessions,
            state_events,
        })
    }
}

impl Drop for IbdActiveGuard {
    fn drop(&mut self) {
        self.sessions
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        self.state_events.notify_waiters();
    }
}

struct TracedMutexGuard<'a, T> {
    lock_name: &'static str,
    acquired_at: Instant,
    guard: tokio::sync::MutexGuard<'a, T>,
}

impl<T> Deref for TracedMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for TracedMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for TracedMutexGuard<'_, T> {
    fn drop(&mut self) {
        tracing::debug!(
            event = "lock_held_ms",
            lock_name = self.lock_name,
            held_ms = self.acquired_at.elapsed().as_millis() as u64,
            "lock released"
        );
    }
}

async fn trace_lock<'a, T>(
    lock_name: &'static str,
    mutex: &'a Arc<Mutex<T>>,
) -> TracedMutexGuard<'a, T> {
    let started = Instant::now();
    let guard = mutex.lock().await;
    tracing::debug!(
        event = "lock_wait_ms",
        lock_name,
        wait_ms = started.elapsed().as_millis() as u64,
        "lock acquired"
    );
    TracedMutexGuard {
        lock_name,
        acquired_at: Instant::now(),
        guard,
    }
}

async fn trace_task_result<F>(task_name: &'static str, future: F) -> Result<(), String>
where
    F: Future<Output = Result<(), String>>,
{
    tracing::info!(event = "task_started", task_name, "task started");
    let result = future.await;
    match &result {
        Ok(()) => tracing::info!(event = "task_stopped", task_name, "task stopped"),
        Err(e) => tracing::error!(
            event = "task_failed",
            task_name,
            error = %e,
            failure_class = "runtime",
            "task failed"
        ),
    }
    result
}

/// Upper bound on PEX known-peer entries. Each entry is an addr string
/// (<= 255 bytes) plus 12 bytes of metadata, so the table tops out at ~3 MiB
/// even with hostile max-length addresses.
const PEX_MAX_KNOWN_PEERS: usize = 10_000;
/// Stop soliciting addresses once we already know at least this many peers.
const PEX_TARGET_KNOWN_PEERS: usize = 64;
/// How often each peer connection considers sending a GetAddr (the 10-minute
/// per-peer cooldown in PexManager is the real limiter; this just paces the
/// check).
const PEX_GETADDR_TICK_SECS: u64 = 60;
const CATCHUP_CHECK_INTERVAL_SECS: u64 = 2;
const CATCHUP_MAX_HASHES_PER_TICK: usize = 16;
/// Keep at most one requested block body outstanding during IBD. This prevents
/// a validating node from leaving a peer blocked while its socket buffers fill
/// with the remainder of a large response page.
const IBD_BLOCK_REQUEST_WINDOW: usize = 1;
const IBD_PROGRESS_LOG_INTERVAL: u64 = 100;

const FUTURE_BLOCK_QUEUE_DRAIN_INTERVAL_SECS: u64 = 30;
const FUTURE_BLOCK_QUEUE_MAX_AGE_SECS: u64 = dom_core::MAX_FUTURE_BLOCK_TIME
    + dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS
    + FUTURE_BLOCK_QUEUE_DRAIN_INTERVAL_SECS * 2;
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4";
const METRICS_MAX_IN_FLIGHT: usize = 8;
const METRICS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const HELLO_EXCHANGE_TIMEOUT_SECS: u64 = dom_wire::handshake::HANDSHAKE_TIMEOUT_SECS;
const OUTBOUND_CONNECT_TIMEOUT_SECS: u64 = 10;
const PEER_ROTATION_METADATA_KEY: &[u8] = b"dom/peer_rotation_state/v2";
const LEGACY_PEER_ROTATION_METADATA_KEY: &[u8] = b"dom/peer_rotation_state/v1";
const PEER_REPUTATION_METADATA_KEY: &[u8] = b"dom/peer_reputation_state/v2";
const LEGACY_PEER_REPUTATION_METADATA_KEY: &[u8] = b"dom/peer_reputation_state/v1";
const MEMPOOL_METADATA_KEY: &[u8] = b"dom/mempool_state/v1";
const NOISE_STATIC_KEY_METADATA_KEY: &[u8] = b"dom/noise_static_key/v1";

/// Bind the P2P listener, dual-stack when the configured address is IPv6
/// (spec A8).
///
/// The single-socket scheme was chosen deliberately over two sockets
/// (R-A8.2): an IPv6 bind gets `IPV6_V6ONLY` set to `false` EXPLICITLY, so
/// `[::]:port` accepts both families on every OS instead of inheriting
/// Linux's `bindv6only` sysctl or the differing defaults elsewhere — and
/// nothing else may then also bind `0.0.0.0` on the same port, which is
/// exactly the double-bind `EADDRINUSE` the risk note warns about. Platforms
/// that refuse dual-stack sockets get a warning and a v6-only listener
/// rather than a dead node (§1.4: nothing may stop the boot).
///
/// An IPv4 address keeps the plain tokio bind: nothing about v4-only
/// behaviour changes, and the default configs still ship `0.0.0.0`, so
/// enabling v6 remains an explicit operator action via
/// `DOM_P2P_LISTEN_ADDR="[::]:33369"` until the hubs have AAAA records and
/// firewall rules to make it useful (§5.3).
async fn bind_p2p_listener(p2p_addr: &str) -> Result<tokio::net::TcpListener, DomError> {
    let parsed: std::net::SocketAddr = p2p_addr
        .parse()
        .map_err(|e| DomError::Internal(format!("Invalid P2P listen addr {p2p_addr}: {e}")))?;
    if parsed.is_ipv4() {
        return tokio::net::TcpListener::bind(parsed)
            .await
            .map_err(|e| DomError::Internal(format!("P2P bind {p2p_addr}: {e}")));
    }

    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .map_err(|e| DomError::Internal(format!("P2P socket for {p2p_addr}: {e}")))?;
    if let Err(e) = socket.set_only_v6(false) {
        warn!("dual-stack unavailable for {p2p_addr}; listening on IPv6 only: {e}");
    }
    // Match tokio's own bind behaviour so a quick restart does not fail on
    // TIME_WAIT remnants of our previous listener.
    #[cfg(unix)]
    socket
        .set_reuse_address(true)
        .map_err(|e| DomError::Internal(format!("P2P SO_REUSEADDR for {p2p_addr}: {e}")))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| DomError::Internal(format!("P2P nonblocking for {p2p_addr}: {e}")))?;
    socket
        .bind(&parsed.into())
        .map_err(|e| DomError::Internal(format!("P2P bind {p2p_addr}: {e}")))?;
    socket
        .listen(1024)
        .map_err(|e| DomError::Internal(format!("P2P listen {p2p_addr}: {e}")))?;
    tokio::net::TcpListener::from_std(socket.into())
        .map_err(|e| DomError::Internal(format!("P2P listener registration {p2p_addr}: {e}")))
}

async fn bind_metrics_listener(
    config: &NodeConfig,
) -> Result<Option<tokio::net::TcpListener>, DomError> {
    let Some(metrics_addr) = config.metrics_listen_addr.as_ref() else {
        return Ok(None);
    };
    let parsed: std::net::SocketAddr = metrics_addr.parse().map_err(|e| {
        DomError::Internal(format!("Invalid metrics listen addr {metrics_addr}: {e}"))
    })?;
    if !parsed.ip().is_loopback() {
        return Err(DomError::PolicyRejected(
            "metrics listener must use an explicit loopback address".into(),
        ));
    }
    let listener = tokio::net::TcpListener::bind(parsed)
        .await
        .map_err(|e| DomError::Internal(format!("metrics bind {parsed}: {e}")))?;
    Ok(Some(listener))
}

async fn serve_metrics(
    listener: tokio::net::TcpListener,
    metrics: Arc<Metrics>,
) -> Result<(), DomError> {
    let capacity = Arc::new(tokio::sync::Semaphore::new(METRICS_MAX_IN_FLIGHT));
    // JoinSet gives the metrics service structured ownership of every accepted
    // connection. Dropping/cancelling this service aborts all children rather
    // than leaving detached tasks outside NodeTaskSupervisor's lifecycle.
    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            biased;
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!("metrics connection task failed: {error}");
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (mut stream, _) =
            accepted.map_err(|e| DomError::Internal(format!("metrics accept: {e}")))?;
        let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
            // Fail closed without queueing sockets: one local scraper must not
            // retain arbitrary pending work or starve the observability loop.
            drop(stream);
            continue;
        };
        let metrics = Arc::clone(&metrics);
        connections.spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_metrics_connection(&mut stream, &metrics).await {
                tracing::debug!("metrics request failed: {e}");
            }
        });
    }
}

async fn handle_metrics_connection(
    stream: &mut tokio::net::TcpStream,
    metrics: &Metrics,
) -> Result<(), DomError> {
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(METRICS_IO_TIMEOUT, stream.read(&mut buf))
        .await
        .map_err(|_| DomError::Internal("metrics read timeout".into()))?
        .map_err(|e| DomError::Internal(format!("metrics read: {e}")))?;
    let request = std::str::from_utf8(&buf[..n]).unwrap_or_default();
    let first_line = request.lines().next().unwrap_or_default();
    let (status, body) = if first_line.starts_with("GET /metrics ") {
        ("200 OK", metrics.export_prometheus())
    } else if first_line.starts_with("GET ") {
        ("404 Not Found", "not found\n".to_string())
    } else {
        ("405 Method Not Allowed", "method not allowed\n".to_string())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {METRICS_CONTENT_TYPE}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tokio::time::timeout(METRICS_IO_TIMEOUT, stream.write_all(response.as_bytes()))
        .await
        .map_err(|_| DomError::Internal("metrics write timeout".into()))?
        .map_err(|e| DomError::Internal(format!("metrics write: {e}")))?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundAttemptOutcome {
    RetryableFailure,
    Registered,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeferredReplayAction {
    RelayBestChain,
    Requeue,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayBlockAction {
    RelayBestChain,
    Suppress,
    PenalizePeer,
    Drop,
}

#[derive(Debug, Clone)]
pub(crate) struct TxChainView {
    pub(crate) current_height: u64,
    pub(crate) chain_id: [u8; 32],
    pub(crate) coinbase_maturity: u64,
    pub(crate) utxos: HashMap<[u8; 33], Option<UtxoEntry>>,
}

#[derive(Debug, Clone)]
struct ReinjectableTx {
    tx: Transaction,
    tx_hash: [u8; 32],
    now_secs: u64,
    chain_view: TxChainView,
}

pub(crate) fn snapshot_tx_chain_view(
    chain: &ChainState,
    tx: &Transaction,
) -> Result<TxChainView, DomError> {
    let mut utxos = HashMap::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let commitment = *input.commitment.as_bytes();
        utxos
            .entry(commitment)
            .or_insert(chain.store.get_utxo(&commitment)?);
    }
    Ok(TxChainView {
        current_height: chain.tip_height.0,
        chain_id: *derive_chain_id(chain.network_magic, &chain.genesis_hash).as_bytes(),
        coinbase_maturity: chain.coinbase_maturity,
        utxos,
    })
}

async fn purge_mempool_confirmed_inputs(
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    transactions: &[Transaction],
) -> Result<(), DomError> {
    let mut spent_inputs: Vec<[u8; 33]> =
        Vec::with_capacity(transactions.iter().map(|tx| tx.inputs.len()).sum());
    for tx in transactions {
        for input in &tx.inputs {
            spent_inputs.push(*input.commitment.as_bytes());
        }
    }
    if spent_inputs.is_empty() {
        return Ok(());
    }

    {
        let mut mempool = mempool.lock().await;
        mempool.remove_confirmed(&spent_inputs);
    }
    persist_mempool_state(chain, mempool).await
}

impl DomNode {
    #[cfg(all(test, feature = "ethereum-checkpoint-verified-poc"))]
    fn init_with_verified_restart_floor_for_test(
        config: NodeConfig,
        checkpoint: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
        policy_hash: [u8; 32],
    ) -> Result<Self, DomError> {
        Self::init_inner(config, None, false, Some((checkpoint, policy_hash)))
    }

    /// Initialize the node from configuration.
    pub fn init(config: NodeConfig) -> Result<Self, DomError> {
        Self::init_inner(
            config,
            None,
            false,
            #[cfg(feature = "ethereum-checkpoint-verified-poc")]
            None,
        )
    }

    /// Initialize the node with an explicit LMDB map size override.
    ///
    /// Production callers should keep using [`Self::init`], which preserves the
    /// 16 GiB default. This override exists for tiny test fixtures so Windows
    /// CI does not reserve a full production-sized LMDB map for each temporary
    /// node/store instance.
    pub fn init_with_map_size(config: NodeConfig, map_size: usize) -> Result<Self, DomError> {
        Self::init_inner(
            config,
            Some(map_size),
            false,
            #[cfg(feature = "ethereum-checkpoint-verified-poc")]
            None,
        )
    }

    /// Initialize an explicitly isolated Regtest node with a restored and
    /// audited native USDOM v4 runtime. The database must already contain the
    /// atomic activation state; this constructor never creates or guesses it.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn init_native_usdom_v4_regtest(
        config: NodeConfig,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_v4_regtest_inner(
            config,
            None,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            None,
        )
    }

    /// Initialize an isolated Regtest runtime with the exact canonical
    /// private-spend verifying key committed by `bridge`. Initialization fails
    /// closed before networking starts if the key is malformed or mismatched.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn init_native_usdom_v4_regtest_with_spend_verifier(
        config: NodeConfig,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_v4_regtest_inner(
            config,
            None,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifying_key),
        )
    }

    /// Test-sized LMDB variant of [`Self::init_native_usdom_v4_regtest`].
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn init_native_usdom_v4_regtest_with_map_size(
        config: NodeConfig,
        map_size: usize,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_v4_regtest_inner(
            config,
            Some(map_size),
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            None,
        )
    }

    /// Test-sized LMDB variant of
    /// [`Self::init_native_usdom_v4_regtest_with_spend_verifier`].
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn init_native_usdom_v4_regtest_with_spend_verifier_and_map_size(
        config: NodeConfig,
        map_size: usize,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_v4_regtest_inner(
            config,
            Some(map_size),
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            Some(spend_verifying_key),
        )
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    fn init_native_usdom_v4_regtest_inner(
        config: NodeConfig,
        map_size_override: Option<usize>,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: Option<&[u8]>,
    ) -> Result<Self, DomError> {
        if config.network != dom_config::Network::Regtest {
            return Err(DomError::PolicyRejected(
                "native USDOM v4 node runtime is available only on explicit Regtest".into(),
            ));
        }
        let mut node = Self::init_inner(
            config,
            map_size_override,
            true,
            #[cfg(feature = "ethereum-checkpoint-verified-poc")]
            None,
        )?;
        let chain_mutex = Arc::get_mut(&mut node.chain).ok_or_else(|| {
            DomError::Internal(
                "native USDOM runtime must be restored before sharing chain state".into(),
            )
        })?;
        let runtime = match spend_verifying_key {
            Some(key) => dom_chain::NativeUsdomV4Runtime::restore_with_spend_verifier(
                chain_mutex.get_mut(),
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
                key,
            )?,
            None => dom_chain::NativeUsdomV4Runtime::restore(
                chain_mutex.get_mut(),
                bridge,
                checkpoint_policy,
                deposit_policy,
                closure_policy,
            )?,
        };
        node.native_usdom_v4_schedule = Some(runtime.activation_schedule());
        node.native_usdom_v4_runtime = Some(Arc::new(Mutex::new(runtime)));
        Ok(node)
    }

    /// Initialize a scheduled native USDOM runtime for a recognized DOM
    /// network. The database must already contain the exact activation record;
    /// construction never installs or guesses consensus configuration.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn init_native_usdom_v4_for_schedule_with_spend_verifier(
        config: NodeConfig,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        schedule: dom_chain::NativeUsdomV4ActivationSchedule,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_v4_for_schedule_inner(
            config,
            None,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifying_key,
            schedule,
            None,
        )
    }

    /// Initialize the hash-pinned V1/V2 candidate and select exactly one
    /// runtime from the atomically persisted migration marker. Before the
    /// migration parent this restores V1. After migration it restores V2.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn init_native_usdom_candidate_for_schedule_with_spend_verifier(
        config: NodeConfig,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        v1_schedule: dom_chain::NativeUsdomV4ActivationSchedule,
        first_v2_height: u64,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_candidate_for_schedule_inner(
            config,
            None,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifying_key,
            v1_schedule,
            first_v2_height,
            None,
        )
    }

    /// Scheduled candidate startup with a manifest-pinned Ethereum witness
    /// that has already been replay-verified into an opaque checkpoint.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn init_native_usdom_candidate_with_restart_checkpoint(
        config: NodeConfig,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        v1_schedule: dom_chain::NativeUsdomV4ActivationSchedule,
        first_v2_height: u64,
        restart_checkpoint: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_candidate_for_schedule_inner(
            config,
            None,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifying_key,
            v1_schedule,
            first_v2_height,
            Some(restart_checkpoint),
        )
    }

    /// Test-sized LMDB variant of the V1/V2 phase-selecting constructor.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn init_native_usdom_candidate_for_schedule_with_spend_verifier_and_map_size(
        config: NodeConfig,
        map_size: usize,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        v1_schedule: dom_chain::NativeUsdomV4ActivationSchedule,
        first_v2_height: u64,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_candidate_for_schedule_inner(
            config,
            Some(map_size),
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifying_key,
            v1_schedule,
            first_v2_height,
            None,
        )
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    fn init_native_usdom_candidate_for_schedule_inner(
        config: NodeConfig,
        map_size_override: Option<usize>,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        v1_schedule: dom_chain::NativeUsdomV4ActivationSchedule,
        first_v2_height: u64,
        restart_checkpoint: Option<
            &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
        >,
    ) -> Result<Self, DomError> {
        if v1_schedule.network_magic() != config.network.magic()
            || first_v2_height <= v1_schedule.first_v4_height()
        {
            return Err(DomError::PolicyRejected(
                "native USDOM V1/V2 schedule does not match configured network or heights".into(),
            ));
        }
        let policy_hash: [u8; 32] = checkpoint_policy.policy_hash().into();
        let mut node = Self::init_inner(
            config,
            map_size_override,
            true,
            restart_checkpoint.map(|checkpoint| (checkpoint, policy_hash)),
        )?;
        let chain_mutex = Arc::get_mut(&mut node.chain).ok_or_else(|| {
            DomError::Internal(
                "native USDOM runtime must be restored before sharing chain state".into(),
            )
        })?;
        let chain = chain_mutex.get_mut();
        match dom_chain::load_persisted_usdom_v2_activation_schedule(&chain.store)? {
            None => {
                // Reaching the selected parent without the marker means the
                // required atomic migration was bypassed. It cannot be repaired
                // by guessing state after restart.
                let activation_parent_height = first_v2_height.checked_sub(1).ok_or_else(|| {
                    DomError::PolicyRejected("native USDOM V2 activation height underflow".into())
                })?;
                if chain.tip_height.0 >= activation_parent_height {
                    return Err(DomError::PolicyRejected(
                        "candidate-V2 activation parent is canonical without its atomic migration marker"
                            .into(),
                    ));
                }
                let runtime =
                    dom_chain::NativeUsdomV4Runtime::restore_for_schedule_with_spend_verifier(
                        chain,
                        bridge,
                        checkpoint_policy,
                        deposit_policy,
                        closure_policy,
                        spend_verifying_key,
                        v1_schedule,
                    )?;
                node.native_usdom_v4_schedule = Some(v1_schedule);
                node.native_usdom_v4_runtime = Some(Arc::new(Mutex::new(runtime)));
                node.candidate_v2_first_height = Some(first_v2_height);
            }
            Some(v2_schedule) => {
                if v2_schedule.first_v2_height() != first_v2_height {
                    return Err(DomError::PolicyRejected(
                        "persisted candidate-V2 activation height differs from the hash-pinned manifest"
                            .into(),
                    ));
                }
                let persisted_v1 = dom_chain::persisted_usdom_v4_activation_schedule(&chain.store)?;
                if persisted_v1 != v1_schedule {
                    return Err(DomError::PolicyRejected(
                        "persisted native USDOM V1 schedule differs from the hash-pinned manifest"
                            .into(),
                    ));
                }
                let runtime =
                    dom_chain::NativeUsdomV2Runtime::restore_for_schedule_with_spend_verifier(
                        chain,
                        bridge,
                        checkpoint_policy,
                        deposit_policy,
                        closure_policy,
                        spend_verifying_key,
                        v2_schedule,
                    )?;
                node.native_usdom_v2_schedule = Some(v2_schedule);
                node.native_usdom_v2_runtime = Some(Arc::new(Mutex::new(runtime)));
            }
        }
        Ok(node)
    }

    /// Test-sized LMDB variant of the scheduled runtime constructor.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn init_native_usdom_v4_for_schedule_with_spend_verifier_and_map_size(
        config: NodeConfig,
        map_size: usize,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        schedule: dom_chain::NativeUsdomV4ActivationSchedule,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_v4_for_schedule_inner(
            config,
            Some(map_size),
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifying_key,
            schedule,
            None,
        )
    }

    /// Scheduled V1 startup with a manifest-pinned, replay-verified external
    /// checkpoint floor.
    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    pub fn init_native_usdom_v4_with_restart_checkpoint(
        config: NodeConfig,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        schedule: dom_chain::NativeUsdomV4ActivationSchedule,
        restart_checkpoint: &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
    ) -> Result<Self, DomError> {
        Self::init_native_usdom_v4_for_schedule_inner(
            config,
            None,
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifying_key,
            schedule,
            Some(restart_checkpoint),
        )
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[allow(clippy::too_many_arguments)]
    fn init_native_usdom_v4_for_schedule_inner(
        config: NodeConfig,
        map_size_override: Option<usize>,
        bridge: dom_usdom_state::BridgeIdentity,
        checkpoint_policy: usdom_ethereum_finality_experiment::checkpoints::StaticCheckpointTrustPolicy,
        deposit_policy: usdom_ethereum_finality_experiment::deposits::StaticDepositTrustPolicy,
        closure_policy: Option<
            usdom_ethereum_finality_experiment::closures::StaticIssuanceClosureTrustPolicy,
        >,
        spend_verifying_key: &[u8],
        schedule: dom_chain::NativeUsdomV4ActivationSchedule,
        restart_checkpoint: Option<
            &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
        >,
    ) -> Result<Self, DomError> {
        if schedule.network_magic() != config.network.magic() {
            return Err(DomError::PolicyRejected(
                "native USDOM node schedule does not match configured network".into(),
            ));
        }
        let policy_hash: [u8; 32] = checkpoint_policy.policy_hash().into();
        let mut node = Self::init_inner(
            config,
            map_size_override,
            true,
            restart_checkpoint.map(|checkpoint| (checkpoint, policy_hash)),
        )?;
        let chain_mutex = Arc::get_mut(&mut node.chain).ok_or_else(|| {
            DomError::Internal(
                "native USDOM runtime must be restored before sharing chain state".into(),
            )
        })?;
        let runtime = dom_chain::NativeUsdomV4Runtime::restore_for_schedule_with_spend_verifier(
            chain_mutex.get_mut(),
            bridge,
            checkpoint_policy,
            deposit_policy,
            closure_policy,
            spend_verifying_key,
            schedule,
        )?;
        node.native_usdom_v4_schedule = Some(schedule);
        node.native_usdom_v4_runtime = Some(Arc::new(Mutex::new(runtime)));
        Ok(node)
    }

    /// Ingest one tagged wire payload through the restored native USDOM v4
    /// runtime. The chain lock is always acquired before the runtime lock, so
    /// all callers share one deterministic lock order. Only canonical tip
    /// changes are relayed and reconciled with the mempool.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn ingest_native_usdom_v4_wire_payload_regtest(
        &self,
        wire_payload: &[u8],
        now: Timestamp,
    ) -> Result<dom_chain::ConnectResult, DomError> {
        if self.config.network != dom_config::Network::Regtest {
            return Err(DomError::PolicyRejected(
                "Regtest native USDOM ingress called for another network".into(),
            ));
        }
        self.ingest_native_usdom_v4_wire_payload(wire_payload, now)
            .await
    }

    /// Ingest one tagged native package through the schedule installed by the
    /// node constructor.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn ingest_native_usdom_v4_wire_payload(
        &self,
        wire_payload: &[u8],
        now: Timestamp,
    ) -> Result<dom_chain::ConnectResult, DomError> {
        let runtime = self.native_usdom_v4_runtime.as_ref().ok_or_else(|| {
            DomError::PolicyRejected("native USDOM v4 runtime is not configured".into())
        })?;
        NativeUsdomV4Ingress {
            chain: self.chain.clone(),
            mempool: self.mempool.clone(),
            runtime: runtime.clone(),
            relay_tx: self.native_usdom_v4_relay_tx.clone(),
            relay_exclude_peer: None,
            wallet: self.wallet.clone(),
            metrics: self.metrics.clone(),
            future_block_queue: self.future_block_queue.clone(),
            native_future_queue: self.native_usdom_v4_future_queue.clone(),
            state_events: self.state_events.clone(),
            orphan_pool: self.native_usdom_v4_orphan_pool.clone(),
            candidate_v2_first_height: self.candidate_v2_first_height,
            migration_shutdown: Some(self.task_supervisor.clone()),
            proof_admission: self.native_usdom_proof_admission.clone(),
        }
        .ingest(wire_payload, now)
        .await
    }

    /// Whether this node owns a restored native USDOM v4 runtime.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn has_native_usdom_v4_runtime(&self) -> bool {
        self.native_usdom_v4_runtime.is_some()
    }

    /// Whether startup selected the persisted candidate-V2 runtime.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn has_native_usdom_v2_runtime(&self) -> bool {
        self.native_usdom_v2_runtime.is_some()
    }

    /// Enable authenticated sync-tip observation before starting P2P tasks.
    /// The trusted Noise identities and quorum are operator-ratified inputs;
    /// without this explicit call observations are ignored and no receipt is persisted.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn configure_sync_attestation(
        &mut self,
        policy: dom_usdom_checkpoint_program::SyncAttestationPolicy,
    ) -> Result<(), DomError> {
        self.sync_attestation_collector = Some(Arc::new(Mutex::new(
            dom_usdom_checkpoint_program::SyncAttestationCollector::new(policy)?,
        )));
        Ok(())
    }

    /// Ingest one exact candidate-V2 package/witness envelope through the
    /// runtime selected at startup. P2P capability wiring is deliberately
    /// separate; this entry point never interprets a V1-only envelope as V2.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn ingest_native_usdom_v2_wire_payload(
        &self,
        wire_payload: &[u8],
        now: Timestamp,
    ) -> Result<dom_chain::ConnectResult, DomError> {
        let runtime = self.native_usdom_v2_runtime.as_ref().ok_or_else(|| {
            DomError::PolicyRejected("native USDOM V2 runtime is not configured".into())
        })?;
        NativeUsdomV2Ingress {
            chain: self.chain.clone(),
            mempool: self.mempool.clone(),
            runtime: runtime.clone(),
            relay_tx: self.native_usdom_v2_relay_tx.clone(),
            relay_exclude_peer: None,
            wallet: self.wallet.clone(),
            metrics: self.metrics.clone(),
            future_block_queue: self.future_block_queue.clone(),
            native_future_queue: self.native_usdom_v4_future_queue.clone(),
            state_events: self.state_events.clone(),
            orphan_pool: self.native_usdom_v4_orphan_pool.clone(),
            proof_admission: self.native_usdom_proof_admission.clone(),
        }
        .ingest(wire_payload, now)
        .await
    }

    /// Submit one canonical nonempty proof envelope to the bounded volatile
    /// Regtest mining pool. Proofs are verified here, reverified for the exact
    /// mining timestamp, and verified a third time by final package ingress.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn submit_native_usdom_v4_mining_envelope_regtest(
        &self,
        envelope_bytes: &[u8],
        candidate_timestamp: Timestamp,
    ) -> Result<Hash256, DomError> {
        if self.config.network != dom_config::Network::Regtest {
            return Err(DomError::PolicyRejected(
                "native USDOM mining candidates are available only on explicit Regtest".into(),
            ));
        }
        self.submit_native_usdom_v4_mining_envelope(envelope_bytes.to_vec(), candidate_timestamp)
            .await
    }

    /// Submit one canonical nonempty envelope to the runtime selected by the
    /// node's immutable activation schedule.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn submit_native_usdom_v4_mining_envelope(
        &self,
        envelope_bytes: Vec<u8>,
        candidate_timestamp: Timestamp,
    ) -> Result<Hash256, DomError> {
        let runtime = self.native_usdom_v4_runtime.as_ref().ok_or_else(|| {
            DomError::PolicyRejected("native USDOM v4 runtime is not configured".into())
        })?;
        let chain = self.chain.clone().lock_owned().await;
        let runtime = runtime.clone().lock_owned().await;
        let (result, count, bytes) = tokio::task::spawn_blocking(move || {
            let _chain = chain;
            let mut runtime = runtime;
            let result = runtime.admit_mining_envelope(&envelope_bytes, candidate_timestamp);
            let (count, bytes) = runtime.mining_candidate_stats();
            (result, count, bytes)
        })
        .await
        .map_err(|error| DomError::Internal(format!("native V1 admission task failed: {error}")))?;
        self.metrics.native_usdom_v4_mining_candidates.store(
            u64::try_from(count).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_mining_candidate_bytes.store(
            u64::try_from(bytes).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        if result.is_err() {
            self.metrics
                .native_usdom_v4_mining_admission_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    /// Submit one inseparable V2 proof-envelope and execution-witness pair to
    /// the bounded volatile mining pool. The runtime verifies the pair at
    /// admission, at template construction and again during package ingress.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn submit_native_usdom_v2_mining_candidate(
        &self,
        envelope_bytes: Vec<u8>,
        witness_bytes: Vec<u8>,
        candidate_timestamp: Timestamp,
    ) -> Result<Hash256, DomError> {
        let runtime = self.native_usdom_v2_runtime.as_ref().ok_or_else(|| {
            DomError::PolicyRejected("native USDOM V2 runtime is not configured".into())
        })?;
        let chain = self.chain.clone().lock_owned().await;
        let runtime = runtime.clone().lock_owned().await;
        let (result, count, bytes) = tokio::task::spawn_blocking(move || {
            let _chain = chain;
            let mut runtime = runtime;
            let result = runtime.admit_mining_candidate(
                &envelope_bytes,
                &witness_bytes,
                candidate_timestamp,
            );
            let (count, bytes) = runtime.mining_candidate_stats();
            (result, count, bytes)
        })
        .await
        .map_err(|error| DomError::Internal(format!("native V2 admission task failed: {error}")))?;
        self.metrics.native_usdom_v4_mining_candidates.store(
            u64::try_from(count).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_mining_candidate_bytes.store(
            u64::try_from(bytes).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        if result.is_err() {
            self.metrics
                .native_usdom_v4_mining_admission_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    /// Snapshot the canonical tip and derive one fully revalidated native
    /// mining template under the global chain-before-runtime lock order.
    /// `None` means this is an ordinary node and its miner must retain the
    /// normal block-version path.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub(crate) async fn native_usdom_v4_mining_template(
        &self,
        block_timestamp: Timestamp,
    ) -> Result<Option<(dom_core::Hash256, dom_chain::NativeUsdomV4MiningTemplate)>, DomError> {
        let Some(runtime) = self.native_usdom_v4_runtime.as_ref() else {
            return Ok(None);
        };
        let chain = self.chain.clone().lock_owned().await;
        let runtime = runtime.clone().lock_owned().await;
        let (tip_hash, template, before_count, count, bytes) =
            tokio::task::spawn_blocking(move || {
                let chain = chain;
                let tip_hash = chain.tip_hash;
                let mut runtime = runtime;
                let before_count = runtime.mining_candidate_stats().0;
                let template = runtime.mining_batch_template(block_timestamp)?;
                let (count, bytes) = runtime.mining_candidate_stats();
                Ok::<_, DomError>((tip_hash, template, before_count, count, bytes))
            })
            .await
            .map_err(|error| {
                DomError::Internal(format!("native V1 template task failed: {error}"))
            })??;
        self.metrics.native_usdom_v4_mining_candidates.store(
            u64::try_from(count).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_mining_candidate_bytes.store(
            u64::try_from(bytes).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_mining_stale_dropped.fetch_add(
            u64::try_from(before_count.saturating_sub(count)).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(Some((tip_hash, template)))
    }

    /// Select exactly one native mining phase. V1 and V2 runtimes are
    /// mutually exclusive at startup; observing both is an internal fail-stop
    /// rather than permission to choose one implicitly.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub(crate) async fn native_usdom_mining_template(
        &self,
        block_timestamp: Timestamp,
    ) -> Result<Option<(Hash256, NativeUsdomMiningTemplate)>, DomError> {
        if self.native_usdom_v4_runtime.is_some() && self.native_usdom_v2_runtime.is_some() {
            return Err(DomError::Internal(
                "both native USDOM mining phases are active".into(),
            ));
        }
        if let Some((tip, template)) = self
            .native_usdom_v4_mining_template(block_timestamp)
            .await?
        {
            return Ok(Some((tip, NativeUsdomMiningTemplate::V1(template))));
        }
        let Some(runtime) = self.native_usdom_v2_runtime.as_ref() else {
            return Ok(None);
        };
        let chain = self.chain.clone().lock_owned().await;
        let runtime = runtime.clone().lock_owned().await;
        let (tip_hash, template, before_count, count, bytes) =
            tokio::task::spawn_blocking(move || {
                let chain = chain;
                let tip_hash = chain.tip_hash;
                let mut runtime = runtime;
                let before_count = runtime.mining_candidate_stats().0;
                let template = runtime.mining_batch_template(block_timestamp)?;
                let (count, bytes) = runtime.mining_candidate_stats();
                Ok::<_, DomError>((tip_hash, template, before_count, count, bytes))
            })
            .await
            .map_err(|error| {
                DomError::Internal(format!("native V2 template task failed: {error}"))
            })??;
        self.metrics.native_usdom_v4_mining_candidates.store(
            u64::try_from(count).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_mining_candidate_bytes.store(
            u64::try_from(bytes).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.native_usdom_v4_mining_stale_dropped.fetch_add(
            u64::try_from(before_count.saturating_sub(count)).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(Some((tip_hash, NativeUsdomMiningTemplate::V2(template))))
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    pub(crate) async fn complete_native_usdom_v4_mining_candidate(
        &self,
        candidate_id: Hash256,
        canonical_height: u64,
        canonical_block_hash: Hash256,
    ) -> Result<bool, DomError> {
        if let Some(runtime) = self.native_usdom_v4_runtime.as_ref() {
            // The ingress result and this cleanup are separated by an async
            // boundary. A competing block may reorganize the just-mined block
            // away in that interval. Recheck the exact canonical identity
            // while holding the chain lock, then take the runtime lock in the
            // global chain-before-runtime order. A reorg can no longer remove
            // a still-usable volatile candidate through a stale result.
            let chain = trace_lock("chain", &self.chain).await;
            if !is_exact_canonical_block(&chain, canonical_height, canonical_block_hash)? {
                return Ok(false);
            }
            let mut runtime = trace_lock("native_usdom_v4_runtime", runtime).await;
            let result = runtime.complete_mining_candidate(candidate_id);
            let (count, bytes) = runtime.mining_candidate_stats();
            self.metrics.native_usdom_v4_mining_candidates.store(
                u64::try_from(count).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
            self.metrics.native_usdom_v4_mining_candidate_bytes.store(
                u64::try_from(bytes).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
            return result;
        }
        Ok(false)
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    pub(crate) async fn complete_native_usdom_v2_mining_candidate(
        &self,
        candidate_id: Hash256,
        canonical_height: u64,
        canonical_block_hash: Hash256,
    ) -> Result<bool, DomError> {
        if let Some(runtime) = self.native_usdom_v2_runtime.as_ref() {
            // See the V1 path above: cleanup authority comes from the current
            // canonical index, never from an ingress result that may have gone
            // stale while this task was descheduled.
            let chain = trace_lock("chain", &self.chain).await;
            if !is_exact_canonical_block(&chain, canonical_height, canonical_block_hash)? {
                return Ok(false);
            }
            let mut runtime = trace_lock("native_usdom_v2_runtime", runtime).await;
            let result = runtime.complete_mining_candidate(candidate_id);
            let (count, bytes) = runtime.mining_candidate_stats();
            self.metrics.native_usdom_v4_mining_candidates.store(
                u64::try_from(count).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
            self.metrics.native_usdom_v4_mining_candidate_bytes.store(
                u64::try_from(bytes).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
            return result;
        }
        Ok(false)
    }

    /// Observe canonical native-v4 relay decisions without gaining authority
    /// to inject unvalidated bytes into live peer sessions.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn subscribe_native_usdom_v4_relays(
        &self,
    ) -> tokio::sync::broadcast::Receiver<NativeUsdomV4Relay> {
        self.native_usdom_v4_relay_tx.subscribe()
    }

    /// Observe validated V2 relay decisions without gaining ingress authority.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub fn subscribe_native_usdom_v2_relays(
        &self,
    ) -> tokio::sync::broadcast::Receiver<NativeUsdomV2Relay> {
        self.native_usdom_v2_relay_tx.subscribe()
    }

    /// Build the first candidate-v2 checkpoint source while retaining the
    /// canonical chain and native-runtime locks for one coherent snapshot.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn build_first_v2_checkpoint_source(
        &self,
        randomx_receipt_image_id: [u8; 32],
    ) -> Result<dom_usdom_checkpoint_program::AuthenticatedCheckpointSourceBundle, DomError> {
        let runtime = self.native_usdom_v2_runtime.as_ref().ok_or_else(|| {
            DomError::PolicyRejected(
                "candidate-v2 checkpoint source requires the active V2 runtime".into(),
            )
        })?;
        let chain = self.chain.clone().lock_owned().await;
        let runtime = runtime.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let schedule = runtime.activation_schedule();
            let closure_policy = runtime.issuance_closure_policy().ok_or_else(|| {
                DomError::PolicyRejected(
                    "candidate-v2 checkpoint source requires an issuance closure policy".into(),
                )
            })?;
            dom_usdom_checkpoint_program::build_first_v2_checkpoint_source(
                &chain,
                schedule,
                runtime.checkpoint_policy(),
                runtime.deposit_policy(),
                closure_policy,
                runtime.spend_verifying_key(),
                runtime.state(),
                randomx_receipt_image_id,
            )
        })
        .await
        .map_err(|error| {
            DomError::Internal(format!(
                "candidate-v2 checkpoint source task failed: {error}"
            ))
        })?
    }

    /// Build the latest fully confirmed candidate-v2 checkpoint source set
    /// while retaining the canonical chain and runtime locks for one coherent
    /// snapshot.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn build_latest_v2_checkpoint_sources(
        &self,
        randomx_receipt_image_id: [u8; 32],
        checkpoint_interval_blocks: u32,
        checkpoint_confirmation_depth_blocks: u32,
    ) -> Result<dom_usdom_checkpoint_program::AuthenticatedCheckpointSourceSet, DomError> {
        let runtime = self.native_usdom_v2_runtime.as_ref().ok_or_else(|| {
            DomError::PolicyRejected(
                "candidate-v2 checkpoint sources require the active V2 runtime".into(),
            )
        })?;
        let chain = self.chain.clone().lock_owned().await;
        let runtime = runtime.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let schedule = runtime.activation_schedule();
            let closure_policy = runtime.issuance_closure_policy().ok_or_else(|| {
                DomError::PolicyRejected(
                    "candidate-v2 checkpoint sources require an issuance closure policy".into(),
                )
            })?;
            dom_usdom_checkpoint_program::build_latest_v2_checkpoint_sources(
                &chain,
                schedule,
                runtime.checkpoint_policy(),
                runtime.deposit_policy(),
                closure_policy,
                runtime.spend_verifying_key(),
                runtime.state(),
                randomx_receipt_image_id,
                checkpoint_interval_blocks,
                checkpoint_confirmation_depth_blocks,
            )
        })
        .await
        .map_err(|error| {
            DomError::Internal(format!(
                "candidate-v2 checkpoint source-set task failed: {error}"
            ))
        })?
    }

    /// Build one canonical `UDFINL04` finalized-burn source while holding the
    /// chain and candidate-V2 runtime locks for a coherent offline snapshot.
    ///
    /// The raw Ethereum witness selects the checkpoint independently; callers
    /// must pass the block identifier authenticated by that witness. This
    /// method never proves, publishes or submits the resulting input.
    #[cfg(feature = "native-usdom-v4-poc")]
    pub async fn build_finalized_burn_prover_input(
        &self,
        v1_schedule: dom_chain::NativeUsdomV4ActivationSchedule,
        canonical_checkpoint: Hash256,
        burn_id: [u8; 32],
        checkpoint_statement: dom_chain::CheckpointStatementV6,
        checkpoint_witness_bytes: Vec<u8>,
    ) -> Result<dom_chain::FinalizedBurnProverInput, DomError> {
        let runtime = self.native_usdom_v2_runtime.as_ref().ok_or_else(|| {
            DomError::PolicyRejected(
                "finalized-burn source requires the active candidate-V2 runtime".into(),
            )
        })?;
        let network_magic = self.config.network.magic();
        let chain = self.chain.clone().lock_owned().await;
        let runtime = runtime.clone().lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let spend_verifier = dom_usdom_privacy::verifier::SpendVerifier::from_bytes(
                runtime.spend_verifying_key(),
            )
            .map_err(|error| {
                DomError::Internal(format!(
                    "restored finalized-burn spend verifier is invalid: {error}"
                ))
            })?;
            dom_chain::export_finalized_burn_prover_input_for_schedule(
                &chain.store,
                network_magic,
                runtime.bridge_identity(),
                canonical_checkpoint,
                burn_id,
                v1_schedule,
                runtime.activation_schedule(),
                runtime.checkpoint_policy().clone(),
                runtime.deposit_policy(),
                runtime.issuance_closure_policy(),
                &spend_verifier,
                checkpoint_statement,
                checkpoint_witness_bytes,
            )
        })
        .await
        .map_err(|error| {
            DomError::Internal(format!("finalized-burn source task failed: {error}"))
        })?
    }

    fn init_inner(
        config: NodeConfig,
        map_size_override: Option<usize>,
        allow_native_usdom_v4_activation: bool,
        #[cfg(feature = "ethereum-checkpoint-verified-poc")] restart_checkpoint: Option<(
            &usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint,
            [u8; 32],
        )>,
    ) -> Result<Self, DomError> {
        info!("Initializing DOM node ({:?} network)", config.network);
        info!("Data directory: {}", config.data_dir);

        // Fail closed before touching the data directory if this build still
        // carries placeholder genesis constants for the requested network.
        let genesis_hash =
            dom_core::startup_genesis_hash_for_network_magic(config.network.magic())?;

        // Open storage
        let data_path = Path::new(&config.data_dir);
        let store = match map_size_override {
            Some(map_size) => DomStore::open_with_map_size(data_path, map_size)?,
            None => DomStore::open(data_path)?,
        };

        // Validate chain state and any required external restart floor before
        // creating even unrelated node metadata in this data directory.
        #[cfg(feature = "ethereum-checkpoint-verified-poc")]
        let chain = match restart_checkpoint {
            Some((checkpoint, policy_hash)) => ChainState::open_with_verified_checkpoint_floor(
                store,
                genesis_hash,
                config.network.magic(),
                checkpoint,
                policy_hash,
            )?,
            None => ChainState::open(store, genesis_hash, config.network.magic())?,
        };
        #[cfg(not(feature = "ethereum-checkpoint-verified-poc"))]
        let chain = ChainState::open(store, genesis_hash, config.network.magic())?;

        // Generate or load the Noise key only after the rollback barrier has
        // accepted this database snapshot.
        let noise_privkey = Zeroizing::new(load_or_create_noise_static_key(&chain.store)?);
        let noise_pubkey = dom_wire::handshake::derive_static_pubkey(&noise_privkey);
        info!("Node identity: {}", hex::encode(noise_pubkey));
        #[cfg(feature = "native-usdom-v4-poc")]
        if chain.native_usdom_v4_activation_initialized()? && !allow_native_usdom_v4_activation {
            return Err(DomError::PolicyRejected(
                "native USDOM v4 is activated in this data directory; start with the exact bridge policies and verifying key instead of the ordinary node constructor"
                    .into(),
            ));
        }
        #[cfg(not(feature = "native-usdom-v4-poc"))]
        let _ = allow_native_usdom_v4_activation;
        info!("Chain tip: height={}", chain.tip_height);

        let mut peers = PeerManager::new(config.max_inbound, config.min_outbound);
        peers.set_seed_ips(config.seed_peers.iter().filter_map(|seed| {
            seed.parse::<std::net::SocketAddr>()
                .ok()
                .map(|addr| addr.ip())
        }));
        restore_peer_rotation_state(&chain.store, &mut peers)?;
        restore_peer_reputation_state(&chain.store, &mut peers)?;
        // Rewrite after restore so expired entries and migrated v1 records are
        // removed from disk immediately instead of surviving until the next
        // peer event.
        persist_peer_reputation_snapshot(&chain.store, &peers.peer_reputation_state())?;
        // Volatile mempool policy (RFC-0012 §1): start empty and clear any legacy
        // on-disk mempool bytes from older builds. The mempool is never loaded
        // from disk; a restarted node re-acquires pending txs from peers.
        clear_persisted_mempool_snapshot(&chain.store)?;
        let mempool = Mempool::new();

        let (block_relay_tx, _) = tokio::sync::broadcast::channel(64);
        #[cfg(feature = "native-usdom-v4-poc")]
        let (native_usdom_v4_relay_tx, _) = tokio::sync::broadcast::channel(64);
        #[cfg(feature = "native-usdom-v4-poc")]
        let (native_usdom_v2_relay_tx, _) = tokio::sync::broadcast::channel(64);
        let (tx_fluff_tx, _) = tokio::sync::broadcast::channel::<Vec<u8>>(256);
        let (tx_stem_tx, _) =
            tokio::sync::broadcast::channel::<dom_wire::dandelion::StemEnvelope>(256);

        // Load the wallet if configured (DOM-SEC-004: mining requires one).
        //
        // The CLI (`dom-wallet init`) and the desktop wallet create wallets
        // as WalletDir DIRECTORIES (wallet.dat + config.json + wallet.lock +
        // journal) — the canonical on-disk format. The node only OPENS such a
        // directory; it never creates a wallet itself: the old Wallet::create
        // fallback produced a LEGACY keychain with no recoverable seed phrase,
        // silently mining rewards into a wallet that cannot be restored. A
        // missing or unopenable wallet therefore leaves mining disabled
        // (fail-closed) instead of creating anything.
        let wallet = if let (Some(wallet_path), Some(wallet_password)) =
            (&config.wallet_path, &config.wallet_password)
        {
            let path = Path::new(wallet_path);
            match WalletDir::open(path, wallet_password) {
                Ok(wallet_dir) => {
                    info!("Configured wallet loaded");
                    Some(Arc::new(Mutex::new(wallet_dir)))
                }
                Err(_error) => {
                    warn!(
                        "Could not open configured wallet; mining remains disabled \
                         (DOM-SEC-004 fail-closed)"
                    );
                    None
                }
            }
        } else {
            None
        };

        // NTP health check (Doc 4.5 mitigation 2)
        let metrics = Arc::new(Metrics::new());
        // dom_advertised_port (spec A5): what this node will announce in its
        // Hello. Published once — the value is fixed for the process lifetime
        // until A3 introduces runtime port mappings.
        metrics.advertised_port.store(
            u64::from(advertised_port(&config)),
            std::sync::atomic::Ordering::Relaxed,
        );
        match check_clock_health() {
            Ok(DriftStatus::Critical { drift_secs }) => {
                warn!(
                    "CLOCK DRIFT CRITICAL: {}s — mining disabled until clock is synchronized",
                    drift_secs
                );
                // Disable mining if drift is critical
                // config.mine = false; // config is not mut here — logged as warning
            }
            Ok(DriftStatus::Warning { drift_secs }) => {
                warn!(
                    "Clock drift warning: {}s — consider synchronizing NTP",
                    drift_secs
                );
            }
            Ok(DriftStatus::Healthy { drift_secs }) => {
                info!("Clock health OK: drift={}s", drift_secs);
            }
            Ok(DriftStatus::Unknown) => {
                warn!("Clock health unknown — NTP servers unreachable");
            }
            Err(e) => {
                warn!("Clock health check failed: {}", e);
            }
        }

        Ok(Self {
            noise_privkey,
            block_relay_tx,
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_relay_tx,
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v2_relay_tx,
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_runtime: None,
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_schedule: None,
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v2_runtime: None,
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_proof_admission: Arc::new(NativeProofAdmission::new()),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v2_schedule: None,
            #[cfg(feature = "native-usdom-v4-poc")]
            candidate_v2_first_height: None,
            #[cfg(feature = "native-usdom-v4-poc")]
            sync_attestation_collector: None,
            tx_fluff_tx,
            tx_stem_tx,
            config: config.clone(),
            chain: Arc::new(Mutex::new(chain)),
            mempool: Arc::new(Mutex::new(mempool)),
            peers: Arc::new(Mutex::new(peers)),
            dandelion: Arc::new(Mutex::new(DandelionRouter::new())),
            wallet,
            metrics,
            future_block_queue: Arc::new(crate::future_block_queue::FutureBlockQueue::new()),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_future_queue: Arc::new(NativeUsdomV4FutureQueue::new()),
            // Part A — persistent re-request: base backoff 2 rounds, doubling to
            // a 64-round ceiling (rounds advance on the ~2s catch-up tick), max 16
            // hashes per batch. A known-missing parent is re-requested forever
            // with this capped backoff, never abandoned after a fixed attempt
            // count. See missing_block_tracker.rs.
            missing_blocks: Arc::new(Mutex::new(MissingBlockTracker::new(
                2,
                64,
                CATCHUP_MAX_HASHES_PER_TICK,
            ))),
            orphan_pool: Arc::new(Mutex::new(RuntimeOrphanPool::new(
                DEFAULT_MAX_ORPHAN_BLOCKS,
                DEFAULT_MAX_ORPHANS_PER_PARENT,
            ))),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_orphan_pool: Arc::new(Mutex::new(RuntimeNativeUsdomV4OrphanPool::new(
                DEFAULT_MAX_ORPHAN_BLOCKS,
                DEFAULT_MAX_ORPHANS_PER_PARENT,
            ))),
            task_supervisor: NodeTaskSupervisor::new(),
            state_events: Arc::new(Notify::new()),
            ibd_active_sessions: Arc::new(AtomicU64::new(0)),
            bounded_rpc_mining_active: Arc::new(AtomicBool::new(false)),
            pex: Arc::new(Mutex::new(crate::pex::PexManager::for_network(
                PEX_MAX_KNOWN_PEERS,
                config.network,
            ))),
            prologue_prefs: Arc::new(crate::prologue_prefs::ProloguePreferences::default()),
            dialback: Arc::new(crate::dialback::DialbackLimiter::default()),
            live_advertised_port: Arc::new(AtomicU64::new(u64::from(advertised_port(&config)))),
        })
    }

    pub fn notify_state_changed(&self) {
        self.state_events.notify_waiters();
    }

    pub(crate) async fn refresh_runtime_metrics(
        chain: &Arc<Mutex<ChainState>>,
        mempool: &Arc<Mutex<Mempool>>,
        future_block_queue: &Arc<crate::future_block_queue::FutureBlockQueue>,
        metrics: &Metrics,
    ) {
        let chain_height = {
            let chain = chain.lock().await;
            chain.tip_height.0
        };
        metrics
            .chain_height
            .store(chain_height, std::sync::atomic::Ordering::Relaxed);

        let mempool_size = {
            let mempool = mempool.lock().await;
            mempool.len() as u64
        };
        metrics
            .mempool_size
            .store(mempool_size, std::sync::atomic::Ordering::Relaxed);

        let future_block_queue_size = future_block_queue.size().await as u64;
        metrics.future_block_queue_size.store(
            future_block_queue_size,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Request coordinated shutdown of live node tasks.
    pub async fn request_shutdown(&self) {
        tracing::info!("shutdown_requested");
        self.task_supervisor.request_shutdown().await;
    }

    /// Observe the node's live shutdown signal.
    pub fn shutdown_token(&self) -> ShutdownToken {
        self.task_supervisor.shutdown_token()
    }

    /// Rebuild a wallet's recoverable output set by scanning the canonical chain
    /// this node already has on disk, then persist the repaired state.
    ///
    /// This is the recovery path for a wallet restored from a seed phrase: the
    /// seed is the sole authority for ownership, but the on-chain coinbases it
    /// owns are only discoverable by walking the chain (see
    /// [`crate::wallet_scan`]). It is the missing step that left a freshly
    /// restored wallet at a zero balance even though the node had the matching
    /// coinbases synced.
    ///
    /// `wallet_dir` MUST be a DIFFERENT wallet directory than the one this node
    /// opened for mining (if any): we only read this node's chain store and
    /// write the passed-in wallet — never the node's own `wallet`, so no
    /// `WalletDir` lock is contended and the `Wallet` lock-order rank is not
    /// involved. The wallet must be unlocked (the deterministic scan derives the
    /// coinbase blinding from the encrypted seed).
    ///
    /// The tip is snapshotted and the blocks are read under the chain lock; the
    /// lock is released BEFORE the CPU-heavy deterministic rescan so block
    /// connection is not stalled while a long chain is re-derived.
    pub async fn rescan_wallet_dir(
        &self,
        wallet_dir: &mut WalletDir,
    ) -> Result<dom_wallet::WalletRescanSummary, DomError> {
        let scan = {
            let chain = self.chain.lock().await;
            let tip = chain.tip_height.0;
            crate::wallet_scan::collect_chain_scan(&chain.store, tip)?
        };
        wallet_dir
            .wallet_mut()
            .rescan_canonical_chain(&scan, dom_wallet::WalletRescanMode::Repair)
            .map_err(|e| DomError::Internal(format!("wallet rescan failed: {e}")))
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    async fn spawn_native_usdom_v4_future_queue_task(
        &self,
        supervisor: &NodeTaskSupervisor,
        shutdown: ShutdownToken,
    ) {
        if self.native_usdom_v4_runtime.is_none() && self.native_usdom_v2_runtime.is_none() {
            return;
        }
        let queue = self.native_usdom_v4_future_queue.clone();
        let v1_ingress =
            self.native_usdom_v4_runtime
                .as_ref()
                .map(|runtime| NativeUsdomV4Ingress {
                    chain: self.chain.clone(),
                    mempool: self.mempool.clone(),
                    runtime: runtime.clone(),
                    relay_tx: self.native_usdom_v4_relay_tx.clone(),
                    relay_exclude_peer: None,
                    wallet: self.wallet.clone(),
                    metrics: self.metrics.clone(),
                    future_block_queue: self.future_block_queue.clone(),
                    native_future_queue: queue.clone(),
                    state_events: self.state_events.clone(),
                    orphan_pool: self.native_usdom_v4_orphan_pool.clone(),
                    candidate_v2_first_height: self.candidate_v2_first_height,
                    migration_shutdown: Some(self.task_supervisor.clone()),
                    proof_admission: self.native_usdom_proof_admission.clone(),
                });
        let v2_ingress =
            self.native_usdom_v2_runtime
                .as_ref()
                .map(|runtime| NativeUsdomV2Ingress {
                    chain: self.chain.clone(),
                    mempool: self.mempool.clone(),
                    runtime: runtime.clone(),
                    relay_tx: self.native_usdom_v2_relay_tx.clone(),
                    relay_exclude_peer: None,
                    wallet: self.wallet.clone(),
                    metrics: self.metrics.clone(),
                    future_block_queue: self.future_block_queue.clone(),
                    native_future_queue: queue.clone(),
                    state_events: self.state_events.clone(),
                    orphan_pool: self.native_usdom_v4_orphan_pool.clone(),
                    proof_admission: self.native_usdom_proof_admission.clone(),
                });
        supervisor
            .spawn_critical(
                TaskKind::NativeFutureQueue,
                Box::pin(async move {
                    trace_task_result("native_usdom_future_queue_drain", async move {
                        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                            FUTURE_BLOCK_QUEUE_DRAIN_INTERVAL_SECS,
                        ));
                        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        loop {
                            tokio::select! {
                                _ = shutdown.wait() => return Ok(()),
                                _ = interval.tick() => {}
                            }
                            let now_secs = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            if let Some(ingress) = v1_ingress.as_ref() {
                                Box::pin(drain_native_usdom_v4_future_packages(
                                    &queue,
                                    Some(ingress),
                                    now_secs,
                                    Timestamp(now_secs),
                                ))
                                .await;
                            } else {
                                Box::pin(drain_native_usdom_v2_future_packages(
                                    &queue,
                                    v2_ingress.as_ref(),
                                    now_secs,
                                    Timestamp(now_secs),
                                ))
                                .await;
                            }
                        }
                    })
                    .await
                }),
            )
            .await;
    }

    /// Start all node services.
    pub async fn run(self: Arc<Self>) -> Result<(), DomError> {
        info!("Starting DOM node services");

        // Bootstrap the local genesis block on EVERY node, not just miners.
        //
        // The genesis is deterministic (a pure function of the network), so
        // every node derives the identical genesis hash. This MUST happen
        // before the peer connector starts IBD, because the proof-of-work seed
        // for epoch-0 blocks is the hash of the block at seed_height 0 — i.e.
        // the genesis. The miner seals epoch-0 blocks against the real genesis
        // hash (`get_hash_at_height(0)`), but a node that never committed its
        // own genesis falls back to a `[0u8; 32]` seed during IBD validation
        // (`compute_randomx_seed`/`_with_batch`). The two seeds disagree, so
        // every epoch-0 block fails PoW with "hash mismatch" and a non-mining
        // node can never sync from a miner. Previously genesis was created only
        // inside `mining_loop` (gated on `config.mine`), which is exactly why a
        // mining node worked but a sync-only node did not. Creating genesis
        // unconditionally here makes the seed consistent on both the mining and
        // validating paths. The `mining_loop` keeps its own idempotent check,
        // so this never double-creates.
        let needs_genesis = {
            let chain = self.chain.lock().await;
            chain.tip_height.0 == 0 && chain.tip_hash == dom_core::Hash256::ZERO
        };
        if needs_genesis {
            crate::miner::create_genesis_block(self.clone()).await?;
        }

        // ── Synchronous listener binds ──────────────────────────────────
        // Bind P2P and RPC sockets BEFORE spawning their accept loops, so
        // bind errors (EADDRINUSE, permission denied, malformed addr)
        // propagate to the caller via `Result<(), DomError>` instead of
        // being swallowed inside a detached task. Previous code spawned
        // `dom_rpc::serve(handle, addr)` (which binds internally) inside
        // `tokio::spawn`, so a stale-port collision on the RPC port turned
        // into a single `warn!` and the node ran indefinitely with a dead
        // RPC server — making readiness checks lie and external tooling
        // (curl/CLI/scripts) see ConnectionRefused with no explanation.
        let p2p_addr = self.config.p2p_listen_addr.clone();
        let p2p_listener = bind_p2p_listener(&p2p_addr).await?;
        info!("P2P listening on {p2p_addr}");

        // A3: ask the router to open our port, and keep the announcement
        // honest over time. Detached and fully bounded — the boot never
        // waits on a router (§1.4) and every probe runs under the module's
        // per-method timeout.
        if crate::portmap::portmap_enabled() {
            let internal_port = self
                .config
                .p2p_listen_addr
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .unwrap_or_else(|| self.config.network.default_port());
            let baseline_port = advertised_port(&self.config);
            let live_port = self.live_advertised_port.clone();
            let metrics = self.metrics.clone();
            let portmap_supervisor = self.task_supervisor.clone();
            let portmap_shutdown = portmap_supervisor.shutdown_token();
            portmap_supervisor
                .spawn(TaskKind::PortMap, async move {
                    loop {
                        let mapping = crate::portmap::try_map(internal_port).await;
                        // What to announce, and why the spec's "no mapping →
                        // announce 0" is refined here: "no gateway answered" is
                        // not evidence of a NAT. A hub on a public IP has no IGD
                        // and must keep announcing its listen port — writing 0
                        // there would blind the whole network's discovery. So:
                        // a granted, usable mapping announces the GRANTED port
                        // (R-A3.4); a mapping the internet cannot reach (CGNAT)
                        // announces 0, because there the NAT is proven and
                        // unreachable; no gateway keeps the configured baseline,
                        // and A4's dial-back by other nodes decides the truth.
                        let (port, code) = match mapping {
                            crate::portmap::Mapping::Upnp { .. } => (mapping.advertised_port(), 1),
                            crate::portmap::Mapping::NatPmp { .. } => {
                                (mapping.advertised_port(), 2)
                            }
                            crate::portmap::Mapping::CgnatDetected => (0, 3),
                            crate::portmap::Mapping::None => (baseline_port, 0),
                        };
                        live_port.store(u64::from(port), std::sync::atomic::Ordering::Relaxed);
                        metrics
                            .advertised_port
                            .store(u64::from(port), std::sync::atomic::Ordering::Relaxed);
                        metrics
                            .portmap_status_code
                            .store(code, std::sync::atomic::Ordering::Relaxed);
                        info!(
                            method = mapping.status_label(),
                            advertised_port = port,
                            "port mapping state"
                        );
                        // Renew at half-lease; with nothing to renew, retry at a
                        // slow cadence — which is also what recovers from a
                        // network change (R-A3.3), at that cadence.
                        let wait = mapping
                            .renew_interval()
                            .unwrap_or(std::time::Duration::from_secs(900));
                        tokio::select! {
                            () = portmap_shutdown.wait() => return Ok(()),
                            () = tokio::time::sleep(wait) => {}
                        }
                    }
                })
                .await;
        }

        let rpc_pair = if let Some(rpc_addr) = self.config.rpc_listen_addr.clone() {
            use crate::node_handle::NodeHandleImpl;
            let parsed: std::net::SocketAddr = rpc_addr.parse().map_err(|e| {
                DomError::Internal(format!("Invalid RPC listen addr {rpc_addr}: {e}"))
            })?;
            let listener = dom_rpc::bind(parsed)
                .await
                .map_err(|e| DomError::Internal(format!("RPC bind {parsed}: {e}")))?;
            let handle: Arc<dyn dom_rpc::NodeHandle> = Arc::new(NodeHandleImpl(self.clone()));
            Some((handle, listener, self.config.rpc_bearer_token.clone()))
        } else {
            None
        };
        let metrics_listener = bind_metrics_listener(&self.config).await?;

        // ── Supervised runtime tasks ────────────────────────────────────
        // Binds already succeeded; from here on long-lived services are
        // supervised so failures are observable and shutdown is coordinated.
        let supervisor = self.task_supervisor.clone();
        let shutdown = supervisor.shutdown_token();
        let node_listener = self.clone();
        let listener_supervisor = supervisor.clone();
        let listener_shutdown = shutdown.clone();
        supervisor
            .spawn_critical(
                TaskKind::Listener,
                Box::pin(async move {
                    trace_task_result("p2p_listener", async move {
                        Box::pin(node_listener.run_p2p_listener_on(
                            p2p_listener,
                            listener_supervisor,
                            listener_shutdown,
                        ))
                        .await
                    })
                    .await
                }),
            )
            .await;

        // Start outbound peer connector
        let node_connector = self.clone();
        let connector_supervisor = supervisor.clone();
        let connector_shutdown = shutdown.clone();
        supervisor
            .spawn_critical(
                TaskKind::Connector,
                Box::pin(async move {
                    trace_task_result("peer_connector", async move {
                        Box::pin(
                            node_connector
                                .run_peer_connector(connector_supervisor, connector_shutdown),
                        )
                        .await
                    })
                    .await
                }),
            )
            .await;

        // Start miner if enabled
        if self.config.mine {
            let node_miner = self.clone();
            let miner_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::Miner, async move {
                    trace_task_result("miner", async move {
                        mining_loop(node_miner, miner_shutdown)
                            .await
                            .map_err(|e| e.to_string())
                    })
                    .await
                })
                .await;
        }

        if let Some((handle, listener, rpc_bearer_token)) = rpc_pair {
            let rpc_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::Rpc, async move {
                    trace_task_result("rpc_server", async move {
                        dom_rpc::serve_with_token_until_shutdown(
                            handle,
                            listener,
                            rpc_bearer_token,
                            async move { rpc_shutdown.wait().await },
                        )
                        .await
                        .map_err(|e| format!("RPC server error: {e}"))
                    })
                    .await
                })
                .await;
        }

        if let Some(listener) = metrics_listener {
            let metrics_shutdown = shutdown.clone();
            let metrics = self.metrics.clone();
            supervisor
                .spawn_critical(TaskKind::Metrics, async move {
                    trace_task_result("metrics_server", async move {
                        tokio::select! {
                            _ = metrics_shutdown.wait() => Ok(()),
                            result = serve_metrics(listener, metrics) => {
                                result.map_err(|e| format!("metrics server error: {e}"))
                            }
                        }
                    })
                    .await
                })
                .await;
        }

        // future_block_queue drain loop — re-evaluate deferred blocks every 30s
        {
            let queue = self.future_block_queue.clone();
            let chain = self.chain.clone();
            let mempool = self.mempool.clone();
            let relay_tx = self.block_relay_tx.clone();
            let metrics = self.metrics.clone();
            let state_events = self.state_events.clone();
            let ready_window = future_block_ready_window(self.config.network);
            let future_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::FutureQueue, Box::pin(async move {
                    trace_task_result("future_block_queue_drain", async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                    FUTURE_BLOCK_QUEUE_DRAIN_INTERVAL_SECS,
                ));
                // Skip: replaying every missed maintenance tick after a stall
                // only repeats the same bounded queue scan in a burst.
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = future_shutdown.wait() => return Ok(()),
                        _ = interval.tick() => {}
                    }
                    let evicted = queue.evict_expired(FUTURE_BLOCK_QUEUE_MAX_AGE_SECS).await;
                    if evicted > 0 {
                        tracing::debug!(
                            "Evicted {evicted} expired deferred block(s) before replay drain"
                        );
                    }
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let now = dom_core::Timestamp(now_secs);
                    let ready = queue.drain_ready(now_secs, ready_window).await;
                    let drained_ready = ready.len();
                    for deferred in ready {
                        tracing::debug!("Re-evaluating deferred block ts={}", deferred.timestamp);
                        match decode_deferred_block_bytes(&deferred.block_bytes) {
                            Ok(block) => {
                                let result = {
                                    let mut c = trace_lock("chain", &chain).await;
                                    c.connect_block(&block, now)
                                };
                                match deferred_replay_action(&result) {
                                    DeferredReplayAction::RelayBestChain => {
                                        tracing::info!(
                                            event = "orphan_reprocessed",
                                            block_height = block.header.height.0,
                                            block_hash = %hex::encode(deferred.block_hash),
                                            action = "accepted_best_chain",
                                            failure_class = "runtime_deferred_replay",
                                            "deferred block reprocessed"
                                        );
                                        if let Ok(ref connect_result) = result {
                                            if let Err(e) = reconcile_mempool_after_connect(
                                                &chain,
                                                &mempool,
                                                connect_result,
                                                &block.transactions,
                                            )
                                            .await
                                            {
                                                tracing::warn!(
                                                    "Deferred block mempool reconciliation failed: {e}"
                                                );
                                            }
                                        }
                                        tracing::info!(
                                            "Accepted deferred block ts={} (new tip)",
                                            deferred.timestamp
                                        );
                                        if let Err(e) = purge_mempool_confirmed_inputs(
                                            &chain,
                                            &mempool,
                                            &block.transactions,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                "Deferred block confirmed-input purge failed: {e}"
                                            );
                                        }
                                        let _ = relay_tx.send(deferred.block_bytes);
                                        state_events.notify_waiters();
                                    }
                                    DeferredReplayAction::Drop => {
                                        if matches!(result, Ok(dom_chain::ConnectResult::SideChain))
                                        {
                                            tracing::info!(
                                                event = "orphan_reprocessed",
                                                block_height = block.header.height.0,
                                                block_hash = %hex::encode(deferred.block_hash),
                                                action = "accepted_side_chain_drop",
                                                failure_class = "runtime_deferred_replay",
                                                "deferred block reprocessed"
                                            );
                                            tracing::debug!(
                                                "Accepted deferred block ts={} (side chain — no rebroadcast)",
                                                deferred.timestamp
                                            );
                                        } else if matches!(
                                            result,
                                            Ok(dom_chain::ConnectResult::AlreadyHave)
                                        ) {
                                            tracing::trace!(
                                                "Deferred block ts={} already known — no-op",
                                                deferred.timestamp
                                            );
                                        } else if let Err(ref e) = result {
                                            tracing::debug!("Deferred block still rejected: {e}");
                                        }
                                    }
                                    DeferredReplayAction::Requeue => {
                                        tracing::info!(
                                            event = "orphan_reprocessed",
                                            block_height = block.header.height.0,
                                            block_hash = %hex::encode(deferred.block_hash),
                                            action = "requeue",
                                            failure_class = "runtime_deferred_replay",
                                            "deferred block reprocessed"
                                        );
                                        let requeued = queue
                                            .defer(crate::future_block_queue::DeferredBlock {
                                                block_hash: deferred.block_hash,
                                                block_height: deferred.block_height,
                                                timestamp: deferred.timestamp,
                                                queued_at: std::time::Instant::now(),
                                                block_bytes: deferred.block_bytes.clone(),
                                            })
                                            .await;
                                        if requeued {
                                            tracing::debug!(
                                                "Deferred block ts={} requeued after retryable rejection",
                                                deferred.timestamp
                                            );
                                        } else {
                                            tracing::warn!(
                                                "Deferred block ts={} could not be requeued (queue full)",
                                                deferred.timestamp
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                // Deferred queue entries are runtime-only and no longer
                                // attributable to a live peer. Malformed bytes must drop
                                // deterministically without requeueing or scoring anyone.
                                metrics
                                    .malformed_block_relays
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                tracing::warn!("Deferred block decode error: {e}");
                            }
                        }
                    }
                    if evicted > 0 || drained_ready > 0 {
                        DomNode::refresh_runtime_metrics(&chain, &mempool, &queue, &metrics)
                            .await;
                    }
                }
                    })
                    .await
            }))
                .await;
        }
        #[cfg(feature = "native-usdom-v4-poc")]
        Box::pin(self.spawn_native_usdom_v4_future_queue_task(&supervisor, shutdown.clone())).await;
        // Dandelion++ Stem-timeout promoter.
        //
        // Every STEM_CHECK_INTERVAL, walk the router and pull out any tx whose
        // stem timer expired. For each, re-look up the tx_bytes in the local
        // mempool, re-serialize them, and broadcast over the Fluff channel so
        // every peer receives the tx and the propagation completes.
        //
        // Without this task, a tx that entered Stem phase but whose target
        // peer disconnected would stay forever in the local stem map and
        // never reach the rest of the network — a privacy guarantee turned
        // into a liveness bug.
        {
            let dandelion = self.dandelion.clone();
            let mempool = self.mempool.clone();
            let tx_fluff_tx = self.tx_fluff_tx.clone();
            let metrics = self.metrics.clone();
            let dandelion_shutdown = shutdown.clone();
            supervisor
                .spawn_critical(TaskKind::DandelionStem, async move {
                    trace_task_result("dandelion_stem_timeout", async move {
                        const STEM_CHECK_INTERVAL_SECS: u64 = 5;
                        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                            STEM_CHECK_INTERVAL_SECS,
                        ));
                        // Skip: one current timeout scan promotes every expired
                        // stem; replaying historical ticks adds no liveness.
                        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        interval.tick().await; // skip first immediate tick
                        loop {
                            tokio::select! {
                                _ = dandelion_shutdown.wait() => return Ok(()),
                                _ = interval.tick() => {}
                            }
                            let timed_out: Vec<[u8; 32]> = {
                                let mut d = trace_lock("dandelion", &dandelion).await;
                                d.collect_timed_out()
                            };
                            if timed_out.is_empty() {
                                continue;
                            }
                            tracing::debug!(
                                "Dandelion: promoting {} stem-timed-out tx(s) to fluff",
                                timed_out.len()
                            );
                            use dom_serialization::DomSerialize;
                            for tx_hash in timed_out {
                                let tx_bytes_opt = {
                                    let m = trace_lock("mempool", &mempool).await;
                                    m.get_tx(&tx_hash).and_then(|e| e.tx.to_bytes().ok())
                                };
                                if let Some(tx_bytes) = tx_bytes_opt {
                                    if tx_fluff_tx.send(tx_bytes).is_ok() {
                                        metrics
                                            .txs_relayed
                                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    }
                                } else {
                                    tracing::debug!("stem-timed-out transaction no longer present");
                                }
                            }
                        }
                    })
                    .await
                })
                .await;
        }
        tracing::info!(
            event = "shutdown_completed",
            failure_class = "runtime_shutdown",
            "shutdown completed"
        );

        tokio::select! {
            _ = shutdown.wait() => {}
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|e| DomError::Internal(format!("install Ctrl-C handler: {e}")))?;
                supervisor.request_shutdown().await;
            }
        }
        tracing::info!(
            event = "shutdown_requested",
            reason = "shutdown_token",
            failure_class = "runtime_shutdown",
            "shutdown requested"
        );
        let failure = supervisor.failure().await;
        let report = supervisor
            .shutdown_ordered(Duration::from_secs(30), async {
                tracing::debug!("shutdown_persistence_drain");
            })
            .await;
        tracing::info!(
            event = "shutdown_completed",
            failure_class = "runtime_shutdown",
            aborted_tasks = report.aborted.len(),
            stopped_tasks = report.stopped_order.len(),
            "shutdown_completed"
        );

        if let Some(failure) = failure {
            Err(DomError::Internal(format!(
                "critical task {:?} failed: {}",
                failure.failure_task, failure.failure_reason
            )))
        } else {
            Ok(())
        }
    }

    /// Accept incoming P2P connections on an already-bound listener.
    ///
    /// Called by `run()` after `tokio::net::TcpListener::bind` has
    /// succeeded synchronously, so this loop never observes bind errors —
    /// only per-connection accept errors, which are logged and skipped.
    async fn run_p2p_listener_on(
        &self,
        listener: tokio::net::TcpListener,
        supervisor: NodeTaskSupervisor,
        shutdown: ShutdownToken,
    ) -> Result<(), String> {
        loop {
            let accepted = tokio::select! {
                _ = shutdown.wait() => return Ok(()),
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, peer_addr)) => {
                    info!("Inbound connection from {peer_addr}");
                    let reserved = {
                        let mut mgr = trace_lock("peers", &self.peers).await;
                        mgr.reserve_inbound(peer_addr)
                    };
                    if let Err(e) = reserved {
                        warn!("Rejecting connection from {peer_addr}: {e}");
                        continue;
                    }
                    // Spawn connection handler
                    let config = self.config.clone();
                    let privkey = self.noise_privkey.clone();
                    let chain = self.chain.clone();
                    let channels = BroadcastChannels {
                        block_relay_tx: self.block_relay_tx.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v4_relay_tx: self.native_usdom_v4_relay_tx.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v2_relay_tx: self.native_usdom_v2_relay_tx.clone(),
                        tx_fluff_tx: self.tx_fluff_tx.clone(),
                        tx_stem_tx: self.tx_stem_tx.clone(),
                    };
                    let svc = NodeServices {
                        mempool: self.mempool.clone(),
                        dandelion: self.dandelion.clone(),
                        peers: self.peers.clone(),
                        metrics: self.metrics.clone(),
                        future_block_queue: self.future_block_queue.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v4_future_queue: self.native_usdom_v4_future_queue.clone(),
                        missing_blocks: self.missing_blocks.clone(),
                        orphan_pool: self.orphan_pool.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v4_orphan_pool: self.native_usdom_v4_orphan_pool.clone(),
                        wallet: self.wallet.clone(),
                        state_events: self.state_events.clone(),
                        ibd_active_sessions: self.ibd_active_sessions.clone(),
                        pex: self.pex.clone(),
                        prologue_prefs: self.prologue_prefs.clone(),
                        dialback: self.dialback.clone(),
                        live_advertised_port: self.live_advertised_port.clone(),
                        task_supervisor: self.task_supervisor.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v4_enabled: self.native_usdom_v4_runtime.is_some(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v4_runtime: self.native_usdom_v4_runtime.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v4_schedule: self.native_usdom_v4_schedule,
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v2_enabled: self.native_usdom_v2_runtime.is_some(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v2_runtime: self.native_usdom_v2_runtime.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_proof_admission: self.native_usdom_proof_admission.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v2_schedule: self.native_usdom_v2_schedule,
                        #[cfg(feature = "native-usdom-v4-poc")]
                        candidate_v2_first_height: self.candidate_v2_first_height,
                        #[cfg(feature = "native-usdom-v4-poc")]
                        sync_attestation_collector: self.sync_attestation_collector.clone(),
                    };
                    let peers = svc.peers.clone();
                    let metrics = svc.metrics.clone();
                    let state_events = svc.state_events.clone();
                    let chain_for_persist = chain.clone();
                    let peer_shutdown = shutdown.clone();
                    let task_id = supervisor
                        .spawn_relay(async move {
                            trace_task_result("p2p_inbound_session", async move {
                                let registered_session = handle_inbound(
                                    stream,
                                    peer_addr,
                                    config,
                                    privkey,
                                    chain,
                                    channels,
                                    svc,
                                    peer_shutdown,
                                )
                                .await;
                                let mut mgr = trace_lock("peers", &peers).await;
                                let peer_key = peer_addr.to_string();
                                if let Some(session_id) = registered_session {
                                    mgr.remove_peer_session(&peer_key, session_id);
                                }
                                mgr.release_inbound_reservation(&peer_addr);
                                drop(mgr);
                                if let Err(e) =
                                    persist_peer_reputation_state(&chain_for_persist, &peers).await
                                {
                                    warn!("Persisting peer reputation state failed: {e}");
                                }
                                refresh_peer_metrics(&peers, &metrics, Some(&state_events)).await;
                                Ok(())
                            })
                            .await
                        })
                        .await;
                    tracing::debug!(?task_id, peer = %peer_addr, "inbound_peer_task_registered");
                }
                Err(e) => {
                    warn!("Accept error: {e}");
                }
            }
        }
    }

    /// Connect to peers (DNS seeds + configured peers).
    async fn run_peer_connector(
        &self,
        supervisor: NodeTaskSupervisor,
        shutdown: ShutdownToken,
    ) -> Result<(), String> {
        let svc = NodeServices {
            mempool: self.mempool.clone(),
            dandelion: self.dandelion.clone(),
            peers: self.peers.clone(),
            metrics: self.metrics.clone(),
            future_block_queue: self.future_block_queue.clone(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_future_queue: self.native_usdom_v4_future_queue.clone(),
            missing_blocks: self.missing_blocks.clone(),
            orphan_pool: self.orphan_pool.clone(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_orphan_pool: self.native_usdom_v4_orphan_pool.clone(),
            wallet: self.wallet.clone(),
            state_events: self.state_events.clone(),
            ibd_active_sessions: self.ibd_active_sessions.clone(),
            pex: self.pex.clone(),
            prologue_prefs: self.prologue_prefs.clone(),
            dialback: self.dialback.clone(),
            live_advertised_port: self.live_advertised_port.clone(),
            task_supervisor: self.task_supervisor.clone(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_enabled: self.native_usdom_v4_runtime.is_some(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_runtime: self.native_usdom_v4_runtime.clone(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v4_schedule: self.native_usdom_v4_schedule,
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v2_enabled: self.native_usdom_v2_runtime.is_some(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v2_runtime: self.native_usdom_v2_runtime.clone(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_proof_admission: self.native_usdom_proof_admission.clone(),
            #[cfg(feature = "native-usdom-v4-poc")]
            native_usdom_v2_schedule: self.native_usdom_v2_schedule,
            #[cfg(feature = "native-usdom-v4-poc")]
            candidate_v2_first_height: self.candidate_v2_first_height,
            #[cfg(feature = "native-usdom-v4-poc")]
            sync_attestation_collector: self.sync_attestation_collector.clone(),
        };
        let mut configured_seed_ip_cache = HashMap::<String, HashSet<std::net::IpAddr>>::new();
        loop {
            if shutdown.is_shutdown() {
                return Ok(());
            }
            let needs_more = {
                let mgr = trace_lock("peers", &self.peers).await;
                mgr.needs_outbound()
            };

            if needs_more {
                if let Err(e) = advance_peer_rotation_cooldowns(&self.chain, &self.peers).await {
                    warn!("Advancing peer rotation cooldowns failed: {e}");
                }
                let mut addrs = resolve_configured_dns_seeds(&self.config).await;
                let resolved_seed_ips = refresh_configured_seed_ips(
                    &self.config.seed_peers,
                    &mut configured_seed_ip_cache,
                )
                .await;
                let mut mgr = trace_lock("peers", &self.peers).await;
                mgr.set_seed_ips(resolved_seed_ips);
                drop(mgr);

                // Also try configured seed peers
                addrs.extend(self.config.seed_peers.iter().cloned());
                // PEX: seed the known-peer table with the bootstrap addresses,
                // drop entries with too many failed dials, and add
                // gossip-learned peers as outbound candidates. Guard dropped
                // before any await below.
                {
                    let mut px = trace_lock("pex", &self.pex).await;
                    px.seed_from_config(&addrs);
                    px.evict_dead_peers();
                    addrs.extend(px.connectable_peers().iter().map(|p| p.addr.clone()));
                }
                addrs.sort();
                addrs.dedup();
                addrs = {
                    let mgr = trace_lock("peers", &self.peers).await;
                    mgr.outbound_candidates_in_retry_order(addrs)
                };

                for addr in addrs {
                    let (reserved, failure_count, cooldown_rounds) = {
                        let mut mgr = trace_lock("peers", &self.peers).await;
                        if !mgr.needs_outbound() {
                            (
                                false,
                                mgr.outbound_failure_count(&addr),
                                mgr.outbound_cooldown_rounds(&addr),
                            )
                        } else {
                            let failure_count = mgr.outbound_failure_count(&addr);
                            let cooldown_rounds = mgr.outbound_cooldown_rounds(&addr);
                            (
                                mgr.reserve_outbound(&addr).is_ok(),
                                failure_count,
                                cooldown_rounds,
                            )
                        }
                    };
                    if !reserved {
                        continue;
                    }
                    tracing::info!(
                        event = "reconnect_attempt",
                        peer_addr = %addr,
                        failure_count,
                        cooldown_rounds,
                        failure_class = "operational_network",
                        "outbound reconnect attempt scheduled"
                    );

                    let config = self.config.clone();
                    let privkey = self.noise_privkey.clone();
                    let chain = self.chain.clone();
                    let channels = BroadcastChannels {
                        block_relay_tx: self.block_relay_tx.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v4_relay_tx: self.native_usdom_v4_relay_tx.clone(),
                        #[cfg(feature = "native-usdom-v4-poc")]
                        native_usdom_v2_relay_tx: self.native_usdom_v2_relay_tx.clone(),
                        tx_fluff_tx: self.tx_fluff_tx.clone(),
                        tx_stem_tx: self.tx_stem_tx.clone(),
                    };
                    info!("Connecting to peer {addr}");
                    let cleanup_addr = addr.clone();
                    let log_addr = cleanup_addr.clone();
                    let peers = self.peers.clone();
                    let metrics = self.metrics.clone();
                    let state_events = self.state_events.clone();
                    let svc_c = svc.clone();
                    let pex = self.pex.clone();
                    let chain_for_persist = self.chain.clone();
                    let peer_shutdown = shutdown.clone();
                    let task_id = supervisor
                        .spawn_relay(async move {
                            trace_task_result("p2p_outbound_session", async move {
                                let outcome = connect_outbound(
                                    &addr,
                                    config,
                                    privkey,
                                    chain,
                                    channels,
                                    svc_c,
                                    peer_shutdown,
                                )
                                .await;
                                if outcome == OutboundAttemptOutcome::RetryableFailure {
                                    // PEX learns the failed dial so dead
                                    // gossiped addresses get evicted.
                                    trace_lock("pex", &pex).await.record_failure(&cleanup_addr);
                                }
                                let mut mgr = trace_lock("peers", &peers).await;
                                if outcome == OutboundAttemptOutcome::RetryableFailure {
                                    mgr.record_outbound_failure(&cleanup_addr);
                                }
                                mgr.remove_outbound_session(&cleanup_addr);
                                mgr.release_outbound_reservation(&cleanup_addr);
                                drop(mgr);
                                if let Err(e) =
                                    persist_peer_rotation_state(&chain_for_persist, &peers).await
                                {
                                    warn!("Persisting peer rotation state failed: {e}");
                                }
                                if let Err(e) =
                                    persist_peer_reputation_state(&chain_for_persist, &peers).await
                                {
                                    warn!("Persisting peer reputation state failed: {e}");
                                }
                                refresh_peer_metrics(&peers, &metrics, Some(&state_events)).await;
                                Ok(())
                            })
                            .await
                        })
                        .await;
                    tracing::debug!(?task_id, peer = %log_addr, "outbound_peer_task_registered");
                }
            }

            tokio::select! {
                _ = shutdown.wait() => return Ok(()),
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(
                    dom_wire::manager::OUTBOUND_RECONNECT_POLICY.initial_delay_secs,
                )) => {}
            }
        }
    }
}

impl dom_rpc::NodeHandle for DomNode {
    fn chain_height(&self) -> u64 {
        self.chain.try_lock().map(|c| c.tip_height.0).unwrap_or(0)
    }

    fn mempool_size(&self) -> usize {
        self.mempool.try_lock().map(|m| m.len()).unwrap_or(0)
    }

    fn network(&self) -> &'static str {
        self.config.network.as_str()
    }

    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
        self.mempool
            .try_lock()
            .map(|m| m.all_hashes())
            .unwrap_or_default()
    }

    fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<dom_rpc::MempoolTxInfo> {
        let pool = self.mempool.try_lock().ok()?;
        let entry = pool.get_tx(hash)?;
        let fee = entry.tx.total_fee().ok()?;
        let weight = entry.tx.weight();
        Some(dom_rpc::MempoolTxInfo {
            tx_hash: *hash,
            fee,
            fee_rate: if weight > 0 { fee / weight as u64 } else { 0 },
            weight,
            kernels: entry
                .tx
                .kernels
                .iter()
                .map(|kernel| dom_rpc::KernelInfo {
                    features: kernel.features,
                    lock_height: kernel.lock_height,
                })
                .collect(),
        })
    }

    fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<dom_rpc::TxAdmission, dom_rpc::RpcError> {
        use dom_serialization::DomDeserialize;
        let tx = dom_consensus::Transaction::from_bytes(&tx_bytes)
            .map_err(|e| dom_rpc::RpcError::InvalidHex(format!("invalid tx: {e}")))?;
        // A2-008: this snapshots the chain view under the chain lock, then
        // releases it before admitting to the mempool — a benign TOCTOU window.
        // The mempool is volatile, non-consensus relay state; a tx admitted
        // against a stale view is never trusted downstream: connect_block
        // re-validates every mined block against the real chain (miner.rs, the
        // final finalize step) and rejects it if an input was spent in the gap,
        // and each Dandelion++ peer re-validates on relay. Closing the window
        // would require holding the chain and mempool locks jointly across
        // admission, against the explicit lock hierarchy (see lock_order.rs) —
        // deadlock/contention risk for no consensus benefit. Acknowledged, not
        // fixed.
        let chain_view = {
            let chain = self
                .chain
                .try_lock()
                .map_err(|_| dom_rpc::RpcError::Internal("chain locked".into()))?;
            snapshot_tx_chain_view(&chain, &tx)
                .map_err(|e| dom_rpc::RpcError::Rejected(e.to_string()))?
        };
        let hash = {
            let data = tx_bytes.clone();
            *dom_crypto::hash::blake2b_256(&data).as_bytes()
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut pool = self
            .mempool
            .try_lock()
            .map_err(|_| dom_rpc::RpcError::Internal("mempool locked".into()))?;
        pool.accept_tx_with_chain_view(
            tx,
            hash,
            now,
            chain_view.current_height,
            chain_view.chain_id,
            chain_view.coinbase_maturity,
            |commitment| Ok(chain_view.utxos.get(commitment).cloned().flatten()),
        )
        .map_err(|e| dom_rpc::RpcError::Rejected(e.to_string()))?;
        self.metrics
            .txs_received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.metrics
            .mempool_size
            .store(pool.len() as u64, std::sync::atomic::Ordering::Relaxed);
        drop(pool);
        self.notify_state_changed();
        let chain = self
            .chain
            .try_lock()
            .map_err(|_| dom_rpc::RpcError::Internal("chain locked".into()))?;
        clear_persisted_mempool_snapshot(&chain.store)
            .map_err(|e| dom_rpc::RpcError::Internal(format!("persist mempool: {e}")))?;

        let (phase, stem_target) =
            if let (Ok(mut d), Ok(p)) = (self.dandelion.try_lock(), self.peers.try_lock()) {
                let peers: Vec<std::net::SocketAddr> = p
                    .connected_peers()
                    .into_iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                let phase = d.route_new_tx(hash, &peers);
                let target = d.get_stem_peer(&hash);
                (phase, target)
            } else {
                (dom_wire::dandelion::DandelionPhase::Fluff, None)
            };
        use dom_wire::dandelion::{DandelionPhase, StemEnvelope};
        let relayed = match phase {
            DandelionPhase::Suppressed => false,
            DandelionPhase::Fluff => self.tx_fluff_tx.send(tx_bytes.clone()).is_ok(),
            DandelionPhase::Stem => {
                if let Some(target) = stem_target {
                    self.tx_stem_tx
                        .send(StemEnvelope {
                            target_peer: target,
                            tx_bytes: tx_bytes.clone(),
                        })
                        .is_ok()
                } else {
                    self.tx_fluff_tx.send(tx_bytes.clone()).is_ok()
                }
            }
        };
        if relayed {
            self.metrics
                .txs_relayed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            info!("transaction accepted but no relay subscriber was available");
        }

        Ok(dom_rpc::TxAdmission {
            tx_hash: hash,
            relayed,
            state: dom_rpc::TxAdmissionState::New,
        })
    }

    fn get_block_header(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let chain = self.chain.try_lock().ok()?;
        chain.store.get_block_header(hash).ok()?
    }

    fn get_block_kernels(&self, hash: &[u8; 32]) -> Option<Vec<dom_rpc::KernelInfo>> {
        use dom_serialization::DomDeserialize;

        let chain = self.chain.try_lock().ok()?;
        let body = chain.store.get_block_body(hash).ok()??;
        let block = dom_consensus::Block::from_bytes(&body).ok()?;
        Some(
            block
                .transactions
                .iter()
                .flat_map(|tx| tx.kernels.iter())
                .map(|kernel| dom_rpc::KernelInfo {
                    features: kernel.features,
                    lock_height: kernel.lock_height,
                })
                .collect(),
        )
    }

    fn get_block_hash_at_height(&self, height: u64) -> Option<[u8; 32]> {
        let chain = self.chain.try_lock().ok()?;
        chain.store.get_hash_at_height(height).ok()?
    }

    fn get_utxo(&self, commitment: &[u8; 33]) -> Option<dom_rpc::UtxoInfo> {
        let chain = self.chain.try_lock().ok()?;
        let tip_height = chain.tip_height.0;
        let entry = chain.store.get_utxo(commitment).ok()??;
        Some(dom_rpc::UtxoInfo {
            commitment: hex::encode(commitment),
            block_height: entry.block_height,
            is_coinbase: entry.is_coinbase,
            is_mature: entry.is_mature(tip_height),
        })
    }

    /// See `node_handle::peer_dto`. This site used to mirror the same defect
    /// with the opposite constant (`"inbound"` for every peer, and a
    /// `connected_since` of 0), so the two `/peers` implementations disagreed
    /// with each other as well as with `/metrics`.
    fn get_peers(&self) -> Vec<dom_rpc::PeerInfo> {
        let Ok(peers) = self.peers.try_lock() else {
            return Vec::new();
        };
        peers
            .connected_peer_infos()
            .into_iter()
            .map(crate::node_handle::peer_dto)
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_inbound(
    mut stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    config: NodeConfig,
    privkey: Zeroizing<[u8; 32]>,
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
    shutdown: ShutdownToken,
) -> Option<u64> {
    let BroadcastChannels {
        block_relay_tx,
        #[cfg(feature = "native-usdom-v4-poc")]
        native_usdom_v4_relay_tx,
        #[cfg(feature = "native-usdom-v4-poc")]
        native_usdom_v2_relay_tx,
        tx_fluff_tx,
        tx_stem_tx,
    } = channels.clone();
    // Derive chain_id from network magic + canonical genesis hash.
    let genesis_hash = match config.network {
        dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        dom_config::Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    let chain_id =
        *derive_chain_id(config.network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes();
    // Strategy B (spec A1): lead with what per-peer memory says. The prologue
    // cannot be probed — a mismatch only surfaces after message 2 is written —
    // so a wrong guess costs this connection, and recovery happens when the
    // peer redials (its dial loop treats handshake failure as retryable).
    let prologue_version = node_prologue_version(
        native_usdom_is_enabled(&svc) || sync_tip_transport_is_enabled(&svc),
        svc.prologue_prefs.version_for(addr.ip()),
    );
    let transport = match tokio::select! {
        _ = shutdown.wait() => return None,
        result = dom_wire::handshake::perform_handshake_responder_versioned(
            &mut stream,
            &privkey,
            prologue_version,
            config.network.magic(),
            &chain_id,
        ) => result,
    } {
        Ok(t) => {
            svc.prologue_prefs
                .record_success(addr.ip(), prologue_version);
            t
        }
        Err(e) => {
            // Only an AEAD transcript failure is evidence about the prologue.
            // Anything else — a readiness probe closing, a scanner, a timeout
            // — says nothing about versions, and demoting on it would let any
            // connect-and-close visitor walk this IP's real peers down to the
            // oldest version (a poisoned readiness probe surfaced exactly
            // that).
            if dom_wire::handshake::is_prologue_mismatch(&e) {
                if let Some(next) = svc
                    .prologue_prefs
                    .demote_after_failure(addr.ip(), prologue_version)
                {
                    // Expected during the version transition, so it must not
                    // feed the ban machinery: penalising it would cool down
                    // exactly the peer whose reconnection completes the
                    // negotiation.
                    info!(
                        "Handshake with {addr} failed on prologue v{prologue_version}; \
                         will offer v{next} when this peer reconnects: {e}"
                    );
                } else {
                    let _ = record_pending_peer_violation(&chain, &svc.peers, addr, &e).await;
                    warn!("Handshake failed with {addr} on every supported version: {e}");
                }
            } else {
                let _ = record_pending_peer_violation(&chain, &svc.peers, addr, &e).await;
                warn!("Handshake failed with {addr}: {e}");
            }
            return None;
        }
    };
    info!("Noise handshake complete with {addr} (prologue v{prologue_version})");

    let mut codec = dom_wire::codec::NoiseCodec::new(transport, config.network.magic());
    match tokio::select! {
        _ = shutdown.wait() => return None,
        result = hello_exchange(
            &mut stream,
            &mut codec,
            &config,
            &chain_id,
            &chain,
            HelloSession {
                advertised_port: svc.live_advertised_port.load(std::sync::atomic::Ordering::Relaxed) as u16,
                wire_version: prologue_version,
                local_capabilities: local_wire_capabilities(&svc, prologue_version),
            },
        ) => result,
    } {
        Ok(peer_hello) => {
            let native_session_negotiated =
                dom_wire::message::native_usdom_v4_capability_negotiated(
                    prologue_version,
                    local_wire_capabilities(&svc, prologue_version),
                    peer_hello.capabilities,
                );
            let native_v2_session_negotiated =
                dom_wire::message::native_usdom_v2_capability_negotiated(
                    prologue_version,
                    local_wire_capabilities(&svc, prologue_version),
                    peer_hello.capabilities,
                );
            let _sync_tip_session_negotiated = dom_wire::message::sync_tip_v1_capability_negotiated(
                prologue_version,
                local_wire_capabilities(&svc, prologue_version),
                peer_hello.capabilities,
            );
            if native_session_negotiated && native_v2_session_negotiated {
                warn!("peer {addr} negotiated mutually exclusive USDOM phases");
                return None;
            }
            let peer_id = codec.peer_id();
            info!(
                "Hello from {addr}: peer_id={} height={} hash={} ua={:?}",
                peer_id
                    .map(hex::encode)
                    .unwrap_or_else(|| "unavailable".into()),
                peer_hello.best_height,
                hex::encode(peer_hello.best_hash),
                peer_hello.user_agent
            );
            // Register peer in manager so connected_peers() sees it
            let registered_session = {
                use dom_wire::peer::PeerInfo;
                let mut peer_info = PeerInfo::new(addr, false);
                let session_id = peer_info.session_id;
                peer_info.peer_id = peer_id;
                peer_info.state = dom_wire::peer::PeerState::Connected;
                peer_info.best_height = peer_hello.best_height;
                peer_info.best_hash = peer_hello.best_hash;
                peer_info.user_agent = peer_hello.user_agent.clone();
                let result = svc.peers.lock().await.register_peer(peer_info);
                info!("register_peer inbound {addr} → {result:?}");
                if let Err(e) = result {
                    warn!("Failed to register inbound peer {addr}: {e}");
                    return None;
                }
                session_id
            };
            if let Err(e) = persist_peer_rotation_state(&chain, &svc.peers).await {
                warn!("Persisting peer rotation state after inbound registration failed: {e}");
            }
            if let Err(e) = persist_peer_reputation_state(&chain, &svc.peers).await {
                warn!("Persisting peer reputation state after inbound registration failed: {e}");
            }
            // The source port of an inbound TCP connection is ephemeral. Learn
            // the peer's IP on the port it ADVERTISED in its Hello as an
            // *unconfirmed* candidate; only a later successful outbound dial
            // makes it PEX shareable. This is the "coordinated
            // version/handshake migration" the previous comment here promised:
            // PROTOCOL_VERSION 3 carries the field (spec A1), and a v2 peer
            // decodes as advertised_port 0 — declared unreachable — which
            // learn_inbound_peer counts but keeps out of the dial pool, in
            // place of the old guess of the default network port that filled
            // every pool with ip:33369 entries nobody was listening on
            // (spec A2). The IP is the connection's source address, never one
            // taken from the payload.
            {
                let mut pex = trace_lock("pex", &svc.pex).await;
                pex.learn_inbound_peer(addr.ip(), peer_hello.advertised_port);
                refresh_pex_metrics(&pex, &svc.metrics);
            }
            // A4: the announced port is a hypothesis until it answers from
            // the outside — routers acknowledge mappings they never honour
            // (R-A3.2), and peers can lie. Dial back and only a completed
            // connection confirms the address for gossip. The target IP is
            // the socket's source address; the payload contributed only the
            // port, and an unusable one never got past learn_inbound_peer.
            // The limiter enforces one probe per source IP per window and a
            // global concurrency cap (R-A4.1); a refused probe just leaves
            // the address unconfirmed, which is the safe state.
            if peer_hello.advertised_port != 0
                && dom_wire::message::sane_advertised_port(peer_hello.advertised_port)
            {
                spawn_dialback_probe(
                    svc.task_supervisor.clone(),
                    addr.ip(),
                    peer_hello.advertised_port,
                    svc.dialback.clone(),
                    svc.pex.clone(),
                    svc.metrics.clone(),
                )
                .await;
            }
            refresh_peer_metrics(&svc.peers, &svc.metrics, Some(&svc.state_events)).await;
            // An inbound peer with a taller chain is a normal IBD source.
            // For equal-height fork resolution, however, the inbound side must
            // remain in `message_loop` to serve the outbound peer's locator.
            // If both sides start IBD after the Hello exchange, both wait for
            // Headers and the connection deadlocks.  The outbound side is the
            // single deterministic requester for equal-height reconciliation.
            let our_height = {
                let chain = chain.lock().await;
                chain.tip_height.0
            };
            if peer_hello.best_height > our_height {
                let ibd_result = tokio::select! {
                    _ = shutdown.wait() => return Some(registered_session),
                    result = run_ibd_session(
                        &mut stream,
                        &mut codec,
                        &config,
                        &chain,
                        &svc.mempool,
                        addr,
                        peer_hello.best_height,
                        false,
                        svc.future_block_queue.clone(),
                        svc.metrics.clone(),
                        svc.wallet.clone(),
                        svc.state_events.clone(),
                        channels.clone(),
                        native_session_negotiated,
                        native_v2_session_negotiated,
                        svc.clone(),
                    ) => result,
                };
                match ibd_result {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = record_peer_violation(&chain, &svc.peers, addr, &e).await;
                        warn!("IBD with {addr} failed: {e}");
                        return Some(registered_session);
                    }
                }
            }
            if let Err(e) = message_loop(
                PeerConn {
                    stream: &mut stream,
                    codec: &mut codec,
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v4_negotiated: native_session_negotiated,
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v2_negotiated: native_v2_session_negotiated,
                    #[cfg(feature = "native-usdom-v4-poc")]
                    sync_tip_v1_negotiated: _sync_tip_session_negotiated,
                },
                &config,
                addr,
                chain.clone(),
                BroadcastChannels {
                    block_relay_tx: block_relay_tx.clone(),
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v4_relay_tx: native_usdom_v4_relay_tx.clone(),
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v2_relay_tx: native_usdom_v2_relay_tx.clone(),
                    tx_fluff_tx: tx_fluff_tx.clone(),
                    tx_stem_tx: tx_stem_tx.clone(),
                },
                svc.clone(),
                shutdown.clone(),
            )
            .await
            {
                // Anti-slowloris: a write that timed out means the peer stalled
                // our sends. recv-side errors are already scored inline before
                // they propagate, so score ONLY write timeouts here to avoid
                // double-counting.
                if is_write_timeout(&e) {
                    let _ = record_peer_violation(&chain, &svc.peers, addr, &e).await;
                }
                let local_height = chain.lock().await.tip_height.0;
                tracing::info!(
                    event = "session_closed_reason",
                    peer_addr = %addr,
                    peer_id = %peer_id.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
                    direction = "inbound",
                    reason = %e,
                    failure_class = "operational_network",
                    ibd_active = svc.ibd_active_sessions.load(std::sync::atomic::Ordering::Acquire) > 0,
                    local_height,
                    remote_height = peer_hello.best_height,
                    remaining_blocks = peer_hello.best_height.saturating_sub(local_height),
                    "peer session closed"
                );
                info!("Connection to {addr} closed: {e}");
            }
            Some(registered_session)
        }
        Err(e) => {
            let _ = record_pending_peer_violation(&chain, &svc.peers, addr, &e).await;
            warn!("Hello exchange with {addr} failed: {e}");
            None
        }
    }
}

async fn connect_outbound(
    addr: &str,
    config: NodeConfig,
    privkey: Zeroizing<[u8; 32]>,
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
    shutdown: ShutdownToken,
) -> OutboundAttemptOutcome {
    let BroadcastChannels {
        block_relay_tx,
        #[cfg(feature = "native-usdom-v4-poc")]
        native_usdom_v4_relay_tx,
        #[cfg(feature = "native-usdom-v4-poc")]
        native_usdom_v2_relay_tx,
        tx_fluff_tx,
        tx_stem_tx,
    } = channels.clone();
    let genesis_hash = match config.network {
        dom_config::Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        dom_config::Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        dom_config::Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    let chain_id =
        *derive_chain_id(config.network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes();
    // Strategy B (spec A1): a failed prologue poisons both the Noise state and
    // the TCP connection — the responder has already seen bytes it could not
    // authenticate — so each fallback version needs a fresh connection. Lead
    // with what per-peer memory says (the newest for an unknown peer) and walk
    // down on failure; only a peer that fails on every supported version is
    // recorded as misbehaving.
    //
    // The version memory is keyed by IP, and a seed configured by name
    // (`seed2.dom-protocol.org:33369`) does not parse as a `SocketAddr` — so
    // the IP has to come off the connected socket instead. Deriving it from
    // the config string left every DNS-seed dial without memory *and* without
    // fallback, failing forever against a peer the same host reached fine when
    // PEX handed it over as a bare IP.
    let config_ip = addr
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|socket| socket.ip());
    // Fallback walk for the rare connection whose socket cannot even name the
    // peer; everything with an IP rides the keyed memory instead, which
    // `demote_after_failure` updates synchronously.
    let mut unkeyed_version: Option<u32> = None;
    let (mut stream, transport, prologue_version) = loop {
        let mut stream = match tokio::select! {
            _ = shutdown.wait() => return OutboundAttemptOutcome::Shutdown,
            result = tokio::time::timeout(
                Duration::from_secs(OUTBOUND_CONNECT_TIMEOUT_SECS),
                tokio::net::TcpStream::connect(addr),
            ) => match result {
                Ok(result) => result,
                Err(_) => {
                    warn!(
                        "Connection to {addr} timed out after \
                         {OUTBOUND_CONNECT_TIMEOUT_SECS}s"
                    );
                    return OutboundAttemptOutcome::RetryableFailure;
                }
            },
        } {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    event = "session_closed_reason",
                    peer_addr = %addr,
                    direction = "outbound",
                    reason = %e,
                    failure_class = "operational_network",
                    "outbound connection failed"
                );
                warn!("Connection to {addr} failed: {e}");
                return OutboundAttemptOutcome::RetryableFailure;
            }
        };
        // A DNS name can resolve to several backends and each reconnect may
        // land on a different one, so ask the socket every time: both the
        // version led with and any demotion recorded below must belong to the
        // endpoint this connection actually reached, not to whichever backend
        // the first attempt happened to hit.
        let peer_ip = config_ip.or_else(|| stream.peer_addr().ok().map(|socket| socket.ip()));
        let prologue_version = match peer_ip {
            Some(ip) => node_prologue_version(
                native_usdom_is_enabled(&svc) || sync_tip_transport_is_enabled(&svc),
                svc.prologue_prefs.version_for(ip),
            ),
            None => node_prologue_version(
                native_usdom_is_enabled(&svc) || sync_tip_transport_is_enabled(&svc),
                unkeyed_version.unwrap_or(dom_wire::handshake::SUPPORTED_PROLOGUE_VERSIONS[0]),
            ),
        };
        match tokio::select! {
            _ = shutdown.wait() => return OutboundAttemptOutcome::Shutdown,
            result = dom_wire::handshake::perform_handshake_initiator_versioned(
                &mut stream,
                &privkey,
                prologue_version,
                config.network.magic(),
                &chain_id,
            ) => result,
        } {
            Ok(t) => {
                if let Some(ip) = peer_ip {
                    svc.prologue_prefs.record_success(ip, prologue_version);
                }
                break (stream, t, prologue_version);
            }
            Err(e) => {
                // Same evidence rule as the responder: only an AEAD failure
                // is about the prologue. A dead seed timing out must not walk
                // the dialer through every version against a host that never
                // answered Noise in the first place.
                let fallback = if dom_wire::handshake::is_prologue_mismatch(&e) {
                    match peer_ip {
                        Some(ip) => svc
                            .prologue_prefs
                            .demote_after_failure(ip, prologue_version),
                        // No IP to key memory by: walk the supported list
                        // directly so even this connection still gets its
                        // one-version-per-attempt fallback.
                        None => dom_wire::handshake::SUPPORTED_PROLOGUE_VERSIONS
                            .iter()
                            .position(|v| *v == prologue_version)
                            .and_then(|idx| {
                                dom_wire::handshake::SUPPORTED_PROLOGUE_VERSIONS.get(idx + 1)
                            })
                            .copied(),
                    }
                } else {
                    None
                };
                match fallback {
                    Some(next) => {
                        // Expected once per cross-version pair during the
                        // transition; reconnect immediately with the older
                        // prologue rather than waiting a full retry cycle.
                        info!(
                            "Handshake with {addr} failed on prologue v{prologue_version}; \
                             reconnecting with v{next}: {e}"
                        );
                        unkeyed_version = Some(next);
                        continue;
                    }
                    None => {
                        if let Ok(peer_addr) = addr.parse() {
                            let _ =
                                record_pending_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                        }
                        warn!("Handshake failed with {addr}: {e}");
                        return OutboundAttemptOutcome::RetryableFailure;
                    }
                }
            }
        }
    };
    info!("Connected to {addr} (prologue v{prologue_version})");

    let mut codec = dom_wire::codec::NoiseCodec::new(transport, config.network.magic());
    match tokio::select! {
        _ = shutdown.wait() => return OutboundAttemptOutcome::Shutdown,
        result = hello_exchange(
            &mut stream,
            &mut codec,
            &config,
            &chain_id,
            &chain,
            HelloSession {
                advertised_port: svc.live_advertised_port.load(std::sync::atomic::Ordering::Relaxed) as u16,
                wire_version: prologue_version,
                local_capabilities: local_wire_capabilities(&svc, prologue_version),
            },
        ) => result,
    } {
        Ok(peer_hello) => {
            let native_session_negotiated =
                dom_wire::message::native_usdom_v4_capability_negotiated(
                    prologue_version,
                    local_wire_capabilities(&svc, prologue_version),
                    peer_hello.capabilities,
                );
            let native_v2_session_negotiated =
                dom_wire::message::native_usdom_v2_capability_negotiated(
                    prologue_version,
                    local_wire_capabilities(&svc, prologue_version),
                    peer_hello.capabilities,
                );
            let _sync_tip_session_negotiated = dom_wire::message::sync_tip_v1_capability_negotiated(
                prologue_version,
                local_wire_capabilities(&svc, prologue_version),
                peer_hello.capabilities,
            );
            if native_session_negotiated && native_v2_session_negotiated {
                warn!("peer {addr} negotiated mutually exclusive USDOM phases");
                return OutboundAttemptOutcome::RetryableFailure;
            }
            let peer_id = codec.peer_id();
            info!(
                "Hello from {addr}: peer_id={} height={} hash={} ua={:?}",
                peer_id
                    .map(hex::encode)
                    .unwrap_or_else(|| "unavailable".into()),
                peer_hello.best_height,
                hex::encode(peer_hello.best_hash),
                peer_hello.user_agent
            );
            let sock_addr: std::net::SocketAddr = match addr.parse() {
                Ok(a) => a,
                Err(_) => match stream.peer_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!("Cannot determine addr for register_peer: {e}");
                        return OutboundAttemptOutcome::RetryableFailure;
                    }
                },
            };
            let canonical_addr = sock_addr.to_string();
            // Register peer in manager so connected_peers() sees it
            {
                use dom_wire::peer::PeerInfo;
                let mut peer_info = PeerInfo::new(sock_addr, true);
                let session_id = peer_info.session_id;
                peer_info.peer_id = peer_id;
                peer_info.state = dom_wire::peer::PeerState::Connected;
                peer_info.best_height = peer_hello.best_height;
                peer_info.best_hash = peer_hello.best_hash;
                peer_info.user_agent = peer_hello.user_agent.clone();
                let mut peers = svc.peers.lock().await;
                if let Some(peer_id) = peer_id {
                    peers.note_peer_identity(addr, peer_id);
                }
                let result = peers.register_peer(peer_info);
                info!("register_peer outbound {addr} → {result:?}");
                if let Err(e) = result {
                    warn!("Failed to register outbound peer {addr}: {e}");
                    return OutboundAttemptOutcome::RetryableFailure;
                }
                peers.bind_outbound_session(addr, &canonical_addr, session_id);
            }
            // A completed Noise + Hello exchange proves this dial target is
            // reachable. Promote it from an unconfirmed PEX candidate and only
            // now refresh last_seen for future Addr responses.
            {
                let mut pex = trace_lock("pex", &svc.pex).await;
                pex.mark_connected(&canonical_addr);
                refresh_pex_metrics(&pex, &svc.metrics);
            }
            if let Err(e) = persist_peer_rotation_state(&chain, &svc.peers).await {
                warn!("Persisting peer rotation state after outbound registration failed: {e}");
            }
            if let Err(e) = persist_peer_reputation_state(&chain, &svc.peers).await {
                warn!("Persisting peer reputation state after outbound registration failed: {e}");
            }
            refresh_peer_metrics(&svc.peers, &svc.metrics, Some(&svc.state_events)).await;
            let peer_addr = match stream.peer_addr() {
                Ok(a) => a,
                Err(_) => {
                    warn!("Could not resolve peer_addr for {addr}");
                    return OutboundAttemptOutcome::RetryableFailure;
                }
            };

            // IBD loop: keep syncing while peer claims to be ahead.
            let (our_height, our_hash) = {
                let chain = chain.lock().await;
                (chain.tip_height.0, *chain.tip_hash.as_bytes())
            };
            if let Some(fork_resolution) = sync_mode_for_peer(
                our_height,
                our_hash,
                peer_hello.best_height,
                peer_hello.best_hash,
            ) {
                let ibd_result = tokio::select! {
                    _ = shutdown.wait() => return OutboundAttemptOutcome::Shutdown,
                    result = run_ibd_session(
                        &mut stream,
                        &mut codec,
                        &config,
                        &chain,
                        &svc.mempool,
                        peer_addr,
                        peer_hello.best_height,
                        fork_resolution,
                        svc.future_block_queue.clone(),
                        svc.metrics.clone(),
                        svc.wallet.clone(),
                        svc.state_events.clone(),
                        channels.clone(),
                        native_session_negotiated,
                        native_v2_session_negotiated,
                        svc.clone(),
                    ) => result,
                };
                match ibd_result {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
                        warn!("IBD with {addr} failed: {e}");
                        return OutboundAttemptOutcome::RetryableFailure;
                    }
                }
            }

            if let Err(e) = message_loop(
                PeerConn {
                    stream: &mut stream,
                    codec: &mut codec,
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v4_negotiated: native_session_negotiated,
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v2_negotiated: native_v2_session_negotiated,
                    #[cfg(feature = "native-usdom-v4-poc")]
                    sync_tip_v1_negotiated: _sync_tip_session_negotiated,
                },
                &config,
                peer_addr,
                chain.clone(),
                BroadcastChannels {
                    block_relay_tx: block_relay_tx.clone(),
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v4_relay_tx: native_usdom_v4_relay_tx.clone(),
                    #[cfg(feature = "native-usdom-v4-poc")]
                    native_usdom_v2_relay_tx: native_usdom_v2_relay_tx.clone(),
                    tx_fluff_tx: tx_fluff_tx.clone(),
                    tx_stem_tx: tx_stem_tx.clone(),
                },
                svc.clone(),
                shutdown.clone(),
            )
            .await
            {
                // Anti-slowloris: a write that timed out means the peer stalled
                // our sends. recv-side errors are already scored inline before
                // they propagate, so score ONLY write timeouts here to avoid
                // double-counting.
                if is_write_timeout(&e) {
                    let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
                }
                let local_height = chain.lock().await.tip_height.0;
                tracing::info!(
                    event = "session_closed_reason",
                    peer_addr = %addr,
                    peer_id = %peer_id.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
                    direction = "outbound",
                    reason = %e,
                    failure_class = "operational_network",
                    ibd_active = svc.ibd_active_sessions.load(std::sync::atomic::Ordering::Acquire) > 0,
                    local_height,
                    remote_height = peer_hello.best_height,
                    remaining_blocks = peer_hello.best_height.saturating_sub(local_height),
                    "peer session closed"
                );
                info!("Connection to {addr} closed: {e}");
            }
            OutboundAttemptOutcome::Registered
        }
        Err(e) => {
            let peer_addr = match stream.peer_addr() {
                Ok(a) => a,
                Err(_) => match addr.parse() {
                    Ok(a) => a,
                    Err(_) => {
                        warn!("Hello exchange with {addr} failed: {e}");
                        return OutboundAttemptOutcome::RetryableFailure;
                    }
                },
            };
            let _ = record_pending_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
            warn!("Hello exchange with {addr} failed: {e}");
            OutboundAttemptOutcome::RetryableFailure
        }
    }
}

/// Perform the Hello message exchange after the Noise handshake completes.
///
/// Sends our Hello with our current tip, receives theirs, and validates:
/// - protocol version matches
/// - network_magic matches
/// - chain_id matches (same network, same genesis)
///
/// Returns the peer's HelloPayload on success.
async fn hello_exchange(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain_id: &[u8; 32],
    chain: &Arc<Mutex<ChainState>>,
    session: HelloSession,
) -> Result<dom_wire::message::HelloPayload, DomError> {
    tokio::time::timeout(
        tokio::time::Duration::from_secs(HELLO_EXCHANGE_TIMEOUT_SECS),
        hello_exchange_inner(stream, codec, config, chain_id, chain, session),
    )
    .await
    .map_err(|_| {
        DomError::peer_misbehavior(
            PeerMisbehavior::HelloTimeout,
            format!("hello timeout after {HELLO_EXCHANGE_TIMEOUT_SECS}s"),
        )
    })?
}

fn node_user_agent() -> String {
    format!("dom-node/{}", env!("CARGO_PKG_VERSION"))
}

fn local_wire_capabilities(svc: &NodeServices, wire_version: u32) -> u64 {
    wire_capabilities(
        native_usdom_v4_is_enabled(svc),
        native_usdom_v2_is_enabled(svc),
        sync_tip_transport_is_enabled(svc),
        wire_version,
    )
}

fn sync_tip_transport_is_enabled(svc: &NodeServices) -> bool {
    #[cfg(feature = "native-usdom-v4-poc")]
    {
        let _ = svc;
        true
    }
    #[cfg(not(feature = "native-usdom-v4-poc"))]
    {
        let _ = svc;
        false
    }
}

fn native_usdom_v4_is_enabled(svc: &NodeServices) -> bool {
    #[cfg(feature = "native-usdom-v4-poc")]
    {
        svc.native_usdom_v4_enabled
    }
    #[cfg(not(feature = "native-usdom-v4-poc"))]
    {
        let _ = svc;
        false
    }
}

fn native_usdom_v2_is_enabled(svc: &NodeServices) -> bool {
    #[cfg(feature = "native-usdom-v4-poc")]
    {
        svc.native_usdom_v2_enabled
    }
    #[cfg(not(feature = "native-usdom-v4-poc"))]
    {
        let _ = svc;
        false
    }
}

fn native_usdom_is_enabled(svc: &NodeServices) -> bool {
    native_usdom_v4_is_enabled(svc) || native_usdom_v2_is_enabled(svc)
}

fn node_prologue_version(native_usdom_v4_enabled: bool, candidate: u32) -> u32 {
    if !native_usdom_v4_enabled && candidate >= 4 {
        dom_core::WIRE_PROTOCOL_VERSION
    } else {
        candidate
    }
}

fn wire_capabilities(
    v1_enabled: bool,
    v2_enabled: bool,
    sync_tip_enabled: bool,
    wire_version: u32,
) -> u64 {
    if wire_version != 4 {
        return 0;
    }
    let mut capabilities = if v1_enabled == v2_enabled {
        0
    } else if v1_enabled {
        dom_wire::message::CAPABILITY_NATIVE_USDOM_V4
    } else {
        dom_wire::message::CAPABILITY_NATIVE_USDOM_V2
    };
    if sync_tip_enabled {
        capabilities |= dom_wire::message::CAPABILITY_SYNC_TIP_V1;
    }
    capabilities
}

#[cfg(feature = "native-usdom-v4-poc")]
fn require_native_usdom_v4_negotiation(negotiated: bool) -> Result<(), DomError> {
    if negotiated {
        Ok(())
    } else {
        Err(DomError::Malformed(
            "native USDOM v4 package received without negotiated capability [ban+20]".into(),
        ))
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn require_native_usdom_v2_negotiation(negotiated: bool) -> Result<(), DomError> {
    if negotiated {
        Ok(())
    } else {
        Err(DomError::Malformed(
            "native USDOM V2 package received without negotiated capability [ban+20]".into(),
        ))
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn should_relay_native_usdom_v4(
    negotiated: bool,
    peer_addr: std::net::SocketAddr,
    exclude_peer: Option<std::net::SocketAddr>,
) -> bool {
    negotiated && exclude_peer != Some(peer_addr)
}

#[cfg(feature = "native-usdom-v4-poc")]
fn native_usdom_v4_relay_message(
    network_magic: u32,
    negotiated: bool,
    peer_addr: std::net::SocketAddr,
    relay: NativeUsdomV4Relay,
) -> Option<dom_wire::message::WireMessage> {
    should_relay_native_usdom_v4(negotiated, peer_addr, relay.exclude_peer).then_some(
        dom_wire::message::WireMessage {
            magic: network_magic,
            command: dom_wire::message::Command::UsdomV4Package,
            payload: relay.wire_payload,
        },
    )
}

#[cfg(feature = "native-usdom-v4-poc")]
fn native_usdom_v2_relay_message(
    network_magic: u32,
    negotiated: bool,
    peer_addr: std::net::SocketAddr,
    relay: NativeUsdomV2Relay,
) -> Option<dom_wire::message::WireMessage> {
    should_relay_native_usdom_v4(negotiated, peer_addr, relay.exclude_peer).then_some(
        dom_wire::message::WireMessage {
            magic: network_magic,
            command: dom_wire::message::Command::UsdomV2Package,
            payload: relay.wire_payload,
        },
    )
}

/// The port this node tells peers to reach it on (spec A1).
///
/// `DOM_ADVERTISED_PORT` wins when set, because the externally reachable port
/// is not knowable from inside the process whenever a NAT, a container
/// publish, or a manual forward remaps it — the listen socket only knows the
/// inside of that mapping. Otherwise the listen port is the best available
/// answer.
///
/// Returns 0 — "not reachable" — rather than a guess whenever the value is
/// unusable: an unparseable address, or a port that
/// [`sane_advertised_port`](dom_wire::message::sane_advertised_port) refuses.
/// A wrong port is worse than no port: peers would spend their dial budget on
/// an address that cannot answer, while 0 simply keeps this node out of the
/// pool until A3/A4 can establish a real mapping.
fn advertised_port(config: &NodeConfig) -> u16 {
    let port = match std::env::var("DOM_ADVERTISED_PORT") {
        Ok(raw) => match raw.trim().parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    value = %raw,
                    "DOM_ADVERTISED_PORT is not a valid port; advertising unreachable"
                );
                return 0;
            }
        },
        Err(_) => config
            .p2p_listen_addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(0),
    };
    if dom_wire::message::sane_advertised_port(port) {
        port
    } else {
        tracing::warn!(port, "refusing to advertise a privileged port");
        0
    }
}

async fn hello_exchange_inner(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain_id: &[u8; 32],
    chain: &Arc<Mutex<ChainState>>,
    session: HelloSession,
) -> Result<dom_wire::message::HelloPayload, DomError> {
    use dom_wire::message::{Command, HelloPayload, WireMessage};

    // Snapshot our tip under the lock.
    let (best_height, best_hash) = {
        let c = chain.lock().await;
        (c.tip_height.0, *c.tip_hash.as_bytes())
    };

    // The Hello mirrors the session's negotiated prologue version: deployed
    // v2 peers reject both `version != 2` and any trailing bytes (R-A1.1).
    let our_hello = HelloPayload {
        version: session.wire_version,
        network_magic: config.network.magic(),
        chain_id: *chain_id,
        best_height,
        best_hash,
        user_agent: node_user_agent(),
        local_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        advertised_port: session.advertised_port,
        capabilities: session.local_capabilities,
    };

    let msg = WireMessage {
        magic: config.network.magic(),
        command: Command::Hello,
        payload: our_hello.to_bytes_for_wire_version(session.wire_version)?,
    };
    codec.send(stream, &msg).await?;

    let peer_msg = codec.recv(stream).await?;
    if peer_msg.command != Command::Hello {
        return Err(DomError::Invalid(format!(
            "expected Hello, got {:?}",
            peer_msg.command
        )));
    }
    let peer_hello = HelloPayload::from_bytes(&peer_msg.payload)?;

    if !dom_wire::handshake::SUPPORTED_PROLOGUE_VERSIONS.contains(&peer_hello.version) {
        return Err(DomError::Invalid(format!(
            "unsupported protocol version: ours={:?} theirs={}",
            dom_wire::handshake::SUPPORTED_PROLOGUE_VERSIONS,
            peer_hello.version
        )));
    }
    // Compare against the prologue selected for this connection, not against
    // the build's maximum. Version fallback happens across fresh Noise
    // connections; inside one authenticated transcript the Hello shape must
    // identify that exact version or capability bits would be ambiguous.
    if peer_hello.version != session.wire_version {
        return Err(DomError::Invalid(format!(
            "hello/prologue version mismatch: prologue={} hello={}",
            session.wire_version, peer_hello.version
        )));
    }
    if peer_hello.network_magic != config.network.magic() {
        return Err(DomError::peer_misbehavior(
            PeerMisbehavior::WrongChainId,
            format!(
                "network_magic mismatch: ours=0x{:08x} theirs=0x{:08x}",
                config.network.magic(),
                peer_hello.network_magic
            ),
        ));
    }
    if peer_hello.chain_id != *chain_id {
        return Err(DomError::peer_misbehavior(
            PeerMisbehavior::WrongChainId,
            "chain_id mismatch",
        ));
    }

    // Peer time discipline evaluation (Doc 4.5 mitigation 3)
    let our_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Note: scorer not available here — log drift for now
    // Full integration requires passing scorer or metrics into hello_exchange
    let drift = our_ts.abs_diff(peer_hello.local_timestamp);
    if drift > dom_core::PEER_DRIFT_DISCONNECT_SECS as u64 {
        return Err(DomError::Invalid(format!(
            "peer clock drift too large: {}s (limit {}s)",
            drift,
            dom_core::PEER_DRIFT_DISCONNECT_SECS
        )));
    }
    if drift > dom_core::PEER_DRIFT_WARN_SECS as u64 {
        warn!("Peer clock drift warning: {}s for peer at exchange", drift);
    }

    Ok(peer_hello)
}

fn peer_violation_score(error: &DomError) -> Option<u32> {
    use dom_wire::peer::ban_scores;

    match error {
        DomError::Malformed(_) => Some(ban_scores::MALFORMED_MESSAGE),
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::AddressFlooding,
            ..
        } => Some(ban_scores::ADDRESS_FLOODING),
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::HandshakeTimeout,
            ..
        } => Some(ban_scores::PROTOCOL_VIOLATION),
        // Anti-slowloris write timeout (dom_wire::codec::NoiseCodec::send): a peer
        // that stops reading stalls our writes. Low severity — a slow peer is not
        // necessarily malicious, so it is a protocol violation, not a ban-on-sight.
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::WriteTimeout,
            ..
        } => Some(ban_scores::PROTOCOL_VIOLATION),
        // Anti-flood per-category message rate limit (crate::msg_rate_limit): a
        // peer flooding valid-but-excessive messages. Low severity — sustained
        // overflow (~10 windows) is what crosses the ban threshold.
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::MessageRateLimit,
            ..
        } => Some(ban_scores::PROTOCOL_VIOLATION),
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::WrongChainId,
            ..
        } => Some(ban_scores::WRONG_CHAIN_ID),
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::UnexpectedHello,
            ..
        } => Some(ban_scores::PROTOCOL_VIOLATION),
        // Severity routing for expensive-to-detect consensus violations: a peer
        // forcing full PoW/signature validation on garbage must not score the
        // same 10 points as a cheap protocol slip (audit: P2P CPU-burn).
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::InvalidPow,
            ..
        } => Some(ban_scores::INVALID_POW),
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::InvalidSignature,
            ..
        } => Some(ban_scores::INVALID_SIGNATURE),
        DomError::Invalid(_) => Some(ban_scores::PROTOCOL_VIOLATION),
        _ => None,
    }
}

/// Annotate a `codec.send` failure with which broadcast/message kind failed,
/// for diagnostics — WITHOUT burying the anti-slowloris write-timeout type. A
/// `PeerMisbehavior(WriteTimeout)` is passed through unchanged so it still
/// routes through [`peer_violation_score`]; everything else (broken pipe,
/// encrypt) is our/transport side and is wrapped as `Internal` (unscored).
fn annotate_send_err(kind: &str, peer_addr: std::net::SocketAddr, e: DomError) -> DomError {
    match &e {
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::WriteTimeout,
            ..
        } => e,
        _ => DomError::Internal(format!("{kind} send to {peer_addr}: {e}")),
    }
}

/// Preserve the error class for a Dandelion++ stem write without recording
/// either the selected hop or the fact that this peer was selected for stem.
/// Those two fields, combined with wall-clock logs, identify the private relay
/// edge that Dandelion++ is intended to hide from routine telemetry.
fn redact_stem_send_err(e: DomError) -> DomError {
    match &e {
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::WriteTimeout,
            ..
        } => e,
        _ => DomError::Internal("private transaction relay write failed".into()),
    }
}

/// Whether an error escaping `message_loop` is the anti-slowloris write timeout.
/// Used to score it at the loop boundary WITHOUT double-scoring recv-side errors
/// (which are already scored inline before they propagate).
fn is_write_timeout(error: &DomError) -> bool {
    matches!(
        error,
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::WriteTimeout,
            ..
        }
    )
}

fn pending_peer_violation_score(error: &DomError) -> Option<u32> {
    match error {
        DomError::TemporarilyInvalid(_) | DomError::Orphan(_) | DomError::Internal(_) => None,
        DomError::PeerMisbehavior {
            kind: PeerMisbehavior::HelloTimeout,
            ..
        } => Some(dom_wire::peer::ban_scores::PROTOCOL_VIOLATION),
        other => peer_violation_score(other),
    }
}

async fn record_peer_violation(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
    peer_addr: std::net::SocketAddr,
    error: &DomError,
) -> bool {
    let Some(score) = peer_violation_score(error) else {
        return false;
    };

    let peer_key = peer_addr.to_string();
    let (banned, previous_score, accumulated_score) = {
        let mut mgr = trace_lock("peers", peers).await;
        let previous = mgr.ban_score(&peer_key).unwrap_or(0);
        let banned = mgr.add_ban_score(&peer_key, score);
        let accumulated = mgr.ban_score(&peer_key).unwrap_or(previous);
        (banned, previous, accumulated)
    };
    if let Err(e) = persist_peer_reputation_state(chain, peers).await {
        warn!("Persisting peer reputation state failed: {e}");
    }

    if previous_score < dom_wire::peer::ban_scores::BAN_THRESHOLD
        && accumulated_score >= dom_wire::peer::ban_scores::BAN_THRESHOLD
    {
        warn!(
            event = "peer_ban_threshold_crossed",
            peer = %peer_addr,
            reason = %error,
            accumulated_score,
            "peer reputation crossed the ban threshold"
        );
    } else if banned {
        warn!("Peer {peer_addr} banned after protocol violation: {error}");
    } else {
        warn!("Peer {peer_addr} protocol violation (+{score}): {error}");
    }

    banned
}

async fn record_pending_peer_violation(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
    peer_addr: std::net::SocketAddr,
    error: &DomError,
) -> bool {
    let Some(score) = pending_peer_violation_score(error) else {
        return false;
    };

    let peer_key = peer_addr.to_string();
    let (banned, previous_score, accumulated_score) = {
        let mut mgr = trace_lock("peers", peers).await;
        let previous = mgr.pending_ban_score(&peer_key);
        let accumulated = mgr.add_pending_ban_score(&peer_key, score);
        (
            accumulated >= dom_wire::peer::ban_scores::BAN_THRESHOLD,
            previous,
            accumulated,
        )
    };
    if let Err(e) = persist_peer_reputation_state(chain, peers).await {
        warn!("Persisting peer reputation state failed: {e}");
    }

    if previous_score < dom_wire::peer::ban_scores::BAN_THRESHOLD
        && accumulated_score >= dom_wire::peer::ban_scores::BAN_THRESHOLD
    {
        warn!(
            event = "pending_peer_ban_threshold_crossed",
            peer = %peer_addr,
            reason = %error,
            accumulated_score,
            "pending peer reputation crossed the ban threshold"
        );
    } else if banned {
        warn!("Pending peer {peer_addr} banned after pre-registration violation: {error}");
    } else {
        warn!("Pending peer {peer_addr} violation (+{score}): {error}");
    }

    banned
}

async fn queue_future_block(
    queue: &Arc<crate::future_block_queue::FutureBlockQueue>,
    block: &dom_consensus::Block,
    _received_block_bytes: Vec<u8>,
) -> bool {
    use dom_serialization::DomSerialize;

    let header_bytes = match block.header.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("Could not serialise deferred block header: {e}");
            return false;
        }
    };
    let hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    let canonical_block_bytes = match block.to_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!("Could not serialise deferred block: {e}");
            return false;
        }
    };
    let deferred = crate::future_block_queue::DeferredBlock {
        block_hash: hash,
        block_height: block.header.height.0,
        timestamp: block.header.timestamp.0,
        queued_at: std::time::Instant::now(),
        block_bytes: canonical_block_bytes,
    };
    let admission = queue.admit(deferred).await;
    let admitted = admission.is_admitted();
    tracing::info!(
        event = "orphan_admitted",
        block_height = block.header.height.0,
        block_hash = %hex::encode(hash),
        action = ?admission,
        failure_class = "runtime_future_block",
        "future block queue admission decided"
    );
    admitted
}

fn deferred_replay_action(
    result: &Result<dom_chain::ConnectResult, DomError>,
) -> DeferredReplayAction {
    match result {
        Ok(dom_chain::ConnectResult::BestChain) | Ok(dom_chain::ConnectResult::Reorg(_)) => {
            DeferredReplayAction::RelayBestChain
        }
        Ok(dom_chain::ConnectResult::SideChain) | Ok(dom_chain::ConnectResult::AlreadyHave) => {
            DeferredReplayAction::Drop
        }
        Err(DomError::TemporarilyInvalid(_)) | Err(DomError::Orphan(_)) => {
            DeferredReplayAction::Requeue
        }
        Err(_) => DeferredReplayAction::Drop,
    }
}

fn relay_block_action(result: &Result<dom_chain::ConnectResult, DomError>) -> RelayBlockAction {
    match result {
        Ok(dom_chain::ConnectResult::BestChain) | Ok(dom_chain::ConnectResult::Reorg(_)) => {
            RelayBlockAction::RelayBestChain
        }
        Ok(dom_chain::ConnectResult::SideChain)
        | Ok(dom_chain::ConnectResult::AlreadyHave)
        | Err(DomError::TemporarilyInvalid(_))
        | Err(DomError::Orphan(_)) => RelayBlockAction::Suppress,
        Err(DomError::Invalid(_))
        | Err(DomError::Malformed(_))
        | Err(DomError::PeerMisbehavior { .. }) => RelayBlockAction::PenalizePeer,
        Err(_) => RelayBlockAction::Drop,
    }
}

fn tx_hash(tx: &Transaction) -> Result<[u8; 32], DomError> {
    use dom_serialization::DomSerialize;

    let tx_bytes = tx.to_bytes()?;
    Ok(*dom_crypto::hash::blake2b_256(&tx_bytes).as_bytes())
}

fn block_hash(block: &dom_consensus::Block) -> Result<[u8; 32], DomError> {
    use dom_serialization::DomSerialize;

    let header_bytes = block.header.to_bytes()?;
    Ok(*dom_crypto::hash::blake2b_256(&header_bytes).as_bytes())
}

fn collect_spent_commitments(transactions: &[Transaction]) -> Vec<[u8; 33]> {
    let mut spent = Vec::with_capacity(transactions.iter().map(|tx| tx.inputs.len()).sum());
    for tx in transactions {
        for input in &tx.inputs {
            spent.push(*input.commitment.as_bytes());
        }
    }
    spent
}

/// Collect, in canonical order, the transactions from disconnected blocks that
/// remain valid under the **new** canonical chain and may be reinjected into the
/// live mempool (RFC-0012 §3).
///
/// Reinjection affects transaction *availability* only; it never affects block
/// validity (RFC-0012 invariant I-1). A candidate is excluded if it is a
/// coinbase/system transaction (§3.2), spends an input that is no longer a live
/// (and, for coinbase, mature) UTXO, or whose outputs/kernels already exist on the
/// surviving branch. Survivors are sorted by `tx_hash` ascending so the
/// reinjection batch — and therefore the resulting mempool — is independent of the
/// order in which the disconnected transactions were originally delivered.
/// Double-spends among survivors are then resolved deterministically by the
/// mempool's input-reservation check (first in hash order wins).
fn collect_reinjectable_reorg_txs(
    chain: &ChainState,
    delta: &dom_chain::ReorgDelta,
) -> Result<Vec<ReinjectableTx>, DomError> {
    let mut reinject = Vec::new();
    for tx in &delta.disconnected_txs {
        // RFC-0012 §3.2: exclude coinbase/system transactions. The canonical
        // coinbase is already structurally excluded (`disconnected_txs` is built
        // from `block.transactions`, never `block.coinbase`); this guard also
        // drops any regular transaction carrying a coinbase kernel feature, which
        // is a system output that must never re-enter the relay mempool.
        let is_coinbase_or_system = tx
            .kernels
            .iter()
            .any(|kernel| kernel.features & dom_core::KERNEL_FEAT_COINBASE != 0);
        if is_coinbase_or_system {
            continue;
        }

        let inputs_are_live = tx.inputs.iter().all(|input| {
            let commitment = input.commitment.as_bytes();
            match chain.store.get_utxo(commitment) {
                Ok(Some(entry)) => {
                    !entry.is_coinbase
                        || entry.is_mature_for(chain.tip_height.0, chain.coinbase_maturity)
                }
                Ok(None) => false,
                Err(_) => false,
            }
        });
        if !inputs_are_live {
            continue;
        }

        let outputs_are_fresh = tx.outputs.iter().all(|output| {
            chain
                .store
                .get_utxo(output.commitment.as_bytes())
                .map(|entry| entry.is_none())
                .unwrap_or(false)
        });
        if !outputs_are_fresh {
            continue;
        }

        let kernels_are_fresh = tx.kernels.iter().all(|kernel| {
            chain
                .store
                .get_kernel_block(kernel.excess.as_bytes())
                .map(|entry| entry.is_none())
                .unwrap_or(false)
        });
        if !kernels_are_fresh {
            continue;
        }

        reinject.push(ReinjectableTx {
            tx: tx.clone(),
            tx_hash: tx_hash(tx)?,
            now_secs: chain.tip_height.0,
            chain_view: snapshot_tx_chain_view(chain, tx)?,
        });
    }
    reinject.sort_unstable_by_key(|entry| entry.tx_hash);
    Ok(reinject)
}

pub(crate) async fn reconcile_mempool_after_connect(
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    connect_result: &dom_chain::ConnectResult,
    connected_block_txs: &[Transaction],
) -> Result<(), DomError> {
    let (spent_commitments, reinjectable) = {
        let chain = chain.lock().await;
        match connect_result {
            dom_chain::ConnectResult::BestChain => {
                (collect_spent_commitments(connected_block_txs), Vec::new())
            }
            dom_chain::ConnectResult::Reorg(delta) => (
                collect_spent_commitments(&delta.connected_txs),
                collect_reinjectable_reorg_txs(&chain, delta)?,
            ),
            dom_chain::ConnectResult::SideChain | dom_chain::ConnectResult::AlreadyHave => {
                return Ok(());
            }
        }
    };

    let mut mempool = mempool.lock().await;
    if !spent_commitments.is_empty() {
        mempool.remove_confirmed(&spent_commitments);
    }
    if !reinjectable.is_empty() {
        for tx in reinjectable {
            let chain_view = tx.chain_view;
            let _ = mempool.accept_tx_with_chain_view(
                tx.tx,
                tx.tx_hash,
                tx.now_secs,
                chain_view.current_height,
                chain_view.chain_id,
                chain_view.coinbase_maturity,
                |commitment| Ok(chain_view.utxos.get(commitment).cloned().flatten()),
            );
        }
    }
    drop(mempool);

    let chain = chain.lock().await;
    clear_persisted_mempool_snapshot(&chain.store)
}

#[cfg(feature = "native-usdom-v4-poc")]
async fn apply_wallet_after_canonical_connect(
    wallet: Option<&Arc<Mutex<WalletDir>>>,
    connect_result: &dom_chain::ConnectResult,
    connected_block_txs: &[Transaction],
    connected_height: u64,
    connected_hash: [u8; 32],
) {
    let Some(wallet) = wallet else {
        return;
    };
    let mut wallet_dir = wallet.lock().await;
    let wallet = wallet_dir.wallet_mut();
    match connect_result {
        dom_chain::ConnectResult::BestChain => {
            if let Err(e) = wallet.apply_canonical_block_with_hash(
                connected_block_txs,
                connected_height,
                Some(connected_hash),
            ) {
                warn!(
                    "wallet canonical native-USDOM block apply failed at height {connected_height}: {e}"
                );
            }
        }
        dom_chain::ConnectResult::Reorg(delta) => {
            if let Err(e) = wallet.rollback_to(delta.common_ancestor_height) {
                warn!(
                    "wallet rollback failed at native-USDOM reorg ancestor height {}: {e}",
                    delta.common_ancestor_height
                );
                return;
            }
            for block in &delta.connected_blocks {
                if let Err(e) = wallet.apply_canonical_block_with_hash(
                    &block.transactions,
                    block.block_height,
                    Some(block.block_hash),
                ) {
                    warn!(
                        "wallet canonical native-USDOM reorg block apply failed at height {} hash {}: {e}",
                        block.block_height,
                        hex::encode(block.block_hash)
                    );
                    break;
                }
            }
        }
        dom_chain::ConnectResult::SideChain | dom_chain::ConnectResult::AlreadyHave => {}
    }
}

fn decode_deferred_block_bytes(block_bytes: &[u8]) -> Result<dom_consensus::Block, DomError> {
    use dom_serialization::DomDeserialize;

    dom_consensus::Block::from_bytes(block_bytes)
}

fn decode_relay_block(msg_payload: &[u8]) -> Result<(Vec<u8>, dom_consensus::Block), DomError> {
    use dom_serialization::DomDeserialize;
    use dom_wire::message::BlockPayload;

    let payload = BlockPayload::from_bytes(msg_payload)?;
    let block = dom_consensus::Block::from_bytes(&payload.block_bytes)?;
    Ok((payload.block_bytes, block))
}

async fn reprocess_orphan_children(
    parent_hash: [u8; 32],
    chain: &Arc<Mutex<ChainState>>,
    relay_tx: &tokio::sync::broadcast::Sender<Vec<u8>>,
    svc: &NodeServices,
) -> Result<(), DomError> {
    let mut ready_parents = vec![parent_hash];
    while let Some(available_parent) = ready_parents.pop() {
        svc.missing_blocks.lock().await.resolve(&available_parent);
        let children = svc
            .orphan_pool
            .lock()
            .await
            .take_children(&available_parent);
        for orphan in children {
            let child = match decode_deferred_block_bytes(&orphan.block_bytes) {
                Ok(block) => block,
                Err(e) => {
                    svc.metrics
                        .malformed_block_relays
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(
                        child = %hex::encode(orphan.block_hash),
                        "Dropping malformed orphan during parent replay: {e}"
                    );
                    continue;
                }
            };
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let result = {
                let mut c = chain.lock().await;
                c.connect_block(&child, dom_core::Timestamp(now_secs))
            };
            match relay_block_action(&result) {
                RelayBlockAction::RelayBestChain => {
                    if let Ok(ref connect_result) = result {
                        reconcile_mempool_after_connect(
                            chain,
                            &svc.mempool,
                            connect_result,
                            &child.transactions,
                        )
                        .await?;
                    }
                    DomNode::refresh_runtime_metrics(
                        chain,
                        &svc.mempool,
                        &svc.future_block_queue,
                        &svc.metrics,
                    )
                    .await;
                    let _ = relay_tx.send(orphan.block_bytes.clone());
                    ready_parents.push(orphan.block_hash);
                }
                RelayBlockAction::Suppress => {
                    if matches!(
                        result,
                        Ok(dom_chain::ConnectResult::SideChain)
                            | Ok(dom_chain::ConnectResult::AlreadyHave)
                    ) {
                        ready_parents.push(orphan.block_hash);
                    } else if matches!(result, Err(DomError::Orphan(_))) {
                        let new_parent = *child.header.prev_hash.as_bytes();
                        svc.missing_blocks.lock().await.note_orphan(
                            orphan.block_hash,
                            new_parent,
                            child.header.height.0.checked_sub(1),
                        );
                        let _ = svc.orphan_pool.lock().await.insert(OrphanBlock {
                            block_hash: orphan.block_hash,
                            parent_hash: new_parent,
                            height: child.header.height.0,
                            block_bytes: orphan.block_bytes,
                        });
                    }
                }
                RelayBlockAction::PenalizePeer | RelayBlockAction::Drop => {
                    if let Err(e) = result {
                        tracing::debug!(
                            child = %hex::encode(orphan.block_hash),
                            "Dropping orphan after parent replay: {e}"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn decode_ibd_block_response(
    msg_payload: &[u8],
    expected_hash: [u8; 32],
) -> Result<(Vec<u8>, dom_consensus::Block), DomError> {
    use dom_serialization::{DomDeserialize, DomSerialize};
    use dom_wire::message::BlockPayload;

    let payload = BlockPayload::from_bytes(msg_payload)?;
    let block = dom_consensus::Block::from_bytes(&payload.block_bytes)?;
    let header_bytes = block.header.to_bytes()?;
    let block_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    if block_hash != expected_hash {
        return Err(DomError::Invalid(format!(
            "IBD block response hash mismatch: expected {}, got {}",
            hex::encode(expected_hash),
            hex::encode(block_hash)
        )));
    }
    Ok((payload.block_bytes, block))
}

enum IbdFetchedBlock {
    Ordinary(dom_consensus::Block),
    #[cfg(feature = "native-usdom-v4-poc")]
    Native {
        wire_payload: Vec<u8>,
        block: dom_consensus::Block,
    },
    #[cfg(feature = "native-usdom-v4-poc")]
    NativeV2 {
        wire_payload: Vec<u8>,
        block: dom_consensus::Block,
    },
}

#[cfg(feature = "native-usdom-v4-poc")]
fn decode_native_ibd_block_response(
    msg_payload: &[u8],
) -> Result<([u8; 32], Vec<u8>, dom_consensus::Block), DomError> {
    let framed = dom_wire::message::UsdomV4PackagePayload::from_bytes(msg_payload)?;
    let package = dom_chain::UsdomV4BlockPackage::from_bytes(&framed.package_bytes)?;
    let block = package.block().clone();
    let hash = block_hash(&block)?;
    Ok((hash, msg_payload.to_vec(), block))
}

#[cfg(feature = "native-usdom-v4-poc")]
fn decode_native_v2_ibd_block_response(
    msg_payload: &[u8],
) -> Result<([u8; 32], Vec<u8>, dom_consensus::Block), DomError> {
    let framed = dom_wire::message::UsdomV2PackagePayload::from_bytes(msg_payload)?;
    dom_chain::UsdomV2ExecutionWitnesses::from_bytes(&framed.witness_bytes)?;
    let package = dom_chain::UsdomV4BlockPackage::from_bytes(&framed.package_bytes)?;
    let block = package.block().clone();
    let hash = block_hash(&block)?;
    Ok((hash, msg_payload.to_vec(), block))
}

pub(crate) fn persist_peer_rotation_snapshot(
    store: &DomStore,
    snapshot: &dom_wire::manager::PersistedPeerRotationState,
) -> Result<(), DomError> {
    use dom_serialization::DomSerialize;

    if snapshot.outbound_failures.is_empty() {
        store.delete_metadata(PEER_ROTATION_METADATA_KEY)?;
        return store.delete_metadata(LEGACY_PEER_ROTATION_METADATA_KEY);
    }
    store.put_metadata(PEER_ROTATION_METADATA_KEY, &snapshot.to_bytes()?)?;
    store.delete_metadata(LEGACY_PEER_ROTATION_METADATA_KEY)
}

pub(crate) fn persist_peer_reputation_snapshot(
    store: &DomStore,
    snapshot: &dom_wire::manager::PersistedPeerReputationState,
) -> Result<(), DomError> {
    use dom_serialization::DomSerialize;

    if snapshot.entries.is_empty() {
        clear_persisted_peer_reputation(store)?;
        return Ok(());
    }
    store.put_metadata(PEER_REPUTATION_METADATA_KEY, &snapshot.to_bytes()?)?;
    store.delete_metadata(LEGACY_PEER_REPUTATION_METADATA_KEY)
}

/// Delete every known peer-reputation metadata version.
///
/// Used by the offline `dom-peer-reputation-clear` maintenance tool.
pub fn clear_persisted_peer_reputation(store: &DomStore) -> Result<(), DomError> {
    store.delete_metadata(PEER_REPUTATION_METADATA_KEY)?;
    store.delete_metadata(LEGACY_PEER_REPUTATION_METADATA_KEY)
}

pub(crate) fn load_peer_rotation_snapshot(
    store: &DomStore,
) -> Result<Option<dom_wire::manager::PersistedPeerRotationState>, DomError> {
    use dom_serialization::DomDeserialize;

    match store.get_metadata(PEER_ROTATION_METADATA_KEY)? {
        Some(bytes) => {
            let snapshot = dom_wire::manager::PersistedPeerRotationState::from_bytes(&bytes)
                .map_err(|e| {
                    DomError::Invalid(format!("peer rotation snapshot decode failed: {e}"))
                })?;
            Ok(Some(snapshot))
        }
        None => match store.get_metadata(LEGACY_PEER_ROTATION_METADATA_KEY)? {
            Some(bytes) => {
                let snapshot =
                    dom_wire::manager::PersistedPeerRotationState::from_legacy_bytes(&bytes)
                        .map_err(|e| {
                            DomError::Invalid(format!(
                                "legacy peer rotation snapshot decode failed: {e}"
                            ))
                        })?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        },
    }
}

pub(crate) fn load_peer_reputation_snapshot(
    store: &DomStore,
) -> Result<Option<dom_wire::manager::PersistedPeerReputationState>, DomError> {
    use dom_serialization::DomDeserialize;

    match store.get_metadata(PEER_REPUTATION_METADATA_KEY)? {
        Some(bytes) => {
            let snapshot = dom_wire::manager::PersistedPeerReputationState::from_bytes(&bytes)
                .map_err(|e| {
                    DomError::Invalid(format!("peer reputation snapshot decode failed: {e}"))
                })?;
            Ok(Some(snapshot))
        }
        None => match store.get_metadata(LEGACY_PEER_REPUTATION_METADATA_KEY)? {
            Some(bytes) => {
                let snapshot =
                    dom_wire::manager::PersistedPeerReputationState::from_legacy_bytes(&bytes)
                        .map_err(|e| {
                            DomError::Invalid(format!(
                                "legacy peer reputation snapshot decode failed: {e}"
                            ))
                        })?;
                // v1 did not retain age. Its entries migrate expired rather
                // than acquiring a fresh 15-minute lifetime on every restart.
                store.delete_metadata(LEGACY_PEER_REPUTATION_METADATA_KEY)?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        },
    }
}

#[cfg(test)]
pub(crate) fn persist_mempool_snapshot(
    store: &DomStore,
    snapshot: &dom_mempool::PersistedMempoolState,
) -> Result<(), DomError> {
    use dom_serialization::DomSerialize;

    if snapshot.entries.is_empty() {
        return store.delete_metadata(MEMPOOL_METADATA_KEY);
    }
    store.put_metadata(MEMPOOL_METADATA_KEY, &snapshot.to_bytes()?)
}

/// Clear any on-disk mempool bytes (RFC-0012 §1).
///
/// The mempool is volatile: it is never loaded from disk into runtime state.
/// Older builds may have left `MEMPOOL_METADATA_KEY` bytes; this removes them so
/// the on-disk view stays consistent with the empty-on-restart policy. It is
/// called on init, on every block connect, and on tx admission.
pub(crate) fn clear_persisted_mempool_snapshot(store: &DomStore) -> Result<(), DomError> {
    store.delete_metadata(MEMPOOL_METADATA_KEY)
}

// Test-only: under the volatile mempool policy (RFC-0012 §1) no runtime path
// reads on-disk mempool bytes into state. This decoder exists solely so tests can
// assert that legacy/adversarial on-disk mempool metadata has been cleared.
#[cfg(test)]
pub(crate) fn load_mempool_snapshot(
    store: &DomStore,
) -> Result<Option<dom_mempool::PersistedMempoolState>, DomError> {
    use dom_serialization::DomDeserialize;

    match store.get_metadata(MEMPOOL_METADATA_KEY)? {
        Some(bytes) => {
            let snapshot = dom_mempool::PersistedMempoolState::from_bytes(&bytes)
                .map_err(|e| DomError::Invalid(format!("mempool snapshot decode failed: {e}")))?;
            Ok(Some(snapshot))
        }
        None => Ok(None),
    }
}

pub(crate) fn restore_peer_rotation_state(
    store: &DomStore,
    peers: &mut PeerManager,
) -> Result<(), DomError> {
    match load_peer_rotation_snapshot(store)? {
        Some(snapshot) => peers
            .restore_outbound_failure_state(&snapshot)
            .map_err(|e| {
                DomError::Invalid(format!("persisted peer rotation state restore failed: {e}"))
            }),
        None => Ok(()),
    }
}

pub(crate) fn restore_peer_reputation_state(
    store: &DomStore,
    peers: &mut PeerManager,
) -> Result<(), DomError> {
    match load_peer_reputation_snapshot(store)? {
        Some(snapshot) => peers.restore_peer_reputation_state(&snapshot).map_err(|e| {
            DomError::Invalid(format!(
                "persisted peer reputation state restore failed: {e}"
            ))
        }),
        None => Ok(()),
    }
}

/// Resolve the DNS-seed bootstrap candidates for this configuration.
///
/// Two gates, both yielding NO candidates:
///   * [`NodeConfig::disable_dns_seeds`] — the desktop wallet sets it whenever
///     the user configured explicit `seed_peers`, so a custom seed (e.g. a
///     local SSH tunnel) is the ONLY bootstrap source and the hardcoded
///     fallback seeds in `dom_wire::dns_seed` cannot reintroduce unwanted
///     peers;
///   * Regtest with no explicitly configured dns_seeds — a private local
///     network must never dial the built-in public testnet seeds. A single
///     such dial parks a relay worker inside `TcpStream::connect` for the
///     full OS connect timeout when the SYN is silently dropped, so the relay
///     registry (and any outbound slot budget) stays occupied by a peer that
///     can never handshake.
///
/// Every other configuration resolves the network's DNS seeds unchanged.
pub(crate) async fn resolve_configured_dns_seeds(config: &NodeConfig) -> Vec<String> {
    if config.disable_dns_seeds {
        return Vec::new();
    }
    if config.network == dom_config::Network::Regtest && config.dns_seeds.is_empty() {
        return Vec::new();
    }
    let is_mainnet = config.network == dom_config::Network::Mainnet;
    let port = config.network.default_port();
    dom_wire::dns_seed::resolve_seeds(is_mainnet, port, &config.dns_seeds).await
}

/// Resolve the current IP identities of explicit `DOM_SEED_PEERS` entries.
///
/// `seed_peers` may be hostnames, so resolve them on each connector pass. A
/// successful lookup replaces that hostname's cached IPs; a transient failure
/// retains its last successful result. Public DNS-seed candidates are not
/// included in this immunity set.
async fn refresh_configured_seed_ips(
    configured_seed_peers: &[String],
    cache: &mut HashMap<String, HashSet<std::net::IpAddr>>,
) -> HashSet<std::net::IpAddr> {
    cache.retain(|seed, _| configured_seed_peers.contains(seed));
    for seed in configured_seed_peers {
        if let Ok(addr) = seed.parse::<std::net::SocketAddr>() {
            cache.insert(seed.clone(), HashSet::from([addr.ip()]));
            continue;
        }
        match tokio::net::lookup_host(seed).await {
            Ok(addrs) => {
                let resolved = addrs.map(|addr| addr.ip()).collect::<HashSet<_>>();
                if !resolved.is_empty() {
                    // A successful refresh replaces this hostname's prior IPs,
                    // so immunity follows real DNS changes.
                    cache.insert(seed.clone(), resolved);
                }
            }
            Err(error) => {
                tracing::warn!(
                    event = "configured_seed_resolution_failed",
                    seed = %seed,
                    error = %error,
                    "keeping the last resolved seed immunity set"
                );
            }
        }
    }
    cache.values().flatten().copied().collect()
}

async fn persist_peer_rotation_state(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
) -> Result<(), DomError> {
    let snapshot = {
        let peers = peers.lock().await;
        peers.outbound_failure_state()
    };
    let chain = chain.lock().await;
    persist_peer_rotation_snapshot(&chain.store, &snapshot)
}

async fn persist_peer_reputation_state(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
) -> Result<(), DomError> {
    let snapshot = {
        let peers = peers.lock().await;
        peers.peer_reputation_state()
    };
    let chain = chain.lock().await;
    persist_peer_reputation_snapshot(&chain.store, &snapshot)
}

/// Persist mempool lifecycle state.
///
/// Under the volatile mempool policy (RFC-0012 §1) the mempool is **never**
/// written to disk: "persisting" it means ensuring no on-disk mempool bytes
/// remain, so a restart deterministically starts empty. The live `mempool` is
/// intentionally unused here.
async fn persist_mempool_state(
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
) -> Result<(), DomError> {
    let chain = chain.lock().await;
    let _ = mempool;
    clear_persisted_mempool_snapshot(&chain.store)
}

async fn advance_peer_rotation_cooldowns(
    chain: &Arc<Mutex<ChainState>>,
    peers: &Arc<Mutex<PeerManager>>,
) -> Result<(), DomError> {
    let changed = {
        let mut peers = peers.lock().await;
        peers.advance_outbound_cooldowns()
    };
    if changed {
        persist_peer_rotation_state(chain, peers).await?;
    }
    Ok(())
}

pub(crate) fn load_or_create_noise_static_key(store: &DomStore) -> Result<[u8; 32], DomError> {
    match store.get_metadata(NOISE_STATIC_KEY_METADATA_KEY)? {
        Some(bytes) => {
            let bytes = Zeroizing::new(bytes);
            parse_persisted_noise_static_key(&bytes)
        }
        None => {
            let (privkey, _) = dom_wire::handshake::generate_static_keypair();
            store.put_metadata(NOISE_STATIC_KEY_METADATA_KEY, &privkey)?;
            Ok(privkey)
        }
    }
}

fn parse_persisted_noise_static_key(bytes: &[u8]) -> Result<[u8; 32], DomError> {
    if bytes.len() != 32 {
        return Err(DomError::Invalid(format!(
            "persisted Noise static key has invalid length: expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(bytes);
    let mut normalized = privkey;
    dom_wire::handshake::clamp_static_privkey(&mut normalized);
    if normalized != privkey {
        return Err(DomError::Invalid(
            "persisted Noise static key is not in canonical clamped form".into(),
        ));
    }
    Ok(privkey)
}

async fn record_duplicate_block_relay(
    peers: &Arc<Mutex<PeerManager>>,
    metrics: &Arc<Metrics>,
    peer_addr: std::net::SocketAddr,
) -> bool {
    let peer_key = peer_addr.to_string();
    metrics
        .suppressed_duplicate_block_relays
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let exceeded = {
        let mut mgr = peers.lock().await;
        mgr.record_duplicate_block_relay(&peer_key)
    };
    if exceeded {
        metrics
            .duplicate_block_relay_quota_exceeded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    exceeded
}

/// Fire one reachability probe at `source_ip:advertised_port` (spec A4).
///
/// Detached: the inbound session must not wait on a probe, and a slow target
/// costs at most `DIALBACK_CONNECT_TIMEOUT` of one bounded slot. Success
/// promotes the address to confirmed — the only state PEX gossips — through
/// the same `mark_connected` an ordinary completed outbound uses. Failure
/// changes nothing: unconfirmed is the safe state, and the regular outbound
/// cooldown machinery governs any retry.
async fn spawn_dialback_probe(
    supervisor: NodeTaskSupervisor,
    source_ip: std::net::IpAddr,
    advertised_port: u16,
    limiter: Arc<crate::dialback::DialbackLimiter>,
    pex: Arc<Mutex<crate::pex::PexManager>>,
    metrics: Arc<Metrics>,
) {
    supervisor
        .spawn_dialback(async move {
            let Some(slot) = limiter.try_begin(source_ip) else {
                return Ok(());
            };
            metrics
                .dialback_attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let target = std::net::SocketAddr::new(source_ip, advertised_port);
            let connected = tokio::time::timeout(
                crate::dialback::DIALBACK_CONNECT_TIMEOUT,
                tokio::net::TcpStream::connect(target),
            )
            .await;
            drop(slot);
            match connected {
                Ok(Ok(_stream)) => {
                    metrics
                        .dialback_success
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let mut px = trace_lock("pex", &pex).await;
                    if px.mark_connected(&target.to_string()) {
                        refresh_pex_metrics(&px, &metrics);
                        tracing::debug!(%target, "dial-back confirmed advertised endpoint");
                    }
                }
                _ => {
                    tracing::debug!(%target, "dial-back could not reach advertised endpoint");
                }
            }
            Ok(())
        })
        .await;
}

/// Publish the PEX pool composition gauges (spec A5).
///
/// Called from the paths that mutate the pool rather than on a timer, so the
/// gauges are exact at every scrape without a dedicated task. All three are
/// unlabeled totals (R-A5.1).
fn refresh_pex_metrics(pex: &crate::pex::PexManager, metrics: &Metrics) {
    let confirmed = pex.confirmed_count() as u64;
    let known = pex.known_count() as u64;
    metrics
        .pex_confirmed_peers
        .store(confirmed, std::sync::atomic::Ordering::Relaxed);
    metrics.pex_unconfirmed_peers.store(
        known.saturating_sub(confirmed),
        std::sync::atomic::Ordering::Relaxed,
    );
    metrics.pex_unreachable_peers.store(
        pex.unreachable_peers_seen(),
        std::sync::atomic::Ordering::Relaxed,
    );
}

async fn refresh_peer_metrics(
    peers: &Arc<Mutex<PeerManager>>,
    metrics: &Arc<Metrics>,
    state_events: Option<&Arc<Notify>>,
) {
    let (peer_count, inbound_peers, outbound_peers, best_known_peer_height) = {
        let mgr = trace_lock("peers", peers).await;
        let mut peer_count = 0u64;
        let mut inbound_peers = 0u64;
        let mut outbound_peers = 0u64;
        let mut best_known_peer_height = 0u64;
        for peer in mgr.peers.values() {
            if peer.state == dom_wire::peer::PeerState::Connected {
                peer_count += 1;
                best_known_peer_height = best_known_peer_height.max(peer.best_height);
                if peer.outbound {
                    outbound_peers += 1;
                } else {
                    inbound_peers += 1;
                }
            }
        }
        (
            peer_count,
            inbound_peers,
            outbound_peers,
            best_known_peer_height,
        )
    };

    metrics
        .peer_count
        .store(peer_count, std::sync::atomic::Ordering::Relaxed);
    metrics
        .inbound_peers
        .store(inbound_peers, std::sync::atomic::Ordering::Relaxed);
    metrics
        .outbound_peers
        .store(outbound_peers, std::sync::atomic::Ordering::Relaxed);
    metrics
        .best_known_peer_height
        .store(best_known_peer_height, std::sync::atomic::Ordering::Relaxed);
    if let Some(state_events) = state_events {
        state_events.notify_waiters();
    }
}

async fn note_peer_best_height(
    peers: &Arc<Mutex<PeerManager>>,
    metrics: &Arc<Metrics>,
    state_events: &Arc<Notify>,
    peer_addr: std::net::SocketAddr,
    height: u64,
    hash: [u8; 32],
) {
    let changed = {
        let mut mgr = trace_lock("peers", peers).await;
        match mgr.peers.get_mut(&peer_addr.to_string()) {
            Some(peer)
                if peer.state == dom_wire::peer::PeerState::Connected
                    && height > peer.best_height =>
            {
                peer.best_height = height;
                peer.best_hash = hash;
                true
            }
            _ => false,
        }
    };
    if changed {
        refresh_peer_metrics(peers, metrics, Some(state_events)).await;
    }
}

/// Decide whether a peer's advertised tip requires a header/body sync.
///
/// `Some(false)` is ordinary catch-up from a taller peer. `Some(true)` is a
/// fork-resolution round: equal height but a different authenticated tip hash.
/// The latter is essential because height alone cannot choose between forks;
/// chain state resolves the fetched branches by accumulated work.
fn sync_mode_for_peer(
    local_height: u64,
    local_hash: [u8; 32],
    peer_height: u64,
    peer_hash: [u8; 32],
) -> Option<bool> {
    if peer_height > local_height {
        Some(false)
    } else if peer_height == local_height && peer_hash != local_hash {
        Some(true)
    } else {
        None
    }
}

/// Persistent message loop after Hello exchange.
///
/// Reads framed messages from the peer in a loop and dispatches by command:
/// - Ping: reply with Pong echoing the payload
/// - Pong: ignored (could update last-seen for liveness tracking)
/// - Other commands: logged and ignored (IBD/relay handled in Phase 3)
///
/// Sends a Ping every `PING_INTERVAL_SECS` to detect dead peers.
/// Exits on any I/O error or idle timeout (NoiseCodec::recv enforces it).
/// Build a sparse block locator (newest tip first, exponentially-spaced).
///
/// Format: [tip, tip-1, tip-2, tip-4, tip-8, tip-16, ..., genesis].
/// This lets the peer find the common ancestor in O(log n) headers.
async fn build_locator(chain: &Arc<Mutex<ChainState>>) -> Result<Vec<[u8; 32]>, DomError> {
    let c = chain.lock().await;
    let tip_height = c.tip_height.0;
    let mut out: Vec<[u8; 32]> = Vec::new();
    let mut step: u64 = 1;
    let mut height = Some(tip_height);
    while let Some(h) = height {
        if out.len() >= dom_core::MAX_LOCATOR_HASHES {
            break;
        }
        if let Some(hash) = c.store.get_hash_at_height(h)? {
            out.push(hash);
        }
        if out.len() >= 10 {
            step = step.saturating_mul(2);
        }
        height = h.checked_sub(step);
    }
    Ok(out)
}

async fn persist_ibd_state(
    chain: &Arc<Mutex<ChainState>>,
    peer_addr: std::net::SocketAddr,
    ibd: &dom_chain::IbdState,
    round: IbdRoundState,
) -> Result<(), DomError> {
    let chain = chain.lock().await;
    // The canonical tip is the durable block cursor. It can advance inside a
    // partially completed body page, before `IbdState::note_round_progress` is
    // called. Persisting the stale in-memory round height alongside the new tip
    // hash made every mid-page restart fail the resumability check.
    let durable_blocks_height = chain.tip_height.0;
    let durable_headers_height = ibd
        .headers_height
        .max(ibd.last_progress_height)
        .max(durable_blocks_height);
    let snapshot = dom_chain::PersistedIbdState {
        phase: ibd.phase,
        peer_addr: peer_addr.to_string(),
        start_height: ibd.start_height,
        best_peer_height: ibd.best_peer_height,
        headers_height: durable_headers_height,
        blocks_height: durable_blocks_height,
        last_progress_height: ibd.last_progress_height.max(durable_blocks_height),
        checkpoint_tip_hash: *chain.tip_hash.as_bytes(),
        retry_attempts: ibd.retry_attempts,
        last_interruption: ibd.last_interruption,
        pending_blocks: round.pending_blocks,
        pending_headers: round.pending_headers,
        block_cursor: round.block_cursor,
        header_cursor: round.header_cursor,
        header_cursor_height: round.header_cursor_height,
    };
    snapshot.save(&chain.store)
}

async fn clear_persisted_ibd_state(chain: &Arc<Mutex<ChainState>>) -> Result<(), DomError> {
    let chain = chain.lock().await;
    dom_chain::PersistedIbdState::clear(&chain.store)
}

struct IbdRuntimeContext<'a> {
    config: &'a NodeConfig,
    peer_addr: std::net::SocketAddr,
    peer_id: Option<[u8; 32]>,
    mempool: Arc<Mutex<Mempool>>,
    future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    metrics: Arc<Metrics>,
    wallet: Option<Arc<Mutex<dom_wallet::WalletDir>>>,
    state_events: Arc<Notify>,
    channels: BroadcastChannels,
    native_usdom_v4_negotiated: bool,
    native_usdom_v2_negotiated: bool,
    svc: NodeServices,
}

#[derive(Clone)]
struct IbdRoundState {
    pending_blocks: Vec<[u8; 32]>,
    pending_headers: Vec<Vec<u8>>,
    block_cursor: u32,
    header_cursor: u32,
    header_cursor_height: u64,
}

async fn initialize_ibd_state(
    chain: &Arc<Mutex<ChainState>>,
    peer_addr: std::net::SocketAddr,
    peer_best_height: u64,
) -> Result<(dom_chain::IbdState, Option<dom_chain::PersistedIbdState>), DomError> {
    let peer_key = peer_addr.to_string();
    let (tip_height, tip_hash, persisted) = {
        let chain = chain.lock().await;
        let persisted = match dom_chain::PersistedIbdState::load(&chain.store) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                // This metadata is local orchestration state, never peer input.
                // Discard corruption/incompatible checkpoints and restart from
                // the canonical local tip without routing the error into peer
                // reputation.
                tracing::warn!(
                    event = "ibd_checkpoint_discarded",
                    reason = %error,
                    local_tip_height = chain.tip_height.0,
                    "invalid local IBD checkpoint discarded"
                );
                if let Err(clear_error) = dom_chain::PersistedIbdState::clear(&chain.store) {
                    tracing::warn!(
                        event = "ibd_checkpoint_clear_failed",
                        reason = %clear_error,
                        "failed to delete invalid local IBD checkpoint"
                    );
                }
                None
            }
        };
        (chain.tip_height.0, *chain.tip_hash.as_bytes(), persisted)
    };

    let Some(snapshot) = persisted else {
        return Ok((dom_chain::IbdState::new(tip_height, peer_best_height), None));
    };

    // The work queues are content-addressed and consensus-validated, so they
    // remain safe across a reconnect, a peer tip increase, or failover to
    // another authenticated Mainnet peer. The durable local checkpoint is the
    // authority. A replacement peer must merely be high enough to serve the
    // saved round.
    let peer_can_serve_saved_round = snapshot.pending_blocks.is_empty()
        && snapshot.pending_headers.is_empty()
        || peer_best_height >= snapshot.header_cursor_height;
    let resumable = snapshot.blocks_height == tip_height
        && snapshot.checkpoint_tip_hash == tip_hash
        && peer_can_serve_saved_round
        && !matches!(
            snapshot.phase,
            dom_chain::IbdPhase::Completed | dom_chain::IbdPhase::Failed
        );

    if !resumable {
        clear_persisted_ibd_state(chain).await?;
        return Ok((dom_chain::IbdState::new(tip_height, peer_best_height), None));
    }

    match dom_chain::IbdState::from_persisted(&snapshot) {
        Ok(mut ibd) => {
            let source_changed = snapshot.peer_addr != peer_key;
            ibd.best_peer_height = ibd.best_peer_height.max(peer_best_height);
            if source_changed {
                ibd.retry_attempts = 0;
                ibd.last_interruption = None;
            }
            tracing::info!(
                event = "ibd_checkpoint_resumed",
                previous_peer_addr = %snapshot.peer_addr,
                peer_addr = %peer_addr,
                source_changed,
                local_height = tip_height,
                remote_height = peer_best_height,
                saved_target_height = snapshot.best_peer_height,
                block_cursor = snapshot.block_cursor,
                pending_blocks = snapshot.pending_blocks.len(),
                header_cursor = snapshot.header_cursor,
                pending_headers = snapshot.pending_headers.len(),
                "resuming durable IBD checkpoint"
            );
            Ok((ibd, Some(snapshot)))
        }
        Err(_) => {
            clear_persisted_ibd_state(chain).await?;
            Ok((dom_chain::IbdState::new(tip_height, peer_best_height), None))
        }
    }
}

async fn resume_ibd_block_sync(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    chain: &Arc<Mutex<ChainState>>,
    runtime: &IbdRuntimeContext<'_>,
    ibd: &mut dom_chain::IbdState,
    round: IbdRoundState,
) -> Result<bool, DomError> {
    use dom_wire::message::{Command, GetBlockDataPayload, WireMessage};

    let start = usize::try_from(round.block_cursor)
        .map_err(|_| DomError::Internal("persisted block cursor conversion failed".into()))?;
    if start >= round.pending_blocks.len() {
        return Ok(false);
    }

    ibd.begin_block_sync();
    let mut connected_any = false;
    let mut processed = round.block_cursor;

    for batch in round.pending_blocks[start..].chunks(IBD_BLOCK_REQUEST_WINDOW) {
        let req = GetBlockDataPayload {
            hashes: batch.to_vec(),
        };
        let wire = WireMessage {
            magic: runtime.config.network.magic(),
            command: Command::GetBlockData,
            payload: req.to_bytes()?,
        };
        codec.send(stream, &wire).await?;

        for expected_hash in batch {
            let fetched = loop {
                let m = codec
                    .recv_with_idle_timeout(
                        stream,
                        tokio::time::Duration::from_secs(
                            dom_wire::handshake::IBD_IDLE_TIMEOUT_SECS,
                        ),
                    )
                    .await?;
                match m.command {
                    Command::Block => {
                        // The peer relays freshly-mined blocks on the SAME
                        // connection while we are still fetching IBD bodies (its
                        // per-peer task forwards every newly mined block — see the
                        // `block_relay_rx` arm of `message_loop`). Such an
                        // unsolicited relay block is NOT the response to our
                        // GetBlockData request. Treating it as one corrupts the
                        // request/response alignment and aborts the entire sync
                        // against an actively-mining peer with "IBD block response
                        // hash mismatch" — the bug that made a mining node and a
                        // sync-only node unable to converge. Match the response by
                        // hash: if it is the block we asked for, accept it;
                        // otherwise skip it (we re-fetch it in a later IBD round
                        // or receive it via normal relay once we are caught up and
                        // back in `message_loop`) and keep waiting for ours.
                        match decode_ibd_block_response(&m.payload, *expected_hash) {
                            Ok((_, block)) => break IbdFetchedBlock::Ordinary(block),
                            Err(_) => {
                                let (block_bytes, relay_block) = decode_relay_block(&m.payload)
                                    .map_err(|e| {
                                        DomError::Malformed(format!(
                                            "unsolicited IBD relay block decode failed: {e}"
                                        ))
                                    })?;
                                let relay_hash = block_hash(&relay_block)?;
                                let parent_hash = *relay_block.header.prev_hash.as_bytes();
                                let insert_outcome =
                                    runtime.svc.orphan_pool.lock().await.insert(OrphanBlock {
                                        block_hash: relay_hash,
                                        parent_hash,
                                        height: relay_block.header.height.0,
                                        block_bytes,
                                    });
                                runtime.svc.missing_blocks.lock().await.note_orphan(
                                    relay_hash,
                                    parent_hash,
                                    relay_block.header.height.0.checked_sub(1),
                                );
                                tracing::debug!(
                                    child = %hex::encode(relay_hash),
                                    parent = %hex::encode(parent_hash),
                                    ?insert_outcome,
                                    "IBD resume: skipping unsolicited relayed block while \
                                     awaiting {} from {}",
                                    hex::encode(expected_hash),
                                    runtime.peer_addr
                                );
                                reprocess_orphan_children(
                                    parent_hash,
                                    chain,
                                    &runtime.channels.block_relay_tx,
                                    &runtime.svc,
                                )
                                .await?;
                            }
                        }
                    }
                    #[cfg(feature = "native-usdom-v4-poc")]
                    Command::UsdomV4Package => {
                        require_native_usdom_v4_negotiation(runtime.native_usdom_v4_negotiated)?;
                        let (response_hash, wire_payload, block) =
                            decode_native_ibd_block_response(&m.payload)?;
                        if response_hash == *expected_hash {
                            break IbdFetchedBlock::Native {
                                wire_payload,
                                block,
                            };
                        }
                        tracing::debug!(
                            received = %hex::encode(response_hash),
                            expected = %hex::encode(expected_hash),
                            peer = %runtime.peer_addr,
                            "IBD resume: skipping unsolicited native package while waiting for requested hash"
                        );
                    }
                    #[cfg(feature = "native-usdom-v4-poc")]
                    Command::UsdomV2Package => {
                        require_native_usdom_v2_negotiation(runtime.native_usdom_v2_negotiated)?;
                        let (response_hash, wire_payload, block) =
                            decode_native_v2_ibd_block_response(&m.payload)?;
                        if response_hash == *expected_hash {
                            break IbdFetchedBlock::NativeV2 {
                                wire_payload,
                                block,
                            };
                        }
                        tracing::debug!(
                            received = %hex::encode(response_hash),
                            expected = %hex::encode(expected_hash),
                            peer = %runtime.peer_addr,
                            "IBD resume: skipping unsolicited native V2 package while waiting for requested hash"
                        );
                    }
                    Command::Ping => {
                        let pong = WireMessage {
                            magic: runtime.config.network.magic(),
                            command: Command::Pong,
                            payload: m.payload,
                        };
                        codec.send(stream, &pong).await?;
                    }
                    Command::Pong => {}
                    other => {
                        tracing::debug!("IBD resume: ignoring {other:?} while waiting for Block");
                    }
                }
            };
            let (height, txs_for_scan, connect_result, native_ingress) = match fetched {
                IbdFetchedBlock::Ordinary(block) => {
                    let height = block.header.height.0;
                    let txs_for_scan = block.transactions.clone();
                    // DOM-AUDIT-001: connect the block under the chain guard,
                    // capture the owned result, then drop the guard before any
                    // mempool or wallet follow-up that re-acquires it.
                    let chain_for_connect = chain.clone();
                    let connect_result = tokio::task::spawn_blocking(move || {
                        let mut chain = chain_for_connect.blocking_lock();
                        chain.connect_block(&block, ibd_now())
                    })
                    .await
                    .map_err(|e| DomError::Internal(format!("IBD validation task failed: {e}")))?
                    .map_err(|e| {
                        DomError::Invalid(format!(
                            "IBD resume from {}: connect_block rejected: {e}",
                            runtime.peer_addr,
                        ))
                    })?;
                    (height, txs_for_scan, connect_result, false)
                }
                #[cfg(feature = "native-usdom-v4-poc")]
                IbdFetchedBlock::Native {
                    wire_payload,
                    block,
                } => {
                    let native_runtime =
                        runtime
                            .svc
                            .native_usdom_v4_runtime
                            .as_ref()
                            .ok_or_else(|| {
                                DomError::Internal(
                                    "native USDOM IBD negotiated without a restored runtime".into(),
                                )
                            })?;
                    let height = block.header.height.0;
                    let txs_for_scan = block.transactions.clone();
                    let connect_result = NativeUsdomV4Ingress {
                        chain: chain.clone(),
                        mempool: runtime.mempool.clone(),
                        runtime: native_runtime.clone(),
                        relay_tx: runtime.channels.native_usdom_v4_relay_tx.clone(),
                        relay_exclude_peer: Some(runtime.peer_addr),
                        wallet: runtime.wallet.clone(),
                        metrics: runtime.metrics.clone(),
                        future_block_queue: runtime.future_block_queue.clone(),
                        native_future_queue: runtime.svc.native_usdom_v4_future_queue.clone(),
                        state_events: runtime.state_events.clone(),
                        orphan_pool: runtime.svc.native_usdom_v4_orphan_pool.clone(),
                        candidate_v2_first_height: runtime.svc.candidate_v2_first_height,
                        migration_shutdown: Some(runtime.svc.task_supervisor.clone()),
                        proof_admission: runtime.svc.native_usdom_proof_admission.clone(),
                    }
                    .ingest(&wire_payload, ibd_now())
                    .await?;
                    (height, txs_for_scan, connect_result, true)
                }
                #[cfg(feature = "native-usdom-v4-poc")]
                IbdFetchedBlock::NativeV2 {
                    wire_payload,
                    block,
                } => {
                    let native_runtime =
                        runtime
                            .svc
                            .native_usdom_v2_runtime
                            .as_ref()
                            .ok_or_else(|| {
                                DomError::Internal(
                                    "native USDOM V2 IBD negotiated without a restored runtime"
                                        .into(),
                                )
                            })?;
                    let height = block.header.height.0;
                    let txs_for_scan = block.transactions.clone();
                    let connect_result = NativeUsdomV2Ingress {
                        chain: chain.clone(),
                        mempool: runtime.mempool.clone(),
                        runtime: native_runtime.clone(),
                        relay_tx: runtime.channels.native_usdom_v2_relay_tx.clone(),
                        relay_exclude_peer: Some(runtime.peer_addr),
                        wallet: runtime.wallet.clone(),
                        metrics: runtime.metrics.clone(),
                        future_block_queue: runtime.future_block_queue.clone(),
                        native_future_queue: runtime.svc.native_usdom_v4_future_queue.clone(),
                        state_events: runtime.state_events.clone(),
                        orphan_pool: runtime.svc.native_usdom_v4_orphan_pool.clone(),
                        proof_admission: runtime.svc.native_usdom_proof_admission.clone(),
                    }
                    .ingest(&wire_payload, ibd_now())
                    .await?;
                    (height, txs_for_scan, connect_result, true)
                }
            };
            let best_chain = match &connect_result {
                dom_chain::ConnectResult::BestChain => {
                    connected_any = true;
                    true
                }
                dom_chain::ConnectResult::Reorg(_) => {
                    connected_any = true;
                    true
                }
                dom_chain::ConnectResult::SideChain => {
                    connected_any = true;
                    false
                }
                dom_chain::ConnectResult::AlreadyHave => {
                    tracing::debug!(
                        "IBD resume from {}: block already known at height {}",
                        runtime.peer_addr,
                        height
                    );
                    connected_any = true;
                    false
                }
            };
            // Chain guard dropped above. The following re-acquire chain/mempool/
            // wallet internally and must run with NO chain guard held.
            if best_chain && !native_ingress {
                purge_mempool_confirmed_inputs(chain, &runtime.mempool, &txs_for_scan).await?;
                DomNode::refresh_runtime_metrics(
                    chain,
                    &runtime.mempool,
                    &runtime.future_block_queue,
                    &runtime.metrics,
                )
                .await;
                if let Some(ref wallet_arc) = runtime.wallet {
                    let mut wallet_dir = wallet_arc.lock().await;
                    let w = wallet_dir.wallet_mut();
                    match connect_result {
                        dom_chain::ConnectResult::BestChain => {
                            w.apply_canonical_block_with_hash(
                                &txs_for_scan,
                                height,
                                Some(*expected_hash),
                            )
                            .map_err(|e| {
                                DomError::Internal(format!(
                                    "wallet canonical block apply during resumed IBD failed: {e}"
                                ))
                            })?;
                        }
                        dom_chain::ConnectResult::Reorg(delta) => {
                            w.rollback_to(delta.common_ancestor_height).map_err(|e| {
                                DomError::Internal(format!(
                                    "wallet rollback during resumed IBD reorg failed: {e}"
                                ))
                            })?;
                            for block in &delta.connected_blocks {
                                w.apply_canonical_block_with_hash(
                                    &block.transactions,
                                    block.block_height,
                                    Some(block.block_hash),
                                )
                                .map_err(|e| {
                                    DomError::Internal(format!(
                                        "wallet canonical reorg block apply during resumed IBD failed: {e}"
                                    ))
                                })?;
                            }
                        }
                        dom_chain::ConnectResult::SideChain
                        | dom_chain::ConnectResult::AlreadyHave => {}
                    }
                }
            }
            if !native_ingress {
                runtime.state_events.notify_waiters();
            }
            reprocess_orphan_children(
                *expected_hash,
                chain,
                &runtime.channels.block_relay_tx,
                &runtime.svc,
            )
            .await?;
            processed = processed.saturating_add(1);
            persist_ibd_state(
                chain,
                runtime.peer_addr,
                ibd,
                IbdRoundState {
                    pending_blocks: round.pending_blocks.clone(),
                    pending_headers: Vec::new(),
                    block_cursor: processed,
                    header_cursor: 0,
                    header_cursor_height: round.header_cursor_height,
                },
            )
            .await?;
            let local_height = chain.lock().await.tip_height.0;
            ibd.blocks_height = local_height;
            ibd.last_progress_height = ibd.last_progress_height.max(local_height);
            let remaining_blocks = ibd.best_peer_height.saturating_sub(local_height);
            let progress_percent = if ibd.best_peer_height == 0 {
                100.0
            } else {
                (local_height as f64 * 100.0 / ibd.best_peer_height as f64).min(100.0)
            };
            if remaining_blocks == 0 || local_height % IBD_PROGRESS_LOG_INTERVAL == 0 {
                tracing::info!(
                    event = "ibd_progress",
                    peer_addr = %runtime.peer_addr,
                    peer_id = %runtime.peer_id.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
                    phase = ?ibd.phase,
                    local_height,
                    remote_height = ibd.best_peer_height,
                    remaining_blocks,
                    progress_percent = format_args!("{progress_percent:.2}"),
                    "IBD progress"
                );
            } else {
                tracing::debug!(
                    event = "ibd_progress",
                    peer_addr = %runtime.peer_addr,
                    local_height,
                    remote_height = ibd.best_peer_height,
                    remaining_blocks,
                    progress_percent,
                    "IBD block committed"
                );
            }
        }
    }

    Ok(connected_any)
}

fn ibd_now() -> Timestamp {
    Timestamp(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

async fn continue_ibd_header_sync(
    chain: &Arc<Mutex<ChainState>>,
    peer_addr: std::net::SocketAddr,
    ibd: &mut dom_chain::IbdState,
    round: IbdRoundState,
    now: Timestamp,
    validation_mode: IbdHeaderValidationMode,
) -> Result<Vec<[u8; 32]>, DomError> {
    let start = usize::try_from(round.header_cursor)
        .map_err(|_| DomError::Internal("persisted header cursor conversion failed".into()))?;
    if start > round.pending_headers.len() {
        return Err(DomError::PolicyRejected(format!(
            "persisted header cursor {} exceeds pending header count {}",
            round.header_cursor,
            round.pending_headers.len()
        )));
    }

    if round.pending_headers.is_empty() {
        return Ok(round.pending_blocks);
    }

    ibd.begin_header_sync();
    if start == 0 && round.pending_blocks.is_empty() {
        // A fresh page is validated once. The former per-header
        // loop re-decoded the complete prefix and rewrote the complete raw
        // header cache after every cursor advance (quadratic CPU and write
        // amplification). A crash before this bounded batch completes simply
        // re-requests it; the final transition is persisted atomically.
        let headers_for_validation = round.pending_headers.clone();
        let chain_for_validation = chain.clone();
        let pending_blocks = tokio::task::spawn_blocking(move || {
            let c = chain_for_validation.blocking_lock();
            match validation_mode {
                #[cfg(feature = "native-usdom-v4-poc")]
                IbdHeaderValidationMode::NativeUsdomV4(schedule) => c
                    .validate_native_usdom_v4_ibd_headers_batch_for_schedule(
                        &headers_for_validation,
                        now,
                        schedule,
                    ),
                #[cfg(feature = "native-usdom-v4-poc")]
                IbdHeaderValidationMode::NativeUsdomV2(schedule) => c
                    .validate_native_usdom_v2_ibd_headers_batch_for_schedule(
                        &headers_for_validation,
                        now,
                        schedule,
                    ),
                IbdHeaderValidationMode::Ordinary => {
                    c.validate_ibd_headers_batch(&headers_for_validation, now)
                }
            }
        })
        .await
        .map_err(|e| DomError::Internal(format!("IBD header validation task failed: {e}")))??;
        ibd.headers_height = ibd.headers_height.max(round.header_cursor_height);
        ibd.last_progress_height = ibd.last_progress_height.max(round.header_cursor_height);
        if pending_blocks.is_empty() {
            ibd.phase = dom_chain::IbdPhase::Discovering;
        } else {
            ibd.begin_block_sync();
        }
        persist_ibd_state(
            chain,
            peer_addr,
            ibd,
            IbdRoundState {
                pending_blocks: pending_blocks.clone(),
                pending_headers: Vec::new(),
                block_cursor: 0,
                header_cursor: 0,
                header_cursor_height: round.header_cursor_height,
            },
        )
        .await?;
        return Ok(pending_blocks);
    }

    let pending_headers = round.pending_headers;
    let mut pending_blocks = round.pending_blocks;

    for cursor in start..pending_headers.len() {
        let (height, updated_pending_blocks) = {
            let c = chain.lock().await;
            match validation_mode {
                #[cfg(feature = "native-usdom-v4-poc")]
                IbdHeaderValidationMode::NativeUsdomV4(schedule) => c
                    .validate_native_usdom_v4_ibd_header_step_for_schedule(
                        &pending_headers,
                        cursor,
                        &pending_blocks,
                        now,
                        schedule,
                    )?,
                #[cfg(feature = "native-usdom-v4-poc")]
                IbdHeaderValidationMode::NativeUsdomV2(schedule) => c
                    .validate_native_usdom_v2_ibd_header_step_for_schedule(
                        &pending_headers,
                        cursor,
                        &pending_blocks,
                        now,
                        schedule,
                    )?,
                IbdHeaderValidationMode::Ordinary => {
                    c.validate_ibd_header_step(&pending_headers, cursor, &pending_blocks, now)?
                }
            }
        };
        pending_blocks = updated_pending_blocks;
        ibd.headers_height = ibd.headers_height.max(height);
        ibd.last_progress_height = ibd.last_progress_height.max(height);
        persist_ibd_state(
            chain,
            peer_addr,
            ibd,
            IbdRoundState {
                pending_blocks: pending_blocks.clone(),
                pending_headers: pending_headers.clone(),
                block_cursor: 0,
                header_cursor: u32::try_from(cursor + 1)
                    .map_err(|_| DomError::Internal("header cursor overflow".into()))?,
                header_cursor_height: round.header_cursor_height,
            },
        )
        .await?;
    }

    if pending_blocks.is_empty() {
        ibd.phase = dom_chain::IbdPhase::Discovering;
    } else {
        ibd.begin_block_sync();
    }
    persist_ibd_state(
        chain,
        peer_addr,
        ibd,
        IbdRoundState {
            pending_blocks: pending_blocks.clone(),
            pending_headers: Vec::new(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: round.header_cursor_height,
        },
    )
    .await?;
    Ok(pending_blocks)
}

#[allow(clippy::too_many_arguments)]
async fn run_ibd_session(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    peer_addr: std::net::SocketAddr,
    peer_best_height: u64,
    fork_resolution: bool,
    future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    metrics: Arc<Metrics>,
    wallet: Option<Arc<Mutex<dom_wallet::WalletDir>>>,
    state_events: Arc<Notify>,
    channels: BroadcastChannels,
    native_usdom_v4_negotiated: bool,
    native_usdom_v2_negotiated: bool,
    svc: NodeServices,
) -> Result<(), DomError> {
    let Some(_ibd_active) =
        IbdActiveGuard::try_new(svc.ibd_active_sessions.clone(), state_events.clone())
    else {
        let local_height = chain.lock().await.tip_height.0;
        tracing::debug!(
            event = "ibd_deferred",
            peer_addr = %peer_addr,
            local_height,
            remote_height = peer_best_height,
            remaining_blocks = peer_best_height.saturating_sub(local_height),
            reason = "another IBD session owns the canonical sync cursor",
            "IBD session deferred"
        );
        return Ok(());
    };
    let our_height = chain.lock().await.tip_height.0;
    // IBD historically treated `local_height >= peer_height` as complete. That
    // leaves equal-height forks permanent: the peers have different tips but
    // never exchange the competing branch, so fork choice cannot compare work.
    // A synthetic one-block target keeps the existing header/body pipeline
    // active for exactly one fork-resolution round; the round exits below once
    // all advertised competing blocks have been connected as side-chain or
    // canonical data.
    let ibd_target_height = if fork_resolution {
        our_height.saturating_add(1)
    } else {
        peer_best_height
    };
    let (mut ibd, persisted) = initialize_ibd_state(chain, peer_addr, ibd_target_height).await?;
    let header_validation_mode =
        ibd_header_validation_mode(native_usdom_v4_negotiated, native_usdom_v2_negotiated, &svc)?;
    let runtime = IbdRuntimeContext {
        config,
        peer_addr,
        peer_id: codec.peer_id(),
        mempool: mempool.clone(),
        future_block_queue,
        metrics,
        wallet: wallet.clone(),
        state_events: state_events.clone(),
        channels,
        native_usdom_v4_negotiated,
        native_usdom_v2_negotiated,
        svc,
    };
    match ibd.begin_session() {
        dom_chain::IbdControl::Complete => {
            clear_persisted_ibd_state(chain).await?;
            info!(
                "IBD with {peer_addr} already complete at height {}",
                our_height
            );
            return Ok(());
        }
        dom_chain::IbdControl::Continue => {}
        dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
            return Err(DomError::Internal(
                "IBD state machine returned invalid initial control".into(),
            ));
        }
    }
    // `_ibd_active` keeps mining paused and serializes ownership of the single
    // persisted IBD cursor for the full session, including reconciliation.
    if let Some(snapshot) = persisted.clone() {
        if !snapshot.pending_headers.is_empty()
            && snapshot.header_cursor < snapshot.pending_headers.len() as u32
        {
            let pending_blocks = continue_ibd_header_sync(
                chain,
                peer_addr,
                &mut ibd,
                IbdRoundState {
                    pending_blocks: snapshot.pending_blocks.clone(),
                    pending_headers: snapshot.pending_headers.clone(),
                    block_cursor: snapshot.block_cursor,
                    header_cursor: snapshot.header_cursor,
                    header_cursor_height: snapshot.header_cursor_height,
                },
                ibd_now(),
                header_validation_mode,
            )
            .await?;
            if !pending_blocks.is_empty() {
                match resume_ibd_block_sync(
                    stream,
                    codec,
                    chain,
                    &runtime,
                    &mut ibd,
                    IbdRoundState {
                        pending_blocks,
                        pending_headers: Vec::new(),
                        block_cursor: 0,
                        header_cursor: 0,
                        header_cursor_height: snapshot.header_cursor_height,
                    },
                )
                .await
                {
                    Ok(true) => {
                        let new_height = chain.lock().await.tip_height.0;
                        match ibd.note_round_progress(new_height) {
                            dom_chain::IbdControl::Complete => {
                                clear_persisted_ibd_state(chain).await?;
                                info!(
                                    "IBD with {peer_addr} resumed and caught up at height {new_height}"
                                );
                                return Ok(());
                            }
                            dom_chain::IbdControl::Continue => {
                                persist_ibd_state(
                                    chain,
                                    peer_addr,
                                    &ibd,
                                    IbdRoundState {
                                        pending_blocks: Vec::new(),
                                        pending_headers: Vec::new(),
                                        block_cursor: 0,
                                        header_cursor: 0,
                                        header_cursor_height: ibd.headers_height,
                                    },
                                )
                                .await?;
                            }
                            dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
                                return Err(DomError::Internal(
                                    "resumed IBD progress transition returned invalid control"
                                        .into(),
                                ));
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(e) => match ibd.note_round_error(&e) {
                        dom_chain::IbdControl::Retry => {
                            let local_height = chain.lock().await.tip_height.0;
                            warn!(
                                event = "ibd_interrupted",
                                peer_addr = %peer_addr,
                                peer_id = %runtime.peer_id.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
                                phase = ?ibd.phase,
                                local_height,
                                remote_height = ibd.best_peer_height,
                                remaining_blocks = ibd.best_peer_height.saturating_sub(local_height),
                                retry_attempt = ibd.retry_attempts,
                                retries_remaining = ibd.remaining_retries(),
                                reason = %e,
                                "IBD interrupted; reconnect required"
                            );
                            return Err(e);
                        }
                        dom_chain::IbdControl::Fail => {
                            clear_persisted_ibd_state(chain).await?;
                            return Err(e);
                        }
                        dom_chain::IbdControl::Complete | dom_chain::IbdControl::Continue => {
                            return Err(DomError::Internal(
                                "resumed IBD error transition returned invalid control".into(),
                            ));
                        }
                    },
                }
            } else {
                persist_ibd_state(
                    chain,
                    peer_addr,
                    &ibd,
                    IbdRoundState {
                        pending_blocks: Vec::new(),
                        pending_headers: Vec::new(),
                        block_cursor: 0,
                        header_cursor: 0,
                        header_cursor_height: ibd.headers_height,
                    },
                )
                .await?;
            }
        } else if !snapshot.pending_blocks.is_empty()
            && snapshot.block_cursor < snapshot.pending_blocks.len() as u32
        {
            match resume_ibd_block_sync(
                stream,
                codec,
                chain,
                &runtime,
                &mut ibd,
                IbdRoundState {
                    pending_blocks: snapshot.pending_blocks.clone(),
                    pending_headers: Vec::new(),
                    block_cursor: snapshot.block_cursor,
                    header_cursor: 0,
                    header_cursor_height: snapshot.header_cursor_height,
                },
            )
            .await
            {
                Ok(true) => {
                    let new_height = chain.lock().await.tip_height.0;
                    match ibd.note_round_progress(new_height) {
                        dom_chain::IbdControl::Complete => {
                            clear_persisted_ibd_state(chain).await?;
                            info!(
                                "IBD with {peer_addr} resumed and caught up at height {new_height}"
                            );
                            return Ok(());
                        }
                        dom_chain::IbdControl::Continue => {
                            persist_ibd_state(
                                chain,
                                peer_addr,
                                &ibd,
                                IbdRoundState {
                                    pending_blocks: Vec::new(),
                                    pending_headers: Vec::new(),
                                    block_cursor: 0,
                                    header_cursor: 0,
                                    header_cursor_height: ibd.headers_height,
                                },
                            )
                            .await?;
                        }
                        dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
                            return Err(DomError::Internal(
                                "resumed IBD progress transition returned invalid control".into(),
                            ));
                        }
                    }
                }
                Ok(false) => {}
                Err(e) => match ibd.note_round_error(&e) {
                    dom_chain::IbdControl::Retry => {
                        let local_height = chain.lock().await.tip_height.0;
                        warn!(
                            event = "ibd_interrupted",
                            peer_addr = %peer_addr,
                            peer_id = %runtime.peer_id.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
                            phase = ?ibd.phase,
                            local_height,
                            remote_height = ibd.best_peer_height,
                            remaining_blocks = ibd.best_peer_height.saturating_sub(local_height),
                            retry_attempt = ibd.retry_attempts,
                            retries_remaining = ibd.remaining_retries(),
                            reason = %e,
                            "IBD interrupted; reconnect required"
                        );
                        return Err(e);
                    }
                    dom_chain::IbdControl::Fail => {
                        clear_persisted_ibd_state(chain).await?;
                        return Err(e);
                    }
                    dom_chain::IbdControl::Complete | dom_chain::IbdControl::Continue => {
                        return Err(DomError::Internal(
                            "resumed IBD error transition returned invalid control".into(),
                        ));
                    }
                },
            }
        } else {
            persist_ibd_state(
                chain,
                peer_addr,
                &ibd,
                IbdRoundState {
                    pending_blocks: Vec::new(),
                    pending_headers: Vec::new(),
                    block_cursor: 0,
                    header_cursor: 0,
                    header_cursor_height: ibd.headers_height,
                },
            )
            .await?;
        }
    } else {
        persist_ibd_state(
            chain,
            peer_addr,
            &ibd,
            IbdRoundState {
                pending_blocks: Vec::new(),
                pending_headers: Vec::new(),
                block_cursor: 0,
                header_cursor: 0,
                header_cursor_height: ibd.headers_height,
            },
        )
        .await?;
    }

    tracing::info!(
        event = "ibd_started",
        peer_addr = %peer_addr,
        peer_id = %runtime.peer_id.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
        phase = ?ibd.phase,
        local_height = our_height,
        remote_height = peer_best_height,
        fork_resolution,
        remaining_blocks = peer_best_height.saturating_sub(our_height),
        progress_percent = if peer_best_height == 0 {
            100.0
        } else {
            (our_height as f64 * 100.0 / peer_best_height as f64).min(100.0)
        },
        "IBD started"
    );

    loop {
        ibd.begin_header_sync();
        match ibd_sync_round(
            stream,
            codec,
            config,
            chain,
            mempool,
            peer_addr,
            runtime.future_block_queue.clone(),
            runtime.metrics.clone(),
            wallet.clone(),
            state_events.clone(),
            runtime.channels.clone(),
            runtime.native_usdom_v4_negotiated,
            runtime.native_usdom_v2_negotiated,
            runtime.svc.clone(),
            &mut ibd,
        )
        .await
        {
            Ok(true) => {
                if fork_resolution {
                    clear_persisted_ibd_state(chain).await?;
                    let (local_height, local_hash) = {
                        let chain = chain.lock().await;
                        (chain.tip_height.0, *chain.tip_hash.as_bytes())
                    };
                    info!(
                        "fork-resolution IBD with {peer_addr} completed: local_height={local_height} local_hash={} peer_height={peer_best_height}",
                        hex::encode(local_hash)
                    );
                    return Ok(());
                }
                let new_height = chain.lock().await.tip_height.0;
                match ibd.note_round_progress(new_height) {
                    dom_chain::IbdControl::Complete => {
                        clear_persisted_ibd_state(chain).await?;
                        info!("IBD with {peer_addr} caught up at height {new_height}");
                        return Ok(());
                    }
                    dom_chain::IbdControl::Continue => {
                        persist_ibd_state(
                            chain,
                            peer_addr,
                            &ibd,
                            IbdRoundState {
                                pending_blocks: Vec::new(),
                                pending_headers: Vec::new(),
                                block_cursor: 0,
                                header_cursor: 0,
                                header_cursor_height: ibd.headers_height,
                            },
                        )
                        .await?;
                        continue;
                    }
                    dom_chain::IbdControl::Retry | dom_chain::IbdControl::Fail => {
                        return Err(DomError::Internal(
                            "IBD progress transition returned invalid control".into(),
                        ));
                    }
                }
            }
            Ok(false) if fork_resolution => {
                clear_persisted_ibd_state(chain).await?;
                info!("fork-resolution IBD with {peer_addr} found no unknown competing blocks");
                return Ok(());
            }
            Ok(false) => match ibd.note_empty_response() {
                dom_chain::IbdControl::Complete => {
                    clear_persisted_ibd_state(chain).await?;
                    info!(
                        "IBD with {peer_addr} completed after empty response at height {}",
                        ibd.blocks_height
                    );
                    return Ok(());
                }
                dom_chain::IbdControl::Retry => {
                    persist_ibd_state(
                        chain,
                        peer_addr,
                        &ibd,
                        IbdRoundState {
                            pending_blocks: Vec::new(),
                            pending_headers: Vec::new(),
                            block_cursor: 0,
                            header_cursor: 0,
                            header_cursor_height: ibd.headers_height,
                        },
                    )
                    .await?;
                    warn!(
                        "IBD with {peer_addr} made no progress; retry {}/{} remaining={}",
                        ibd.retry_attempts,
                        dom_chain::ibd::MAX_IBD_RETRY_ATTEMPTS,
                        ibd.remaining_retries()
                    );
                    continue;
                }
                dom_chain::IbdControl::Fail => {
                    clear_persisted_ibd_state(chain).await?;
                    return Err(DomError::PolicyRejected(format!(
                        "IBD from {peer_addr}: exhausted retry budget after empty response"
                    )));
                }
                dom_chain::IbdControl::Continue => {
                    return Err(DomError::Internal(
                        "IBD empty-response transition returned invalid control".into(),
                    ));
                }
            },
            Err(e) => match ibd.note_round_error(&e) {
                dom_chain::IbdControl::Retry => {
                    let local_height = chain.lock().await.tip_height.0;
                    warn!(
                        event = "ibd_interrupted",
                        peer_addr = %peer_addr,
                        peer_id = %runtime.peer_id.map(hex::encode).unwrap_or_else(|| "unavailable".into()),
                        phase = ?ibd.phase,
                        local_height,
                        remote_height = ibd.best_peer_height,
                        remaining_blocks = ibd.best_peer_height.saturating_sub(local_height),
                        retry_attempt = ibd.retry_attempts,
                        retries_remaining = ibd.remaining_retries(),
                        reason = %e,
                        "IBD interrupted; reconnect required"
                    );
                    // NoiseCodec treats every receive error as fatal for this
                    // transport. Retrying on the same stream only consumes the
                    // retry budget and eventually deletes a valid checkpoint.
                    // Keep the last durable snapshot and let the peer connector
                    // establish a fresh authenticated session.
                    return Err(e);
                }
                dom_chain::IbdControl::Fail => {
                    clear_persisted_ibd_state(chain).await?;
                    return Err(e);
                }
                dom_chain::IbdControl::Complete => {
                    clear_persisted_ibd_state(chain).await?;
                    return Ok(());
                }
                dom_chain::IbdControl::Continue => {
                    return Err(DomError::Internal(
                        "IBD error transition returned invalid control".into(),
                    ));
                }
            },
        }
    }
}

/// Run a single IBD sync round against one peer.
///
/// Sends GetHeaders, receives headers, requests bodies in batches, and connects
/// each block via ChainState::connect_block. Returns Ok(true) if any progress
/// was made (at least one block accepted), Ok(false) if peer had nothing new.
#[allow(clippy::too_many_arguments)]
async fn ibd_sync_round(
    stream: &mut tokio::net::TcpStream,
    codec: &mut dom_wire::codec::NoiseCodec,
    config: &NodeConfig,
    chain: &Arc<Mutex<ChainState>>,
    mempool: &Arc<Mutex<Mempool>>,
    peer_addr: std::net::SocketAddr,
    future_block_queue: Arc<crate::future_block_queue::FutureBlockQueue>,
    metrics: Arc<Metrics>,
    wallet: Option<Arc<Mutex<dom_wallet::WalletDir>>>,
    state_events: Arc<Notify>,
    channels: BroadcastChannels,
    native_usdom_v4_negotiated: bool,
    native_usdom_v2_negotiated: bool,
    svc: NodeServices,
    ibd: &mut dom_chain::IbdState,
) -> Result<bool, DomError> {
    use dom_consensus::block::BlockHeader;
    use dom_serialization::DomDeserialize;
    use dom_wire::message::{Command, GetHeadersPayload, HeadersPayload, WireMessage};

    // 1. Request headers from peer using our locator.
    let locator = build_locator(chain).await?;
    let req = GetHeadersPayload {
        locator_hashes: locator,
        stop_hash: [0u8; 32],
    };
    let wire = WireMessage {
        magic: config.network.magic(),
        command: Command::GetHeaders,
        payload: req.to_bytes()?,
    };
    codec.send(stream, &wire).await?;

    // 2. Receive Headers (skip non-Headers messages).
    let headers_msg = loop {
        let msg = codec
            .recv_with_idle_timeout(
                stream,
                tokio::time::Duration::from_secs(dom_wire::handshake::IBD_IDLE_TIMEOUT_SECS),
            )
            .await?;
        match msg.command {
            Command::Headers => break msg,
            Command::Ping => {
                let pong = WireMessage {
                    magic: config.network.magic(),
                    command: Command::Pong,
                    payload: msg.payload,
                };
                codec.send(stream, &pong).await?;
            }
            Command::Pong => {}
            other => {
                tracing::debug!("IBD: ignoring {other:?} while waiting for Headers");
            }
        }
    };
    let headers_payload = HeadersPayload::from_bytes(&headers_msg.payload)?;
    if headers_payload.headers.is_empty() {
        return Ok(false); // peer has nothing new for us
    }

    let now = ibd_now();
    let header_cursor_height = BlockHeader::from_bytes(
        headers_payload
            .headers
            .last()
            .ok_or_else(|| DomError::Internal("headers payload unexpectedly empty".into()))?,
    )?
    .height
    .0;

    let header_validation_mode =
        ibd_header_validation_mode(native_usdom_v4_negotiated, native_usdom_v2_negotiated, &svc)?;

    let block_hashes = continue_ibd_header_sync(
        chain,
        peer_addr,
        ibd,
        IbdRoundState {
            pending_blocks: Vec::new(),
            pending_headers: headers_payload.headers.clone(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height,
        },
        now,
        header_validation_mode,
    )
    .await?;

    if block_hashes.is_empty() {
        tracing::debug!(
            "IBD: peer sent {} headers but all are already in our store — no bodies to fetch",
            headers_payload.headers.len()
        );
        return Ok(false);
    }

    let runtime = IbdRuntimeContext {
        config,
        peer_addr,
        peer_id: codec.peer_id(),
        mempool: mempool.clone(),
        future_block_queue,
        metrics,
        wallet,
        state_events,
        channels,
        native_usdom_v4_negotiated,
        native_usdom_v2_negotiated,
        svc,
    };
    resume_ibd_block_sync(
        stream,
        codec,
        chain,
        &runtime,
        ibd,
        IbdRoundState {
            pending_blocks: block_hashes,
            pending_headers: Vec::new(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height,
        },
    )
    .await
}

/// Build a Headers response for a GetHeaders request.
///
/// Finds the most recent locator hash on our main chain, then returns up to
/// MAX_HEADERS_PER_MSG headers forward from there, stopping at stop_hash or tip.
async fn build_headers_response(
    chain: &Arc<Mutex<ChainState>>,
    req: &dom_wire::message::GetHeadersPayload,
) -> Result<Vec<Vec<u8>>, DomError> {
    use dom_serialization::DomDeserialize;
    let c = chain.lock().await;
    let tip_height = c.tip_height.0;

    let mut start_height: u64 = 0;
    for h in &req.locator_hashes {
        if let Some(header_bytes) = c.store.get_block_header(h)? {
            let header = dom_consensus::block::BlockHeader::from_bytes(&header_bytes)?;
            if c.store.get_hash_at_height(header.height.0)? == Some(*h) {
                start_height = header.height.0 + 1;
                break;
            }
        }
    }

    let max = dom_core::MAX_HEADERS_PER_MSG;
    let stop_is_zero = req.stop_hash == [0u8; 32];
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(max);
    let mut h = start_height;
    while h <= tip_height && out.len() < max {
        let hash = match c.store.get_hash_at_height(h)? {
            Some(x) => x,
            None => break,
        };
        let bytes = match c.store.get_block_header(&hash)? {
            Some(b) => b,
            None => break,
        };
        out.push(bytes);
        if !stop_is_zero && hash == req.stop_hash {
            break;
        }
        h += 1;
    }
    Ok(out)
}

fn getblockdata_hashes_to_serve(hashes: &[[u8; 32]]) -> &[[u8; 32]] {
    &hashes[..hashes.len().min(dom_core::MAX_GETBLOCKDATA_SERVE_HASHES)]
}

#[cfg(feature = "native-usdom-v4-poc")]
fn block_data_response(
    network_magic: u32,
    native_usdom_v4_negotiated: bool,
    native_usdom_v2_negotiated: bool,
    native_package: Option<Vec<u8>>,
    native_v2_witnesses: Option<Vec<u8>>,
    ordinary_block: Option<Vec<u8>>,
) -> Result<Option<dom_wire::message::WireMessage>, DomError> {
    use dom_wire::message::{
        BlockPayload, Command, UsdomV2PackagePayload, UsdomV4PackagePayload, WireMessage,
    };

    if let Some(package_bytes) = native_package {
        if let Some(witness_bytes) = native_v2_witnesses {
            if !native_usdom_v2_negotiated {
                return Ok(None);
            }
            return Ok(Some(WireMessage {
                magic: network_magic,
                command: Command::UsdomV2Package,
                payload: UsdomV2PackagePayload {
                    package_bytes,
                    witness_bytes,
                }
                .to_bytes()?,
            }));
        }
        if !native_usdom_v4_negotiated {
            // Never downgrade a native-v4 block into the ordinary Block
            // command. A legacy session cannot validate its proof envelope.
            return Ok(None);
        }
        return Ok(Some(WireMessage {
            magic: network_magic,
            command: Command::UsdomV4Package,
            payload: UsdomV4PackagePayload { package_bytes }.to_bytes()?,
        }));
    }
    ordinary_block
        .map(|block_bytes| {
            Ok(WireMessage {
                magic: network_magic,
                command: Command::Block,
                payload: BlockPayload { block_bytes }.to_bytes()?,
            })
        })
        .transpose()
}

#[cfg(feature = "native-usdom-v4-poc")]
async fn load_block_data_response(
    chain: Arc<Mutex<ChainState>>,
    network_magic: u32,
    native_v1_runtime_enabled: bool,
    native_v2_runtime_enabled: bool,
    native_usdom_v4_negotiated: bool,
    native_usdom_v2_negotiated: bool,
    hash: [u8; 32],
) -> Result<Option<dom_wire::message::WireMessage>, DomError> {
    tokio::task::spawn_blocking(move || {
        let chain = chain.blocking_lock();
        let native_package = if native_v1_runtime_enabled || native_v2_runtime_enabled {
            dom_chain::load_persisted_usdom_v4_package(
                &chain.store,
                network_magic,
                Hash256::from_bytes(hash),
            )?
        } else {
            None
        };
        let native_v2_witnesses = if native_v2_runtime_enabled && native_package.is_some() {
            dom_chain::load_persisted_usdom_v2_execution_witnesses(
                &chain.store,
                Hash256::from_bytes(hash),
            )?
            .map(|witnesses| witnesses.to_bytes())
            .transpose()?
        } else {
            None
        };
        let ordinary_block = if native_package.is_none() {
            chain.store.get_block_body(&hash)?
        } else {
            None
        };
        block_data_response(
            network_magic,
            native_usdom_v4_negotiated,
            native_usdom_v2_negotiated,
            native_package,
            native_v2_witnesses,
            ordinary_block,
        )
    })
    .await
    .map_err(|e| DomError::Internal(format!("block-data read task failed: {e}")))?
}

fn catchup_interval() -> tokio::time::Interval {
    let mut timer = tokio::time::interval(tokio::time::Duration::from_secs(
        CATCHUP_CHECK_INTERVAL_SECS,
    ));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    timer
}

#[cfg(feature = "native-usdom-v4-poc")]
fn unix_time_seconds() -> Result<u64, DomError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| DomError::Internal("system clock precedes Unix epoch".into()))
}

#[cfg(feature = "native-usdom-v4-poc")]
fn checkpoint_sync_tip(chain: &ChainState) -> dom_usdom_checkpoint_program::SyncTip {
    let mut total_difficulty = [0; 32];
    chain.tip_difficulty.to_big_endian(&mut total_difficulty);
    dom_usdom_checkpoint_program::SyncTip {
        network_magic: chain.network_magic,
        chain_id: *derive_chain_id(chain.network_magic, &chain.genesis_hash).as_bytes(),
        height: chain.tip_height.0,
        block: *chain.tip_hash.as_bytes(),
        total_difficulty,
    }
}

#[cfg(feature = "native-usdom-v4-poc")]
fn sync_tip_payload(chain: &ChainState, generated_at: u64) -> dom_wire::message::SyncTipPayload {
    let tip = checkpoint_sync_tip(chain);
    dom_wire::message::SyncTipPayload {
        network_magic: tip.network_magic,
        chain_id: tip.chain_id,
        height: tip.height,
        block: tip.block,
        total_difficulty: tip.total_difficulty,
        generated_at,
    }
}

async fn message_loop(
    conn: PeerConn<'_>,
    config: &NodeConfig,
    peer_addr: std::net::SocketAddr,
    chain: Arc<Mutex<ChainState>>,
    channels: BroadcastChannels,
    svc: NodeServices,
    shutdown: ShutdownToken,
) -> Result<(), DomError> {
    // Subscribe to all broadcast channels for this peer connection.
    let mut block_relay_rx = channels.block_relay_tx.subscribe();
    let block_relay_tx = channels.block_relay_tx.clone();
    let mut native_usdom_v4_relay_rx = {
        #[cfg(feature = "native-usdom-v4-poc")]
        {
            Some(channels.native_usdom_v4_relay_tx.subscribe())
        }
        #[cfg(not(feature = "native-usdom-v4-poc"))]
        {
            None
        }
    };
    let mut native_usdom_v2_relay_rx = {
        #[cfg(feature = "native-usdom-v4-poc")]
        {
            Some(channels.native_usdom_v2_relay_tx.subscribe())
        }
        #[cfg(not(feature = "native-usdom-v4-poc"))]
        {
            None
        }
    };
    let mut tx_fluff_rx = channels.tx_fluff_tx.subscribe();
    let tx_fluff_tx = channels.tx_fluff_tx.clone();
    let mut tx_stem_rx = channels.tx_stem_tx.subscribe();
    let tx_stem_tx = channels.tx_stem_tx.clone();
    let PeerConn {
        stream,
        codec,
        #[cfg(feature = "native-usdom-v4-poc")]
        native_usdom_v4_negotiated,
        #[cfg(feature = "native-usdom-v4-poc")]
        native_usdom_v2_negotiated,
        #[cfg(feature = "native-usdom-v4-poc")]
        sync_tip_v1_negotiated,
    } = conn;
    #[cfg(feature = "native-usdom-v4-poc")]
    let ibd_native_usdom_v4_negotiated = native_usdom_v4_negotiated;
    #[cfg(not(feature = "native-usdom-v4-poc"))]
    let ibd_native_usdom_v4_negotiated = false;
    #[cfg(feature = "native-usdom-v4-poc")]
    let ibd_native_usdom_v2_negotiated = native_usdom_v2_negotiated;
    #[cfg(not(feature = "native-usdom-v4-poc"))]
    let ibd_native_usdom_v2_negotiated = false;
    #[cfg(feature = "native-usdom-v4-poc")]
    use dom_wire::message::SyncTipPayload;
    use dom_wire::message::{
        AddrPayload, BlockPayload, Command, GetAddrPayload, GetBlockDataPayload, GetHeadersPayload,
        HeadersPayload, WireMessage,
    };

    const PING_INTERVAL_SECS: u64 = 30;
    let mut ping_timer =
        tokio::time::interval(tokio::time::Duration::from_secs(PING_INTERVAL_SECS));
    // Skip: a delayed connection needs one current liveness probe, never a
    // burst of historical pings.
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick.
    ping_timer.tick().await;
    let mut catchup_timer = catchup_interval();
    // Skip: IBD can occupy this select arm for minutes. Replaying every missed
    // tick would advance the re-request clock in a burst and flood the seed.
    catchup_timer.tick().await;

    // PEX (RFC-0005 §6): periodically consider asking this peer for addresses.
    // The per-peer GETADDR_COOLDOWN_SECS inside PexManager is the real rate
    // limit; this timer only paces the check.
    let mut pex_timer =
        tokio::time::interval(tokio::time::Duration::from_secs(PEX_GETADDR_TICK_SECS));
    // Skip: PEX has its own cooldown; historical checks have no useful work.
    pex_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    pex_timer.tick().await;
    let pex_peer_key = peer_addr.to_string();
    // Part D — highest block height this peer relayed whose parent we lacked
    // (an orphan above our tip). The catch-up tick below re-syncs toward
    // max(peer Hello height, this) via IBD, so a live-relayed orphan hole is
    // rebuilt even though `peer_best_height` is only refreshed at Hello.
    let mut blocked_orphan_target: u64 = 0;
    // Inbound Addr rate limit for THIS connection: beyond the budget each
    // extra Addr message scores ADDRESS_FLOODING instead of being processed.
    let mut addr_flood = crate::pex::AddrFloodTracker::new();
    // Per-category inbound message rate limit for THIS connection (anti-flood):
    // a peer that floods one category scores PROTOCOL_VIOLATION and, on
    // sustained overflow, is disconnected — without affecting other peers
    // (each connection has its own limiter). GetAddr/Addr are excluded here
    // (they have their own limiters above).
    let mut msg_rate = crate::msg_rate_limit::MessageRateLimiter::from_env();
    // Block bodies explicitly requested by this connection are sync responses,
    // not unsolicited relay traffic. This set makes that distinction before
    // the per-category limiter decides whether an overflow may affect score.
    let mut outstanding_sync_blocks = HashSet::<[u8; 32]>::new();

    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                return Ok(());
            }
            // Relay broadcast: someone (miner or another peer task) wants to send a Block
            relay = block_relay_rx.recv() => {
                match relay {
                    Ok(block_bytes) => {
                        let payload = BlockPayload { block_bytes };
                        let msg = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Block,
                            payload: payload.to_bytes()?,
                        };
                        if let Err(e) = codec.send(stream, &msg).await {
                            return Err(annotate_send_err("relay", peer_addr, e));
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("relay lagged by {n} for {peer_addr}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(DomError::Internal("relay channel closed".into()));
                    }
                }
            }
            native_relay = receive_native_usdom_v4_relay(&mut native_usdom_v4_relay_rx) => {
                #[cfg(feature = "native-usdom-v4-poc")]
                {
                    match native_relay {
                        Ok(relay) => {
                            if let Some(msg) = native_usdom_v4_relay_message(
                                config.network.magic(),
                                native_usdom_v4_negotiated,
                                peer_addr,
                                relay,
                            ) {
                                if let Err(e) = codec.send(stream, &msg).await {
                                    return Err(annotate_send_err(
                                        "native USDOM v4 relay",
                                        peer_addr,
                                        e,
                                    ));
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            // Unlike ordinary blocks, native package IBD is not
                            // available yet. Continuing after dropping one
                            // package would leave this peer on an unknowingly
                            // discontinuous stream. Close locally without peer
                            // scoring; reconnect/recovery remains explicit.
                            return Err(DomError::Internal(format!(
                                "native USDOM v4 relay lagged by {n} for {peer_addr}"
                            )));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return Err(DomError::Internal(
                                "native USDOM v4 relay channel closed".into(),
                            ));
                        }
                    }
                }
                #[cfg(not(feature = "native-usdom-v4-poc"))]
                {
                    let _ = native_relay;
                    unreachable!("disabled native relay future cannot become ready");
                }
            }
            native_v2_relay = receive_native_usdom_v2_relay(&mut native_usdom_v2_relay_rx) => {
                #[cfg(feature = "native-usdom-v4-poc")]
                {
                    match native_v2_relay {
                        Ok(relay) => {
                            if let Some(msg) = native_usdom_v2_relay_message(
                                config.network.magic(),
                                native_usdom_v2_negotiated,
                                peer_addr,
                                relay,
                            ) {
                                if let Err(error) = codec.send(stream, &msg).await {
                                    return Err(annotate_send_err(
                                        "native USDOM V2 relay",
                                        peer_addr,
                                        error,
                                    ));
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            return Err(DomError::Internal(format!(
                                "native USDOM V2 relay lagged by {n} for {peer_addr}"
                            )));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            return Err(DomError::Internal(
                                "native USDOM V2 relay channel closed".into(),
                            ));
                        }
                    }
                }
                #[cfg(not(feature = "native-usdom-v4-poc"))]
                {
                    let _ = native_v2_relay;
                    unreachable!("disabled native V2 relay future cannot become ready");
                }
            }
            // Dandelion++ Fluff: a transaction we want to broadcast to every peer.
            // Each connected peer task receives every Fluff envelope and forwards it.
            fluff = tx_fluff_rx.recv() => {
                match fluff {
                    Ok(tx_bytes) => {
                        let msg = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Tx,
                            payload: tx_bytes,
                        };
                        if let Err(e) = codec.send(stream, &msg).await {
                            return Err(annotate_send_err("fluff", peer_addr, e));
                        }
                        svc.metrics
                            .txs_relayed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Neither the peer nor the precise missed-envelope count
                        // belongs in telemetry: together with wall-clock log time
                        // they expose a per-peer transaction propagation signal.
                        tracing::warn!("transaction fluff relay receiver lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(DomError::Internal("tx_fluff channel closed".into()));
                    }
                }
            }
            // Dandelion++ Stem: a transaction to be forwarded to ONE specific peer.
            // Every peer task receives the envelope, but only the task whose
            // peer_addr matches StemEnvelope.target_peer actually sends. This
            // preserves source-anonymity per the Dandelion++ paper.
            stem = tx_stem_rx.recv() => {
                match stem {
                    Ok(env) => {
                        if env.target_peer == peer_addr {
                            let msg = WireMessage {
                                magic: config.network.magic(),
                                command: Command::Tx,
                                payload: env.tx_bytes,
                            };
                            if let Err(e) = codec.send(stream, &msg).await {
                                return Err(redact_stem_send_err(e));
                            }
                            svc.metrics
                                .txs_relayed
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        // else: this envelope is targeted at a different peer; ignore
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // A stem receiver is the selected privacy hop. Logging its
                        // address or exact queue delta makes that choice observable.
                        tracing::warn!("transaction stem relay receiver lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return Err(DomError::Internal("tx_stem channel closed".into()));
                    }
                }
            }
            // Periodic ping
            _ = ping_timer.tick() => {
                let nonce: [u8; 8] = rand::random();
                let ping = WireMessage {
                    magic: config.network.magic(),
                    command: Command::Ping,
                    payload: nonce.to_vec(),
                };
                if let Err(e) = codec.send(stream, &ping).await {
                    return Err(annotate_send_err("ping", peer_addr, e));
                }
                #[cfg(feature = "native-usdom-v4-poc")]
                if sync_tip_v1_negotiated {
                    let generated_at = unix_time_seconds()?;
                    let payload = {
                        let chain = chain.lock().await;
                        sync_tip_payload(&chain, generated_at)
                    };
                    let advertisement = WireMessage {
                        magic: config.network.magic(),
                        command: Command::SyncTip,
                        payload: payload.to_bytes()?,
                    };
                    if let Err(error) = codec.send(stream, &advertisement).await {
                        return Err(annotate_send_err("sync-tip", peer_addr, error));
                    }
                }
            }
            _ = catchup_timer.tick() => {
                // Part A — persistent re-request tick. Advancing the tracker's
                // clock here (and only here) is what moves per-hash backoff
                // forward at a fixed cadence, independent of orphan-arrival rate.
                // A known-missing parent whose buffered orphan was evicted is
                // still pursued to convergence, with the interval growing (capped)
                // so re-request can never become a flood.
                let rerequest = {
                    let mut tracker = svc.missing_blocks.lock().await;
                    let round = tracker.advance_round();
                    tracker.next_request_batch(round)
                };
                if !rerequest.is_empty() {
                    outstanding_sync_blocks.extend(rerequest.iter().copied());
                    let req = GetBlockDataPayload { hashes: rerequest };
                    let wire = WireMessage {
                        magic: config.network.magic(),
                        command: Command::GetBlockData,
                        payload: req.to_bytes()?,
                    };
                    if let Err(e) = codec.send(stream, &wire).await {
                        return Err(annotate_send_err("missing-parent re-request", peer_addr, e));
                    }
                }

                // Part D — active recovery via IBD. Re-sync when we are behind a
                // known-higher tip but blocked by a missing intermediate block.
                // The target is the max of the peer's Hello-advertised height and
                // any orphan this peer relayed above our tip; the latter catches
                // the live-relay hole that `peer_best_height` alone misses.
                // Reuses the proven IBD path, which rebuilds the gap from our tip
                // regardless of what the buffered orphan pool retained.
                let our_height = chain.lock().await.tip_height.0;
                let peer_best_height = {
                    let peers = svc.peers.lock().await;
                    peers.peer_best_height(&pex_peer_key)
                };
                let target = peer_best_height.unwrap_or(0).max(blocked_orphan_target);
                if target > our_height {
                    Box::pin(run_ibd_session(
                        stream,
                        codec,
                        config,
                        &chain,
                        &svc.mempool,
                        peer_addr,
                        target,
                        false,
                        svc.future_block_queue.clone(),
                        svc.metrics.clone(),
                        svc.wallet.clone(),
                        svc.state_events.clone(),
                        channels.clone(),
                        ibd_native_usdom_v4_negotiated,
                        ibd_native_usdom_v2_negotiated,
                        svc.clone(),
                    ))
                    .await?;
                }
            }
            // Periodic PEX: solicit addresses while our known set is below
            // target, at most once per GETADDR_COOLDOWN_SECS per peer.
            // Decision is taken (and recorded) under the lock; the guard is
            // dropped before the send await.
            _ = pex_timer.tick() => {
                let send_getaddr = {
                    let mut px = trace_lock("pex", &svc.pex).await;
                    if px.known_count() < PEX_TARGET_KNOWN_PEERS
                        && px.should_getaddr(&pex_peer_key)
                    {
                        px.record_getaddr(&pex_peer_key);
                        true
                    } else {
                        false
                    }
                };
                if send_getaddr {
                    let msg = WireMessage {
                        magic: config.network.magic(),
                        command: Command::GetAddr,
                        payload: GetAddrPayload.to_bytes()?,
                    };
                    if let Err(e) = codec.send(stream, &msg).await {
                        return Err(annotate_send_err("getaddr", peer_addr, e));
                    }
                }
            }
            // Inbound message
            recv = codec.recv(stream) => {
                let msg = match recv {
                    Ok(msg) => msg,
                    Err(e) => {
                        let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
                        return Err(e);
                    }
                };
                // Anti-flood: sync request/response overflow is paced and
                // dropped without reputation damage. Other categories may
                // score only their first excess in each fixed window.
                let requested_block_response =
                    msg.command == Command::Block && !outstanding_sync_blocks.is_empty();
                if let crate::msg_rate_limit::RateLimitDecision::Throttle {
                    category,
                    score_violation,
                } = msg_rate.check(msg.command, requested_block_response)
                {
                    let err = DomError::peer_misbehavior(
                        PeerMisbehavior::MessageRateLimit,
                        format!(
                            "message rate limit exceeded for {:?} [ban+{}]",
                            msg.command,
                            dom_wire::peer::ban_scores::PROTOCOL_VIOLATION,
                        ),
                    );
                    if category == crate::msg_rate_limit::RateCategory::Sync {
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            crate::msg_rate_limit::SYNC_THROTTLE_DELAY_MS,
                        ))
                        .await;
                    } else if score_violation
                        && record_peer_violation(&chain, &svc.peers, peer_addr, &err).await
                    {
                        return Err(err);
                    }
                    tracing::debug!(
                        ?category,
                        score_violation,
                        "rate-limited {:?} from {peer_addr}; dropping message", msg.command
                    );
                    continue;
                }
                match msg.command {
                    Command::Ping => {
                        // Echo payload as Pong
                        let pong = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Pong,
                            payload: msg.payload,
                        };
                        codec.send(stream, &pong).await?;
                    }
                    Command::Pong => {
                        // Liveness confirmed; nothing else to do until peer tracking added
                    }
                    #[cfg(feature = "native-usdom-v4-poc")]
                    Command::SyncTip => {
                        if !sync_tip_v1_negotiated {
                            let error = DomError::Malformed(
                                "sync-tip received without negotiated capability [ban+20]".into(),
                            );
                            let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &error).await;
                            return Err(error);
                        }
                        let payload = match SyncTipPayload::from_bytes(&msg.payload) {
                            Ok(payload) => payload,
                            Err(error) => {
                                let _ = record_peer_violation(
                                    &chain,
                                    &svc.peers,
                                    peer_addr,
                                    &error,
                                )
                                .await;
                                return Err(error);
                            }
                        };
                        let peer_id = codec.peer_id().ok_or_else(|| {
                            DomError::PolicyRejected(
                                "sync-tip session has no authenticated Noise identity".into(),
                            )
                        })?;
                        let received_at = unix_time_seconds()?;
                        let local_tip = {
                            let chain = chain.lock().await;
                            checkpoint_sync_tip(&chain)
                        };
                        let advertised_tip = dom_usdom_checkpoint_program::SyncTip {
                            network_magic: payload.network_magic,
                            chain_id: payload.chain_id,
                            height: payload.height,
                            block: payload.block,
                            total_difficulty: payload.total_difficulty,
                        };
                        let receipt = {
                            let Some(collector) = svc.sync_attestation_collector.as_ref() else {
                                // Transport support is network-wide. Nodes without a
                                // ratified local policy announce their own tip but retain
                                // no remote observations and can never persist a receipt.
                                continue;
                            };
                            let observed = {
                                let mut collector = collector.lock().await;
                                collector.observe(
                                    peer_id,
                                    advertised_tip,
                                    payload.generated_at,
                                    received_at,
                                    local_tip,
                                )
                            };
                            match observed {
                                Ok(receipt) => receipt,
                                Err(error) => {
                                    let _ = record_peer_violation(
                                        &chain,
                                        &svc.peers,
                                        peer_addr,
                                        &error,
                                    )
                                    .await;
                                    return Err(error);
                                }
                            }
                        };
                        if let Some(receipt) = receipt {
                            let policy = svc
                                .sync_attestation_collector
                                .as_ref()
                                .expect("negotiated collector")
                                .lock()
                                .await
                                .policy()
                                .clone();
                            // Recheck the tip under the chain lock before the one-record
                            // LMDB commit. A concurrent block makes the receipt stale and
                            // it is deliberately not persisted.
                            let chain = chain.lock().await;
                            if checkpoint_sync_tip(&chain) == receipt.tip {
                                receipt.save(&chain.store, &policy, received_at)?;
                            }
                        }
                    }
                    Command::Hello => {
                        // Second Hello after handshake is a protocol violation
                        let err = DomError::peer_misbehavior(
                            PeerMisbehavior::UnexpectedHello,
                            "unexpected Hello in message loop [ban+20]",
                        );
                        let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &err).await;
                        return Err(err);
                    }
                    Command::GetHeaders => {
                        let req = match GetHeadersPayload::from_bytes(&msg.payload) {
                            Ok(req) => req,
                            Err(e) => {
                                let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                                return Err(e);
                            }
                        };
                        let headers = build_headers_response(&chain, &req).await?;
                        let resp = HeadersPayload { headers };
                        let wire = WireMessage {
                            magic: config.network.magic(),
                            command: Command::Headers,
                            payload: resp.to_bytes()?,
                        };
                        codec.send(stream, &wire).await?;
                    }
                    Command::Headers => {
                        // Headers is strictly a response to this connection's
                        // active GetHeaders request. IBD consumes those replies
                        // synchronously before entering message_loop. Accepting
                        // unsolicited headers here lets a peer evade validation
                        // whenever another connection owns the global IBD
                        // cursor, so score and close the offending session.
                        let err = DomError::Invalid(
                            "unsolicited Headers outside an active IBD request".into(),
                        );
                        let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &err).await;
                        return Err(err);
                    }
                    Command::Block => {
                        // Peer relayed a block to us. Validate and accept.
                        let (block_bytes, block) = match decode_relay_block(&msg.payload) {
                            Ok(decoded) => decoded,
                            Err(e) => {
                                svc.metrics
                                    .malformed_block_relays
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                                return Err(e);
                            }
                        };
                        let relay_block_hash = {
                            use dom_serialization::DomSerialize;
                            *dom_crypto::hash::blake2b_256(&block.header.to_bytes()?).as_bytes()
                        };
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let now = dom_core::Timestamp(now_secs);
                        let current_block_hash = block_hash(&block)?;
                        outstanding_sync_blocks.remove(&current_block_hash);

                        // Doc 4.5 mitigation 1: soft buffer for future blocks
                        use dom_consensus::block::{
                            validate_future_timestamp_with_buffer_limits, TimestampDecision,
                        };
                        let (max_future, soft_buffer) =
                            if config.network == dom_config::Network::Testnet {
                                (
                                    dom_core::TESTNET_MAX_FUTURE_BLOCK_TIME,
                                    dom_core::TESTNET_FUTURE_BLOCK_SOFT_BUFFER_SECS,
                                )
                            } else {
                                (
                                    dom_core::MAX_FUTURE_BLOCK_TIME,
                                    dom_core::FUTURE_BLOCK_SOFT_BUFFER_SECS,
                                )
                            };
                        match validate_future_timestamp_with_buffer_limits(
                            &block.header,
                            now,
                            max_future,
                            soft_buffer,
                        ) {
                            Ok(TimestampDecision::Accept) => {
                                // Normal path: validate and connect
                                let height = block.header.height.0;
                                let txs_for_scan = block.transactions.clone();
                                let result = {
                                    let mut c = chain.lock().await;
                                    c.connect_block(&block, now)
                                };
                                // A connected peer's runtime block announcement
                                // may advance beyond its one-time Hello height.
                                // Preserve the per-peer maximum so a later,
                                // lower announcement cannot relax mining safety.
                                if result.is_ok() || matches!(&result, Err(DomError::Orphan(_))) {
                                    note_peer_best_height(
                                        &svc.peers,
                                        &svc.metrics,
                                        &svc.state_events,
                                        peer_addr,
                                        height,
                                        relay_block_hash,
                                    )
                                    .await;
                                }
                                match relay_block_action(&result) {
                                    RelayBlockAction::RelayBestChain => {
                                        if let Ok(ref connect_result) = result {
                                            if let Err(e) = reconcile_mempool_after_connect(
                                                &chain,
                                                &svc.mempool,
                                                connect_result,
                                                &block.transactions,
                                            )
                                            .await
                                            {
                                                tracing::warn!(
                                                    "Mempool reconciliation failed after block from {peer_addr}: {e}"
                                                );
                                            }
                                        }
                                        tracing::info!(
                                            "Accepted relayed block from {peer_addr} (new tip)"
                                        );
                                        // Wallet state follows canonical blocks only.
                                        if let Ok(ref connect_result) = result {
                                            match connect_result {
                                                dom_chain::ConnectResult::BestChain => {
                                                    if let Some(ref wallet_arc) = svc.wallet {
                                                        let mut wallet_dir =
                                                            wallet_arc.lock().await;
                                                        let w = wallet_dir.wallet_mut();
                                                        if let Err(e) =
                                                            w.apply_canonical_block_with_hash(
                                                                &txs_for_scan,
                                                                height,
                                                                Some(relay_block_hash),
                                                            )
                                                        {
                                                            tracing::warn!(
                                                                "wallet canonical block apply failed at height {height}: {e}"
                                                            );
                                                        }
                                                    }
                                                }
                                                dom_chain::ConnectResult::Reorg(delta) => {
                                                    if let Some(ref wallet_arc) = svc.wallet {
                                                        let mut wallet_dir =
                                                            wallet_arc.lock().await;
                                                        let w = wallet_dir.wallet_mut();
                                                        if let Err(e) = w.rollback_to(
                                                            delta.common_ancestor_height,
                                                        ) {
                                                            tracing::warn!(
                                                                "wallet rollback failed at reorg ancestor height {}: {e}",
                                                                delta.common_ancestor_height
                                                            );
                                                        } else {
                                                            for block in &delta.connected_blocks {
                                                                if let Err(e) = w
                                                                    .apply_canonical_block_with_hash(
                                                                        &block.transactions,
                                                                        block.block_height,
                                                                        Some(block.block_hash),
                                                                    )
                                                                {
                                                                    tracing::warn!(
                                                                        "wallet canonical reorg block apply failed at height {} hash {}: {e}",
                                                                        block.block_height,
                                                                        hex::encode(block.block_hash)
                                                                    );
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                dom_chain::ConnectResult::SideChain
                                                | dom_chain::ConnectResult::AlreadyHave => {}
                                            }
                                        }
                                        DomNode::refresh_runtime_metrics(
                                            &chain,
                                            &svc.mempool,
                                            &svc.future_block_queue,
                                            &svc.metrics,
                                        )
                                        .await;
                                        // DOM-SEC-RELAY-LOOP: only rebroadcast when we
                                        // actually extended the best chain. SideChain
                                        // and AlreadyHave MUST NOT rebroadcast — that
                                        // creates infinite relay loops between peers.
                                        let _ = block_relay_tx.send(block_bytes);
                                        svc.state_events.notify_waiters();
                                        if let Err(e) = reprocess_orphan_children(
                                            current_block_hash,
                                            &chain,
                                            &block_relay_tx,
                                            &svc,
                                        )
                                        .await
                                        {
                                            tracing::warn!(
                                                "Orphan replay after block from {peer_addr} failed: {e}"
                                            );
                                        }
                                    }
                                    RelayBlockAction::Suppress => {
                                        if matches!(result, Ok(dom_chain::ConnectResult::SideChain)) {
                                            tracing::debug!(
                                                "Accepted relayed block from {peer_addr} (side chain — no rebroadcast)"
                                            );
                                            // Wallet state intentionally ignores side-chain blocks.
                                            // Pending-spend reconciliation and output recovery are
                                            // canonical-only until the wallet learns explicit reorg
                                            // rollback semantics.
                                            if let Err(e) = reprocess_orphan_children(
                                                current_block_hash,
                                                &chain,
                                                &block_relay_tx,
                                                &svc,
                                            )
                                            .await
                                            {
                                                tracing::warn!(
                                                    "Side-chain orphan replay after block from {peer_addr} failed: {e}"
                                                );
                                            }
                                        } else if matches!(result, Ok(dom_chain::ConnectResult::AlreadyHave)) {
                                            if record_duplicate_block_relay(
                                                &svc.peers,
                                                &svc.metrics,
                                                peer_addr,
                                            )
                                            .await
                                            {
                                                return Err(DomError::PolicyRejected(
                                                    "duplicate block relay quota exceeded".into(),
                                                ));
                                            }
                                            tracing::trace!(
                                                "Block from {peer_addr} already known — no-op"
                                            );
                                        } else if matches!(result, Err(DomError::Orphan(_))) {
                                            let parent_hash = *block.header.prev_hash.as_bytes();
                                            let insert_outcome = svc.orphan_pool.lock().await.insert(OrphanBlock {
                                                block_hash: current_block_hash,
                                                parent_hash,
                                                height: block.header.height.0,
                                                block_bytes: block_bytes.clone(),
                                            });
                                            // Part D — this peer just relayed a block whose parent we
                                            // lack, so it holds a chain extending past our tip. Record
                                            // the height as a catch-up target; the periodic tick below
                                            // triggers a robust IBD re-sync toward it, guaranteeing the
                                            // hole is rebuilt even if the buffered orphan is later
                                            // evicted (peer_best_height alone would miss this, as it is
                                            // only learned at the Hello handshake).
                                            blocked_orphan_target =
                                                blocked_orphan_target.max(block.header.height.0);
                                            // Part A — request the missing parent immediately at the
                                            // current re-request clock (no clock advance, so an orphan
                                            // burst cannot compress the backoff of other tracked
                                            // parents). Persistent re-request continues on the tick.
                                            let requests = {
                                                let mut tracker = svc.missing_blocks.lock().await;
                                                tracker.note_orphan(
                                                    current_block_hash,
                                                    parent_hash,
                                                    block.header.height.0.checked_sub(1),
                                                );
                                                let round = tracker.current_round();
                                                tracker.next_request_batch(round)
                                            };
                                            tracing::debug!(
                                                peer = %peer_addr,
                                                child = %hex::encode(current_block_hash),
                                                parent = %hex::encode(parent_hash),
                                                ?insert_outcome,
                                                catchup_target = blocked_orphan_target,
                                                "Recorded orphan block and scheduled missing-parent request"
                                            );
                                            if !requests.is_empty() {
                                                outstanding_sync_blocks
                                                    .extend(requests.iter().copied());
                                                let req = GetBlockDataPayload { hashes: requests };
                                                let wire = WireMessage {
                                                    magic: config.network.magic(),
                                                    command: Command::GetBlockData,
                                                    payload: req.to_bytes()?,
                                                };
                                                codec.send(stream, &wire).await?;
                                            }
                                        } else if let Err(ref e) = result {
                                            tracing::debug!("Block from {peer_addr} not accepted: {e}");
                                        }
                                    }
                                    RelayBlockAction::PenalizePeer => {
                                        let e = result.expect_err("penalized relay result must be an error");
                                        if matches!(e, DomError::Malformed(_)) {
                                            svc.metrics
                                                .malformed_block_relays
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        }
                                        tracing::warn!(
                                            event = "consensus_rejection",
                                            peer_addr = %peer_addr,
                                            block_height = block.header.height.0,
                                            reason = %e,
                                            failure_class = "consensus_rejection",
                                            "relayed block rejected"
                                        );
                                        let banned =
                                            record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                                .await;
                                        tracing::warn!("Rejected block from {peer_addr}: {e}");
                                        if banned {
                                            return Err(e);
                                        }
                                    }
                                    RelayBlockAction::Drop => {
                                        if let Err(ref e) = result {
                                            tracing::debug!("Block from {peer_addr} not accepted: {e}");
                                        }
                                    }
                                }
                            }
                            Ok(TimestampDecision::Defer) => {
                                // Soft buffer: hold for re-evaluation
                                tracing::info!(
                                    event = "future_block_policy_action",
                                    peer_addr = %peer_addr,
                                    block_height = block.header.height.0,
                                    block_timestamp = block.header.timestamp.0,
                                    action = "defer",
                                    failure_class = "runtime_future_block",
                                    "future block deferred by soft buffer"
                                );
                                tracing::debug!("Block from {peer_addr} deferred (future timestamp soft buffer)");
                                if queue_future_block(&svc.future_block_queue, &block, block_bytes).await {
                                    tracing::debug!(
                                        "Deferred block ts={} queued for replay",
                                        block.header.timestamp.0
                                    );
                                } else {
                                    tracing::warn!(
                                        "Deferred block ts={} dropped because future queue is full",
                                        block.header.timestamp.0
                                    );
                                }
                                DomNode::refresh_runtime_metrics(
                                    &chain,
                                    &svc.mempool,
                                    &svc.future_block_queue,
                                    &svc.metrics,
                                )
                                .await;
                            }
                            Err(e) => {
                                tracing::info!(
                                    event = "future_block_policy_action",
                                    peer_addr = %peer_addr,
                                    block_height = block.header.height.0,
                                    block_timestamp = block.header.timestamp.0,
                                    action = "reject",
                                    reason = %e,
                                    failure_class = "consensus_rejection",
                                    "future block rejected by timestamp policy"
                                );
                                tracing::warn!("Block from {peer_addr} rejected by timestamp: {e}");
                                svc.metrics
                                    .blocks_rejected_timestamp
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    Command::Tx => {
                        // Relayed transaction from peer — payload IS the raw tx bytes
                        use dom_serialization::DomDeserialize;
                        use dom_consensus::Transaction;
                        let tx_bytes = msg.payload.clone();
                        let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();
                        // FABLE5-001: short-circuit replays of txs already in our
                        // mempool BEFORE deserializing, taking the chain lock, or
                        // running validation. The mempool's entry set is the
                        // (bounded) set of known-good txs; a hash hit means this is a
                        // duplicate whose admission could only be rejected as "already
                        // in mempool", so re-validating it would only burn CPU and
                        // chain-lock time on every replay. Invalid/unknown txs are NOT
                        // in the mempool, so they still flow through full validation
                        // and peer-scoring below.
                        if svc.mempool.lock().await.contains(&tx_hash) {
                            svc.metrics
                                .suppressed_duplicate_tx_relays
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::debug!("duplicate transaction replay suppressed");
                        } else {
                        match Transaction::from_bytes(&tx_bytes) {
                            Ok(tx) => {
                                let chain_view = {
                                    let c = chain.lock().await;
                                    snapshot_tx_chain_view(&c, &tx)
                                };
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let accepted = match chain_view {
                                    Ok(view) => {
                                        let mut m = svc.mempool.lock().await;
                                        let result = m.accept_tx_with_chain_view(
                                            tx,
                                            tx_hash,
                                            now_secs,
                                            view.current_height,
                                            view.chain_id,
                                            view.coinbase_maturity,
                                            |commitment| {
                                                Ok(view.utxos.get(commitment).cloned().flatten())
                                            },
                                        );
                                        drop(m);
                                        if result.is_ok() {
                                            svc.metrics
                                                .txs_received
                                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            DomNode::refresh_runtime_metrics(
                                                &chain,
                                                &svc.mempool,
                                                &svc.future_block_queue,
                                                &svc.metrics,
                                            )
                                            .await;
                                            let chain = chain.lock().await;
                                            clear_persisted_mempool_snapshot(&chain.store)?;
                                        }
                                        result
                                    }
                                    Err(e) => Err(e),
                                };
                                if accepted.is_ok() {
                                    svc.state_events.notify_waiters();
                                    tracing::debug!("relayed transaction accepted");
                                    // Dandelion++ re-route: decide Stem vs Fluff,
                                    // then dispatch the tx over the correct channel.
                                    let peer_list: Vec<std::net::SocketAddr> = if let Ok(p) = svc.peers.try_lock() {
                                        p.connected_peers()
                                            .into_iter()
                                            .filter_map(|s| s.parse().ok())
                                            .collect()
                                    } else {
                                        Vec::new()
                                    };
                                    let phase = {
                                        let mut d = svc.dandelion.lock().await;
                                        d.process_stem_tx(tx_hash, &peer_list, peer_addr)
                                    };
                                    use dom_wire::dandelion::{DandelionPhase, StemEnvelope};
                                    match phase {
                                        DandelionPhase::Suppressed => {}
                                        DandelionPhase::Fluff => {
                                            if tx_fluff_tx.send(tx_bytes.clone()).is_ok() {
                                                svc.metrics.txs_relayed.fetch_add(
                                                    1,
                                                    std::sync::atomic::Ordering::Relaxed,
                                                );
                                            }
                                        }
                                        DandelionPhase::Stem => {
                                            if let Some(target) = svc.dandelion.lock().await.get_stem_peer(&tx_hash) {
                                                if tx_stem_tx.send(StemEnvelope {
                                                    target_peer: target,
                                                    tx_bytes: tx_bytes.clone(),
                                                }).is_ok() {
                                                    svc.metrics.txs_relayed.fetch_add(
                                                        1,
                                                        std::sync::atomic::Ordering::Relaxed,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                } else if let Err(e) = accepted {
                                    tracing::debug!(
                                        event = "consensus_rejection",
                                        failure_class = "consensus_rejection",
                                        "relayed transaction rejected"
                                    );
                                    let banned =
                                        record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                            .await;
                                    if banned {
                                        return Err(e);
                                    }
                                }
                            }
                            Err(e) => {
                                let banned =
                                    record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                        .await;
                                tracing::debug!("malformed relayed transaction rejected");
                                if banned {
                                    return Err(e);
                                }
                            }
                        }
                        }
                    }
                    Command::GetBlockData => {
                        let req = match GetBlockDataPayload::from_bytes(&msg.payload) {
                            Ok(req) => req,
                            Err(e) => {
                                let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                                return Err(e);
                            }
                        };
                        if req.hashes.len() > dom_core::MAX_GETBLOCKDATA_SERVE_HASHES {
                            tracing::debug!(
                                peer = %peer_addr,
                                requested = req.hashes.len(),
                                served_cap = dom_core::MAX_GETBLOCKDATA_SERVE_HASHES,
                                "GetBlockData request truncated to the serve cap"
                            );
                        }
                        for hash in getblockdata_hashes_to_serve(&req.hashes) {
                            #[cfg(feature = "native-usdom-v4-poc")]
                            let response = load_block_data_response(
                                chain.clone(),
                                config.network.magic(),
                                native_usdom_v4_is_enabled(&svc),
                                native_usdom_v2_is_enabled(&svc),
                                native_usdom_v4_negotiated,
                                native_usdom_v2_negotiated,
                                *hash,
                            )
                            .await?;

                            #[cfg(not(feature = "native-usdom-v4-poc"))]
                            let response = {
                                let body = {
                                    let c = chain.lock().await;
                                    c.store.get_block_body(hash)?
                                };
                                body.map(|block_bytes| -> Result<WireMessage, DomError> {
                                    Ok(WireMessage {
                                        magic: config.network.magic(),
                                        command: Command::Block,
                                        payload: BlockPayload { block_bytes }.to_bytes()?,
                                    })
                                })
                                .transpose()?
                            };

                            if let Some(wire) = response {
                                codec.send(stream, &wire).await?;
                            }
                        }
                    }
                    Command::GetAddr => {
                        // Strict parse: GetAddr carries no body.
                        if let Err(e) = GetAddrPayload::from_bytes(&msg.payload) {
                            let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                .await;
                            return Err(e);
                        }
                        // Serve-side rate limit: at most one Addr response per
                        // peer per GETADDR_COOLDOWN_SECS. Response is encoded
                        // under the lock; the guard drops before the send.
                        let response_payload = {
                            let mut px = trace_lock("pex", &svc.pex).await;
                            if px.should_serve_getaddr(&pex_peer_key) {
                                px.record_getaddr_served(&pex_peer_key);
                                Some(crate::pex::encode_addr_payload(&px.peers_for_sharing()))
                            } else {
                                None
                            }
                        };
                        match response_payload {
                            Some(payload) => {
                                let wire = WireMessage {
                                    magic: config.network.magic(),
                                    command: Command::Addr,
                                    payload,
                                };
                                codec.send(stream, &wire).await?;
                            }
                            None => {
                                tracing::debug!(
                                    "suppressing GetAddr response to {peer_addr} (cooldown)"
                                );
                            }
                        }
                    }
                    Command::Addr => {
                        let payload = match AddrPayload::from_bytes(&msg.payload) {
                            Ok(payload) => payload,
                            Err(e) => {
                                let _ = record_peer_violation(&chain, &svc.peers, peer_addr, &e)
                                    .await;
                                return Err(e);
                            }
                        };
                        if !addr_flood.allow() {
                            // Too many Addr messages this window: score
                            // ADDRESS_FLOODING and drop the message without
                            // touching the PEX table.
                            let err = DomError::peer_misbehavior(
                                PeerMisbehavior::AddressFlooding,
                                format!(
                                    "address flooding: more than {} Addr messages in {}s [ban+{}]",
                                    crate::pex::MAX_ADDR_MESSAGES_PER_WINDOW,
                                    crate::pex::ADDR_FLOOD_WINDOW_SECS,
                                    dom_wire::peer::ban_scores::ADDRESS_FLOODING,
                                ),
                            );
                            let banned =
                                record_peer_violation(&chain, &svc.peers, peer_addr, &err).await;
                            if banned {
                                return Err(err);
                            }
                        } else {
                            let added = {
                                let mut px = trace_lock("pex", &svc.pex).await;
                                let added = px.process_addr_message(payload.entries);
                                refresh_pex_metrics(&px, &svc.metrics);
                                added
                            };
                            tracing::debug!(
                                "PEX: learned {added} new peer address(es) from {peer_addr}"
                            );
                        }
                    }
                    #[cfg(feature = "native-usdom-v4-poc")]
                    Command::UsdomV4Package => {
                        if let Err(err) =
                            require_native_usdom_v4_negotiation(native_usdom_v4_negotiated)
                        {
                            let _ =
                                record_peer_violation(&chain, &svc.peers, peer_addr, &err).await;
                            return Err(err);
                        }
                        let runtime = svc.native_usdom_v4_runtime.as_ref().ok_or_else(|| {
                            DomError::Internal(
                                "native USDOM capability negotiated without a restored runtime"
                                    .into(),
                            )
                        })?;
                        let ingress = NativeUsdomV4Ingress {
                            chain: chain.clone(),
                            mempool: svc.mempool.clone(),
                            runtime: runtime.clone(),
                            relay_tx: channels.native_usdom_v4_relay_tx.clone(),
                            relay_exclude_peer: Some(peer_addr),
                            wallet: svc.wallet.clone(),
                            metrics: svc.metrics.clone(),
                            future_block_queue: svc.future_block_queue.clone(),
                            native_future_queue: svc.native_usdom_v4_future_queue.clone(),
                            state_events: svc.state_events.clone(),
                            orphan_pool: svc.native_usdom_v4_orphan_pool.clone(),
                            candidate_v2_first_height: svc.candidate_v2_first_height,
                            migration_shutdown: Some(svc.task_supervisor.clone()),
                            proof_admission: svc.native_usdom_proof_admission.clone(),
                        };
                        match ingress.ingest(&msg.payload, ibd_now()).await {
                            Ok(dom_chain::ConnectResult::BestChain) => {
                                info!(
                                    "accepted authenticated native USDOM v4 package from {peer_addr} (new tip)"
                                );
                            }
                            Ok(dom_chain::ConnectResult::Reorg(_)) => {
                                info!(
                                    "accepted authenticated native USDOM v4 package from {peer_addr} (reorg)"
                                );
                            }
                            Ok(dom_chain::ConnectResult::SideChain) => {
                                tracing::debug!(
                                    "accepted authenticated native USDOM v4 package from {peer_addr} (side chain)"
                                );
                            }
                            Ok(dom_chain::ConnectResult::AlreadyHave) => {
                                tracing::trace!(
                                    "native USDOM v4 package from {peer_addr} already known"
                                );
                            }
                            Err(e @ DomError::Orphan(_)) => {
                                let metadata =
                                    native_usdom_v4_package_metadata(&msg.payload)?;
                                blocked_orphan_target =
                                    blocked_orphan_target.max(metadata.height);
                                note_peer_best_height(
                                    &svc.peers,
                                    &svc.metrics,
                                    &svc.state_events,
                                    peer_addr,
                                    metadata.height,
                                    metadata.block_hash,
                                )
                                .await;
                                let requests = {
                                    let mut tracker = svc.missing_blocks.lock().await;
                                    tracker.note_orphan(
                                        metadata.block_hash,
                                        metadata.parent_hash,
                                        metadata.height.checked_sub(1),
                                    );
                                    let round = tracker.current_round();
                                    tracker.next_request_batch(round)
                                };
                                tracing::debug!(
                                    peer = %peer_addr,
                                    child = %hex::encode(metadata.block_hash),
                                    parent = %hex::encode(metadata.parent_hash),
                                    catchup_target = blocked_orphan_target,
                                    reason = %e,
                                    "retained exact native orphan package and scheduled parent recovery"
                                );
                                if !requests.is_empty() {
                                    outstanding_sync_blocks.extend(requests.iter().copied());
                                    let request = GetBlockDataPayload { hashes: requests };
                                    codec
                                        .send(
                                            stream,
                                            &WireMessage {
                                                magic: config.network.magic(),
                                                command: Command::GetBlockData,
                                                payload: request.to_bytes()?,
                                            },
                                        )
                                        .await?;
                                }
                            }
                            Err(e @ DomError::TemporarilyInvalid(_)) => {
                                let metadata =
                                    native_usdom_v4_package_metadata(&msg.payload)?;
                                note_peer_best_height(
                                    &svc.peers,
                                    &svc.metrics,
                                    &svc.state_events,
                                    peer_addr,
                                    metadata.height,
                                    metadata.block_hash,
                                )
                                .await;
                                tracing::debug!(
                                    peer = %peer_addr,
                                    block_hash = %hex::encode(metadata.block_hash),
                                    height = metadata.height,
                                    reason = %e,
                                    "retained exact native package in future-timestamp queue"
                                );
                            }
                            Err(e) => {
                                let _ =
                                    record_peer_violation(&chain, &svc.peers, peer_addr, &e).await;
                                return Err(e);
                            }
                        }
                    }
                    #[cfg(feature = "native-usdom-v4-poc")]
                    Command::UsdomV2Package => {
                        if let Err(error) =
                            require_native_usdom_v2_negotiation(native_usdom_v2_negotiated)
                        {
                            let _ =
                                record_peer_violation(&chain, &svc.peers, peer_addr, &error).await;
                            return Err(error);
                        }
                        let runtime = svc.native_usdom_v2_runtime.as_ref().ok_or_else(|| {
                            DomError::Internal(
                                "native USDOM V2 capability negotiated without a restored runtime"
                                    .into(),
                            )
                        })?;
                        let ingress = NativeUsdomV2Ingress {
                            chain: chain.clone(),
                            mempool: svc.mempool.clone(),
                            runtime: runtime.clone(),
                            relay_tx: channels.native_usdom_v2_relay_tx.clone(),
                            relay_exclude_peer: Some(peer_addr),
                            wallet: svc.wallet.clone(),
                            metrics: svc.metrics.clone(),
                            future_block_queue: svc.future_block_queue.clone(),
                            native_future_queue: svc.native_usdom_v4_future_queue.clone(),
                            state_events: svc.state_events.clone(),
                            orphan_pool: svc.native_usdom_v4_orphan_pool.clone(),
                            proof_admission: svc.native_usdom_proof_admission.clone(),
                        };
                        match ingress.ingest(&msg.payload, ibd_now()).await {
                            Ok(dom_chain::ConnectResult::BestChain) => info!(
                                "accepted authenticated native USDOM V2 package from {peer_addr} (new tip)"
                            ),
                            Ok(dom_chain::ConnectResult::Reorg(_)) => info!(
                                "accepted authenticated native USDOM V2 package from {peer_addr} (reorg)"
                            ),
                            Ok(dom_chain::ConnectResult::SideChain) => tracing::debug!(
                                "accepted authenticated native USDOM V2 package from {peer_addr} (side chain)"
                            ),
                            Ok(dom_chain::ConnectResult::AlreadyHave) => tracing::trace!(
                                "native USDOM V2 package from {peer_addr} already known"
                            ),
                            Err(error @ DomError::Orphan(_)) => {
                                let metadata = native_usdom_v2_package_metadata(&msg.payload)?;
                                blocked_orphan_target =
                                    blocked_orphan_target.max(metadata.height);
                                note_peer_best_height(
                                    &svc.peers,
                                    &svc.metrics,
                                    &svc.state_events,
                                    peer_addr,
                                    metadata.height,
                                    metadata.block_hash,
                                )
                                .await;
                                let requests = {
                                    let mut tracker = svc.missing_blocks.lock().await;
                                    tracker.note_orphan(
                                        metadata.block_hash,
                                        metadata.parent_hash,
                                        metadata.height.checked_sub(1),
                                    );
                                    let round = tracker.current_round();
                                    tracker.next_request_batch(round)
                                };
                                tracing::debug!(
                                    peer = %peer_addr,
                                    child = %hex::encode(metadata.block_hash),
                                    parent = %hex::encode(metadata.parent_hash),
                                    reason = %error,
                                    "retained exact native V2 orphan and scheduled parent recovery"
                                );
                                if !requests.is_empty() {
                                    outstanding_sync_blocks.extend(requests.iter().copied());
                                    codec
                                        .send(
                                            stream,
                                            &WireMessage {
                                                magic: config.network.magic(),
                                                command: Command::GetBlockData,
                                                payload: GetBlockDataPayload { hashes: requests }
                                                    .to_bytes()?,
                                            },
                                        )
                                        .await?;
                                }
                            }
                            Err(error @ DomError::TemporarilyInvalid(_)) => {
                                let metadata = native_usdom_v2_package_metadata(&msg.payload)?;
                                note_peer_best_height(
                                    &svc.peers,
                                    &svc.metrics,
                                    &svc.state_events,
                                    peer_addr,
                                    metadata.height,
                                    metadata.block_hash,
                                )
                                .await;
                                tracing::debug!(
                                    peer = %peer_addr,
                                    block_hash = %hex::encode(metadata.block_hash),
                                    height = metadata.height,
                                    reason = %error,
                                    "retained exact native V2 package in future-timestamp queue"
                                );
                            }
                            Err(error) => {
                                let _ =
                                    record_peer_violation(&chain, &svc.peers, peer_addr, &error)
                                        .await;
                                return Err(error);
                            }
                        }
                    }
                    other => {
                        tracing::debug!("ignoring {other:?} from {peer_addr}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn native_proof_admission_is_global_fail_fast_and_releases() {
        let admission = std::sync::Arc::new(super::NativeProofAdmission::new());
        let permit = super::try_acquire_native_proof_permit(&admission, b"package-a").unwrap();
        assert!(super::try_acquire_native_proof_permit(&admission, b"package-b").is_err());
        drop(permit);
        assert!(super::try_acquire_native_proof_permit(&admission, b"package-b").is_ok());
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn native_proof_permit_survives_async_owner_cancellation_pattern() {
        let admission = std::sync::Arc::new(super::NativeProofAdmission::new());
        let async_owner = std::sync::Arc::new(
            super::try_acquire_native_proof_permit(&admission, b"package-a").unwrap(),
        );
        let blocking_owner = async_owner.clone();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            release_rx.recv().unwrap();
            drop(blocking_owner);
        });

        drop(async_owner);
        assert!(super::try_acquire_native_proof_permit(&admission, b"package-b").is_err());
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(super::try_acquire_native_proof_permit(&admission, b"package-b").is_ok());
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn identical_native_proof_package_is_suppressed_while_inflight() {
        let admission = std::sync::Arc::new(super::NativeProofAdmission::new());
        let permit = super::try_acquire_native_proof_permit(&admission, b"same-package").unwrap();
        let error = match super::try_acquire_native_proof_permit(&admission, b"same-package") {
            Ok(_) => panic!("duplicate package must be suppressed"),
            Err(error) => error,
        };
        assert!(format!("{error}").contains("already in flight"));
        assert!(
            super::is_native_proof_capacity_error(&error),
            "a deferred duplicate must be requeued while the original proof job owns capacity"
        );
        drop(permit);
        assert!(
            super::try_acquire_native_proof_permit(&admission, b"same-package").is_ok(),
            "invalid/aborted packages must not create a persistent negative cache"
        );
    }

    #[test]
    fn relay_logs_do_not_link_valid_transactions_to_ingress_peers() {
        let source = include_str!("node.rs");
        let production = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("node test module marker")
            .0;
        for forbidden in [
            "Accepted relayed tx",
            "Rejected relayed tx",
            "Invalid tx from",
            "Stem-timed-out tx {}",
            "tx_hash = %hex::encode(tx_hash)",
            "tx accepted but not relayed: no peer subscribers (tx {})",
            "tx_fluff lagged by {n} for {peer_addr}",
            "tx_stem lagged by {n} for {peer_addr}",
        ] {
            assert!(
                !production.contains(forbidden),
                "privacy-linkable relay log reintroduced: {forbidden}"
            );
        }
        for required in [
            "duplicate transaction replay suppressed",
            "relayed transaction accepted",
            "malformed relayed transaction rejected",
            "transaction fluff relay receiver lagged",
            "transaction stem relay receiver lagged",
        ] {
            assert!(
                production.contains(required),
                "redacted relay log missing: {required}"
            );
        }
    }

    use super::{
        annotate_send_err, bind_metrics_listener, bind_p2p_listener, catchup_interval,
        clear_persisted_mempool_snapshot, clear_persisted_peer_reputation,
        continue_ibd_header_sync, decode_deferred_block_bytes, decode_ibd_block_response,
        decode_relay_block, deferred_replay_action, getblockdata_hashes_to_serve, ibd_now,
        initialize_ibd_state, is_write_timeout, load_mempool_snapshot,
        load_or_create_noise_static_key, load_peer_reputation_snapshot,
        load_peer_rotation_snapshot, node_prologue_version, parse_persisted_noise_static_key,
        peer_violation_score, pending_peer_violation_score, persist_ibd_state,
        persist_mempool_snapshot, persist_peer_reputation_snapshot, purge_mempool_confirmed_inputs,
        reconcile_mempool_after_connect, record_peer_violation, redact_stem_send_err,
        refresh_peer_metrics, relay_block_action, resolve_configured_dns_seeds,
        restore_peer_rotation_state, serve_metrics, sync_mode_for_peer, trace_lock, tx_hash,
        wire_capabilities, DeferredReplayAction, DomNode, IbdActiveGuard, IbdRoundState,
        OutboundAttemptOutcome, RelayBlockAction, CATCHUP_MAX_HASHES_PER_TICK,
        LEGACY_PEER_REPUTATION_METADATA_KEY, LEGACY_PEER_ROTATION_METADATA_KEY,
        MEMPOOL_METADATA_KEY, METRICS_CONTENT_TYPE, NOISE_STATIC_KEY_METADATA_KEY,
        PEER_REPUTATION_METADATA_KEY, PEER_ROTATION_METADATA_KEY,
    };

    #[test]
    fn future_queue_replay_window_matches_each_networks_acceptance_limit() {
        assert_eq!(
            super::future_block_ready_window(dom_config::Network::Mainnet),
            dom_core::MAX_FUTURE_BLOCK_TIME
        );
        assert_eq!(
            super::future_block_ready_window(dom_config::Network::Regtest),
            dom_core::MAX_FUTURE_BLOCK_TIME
        );
        assert_eq!(
            super::future_block_ready_window(dom_config::Network::Testnet),
            dom_core::TESTNET_MAX_FUTURE_BLOCK_TIME
        );
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn native_queue_pressure_outcomes_increment_only_the_matching_counters() {
        let metrics = crate::metrics::Metrics::new();
        super::record_native_future_admission(
            &metrics,
            crate::future_block_queue::FutureBlockAdmission::Queued,
        );
        super::record_native_future_admission(
            &metrics,
            crate::future_block_queue::FutureBlockAdmission::RejectedCapacity,
        );
        super::record_native_future_admission(
            &metrics,
            crate::future_block_queue::FutureBlockAdmission::QueuedAfterEviction,
        );
        super::record_native_orphan_admission(
            &metrics,
            crate::orphan_pool::OrphanInsertOutcome::Inserted,
        );
        super::record_native_orphan_admission(
            &metrics,
            crate::orphan_pool::OrphanInsertOutcome::EvictedOldest,
        );
        super::record_native_orphan_admission(
            &metrics,
            crate::orphan_pool::OrphanInsertOutcome::RejectedParentLimit,
        );
        super::record_native_future_expiration(&metrics, 2);

        assert_eq!(
            metrics
                .native_usdom_v4_future_admission_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .native_usdom_v4_future_evictions
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .native_usdom_v4_orphan_evictions
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .native_usdom_v4_orphan_admission_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .native_usdom_v4_future_expired
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[test]
    fn native_wire_capability_requires_runtime_and_v4_session() {
        let v1 = dom_wire::message::CAPABILITY_NATIVE_USDOM_V4;
        let v2 = dom_wire::message::CAPABILITY_NATIVE_USDOM_V2;
        let sync = dom_wire::message::CAPABILITY_SYNC_TIP_V1;
        assert_eq!(wire_capabilities(true, false, false, 4), v1);
        assert_eq!(wire_capabilities(false, true, false, 4), v2);
        assert_eq!(wire_capabilities(false, false, false, 4), 0);
        assert_eq!(wire_capabilities(true, true, false, 4), 0);
        assert_eq!(wire_capabilities(false, false, true, 4), sync);
        assert_eq!(wire_capabilities(true, false, true, 4), v1 | sync);
        assert_eq!(wire_capabilities(true, false, true, 3), 0);
        assert_eq!(wire_capabilities(false, true, true, 2), 0);
        assert_eq!(node_prologue_version(true, 4), 4);
        assert_eq!(node_prologue_version(false, 4), 3);
        assert_eq!(node_prologue_version(false, 3), 3);
        assert_eq!(node_prologue_version(false, 2), 2);
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn native_wire_ingress_requires_authenticated_bilateral_negotiation() {
        assert!(super::require_native_usdom_v4_negotiation(true).is_ok());
        let err = super::require_native_usdom_v4_negotiation(false)
            .expect_err("an unnegotiated native package must fail closed");
        assert!(matches!(err, dom_core::DomError::Malformed(_)));
        assert_eq!(
            peer_violation_score(&err),
            Some(dom_wire::peer::ban_scores::MALFORMED_MESSAGE)
        );
        assert!(super::require_native_usdom_v2_negotiation(true).is_ok());
        let v2_error = super::require_native_usdom_v2_negotiation(false)
            .expect_err("an unnegotiated V2 package must fail closed");
        assert_eq!(
            peer_violation_score(&v2_error),
            Some(dom_wire::peer::ban_scores::MALFORMED_MESSAGE)
        );
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn native_wire_fanout_requires_negotiation_and_skips_origin_connection() {
        let origin: std::net::SocketAddr = "127.0.0.1:33369".parse().unwrap();
        let other: std::net::SocketAddr = "127.0.0.1:33370".parse().unwrap();
        assert!(!super::should_relay_native_usdom_v4(false, other, None));
        assert!(!super::should_relay_native_usdom_v4(
            true,
            origin,
            Some(origin)
        ));
        assert!(super::should_relay_native_usdom_v4(
            true,
            other,
            Some(origin)
        ));
        assert!(super::should_relay_native_usdom_v4(true, origin, None));

        let bytes = b"exact-canonical-wire-payload".to_vec();
        let message = super::native_usdom_v4_relay_message(
            dom_core::NETWORK_MAGIC_REGTEST,
            true,
            other,
            super::NativeUsdomV4Relay {
                wire_payload: bytes.clone(),
                exclude_peer: Some(origin),
            },
        )
        .expect("authorized non-origin peer must receive the relay");
        assert_eq!(message.magic, dom_core::NETWORK_MAGIC_REGTEST);
        assert_eq!(message.command, dom_wire::message::Command::UsdomV4Package);
        assert_eq!(message.payload, bytes);
        assert!(super::native_usdom_v4_relay_message(
            dom_core::NETWORK_MAGIC_REGTEST,
            false,
            other,
            super::NativeUsdomV4Relay {
                wire_payload: vec![1],
                exclude_peer: None,
            },
        )
        .is_none());

        let v2_message = super::native_usdom_v2_relay_message(
            dom_core::NETWORK_MAGIC_REGTEST,
            true,
            other,
            super::NativeUsdomV2Relay {
                wire_payload: bytes.clone(),
                exclude_peer: Some(origin),
            },
        )
        .expect("authorized V2 peer must receive the relay");
        assert_eq!(
            v2_message.command,
            dom_wire::message::Command::UsdomV2Package
        );
        assert_eq!(v2_message.payload, bytes);
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn getblockdata_serves_exact_native_package_only_to_negotiated_session() {
        use dom_wire::message::{
            BlockPayload, Command, UsdomV2PackagePayload, UsdomV4PackagePayload,
        };

        let package = b"canonical-native-package".to_vec();
        let response = super::block_data_response(
            dom_core::NETWORK_MAGIC_REGTEST,
            true,
            false,
            Some(package.clone()),
            None,
            None,
        )
        .unwrap()
        .expect("negotiated native package response");
        assert_eq!(response.command, Command::UsdomV4Package);
        assert_eq!(
            UsdomV4PackagePayload::from_bytes(&response.payload)
                .unwrap()
                .package_bytes,
            package
        );
        assert!(super::block_data_response(
            dom_core::NETWORK_MAGIC_REGTEST,
            false,
            false,
            Some(vec![1]),
            None,
            None,
        )
        .unwrap()
        .is_none());

        let v2_package = b"canonical-v2-package".to_vec();
        let v2_witnesses = b"canonical-v2-witnesses".to_vec();
        let response = super::block_data_response(
            dom_core::NETWORK_MAGIC_REGTEST,
            false,
            true,
            Some(v2_package.clone()),
            Some(v2_witnesses.clone()),
            None,
        )
        .unwrap()
        .expect("negotiated V2 package response");
        assert_eq!(response.command, Command::UsdomV2Package);
        let framed = UsdomV2PackagePayload::from_bytes(&response.payload).unwrap();
        assert_eq!(framed.package_bytes, v2_package);
        assert_eq!(framed.witness_bytes, v2_witnesses);
        assert!(super::block_data_response(
            dom_core::NETWORK_MAGIC_REGTEST,
            false,
            false,
            Some(vec![1]),
            Some(vec![2]),
            None,
        )
        .unwrap()
        .is_none());

        let ordinary = b"ordinary-block".to_vec();
        let response = super::block_data_response(
            dom_core::NETWORK_MAGIC_REGTEST,
            true,
            false,
            None,
            None,
            Some(ordinary.clone()),
        )
        .unwrap()
        .expect("ordinary response");
        assert_eq!(response.command, Command::Block);
        assert_eq!(
            BlockPayload::from_bytes(&response.payload)
                .unwrap()
                .block_bytes,
            ordinary
        );
    }

    #[cfg(feature = "native-usdom-v4-poc")]
    #[test]
    fn native_ibd_response_preserves_exact_package_and_matches_block_hash() {
        use dom_chain::{UsdomV4BlockPackage, UsdomV4ProofEnvelope};
        use dom_wire::message::UsdomV4PackagePayload;

        let mut block = synthetic_block(7, 19);
        block.header.version = dom_core::BLOCK_VERSION_V4;
        let package = UsdomV4BlockPackage::new(block.clone(), UsdomV4ProofEnvelope::empty())
            .unwrap()
            .to_bytes()
            .unwrap();
        let wire_payload = UsdomV4PackagePayload {
            package_bytes: package,
        }
        .to_bytes()
        .unwrap();
        let (decoded_hash, decoded_wire, decoded_block) =
            super::decode_native_ibd_block_response(&wire_payload).unwrap();
        assert_eq!(decoded_hash, block_hash(&block));
        assert_eq!(decoded_wire, wire_payload);
        assert_eq!(decoded_block, block);
        assert!(super::decode_native_ibd_block_response(b"not-framed").is_err());
    }

    /// A8: the v4-only path is untouched — plain bind, accepts v4.
    #[tokio::test]
    async fn v4_p2p_listener_binds_and_accepts() {
        let listener = bind_p2p_listener("127.0.0.1:0").await.expect("v4 bind");
        let port = listener.local_addr().expect("addr").port();
        let client = tokio::net::TcpStream::connect(("127.0.0.1", port));
        let (accepted, connected) = tokio::join!(listener.accept(), client);
        accepted.expect("accept v4");
        connected.expect("connect v4");
    }

    /// A8: one IPv6 socket with IPV6_V6ONLY=false serves both families —
    /// the single-socket scheme that avoids the double-bind EADDRINUSE
    /// (R-A8.2).
    ///
    /// Environment-gated, not platform-gated: a container with no ::1 (this
    /// repo's sandboxes included) cannot exercise dual-stack at all, and a
    /// hard failure there would misreport infra as a regression. CI's runners
    /// have loopback IPv6 and run the real assertion.
    #[tokio::test]
    async fn dual_stack_p2p_listener_accepts_both_families() {
        if tokio::net::TcpListener::bind("[::1]:0").await.is_err() {
            eprintln!("skipping dual-stack assertion: environment has no IPv6 loopback");
            return;
        }
        let listener = bind_p2p_listener("[::]:0").await.expect("dual-stack bind");
        let port = listener.local_addr().expect("addr").port();

        let v6 = tokio::net::TcpStream::connect(("::1", port));
        let (accepted, connected) = tokio::join!(listener.accept(), v6);
        accepted.expect("accept v6");
        connected.expect("connect v6");

        let v4 = tokio::net::TcpStream::connect(("127.0.0.1", port));
        let (accepted, connected) = tokio::join!(listener.accept(), v4);
        accepted.expect("accept v4 through the v6 socket");
        connected.expect("connect v4 through the v6 socket");
    }

    use crate::future_block_queue::DeferredBlock;
    use crate::metrics::Metrics;
    use crate::orphan_pool::OrphanBlock;
    use crate::replay_snapshot::ReplaySnapshot;
    use crate::task_supervisor::{SupervisorStatus, TaskKind};
    use dom_chain::{
        build_canonical_genesis, ChainState, ConnectResult, IbdInterruption, IbdPhase, IbdState,
        PersistedIbdState, ReorgDelta,
    };
    use dom_config::NodeConfig;
    use dom_consensus::block::{BlockHeader, ProofOfWork};
    use dom_consensus::{
        Block, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionInput,
        TransactionKernel, TransactionOutput,
    };
    use dom_core::PeerMisbehavior;
    use dom_core::{
        Amount, BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
        MAX_BLOCK_SERIALIZED_SIZE, MIN_RELAY_FEE_RATE, NETWORK_MAGIC_REGTEST, TAG_KERNEL_MSG,
        TAG_KERNEL_MSG_COINBASE,
    };
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::keys::SecretKey;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::schnorr_sign;
    use dom_mempool::Mempool;
    use dom_pow::{
        compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target,
        target_to_compact, target_to_difficulty, CompactTarget,
    };
    use dom_serialization::DomSerialize;
    use dom_store::utxo::UtxoEntry;
    use dom_store::DomStore;
    use dom_wire::manager::{PeerManager, PersistedPeerReputationState};
    use dom_wire::message::BlockPayload;
    use dom_wire::peer::ban_scores;
    use dom_wire::peer::{PeerInfo, PeerState};
    use primitive_types::U256;
    use std::fs;
    use std::io::{self, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::{Mutex, Notify};
    use tokio::task::JoinHandle;

    #[derive(Clone, Default)]
    struct TestLogBuffer(Arc<StdMutex<Vec<u8>>>);

    struct TestLogWriter(Arc<StdMutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TestLogBuffer {
        type Writer = TestLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            TestLogWriter(self.0.clone())
        }
    }

    impl Write for TestLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TestLogBuffer {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().expect("log buffer lock").clone())
                .expect("UTF-8 tracing output")
        }
    }

    #[tokio::test]
    async fn missed_catchup_ticks_skip_burst_and_fit_sync_budget() {
        let timer = catchup_interval();
        assert_eq!(
            timer.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Skip,
            "a long IBD must collapse missed catch-up ticks into one current tick"
        );
        const {
            assert!(
                CATCHUP_MAX_HASHES_PER_TICK <= crate::msg_rate_limit::SYNC_PER_WINDOW as usize,
                "one post-IBD catch-up tick must fit inside the sync limiter budget"
            );
            assert!(
                CATCHUP_MAX_HASHES_PER_TICK <= dom_core::MAX_GETBLOCKDATA_SERVE_HASHES,
                "the catch-up batch must fit inside the server response cap"
            );
        }
    }

    #[test]
    fn hello_user_agent_tracks_workspace_package_version() {
        assert_eq!(super::node_user_agent(), "dom-node/0.2.0");
    }

    #[test]
    fn getblockdata_handler_caps_bodies_per_request() {
        let hashes = vec![[7u8; 32]; dom_core::MAX_GETBLOCKDATA_HASHES];
        assert_eq!(
            getblockdata_hashes_to_serve(&hashes).len(),
            dom_core::MAX_GETBLOCKDATA_SERVE_HASHES
        );
    }

    /// When `disable_dns_seeds` is set the outbound connector must contribute
    /// NO DNS-resolved bootstrap candidates — neither the configured DNS seeds
    /// nor the hardcoded fallback list. This is what stops a testnet DNS seed
    /// from reintroducing the bootstrap host on the default P2P port once the
    /// user supplies an explicit seed peer. The disabled path performs no
    /// network access, so the test is hermetic.
    #[tokio::test]
    async fn disabled_dns_seeds_yield_no_candidates() {
        let mut config = NodeConfig::testnet();
        // Sanity: testnet ships a non-empty DNS seed by default, so an empty
        // result can only come from the gate (not from an empty seed list).
        assert!(!config.dns_seeds.is_empty());
        config.disable_dns_seeds = true;
        assert!(resolve_configured_dns_seeds(&config).await.is_empty());
    }

    /// Regtest with no explicitly configured dns_seeds must contribute NO
    /// bootstrap candidates either — a private local network must never dial
    /// the hardcoded public testnet fallback. (Same invariant the relay
    /// registry CI fix relies on; kept here so the wallet's
    /// `disable_dns_seeds` path and the regtest gate cannot regress each
    /// other.)
    #[tokio::test]
    async fn regtest_without_explicit_dns_seeds_yields_no_candidates() {
        let config = NodeConfig::regtest();
        assert!(config.dns_seeds.is_empty());
        assert!(!config.disable_dns_seeds);
        assert!(resolve_configured_dns_seeds(&config).await.is_empty());
    }

    // 64 MiB
    const TEST_LMDB_MAP_SIZE: usize = 64 << 20;
    // Guard for CI scheduler stalls. Tests still wait on explicit supervisor
    // readiness and `ShutdownToken`; this is not the shutdown mechanism.
    const RUNTIME_TEST_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15);

    type TestUtxoBytes = ([u8; 33], Vec<u8>);

    #[tokio::test]
    async fn traced_lock_guard_preserves_state_transition() {
        let state = Arc::new(Mutex::new(0u8));
        {
            let mut guard = trace_lock("test_state", &state).await;
            *guard = 1;
        }
        assert_eq!(*state.lock().await, 1);
    }

    #[tokio::test]
    async fn metrics_listener_none_does_not_bind() {
        let config = regtest_node_config(std::path::Path::new("/tmp/dom-metrics-none"));
        assert!(config.metrics_listen_addr.is_none());
        let listener = bind_metrics_listener(&config)
            .await
            .expect("metrics listener disabled");
        assert!(listener.is_none());
    }

    #[tokio::test]
    async fn metrics_listener_rejects_non_loopback_before_bind() {
        let mut config = regtest_node_config(std::path::Path::new("/tmp/dom-metrics-public"));
        config.metrics_listen_addr = Some("0.0.0.0:0".to_string());
        let error = bind_metrics_listener(&config)
            .await
            .expect_err("unauthenticated metrics must not bind publicly");
        assert!(matches!(error, DomError::PolicyRejected(_)));
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind metrics test listener");
        let addr = listener.local_addr().expect("metrics listener addr");
        let metrics = Arc::new(Metrics::new());
        metrics
            .chain_height
            .store(42, std::sync::atomic::Ordering::Relaxed);
        let server = tokio::spawn(serve_metrics(listener, metrics));

        let mut stream = TcpStream::connect(addr).await.expect("connect metrics");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .expect("write metrics request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read metrics response");
        let response = String::from_utf8(response).expect("utf8 metrics response");

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(&format!("Content-Type: {METRICS_CONTENT_TYPE}")));
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(response.contains("dom_chain_height 42"));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn refresh_runtime_metrics_reads_chain_mempool_and_future_queue() {
        let dir = fresh_test_dir("runtime-metrics-refresh");
        let node = init_test_node(regtest_node_config(&dir));
        let block = synthetic_block(7, 1);
        commit_chain_block(&node.chain, &block).await;
        let tx = mempool_tx(0x44, 100);
        let tx_hash = tx_hash(&tx).expect("tx hash");
        {
            let mut mempool = node.mempool.lock().await;
            mempool.accept_tx(tx, tx_hash, 1).expect("accept tx");
        }
        assert!(
            node.future_block_queue
                .defer(DeferredBlock {
                    block_hash: [0x55; 32],
                    block_height: 8,
                    timestamp: 2_000_000_000,
                    queued_at: Instant::now(),
                    block_bytes: vec![0x01],
                })
                .await
        );

        DomNode::refresh_runtime_metrics(
            &node.chain,
            &node.mempool,
            &node.future_block_queue,
            &node.metrics,
        )
        .await;

        assert_eq!(
            node.metrics
                .chain_height
                .load(std::sync::atomic::Ordering::Relaxed),
            7
        );
        assert_eq!(
            node.metrics
                .mempool_size
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            node.metrics
                .future_block_queue_size
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        crate::test_dir::remove_test_dir(&dir);
    }

    fn commitment(seed: u8, value: u64) -> Commitment {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        let blind = BlindingFactor::from_bytes(bytes).expect("deterministic blinding");
        Commitment::commit(value, &blind)
    }

    fn scalar(seed: u8) -> BlindingFactor {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        BlindingFactor::from_bytes(bytes).expect("deterministic blinding")
    }

    fn build_coinbase(
        height: BlockHeight,
        claimed_fees: u64,
        chain_id: &[u8; 32],
    ) -> CoinbaseTransaction {
        let reward = dom_core::block_reward(height).noms();
        let explicit_value = reward + claimed_fees;
        let blinding = scalar(height.0 as u8 + 1);
        let commitment = Commitment::commit(explicit_value, &blinding);
        let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).expect("coinbase proof");
        let excess = Commitment::commit(0, &blinding);
        let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
        let msg = {
            let mut data = Vec::with_capacity(1 + 8);
            data.push(KERNEL_FEAT_COINBASE);
            data.extend_from_slice(&explicit_value.to_le_bytes());
            blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
        };
        let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("coinbase sig");
        CoinbaseTransaction {
            output: TransactionOutput { commitment, proof },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value,
                excess,
                excess_signature: sig.to_bytes(),
            },
            offset: [0u8; 32],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mine_fast_header(
        seed_hash: [u8; 32],
        prev_hash: Hash256,
        height: BlockHeight,
        timestamp: Timestamp,
        output_root: Hash256,
        kernel_root: Hash256,
        rangeproof_root: Hash256,
        total_kernel_offset: [u8; 32],
        total_difficulty: U256,
    ) -> BlockHeader {
        let target =
            compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
        let mut nonce = 0u64;
        loop {
            let mut header = BlockHeader {
                version: dom_core::required_block_version_for_network(
                    NETWORK_MAGIC_REGTEST,
                    height.0,
                ),
                height,
                prev_hash,
                timestamp,
                output_root,
                kernel_root,
                rangeproof_root,
                total_kernel_offset,
                target: CompactTarget(target_to_compact(&target)),
                total_difficulty,
                pow: ProofOfWork {
                    nonce,
                    randomx_hash: Hash256::ZERO,
                },
            };
            let hash = fast_pow_hash(&seed_hash, &header.pow_preimage());
            if hash_meets_target(&hash, &target) {
                header.pow.randomx_hash = Hash256::from_bytes(hash);
                return header;
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    fn build_coinbase_only_block(
        seed_hash: [u8; 32],
        prev_hash: Hash256,
        height: BlockHeight,
        parent_total_difficulty: U256,
        total_kernel_offset: [u8; 32],
        chain_id: &[u8; 32],
    ) -> Block {
        let coinbase = build_coinbase(height, 0, chain_id);
        let (output_root, kernel_root, rangeproof_root) =
            dom_consensus::compute_block_pmmr_roots(height, &coinbase, &[]).expect("roots");
        let timestamp = genesis_anchor(NETWORK_MAGIC_REGTEST)
            .expect("anchor")
            .timestamp
            .checked_add_secs(height.0 * dom_core::TARGET_SPACING)
            .expect("timestamp");
        let target =
            compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
        let total_difficulty = parent_total_difficulty + U256::from(target_to_difficulty(&target));
        let header = mine_fast_header(
            seed_hash,
            prev_hash,
            height,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset,
            total_difficulty,
        );
        Block {
            header,
            coinbase,
            transactions: vec![],
        }
    }

    fn safe_now() -> Timestamp {
        Timestamp(2_000_000_000)
    }

    fn synthetic_block(height: u64, nonce: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height: BlockHeight(height),
                prev_hash: Hash256::ZERO,
                timestamp: Timestamp(1_700_000_000 + height),
                output_root: Hash256::ZERO,
                kernel_root: Hash256::ZERO,
                rangeproof_root: Hash256::ZERO,
                total_kernel_offset: [0u8; 32],
                target: CompactTarget(0),
                total_difficulty: U256::from(height),
                pow: ProofOfWork {
                    nonce,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase: CoinbaseTransaction {
                output: dom_consensus::TransactionOutput {
                    commitment: commitment(1, 50),
                    proof: vec![0x42; 8],
                },
                kernel: CoinbaseKernel {
                    features: KERNEL_FEAT_COINBASE,
                    explicit_value: 50,
                    excess: commitment(2, 0),
                    excess_signature: [0x24; 65],
                },
                offset: [0u8; 32],
            },
            transactions: Vec::new(),
        }
    }

    fn synthetic_block_with_transactions(
        prev_hash: Hash256,
        height: u64,
        nonce: u64,
        coinbase_seed: u8,
        transactions: Vec<Transaction>,
    ) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                height: BlockHeight(height),
                prev_hash,
                timestamp: Timestamp(1_700_100_000 + height),
                output_root: Hash256::ZERO,
                kernel_root: Hash256::ZERO,
                rangeproof_root: Hash256::ZERO,
                total_kernel_offset: [0u8; 32],
                target: CompactTarget(0),
                total_difficulty: U256::from(height),
                pow: ProofOfWork {
                    nonce,
                    randomx_hash: Hash256::ZERO,
                },
            },
            coinbase: CoinbaseTransaction {
                output: TransactionOutput {
                    commitment: commitment(coinbase_seed, 1_000_000 + height),
                    proof: vec![coinbase_seed; 8],
                },
                kernel: CoinbaseKernel {
                    features: KERNEL_FEAT_COINBASE,
                    explicit_value: 1,
                    excess: commitment(coinbase_seed.wrapping_add(100), 0),
                    excess_signature: [coinbase_seed; 65],
                },
                offset: [0u8; 32],
            },
            transactions,
        }
    }

    fn synthetic_spend_tx(input: Commitment, output_seed: u8, kernel_seed: u8) -> Transaction {
        Transaction {
            inputs: vec![TransactionInput { commitment: input }],
            outputs: vec![TransactionOutput {
                commitment: commitment(output_seed, u64::from(output_seed) + 1),
                proof: vec![output_seed; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(kernel_seed, 0),
                excess_signature: [kernel_seed; 65],
            }],
            offset: [0u8; 32],
        }
    }

    fn signed_spend_tx(
        input_value: u64,
        input_blinding: BlindingFactor,
        fee: u64,
        _output_seed: u8,
        kernel_seed: u8,
        chain_id: &[u8; 32],
    ) -> Transaction {
        let output_value = input_value.checked_sub(fee).expect("fee below input");
        let kernel_blinding = scalar(kernel_seed);
        let output_blinding = input_blinding
            .add(&kernel_blinding)
            .expect("output blinding");
        let input = Commitment::commit(input_value, &input_blinding);
        let output = Commitment::commit(output_value, &output_blinding);
        let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).expect("tx proof");
        let excess = Commitment::commit(0, &kernel_blinding);
        let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
        let msg = {
            let mut data = Vec::with_capacity(1 + 8 + 8);
            data.push(KERNEL_FEAT_PLAIN);
            data.extend_from_slice(&fee.to_le_bytes());
            data.extend_from_slice(&0u64.to_le_bytes());
            blake2b_256_tagged(TAG_KERNEL_MSG, &data)
        };
        let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("kernel sig");

        Transaction {
            inputs: vec![TransactionInput { commitment: input }],
            outputs: vec![TransactionOutput {
                commitment: output,
                proof,
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).expect("fee"),
                lock_height: 0,
                excess,
                excess_signature: sig.to_bytes(),
            }],
            offset: [0u8; 32],
        }
    }

    fn spending_tx(input: Commitment, seed: u8) -> Transaction {
        Transaction {
            inputs: vec![TransactionInput { commitment: input }],
            outputs: vec![TransactionOutput {
                commitment: commitment(seed.wrapping_add(10), 1),
                proof: vec![seed; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 25).unwrap(),
                lock_height: 0,
                excess: commitment(seed.wrapping_add(20), 0),
                excess_signature: [seed; 65],
            }],
            offset: [0u8; 32],
        }
    }

    fn mempool_tx(seed: u8, fee_multiplier: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: commitment(seed, 1),
                proof: vec![seed; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * fee_multiplier).unwrap(),
                lock_height: 0,
                excess: commitment(seed.wrapping_add(50), 0),
                excess_signature: [seed; 65],
            }],
            offset: [0u8; 32],
        }
    }

    fn block_state_changes(block: &Block) -> (Vec<TestUtxoBytes>, Vec<[u8; 33]>) {
        let mut new_utxos = vec![(
            *block.coinbase.output.commitment.as_bytes(),
            UtxoEntry {
                block_height: block.header.height.0,
                is_coinbase: true,
                proof: block.coinbase.output.proof.clone(),
            }
            .to_bytes(),
        )];
        let mut spent_utxos = Vec::new();
        for tx in &block.transactions {
            for input in &tx.inputs {
                spent_utxos.push(*input.commitment.as_bytes());
            }
            for output in &tx.outputs {
                new_utxos.push((
                    *output.commitment.as_bytes(),
                    UtxoEntry {
                        block_height: block.header.height.0,
                        is_coinbase: false,
                        proof: output.proof.clone(),
                    }
                    .to_bytes(),
                ));
            }
        }
        (new_utxos, spent_utxos)
    }

    fn kernel_excesses(block: &Block) -> Vec<([u8; 33], [u8; 32])> {
        let hash = block_hash(block);
        let mut out = vec![(*block.coinbase.kernel.excess.as_bytes(), hash)];
        for tx in &block.transactions {
            for kernel in &tx.kernels {
                out.push((*kernel.excess.as_bytes(), hash));
            }
        }
        out
    }

    async fn commit_chain_block(chain: &Arc<Mutex<ChainState>>, block: &Block) {
        let hash = block_hash(block);
        let header_bytes = block.header.to_bytes().expect("header bytes");
        let body_bytes = block.to_bytes().expect("body bytes");
        let (new_utxos, spent_utxos) = block_state_changes(block);
        let kernels = kernel_excesses(block);
        let mut guard = chain.lock().await;
        guard
            .store
            .commit_block(
                &hash,
                block.header.height.0,
                &header_bytes,
                &body_bytes,
                &new_utxos,
                &spent_utxos,
                &kernels,
            )
            .expect("commit block");
        guard.tip_hash = Hash256::from_bytes(hash);
        guard.tip_height = block.header.height;
        guard.tip_difficulty = block.header.total_difficulty;
    }
    fn ibd_payload(block: &Block) -> Vec<u8> {
        BlockPayload {
            block_bytes: block.to_bytes().expect("serialize block"),
        }
        .to_bytes()
        .expect("serialize block payload")
    }

    fn block_hash(block: &Block) -> [u8; 32] {
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().expect("serialize header"))
            .as_bytes()
    }

    fn header_hash(header: &BlockHeader) -> [u8; 32] {
        *dom_crypto::hash::blake2b_256(&header.to_bytes().expect("serialize header")).as_bytes()
    }

    fn open_chain(dir: &std::path::Path) -> Arc<Mutex<ChainState>> {
        let store = open_test_store(dir);
        let chain = ChainState::open(
            store,
            Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            NETWORK_MAGIC_REGTEST,
        )
        .expect("chain open");
        Arc::new(Mutex::new(chain))
    }

    async fn store_known_header(chain: &Arc<Mutex<ChainState>>, header: &BlockHeader) {
        let header_bytes = header.to_bytes().expect("serialize header");
        let hash = header_hash(header);
        let chain = chain.lock().await;
        chain
            .store
            .store_known_block(&hash, &header_bytes, &[0u8; 8])
            .expect("store known header");
    }

    fn synthetic_known_header(
        height: u64,
        prev_hash: Hash256,
        total_difficulty: u64,
    ) -> BlockHeader {
        BlockHeader {
            version: 1,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(1_700_000_000 + height),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0),
            total_difficulty: U256::from(total_difficulty),
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        }
    }

    fn fresh_test_dir(label: &str) -> PathBuf {
        let unique = format!(
            "dom-node-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    fn regtest_node_config(data_dir: &std::path::Path) -> NodeConfig {
        let mut config = NodeConfig::regtest();
        config.data_dir = data_dir.to_string_lossy().into_owned();
        config.wallet_path = None;
        config.wallet_password = None;
        config.mine = false;
        config
    }

    fn init_test_node(config: NodeConfig) -> DomNode {
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE).expect("node init")
    }

    fn open_test_store(dir: &std::path::Path) -> DomStore {
        DomStore::open_with_map_size(dir, TEST_LMDB_MAP_SIZE).expect("store open")
    }

    fn free_local_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral localhost port")
            .local_addr()
            .expect("read localhost addr")
            .port()
    }

    async fn wait_for_supervisor(
        node: &Arc<DomNode>,
        predicate: impl Fn(Vec<TaskKind>, usize, SupervisorStatus, bool) -> bool,
    ) {
        tokio::time::timeout(RUNTIME_TEST_CONVERGENCE_TIMEOUT, async {
            loop {
                let kinds = node.task_supervisor.active_kinds().await;
                let relay_count = node.task_supervisor.relay_count().await;
                let status = node.task_supervisor.status().await;
                let shutdown = node.task_supervisor.is_shutdown();
                if predicate(kinds, relay_count, status, shutdown) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("runtime status should converge");
    }

    async fn wait_for_core_runtime(node: &Arc<DomNode>) {
        wait_for_supervisor(node, |kinds, _, status, shutdown| {
            kinds.contains(&TaskKind::Listener)
                && kinds.contains(&TaskKind::Connector)
                && kinds.contains(&TaskKind::FutureQueue)
                && kinds.contains(&TaskKind::DandelionStem)
                && status == SupervisorStatus::Running
                && !shutdown
        })
        .await;
    }

    async fn connect_when_listener_accepts(listen_addr: &str) -> TcpStream {
        tokio::time::timeout(RUNTIME_TEST_CONVERGENCE_TIMEOUT, async {
            loop {
                match TcpStream::connect(listen_addr).await {
                    Ok(stream) => return stream,
                    Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
                }
            }
        })
        .await
        .expect("listener should accept connections")
    }

    async fn wait_for_relay_count(node: &Arc<DomNode>, expected: usize) {
        let deadline = tokio::time::Instant::now() + RUNTIME_TEST_CONVERGENCE_TIMEOUT;
        loop {
            let relay_count = node.task_supervisor.relay_count().await;
            if relay_count == expected {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "relay worker count should converge to {expected}; last observed {relay_count}"
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn shutdown_and_join_run(
        node: &Arc<DomNode>,
        run: JoinHandle<Result<(), DomError>>,
        context: &str,
    ) {
        node.request_shutdown().await;
        tokio::time::timeout(RUNTIME_TEST_CONVERGENCE_TIMEOUT, run)
            .await
            .unwrap_or_else(|_| panic!("{context}: run should stop after shutdown"))
            .expect("join")
            .expect("graceful shutdown");
        assert!(
            node.task_supervisor.is_empty().await,
            "{context}: supervisor registry drained"
        );
        assert!(
            node.task_supervisor.failure().await.is_none(),
            "{context}: no critical task failure recorded"
        );
    }

    fn spawn_node_run(node: Arc<DomNode>) -> JoinHandle<Result<(), DomError>> {
        tokio::spawn(Box::pin(node.run()))
    }

    #[tokio::test]
    async fn run_registers_listener_connector_future_queue_and_dandelion_tasks() {
        let dir = fresh_test_dir("runtime-registers-core-tasks");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let node = Arc::new(init_test_node(config));
        let run = spawn_node_run(node.clone());

        wait_for_core_runtime(&node).await;
        shutdown_and_join_run(&node, run, "core runtime").await;
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn run_registers_miner_only_when_mining_enabled() {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let dir_off = fresh_test_dir("runtime-miner-disabled");
        let mut config_off = regtest_node_config(&dir_off);
        config_off.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let node_off = Arc::new(init_test_node(config_off));
        let run_off = spawn_node_run(node_off.clone());
        wait_for_supervisor(&node_off, |kinds, _, _, _| {
            !kinds.contains(&TaskKind::Miner)
                && kinds.contains(&TaskKind::Listener)
                && kinds.contains(&TaskKind::Connector)
                && kinds.contains(&TaskKind::FutureQueue)
                && kinds.contains(&TaskKind::DandelionStem)
        })
        .await;
        shutdown_and_join_run(&node_off, run_off, "miner disabled runtime").await;
        crate::test_dir::remove_test_dir(&dir_off);

        let dir_on = fresh_test_dir("runtime-miner-enabled");
        let mut config_on = regtest_node_config(&dir_on);
        config_on.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        config_on.mine = true;
        let node_on = Arc::new(init_test_node(config_on));
        let run_on = spawn_node_run(node_on.clone());
        wait_for_supervisor(&node_on, |kinds, _, _, _| {
            kinds.contains(&TaskKind::Miner)
                && kinds.contains(&TaskKind::Listener)
                && kinds.contains(&TaskKind::Connector)
                && kinds.contains(&TaskKind::FutureQueue)
                && kinds.contains(&TaskKind::DandelionStem)
        })
        .await;
        shutdown_and_join_run(&node_on, run_on, "miner enabled runtime").await;
        crate::test_dir::remove_test_dir(&dir_on);
    }

    #[tokio::test]
    async fn run_does_not_immediately_shutdown_after_startup() {
        let dir = fresh_test_dir("runtime-long-lived");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let node = Arc::new(init_test_node(config));
        let run = spawn_node_run(node.clone());

        wait_for_supervisor(&node, |_, _, status, shutdown| {
            status == SupervisorStatus::Running && !shutdown
        })
        .await;
        assert!(
            !run.is_finished(),
            "DomNode::run must stay alive until explicit shutdown"
        );

        shutdown_and_join_run(&node, run, "long-lived runtime").await;
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn relay_worker_registry_is_cleaned_after_worker_exit() {
        let dir = fresh_test_dir("runtime-relay-cleanup");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = format!("127.0.0.1:{}", free_local_port());
        let listen_addr = config.p2p_listen_addr.clone();
        let node = Arc::new(init_test_node(config));
        let run = spawn_node_run(node.clone());

        let stream = connect_when_listener_accepts(&listen_addr).await;
        wait_for_relay_count(&node, 1).await;
        drop(stream);
        wait_for_relay_count(&node, 0).await;

        shutdown_and_join_run(&node, run, "relay cleanup runtime").await;
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn noise_static_key_persists_across_store_reopen() {
        let dir = fresh_test_dir("noise-key-reopen");
        let store = open_test_store(&dir);
        let first = load_or_create_noise_static_key(&store).expect("first load/create");
        drop(store);

        let reopened = open_test_store(&dir);
        let second = load_or_create_noise_static_key(&reopened).expect("second load");

        assert_eq!(first, second, "persisted Noise key must survive reopen");
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn node_identity_survives_restart_init() {
        let dir = fresh_test_dir("noise-node-restart");
        let config = regtest_node_config(&dir);

        let first = init_test_node(config.clone());
        let second = init_test_node(config);

        assert_eq!(
            first.noise_privkey, second.noise_privkey,
            "Noise static key must survive restart"
        );
        assert_eq!(
            dom_wire::handshake::derive_static_pubkey(&first.noise_privkey),
            dom_wire::handshake::derive_static_pubkey(&second.noise_privkey),
            "derived public identity must survive restart"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn malformed_persisted_noise_key_is_rejected_without_replacement() {
        let dir = fresh_test_dir("noise-key-corrupt");
        let store = open_test_store(&dir);
        store
            .put_metadata(NOISE_STATIC_KEY_METADATA_KEY, b"corrupt")
            .expect("write corrupt metadata");

        let err = load_or_create_noise_static_key(&store).expect_err("corrupt key should fail");
        let message = err.to_string();
        assert!(
            message.contains("invalid length"),
            "unexpected error message: {message}"
        );
        assert_eq!(
            store
                .get_metadata(NOISE_STATIC_KEY_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"corrupt"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn malformed_persisted_noise_key_aborts_node_init() {
        let dir = fresh_test_dir("noise-node-corrupt");
        let store = open_test_store(&dir);
        store
            .put_metadata(NOISE_STATIC_KEY_METADATA_KEY, b"corrupt")
            .expect("write corrupt metadata");
        drop(store);

        let err = match DomNode::init_with_map_size(regtest_node_config(&dir), TEST_LMDB_MAP_SIZE) {
            Ok(_) => panic!("init should fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("persisted Noise static key"),
            "unexpected error message: {message}"
        );

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(NOISE_STATIC_KEY_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"corrupt"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn mempool_is_empty_by_design_after_restart() {
        let dir = fresh_test_dir("mempool-restart-empty");
        let config = regtest_node_config(&dir);
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: commitment(90, 5),
                proof: vec![0x90; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(91, 0),
                excess_signature: [0x91; 65],
            }],
            offset: [0u8; 32],
        };
        let tx_hash = tx_hash(&tx).expect("tx hash");

        let first = init_test_node(config.clone());
        first
            .mempool
            .try_lock()
            .expect("mempool lock")
            .accept_tx(tx, tx_hash, 1)
            .expect("accept runtime tx");
        assert_eq!(first.mempool.try_lock().expect("mempool lock").len(), 1);
        drop(first);

        let second = init_test_node(config);
        assert_eq!(
            second.mempool.try_lock().expect("mempool lock").len(),
            0,
            "mempool must restart empty instead of reconstructing runtime-only state"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    /// TASK 27 / RFC-0012 §2: under the volatile policy there is no persisted
    /// mempool to revalidate on reopen. This proves the two properties that make
    /// that safe: restart is **deterministic** (always empty) and
    /// **consensus-neutral** (the canonical chain tip after restart is identical
    /// regardless of what the mempool held — runtime txs and even a structurally
    /// valid on-disk legacy snapshot — and identical to a node that never had any
    /// mempool activity at all).
    #[test]
    fn chain_validity_is_unaffected_by_mempool_restart_state() {
        // Node A: accept a runtime tx AND plant a structurally valid legacy
        // on-disk mempool snapshot, then capture the canonical chain tip.
        let dir_a = fresh_test_dir("mempool-neutral-a");
        let tip_a_before = {
            let node = init_test_node(regtest_node_config(&dir_a));
            let tx = mempool_tx(0x31, 100);
            let hash = tx_hash(&tx).expect("hash a");
            node.mempool
                .try_lock()
                .expect("mempool lock")
                .accept_tx(tx.clone(), hash, 1)
                .expect("accept runtime tx");
            let chain = node.chain.try_lock().expect("chain lock");
            let mut planted = Mempool::new();
            planted.accept_tx(tx, hash, 1).expect("plant accept");
            persist_mempool_snapshot(&chain.store, &planted.snapshot())
                .expect("plant legacy snapshot");
            (chain.tip_height.0, *chain.tip_hash.as_bytes())
        };

        // Node B (control): never touches the mempool.
        let dir_b = fresh_test_dir("mempool-neutral-b");
        let node_b = init_test_node(regtest_node_config(&dir_b));
        let tip_b = {
            let chain = node_b.chain.try_lock().expect("chain lock b");
            (chain.tip_height.0, *chain.tip_hash.as_bytes())
        };
        assert!(
            node_b
                .mempool
                .try_lock()
                .expect("mempool lock b")
                .is_empty(),
            "control node starts with an empty mempool"
        );
        drop(node_b);

        // Restart A. The chain tip must be byte-identical to before the restart
        // (mempool state did not perturb consensus) and to the control node
        // (chain validity is independent of mempool history). The mempool must be
        // empty and the legacy on-disk snapshot must be gone.
        let restarted = init_test_node(regtest_node_config(&dir_a));
        let tip_a_after = {
            let chain = restarted.chain.try_lock().expect("chain lock a2");
            (chain.tip_height.0, *chain.tip_hash.as_bytes())
        };
        assert_eq!(
            tip_a_after, tip_a_before,
            "chain tip is unchanged by mempool restart state (consensus-neutral)"
        );
        assert_eq!(
            tip_a_after, tip_b,
            "chain validity is identical regardless of mempool history (deterministic)"
        );
        assert_eq!(
            restarted.mempool.try_lock().expect("mempool lock a2").len(),
            0,
            "restart is deterministic: mempool is always empty"
        );
        let reopened = DomStore::open(&dir_a).expect("store reopen a");
        assert!(
            load_mempool_snapshot(&reopened)
                .expect("load mempool a")
                .is_none(),
            "no persisted mempool is trusted or loaded on reopen"
        );

        crate::test_dir::remove_test_dir(&dir_a);
        crate::test_dir::remove_test_dir(&dir_b);
    }

    #[test]
    fn unclamped_persisted_noise_key_is_rejected() {
        let raw = [0xff; 32];
        let err = parse_persisted_noise_static_key(&raw).expect_err("unclamped key should fail");
        let message = err.to_string();
        assert!(
            message.contains("canonical clamped form"),
            "unexpected error message: {message}"
        );
    }

    #[test]
    fn legacy_peer_rotation_snapshot_loads_for_restart_compatibility() {
        use dom_serialization::Writer;

        let dir = fresh_test_dir("peer-rotation-legacy");
        let store = open_test_store(&dir);
        let mut w = Writer::new();
        w.write_u64(3);
        w.write_u32(1);
        w.write_vec(b"198.51.100.30:33369").expect("addr");
        w.write_u8(3);
        w.write_u64(3);
        store
            .put_metadata(LEGACY_PEER_ROTATION_METADATA_KEY, &w.finish())
            .expect("persist legacy peer rotation");

        let snapshot = load_peer_rotation_snapshot(&store)
            .expect("load peer rotation")
            .expect("snapshot present");
        assert_eq!(snapshot.next_failure_seq, 3);
        assert_eq!(snapshot.outbound_failures.len(), 1);
        assert_eq!(snapshot.outbound_failures[0].cooldown_rounds, 0);

        let mut peers = PeerManager::new(125, 2);
        restore_peer_rotation_state(&store, &mut peers).expect("restore peer rotation");
        assert_eq!(peers.outbound_failure_count("198.51.100.30:33369"), 3);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn invalid_persisted_peer_rotation_aborts_node_init_without_clearing_state() {
        let dir = fresh_test_dir("peer-rotation-invalid");
        let store = open_test_store(&dir);
        store
            .put_metadata(PEER_ROTATION_METADATA_KEY, b"invalid")
            .expect("persist invalid peer rotation");
        drop(store);

        let err = match DomNode::init_with_map_size(regtest_node_config(&dir), TEST_LMDB_MAP_SIZE) {
            Ok(_) => panic!("invalid peer rotation should fail init"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("peer rotation"),
            "unexpected error message: {message}"
        );

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(PEER_ROTATION_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"invalid"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn missing_persisted_peer_reputation_starts_empty() {
        let dir = fresh_test_dir("peer-reputation-empty");
        let store = open_test_store(&dir);
        assert!(load_peer_reputation_snapshot(&store)
            .expect("load peer reputation")
            .is_none());

        let node = init_test_node(regtest_node_config(&dir));
        let peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(peers.pending_penalty_count(), 0);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn peer_score_survives_restart_init() {
        let dir = fresh_test_dir("peer-reputation-restart");
        let store = open_test_store(&dir);
        let mut peers = PeerManager::new(125, 8);
        let peer = PeerInfo::new("10.0.0.42:33369".parse().expect("peer addr"), false);
        let addr = peer.addr.to_string();
        peers.register_peer(peer).expect("register peer");
        assert!(!peers.add_ban_score(&addr, 35));
        persist_peer_reputation_snapshot(&store, &peers.peer_reputation_state())
            .expect("persist peer reputation");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        let peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(peers.pending_ban_score(&addr), 35);
        assert_eq!(peers.ban_score(&addr), None);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn banned_peer_remains_banned_after_restart() {
        let dir = fresh_test_dir("peer-reputation-ban-restart");
        let store = open_test_store(&dir);
        let mut peers = PeerManager::new(125, 8);
        let addr = "10.0.0.43:33369";
        assert_eq!(
            peers.add_pending_ban_score(addr, ban_scores::BAN_THRESHOLD),
            100
        );
        persist_peer_reputation_snapshot(&store, &peers.peer_reputation_state())
            .expect("persist peer reputation");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        let mut peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(peers.pending_ban_score(addr), ban_scores::BAN_THRESHOLD);
        assert!(peers.reserve_outbound(addr).is_err());
        assert!(
            peers
                .reserve_inbound(addr.parse().expect("peer addr"))
                .is_err(),
            "persisted ban should block later inbound retry"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn expired_peer_penalty_reintegrates_after_node_restart_without_data_dir_reset() {
        let dir = fresh_test_dir("peer-reputation-expired-restart");
        let store = open_test_store(&dir);
        let addr = "10.0.0.46:33369";
        let snapshot = PersistedPeerReputationState {
            entries: vec![dom_wire::manager::PersistedPeerReputation {
                addr: addr.into(),
                score: ban_scores::BAN_THRESHOLD,
                expires_at_unix_secs: 0,
            }],
        };
        persist_peer_reputation_snapshot(&store, &snapshot).expect("persist expired reputation");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        let mut peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(peers.pending_ban_score(addr), 0);
        let mut peer = PeerInfo::new(addr.parse().expect("peer addr"), true);
        peer.state = PeerState::Connected;
        peers
            .register_peer(peer)
            .expect("expired score must not be renewed on restart");
        drop(peers);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn reputation_cleanup_removes_current_and_legacy_metadata() {
        let dir = fresh_test_dir("peer-reputation-clear-tool");
        let store = open_test_store(&dir);
        store
            .put_metadata(PEER_REPUTATION_METADATA_KEY, b"current")
            .expect("write current reputation");
        store
            .put_metadata(LEGACY_PEER_REPUTATION_METADATA_KEY, b"legacy")
            .expect("write legacy reputation");

        clear_persisted_peer_reputation(&store).expect("clear all reputation metadata");

        assert!(store
            .get_metadata(PEER_REPUTATION_METADATA_KEY)
            .expect("read current")
            .is_none());
        assert!(store
            .get_metadata(LEGACY_PEER_REPUTATION_METADATA_KEY)
            .expect("read legacy")
            .is_none());
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn wrong_network_ban_score_survives_restart() {
        let dir = fresh_test_dir("peer-reputation-wrong-network");
        let store = open_test_store(&dir);
        let snapshot = PersistedPeerReputationState {
            entries: vec![dom_wire::manager::PersistedPeerReputation {
                addr: "10.0.0.44:33369".into(),
                score: ban_scores::WRONG_CHAIN_ID,
                expires_at_unix_secs: u64::MAX,
            }],
        };
        persist_peer_reputation_snapshot(&store, &snapshot).expect("persist peer reputation");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        let peers = node.peers.try_lock().expect("peer lock");
        assert_eq!(
            peers.pending_ban_score("10.0.0.44:33369"),
            ban_scores::WRONG_CHAIN_ID
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn invalid_persisted_peer_reputation_aborts_node_init_without_clearing_state() {
        let dir = fresh_test_dir("peer-reputation-invalid");
        let store = open_test_store(&dir);
        store
            .put_metadata(PEER_REPUTATION_METADATA_KEY, b"invalid")
            .expect("persist invalid peer reputation");
        drop(store);

        let err = match DomNode::init_with_map_size(regtest_node_config(&dir), TEST_LMDB_MAP_SIZE) {
            Ok(_) => panic!("invalid peer reputation should fail init"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("peer reputation"),
            "unexpected error message: {message}"
        );

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(PEER_REPUTATION_METADATA_KEY)
                .expect("reload metadata")
                .expect("metadata present"),
            b"invalid"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn peer_reputation_persistence_remains_separate_from_noise_identity() {
        let dir = fresh_test_dir("peer-reputation-separate-identity");
        let store = open_test_store(&dir);
        let noise = load_or_create_noise_static_key(&store).expect("noise key");
        let snapshot = PersistedPeerReputationState {
            entries: vec![dom_wire::manager::PersistedPeerReputation {
                addr: "10.0.0.45:33369".into(),
                score: 20,
                expires_at_unix_secs: u64::MAX,
            }],
        };
        persist_peer_reputation_snapshot(&store, &snapshot).expect("persist peer reputation");
        drop(store);

        let reopened = open_test_store(&dir);
        assert_eq!(
            reopened
                .get_metadata(NOISE_STATIC_KEY_METADATA_KEY)
                .expect("noise metadata")
                .expect("noise key present"),
            noise.to_vec()
        );
        assert_eq!(
            load_peer_reputation_snapshot(&reopened)
                .expect("load peer reputation")
                .expect("peer reputation present"),
            snapshot
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn persisted_mempool_snapshot_is_cleared_and_not_restored_on_restart_init() {
        let dir = fresh_test_dir("mempool-restart-legacy-snapshot");
        let store = open_test_store(&dir);
        let tx_a = mempool_tx(0x21, 100);
        let tx_b = mempool_tx(0x22, 200);
        let hash_a = tx_hash(&tx_a).expect("hash a");
        let hash_b = tx_hash(&tx_b).expect("hash b");
        let mut mempool = Mempool::new();
        mempool
            .accept_tx(tx_b.clone(), hash_b, 2)
            .expect("accept b");
        mempool
            .accept_tx(tx_a.clone(), hash_a, 1)
            .expect("accept a");
        persist_mempool_snapshot(&store, &mempool.snapshot()).expect("persist mempool");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        assert_eq!(
            node.mempool.blocking_lock().len(),
            0,
            "legacy mempool snapshot must not be restored into runtime state"
        );

        let reopened = open_test_store(&dir);
        assert!(
            load_mempool_snapshot(&reopened)
                .expect("load mempool")
                .is_none(),
            "legacy mempool snapshot metadata must be cleared on restart"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn invalid_persisted_mempool_is_ignored_and_cleared_on_restart_init() {
        let dir = fresh_test_dir("mempool-invalid");
        let store = open_test_store(&dir);
        store
            .put_metadata(MEMPOOL_METADATA_KEY, b"invalid")
            .expect("persist invalid mempool");
        drop(store);

        let node = init_test_node(regtest_node_config(&dir));
        assert_eq!(
            node.mempool.try_lock().expect("mempool lock").len(),
            0,
            "invalid legacy mempool metadata must not reconstruct runtime state"
        );

        let reopened = open_test_store(&dir);
        assert!(
            reopened
                .get_metadata(MEMPOOL_METADATA_KEY)
                .expect("reload metadata")
                .is_none(),
            "invalid legacy mempool metadata should be cleared explicitly"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn clear_persisted_mempool_snapshot_removes_legacy_metadata() {
        let dir = fresh_test_dir("mempool-clear-legacy");
        let store = open_test_store(&dir);
        store
            .put_metadata(MEMPOOL_METADATA_KEY, b"stale")
            .expect("persist legacy mempool metadata");

        clear_persisted_mempool_snapshot(&store).expect("clear mempool metadata");
        assert!(store
            .get_metadata(MEMPOOL_METADATA_KEY)
            .expect("reload metadata")
            .is_none());
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn malformed_message_maps_to_malformed_score() {
        assert_eq!(
            peer_violation_score(&DomError::Malformed("bad frame".into())),
            Some(ban_scores::MALFORMED_MESSAGE)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abusive_peer_still_bans_and_threshold_warn_contains_reason() {
        let dir = fresh_test_dir("peer-threshold-warn");
        let node = init_test_node(regtest_node_config(&dir));
        let peer_addr: SocketAddr = "127.0.0.2:33369".parse().expect("peer addr");
        let mut peer = PeerInfo::new(peer_addr, false);
        peer.state = PeerState::Connected;
        node.peers
            .lock()
            .await
            .register_peer(peer)
            .expect("register abusive test peer");

        let logs = TestLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(logs.clone())
            .finish();
        let _subscriber_guard = tracing::subscriber::set_default(subscriber);
        let error = DomError::Malformed("repeated malformed abuse".into());

        for attempt in 0..5 {
            let banned = record_peer_violation(&node.chain, &node.peers, peer_addr, &error).await;
            assert_eq!(
                banned,
                attempt == 4,
                "five malformed-message penalties must still reach the threshold"
            );
        }

        let output = logs.contents();
        assert!(output.contains("peer_ban_threshold_crossed"), "{output}");
        assert!(output.contains(&format!("peer={peer_addr}")), "{output}");
        assert!(
            output.contains("reason=Malformed: repeated malformed abuse"),
            "{output}"
        );
        assert!(output.contains("accumulated_score=100"), "{output}");
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn wrong_network_identity_maps_to_immediate_ban_score() {
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::WrongChainId,
                "chain_id mismatch",
            )),
            Some(ban_scores::WRONG_CHAIN_ID)
        );
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::WrongChainId,
                "network_magic mismatch: ours=0x444f4d31 theirs=0x54444f4d",
            )),
            Some(ban_scores::WRONG_CHAIN_ID)
        );
    }

    #[test]
    fn invalid_pow_maps_to_invalid_pow_score() {
        // Both real messages from dom-consensus block.rs (validate_pow and
        // validate_pow_for_network) must route to INVALID_POW, not the
        // generic PROTOCOL_VIOLATION catch-all.
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::InvalidPow,
                "proof-of-work invalid: RandomX hash mismatch or does not meet target",
            )),
            Some(ban_scores::INVALID_POW)
        );
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::InvalidPow,
                "proof-of-work invalid: hash mismatch or does not meet target",
            )),
            Some(ban_scores::INVALID_POW)
        );
    }

    #[test]
    fn invalid_signature_maps_to_invalid_signature_score() {
        // Real messages from dom-consensus: kernel Schnorr verification
        // (lib.rs) and coinbase kernel verification (transaction.rs).
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::InvalidSignature,
                "kernel 0 Schnorr signature invalid",
            )),
            Some(ban_scores::INVALID_SIGNATURE)
        );
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::InvalidSignature,
                "coinbase kernel signature invalid — miner does not prove ownership",
            )),
            Some(ban_scores::INVALID_SIGNATURE)
        );
    }

    #[test]
    fn generic_invalid_still_maps_to_protocol_violation() {
        // Regression: Invalid errors without a specific severity arm keep the
        // generic PROTOCOL_VIOLATION score.
        assert_eq!(
            peer_violation_score(&DomError::Invalid("claimed fees 5 != actual fees 7".into())),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn write_timeout_maps_to_protocol_violation() {
        // Anti-slowloris: a stalled write (peer stopped reading) is a low-severity
        // protocol violation — a slow peer is not necessarily malicious.
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::WriteTimeout,
                "write timeout after 30s",
            )),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn message_rate_limit_maps_to_protocol_violation() {
        // Anti-flood: exceeding a per-category inbound message budget is a
        // low-severity protocol violation; ~10 overflowing windows ban the peer.
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::MessageRateLimit,
                "message rate limit exceeded for Block [ban+10]",
            )),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn is_write_timeout_distinguishes_write_stall_from_recv_errors() {
        // Only the write-side timeout is scored at the message_loop boundary;
        // recv-side errors are scored inline and must NOT match here (else they
        // would be double-counted).
        assert!(is_write_timeout(&DomError::peer_misbehavior(
            PeerMisbehavior::WriteTimeout,
            "write timeout after 30s",
        )));
        assert!(!is_write_timeout(&DomError::PolicyRejected(
            "idle timeout after 60s".into()
        )));
        assert!(!is_write_timeout(&DomError::Malformed("bad frame".into())));
        assert!(!is_write_timeout(&DomError::Internal(
            "relay channel closed".into()
        )));
    }

    #[test]
    fn annotate_send_err_preserves_write_timeout_but_wraps_others() {
        let addr: std::net::SocketAddr = "127.0.0.1:1234".parse().unwrap();
        // Write timeout passes through unchanged so it still routes to scoring.
        let to = annotate_send_err(
            "relay",
            addr,
            DomError::peer_misbehavior(PeerMisbehavior::WriteTimeout, "write timeout after 30s"),
        );
        assert_eq!(
            peer_violation_score(&to),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
        // Non-timeout failures (broken pipe etc.) are our/transport side: wrapped
        // as Internal (diagnostic context) and left unscored.
        let other = annotate_send_err(
            "relay",
            addr,
            DomError::Internal("write frame data: broken pipe".into()),
        );
        assert!(matches!(&other, DomError::Internal(m) if m.contains("relay send to")));
        assert_eq!(peer_violation_score(&other), None);
    }

    #[test]
    fn stem_send_error_does_not_disclose_selected_privacy_hop() {
        let error = redact_stem_send_err(DomError::Internal(
            "write frame to 198.51.100.8:3414 failed".into(),
        ));
        let rendered = error.to_string();
        assert_eq!(rendered, "Internal: private transaction relay write failed");
        assert!(!rendered.contains("198.51.100.8"));
        assert!(!rendered.contains("stem"));

        let timeout = redact_stem_send_err(DomError::peer_misbehavior(
            PeerMisbehavior::WriteTimeout,
            "write timeout after 30s",
        ));
        assert_eq!(
            peer_violation_score(&timeout),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn two_invalid_pow_blocks_cross_ban_threshold() {
        // The audit finding: at PROTOCOL_VIOLATION (10) a peer needed ~10
        // invalid-PoW blocks (each forcing full validation) to be banned.
        // At INVALID_POW (50), two blocks must reach BAN_THRESHOLD (100).
        let pow_error = DomError::peer_misbehavior(
            PeerMisbehavior::InvalidPow,
            "proof-of-work invalid: RandomX hash mismatch or does not meet target",
        );
        let score = peer_violation_score(&pow_error).expect("invalid PoW must score");

        let mut peer =
            dom_wire::peer::PeerInfo::new("127.0.0.1:33369".parse().expect("addr"), false);
        assert!(
            !peer.add_ban_score(score),
            "first invalid-PoW block must not ban yet"
        );
        assert!(
            peer.add_ban_score(score),
            "second invalid-PoW block must cross BAN_THRESHOLD"
        );
        assert!(peer.ban_score >= ban_scores::BAN_THRESHOLD);
    }

    #[test]
    fn temporary_peer_errors_do_not_score() {
        assert_eq!(
            peer_violation_score(&DomError::TemporarilyInvalid("future block".into())),
            None
        );
        assert_eq!(
            peer_violation_score(&DomError::Orphan("missing parent".into())),
            None
        );
    }

    // ── dom-shield: peer_violation_score structured-routing KAV ───────────────
    //
    // peer_violation_score must route severity by DomError::PeerMisbehavior kind,
    // not by inspecting attacker-influenced error text.

    #[test]
    fn shield_pow_severity_uses_structured_kind_not_text() {
        let near_miss = DomError::Invalid("PoW check failed: hash above target".into());
        assert_eq!(
            peer_violation_score(&near_miss),
            Some(ban_scores::PROTOCOL_VIOLATION),
            "plain Invalid text must not receive INVALID_POW severity"
        );
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::InvalidPow,
                "PoW check failed: hash above target",
            )),
            Some(ban_scores::INVALID_POW),
            "structured InvalidPow keeps severity independent of message wording"
        );
        assert_eq!(ban_scores::INVALID_POW, 50);
        assert_eq!(ban_scores::PROTOCOL_VIOLATION, 10);
    }

    #[test]
    fn shield_signature_severity_uses_structured_kind_not_text() {
        let near_miss = DomError::Invalid("bad Schnorr sig on kernel 0".into());
        assert_eq!(
            peer_violation_score(&near_miss),
            Some(ban_scores::PROTOCOL_VIOLATION),
            "plain Invalid text must not receive INVALID_SIGNATURE severity"
        );
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::InvalidSignature,
                "bad Schnorr sig on kernel 0",
            )),
            Some(ban_scores::INVALID_SIGNATURE),
            "structured InvalidSignature keeps severity independent of message wording"
        );
        assert_eq!(ban_scores::INVALID_SIGNATURE, 25);
    }

    #[test]
    fn shield_substring_match_is_position_independent_and_overmatches() {
        let incidental = DomError::Invalid(
            "rejected child block citing parent 'proof-of-work invalid' marker".into(),
        );
        assert_eq!(
            peer_violation_score(&incidental),
            Some(ban_scores::PROTOCOL_VIOLATION),
            "incidental quoted text must not inherit INVALID_POW severity"
        );
    }

    #[test]
    fn address_flooding_maps_to_address_flooding_score() {
        assert_eq!(
            peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::AddressFlooding,
                "address flooding: more than 4 Addr messages in 600s [ban+30]",
            )),
            Some(ban_scores::ADDRESS_FLOODING)
        );
        // Other policy rejections must NOT inherit the flooding score.
        assert_eq!(
            peer_violation_score(&DomError::PolicyRejected("mempool full".into())),
            None
        );
    }

    #[test]
    fn pre_registration_handshake_timeout_scores() {
        assert_eq!(
            pending_peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::HandshakeTimeout,
                "handshake timeout after 10s",
            )),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn pre_registration_hello_timeout_scores() {
        assert_eq!(
            pending_peer_violation_score(&DomError::peer_misbehavior(
                PeerMisbehavior::HelloTimeout,
                "hello timeout after 10s",
            )),
            Some(ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn deferred_best_chain_replays_to_relay() {
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::BestChain)),
            DeferredReplayAction::RelayBestChain
        );
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::Reorg(ReorgDelta::default()))),
            DeferredReplayAction::RelayBestChain
        );
    }

    #[test]
    fn deferred_retryable_rejections_requeue() {
        assert_eq!(
            deferred_replay_action(&Err(DomError::TemporarilyInvalid("future block".into()))),
            DeferredReplayAction::Requeue
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Orphan("missing parent".into()))),
            DeferredReplayAction::Requeue
        );
    }

    #[test]
    fn deferred_non_retryable_outcomes_drop() {
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::SideChain)),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Ok(ConnectResult::AlreadyHave)),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Malformed("bad deferred bytes".into()))),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Invalid("bad block".into()))),
            DeferredReplayAction::Drop
        );
        assert_eq!(
            deferred_replay_action(&Err(DomError::Internal("store failure".into()))),
            DeferredReplayAction::Drop
        );
    }

    #[test]
    fn relay_best_chain_rebroadcasts() {
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::BestChain)),
            RelayBlockAction::RelayBestChain
        );
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::Reorg(ReorgDelta::default()))),
            RelayBlockAction::RelayBestChain
        );
    }

    #[tokio::test]
    async fn reorg_mempool_reconciliation_reinjects_live_txs_and_evicts_conflicts() {
        let dir = fresh_test_dir("reorg-mempool-reconcile");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        let base_value = 500_000;
        let base_blinding = scalar(40);
        let base_output = Commitment::commit(base_value, &base_blinding);
        let base_tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: base_output.clone(),
                proof: vec![0x40; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(41, 0),
                excess_signature: [0x41; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block =
            synthetic_block_with_transactions(Hash256::ZERO, 1, 11, 42, vec![base_tx.clone()]);
        commit_chain_block(&chain, &base_block).await;

        let disconnected_tx = signed_spend_tx(
            base_value,
            base_blinding,
            MIN_RELAY_FEE_RATE * 100,
            50,
            51,
            &chain_id,
        );
        let conflicting_input = commitment(60, 30);
        let conflicting_live_tx = synthetic_spend_tx(conflicting_input.clone(), 61, 62);
        let conflicting_live_hash = tx_hash(&conflicting_live_tx).expect("hash");
        {
            let mut pool = mempool.lock().await;
            pool.accept_tx(conflicting_live_tx, conflicting_live_hash, 1)
                .expect("accept conflicting tx");
        }
        let connected_tx = synthetic_spend_tx(conflicting_input, 63, 64);
        let reorg = ReorgDelta {
            disconnected_txs: vec![disconnected_tx.clone()],
            connected_txs: vec![connected_tx],
            ..Default::default()
        };

        reconcile_mempool_after_connect(&chain, &mempool, &ConnectResult::Reorg(reorg), &[])
            .await
            .expect("reconcile reorg mempool");

        let disconnected_hash = tx_hash(&disconnected_tx).expect("hash");
        let pool = mempool.lock().await;
        assert!(
            pool.get_tx(&disconnected_hash).is_some(),
            "live disconnected tx must be resurrected deterministically"
        );
        assert!(
            pool.get_tx(&conflicting_live_hash).is_none(),
            "connected-branch input must evict conflicting mempool tx"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn reorg_reinjection_is_canonical_and_chainstate_aware() {
        let dir = fresh_test_dir("reorg-reinject-canonical");
        let chain = open_chain(&dir);
        let mempool_a = Arc::new(Mutex::new(Mempool::new()));
        let mempool_b = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        let live_value = 500_000;
        let live_blinding = scalar(70);
        let live_output = Commitment::commit(live_value, &live_blinding);
        let base_tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: live_output.clone(),
                proof: vec![0x70; 8],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(dom_core::MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(71, 0),
                excess_signature: [0x71; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block = synthetic_block_with_transactions(Hash256::ZERO, 1, 17, 72, vec![base_tx]);
        commit_chain_block(&chain, &base_block).await;

        let conflict_a = signed_spend_tx(
            live_value,
            live_blinding.clone(),
            MIN_RELAY_FEE_RATE * 100,
            73,
            74,
            &chain_id,
        );
        let conflict_b = signed_spend_tx(
            live_value,
            live_blinding,
            MIN_RELAY_FEE_RATE * 100,
            75,
            76,
            &chain_id,
        );
        let missing_input_tx = signed_spend_tx(
            500_000,
            scalar(77),
            MIN_RELAY_FEE_RATE * 100,
            78,
            79,
            &chain_id,
        );
        let immature_coinbase_tx = signed_spend_tx(
            1_000_001,
            scalar(72),
            MIN_RELAY_FEE_RATE * 100,
            80,
            81,
            &chain_id,
        );

        let delta_a = ReorgDelta {
            disconnected_txs: vec![
                conflict_b.clone(),
                missing_input_tx.clone(),
                immature_coinbase_tx.clone(),
                conflict_a.clone(),
            ],
            connected_txs: vec![],
            ..Default::default()
        };
        let delta_b = ReorgDelta {
            disconnected_txs: vec![
                conflict_a.clone(),
                immature_coinbase_tx,
                missing_input_tx,
                conflict_b.clone(),
            ],
            connected_txs: vec![],
            ..Default::default()
        };

        reconcile_mempool_after_connect(&chain, &mempool_a, &ConnectResult::Reorg(delta_a), &[])
            .await
            .expect("reconcile canonical order A");
        reconcile_mempool_after_connect(&chain, &mempool_b, &ConnectResult::Reorg(delta_b), &[])
            .await
            .expect("reconcile canonical order B");

        let conflict_a_hash = tx_hash(&conflict_a).expect("hash");
        let conflict_b_hash = tx_hash(&conflict_b).expect("hash");
        let winner = conflict_a_hash.min(conflict_b_hash);
        let loser = conflict_a_hash.max(conflict_b_hash);

        let pool_a = mempool_a.lock().await;
        let pool_b = mempool_b.lock().await;
        assert_eq!(pool_a.all_hashes(), vec![winner]);
        assert_eq!(pool_b.all_hashes(), vec![winner]);
        assert!(pool_a.get_tx(&winner).is_some());
        assert!(pool_a.get_tx(&loser).is_none());
        assert!(
            pool_b.all_hashes() == pool_a.all_hashes(),
            "repeated reinjection over the same inputs must converge identically"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    /// RFC-0012 §3.2: a disconnected transaction carrying a coinbase/system kernel
    /// feature must never be reinjected into the relay mempool, even when its
    /// inputs are live under the new canonical chain. A sibling plain transaction
    /// over a different live output is reinjected, proving the exclusion is
    /// specific to the coinbase feature and not a blanket drop.
    #[tokio::test]
    async fn reorg_reinjection_excludes_coinbase_feature_transactions() {
        let dir = fresh_test_dir("reorg-reinject-coinbase-excluded");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        // Two live outputs created by a base block.
        let live_a_value = 500_000;
        let live_b_value = 600_000;
        let live_a_blinding = scalar(110);
        let live_b_blinding = scalar(112);
        let live_a = Commitment::commit(live_a_value, &live_a_blinding);
        let live_b = Commitment::commit(live_b_value, &live_b_blinding);
        let base_tx = Transaction {
            inputs: vec![],
            outputs: vec![
                TransactionOutput {
                    commitment: live_a.clone(),
                    proof: vec![0xA0; 8],
                },
                TransactionOutput {
                    commitment: live_b.clone(),
                    proof: vec![0xB0; 8],
                },
            ],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(114, 0),
                excess_signature: [0xC0; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block =
            synthetic_block_with_transactions(Hash256::ZERO, 1, 23, 120, vec![base_tx]);
        commit_chain_block(&chain, &base_block).await;

        // Plain tx over live_a — eligible. Coinbase-feature tx over live_b —
        // forbidden for relay despite a live input.
        let plain_tx = signed_spend_tx(
            live_a_value,
            live_a_blinding,
            MIN_RELAY_FEE_RATE * 100,
            130,
            131,
            &chain_id,
        );
        let mut coinbase_feature_tx = signed_spend_tx(
            live_b_value,
            live_b_blinding,
            MIN_RELAY_FEE_RATE * 100,
            132,
            133,
            &chain_id,
        );
        coinbase_feature_tx.kernels[0].features = dom_core::KERNEL_FEAT_COINBASE;

        let reorg = ReorgDelta {
            disconnected_txs: vec![coinbase_feature_tx.clone(), plain_tx.clone()],
            connected_txs: vec![],
            ..Default::default()
        };
        reconcile_mempool_after_connect(&chain, &mempool, &ConnectResult::Reorg(reorg), &[])
            .await
            .expect("reconcile reorg mempool");

        let pool = mempool.lock().await;
        assert!(
            pool.get_tx(&tx_hash(&plain_tx).expect("hash")).is_some(),
            "plain tx over a live output must be reinjected"
        );
        assert!(
            pool.get_tx(&tx_hash(&coinbase_feature_tx).expect("hash"))
                .is_none(),
            "coinbase/system-feature tx must be excluded from reinjection"
        );
        assert_eq!(pool.len(), 1, "exactly the eligible plain tx is reinjected");
        drop(pool);
        crate::test_dir::remove_test_dir(&dir);
    }

    /// RFC-0012 §3.4: two nodes that experience the same reorg but originally
    /// received the disconnected transactions in different orders converge to the
    /// same canonical mempool **digest**. This pins the convergence guarantee to
    /// the byte-level digest, not just the hash listing.
    #[tokio::test]
    async fn reorg_reinjection_converges_to_same_digest_across_delivery_order() {
        let dir = fresh_test_dir("reorg-reinject-digest-converge");
        let chain = open_chain(&dir);
        let mempool_a = Arc::new(Mutex::new(Mempool::new()));
        let mempool_b = Arc::new(Mutex::new(Mempool::new()));
        let chain_id = {
            let c = chain.lock().await;
            *dom_consensus::derive_chain_id(c.network_magic, &c.genesis_hash).as_bytes()
        };

        // Three independent live outputs → three non-conflicting eligible txs.
        let live_values = [500_000, 600_000, 700_000];
        let live_blindings = [scalar(140), scalar(142), scalar(144)];
        let live = [
            Commitment::commit(live_values[0], &live_blindings[0]),
            Commitment::commit(live_values[1], &live_blindings[1]),
            Commitment::commit(live_values[2], &live_blindings[2]),
        ];
        let base_tx = Transaction {
            inputs: vec![],
            outputs: live
                .iter()
                .enumerate()
                .map(|(i, c)| TransactionOutput {
                    commitment: c.clone(),
                    proof: vec![0xD0 + i as u8; 8],
                })
                .collect(),
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 100).expect("fee"),
                lock_height: 0,
                excess: commitment(146, 0),
                excess_signature: [0xE0; 65],
            }],
            offset: [0u8; 32],
        };
        let base_block =
            synthetic_block_with_transactions(Hash256::ZERO, 1, 29, 150, vec![base_tx]);
        commit_chain_block(&chain, &base_block).await;

        let t0 = signed_spend_tx(
            live_values[0],
            live_blindings[0].clone(),
            MIN_RELAY_FEE_RATE * 100,
            160,
            161,
            &chain_id,
        );
        let t1 = signed_spend_tx(
            live_values[1],
            live_blindings[1].clone(),
            MIN_RELAY_FEE_RATE * 100,
            162,
            163,
            &chain_id,
        );
        let t2 = signed_spend_tx(
            live_values[2],
            live_blindings[2].clone(),
            MIN_RELAY_FEE_RATE * 100,
            164,
            165,
            &chain_id,
        );

        // Different delivery orders into A and B.
        let delta_a = ReorgDelta {
            disconnected_txs: vec![t2.clone(), t0.clone(), t1.clone()],
            connected_txs: vec![],
            ..Default::default()
        };
        let delta_b = ReorgDelta {
            disconnected_txs: vec![t1.clone(), t2.clone(), t0.clone()],
            connected_txs: vec![],
            ..Default::default()
        };
        reconcile_mempool_after_connect(&chain, &mempool_a, &ConnectResult::Reorg(delta_a), &[])
            .await
            .expect("reconcile A");
        reconcile_mempool_after_connect(&chain, &mempool_b, &ConnectResult::Reorg(delta_b), &[])
            .await
            .expect("reconcile B");

        let pool_a = mempool_a.lock().await;
        let pool_b = mempool_b.lock().await;
        assert_eq!(pool_a.len(), 3, "all three eligible txs reinjected");
        assert_eq!(
            pool_a.digest(),
            pool_b.digest(),
            "reorg reinjection converges to the same mempool digest regardless of delivery order"
        );
        drop(pool_a);
        drop(pool_b);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn relay_duplicates_and_retryable_errors_are_suppressed() {
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::SideChain)),
            RelayBlockAction::Suppress
        );
        assert_eq!(
            relay_block_action(&Ok(ConnectResult::AlreadyHave)),
            RelayBlockAction::Suppress
        );
        assert_eq!(
            relay_block_action(&Err(DomError::TemporarilyInvalid("future block".into()))),
            RelayBlockAction::Suppress
        );
        assert_eq!(
            relay_block_action(&Err(DomError::Orphan("missing parent".into()))),
            RelayBlockAction::Suppress
        );
    }

    #[test]
    fn relay_invalid_or_malformed_errors_penalize_peers() {
        assert_eq!(
            relay_block_action(&Err(DomError::Invalid("bad block".into()))),
            RelayBlockAction::PenalizePeer
        );
        assert_eq!(
            relay_block_action(&Err(DomError::Malformed("bad payload".into()))),
            RelayBlockAction::PenalizePeer
        );
        assert_eq!(
            relay_block_action(&Err(DomError::Internal("store failure".into()))),
            RelayBlockAction::Drop
        );
    }

    #[test]
    fn malformed_relay_payload_is_rejected_before_block_decode() {
        let err = decode_relay_block(&[0xde, 0xad]).expect_err("short payload must fail");
        assert!(matches!(err, DomError::Malformed(_)));
    }

    #[test]
    fn oversized_relay_payload_is_rejected_without_allocating_block_body() {
        let oversized = ((MAX_BLOCK_SERIALIZED_SIZE + 1) as u32).to_le_bytes();
        let err = decode_relay_block(&oversized).expect_err("oversized payload must fail");
        assert!(
            matches!(err, DomError::Malformed(ref msg) if msg.contains("block too large")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn malformed_relay_block_body_is_rejected() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(3u32).to_le_bytes());
        payload.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

        let err = decode_relay_block(&payload).expect_err("malformed block body must fail");
        assert!(matches!(err, DomError::Malformed(_)));
    }

    #[test]
    fn ibd_block_response_rejects_hash_mismatch() {
        let expected = synthetic_block(1, 11);
        let wrong = synthetic_block(1, 22);
        let err = decode_ibd_block_response(&ibd_payload(&wrong), block_hash(&expected))
            .expect_err("mismatched IBD block must reject");
        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("hash mismatch")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn ibd_block_response_accepts_requested_block() {
        let block = synthetic_block(2, 33);
        let decoded = decode_ibd_block_response(&ibd_payload(&block), block_hash(&block))
            .expect("matching IBD block must decode");
        assert_eq!(decoded.1.header.height.0, 2);
        assert_eq!(decoded.1.header.pow.nonce, 33);
    }

    #[tokio::test]
    async fn invariant_ibd_import_rejects_header_and_pmmr_valid_but_economically_unbalanced_block()
    {
        std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
        let dir = fresh_test_dir("ibd-invalid-economic-balance");
        let chain = open_chain(&dir);
        let chain_id = {
            use dom_consensus::derive_chain_id;
            *derive_chain_id(
                NETWORK_MAGIC_REGTEST,
                &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
            )
            .as_bytes()
        };

        let genesis = build_canonical_genesis(NETWORK_MAGIC_REGTEST, &chain_id)
            .expect("canonical Regtest genesis")
            .block
            .expect("Regtest genesis has a canonical block body");
        // Regtest's frozen genesis uses its historical signing context to avoid
        // a genesis-hash/chain-ID signing cycle. Persist the already canonical
        // identity directly, as production bootstrap does, then exercise
        // `connect_block` only for the adversarial IBD block under test.
        commit_chain_block(&chain, &genesis).await;

        let mut invalid_offset = [0u8; 32];
        invalid_offset[31] = 1;
        let invalid = build_coinbase_only_block(
            block_hash(&genesis),
            Hash256::from_bytes(block_hash(&genesis)),
            BlockHeight(1),
            genesis.header.total_difficulty,
            invalid_offset,
            &chain_id,
        );
        let payload = ibd_payload(&invalid);
        let (_, decoded) = decode_ibd_block_response(&payload, block_hash(&invalid))
            .expect("IBD payload itself must decode and hash-match");

        let err = {
            let mut guard = chain.lock().await;
            guard
                .connect_block(&decoded, safe_now())
                .expect_err("IBD import must reject economic imbalance")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("aggregate") || msg.contains("balance"),
            "expected economic-balance rejection, got: {msg}"
        );

        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn malformed_deferred_block_bytes_are_dropped_on_decode() {
        let err = decode_deferred_block_bytes(&[0x01, 0x02, 0x03])
            .expect_err("malformed deferred bytes must fail");
        assert!(matches!(err, DomError::Malformed(_)));
    }

    #[test]
    fn outbound_attempt_outcome_marks_retryable_failures_only() {
        assert_eq!(
            OutboundAttemptOutcome::RetryableFailure,
            OutboundAttemptOutcome::RetryableFailure
        );
        assert_ne!(
            OutboundAttemptOutcome::RetryableFailure,
            OutboundAttemptOutcome::Registered
        );
        assert_ne!(
            OutboundAttemptOutcome::RetryableFailure,
            OutboundAttemptOutcome::Shutdown
        );
    }

    #[tokio::test]
    async fn refresh_peer_metrics_counts_connected_peer_directions() {
        let peers = Arc::new(Mutex::new(PeerManager::new(125, 8)));
        let metrics = Arc::new(Metrics::new());

        let inbound_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
        let mut inbound = PeerInfo::new(inbound_addr, false);
        inbound.state = PeerState::Connected;

        let outbound_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 33369);
        let mut outbound = PeerInfo::new(outbound_addr, true);
        outbound.state = PeerState::Connected;

        let banned_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 33369);
        let mut banned = PeerInfo::new(banned_addr, false);
        banned.state = PeerState::Banned;

        {
            let mut mgr = peers.lock().await;
            mgr.register_peer(inbound).expect("register inbound");
            mgr.register_peer(outbound).expect("register outbound");
            mgr.peers.insert(banned_addr.to_string(), banned);
        }

        refresh_peer_metrics(&peers, &metrics, None).await;

        assert_eq!(
            metrics
                .peer_count
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics
                .inbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .outbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn refresh_peer_metrics_ignores_failed_outbound_reservations() {
        let peers = Arc::new(Mutex::new(PeerManager::new(125, 1)));
        let metrics = Arc::new(Metrics::new());

        {
            let mut mgr = peers.lock().await;
            mgr.reserve_outbound("203.0.113.44:33369")
                .expect("reserve outbound");
        }
        refresh_peer_metrics(&peers, &metrics, None).await;

        assert_eq!(
            metrics
                .peer_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .inbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .outbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        {
            let mut mgr = peers.lock().await;
            mgr.release_outbound_reservation("203.0.113.44:33369");
        }
        refresh_peer_metrics(&peers, &metrics, None).await;

        assert_eq!(
            metrics
                .peer_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .inbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            metrics
                .outbound_peers
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn best_chain_cleanup_purges_mempool_conflicts_by_input() {
        let dir = fresh_test_dir("mempool-purge");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let shared_input = commitment(9, 50);
        let tx = spending_tx(shared_input, 0x21);
        let tx_hash = [0x21; 32];
        {
            let mut pool = mempool.lock().await;
            pool.accept_tx(tx.clone(), tx_hash, 0).expect("accept tx");
            assert_eq!(pool.len(), 1);
        }

        purge_mempool_confirmed_inputs(&chain, &mempool, &[tx])
            .await
            .expect("purge mempool");

        let pool = mempool.lock().await;
        assert_eq!(
            pool.len(),
            0,
            "confirmed inputs must be purged from mempool"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    /// DOM-AUDIT-001 regression. `resume_ibd_block_sync` used to call
    /// `purge_mempool_confirmed_inputs` while the chain guard `c` from
    /// `connect_block` was still alive. `purge` re-acquires the chain lock via
    /// `persist_mempool_state`, and tokio's `Mutex` is NOT reentrant, so the IBD
    /// task deadlocked on its own guard. The fix captures the `ConnectResult`
    /// under the guard, drops it, and only then purges + applies to the wallet.
    ///
    /// This test pins both halves of the invariant on the non-empty purge path
    /// (a non-coinbase tx whose input commitment is live in the mempool, which
    /// forces the re-acquiring `persist_mempool_state` branch):
    ///   1. holding the chain guard across `purge` deadlocks (pre-fix behaviour),
    ///   2. dropping it first lets `purge` complete and empties the mempool.
    /// The deadlock is detected with a short `tokio::time::timeout`: the IBD task
    /// parks forever on the self-held mutex while the runtime's timer driver
    /// still fires the timeout, so the pre-fix branch resolves to `Err(Elapsed)`
    /// rather than hanging the test. The fixed branch completes in microseconds,
    /// well inside its (deliberately generous) timeout.
    #[tokio::test]
    async fn ibd_resume_purge_after_connect_does_not_deadlock_on_chain_relock() {
        let dir = fresh_test_dir("ibd-purge-relock");
        let chain = open_chain(&dir);
        let shared_input = commitment(9, 50);

        // (1) Pre-fix pattern: chain guard held across purge -> must deadlock.
        {
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let tx = spending_tx(shared_input.clone(), 0x21);
            {
                let mut pool = mempool.lock().await;
                pool.accept_tx(tx.clone(), [0x21; 32], 0)
                    .expect("accept tx");
                assert_eq!(pool.len(), 1);
            }

            let guard = chain.lock().await;
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                purge_mempool_confirmed_inputs(&chain, &mempool, &[tx]),
            )
            .await;
            assert!(
                outcome.is_err(),
                "purge while holding the chain guard must deadlock on the re-acquire (DOM-AUDIT-001)"
            );
            drop(guard);
        }

        // (2) Fixed pattern: guard dropped before purge -> completes + purges.
        {
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let tx = spending_tx(shared_input, 0x22);
            {
                let mut pool = mempool.lock().await;
                pool.accept_tx(tx.clone(), [0x22; 32], 0)
                    .expect("accept tx");
                assert_eq!(pool.len(), 1);
            }

            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                purge_mempool_confirmed_inputs(&chain, &mempool, &[tx]),
            )
            .await
            .expect("purge must not deadlock once the chain guard is dropped")
            .expect("purge succeeds");

            assert_eq!(
                mempool.lock().await.len(),
                0,
                "confirmed inputs must be purged once the chain guard is released"
            );
        }

        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn persisted_header_resume_completes_with_canonical_snapshot_cleanup() {
        let dir = fresh_test_dir("header-resume-ok");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };

        let header1 = synthetic_known_header(0, Hash256::ZERO, 1);
        let header2 = synthetic_known_header(1, Hash256::from_bytes(header_hash(&header1)), 2);
        store_known_header(&chain, &header1).await;
        store_known_header(&chain, &header2).await;

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: vec![
                header1.to_bytes().expect("header1 bytes"),
                header2.to_bytes().expect("header2 bytes"),
            ],
            block_cursor: 0,
            header_cursor: 1,
            header_cursor_height: 1,
        };
        {
            let chain = chain.lock().await;
            snapshot.save(&chain.store).expect("save snapshot");
        }

        let (mut ibd, restored) = initialize_ibd_state(&chain, peer_addr, 1)
            .await
            .expect("initialize");
        let restored = restored.expect("restored snapshot");
        let pending_blocks = continue_ibd_header_sync(
            &chain,
            peer_addr,
            &mut ibd,
            IbdRoundState {
                pending_blocks: restored.pending_blocks.clone(),
                pending_headers: restored.pending_headers.clone(),
                block_cursor: restored.block_cursor,
                header_cursor: restored.header_cursor,
                header_cursor_height: restored.header_cursor_height,
            },
            ibd_now(),
            super::IbdHeaderValidationMode::Ordinary,
        )
        .await
        .expect("resume header sync");

        assert!(pending_blocks.is_empty());
        assert_eq!(ibd.headers_height, 1);
        assert_eq!(ibd.phase, IbdPhase::Discovering);

        let persisted = {
            let chain = chain.lock().await;
            PersistedIbdState::load(&chain.store)
                .expect("load snapshot")
                .expect("snapshot present")
        };
        assert!(persisted.pending_headers.is_empty());
        assert!(persisted.pending_blocks.is_empty());
        assert_eq!(persisted.header_cursor, 0);
        assert_eq!(persisted.headers_height, 1);
        assert_eq!(persisted.phase, IbdPhase::Discovering);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn persisted_ibd_checkpoint_uses_durable_tip_inside_partial_block_page() {
        let dir = fresh_test_dir("ibd-durable-tip-cursor");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let ibd = IbdState::new(0, 10);
        {
            let mut guard = chain.lock().await;
            guard.tip_height = BlockHeight(5);
            guard.tip_hash = Hash256::from_bytes([0x55; 32]);
        }

        persist_ibd_state(
            &chain,
            peer_addr,
            &ibd,
            IbdRoundState {
                pending_blocks: vec![[0x77; 32]; 5],
                pending_headers: Vec::new(),
                block_cursor: 2,
                header_cursor: 0,
                header_cursor_height: 10,
            },
        )
        .await
        .expect("persist partial body page");

        let snapshot = {
            let guard = chain.lock().await;
            PersistedIbdState::load(&guard.store)
                .expect("load snapshot")
                .expect("snapshot exists")
        };
        assert_eq!(snapshot.blocks_height, 5);
        assert_eq!(snapshot.last_progress_height, 5);
        assert_eq!(snapshot.checkpoint_tip_hash, [0x55; 32]);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn persisted_header_prefix_reconciles_hash_that_became_known() {
        let dir = fresh_test_dir("header-resume-known-prefix");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };

        let header1 = synthetic_known_header(0, Hash256::ZERO, 1);
        let header2 = synthetic_known_header(1, Hash256::from_bytes(header_hash(&header1)), 2);
        let header1_hash = header_hash(&header1);
        // The persisted queue was created while header1 was missing. It became
        // known before reconstruction, producing the observed N-1/expected N
        // state from the Mainnet incident.
        store_known_header(&chain, &header1).await;
        store_known_header(&chain, &header2).await;

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: vec![header1_hash],
            pending_headers: vec![
                header1.to_bytes().expect("header1 bytes"),
                header2.to_bytes().expect("header2 bytes"),
            ],
            block_cursor: 0,
            header_cursor: 1,
            header_cursor_height: 1,
        };
        {
            let guard = chain.lock().await;
            snapshot.save(&guard.store).expect("save snapshot");
        }

        let (mut ibd, restored) = initialize_ibd_state(&chain, peer_addr, 1)
            .await
            .expect("initialize");
        let restored = restored.expect("snapshot remains resumable");
        let pending = continue_ibd_header_sync(
            &chain,
            peer_addr,
            &mut ibd,
            IbdRoundState {
                pending_blocks: restored.pending_blocks,
                pending_headers: restored.pending_headers,
                block_cursor: restored.block_cursor,
                header_cursor: restored.header_cursor,
                header_cursor_height: restored.header_cursor_height,
            },
            ibd_now(),
            super::IbdHeaderValidationMode::Ordinary,
        )
        .await
        .expect("reconcile now-known prefix hash");
        assert!(pending.is_empty());
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn persisted_ibd_checkpoint_survives_reconnect_and_peer_tip_growth() {
        let dir = fresh_test_dir("ibd-reconnect-tip-growth");
        let chain = open_chain(&dir);
        let old_peer: SocketAddr = "127.0.0.1:33369".parse().expect("old peer");
        let new_peer: SocketAddr = "127.0.0.2:33369".parse().expect("new peer");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };
        let header = synthetic_known_header(0, Hash256::ZERO, 1);

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: old_peer.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 2,
            last_interruption: Some(IbdInterruption::PeerDisconnected),
            pending_blocks: Vec::new(),
            pending_headers: vec![header.to_bytes().expect("header bytes")],
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 1,
        };
        {
            let guard = chain.lock().await;
            snapshot.save(&guard.store).expect("save snapshot");
        }

        let (ibd, restored) = initialize_ibd_state(&chain, new_peer, 2)
            .await
            .expect("initialize after failover");
        assert!(
            restored.is_some(),
            "durable queue must survive peer failover"
        );
        assert_eq!(ibd.best_peer_height, 2);
        assert_eq!(ibd.retry_attempts, 0, "new peer gets a fresh retry budget");
        assert_eq!(ibd.last_interruption, None);
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn inconsistent_local_ibd_checkpoint_is_discarded_without_peer_penalty() {
        let dir = fresh_test_dir("ibd-local-checkpoint-discard");
        let node = init_test_node(regtest_node_config(&dir));
        let (local_height, local_hash) = {
            let chain = node.chain.lock().await;
            (chain.tip_height.0, *chain.tip_hash.as_bytes())
        };
        let inconsistent = PersistedIbdState {
            phase: IbdPhase::BlockSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10_394,
            best_peer_height: 10_500,
            headers_height: 10_500,
            blocks_height: 10_226,
            last_progress_height: 10_500,
            checkpoint_tip_hash: local_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: Vec::new(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 10_500,
        };
        {
            let chain = node.chain.lock().await;
            inconsistent
                .save(&chain.store)
                .expect("persist inconsistent local checkpoint");
        }

        let peer_addr = "127.0.0.1:33369".parse().expect("peer addr");
        let (ibd, resumed) =
            initialize_ibd_state(&node.chain, peer_addr, local_height.saturating_add(10))
                .await
                .expect("local checkpoint corruption must not escape as a peer error");

        assert!(resumed.is_none());
        assert_eq!(ibd.start_height, local_height);
        {
            let chain = node.chain.lock().await;
            assert!(PersistedIbdState::load(&chain.store)
                .expect("load after discard")
                .is_none());
        }
        assert_eq!(
            node.peers
                .lock()
                .await
                .pending_ban_score(&peer_addr.to_string()),
            0,
            "local checkpoint errors must never affect peer reputation"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn only_one_ibd_session_can_own_the_persisted_cursor() {
        let sessions = Arc::new(AtomicU64::new(0));
        let state_events = Arc::new(Notify::new());
        let first = IbdActiveGuard::try_new(sessions.clone(), state_events.clone())
            .expect("first session owns cursor");
        assert!(IbdActiveGuard::try_new(sessions.clone(), state_events.clone()).is_none());
        assert_eq!(sessions.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(first);
        let second = IbdActiveGuard::try_new(sessions.clone(), state_events)
            .expect("ownership released on drop");
        assert_eq!(sessions.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(second);
        assert_eq!(sessions.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn persisted_header_resume_rejects_corrupted_continuation() {
        let dir = fresh_test_dir("header-resume-bad");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };

        let header1 = synthetic_known_header(0, Hash256::ZERO, 1);
        let mut header2 = synthetic_known_header(1, Hash256::from_bytes(header_hash(&header1)), 2);
        header2.prev_hash = Hash256::from_bytes([0x99; 32]);
        store_known_header(&chain, &header1).await;

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: vec![
                header1.to_bytes().expect("header1 bytes"),
                header2.to_bytes().expect("header2 bytes"),
            ],
            block_cursor: 0,
            header_cursor: 1,
            header_cursor_height: 1,
        };
        {
            let chain = chain.lock().await;
            snapshot.save(&chain.store).expect("save snapshot");
        }

        let (mut ibd, restored) = initialize_ibd_state(&chain, peer_addr, 1)
            .await
            .expect("initialize");
        let restored = restored.expect("restored snapshot should remain resumable");
        let err = continue_ibd_header_sync(
            &chain,
            peer_addr,
            &mut ibd,
            IbdRoundState {
                pending_blocks: restored.pending_blocks.clone(),
                pending_headers: restored.pending_headers.clone(),
                block_cursor: restored.block_cursor,
                header_cursor: restored.header_cursor,
                header_cursor_height: restored.header_cursor_height,
            },
            ibd_now(),
            super::IbdHeaderValidationMode::Ordinary,
        )
        .await
        .expect_err("corrupted continuation must reject");

        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("prev_hash mismatch")),
            "unexpected error: {err}"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn persisted_header_resume_rejects_malformed_header_bytes() {
        let dir = fresh_test_dir("header-resume-malformed");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");
        let checkpoint_tip_hash = { *chain.lock().await.tip_hash.as_bytes() };

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 1,
            headers_height: 0,
            blocks_height: 0,
            last_progress_height: 0,
            checkpoint_tip_hash,
            retry_attempts: 0,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: vec![vec![0xAA, 0xBB, 0xCC]],
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 1,
        };
        {
            let chain = chain.lock().await;
            snapshot.save(&chain.store).expect("save snapshot");
        }

        let (mut ibd, restored) = initialize_ibd_state(&chain, peer_addr, 1)
            .await
            .expect("initialize");
        let restored = restored.expect("restored snapshot");
        let err = continue_ibd_header_sync(
            &chain,
            peer_addr,
            &mut ibd,
            IbdRoundState {
                pending_blocks: restored.pending_blocks.clone(),
                pending_headers: restored.pending_headers.clone(),
                block_cursor: restored.block_cursor,
                header_cursor: restored.header_cursor,
                header_cursor_height: restored.header_cursor_height,
            },
            ibd_now(),
            super::IbdHeaderValidationMode::Ordinary,
        )
        .await
        .expect_err("malformed resumed header bytes must reject");

        assert!(
            matches!(err, DomError::Malformed(_)),
            "unexpected error: {err}"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn persisted_ibd_snapshot_is_rejected_when_tip_hash_changed_at_same_height() {
        let dir = fresh_test_dir("header-resume-tip-mismatch");
        let chain = open_chain(&dir);
        let peer_addr: SocketAddr = "127.0.0.1:33369".parse().expect("peer addr");

        {
            let mut guard = chain.lock().await;
            guard.tip_height = BlockHeight(5);
            guard.tip_hash = Hash256::from_bytes([0x10; 32]);
        }

        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: peer_addr.to_string(),
            start_height: 0,
            best_peer_height: 7,
            headers_height: 5,
            blocks_height: 5,
            last_progress_height: 5,
            checkpoint_tip_hash: [0x20; 32],
            retry_attempts: 1,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks: Vec::new(),
            pending_headers: vec![
                synthetic_known_header(5, Hash256::from_bytes([0x10; 32]), 6)
                    .to_bytes()
                    .expect("header bytes"),
            ],
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 6,
        };
        {
            let guard = chain.lock().await;
            snapshot.save(&guard.store).expect("save snapshot");
        }

        let (_, restored) = initialize_ibd_state(&chain, peer_addr, 7)
            .await
            .expect("initialize");

        assert!(restored.is_none(), "mismatched tip hash must not resume");

        let persisted = {
            let guard = chain.lock().await;
            PersistedIbdState::load(&guard.store).expect("load snapshot")
        };
        assert!(
            persisted.is_none(),
            "mismatched snapshot must be cleared deterministically"
        );
        crate::test_dir::remove_test_dir(&dir);
    }

    /// TASK 17 — chain-lock-across-await regression guard.
    ///
    /// The block-connect reconciliation path must acquire the chain lock,
    /// extract what it needs, DROP it, and only then await the mempool lock —
    /// it must never hold the chain guard across the mempool `.await`
    /// (`reconcile_mempool_after_connect`, node.rs: the `{ let chain =
    /// chain.lock().await; ... }` block drops the guard before
    /// `mempool.lock().await`).
    ///
    /// This is proven deterministically — no timing sleeps. On a current-thread
    /// runtime the test holds the mempool lock so `reconcile` is forced to park
    /// on it; once parked, the chain lock MUST be free. `try_lock` succeeding is
    /// only possible if `reconcile` already released the chain guard before the
    /// mempool await. Were the guard held across the await, `try_lock` returns
    /// `Err` and the test fails with a clear message rather than deadlocking.
    #[tokio::test(flavor = "current_thread")]
    async fn task17_reconcile_does_not_hold_chain_lock_across_mempool_await() {
        let dir = fresh_test_dir("task17-reconcile-lock-across-await");
        let chain = open_chain(&dir);
        let mempool = Arc::new(Mutex::new(Mempool::new()));

        // Hold the mempool lock so reconcile is forced to park on it.
        let mempool_guard = mempool.lock().await;

        let chain_task = chain.clone();
        let mempool_task = mempool.clone();
        // `BestChain` reaches the unconditional mempool acquisition after the
        // chain guard is dropped, even with no connected transactions.
        let handle = tokio::spawn(async move {
            reconcile_mempool_after_connect(
                &chain_task,
                &mempool_task,
                &ConnectResult::BestChain,
                &[],
            )
            .await
        });

        // Cooperatively schedule the spawned task until it parks on the held
        // mempool lock. On a current-thread runtime each poll runs it to its
        // next await; it must pass the chain acquire+drop first.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        // Proof: while reconcile is parked on the mempool await, the chain lock
        // must be free. This is the assertion that would fail (deterministically)
        // if the chain guard were held across the mempool await.
        {
            let _chain_guard = chain
                .try_lock()
                .expect("chain lock must be released before reconcile awaits the mempool");
        }

        // Let reconcile finish.
        drop(mempool_guard);
        handle
            .await
            .expect("reconcile task join")
            .expect("reconcile must succeed");

        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_during_orphan_future_processing_restarts_cleanly() {
        let dir = fresh_test_dir("runtime-orphan-future-shutdown");
        let node = init_test_node(regtest_node_config(&dir));
        let before = ReplaySnapshot::capture_runtime(&node.chain, &node.mempool, &node.peers)
            .await
            .expect("capture before");

        let future_hash = [0xA1; 32];
        assert!(
            node.future_block_queue
                .defer(DeferredBlock {
                    block_hash: future_hash,
                    block_height: before.chain_tip_height + 1,
                    timestamp: 1_700_100_000,
                    queued_at: Instant::now(),
                    block_bytes: vec![0xA1; 32],
                })
                .await
        );
        {
            let mut orphans = node.orphan_pool.lock().await;
            assert_eq!(
                orphans.insert(OrphanBlock {
                    block_hash: [0xB2; 32],
                    parent_hash: [0xB1; 32],
                    height: before.chain_tip_height + 2,
                    block_bytes: vec![0xB2; 64],
                }),
                crate::orphan_pool::OrphanInsertOutcome::Inserted
            );
        }
        {
            let mut missing = node.missing_blocks.lock().await;
            missing.note_orphan([0xB2; 32], [0xB1; 32], Some(before.chain_tip_height + 1));
            assert_eq!(missing.missing_len(), 1);
        }
        assert_eq!(node.future_block_queue.size().await, 1);
        assert_eq!(node.orphan_pool.lock().await.len(), 1);

        node.request_shutdown().await;
        assert!(node.task_supervisor.is_empty().await);
        drop(node);

        let reopened_store = open_test_store(&dir);
        drop(reopened_store);
        let restarted = init_test_node(regtest_node_config(&dir));
        let after =
            ReplaySnapshot::capture_runtime(&restarted.chain, &restarted.mempool, &restarted.peers)
                .await
                .expect("capture after");

        before
            .assert_equivalent(&after)
            .expect("deep replay snapshot remains valid after runtime-only interruption");
        assert_eq!(
            restarted.future_block_queue.size().await,
            0,
            "future queue is runtime-only and restarts empty"
        );
        assert!(
            restarted.orphan_pool.lock().await.is_empty(),
            "orphan pool is runtime-only and restarts empty"
        );
        assert_eq!(
            restarted.missing_blocks.lock().await.missing_len(),
            0,
            "missing-parent tracker is runtime-only and restarts empty"
        );

        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn interruption_during_mempool_reconciliation_leaves_store_restartable() {
        let dir = fresh_test_dir("runtime-mempool-reconcile-interrupt");
        let node = init_test_node(regtest_node_config(&dir));
        let before = ReplaySnapshot::capture_runtime(&node.chain, &node.mempool, &node.peers)
            .await
            .expect("capture before");

        let mempool_guard = node.mempool.lock().await;
        let chain_task = node.chain.clone();
        let mempool_task = node.mempool.clone();
        let handle = tokio::spawn(async move {
            reconcile_mempool_after_connect(
                &chain_task,
                &mempool_task,
                &ConnectResult::BestChain,
                &[],
            )
            .await
        });

        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        {
            let _chain_guard = node
                .chain
                .try_lock()
                .expect("chain lock must not be held while reconcile awaits mempool");
        }

        handle.abort();
        let join = handle
            .await
            .expect_err("interrupted reconcile task is cancelled");
        assert!(join.is_cancelled(), "reconcile task cancelled explicitly");
        drop(mempool_guard);

        assert_eq!(
            node.mempool.lock().await.len(),
            0,
            "interrupted reconciliation did not silently mutate mempool"
        );
        let after_interrupt =
            ReplaySnapshot::capture_runtime(&node.chain, &node.mempool, &node.peers)
                .await
                .expect("capture after interrupt");
        before
            .assert_equivalent(&after_interrupt)
            .expect("no partial mutation accepted after interrupted reconciliation");

        node.request_shutdown().await;
        drop(node);

        let reopened_store = open_test_store(&dir);
        drop(reopened_store);
        let restarted = init_test_node(regtest_node_config(&dir));
        let after_restart =
            ReplaySnapshot::capture_runtime(&restarted.chain, &restarted.mempool, &restarted.peers)
                .await
                .expect("capture after restart");
        before
            .assert_equivalent(&after_restart)
            .expect("deep replay snapshot remains valid after restart");

        crate::test_dir::remove_test_dir(&dir);
    }

    #[tokio::test]
    async fn live_node_run_observes_shutdown_and_drains_supervisor() {
        let dir = fresh_test_dir("live-node-shutdown");
        let mut config = regtest_node_config(&dir);
        config.p2p_listen_addr = "127.0.0.1:0".into();
        config.rpc_listen_addr = None;
        config.mine = false;
        let node = Arc::new(init_test_node(config));
        let handle = spawn_node_run(node.clone());

        tokio::time::timeout(RUNTIME_TEST_CONVERGENCE_TIMEOUT, async {
            loop {
                if node.task_supervisor.contains(TaskKind::Listener).await
                    && node.task_supervisor.contains(TaskKind::Connector).await
                    && node.task_supervisor.contains(TaskKind::FutureQueue).await
                    && node.task_supervisor.contains(TaskKind::DandelionStem).await
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("live node tasks registered");

        node.request_shutdown().await;
        tokio::time::timeout(RUNTIME_TEST_CONVERGENCE_TIMEOUT, handle)
            .await
            .expect("run returns after shutdown")
            .expect("join")
            .expect("clean shutdown");
        assert!(node.task_supervisor.is_empty().await);
        assert!(node.task_supervisor.failure().await.is_none());

        crate::test_dir::remove_test_dir(&dir);
    }

    #[test]
    fn equal_height_different_tip_requires_fork_resolution() {
        let ours = [0x11; 32];
        let theirs = [0x22; 32];

        assert_eq!(sync_mode_for_peer(100, ours, 101, theirs), Some(false));
        assert_eq!(sync_mode_for_peer(100, ours, 100, theirs), Some(true));
        assert_eq!(sync_mode_for_peer(100, ours, 100, ours), None);
        assert_eq!(sync_mode_for_peer(100, ours, 99, theirs), None);
    }

    #[cfg(feature = "ethereum-checkpoint-verified-poc")]
    #[test]
    fn verified_restart_constructor_reaches_required_floor_before_node_metadata() {
        use alloy::primitives::B256;
        use usdom_ethereum_finality_experiment::checkpoints::{
            unsafe_test_only_verified_checkpoint, CHECKPOINT_RECORD_LENGTH,
        };

        let dir = fresh_test_dir("verified-restart-floor");
        let wire = hex::decode(
            include_str!(
                "../../../labs/usdom-ethereum-finality/fixtures/checkpoint-handoff-v2.hex"
            )
            .trim(),
        )
        .unwrap();
        let source_record: [u8; CHECKPOINT_RECORD_LENGTH] = wire.try_into().unwrap();
        let mut floor = dom_chain::ethereum_checkpoint_poc::decode_test_oracle_v2(&source_record)
            .expect("canonical handoff fixture");
        floor.dom_network_magic = dom_core::NETWORK_MAGIC_REGTEST;
        floor.checkpoint_event_digest =
            dom_chain::ethereum_checkpoint_poc::expected_checkpoint_event_digest(floor);
        let record: [u8; CHECKPOINT_RECORD_LENGTH] =
            dom_chain::ethereum_checkpoint_poc::encode_test_oracle_v2(floor)
                .unwrap()
                .try_into()
                .unwrap();
        let policy_hash = [0x91; 32];
        let checkpoint =
            unsafe_test_only_verified_checkpoint(record, 1_700_000_000, B256::from(policy_hash));
        let error = DomNode::init_with_verified_restart_floor_for_test(
            regtest_node_config(&dir),
            &checkpoint,
            policy_hash,
        )
        .err()
        .expect("an empty database cannot satisfy a nonempty external floor");
        assert!(
            error.to_string().contains("required checkpoint is missing"),
            "{error}"
        );

        let store = open_test_store(&dir);
        assert!(store
            .get_metadata(NOISE_STATIC_KEY_METADATA_KEY)
            .unwrap()
            .is_none());
        drop(store);
        crate::test_dir::remove_test_dir(&dir);
    }
}

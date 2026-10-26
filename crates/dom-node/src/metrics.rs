//! Node metrics for monitoring and observability.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

pub struct Metrics {
    pub chain_height: Arc<AtomicU64>,
    pub total_difficulty: Arc<AtomicU64>,
    pub peer_count: Arc<AtomicU64>,
    pub inbound_peers: Arc<AtomicU64>,
    pub outbound_peers: Arc<AtomicU64>,
    pub blocks_mined: Arc<AtomicU64>,
    pub mining_active: Arc<AtomicU64>,
    pub mining_paused_for_sync: Arc<AtomicU64>,
    pub mining_template_height: Arc<AtomicU64>,
    pub best_known_peer_height: Arc<AtomicU64>,
    pub stale_templates_cancelled: Arc<AtomicU64>,
    pub mining_hashes: Arc<AtomicU64>,
    pub mempool_size: Arc<AtomicU64>,
    pub txs_received: Arc<AtomicU64>,
    pub txs_relayed: Arc<AtomicU64>,
    pub block_validation_time_ms: Arc<AtomicU64>,
    pub ibd_progress_percent: Arc<AtomicU64>,

    // Time discipline metrics (Doc 4.5)
    /// Total blocks rejected due to timestamp violations.
    pub blocks_rejected_timestamp: Arc<AtomicU64>,
    /// Current local clock drift in seconds (can be negative).
    pub local_clock_drift_seconds: Arc<AtomicI64>,
    /// Number of connected peers with drift above threshold.
    pub peers_with_high_drift: Arc<AtomicU64>,
    /// Current size of the future block queue.
    pub future_block_queue_size: Arc<AtomicU64>,
    /// Exact native-v4 packages retained for future-timestamp replay.
    pub native_usdom_v4_future_packages: Arc<AtomicU64>,
    /// Exact native-v4 future-package bytes retained in memory.
    pub native_usdom_v4_future_bytes: Arc<AtomicU64>,
    /// Exact native-v4 packages retained while their parent is missing.
    pub native_usdom_v4_orphan_packages: Arc<AtomicU64>,
    /// Exact native-v4 orphan-package bytes retained in memory.
    pub native_usdom_v4_orphan_bytes: Arc<AtomicU64>,
    /// Native future-package admissions rejected by a local queue invariant.
    pub native_usdom_v4_future_admission_rejected: Arc<AtomicU64>,
    /// Native future packages expired before becoming replayable.
    pub native_usdom_v4_future_expired: Arc<AtomicU64>,
    /// Native future admissions that evicted lower-priority retained packages.
    pub native_usdom_v4_future_evictions: Arc<AtomicU64>,
    /// Native orphan admissions that evicted at least one oldest package.
    pub native_usdom_v4_orphan_evictions: Arc<AtomicU64>,
    /// Native orphan admissions rejected by the byte or per-parent bound.
    pub native_usdom_v4_orphan_admission_rejected: Arc<AtomicU64>,
    /// Canonical proof envelopes retained for local native-v4 mining.
    pub native_usdom_v4_mining_candidates: Arc<AtomicU64>,
    /// Exact canonical bytes retained by the native-v4 mining pool.
    pub native_usdom_v4_mining_candidate_bytes: Arc<AtomicU64>,
    /// Mining-envelope admissions rejected by framing, proof or pool policy.
    pub native_usdom_v4_mining_admission_rejected: Arc<AtomicU64>,
    /// Previously admitted envelopes dropped after becoming stale or invalid.
    pub native_usdom_v4_mining_stale_dropped: Arc<AtomicU64>,
    /// Total duplicate relayed blocks suppressed without rebroadcast.
    pub suppressed_duplicate_block_relays: Arc<AtomicU64>,
    /// Total malformed relayed block payloads or block bodies rejected.
    pub malformed_block_relays: Arc<AtomicU64>,
    /// Total times a peer exceeded duplicate block relay quota.
    pub duplicate_block_relay_quota_exceeded: Arc<AtomicU64>,
    /// Total relayed txs already in the mempool, skipped before chain lock /
    /// validation (FABLE5-001 replay short-circuit).
    pub suppressed_duplicate_tx_relays: Arc<AtomicU64>,

    // Peer autodiscovery metrics (spec A5). Deliberately unlabeled per peer:
    // R-A5.1 — a small network today is a series explosion tomorrow.
    /// Port this node advertises in its Hello (0 = declared unreachable).
    pub advertised_port: Arc<AtomicU64>,
    /// PEX entries confirmed by a successful outbound dial.
    pub pex_confirmed_peers: Arc<AtomicU64>,
    /// PEX entries not yet confirmed (dial candidates, never gossiped).
    pub pex_unconfirmed_peers: Arc<AtomicU64>,
    /// Inbound peers that announced no usable listening port (R-A2.2).
    pub pex_unreachable_peers: Arc<AtomicU64>,
    /// Dial-back reachability probes attempted (A4).
    pub dialback_attempts: Arc<AtomicU64>,
    /// Dial-back reachability probes that connected (A4).
    pub dialback_success: Arc<AtomicU64>,
    /// Port-mapping outcome (A3): 0 none, 1 upnp, 2 natpmp, 3 cgnat_detected.
    /// Rendered as the labeled one-hot gauge `dom_portmap_status` — the
    /// number that decides whether A7 (hole punching) is worth building.
    pub portmap_status_code: Arc<AtomicU64>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            chain_height: Arc::new(AtomicU64::new(0)),
            total_difficulty: Arc::new(AtomicU64::new(0)),
            peer_count: Arc::new(AtomicU64::new(0)),
            inbound_peers: Arc::new(AtomicU64::new(0)),
            outbound_peers: Arc::new(AtomicU64::new(0)),
            blocks_mined: Arc::new(AtomicU64::new(0)),
            mining_active: Arc::new(AtomicU64::new(0)),
            mining_paused_for_sync: Arc::new(AtomicU64::new(0)),
            mining_template_height: Arc::new(AtomicU64::new(0)),
            best_known_peer_height: Arc::new(AtomicU64::new(0)),
            stale_templates_cancelled: Arc::new(AtomicU64::new(0)),
            mining_hashes: Arc::new(AtomicU64::new(0)),
            mempool_size: Arc::new(AtomicU64::new(0)),
            txs_received: Arc::new(AtomicU64::new(0)),
            txs_relayed: Arc::new(AtomicU64::new(0)),
            block_validation_time_ms: Arc::new(AtomicU64::new(0)),
            ibd_progress_percent: Arc::new(AtomicU64::new(0)),
            blocks_rejected_timestamp: Arc::new(AtomicU64::new(0)),
            local_clock_drift_seconds: Arc::new(AtomicI64::new(0)),
            peers_with_high_drift: Arc::new(AtomicU64::new(0)),
            future_block_queue_size: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_future_packages: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_future_bytes: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_orphan_packages: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_orphan_bytes: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_future_admission_rejected: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_future_expired: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_future_evictions: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_orphan_evictions: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_orphan_admission_rejected: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_mining_candidates: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_mining_candidate_bytes: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_mining_admission_rejected: Arc::new(AtomicU64::new(0)),
            native_usdom_v4_mining_stale_dropped: Arc::new(AtomicU64::new(0)),
            suppressed_duplicate_block_relays: Arc::new(AtomicU64::new(0)),
            malformed_block_relays: Arc::new(AtomicU64::new(0)),
            duplicate_block_relay_quota_exceeded: Arc::new(AtomicU64::new(0)),
            suppressed_duplicate_tx_relays: Arc::new(AtomicU64::new(0)),
            advertised_port: Arc::new(AtomicU64::new(0)),
            pex_confirmed_peers: Arc::new(AtomicU64::new(0)),
            pex_unconfirmed_peers: Arc::new(AtomicU64::new(0)),
            pex_unreachable_peers: Arc::new(AtomicU64::new(0)),
            dialback_attempts: Arc::new(AtomicU64::new(0)),
            dialback_success: Arc::new(AtomicU64::new(0)),
            portmap_status_code: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn export_prometheus(&self) -> String {
        let mut out = String::new();
        let metrics_list = [
            (
                "dom_chain_height",
                "Current blockchain height",
                "gauge",
                &self.chain_height,
            ),
            (
                "dom_total_difficulty",
                "Total accumulated difficulty",
                "gauge",
                &self.total_difficulty,
            ),
            (
                "dom_peer_count",
                "Number of connected peers",
                "gauge",
                &self.peer_count,
            ),
            (
                "dom_inbound_peers",
                "Inbound peer connections",
                "gauge",
                &self.inbound_peers,
            ),
            (
                "dom_outbound_peers",
                "Outbound peer connections",
                "gauge",
                &self.outbound_peers,
            ),
            (
                "dom_advertised_port",
                "Port this node advertises for inbound connections (0 = unreachable)",
                "gauge",
                &self.advertised_port,
            ),
            (
                "dom_pex_confirmed_peers",
                "PEX entries confirmed by a successful outbound dial",
                "gauge",
                &self.pex_confirmed_peers,
            ),
            (
                "dom_pex_unconfirmed_peers",
                "PEX dial candidates not yet confirmed",
                "gauge",
                &self.pex_unconfirmed_peers,
            ),
            (
                "dom_pex_unreachable_peers",
                "Inbound peers that announced no usable listening port",
                "gauge",
                &self.pex_unreachable_peers,
            ),
            (
                "dom_dialback_attempts_total",
                "Dial-back reachability probes attempted",
                "counter",
                &self.dialback_attempts,
            ),
            (
                "dom_dialback_success_total",
                "Dial-back reachability probes that connected",
                "counter",
                &self.dialback_success,
            ),
            (
                "dom_blocks_mined",
                "Total blocks mined",
                "counter",
                &self.blocks_mined,
            ),
            (
                "dom_mining_active",
                "Whether RandomX mining workers are active",
                "gauge",
                &self.mining_active,
            ),
            (
                "dom_mining_paused_for_sync",
                "Whether mining is paused because the node is synchronizing",
                "gauge",
                &self.mining_paused_for_sync,
            ),
            (
                "dom_mining_template_height",
                "Height of the template currently being mined, or zero",
                "gauge",
                &self.mining_template_height,
            ),
            (
                "dom_best_known_peer_height",
                "Highest height announced by a currently connected valid peer",
                "gauge",
                &self.best_known_peer_height,
            ),
            (
                "dom_stale_templates_cancelled_total",
                "Mining templates cancelled after their parent became stale",
                "counter",
                &self.stale_templates_cancelled,
            ),
            (
                "dom_mining_hashes_total",
                "Nonce hashes attempted by local mining workers",
                "counter",
                &self.mining_hashes,
            ),
            // Do not export mempool cardinality or transaction receive/relay
            // counters. The metrics socket is loopback-only but unauthenticated;
            // exposing these lets another local account reconstruct the same
            // propagation-front timing that `/mempool` and `/tx/:hash` keep
            // behind the RPC bearer for Dandelion++ privacy. The atomics remain
            // available to internal node policy and authenticated projections.
            (
                "dom_block_validation_time_ms",
                "Block validation time",
                "gauge",
                &self.block_validation_time_ms,
            ),
            (
                "dom_ibd_progress_percent",
                "IBD progress",
                "gauge",
                &self.ibd_progress_percent,
            ),
            (
                "dom_blocks_rejected_timestamp_total",
                "Blocks rejected by timestamp",
                "counter",
                &self.blocks_rejected_timestamp,
            ),
            (
                "dom_peers_with_high_drift",
                "Peers with high clock drift",
                "gauge",
                &self.peers_with_high_drift,
            ),
            (
                "dom_future_block_queue_size",
                "Future block queue size",
                "gauge",
                &self.future_block_queue_size,
            ),
            (
                "dom_native_usdom_v4_future_packages",
                "Exact native USDOM v4 packages retained for future-timestamp replay",
                "gauge",
                &self.native_usdom_v4_future_packages,
            ),
            (
                "dom_native_usdom_v4_future_bytes",
                "Exact native USDOM v4 future-package bytes retained in memory",
                "gauge",
                &self.native_usdom_v4_future_bytes,
            ),
            (
                "dom_native_usdom_v4_orphan_packages",
                "Exact native USDOM v4 packages retained for missing-parent replay",
                "gauge",
                &self.native_usdom_v4_orphan_packages,
            ),
            (
                "dom_native_usdom_v4_orphan_bytes",
                "Exact native USDOM v4 orphan-package bytes retained in memory",
                "gauge",
                &self.native_usdom_v4_orphan_bytes,
            ),
            (
                "dom_native_usdom_v4_future_admission_rejected_total",
                "Native USDOM v4 future-package admissions rejected by local queue bounds",
                "counter",
                &self.native_usdom_v4_future_admission_rejected,
            ),
            (
                "dom_native_usdom_v4_future_expired_total",
                "Native USDOM v4 future packages expired before replay",
                "counter",
                &self.native_usdom_v4_future_expired,
            ),
            (
                "dom_native_usdom_v4_future_evictions_total",
                "Native USDOM v4 future admissions that evicted lower-priority packages",
                "counter",
                &self.native_usdom_v4_future_evictions,
            ),
            (
                "dom_native_usdom_v4_orphan_evictions_total",
                "Native USDOM v4 orphan admissions that evicted oldest retained work",
                "counter",
                &self.native_usdom_v4_orphan_evictions,
            ),
            (
                "dom_native_usdom_v4_orphan_admission_rejected_total",
                "Native USDOM v4 orphan admissions rejected by local queue bounds",
                "counter",
                &self.native_usdom_v4_orphan_admission_rejected,
            ),
            // Pending native USDOM mining envelopes include private transfers,
            // burns and issuance. Exact queue count/bytes would disclose local
            // private-activity timing through an unauthenticated surface.
            (
                "dom_native_usdom_v4_mining_admission_rejected_total",
                "Native USDOM v4 mining envelopes rejected by framing proof or pool policy",
                "counter",
                &self.native_usdom_v4_mining_admission_rejected,
            ),
            (
                "dom_native_usdom_v4_mining_stale_dropped_total",
                "Previously admitted native USDOM v4 mining envelopes dropped as stale",
                "counter",
                &self.native_usdom_v4_mining_stale_dropped,
            ),
            (
                "dom_suppressed_duplicate_block_relays_total",
                "Duplicate relayed blocks suppressed without rebroadcast",
                "counter",
                &self.suppressed_duplicate_block_relays,
            ),
            (
                "dom_malformed_block_relays_total",
                "Malformed relayed block payloads or block bodies rejected",
                "counter",
                &self.malformed_block_relays,
            ),
            (
                "dom_duplicate_block_relay_quota_exceeded_total",
                "Times a peer exceeded duplicate block relay quota",
                "counter",
                &self.duplicate_block_relay_quota_exceeded,
            ),
            (
                "dom_suppressed_duplicate_tx_relays_total",
                "Relayed txs already in mempool, skipped before validation",
                "counter",
                &self.suppressed_duplicate_tx_relays,
            ),
        ];

        // Export drift separately (AtomicI64 requires different load)
        out.push_str(
            "# HELP dom_clock_drift_seconds Local clock drift in seconds (can be negative)\n",
        );
        out.push_str("# TYPE dom_clock_drift_seconds gauge\n");
        out.push_str(&format!(
            "dom_clock_drift_seconds {}\n\n",
            self.local_clock_drift_seconds.load(Ordering::Relaxed)
        ));

        // dom_portmap_status (A3/A5): labeled one-hot, rendered by hand
        // because the shared loop below is for unlabeled series. The four
        // method labels are a fixed set — never per-peer (R-A5.1).
        let code = self.portmap_status_code.load(Ordering::Relaxed);
        out.push_str("# HELP dom_portmap_status Port-mapping outcome by method\n");
        out.push_str("# TYPE dom_portmap_status gauge\n");
        for (label, value) in [
            ("none", 0u64),
            ("upnp", 1),
            ("natpmp", 2),
            ("cgnat_detected", 3),
        ] {
            out.push_str(&format!(
                "dom_portmap_status{{method=\"{label}\"}} {}\n",
                u64::from(code == value)
            ));
        }
        out.push('\n');

        for (name, help, kind, counter) in metrics_list.iter() {
            out.push_str(&format!("# HELP {} {}\n", name, help));
            out.push_str(&format!("# TYPE {} {}\n", name, kind));
            out.push_str(&format!("{} {}\n\n", name, counter.load(Ordering::Relaxed)));
        }
        out
    }

    pub fn health_check(&self) -> HealthStatus {
        let height = self.chain_height.load(Ordering::Relaxed);
        let peers = self.peer_count.load(Ordering::Relaxed);
        let ibd_progress = self.ibd_progress_percent.load(Ordering::Relaxed);
        let healthy = height > 0 && peers > 0 && ibd_progress >= 99;
        HealthStatus {
            status: if healthy { "healthy" } else { "syncing" }.to_string(),
            height,
            peers,
            syncing: ibd_progress < 100,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub status: String,
    pub height: u64,
    pub peers: u64,
    pub syncing: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_zero() {
        let m = Metrics::new();
        assert_eq!(m.chain_height.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn prometheus_export_works() {
        let m = Metrics::new();
        m.chain_height.store(100, Ordering::Relaxed);
        m.peer_count.store(5, Ordering::Relaxed);
        m.suppressed_duplicate_block_relays
            .store(2, Ordering::Relaxed);
        m.native_usdom_v4_future_packages
            .store(3, Ordering::Relaxed);
        m.native_usdom_v4_orphan_bytes
            .store(4096, Ordering::Relaxed);
        m.native_usdom_v4_orphan_evictions
            .store(1, Ordering::Relaxed);
        m.native_usdom_v4_future_evictions
            .store(4, Ordering::Relaxed);
        m.native_usdom_v4_mining_candidates
            .store(2, Ordering::Relaxed);
        m.native_usdom_v4_mining_candidate_bytes
            .store(8192, Ordering::Relaxed);
        m.native_usdom_v4_mining_admission_rejected
            .store(5, Ordering::Relaxed);
        m.native_usdom_v4_mining_stale_dropped
            .store(1, Ordering::Relaxed);
        let output = m.export_prometheus();
        assert!(output.contains("dom_chain_height 100"));
        assert!(output.contains("dom_peer_count 5"));
        assert!(output.contains("dom_mining_paused_for_sync 0"));
        assert!(output.contains("dom_best_known_peer_height 0"));
        assert!(output.contains("dom_suppressed_duplicate_block_relays_total 2"));
        assert!(output.contains("dom_native_usdom_v4_future_packages 3"));
        assert!(output.contains("dom_native_usdom_v4_orphan_bytes 4096"));
        assert!(output.contains("dom_native_usdom_v4_orphan_evictions_total 1"));
        assert!(output.contains("dom_native_usdom_v4_future_evictions_total 4"));
        assert!(!output.contains("dom_mempool_size"));
        assert!(!output.contains("dom_txs_received"));
        assert!(!output.contains("dom_txs_relayed"));
        assert!(!output.contains("dom_native_usdom_v4_mining_candidates"));
        assert!(!output.contains("dom_native_usdom_v4_mining_candidate_bytes"));
        assert!(output.contains("dom_native_usdom_v4_mining_admission_rejected_total 5"));
        assert!(output.contains("dom_native_usdom_v4_mining_stale_dropped_total 1"));
    }

    #[test]
    fn health_check_healthy() {
        let m = Metrics::new();
        m.chain_height.store(100, Ordering::Relaxed);
        m.peer_count.store(3, Ordering::Relaxed);
        m.ibd_progress_percent.store(100, Ordering::Relaxed);
        assert_eq!(m.health_check().status, "healthy");
    }

    #[test]
    fn health_check_syncing() {
        let m = Metrics::new();
        m.chain_height.store(50, Ordering::Relaxed);
        m.ibd_progress_percent.store(50, Ordering::Relaxed);
        assert!(m.health_check().syncing);
    }
}

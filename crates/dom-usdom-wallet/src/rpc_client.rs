//! Strict loopback client for the authenticated native USDOM RPC boundary.

use std::{
    fs::File,
    io::{Read, Take},
    net::IpAddr,
    path::Path,
    time::Duration,
};

use dom_consensus::{bind_usdom_batch_commitment, BlockHeader};
use dom_core::{
    Hash256, BLOCK_VERSION_V4, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_usdom_privacy::Scalar;
use dom_usdom_state::{
    authenticate_transition_projection_batch, BridgeIdentity, EthereumDepositOccurrence,
    TransitionCommitmentProjection, MAX_PRIVATE_BURN_PAYLOAD_BYTES,
    MAX_TRANSITION_PROJECTION_BYTES,
};
use reqwest::{
    blocking::{Client, Response},
    redirect::Policy,
    Url,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use usdom_ethereum_finality_experiment::checkpoints::VerifiedCheckpoint;
use zeroize::Zeroizing;

use super::{
    CanonicalWalletBlock, DurablePendingBurnPermit, DurablePendingTransferPermit, WalletError,
    WalletSecrets, WalletState, WalletTransitionObservation,
};

const RPC_SCHEMA_VERSION: u16 = 1;
const MAX_RPC_RESPONSE_BYTES: u64 = 256 * 1024;
const MAX_HISTORY_RPC_RESPONSE_BYTES: u64 = 3 * 1024 * 1024;
const MAX_AUTHENTICATED_HISTORY_RESCAN_BLOCKS: u64 = 65_536;
const MAX_AUTHENTICATED_HISTORY_RESCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOKEN_FILE_BYTES: u64 = 1024;

/// Failure before, during, or after authenticated node communication.
#[derive(Debug, Error)]
pub enum UsdomRpcClientError {
    /// URL, token, request, or response violated the fixed client policy.
    #[error("invalid native USDOM RPC data: {0}")]
    Invalid(String),
    /// Authenticated HTTP transport failed.
    #[error("native USDOM RPC transport failed: {0}")]
    Transport(String),
    /// The node rejected the request with a bounded response body.
    #[error("native USDOM RPC rejected the request: {0}")]
    Rejected(String),
    /// The requested pending payload does not exist in this wallet state.
    #[error("unknown pending native USDOM transfer")]
    UnknownPendingTransfer,
    /// The requested burn is absent or lacks durable submission authority.
    #[error("unknown pending native USDOM burn")]
    UnknownPendingBurn,
}

/// Failure while fetching authenticated history or atomically recovering one
/// historical Ethereum deposit into a wallet projection.
#[derive(Debug, Error)]
pub enum RemoteHistoricalDepositRecoveryError {
    /// The strict loopback RPC exchange or response authentication failed.
    #[error(transparent)]
    Rpc(#[from] UsdomRpcClientError),
    /// Applying history or deriving the exact deposit-owned note failed.
    #[error(transparent)]
    Wallet(#[from] WalletError),
}

/// Node acknowledgement for one exact pending transfer payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateTransferSubmission {
    /// Exact wallet payload identifier.
    pub transition_id: Hash256,
    /// Exact single-entry candidate envelope identifier.
    pub candidate_id: Hash256,
}

/// Node acknowledgement for one exact pending private-burn payload.
pub type PrivateBurnSubmission = PrivateTransferSubmission;

/// Node acknowledgement for one exact candidate-V2 proof/witness pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2CandidateSubmission {
    /// Domain-separated identifier of both canonical byte strings.
    pub candidate_id: Hash256,
}

/// Chain-pinned request for one exact pending transfer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateTransferScanRequest {
    /// Expected DOM network magic.
    pub network_magic: u32,
    /// Expected consensus chain identifier.
    pub chain_id: Hash256,
    /// Exact randomized transfer payload identifier.
    pub transition_id: Hash256,
    /// First canonical height to inspect.
    pub start_height: u64,
    /// Number of canonical blocks to inspect, in `1..=256`.
    pub max_blocks: u64,
    /// Canonical block immediately before `start_height`.
    pub anchor: Option<(u64, Hash256)>,
}

/// Chain-pinned request for one exact pending private-burn identifier.
pub type PrivateBurnScanRequest = PrivateTransferScanRequest;

/// Exact canonical location reported for one payload identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalPrivateTransferInclusion {
    /// Canonical DOM height.
    pub height: u64,
    /// Canonical DOM block identifier.
    pub block_hash: Hash256,
    /// Zero-based proof-envelope entry index.
    pub transition_index: u32,
}

/// Exact canonical location of one private-burn payload.
pub type CanonicalPrivateBurnInclusion = CanonicalPrivateTransferInclusion;

/// Strictly validated page returned by the authenticated canonical lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateTransferScanPage {
    /// Canonical tip observed with the scan.
    pub tip: (u64, Hash256),
    /// Last height examined, or `None` when the requested range was empty.
    pub scanned_to: Option<u64>,
    /// Exact inclusion if found.
    pub inclusion: Option<CanonicalPrivateTransferInclusion>,
    /// Next height and required anchor when another page remains.
    pub continuation: Option<(u64, u64, Hash256)>,
}

/// Strictly validated canonical lookup page for a private burn.
pub type PrivateBurnScanPage = PrivateTransferScanPage;

/// Exact block and native-state root immediately preceding a history page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedHistoryAnchor {
    /// Canonical DOM height.
    pub height: u64,
    /// Canonical DOM block identifier.
    pub block_hash: Hash256,
    /// Native USDOM state root after this block.
    pub state_root: Hash256,
}

/// Request pinned to one operator-trusted DOM tip and native USDOM domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedHistoryRequest {
    /// Expected DOM network magic.
    pub network_magic: u32,
    /// Expected consensus chain identifier.
    pub chain_id: Hash256,
    /// Exact native USDOM domain.
    pub dom_domain: Hash256,
    /// Operator-pinned finalized DOM tip.
    pub trusted_tip: (u64, Hash256),
    /// First canonical native history height.
    pub start_height: u64,
    /// Requested page size in `1..=16`.
    pub max_blocks: u64,
    /// Exact preceding block and native state.
    pub anchor: Option<AuthenticatedHistoryAnchor>,
}

/// Complete native USDOM history segment linked through its terminal trusted tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedHistoryScan {
    /// Operator-pinned terminal tip reached by the returned sequence.
    pub trusted_tip: (u64, Hash256),
    /// Contiguous canonical wallet blocks safe to apply in order.
    pub blocks: Vec<CanonicalWalletBlock>,
    /// Native USDOM state root after the terminal trusted block.
    pub terminal_state_root: Hash256,
}

/// Ethereum-finalized DOM checkpoint identity accepted by the wallet.
///
/// Fields are private so callers cannot manufacture finality from decoded
/// bytes. Construction requires the opaque output of the Ethereum checkpoint
/// verifier and matches its immutable network, bridge domain and trust policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedCheckpointHistoryAnchor {
    trusted_tip: (u64, Hash256),
    state_root: Hash256,
    checkpoint_event_digest: Hash256,
}

impl VerifiedCheckpointHistoryAnchor {
    /// Validate one opaque Ethereum checkpoint against the exact immutable
    /// wallet finality policy and return a non-forgeable history anchor.
    pub fn from_verified_checkpoint(
        checkpoint: &VerifiedCheckpoint,
        expected_network_magic: u32,
        expected_dom_domain: Hash256,
        expected_checkpoint_policy_hash: Hash256,
    ) -> Result<Self, UsdomRpcClientError> {
        verified_checkpoint_history_anchor(
            checkpoint,
            expected_network_magic,
            expected_dom_domain,
            expected_checkpoint_policy_hash,
        )
    }

    /// Finalized DOM height and block identifier authenticated by Ethereum.
    pub fn trusted_tip(self) -> (u64, Hash256) {
        self.trusted_tip
    }

    /// Native USDOM state root committed by the finalized checkpoint event.
    pub fn state_root(self) -> Hash256 {
        self.state_root
    }

    /// Digest of the exact authenticated checkpoint event.
    pub fn checkpoint_event_digest(self) -> Hash256 {
        self.checkpoint_event_digest
    }
}

/// Complete header- and state-authenticated history ending at an independently
/// verified Ethereum-finalized DOM checkpoint.
///
/// This type cannot be constructed by RPC data alone. Its private fields are
/// populated only after the terminal block and state root match the opaque
/// [`VerifiedCheckpoint`] capability supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpointHistoryScan {
    anchor: VerifiedCheckpointHistoryAnchor,
    blocks: Vec<CanonicalWalletBlock>,
}

impl VerifiedCheckpointHistoryScan {
    /// Exact Ethereum-finalized checkpoint identity.
    pub fn anchor(&self) -> VerifiedCheckpointHistoryAnchor {
        self.anchor
    }

    /// Authenticated canonical wallet blocks ending at the checkpoint.
    pub fn blocks(&self) -> &[CanonicalWalletBlock] {
        &self.blocks
    }

    /// Consume the finality capability and return its authenticated history.
    pub fn into_blocks(self) -> Vec<CanonicalWalletBlock> {
        self.blocks
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedHistoryPage {
    trusted_tip: (u64, Hash256),
    blocks: Vec<CanonicalWalletBlock>,
    continuation: Option<(u64, AuthenticatedHistoryAnchor)>,
    response_bytes: usize,
    terminal_state_root: Hash256,
}

/// Authenticated client restricted to a literal loopback HTTP endpoint.
pub struct UsdomRpcClient {
    base_url: Url,
    bearer_token: Zeroizing<String>,
    client: Client,
}

impl UsdomRpcClient {
    /// Construct from a token already obtained through an external secret
    /// authority. Only literal loopback IPs, HTTP, and a root base path pass.
    pub fn new(base_url: &str, bearer_token: String) -> Result<Self, UsdomRpcClientError> {
        Self::with_token(base_url, Zeroizing::new(bearer_token))
    }

    fn with_token(
        base_url: &str,
        bearer_token: Zeroizing<String>,
    ) -> Result<Self, UsdomRpcClientError> {
        let base_url = validate_base_url(base_url)?;
        validate_token(&bearer_token)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .user_agent("dom-usdom-wallet/0.2")
            .build()
            .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
        Ok(Self {
            base_url,
            bearer_token,
            client,
        })
    }

    /// Load an owner-only token file and construct the strict loopback client.
    pub fn from_token_file(base_url: &str, token_path: &Path) -> Result<Self, UsdomRpcClientError> {
        let token = load_owner_only_token(token_path)?;
        Self::with_token(base_url, token)
    }

    /// Submit exact bytes retained by a pending wallet entry only after the
    /// snapshot/authority protocol issued its unforgeable durable permit.
    pub fn submit_pending_private_transfer(
        &self,
        state: &WalletState,
        permit: &DurablePendingTransferPermit,
    ) -> Result<PrivateTransferSubmission, UsdomRpcClientError> {
        let transition_id = permit.transition_id();
        let payload = state
            .authorized_private_transfer_payload(transition_id)
            .ok_or(UsdomRpcClientError::UnknownPendingTransfer)?;
        let endpoint = self.endpoint("usdom/v4/transfer/submit/v1")?;
        let request = SubmitRequest {
            schema_version: RPC_SCHEMA_VERSION,
            payload_hex: hex::encode(payload),
        };
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .json(&request)
            .send()
            .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
        let body = read_response(response)?;
        parse_submission_response(&body, transition_id)
    }

    /// Submit exact pending burn bytes only after rollback-resistant wallet
    /// persistence issued the corresponding durable capability.
    pub fn submit_pending_private_burn(
        &self,
        state: &WalletState,
        permit: &DurablePendingBurnPermit,
    ) -> Result<PrivateBurnSubmission, UsdomRpcClientError> {
        let transition_id = permit.transition_id();
        let payload = state
            .authorized_private_burn_payload(transition_id)
            .ok_or(UsdomRpcClientError::UnknownPendingBurn)?;
        let endpoint = self.endpoint("usdom/v4/burn/submit/v1")?;
        let request = SubmitRequest {
            schema_version: RPC_SCHEMA_VERSION,
            payload_hex: hex::encode(payload),
        };
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .json(&request)
            .send()
            .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
        let body = read_response(response)?;
        parse_submission_response(&body, transition_id)
    }

    /// Submit one exact candidate-V2 proof envelope and its ordered execution
    /// witnesses through the authenticated canonical binary RPC. The node
    /// independently parses and verifies both parts before retaining them.
    pub fn submit_v2_candidate(
        &self,
        envelope: &[u8],
        witnesses: &[u8],
    ) -> Result<V2CandidateSubmission, UsdomRpcClientError> {
        let expected_candidate_id = Hash256::from_bytes(
            dom_usdom_rpc_protocol::candidate_id_v1(envelope, witnesses)
                .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?,
        );
        let request = dom_usdom_rpc_protocol::encode_candidate_submission_v1(envelope, witnesses)
            .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
        let endpoint = self.endpoint("usdom/v2/candidate/submit/v1")?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .header("content-type", "application/octet-stream")
            .body(request)
            .send()
            .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
        let body = read_response(response)?;
        parse_v2_candidate_submission_response(&body, expected_candidate_id)
    }

    /// Query a bounded canonical page for one exact payload identifier.
    pub fn scan_private_transfer(
        &self,
        request: PrivateTransferScanRequest,
    ) -> Result<PrivateTransferScanPage, UsdomRpcClientError> {
        validate_scan_request(request)?;
        let endpoint = self.endpoint("usdom/v4/transfer/scan/v1")?;
        let body = ScanRequestBody {
            schema_version: RPC_SCHEMA_VERSION,
            expected_network_magic: request.network_magic,
            expected_chain_id: hex::encode(request.chain_id.as_bytes()),
            transition_id: hex::encode(request.transition_id.as_bytes()),
            start_height: request.start_height,
            max_blocks: request.max_blocks,
            anchor: request.anchor.map(|(height, hash)| ScanAnchorBody {
                height,
                block_hash: hex::encode(hash.as_bytes()),
            }),
        };
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .json(&body)
            .send()
            .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
        let response = read_response(response)?;
        parse_scan_response(&response, request)
    }

    /// Query a bounded canonical page for one exact private-burn payload.
    pub fn scan_private_burn(
        &self,
        request: PrivateBurnScanRequest,
    ) -> Result<PrivateBurnScanPage, UsdomRpcClientError> {
        validate_scan_request(request)?;
        let endpoint = self.endpoint("usdom/v4/burn/scan/v1")?;
        let body = ScanRequestBody {
            schema_version: RPC_SCHEMA_VERSION,
            expected_network_magic: request.network_magic,
            expected_chain_id: hex::encode(request.chain_id.as_bytes()),
            transition_id: hex::encode(request.transition_id.as_bytes()),
            start_height: request.start_height,
            max_blocks: request.max_blocks,
            anchor: request.anchor.map(|(height, hash)| ScanAnchorBody {
                height,
                block_hash: hex::encode(hash.as_bytes()),
            }),
        };
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .json(&body)
            .send()
            .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
        let response = read_response(response)?;
        parse_scan_response(&response, request)
    }

    /// Fetch every page through the exact trusted tip and release blocks only
    /// after the complete forward ancestry has been authenticated.
    pub fn scan_authenticated_history_to_trusted_tip(
        &self,
        request: AuthenticatedHistoryRequest,
    ) -> Result<AuthenticatedHistoryScan, UsdomRpcClientError> {
        self.scan_authenticated_history(request, false)
    }

    fn scan_authenticated_history(
        &self,
        mut request: AuthenticatedHistoryRequest,
        require_checkpoint_finality: bool,
    ) -> Result<AuthenticatedHistoryScan, UsdomRpcClientError> {
        validate_history_request(request)?;
        let total = request
            .trusted_tip
            .0
            .checked_sub(request.start_height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or_else(|| UsdomRpcClientError::Invalid("history rescan range overflow".into()))?;
        if total > MAX_AUTHENTICATED_HISTORY_RESCAN_BLOCKS {
            return Err(UsdomRpcClientError::Invalid(format!(
                "history rescan exceeds {MAX_AUTHENTICATED_HISTORY_RESCAN_BLOCKS} blocks"
            )));
        }
        let trusted_tip = request.trusted_tip;
        let mut blocks = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
        let mut response_bytes = 0usize;
        let terminal_state_root;
        loop {
            let page =
                self.scan_authenticated_history_page(request, require_checkpoint_finality)?;
            if page.trusted_tip != trusted_tip || page.blocks.is_empty() {
                return Err(UsdomRpcClientError::Invalid(
                    "authenticated history page made no trusted progress".into(),
                ));
            }
            response_bytes = checked_history_rescan_bytes(response_bytes, page.response_bytes)?;
            let page_terminal_state_root = page.terminal_state_root;
            blocks.extend(page.blocks);
            let Some((next_height, anchor)) = page.continuation else {
                terminal_state_root = page_terminal_state_root;
                break;
            };
            request.start_height = next_height;
            request.anchor = Some(anchor);
        }
        if blocks.len() != usize::try_from(total).unwrap_or(usize::MAX)
            || blocks.last().map(|block| (block.height, block.identifier)) != Some(trusted_tip)
        {
            return Err(UsdomRpcClientError::Invalid(
                "complete authenticated history did not reach the exact trusted tip".into(),
            ));
        }
        Ok(AuthenticatedHistoryScan {
            trusted_tip,
            blocks,
            terminal_state_root,
        })
    }

    /// Fetch and authenticate history ending at one Ethereum-finalized DOM
    /// checkpoint. RPC data cannot create the finality authority: the caller
    /// must supply the opaque checkpoint verifier output and the exact expected
    /// immutable policy hash.
    pub fn scan_authenticated_history_to_verified_checkpoint(
        &self,
        request: AuthenticatedHistoryRequest,
        anchor: VerifiedCheckpointHistoryAnchor,
    ) -> Result<VerifiedCheckpointHistoryScan, UsdomRpcClientError> {
        if request.trusted_tip != anchor.trusted_tip {
            return Err(UsdomRpcClientError::Invalid(
                "history trusted tip differs from the verified Ethereum checkpoint".into(),
            ));
        }
        let scan = self.scan_authenticated_history(request, true)?;
        if scan.terminal_state_root != anchor.state_root {
            return Err(UsdomRpcClientError::Invalid(
                "history terminal state differs from the verified Ethereum checkpoint".into(),
            ));
        }
        Ok(VerifiedCheckpointHistoryScan {
            anchor,
            blocks: scan.blocks,
        })
    }

    /// Fetch history through an operator-pinned tip, authenticate every block,
    /// and recover one exact Ethereum deposit atomically into `state`.
    ///
    /// The RPC server supplies canonical block material only. Ownership and the
    /// note commitment are derived locally from `wallet`, `bridge`, and the
    /// independently authenticated Ethereum deposit occurrence. A failure in
    /// either history application or recovery leaves the wallet at its prior
    /// tip.
    pub fn recover_historical_deposit(
        &self,
        state: &mut WalletState,
        wallet: &WalletSecrets,
        request: AuthenticatedHistoryRequest,
        bridge: BridgeIdentity,
        occurrence: EthereumDepositOccurrence,
    ) -> Result<Scalar, RemoteHistoricalDepositRecoveryError> {
        let scan = self.scan_authenticated_history_to_trusted_tip(request)?;
        state
            .apply_authenticated_history_and_recover_deposit(
                wallet,
                scan.blocks,
                bridge,
                occurrence,
            )
            .map_err(Into::into)
    }

    /// Recover one deposit only after the complete history terminates at an
    /// independently verified Ethereum-finalized DOM checkpoint.
    pub fn recover_historical_deposit_at_verified_checkpoint(
        &self,
        state: &mut WalletState,
        wallet: &WalletSecrets,
        request: AuthenticatedHistoryRequest,
        anchor: VerifiedCheckpointHistoryAnchor,
        bridge: BridgeIdentity,
        occurrence: EthereumDepositOccurrence,
    ) -> Result<Scalar, RemoteHistoricalDepositRecoveryError> {
        let scan = self.scan_authenticated_history_to_verified_checkpoint(request, anchor)?;
        state
            .apply_authenticated_history_and_recover_deposit(
                wallet,
                scan.into_blocks(),
                bridge,
                occurrence,
            )
            .map_err(Into::into)
    }

    fn scan_authenticated_history_page(
        &self,
        request: AuthenticatedHistoryRequest,
        require_checkpoint_finality: bool,
    ) -> Result<AuthenticatedHistoryPage, UsdomRpcClientError> {
        let endpoint = self.endpoint("usdom/v4/history/scan/v1")?;
        let body = HistoryRequestBody {
            schema_version: RPC_SCHEMA_VERSION,
            expected_network_magic: request.network_magic,
            expected_chain_id: hex::encode(request.chain_id.as_bytes()),
            expected_dom_domain: hex::encode(request.dom_domain.as_bytes()),
            trusted_tip: HistoryTipBody {
                height: request.trusted_tip.0,
                hash: hex::encode(request.trusted_tip.1.as_bytes()),
            },
            start_height: request.start_height,
            max_blocks: request.max_blocks,
            anchor: request.anchor.map(|anchor| HistoryAnchorBody {
                height: anchor.height,
                block_hash: hex::encode(anchor.block_hash.as_bytes()),
                state_root: hex::encode(anchor.state_root.as_bytes()),
            }),
            require_checkpoint_finality,
        };
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.bearer_token.as_str())
            .json(&body)
            .send()
            .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
        let response = read_response_bounded(response, MAX_HISTORY_RPC_RESPONSE_BYTES)?;
        parse_history_response(&response, request, require_checkpoint_finality)
    }

    fn endpoint(&self, relative: &str) -> Result<Url, UsdomRpcClientError> {
        self.base_url
            .join(relative)
            .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))
    }
}

#[derive(Serialize)]
struct SubmitRequest {
    schema_version: u16,
    payload_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitResponse {
    schema_version: u16,
    accepted: bool,
    transition_id: String,
    candidate_id: String,
    state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V2CandidateSubmitResponse {
    schema_version: u16,
    accepted: bool,
    candidate_id: String,
    state: String,
}

#[derive(Serialize)]
struct ScanRequestBody {
    schema_version: u16,
    expected_network_magic: u32,
    expected_chain_id: String,
    transition_id: String,
    start_height: u64,
    max_blocks: u64,
    anchor: Option<ScanAnchorBody>,
}

#[derive(Serialize)]
struct ScanAnchorBody {
    height: u64,
    block_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanResponse {
    schema_version: u16,
    identity: ScanIdentityResponse,
    request_anchor: Option<ScanAnchorResponse>,
    scanned_from: u64,
    scanned_to: Option<u64>,
    inclusion: Option<ScanInclusionResponse>,
    continuation: Option<ScanContinuationResponse>,
    finality_claimed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanIdentityResponse {
    network: String,
    network_magic: u32,
    chain_id: String,
    genesis_hash: String,
    tip_height: u64,
    tip_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanAnchorResponse {
    height: u64,
    block_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanInclusionResponse {
    height: u64,
    block_hash: String,
    transition_index: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanContinuationResponse {
    next_height: u64,
    anchor: ScanAnchorResponse,
    snapshot_tip: ScanTipResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanTipResponse {
    height: u64,
    hash: String,
}

#[derive(Serialize)]
struct HistoryRequestBody {
    schema_version: u16,
    expected_network_magic: u32,
    expected_chain_id: String,
    expected_dom_domain: String,
    trusted_tip: HistoryTipBody,
    start_height: u64,
    max_blocks: u64,
    anchor: Option<HistoryAnchorBody>,
    require_checkpoint_finality: bool,
}

#[derive(Serialize)]
struct HistoryTipBody {
    height: u64,
    hash: String,
}

#[derive(Serialize)]
struct HistoryAnchorBody {
    height: u64,
    block_hash: String,
    state_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryResponse {
    schema_version: u16,
    identity: ScanIdentityResponse,
    dom_domain: String,
    trusted_tip: ScanTipResponse,
    request_anchor: Option<HistoryAnchorResponse>,
    blocks: Vec<HistoryBlockResponse>,
    continuation: Option<HistoryContinuationResponse>,
    finality_claimed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryAnchorResponse {
    height: u64,
    block_hash: String,
    state_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryBlockResponse {
    height: u64,
    block_hash: String,
    header_hex: String,
    previous_block_hash: String,
    block_timestamp: u64,
    previous_state_root: String,
    new_state_root: String,
    transitions_root: String,
    batch_header_commitment: String,
    raw_rangeproof_root: String,
    transitions: Vec<HistoryTransitionResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryTransitionResponse {
    projection_hex: String,
    private_payload_hex: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryContinuationResponse {
    next_height: u64,
    anchor: HistoryAnchorResponse,
}

fn validate_base_url(value: &str) -> Result<Url, UsdomRpcClientError> {
    let url = Url::parse(value).map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| UsdomRpcClientError::Invalid("RPC URL has no host".into()))?;
    let ip = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .map_err(|_| UsdomRpcClientError::Invalid("RPC host must be a literal IP".into()))?;
    if url.scheme() != "http"
        || !ip.is_loopback()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(UsdomRpcClientError::Invalid(
            "RPC URL must be root HTTP on a literal loopback IP without credentials".into(),
        ));
    }
    Ok(url)
}

fn validate_token(token: &str) -> Result<(), UsdomRpcClientError> {
    if token.len() < 32
        || token.len() > 256
        || token
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(UsdomRpcClientError::Invalid(
            "Bearer token must contain 32..=256 non-whitespace bytes".into(),
        ));
    }
    Ok(())
}

fn load_owner_only_token(path: &Path) -> Result<Zeroizing<String>, UsdomRpcClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let parent = path.parent().ok_or_else(|| {
            UsdomRpcClientError::Invalid("Bearer token path has no parent directory".into())
        })?;
        let parent_metadata = std::fs::symlink_metadata(parent)
            .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.mode() & 0o077 != 0
        {
            return Err(UsdomRpcClientError::Invalid(
                "Bearer token parent directory must be private and not a symlink".into(),
            ));
        }
    }
    let file = File::open(path).map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    if !metadata.is_file() || !named.file_type().is_file() || named.file_type().is_symlink() {
        return Err(UsdomRpcClientError::Invalid(
            "Bearer token path is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.dev() != named.dev()
            || metadata.ino() != named.ino()
        {
            return Err(UsdomRpcClientError::Invalid(
                "Bearer token file must be owner-only and unlinked".into(),
            ));
        }
    }
    if metadata.len() == 0 || metadata.len() > MAX_TOKEN_FILE_BYTES {
        return Err(UsdomRpcClientError::Invalid(
            "Bearer token file has invalid length".into(),
        ));
    }
    let mut raw = Zeroizing::new(String::new());
    file.take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    if raw.len() as u64 > MAX_TOKEN_FILE_BYTES {
        return Err(UsdomRpcClientError::Invalid(
            "Bearer token file exceeds limit".into(),
        ));
    }
    let token = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned());
    validate_token(&token)?;
    Ok(token)
}

fn read_response(response: Response) -> Result<Zeroizing<Vec<u8>>, UsdomRpcClientError> {
    read_response_bounded(response, MAX_RPC_RESPONSE_BYTES)
}

fn read_response_bounded(
    response: Response,
    limit: u64,
) -> Result<Zeroizing<Vec<u8>>, UsdomRpcClientError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(UsdomRpcClientError::Invalid(
            "RPC response exceeds limit".into(),
        ));
    }
    let mut body = Zeroizing::new(Vec::new());
    let mut bounded: Take<Response> = response.take(limit + 1);
    bounded
        .read_to_end(&mut body)
        .map_err(|error| UsdomRpcClientError::Transport(error.to_string()))?;
    if body.len() as u64 > limit {
        return Err(UsdomRpcClientError::Invalid(
            "RPC response exceeds limit".into(),
        ));
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<ErrorResponse>(&body)
            .map(|value| value.error)
            .unwrap_or_else(|_| format!("HTTP {status}"));
        return Err(UsdomRpcClientError::Rejected(message));
    }
    Ok(body)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorResponse {
    error: String,
}

fn parse_hash(value: &str, label: &str) -> Result<Hash256, UsdomRpcClientError> {
    let bytes = hex::decode(value)
        .map_err(|_| UsdomRpcClientError::Invalid(format!("invalid {label} hex")))?;
    if bytes.len() != 32 || hex::encode(&bytes) != value {
        return Err(UsdomRpcClientError::Invalid(format!(
            "{label} must be canonical lowercase 32-byte hex"
        )));
    }
    let mut exact = [0; 32];
    exact.copy_from_slice(&bytes);
    let hash = Hash256::from_bytes(exact);
    if hash == Hash256::ZERO {
        return Err(UsdomRpcClientError::Invalid(format!(
            "{label} must not be zero"
        )));
    }
    Ok(hash)
}

fn parse_submission_response(
    body: &[u8],
    expected_transition_id: Hash256,
) -> Result<PrivateTransferSubmission, UsdomRpcClientError> {
    let response: SubmitResponse = serde_json::from_slice(body)
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    let transition_id = parse_hash(&response.transition_id, "transition_id")?;
    let candidate_id = parse_hash(&response.candidate_id, "candidate_id")?;
    if response.schema_version != RPC_SCHEMA_VERSION
        || !response.accepted
        || response.state != "queued"
        || transition_id != expected_transition_id
    {
        return Err(UsdomRpcClientError::Invalid(
            "RPC submission acknowledgement does not match the pending payload".into(),
        ));
    }
    Ok(PrivateTransferSubmission {
        transition_id,
        candidate_id,
    })
}

fn parse_v2_candidate_submission_response(
    body: &[u8],
    expected_candidate_id: Hash256,
) -> Result<V2CandidateSubmission, UsdomRpcClientError> {
    let response: V2CandidateSubmitResponse = serde_json::from_slice(body)
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    let candidate_id = parse_hash(&response.candidate_id, "candidate_id")?;
    if response.schema_version != RPC_SCHEMA_VERSION
        || !response.accepted
        || response.state != "queued"
        || candidate_id != expected_candidate_id
    {
        return Err(UsdomRpcClientError::Invalid(
            "RPC V2 candidate acknowledgement is not canonical".into(),
        ));
    }
    Ok(V2CandidateSubmission { candidate_id })
}

fn validate_scan_request(request: PrivateTransferScanRequest) -> Result<(), UsdomRpcClientError> {
    if request.network_magic == 0
        || request.chain_id == Hash256::ZERO
        || request.transition_id == Hash256::ZERO
        || request.max_blocks == 0
        || request.max_blocks > 256
    {
        return Err(UsdomRpcClientError::Invalid(
            "invalid private-transfer scan identity or range".into(),
        ));
    }
    match (request.start_height, request.anchor) {
        (0, None) => Ok(()),
        (start, Some((height, hash)))
            if hash != Hash256::ZERO && height.checked_add(1) == Some(start) =>
        {
            Ok(())
        }
        _ => Err(UsdomRpcClientError::Invalid(
            "scan anchor must immediately precede a nonzero start".into(),
        )),
    }
}

fn parse_scan_response(
    body: &[u8],
    request: PrivateTransferScanRequest,
) -> Result<PrivateTransferScanPage, UsdomRpcClientError> {
    let response: ScanResponse = serde_json::from_slice(body)
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    let chain_id = parse_hash(&response.identity.chain_id, "chain_id")?;
    let _genesis_hash = parse_hash(&response.identity.genesis_hash, "genesis_hash")?;
    let tip_hash = parse_hash(&response.identity.tip_hash, "tip_hash")?;
    if response.schema_version != RPC_SCHEMA_VERSION
        || response.finality_claimed
        || response.identity.network_magic != request.network_magic
        || network_name(response.identity.network_magic) != Some(response.identity.network.as_str())
        || chain_id != request.chain_id
        || response.scanned_from != request.start_height
    {
        return Err(UsdomRpcClientError::Invalid(
            "RPC scan identity or schema mismatch".into(),
        ));
    }
    let echoed_anchor = response
        .request_anchor
        .map(|value| {
            Ok((
                value.height,
                parse_hash(&value.block_hash, "request anchor")?,
            ))
        })
        .transpose()?;
    if echoed_anchor != request.anchor {
        return Err(UsdomRpcClientError::Invalid(
            "RPC scan did not echo the exact request anchor".into(),
        ));
    }
    let requested_end = request
        .start_height
        .checked_add(request.max_blocks - 1)
        .ok_or_else(|| UsdomRpcClientError::Invalid("scan range overflow".into()))?;
    if response.scanned_to.is_some_and(|height| {
        height < request.start_height
            || height > requested_end
            || height > response.identity.tip_height
    }) {
        return Err(UsdomRpcClientError::Invalid(
            "RPC scanned range is outside the request".into(),
        ));
    }
    let inclusion = response
        .inclusion
        .map(|value| {
            if response.scanned_to != Some(value.height) {
                return Err(UsdomRpcClientError::Invalid(
                    "RPC inclusion is outside the scanned suffix".into(),
                ));
            }
            Ok(CanonicalPrivateTransferInclusion {
                height: value.height,
                block_hash: parse_hash(&value.block_hash, "inclusion block hash")?,
                transition_index: value.transition_index,
            })
        })
        .transpose()?;
    if response.scanned_to.is_none() && (inclusion.is_some() || response.continuation.is_some()) {
        return Err(UsdomRpcClientError::Invalid(
            "empty RPC scan page contains a result or continuation".into(),
        ));
    }
    let continuation = response
        .continuation
        .map(|value| {
            let anchor_hash = parse_hash(&value.anchor.block_hash, "continuation anchor")?;
            let snapshot_tip = parse_hash(&value.snapshot_tip.hash, "continuation tip")?;
            if inclusion.is_some()
                || response.scanned_to != Some(value.anchor.height)
                || value.anchor.height.checked_add(1) != Some(value.next_height)
                || value.next_height > response.identity.tip_height.saturating_add(1)
                || value.snapshot_tip.height != response.identity.tip_height
                || snapshot_tip != tip_hash
            {
                return Err(UsdomRpcClientError::Invalid(
                    "RPC continuation is inconsistent with the scan page".into(),
                ));
            }
            Ok((value.next_height, value.anchor.height, anchor_hash))
        })
        .transpose()?;
    if inclusion.is_none()
        && response
            .scanned_to
            .is_some_and(|height| height < response.identity.tip_height && continuation.is_none())
    {
        return Err(UsdomRpcClientError::Invalid(
            "incomplete RPC scan page omitted its continuation".into(),
        ));
    }
    Ok(PrivateTransferScanPage {
        tip: (response.identity.tip_height, tip_hash),
        scanned_to: response.scanned_to,
        inclusion,
        continuation,
    })
}

fn validate_history_request(
    request: AuthenticatedHistoryRequest,
) -> Result<(), UsdomRpcClientError> {
    if !matches!(
        request.network_magic,
        NETWORK_MAGIC_MAINNET | NETWORK_MAGIC_TESTNET | NETWORK_MAGIC_REGTEST
    ) || request.chain_id == Hash256::ZERO
        || request.dom_domain == Hash256::ZERO
        || request.trusted_tip.1 == Hash256::ZERO
        || request.start_height == 0
        || request.start_height > request.trusted_tip.0
        || request.max_blocks == 0
        || request.max_blocks > 16
    {
        return Err(UsdomRpcClientError::Invalid(
            "invalid authenticated history identity, tip, domain or range".into(),
        ));
    }
    match request.anchor {
        Some(anchor)
            if anchor.block_hash != Hash256::ZERO
                && anchor.state_root != Hash256::ZERO
                && anchor.height.checked_add(1) == Some(request.start_height) =>
        {
            Ok(())
        }
        _ => Err(UsdomRpcClientError::Invalid(
            "authenticated history requires the exact preceding block and state root".into(),
        )),
    }
}

fn verified_checkpoint_history_anchor(
    checkpoint: &VerifiedCheckpoint,
    expected_network_magic: u32,
    expected_dom_domain: Hash256,
    expected_checkpoint_policy_hash: Hash256,
) -> Result<VerifiedCheckpointHistoryAnchor, UsdomRpcClientError> {
    const RECORD_VERSION: u8 = 2;
    const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;
    let record = checkpoint.record();
    let read_u64 = |range: std::ops::Range<usize>, label: &str| {
        record
            .get(range)
            .ok_or_else(|| UsdomRpcClientError::Invalid(format!("truncated {label}")))?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| UsdomRpcClientError::Invalid(format!("invalid {label}")))
    };
    let read_u32 = |range: std::ops::Range<usize>, label: &str| {
        record
            .get(range)
            .ok_or_else(|| UsdomRpcClientError::Invalid(format!("truncated {label}")))?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| UsdomRpcClientError::Invalid(format!("invalid {label}")))
    };
    let read_hash = |range: std::ops::Range<usize>, label: &str| {
        let bytes: [u8; 32] = record
            .get(range)
            .ok_or_else(|| UsdomRpcClientError::Invalid(format!("truncated {label}")))?
            .try_into()
            .map_err(|_| UsdomRpcClientError::Invalid(format!("invalid {label}")))?;
        let value = Hash256::from_bytes(bytes);
        if value == Hash256::ZERO {
            return Err(UsdomRpcClientError::Invalid(format!("zero {label}")));
        }
        Ok(value)
    };
    let height = read_u64(1..9, "checkpoint DOM height")?;
    let block = read_hash(9..41, "checkpoint DOM block")?;
    let state_root = read_hash(41..73, "checkpoint DOM state root")?;
    let network_magic = read_u32(73..77, "checkpoint DOM network")?;
    let ethereum_chain_id = read_u64(77..85, "checkpoint Ethereum chain")?;
    let dom_domain = read_hash(353..385, "checkpoint DOM domain")?;
    let checkpoint_event_digest = read_hash(385..417, "checkpoint event digest")?;
    let trust_policy_hash = Hash256::from_bytes(checkpoint.trust_policy_hash().into());
    if record[0] != RECORD_VERSION
        || height == 0
        || network_magic != expected_network_magic
        || ethereum_chain_id != ETHEREUM_MAINNET_CHAIN_ID
        || dom_domain != expected_dom_domain
        || expected_checkpoint_policy_hash == Hash256::ZERO
        || trust_policy_hash != expected_checkpoint_policy_hash
    {
        return Err(UsdomRpcClientError::Invalid(
            "verified checkpoint does not match the expected wallet finality policy".into(),
        ));
    }
    Ok(VerifiedCheckpointHistoryAnchor {
        trusted_tip: (height, block),
        state_root,
        checkpoint_event_digest,
    })
}

fn parse_history_anchor(
    value: HistoryAnchorResponse,
) -> Result<AuthenticatedHistoryAnchor, UsdomRpcClientError> {
    Ok(AuthenticatedHistoryAnchor {
        height: value.height,
        block_hash: parse_hash(&value.block_hash, "history anchor block hash")?,
        state_root: parse_hash(&value.state_root, "history anchor state root")?,
    })
}

fn decode_canonical_hex(
    value: &str,
    label: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, UsdomRpcClientError> {
    if value.len() > maximum_bytes.saturating_mul(2) || !value.len().is_multiple_of(2) {
        return Err(UsdomRpcClientError::Invalid(format!(
            "{label} exceeds its canonical bound"
        )));
    }
    let bytes = hex::decode(value)
        .map_err(|_| UsdomRpcClientError::Invalid(format!("invalid {label} hex")))?;
    if bytes.is_empty() || hex::encode(&bytes) != value {
        return Err(UsdomRpcClientError::Invalid(format!(
            "{label} must be nonempty canonical lowercase hex"
        )));
    }
    Ok(bytes)
}

fn parse_history_response(
    body: &[u8],
    request: AuthenticatedHistoryRequest,
    require_checkpoint_finality: bool,
) -> Result<AuthenticatedHistoryPage, UsdomRpcClientError> {
    validate_history_request(request)?;
    let response: HistoryResponse = serde_json::from_slice(body)
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
    let response_chain_id = parse_hash(&response.identity.chain_id, "history chain_id")?;
    let _genesis_hash = parse_hash(&response.identity.genesis_hash, "history genesis_hash")?;
    let identity_tip = parse_hash(&response.identity.tip_hash, "history identity tip")?;
    let response_domain = parse_hash(&response.dom_domain, "history domain")?;
    let response_trusted_tip = parse_hash(&response.trusted_tip.hash, "history trusted tip")?;
    if response.schema_version != RPC_SCHEMA_VERSION
        || response.finality_claimed != require_checkpoint_finality
        || response.identity.network_magic != request.network_magic
        || network_name(response.identity.network_magic) != Some(response.identity.network.as_str())
        || response_chain_id != request.chain_id
        || response_domain != request.dom_domain
        || response.identity.tip_height < request.trusted_tip.0
        || (response.identity.tip_height == request.trusted_tip.0
            && identity_tip != request.trusted_tip.1)
        || (response.trusted_tip.height, response_trusted_tip) != request.trusted_tip
    {
        return Err(UsdomRpcClientError::Invalid(
            "authenticated history identity, domain or trusted tip mismatch".into(),
        ));
    }
    let echoed_anchor = response
        .request_anchor
        .map(parse_history_anchor)
        .transpose()?;
    if echoed_anchor != request.anchor {
        return Err(UsdomRpcClientError::Invalid(
            "authenticated history did not echo the exact request anchor".into(),
        ));
    }
    if response.blocks.is_empty() || response.blocks.len() > request.max_blocks as usize {
        return Err(UsdomRpcClientError::Invalid(
            "authenticated history returned an invalid block count".into(),
        ));
    }
    let request_end = request
        .start_height
        .checked_add(request.max_blocks - 1)
        .ok_or_else(|| UsdomRpcClientError::Invalid("history range overflow".into()))?
        .min(request.trusted_tip.0);
    let anchor = request.anchor.ok_or_else(|| {
        UsdomRpcClientError::Invalid("authenticated history anchor is missing".into())
    })?;
    let mut expected_height = request.start_height;
    let mut expected_parent = anchor.block_hash;
    let mut expected_state_root = anchor.state_root;
    let mut blocks = Vec::with_capacity(response.blocks.len());

    for value in response.blocks {
        if value.height != expected_height || value.height > request_end {
            return Err(UsdomRpcClientError::Invalid(
                "authenticated history block range is discontinuous".into(),
            ));
        }
        let block_hash = parse_hash(&value.block_hash, "history block hash")?;
        let previous_block_hash =
            parse_hash(&value.previous_block_hash, "history previous block hash")?;
        let previous_state_root =
            parse_hash(&value.previous_state_root, "history previous state root")?;
        let new_state_root = parse_hash(&value.new_state_root, "history new state root")?;
        let transitions_root = parse_hash(&value.transitions_root, "history transitions root")?;
        let batch_header_commitment = parse_hash(
            &value.batch_header_commitment,
            "history batch header commitment",
        )?;
        let raw_rangeproof_root =
            parse_hash(&value.raw_rangeproof_root, "history raw rangeproof root")?;
        if previous_block_hash != expected_parent || previous_state_root != expected_state_root {
            return Err(UsdomRpcClientError::Invalid(
                "authenticated history parent or state-root continuity mismatch".into(),
            ));
        }
        let header_bytes = decode_canonical_hex(&value.header_hex, "history header", 1024)?;
        let header = BlockHeader::from_bytes(&header_bytes)
            .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
        if header
            .to_bytes()
            .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?
            != header_bytes
            || header.version != BLOCK_VERSION_V4
            || header.height.0 != value.height
            || header.prev_hash != previous_block_hash
            || header.timestamp.0 != value.block_timestamp
            || dom_crypto::blake2b_256(&header_bytes) != block_hash
        {
            return Err(UsdomRpcClientError::Invalid(
                "authenticated history DOM header mismatch".into(),
            ));
        }

        let mut projections = Vec::with_capacity(value.transitions.len());
        let mut transported_payloads = Vec::with_capacity(value.transitions.len());
        for transition in value.transitions {
            let projection_bytes = decode_canonical_hex(
                &transition.projection_hex,
                "history transition projection",
                MAX_TRANSITION_PROJECTION_BYTES,
            )?;
            let projection = TransitionCommitmentProjection::from_bytes(&projection_bytes)
                .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
            if projection.domain() != *request.dom_domain.as_bytes() {
                return Err(UsdomRpcClientError::Invalid(
                    "history transition projection has the wrong domain".into(),
                ));
            }
            let private_payload = transition
                .private_payload_hex
                .map(|payload| {
                    decode_canonical_hex(
                        &payload,
                        "history private payload",
                        MAX_PRIVATE_BURN_PAYLOAD_BYTES,
                    )
                })
                .transpose()?;
            projections.push(projection);
            transported_payloads.push(private_payload);
        }
        let authenticated = authenticate_transition_projection_batch(
            *request.dom_domain.as_bytes(),
            value.block_timestamp,
            previous_state_root,
            new_state_root,
            &projections,
        )
        .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?;
        if authenticated.transitions_root != transitions_root
            || authenticated.header_commitment != batch_header_commitment
            || bind_usdom_batch_commitment(raw_rangeproof_root, batch_header_commitment)
                .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))?
                != header.rangeproof_root
        {
            return Err(UsdomRpcClientError::Invalid(
                "history projections are not bound into the exact DOM header".into(),
            ));
        }
        let observations = projections
            .iter()
            .zip(transported_payloads.iter())
            .map(|(projection, payload)| {
                WalletTransitionObservation::from_authenticated_projection(
                    projection,
                    payload.as_deref(),
                )
                .map_err(|error| UsdomRpcClientError::Invalid(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        blocks.push(CanonicalWalletBlock {
            height: value.height,
            identifier: block_hash,
            parent_identifier: previous_block_hash,
            transitions: observations,
        });
        expected_height = expected_height
            .checked_add(1)
            .ok_or_else(|| UsdomRpcClientError::Invalid("history height overflow".into()))?;
        expected_parent = block_hash;
        expected_state_root = new_state_root;
    }

    let last = blocks.last().ok_or_else(|| {
        UsdomRpcClientError::Invalid("authenticated history returned no canonical block".into())
    })?;
    let continuation = response
        .continuation
        .map(|value| {
            let anchor = parse_history_anchor(value.anchor)?;
            if value.next_height != expected_height
                || anchor.height != last.height
                || anchor.block_hash != last.identifier
                || anchor.state_root != expected_state_root
            {
                return Err(UsdomRpcClientError::Invalid(
                    "authenticated history continuation mismatch".into(),
                ));
            }
            Ok((value.next_height, anchor))
        })
        .transpose()?;
    if last.height < request.trusted_tip.0 {
        if continuation.is_none() {
            return Err(UsdomRpcClientError::Invalid(
                "incomplete authenticated history omitted its continuation".into(),
            ));
        }
    } else if last.identifier != request.trusted_tip.1 || continuation.is_some() {
        return Err(UsdomRpcClientError::Invalid(
            "terminal authenticated history does not reach the trusted tip".into(),
        ));
    }
    Ok(AuthenticatedHistoryPage {
        trusted_tip: request.trusted_tip,
        blocks,
        continuation,
        response_bytes: body.len(),
        terminal_state_root: expected_state_root,
    })
}

fn checked_history_rescan_bytes(
    accumulated: usize,
    page: usize,
) -> Result<usize, UsdomRpcClientError> {
    let total = accumulated.checked_add(page).ok_or_else(|| {
        UsdomRpcClientError::Invalid("authenticated history byte count overflow".into())
    })?;
    if total > MAX_AUTHENTICATED_HISTORY_RESCAN_BYTES {
        return Err(UsdomRpcClientError::Invalid(format!(
            "authenticated history rescan exceeds {MAX_AUTHENTICATED_HISTORY_RESCAN_BYTES} bytes"
        )));
    }
    Ok(total)
}

fn network_name(network_magic: u32) -> Option<&'static str> {
    match network_magic {
        NETWORK_MAGIC_MAINNET => Some("mainnet"),
        NETWORK_MAGIC_TESTNET => Some("testnet"),
        NETWORK_MAGIC_REGTEST => Some("regtest"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    use dom_usdom_privacy::{chain_scalar, privacy_policy_hash};
    use dom_usdom_state::BurnTimingPolicy;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).unwrap();
            assert_ne!(read, 0, "HTTP request ended before its declared body");
            request.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n") else {
                continue;
            };
            let body_offset = header_end + 4;
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            if request.len() == body_offset + content_length {
                return request;
            }
            assert!(request.len() < body_offset + content_length);
        }
    }

    fn authenticated_history_fixture() -> (AuthenticatedHistoryRequest, serde_json::Value) {
        let domain = hash(0x33);
        let previous_state_root = hash(0x88);
        let new_state_root = hash(0x99);
        let timestamp = 1_800_000_000;
        let batch = authenticate_transition_projection_batch(
            *domain.as_bytes(),
            timestamp,
            previous_state_root,
            new_state_root,
            &[],
        )
        .unwrap();
        let raw_rangeproof_root = hash(0xdd);
        let rangeproof_root =
            bind_usdom_batch_commitment(raw_rangeproof_root, batch.header_commitment).unwrap();
        let mut header = Vec::new();
        header.extend_from_slice(&BLOCK_VERSION_V4.to_le_bytes());
        header.extend_from_slice(&1u64.to_le_bytes());
        header.extend_from_slice(hash(0x44).as_bytes());
        header.extend_from_slice(&timestamp.to_le_bytes());
        header.extend_from_slice(hash(0x11).as_bytes());
        header.extend_from_slice(hash(0x22).as_bytes());
        header.extend_from_slice(rangeproof_root.as_bytes());
        header.extend_from_slice(&[0; 32]);
        header.extend_from_slice(&0x207f_ffffu32.to_le_bytes());
        let mut difficulty = [0u8; 32];
        difficulty[31] = 1;
        header.extend_from_slice(&difficulty);
        header.extend_from_slice(&7u64.to_le_bytes());
        header.extend_from_slice(hash(0x55).as_bytes());
        BlockHeader::from_bytes(&header).expect("canonical history fixture header");
        let block_hash = dom_crypto::blake2b_256(&header);
        let request = AuthenticatedHistoryRequest {
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: hash(0x10),
            dom_domain: domain,
            trusted_tip: (1, block_hash),
            start_height: 1,
            max_blocks: 1,
            anchor: Some(AuthenticatedHistoryAnchor {
                height: 0,
                block_hash: hash(0x44),
                state_root: previous_state_root,
            }),
        };
        let response = serde_json::json!({
            "schema_version": 1,
            "identity": {
                "network": "regtest",
                "network_magic": NETWORK_MAGIC_REGTEST,
                "chain_id": hex::encode(request.chain_id.as_bytes()),
                "genesis_hash": "66".repeat(32),
                "tip_height": 1,
                "tip_hash": hex::encode(block_hash.as_bytes()),
            },
            "dom_domain": hex::encode(domain.as_bytes()),
            "trusted_tip": {"height": 1, "hash": hex::encode(block_hash.as_bytes())},
            "request_anchor": {
                "height": 0,
                "block_hash": "44".repeat(32),
                "state_root": "88".repeat(32),
            },
            "blocks": [{
                "height": 1,
                "block_hash": hex::encode(block_hash.as_bytes()),
                "header_hex": hex::encode(header),
                "previous_block_hash": "44".repeat(32),
                "block_timestamp": timestamp,
                "previous_state_root": "88".repeat(32),
                "new_state_root": "99".repeat(32),
                "transitions_root": hex::encode(batch.transitions_root.as_bytes()),
                "batch_header_commitment": hex::encode(batch.header_commitment.as_bytes()),
                "raw_rangeproof_root": "dd".repeat(32),
                "transitions": [],
            }],
            "continuation": null,
            "finality_claimed": false,
        });
        (request, response)
    }

    fn verified_history_checkpoint(
        request: AuthenticatedHistoryRequest,
        state_root: Hash256,
        policy_hash: Hash256,
    ) -> VerifiedCheckpoint {
        let mut record = [0u8; 417];
        record[0] = 2;
        record[1..9].copy_from_slice(&request.trusted_tip.0.to_be_bytes());
        record[9..41].copy_from_slice(request.trusted_tip.1.as_bytes());
        record[41..73].copy_from_slice(state_root.as_bytes());
        record[73..77].copy_from_slice(&request.network_magic.to_be_bytes());
        record[77..85].copy_from_slice(&1u64.to_be_bytes());
        record[85..93].copy_from_slice(&1u64.to_be_bytes());
        record[93..125].copy_from_slice(hash(0xa1).as_bytes());
        record[125..157].copy_from_slice(hash(0xa2).as_bytes());
        record[157..189].copy_from_slice(hash(0xa3).as_bytes());
        record[189..197].copy_from_slice(&1u64.to_be_bytes());
        record[197..229].copy_from_slice(hash(0xa4).as_bytes());
        record[229..261].copy_from_slice(hash(0xa5).as_bytes());
        record[269..289].copy_from_slice(&[0xa6; 20]);
        record[289..321].copy_from_slice(hash(0xa7).as_bytes());
        record[321..353].copy_from_slice(hash(0xa8).as_bytes());
        record[353..385].copy_from_slice(request.dom_domain.as_bytes());
        record[385..417].copy_from_slice(hash(0xa9).as_bytes());
        usdom_ethereum_finality_experiment::checkpoints::unsafe_test_only_verified_checkpoint(
            record,
            1,
            (*policy_hash.as_bytes()).into(),
        )
    }

    #[test]
    fn client_accepts_only_literal_loopback_root_http_and_strong_token() {
        let token = "a".repeat(64);
        assert!(UsdomRpcClient::new("http://127.0.0.1:3370/", token.clone()).is_ok());
        assert!(UsdomRpcClient::new("http://[::1]:3370/", token.clone()).is_ok());
        for url in [
            "https://127.0.0.1:3370/",
            "http://localhost:3370/",
            "http://192.0.2.1:3370/",
            "http://user@127.0.0.1:3370/",
            "http://127.0.0.1:3370/base/",
        ] {
            assert!(UsdomRpcClient::new(url, token.clone()).is_err(), "{url}");
        }
        assert!(UsdomRpcClient::new("http://127.0.0.1:3370/", "short".into()).is_err());
    }

    #[test]
    fn submission_response_must_match_exact_pending_identifier() {
        let expected = hash(0x55);
        let valid = serde_json::json!({
            "schema_version": 1,
            "accepted": true,
            "transition_id": "55".repeat(32),
            "candidate_id": "66".repeat(32),
            "state": "queued"
        });
        let parsed = parse_submission_response(valid.to_string().as_bytes(), expected).unwrap();
        assert_eq!(parsed.transition_id, expected);
        assert_eq!(parsed.candidate_id, hash(0x66));

        for mutation in [
            serde_json::json!({"schema_version": 2, "accepted": true, "transition_id": "55".repeat(32), "candidate_id": "66".repeat(32), "state": "queued"}),
            serde_json::json!({"schema_version": 1, "accepted": true, "transition_id": "54".repeat(32), "candidate_id": "66".repeat(32), "state": "queued"}),
            serde_json::json!({"schema_version": 1, "accepted": true, "transition_id": "55".repeat(32), "candidate_id": "66".repeat(32), "state": "confirmed"}),
        ] {
            assert!(parse_submission_response(mutation.to_string().as_bytes(), expected).is_err());
        }
    }

    #[test]
    fn v2_candidate_response_is_strict_and_nonzero() {
        let valid = serde_json::json!({
            "schema_version": 1,
            "accepted": true,
            "candidate_id": "86".repeat(32),
            "state": "queued"
        });
        assert_eq!(
            parse_v2_candidate_submission_response(valid.to_string().as_bytes(), hash(0x86))
                .unwrap()
                .candidate_id,
            hash(0x86)
        );
        for mutation in [
            serde_json::json!({"schema_version": 2, "accepted": true, "candidate_id": "86".repeat(32), "state": "queued"}),
            serde_json::json!({"schema_version": 1, "accepted": false, "candidate_id": "86".repeat(32), "state": "queued"}),
            serde_json::json!({"schema_version": 1, "accepted": true, "candidate_id": "00".repeat(32), "state": "queued"}),
            serde_json::json!({"schema_version": 1, "accepted": true, "candidate_id": "85".repeat(32), "state": "queued"}),
            serde_json::json!({"schema_version": 1, "accepted": true, "candidate_id": "86".repeat(32), "state": "confirmed"}),
            serde_json::json!({"schema_version": 1, "accepted": true, "candidate_id": "86".repeat(32), "state": "queued", "extra": true}),
        ] {
            assert!(parse_v2_candidate_submission_response(
                mutation.to_string().as_bytes(),
                hash(0x86),
            )
            .is_err());
        }
    }

    #[test]
    fn v2_candidate_client_sends_the_exact_authenticated_binary_pair() {
        let envelope = vec![0x10, 0x20, 0x30];
        let witnesses = vec![0x40, 0x50];
        let expected =
            dom_usdom_rpc_protocol::encode_candidate_submission_v1(&envelope, &witnesses).unwrap();
        let expected_candidate_id = Hash256::from_bytes(
            dom_usdom_rpc_protocol::candidate_id_v1(&envelope, &witnesses).unwrap(),
        );
        let expected_candidate_hex = hex::encode(expected_candidate_id.as_bytes());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            let header_end = request
                .windows(4)
                .position(|value| value == b"\r\n\r\n")
                .unwrap();
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let lowercase_headers = headers.to_ascii_lowercase();
            assert!(headers.starts_with("POST /usdom/v2/candidate/submit/v1 HTTP/1.1"));
            assert!(lowercase_headers.contains("authorization: bearer "));
            assert!(lowercase_headers.contains("content-type: application/octet-stream"));
            assert_eq!(&request[header_end + 4..], expected);

            let response = serde_json::json!({
                "schema_version": 1,
                "accepted": true,
                "candidate_id": expected_candidate_hex,
                "state": "queued"
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });

        let client = UsdomRpcClient::new(&format!("http://{address}/"), "a".repeat(64)).unwrap();
        assert_eq!(
            client
                .submit_v2_candidate(&envelope, &witnesses)
                .unwrap()
                .candidate_id,
            expected_candidate_id
        );
        server.join().unwrap();
    }

    #[test]
    fn scan_response_is_identity_anchor_range_and_finality_bound() {
        let request = PrivateTransferScanRequest {
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: hash(0x11),
            transition_id: hash(0x55),
            start_height: 12,
            max_blocks: 4,
            anchor: Some((11, hash(0x44))),
        };
        let valid = serde_json::json!({
            "schema_version": 1,
            "identity": {
                "network": "regtest",
                "network_magic": request.network_magic,
                "chain_id": "11".repeat(32),
                "genesis_hash": "22".repeat(32),
                "tip_height": 15,
                "tip_hash": "77".repeat(32)
            },
            "request_anchor": {"height": 11, "block_hash": "44".repeat(32)},
            "scanned_from": 12,
            "scanned_to": 12,
            "inclusion": {"height": 12, "block_hash": "33".repeat(32), "transition_index": 0},
            "continuation": null,
            "finality_claimed": false
        });
        let page = parse_scan_response(valid.to_string().as_bytes(), request).unwrap();
        assert_eq!(page.inclusion.unwrap().block_hash, hash(0x33));

        let mut wrong = valid.clone();
        wrong["finality_claimed"] = serde_json::json!(true);
        assert!(parse_scan_response(wrong.to_string().as_bytes(), request).is_err());

        let mut wrong = valid.clone();
        wrong["identity"]["network"] = serde_json::json!("mainnet");
        assert!(parse_scan_response(wrong.to_string().as_bytes(), request).is_err());

        let mut wrong = valid.clone();
        wrong["request_anchor"]["block_hash"] = serde_json::json!("45".repeat(32));
        assert!(parse_scan_response(wrong.to_string().as_bytes(), request).is_err());

        let mut wrong = valid.clone();
        wrong["identity"]["genesis_hash"] = serde_json::json!("ab".repeat(32).to_uppercase());
        assert!(parse_scan_response(wrong.to_string().as_bytes(), request).is_err());
    }

    #[test]
    fn incomplete_scan_page_requires_a_tip_bound_continuation() {
        let request = PrivateTransferScanRequest {
            network_magic: NETWORK_MAGIC_REGTEST,
            chain_id: hash(0x11),
            transition_id: hash(0x55),
            start_height: 12,
            max_blocks: 2,
            anchor: Some((11, hash(0x44))),
        };
        let page = serde_json::json!({
            "schema_version": 1,
            "identity": {
                "network": "regtest",
                "network_magic": request.network_magic,
                "chain_id": "11".repeat(32),
                "genesis_hash": "22".repeat(32),
                "tip_height": 20,
                "tip_hash": "77".repeat(32)
            },
            "request_anchor": {"height": 11, "block_hash": "44".repeat(32)},
            "scanned_from": 12,
            "scanned_to": 13,
            "inclusion": null,
            "continuation": {
                "next_height": 14,
                "anchor": {"height": 13, "block_hash": "33".repeat(32)},
                "snapshot_tip": {"height": 20, "hash": "77".repeat(32)}
            },
            "finality_claimed": false
        });
        let parsed = parse_scan_response(page.to_string().as_bytes(), request).unwrap();
        assert_eq!(parsed.continuation, Some((14, 13, hash(0x33))));

        let mut missing = page.clone();
        missing["continuation"] = serde_json::Value::Null;
        assert!(parse_scan_response(missing.to_string().as_bytes(), request).is_err());

        let mut wrong_tip = page;
        wrong_tip["continuation"]["snapshot_tip"]["hash"] = serde_json::json!("76".repeat(32));
        assert!(parse_scan_response(wrong_tip.to_string().as_bytes(), request).is_err());
    }

    #[test]
    fn history_response_recomputes_header_batch_state_and_tip_bindings() {
        let (request, valid) = authenticated_history_fixture();
        let parsed = parse_history_response(valid.to_string().as_bytes(), request, false).unwrap();
        assert_eq!(parsed.trusted_tip, request.trusted_tip);
        assert_eq!(parsed.blocks.len(), 1);
        assert_eq!(parsed.blocks[0].identifier, request.trusted_tip.1);
        assert!(parsed.blocks[0].transitions.is_empty());
        assert!(parsed.continuation.is_none());

        let mut wrong = valid.clone();
        wrong["blocks"][0]["raw_rangeproof_root"] = serde_json::json!("de".repeat(32));
        assert!(parse_history_response(wrong.to_string().as_bytes(), request, false).is_err());

        let mut wrong = valid.clone();
        wrong["blocks"][0]["new_state_root"] = serde_json::json!("98".repeat(32));
        assert!(parse_history_response(wrong.to_string().as_bytes(), request, false).is_err());

        let mut wrong = valid.clone();
        wrong["blocks"][0]["header_hex"] = serde_json::json!(valid["blocks"][0]["header_hex"]
            .as_str()
            .unwrap()
            .to_uppercase());
        assert!(parse_history_response(wrong.to_string().as_bytes(), request, false).is_err());

        let mut wrong = valid.clone();
        wrong["finality_claimed"] = serde_json::json!(true);
        assert!(parse_history_response(wrong.to_string().as_bytes(), request, false).is_err());

        let mut historical = valid;
        historical["identity"]["tip_height"] = serde_json::json!(2);
        historical["identity"]["tip_hash"] = serde_json::json!("ab".repeat(32));
        assert!(parse_history_response(historical.to_string().as_bytes(), request, false).is_ok());
    }

    #[test]
    fn verified_checkpoint_capability_binds_history_tip_state_domain_network_and_policy() {
        let (request, mut response) = authenticated_history_fixture();
        let policy_hash = hash(0xc1);
        let checkpoint = verified_history_checkpoint(request, hash(0x99), policy_hash);
        let anchor = VerifiedCheckpointHistoryAnchor::from_verified_checkpoint(
            &checkpoint,
            request.network_magic,
            request.dom_domain,
            policy_hash,
        )
        .unwrap();
        assert_eq!(anchor.trusted_tip(), request.trusted_tip);
        assert_eq!(anchor.state_root(), hash(0x99));
        assert_eq!(anchor.checkpoint_event_digest(), hash(0xa9));
        assert!(verified_checkpoint_history_anchor(
            &checkpoint,
            NETWORK_MAGIC_MAINNET,
            request.dom_domain,
            policy_hash,
        )
        .is_err());

        response["finality_claimed"] = serde_json::json!(true);
        assert!(verified_checkpoint_history_anchor(
            &checkpoint,
            request.network_magic,
            hash(0x34),
            policy_hash,
        )
        .is_err());
        assert!(verified_checkpoint_history_anchor(
            &checkpoint,
            request.network_magic,
            request.dom_domain,
            hash(0xc2),
        )
        .is_err());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = response.to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request_bytes = read_http_request(&mut stream);
            let body_offset = request_bytes
                .windows(4)
                .position(|value| value == b"\r\n\r\n")
                .unwrap()
                + 4;
            let request_json: serde_json::Value =
                serde_json::from_slice(&request_bytes[body_offset..]).unwrap();
            assert_eq!(
                request_json["require_checkpoint_finality"],
                serde_json::json!(true)
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let client = UsdomRpcClient::new(&format!("http://{address}/"), "a".repeat(64)).unwrap();
        let scan = client
            .scan_authenticated_history_to_verified_checkpoint(request, anchor)
            .unwrap();
        server.join().unwrap();
        assert_eq!(scan.anchor(), anchor);
        assert_eq!(scan.blocks().len(), 1);
        assert_eq!(scan.blocks()[0].identifier, request.trusted_tip.1);
    }

    #[test]
    fn authenticated_history_enforces_a_cumulative_response_byte_ceiling() {
        assert_eq!(
            checked_history_rescan_bytes(MAX_AUTHENTICATED_HISTORY_RESCAN_BYTES - 1, 1).unwrap(),
            MAX_AUTHENTICATED_HISTORY_RESCAN_BYTES
        );
        assert!(checked_history_rescan_bytes(MAX_AUTHENTICATED_HISTORY_RESCAN_BYTES, 1).is_err());
        assert!(checked_history_rescan_bytes(usize::MAX, 1).is_err());
    }

    #[test]
    fn remote_historical_deposit_recovery_rolls_back_an_absent_occurrence() {
        let (request, response) = authenticated_history_fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = response.to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request_bytes = [0u8; 8192];
            let size = stream.read(&mut request_bytes).unwrap();
            let request_text = std::str::from_utf8(&request_bytes[..size]).unwrap();
            assert!(request_text.starts_with("POST /usdom/v4/history/scan/v1 HTTP/1.1"));
            assert!(request_text.contains("authorization: Bearer "));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let domain = *request.dom_domain.as_bytes();
        let policy_hash = *privacy_policy_hash().as_bytes();
        let chain = chain_scalar(domain, policy_hash);
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5252);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let bridge = BridgeIdentity {
            dom_domain: domain,
            ethereum_genesis_validators_root: [0xa1; 32],
            ethereum_chain_id: {
                let mut id = [0u8; 32];
                id[31] = 1;
                id
            },
            ethereum_checkpoint_policy_hash: [0xa2; 32],
            ethereum_deposit_policy_hash: [0xa3; 32],
            privacy_policy_hash: policy_hash,
            privacy_verifier_config_hash: [0xa4; 32],
            reserve: [0xa5; 20],
            burn_timing: BurnTimingPolicy {
                withdrawal_delay_secs: 24 * 60 * 60,
                min_execution_window_secs: 60 * 60,
                max_certificate_lifetime_secs: 7 * 24 * 60 * 60,
                relay_safety_margin_secs: 2 * 24 * 60 * 60,
                max_ethereum_anchor_age_secs: 24 * 60 * 60,
                max_dom_clock_lead_secs: 2 * 60 * 60,
            },
        };
        let occurrence = EthereumDepositOccurrence {
            genesis_validators_root: bridge.ethereum_genesis_validators_root,
            block_hash: [0xb1; 32],
            block_number: 22_200_100,
            transaction_index: 1,
            receipt_log_index: 0,
            deposit_id: [0xb2; 32],
            funder: [0xb3; 20],
            amount: 1_000_000,
            receiving_commitment: wallet.address().unwrap().owner().to_bytes(),
        };
        let mut state = WalletState::new_empty(chain, 0, hash(0x44)).unwrap();
        let client = UsdomRpcClient::new(
            &format!("http://{address}/"),
            "authenticated-test-token-material-64-bytes-aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        )
        .unwrap();

        assert!(matches!(
            client.recover_historical_deposit(&mut state, &wallet, request, bridge, occurrence,),
            Err(RemoteHistoricalDepositRecoveryError::Wallet(
                WalletError::ExpectedIssuanceNotCanonical
            ))
        ));
        server.join().unwrap();
        assert_eq!(state.tip_height(), 0);
        assert_eq!(state.tip_identifier(), hash(0x44));
        assert!(state.note_summaries().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn token_file_must_be_owner_only_regular_and_not_a_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("rpc.token");
        std::fs::write(&path, format!("{}\n", "a".repeat(64))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(&*load_owner_only_token(&path).unwrap(), &"a".repeat(64));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_owner_only_token(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("rpc.link");
        symlink(&path, &link).unwrap();
        assert!(load_owner_only_token(&link).is_err());
    }
}

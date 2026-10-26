//! # dom-chain
//!
//! Chain state management: IBD, block validation, reorganization, chain selection.
//!
//! ## IBD (Initial Block Download) — headers-first
//!
//! 1. Connect to peers and request headers (GET_HEADERS)
//! 2. Validate headers (PoW, timestamps, difficulty)
//! 3. Once headers are verified, download full blocks in parallel
//! 4. Validate and commit each block atomically
//!
//! This prevents a low-work chain from wasting significant CPU.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod chain_state;
pub mod genesis;
pub mod ibd;
pub mod reorg;

#[cfg(feature = "ethereum-checkpoint-poc")]
pub mod ethereum_checkpoint_poc;

#[cfg(feature = "native-usdom-v4-poc")]
pub mod native_usdom_v4;

#[cfg(kani)]
mod kani_invariants;

pub use chain_state::{
    genesis_canonical_changeset, ChainState, ConnectResult, ReorgBlockDelta, ReorgDelta,
    CHAIN_CORRUPT_SENTINEL, MAX_RETAINED_SIDE_BRANCH_LENGTH, MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH,
    MAX_RETAINED_SIDE_BRANCH_TIPS,
};
pub use genesis::{
    build_canonical_genesis, canonical_genesis_inscription, canonical_header_identifier,
    validate_mainnet_genesis_identity, CanonicalGenesis, GenesisInscriptionV1,
    MainnetGenesisIdentityV1, GENESIS_INSCRIPTION_VERSION, MAINNET_GENESIS_IDENTITY_VERSION,
    MAX_GENESIS_INSCRIPTION_BYTES,
};
pub use ibd::{
    IbdControl, IbdInterruption, IbdPhase, IbdState, PersistedIbdState, IBD_SESSION_METADATA_KEY,
    LEGACY_IBD_SESSION_METADATA_KEY,
};

#[cfg(feature = "native-usdom-v4-poc")]
pub use native_usdom_v4::{
    audit_persisted_usdom_v4_reorg_window, audit_persisted_usdom_v4_reorg_window_for_schedule,
    bind_verified_ethereum_checkpoint_to_native_burn, ethereum_checkpoint_policy_hash,
    export_finalized_burn_prover_input_for_schedule,
    export_native_usdom_v4_burn_block_prover_input,
    export_native_usdom_v4_burn_block_prover_input_for_schedule,
    export_native_usdom_v4_snapshot_manifest, install_verified_native_burn_checkpoint,
    load_authenticated_usdom_v4_history_block, load_persisted_usdom_v2_activation_schedule,
    load_persisted_usdom_v2_execution_witnesses, load_persisted_usdom_v4_package,
    native_usdom_v2_activation_updates, native_usdom_v4_activation_updates,
    native_usdom_v4_activation_updates_for_schedule, native_usdom_v4_regtest_activation_schedule,
    persisted_usdom_v4_activation_schedule, restore_persisted_usdom_v2_activation,
    restore_persisted_usdom_v2_state_for_schedule, restore_persisted_usdom_v4_state,
    restore_persisted_usdom_v4_state_for_schedule, rewind_persisted_usdom_v2_state_to_ancestor,
    rewind_persisted_usdom_v4_state_to_ancestor,
    rewind_persisted_usdom_v4_state_to_ancestor_for_schedule,
    verify_native_usdom_v4_snapshot_manifest, verify_usdom_v4_serialized_candidate_for_schedule,
    verify_usdom_v4_serialized_candidate_regtest,
    verify_usdom_v4_serialized_transition_batch_for_schedule,
    verify_usdom_v4_serialized_transition_batch_for_v2_schedule, AuthenticatedUsdomV4HistoryBlock,
    AuthenticatedUsdomV4HistoryTransition, FinalizedBurnStatement, NativeBurnBlockBinding,
    NativeBurnBlockProverInput, NativeBurnCheckpointBinding, NativeUsdomV2ActivationSchedule,
    NativeUsdomV2MiningTemplate, NativeUsdomV2Runtime, NativeUsdomV4ActivationSchedule,
    NativeUsdomV4HistoryAudit, NativeUsdomV4MiningTemplate, NativeUsdomV4Runtime,
    NativeUsdomV4SnapshotBlock, NativeUsdomV4SnapshotManifest, UsdomV2BlockSidecar,
    UsdomV2ExecutionWitnesses, UsdomV4BlockPackage, UsdomV4ProofEnvelope, UsdomV4ProofKind,
    VerifiedUsdomV4Candidate, VerifiedUsdomV4CandidateV2, VerifiedUsdomV4TransitionBatch,
    FINALIZED_BURN_STATEMENT_TYPE, MAX_NATIVE_BURN_BLOCK_PROVER_INPUT_BYTES,
    MAX_USDOM_V2_WITNESS_BUNDLE_BYTES, MAX_USDOM_V4_ENVELOPE_BYTES, MAX_USDOM_V4_MINING_CANDIDATES,
    MAX_USDOM_V4_MINING_CANDIDATE_BYTES, MAX_USDOM_V4_PROOF_BYTES,
    USDOM_V2_ACTIVATION_SCHEDULE_BYTES,
};

#[cfg(feature = "native-usdom-v4-poc")]
pub use dom_usdom_finalized_burn_program::{
    CheckpointStatementV6, FinalizedBurnProverInput, FINALIZED_BURN_PROVER_INPUT_VERSION,
    MAX_FINALIZED_BURN_PROVER_INPUT_BYTES,
};

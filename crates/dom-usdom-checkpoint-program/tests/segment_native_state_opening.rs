#![cfg(feature = "segment-state-opening")]

use dom_core::{Hash256, MAX_FUTURE_BLOCK_TIME};
use dom_usdom_checkpoint_program::{
    CheckpointSegmentNativeStateOpening, CheckpointSegmentNativeStateOpeningError,
    CheckpointSegmentState, MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
};
use dom_usdom_checkpoint_statement::{
    checkpoint_economic_state_root, CheckpointContext, ContextHeader, SeedAnchor,
    CHECKPOINT_CONTEXT_HEADER_COUNT, CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS,
};
use dom_usdom_state::{
    BridgeIdentity, BurnTimingPolicy, NativeUsdomState, RESERVE_MAX_CERTIFICATE_LIFETIME_SECS,
    RESERVE_MIN_EXECUTION_WINDOW_SECS,
};

fn bridge() -> BridgeIdentity {
    let mut ethereum_chain_id = [0u8; 32];
    ethereum_chain_id[31] = 1;
    BridgeIdentity {
        dom_domain: [0x11; 32],
        ethereum_genesis_validators_root: [0x12; 32],
        ethereum_chain_id,
        ethereum_checkpoint_policy_hash: [0x13; 32],
        ethereum_deposit_policy_hash: [0x14; 32],
        privacy_policy_hash: [0x17; 32],
        privacy_verifier_config_hash: [0x15; 32],
        reserve: [0x16; 20],
        burn_timing: BurnTimingPolicy {
            withdrawal_delay_secs: 86_400,
            min_execution_window_secs: RESERVE_MIN_EXECUTION_WINDOW_SECS,
            max_certificate_lifetime_secs: RESERVE_MAX_CERTIFICATE_LIFETIME_SECS,
            relay_safety_margin_secs: 3_600,
            max_ethereum_anchor_age_secs: 1_800,
            max_dom_clock_lead_secs: MAX_FUTURE_BLOCK_TIME,
        },
    }
}

fn segment_state(native_state_root: Hash256) -> CheckpointSegmentState {
    let height = 1_000;
    let block_hash = [0x21; 32];
    let economic_utxo_root = [0x31; 32];
    let economic_kernel_root = [0x32; 32];
    let mut recent_headers = [ContextHeader {
        height: 0,
        block: [0; 32],
        timestamp: 0,
    }; CHECKPOINT_CONTEXT_HEADER_COUNT];
    for (index, header) in recent_headers.iter_mut().enumerate() {
        header.height = height - (CHECKPOINT_CONTEXT_HEADER_COUNT - 1 - index) as u64;
        header.block = [0x40 + index as u8; 32];
        header.timestamp = 1_700_000_000 + index as u64;
    }
    recent_headers[CHECKPOINT_CONTEXT_HEADER_COUNT - 1].block = block_hash;
    CheckpointSegmentState {
        network_magic: 0xA1B2C3D4,
        chain_id: [0x22; 32],
        activation_schedule_commitment: [0x23; 32],
        checkpoint_config_hash: [0x24; 32],
        checkpoint_policy_hash: bridge().ethereum_checkpoint_policy_hash,
        deposit_policy_hash: bridge().ethereum_deposit_policy_hash,
        privacy_verifier_config_hash: bridge().privacy_verifier_config_hash,
        randomx_receipt_image_id: [0x25; 32],
        height,
        block_hash,
        native_state_root: *native_state_root.as_bytes(),
        economic_utxo_root,
        economic_kernel_root,
        total_difficulty: [0x26; 32],
        context: CheckpointContext {
            checkpoint_height: height,
            checkpoint_block: block_hash,
            max_span: 390,
            economic_state_root: checkpoint_economic_state_root(
                economic_utxo_root,
                economic_kernel_root,
            )
            .expect("economic root"),
            recent_headers,
            seed_anchor_count: 0,
            seed_anchors: [SeedAnchor::default(); CHECKPOINT_CONTEXT_MAX_SEED_ANCHORS],
        },
    }
}

#[test]
fn native_state_opening_is_canonical_and_authenticates_every_policy_root() {
    let native = NativeUsdomState::new(bridge())
        .expect("native state")
        .state_commitment_v2()
        .expect("candidate-v2 state");
    let opening = CheckpointSegmentNativeStateOpening::new(
        native.to_bytes().expect("canonical candidate-v2 state"),
    )
    .expect("opening");
    let state = segment_state(native.root());
    let bytes = opening.to_bytes().expect("canonical opening");

    assert_eq!(&bytes[..8], b"UDCSNS01");
    assert!(bytes.len() <= MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES);
    assert_eq!(
        CheckpointSegmentNativeStateOpening::from_bytes(&bytes).expect("decode"),
        opening
    );
    assert_eq!(opening.authenticate(&state).expect("authenticated"), native);
    assert_ne!(opening.commitment().expect("commitment"), [0; 32]);

    for end in 0..bytes.len() {
        assert!(CheckpointSegmentNativeStateOpening::from_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CheckpointSegmentNativeStateOpening::from_bytes(&trailing).is_err());

    let mut wrong_root = state;
    wrong_root.native_state_root[0] ^= 1;
    assert_eq!(
        opening.authenticate(&wrong_root),
        Err(CheckpointSegmentNativeStateOpeningError::StateMismatch)
    );
    let mut wrong_checkpoint_policy = state;
    wrong_checkpoint_policy.checkpoint_policy_hash[0] ^= 1;
    assert_eq!(
        opening.authenticate(&wrong_checkpoint_policy),
        Err(CheckpointSegmentNativeStateOpeningError::StateMismatch)
    );
    let mut wrong_deposit_policy = state;
    wrong_deposit_policy.deposit_policy_hash[0] ^= 1;
    assert_eq!(
        opening.authenticate(&wrong_deposit_policy),
        Err(CheckpointSegmentNativeStateOpeningError::StateMismatch)
    );
    let mut wrong_verifier = state;
    wrong_verifier.privacy_verifier_config_hash[0] ^= 1;
    assert_eq!(
        opening.authenticate(&wrong_verifier),
        Err(CheckpointSegmentNativeStateOpeningError::StateMismatch)
    );

    let mut corrupt_state = bytes;
    let last = corrupt_state.len() - 1;
    corrupt_state[last] ^= 1;
    let corrupt = CheckpointSegmentNativeStateOpening::from_bytes(&corrupt_state)
        .expect("framing remains valid");
    assert_eq!(
        corrupt.authenticate(&state),
        Err(CheckpointSegmentNativeStateOpeningError::InvalidState)
    );
}

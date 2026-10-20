//! RISC Zero outer guest for one complete `UDCPST04` checkpoint statement.
//!
//! The guest authenticates policy and the previous candidate-v2 state, checks
//! a bounded chain of complete segment transitions through the target and
//! confirmation suffix, verifies every receipt under the compile-time pinned
//! complete-segment ImageID, and commits only the Solidity statement hash.

#![no_main]

#[cfg(target_os = "zkvm")]
use dom_usdom_checkpoint_program::{
    validate_checkpoint_outer_chain, verify_checkpoint_segment_receipts_in_guest,
    CheckpointOuterChain, CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointStatementV4, CHECKPOINT_STATEMENT_V4_BYTES, MAX_CHECKPOINT_OUTER_CHAIN_BYTES,
    MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES, MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
};
#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

/// Candidate complete-segment ImageID frozen into this outer relation.
#[cfg(target_os = "zkvm")]
const SEGMENT_IMAGE_ID: [u8; 32] = [
    0x4e, 0x71, 0x14, 0x90, 0xf3, 0xab, 0x7d, 0xde, 0x97, 0x63, 0x66, 0x87, 0x97, 0x24, 0x56, 0xda,
    0x58, 0xda, 0x42, 0x87, 0xce, 0x50, 0x17, 0xe3, 0x8d, 0x4a, 0xca, 0xa7, 0x26, 0x3a, 0x02, 0xd6,
];

#[cfg(target_os = "zkvm")]
fn read_bounded(maximum: usize, label: &str) -> Vec<u8> {
    let length: u32 = env::read();
    let length = usize::try_from(length).expect("input length must fit usize");
    assert!(length > 0 && length <= maximum, "invalid {label} length");
    let mut bytes = vec![0u8; length];
    env::read_slice(&mut bytes);
    bytes
}

#[cfg(target_os = "zkvm")]
fn guest_main() {
    let mut statement_bytes = [0u8; CHECKPOINT_STATEMENT_V4_BYTES];
    env::read_slice(&mut statement_bytes);
    let policy_bytes = read_bounded(
        MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
        "checkpoint policy",
    );
    let opening_bytes = read_bounded(
        MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
        "checkpoint native-state opening",
    );
    let chain_bytes = read_bounded(MAX_CHECKPOINT_OUTER_CHAIN_BYTES, "checkpoint segment chain");

    let statement =
        CheckpointStatementV4::from_bytes(&statement_bytes).expect("invalid checkpoint statement");
    let policy =
        CheckpointSegmentPolicyInput::from_bytes(&policy_bytes).expect("invalid checkpoint policy");
    let opening = CheckpointSegmentNativeStateOpening::from_bytes(&opening_bytes)
        .expect("invalid checkpoint native-state opening");
    let chain =
        CheckpointOuterChain::from_bytes(&chain_bytes).expect("invalid checkpoint segment chain");
    let executed =
        validate_checkpoint_outer_chain(&statement, &chain, &policy, &opening, SEGMENT_IMAGE_ID)
            .expect("checkpoint outer composition failed");
    verify_checkpoint_segment_receipts_in_guest(executed.segment_receipts())
        .expect("segment receipt assumption verification is infallible");
    env::commit_slice(&executed.statement_hash());
}

#[cfg(not(target_os = "zkvm"))]
#[allow(clippy::panic)]
fn guest_main() {
    panic!("checkpoint outer guest must execute inside the RISC Zero zkVM");
}

risc0_zkvm::guest::entry!(guest_main);

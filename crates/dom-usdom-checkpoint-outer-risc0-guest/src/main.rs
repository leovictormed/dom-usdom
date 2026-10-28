//! RISC Zero outer guest for one complete `UDCPST06` checkpoint statement.
//!
//! The guest authenticates policy and the previous candidate-v2 state, checks
//! a bounded chain of complete segment transitions through the target and
//! confirmation suffix, verifies every receipt under the compile-time pinned
//! complete-segment ImageID, and commits only the Solidity statement hash.

#![no_main]

#[cfg(target_os = "zkvm")]
use dom_usdom_checkpoint_program::{
    validate_checkpoint_outer_chain_v6, verify_checkpoint_segment_receipts_in_guest,
    CheckpointOuterChain, CheckpointSegmentNativeStateOpening, CheckpointSegmentPolicyInput,
    CheckpointStatementV6, CHECKPOINT_STATEMENT_V6_BYTES, MAX_CHECKPOINT_OUTER_CHAIN_BYTES,
    MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES, MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
};
#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

/// Candidate complete-segment ImageID frozen into this outer relation.
#[cfg(target_os = "zkvm")]
const SEGMENT_IMAGE_ID: [u8; 32] = [
    0x37, 0x1e, 0x40, 0x8b, 0x36, 0x0a, 0x0e, 0x4a, 0x0a, 0xae, 0x2c, 0xb9, 0x94, 0xbd, 0xdb, 0x2d,
    0x66, 0xaf, 0xcc, 0x58, 0x91, 0xa7, 0xed, 0x57, 0x4f, 0xa8, 0x31, 0x19, 0x73, 0x4b, 0xfb, 0xf7,
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
    let mut statement_bytes = [0u8; CHECKPOINT_STATEMENT_V6_BYTES];
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
        CheckpointStatementV6::from_bytes(&statement_bytes).expect("invalid checkpoint statement");
    let policy =
        CheckpointSegmentPolicyInput::from_bytes(&policy_bytes).expect("invalid checkpoint policy");
    let opening = CheckpointSegmentNativeStateOpening::from_bytes(&opening_bytes)
        .expect("invalid checkpoint native-state opening");
    let chain =
        CheckpointOuterChain::from_bytes(&chain_bytes).expect("invalid checkpoint segment chain");
    let executed =
        validate_checkpoint_outer_chain_v6(&statement, &chain, &policy, &opening, SEGMENT_IMAGE_ID)
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

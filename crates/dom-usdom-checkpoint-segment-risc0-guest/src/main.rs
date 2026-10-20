//! RISC Zero guest for one complete bounded `UDCSTN02` segment.
//!
//! The guest authenticates the previous candidate-v2 native state, rebuilds
//! every immutable policy, validates each canonical DOM block and proof
//! envelope, executes native USDOM and ordinary economic transitions, and
//! verifies the exact state-pinned RandomX receipt for every header. It commits
//! only the 32-byte transition commitment after all relations succeed.

#![no_main]

#[cfg(target_os = "zkvm")]
use dom_usdom_checkpoint_program::{
    execute_checkpoint_segment_portable, verify_checkpoint_economic_block_receipts_in_guest,
    verify_checkpoint_segment_randomx_bindings_in_guest, CheckpointSegmentNativeStateOpening,
    CheckpointSegmentPolicyInput, CheckpointSegmentPrivateInput, CheckpointSegmentTransition,
    CHECKPOINT_SEGMENT_TRANSITION_BYTES, MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
    MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES, MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
};
#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

#[cfg(target_os = "zkvm")]
const ECONOMIC_BLOCK_IMAGE_ID: [u8; 32] = [
    0x03, 0xdc, 0x11, 0x1f, 0xee, 0x3c, 0x42, 0xa7, 0x72, 0xf1, 0x42, 0xc8, 0x0d, 0x4a, 0x92, 0x1a,
    0x19, 0xbd, 0xe1, 0x0f, 0x93, 0x2f, 0x86, 0xc8, 0x88, 0x60, 0x65, 0x03, 0xa2, 0x8c, 0x22, 0xa7,
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
    let mut transition_bytes = [0u8; CHECKPOINT_SEGMENT_TRANSITION_BYTES];
    env::read_slice(&mut transition_bytes);
    let policy_bytes = read_bounded(
        MAX_CHECKPOINT_SEGMENT_POLICY_INPUT_BYTES,
        "checkpoint segment policy",
    );
    let opening_bytes = read_bounded(
        MAX_CHECKPOINT_SEGMENT_NATIVE_OPENING_BYTES,
        "checkpoint segment native opening",
    );
    let private_input_bytes = read_bounded(
        MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
        "checkpoint segment private input",
    );

    let transition = CheckpointSegmentTransition::from_bytes(&transition_bytes)
        .expect("invalid checkpoint segment transition");
    let policy = CheckpointSegmentPolicyInput::from_bytes(&policy_bytes)
        .expect("invalid checkpoint segment policy");
    let opening = CheckpointSegmentNativeStateOpening::from_bytes(&opening_bytes)
        .expect("invalid checkpoint segment native-state opening");
    let private_input = CheckpointSegmentPrivateInput::from_bytes(&private_input_bytes)
        .expect("invalid checkpoint segment private input");
    let executed =
        execute_checkpoint_segment_portable(&transition, &private_input, &policy, &opening)
            .expect("checkpoint segment execution failed");
    verify_checkpoint_segment_randomx_bindings_in_guest(executed.randomx_bindings())
        .expect("RandomX receipt assumption verification is infallible");
    verify_checkpoint_economic_block_receipts_in_guest(
        executed.economic_block_bindings(),
        ECONOMIC_BLOCK_IMAGE_ID,
    )
    .expect("economic block receipt assumption verification is infallible");
    env::commit_slice(&executed.transition_commitment());
}

#[cfg(not(target_os = "zkvm"))]
#[allow(clippy::panic)]
fn guest_main() {
    panic!("checkpoint segment guest must execute inside the RISC Zero zkVM");
}

risc0_zkvm::guest::entry!(guest_main);

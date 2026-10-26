//! RISC Zero component guest for ordered per-header RandomX receipts.
//!
//! This guest commits `UDCRXAG1`, a distinct component journal. It does not
//! execute ordinary DOM economic validation or native USDOM state transitions
//! and therefore cannot emit or replace a complete UDCSTN04 checkpoint proof.

#![no_main]

#[cfg(target_os = "zkvm")]
use dom_usdom_checkpoint_program::{
    checkpoint_segment_randomx_aggregate, CheckpointSegmentPrivateInput,
    CheckpointSegmentTransition, CHECKPOINT_SEGMENT_TRANSITION_BYTES,
    MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
};
#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

#[cfg(target_os = "zkvm")]
use dom_usdom_checkpoint_program::verify_checkpoint_segment_randomx_bindings_in_guest;

#[cfg(target_os = "zkvm")]
fn guest_main() {
    let mut transition_bytes = [0u8; CHECKPOINT_SEGMENT_TRANSITION_BYTES];
    env::read_slice(&mut transition_bytes);
    let mut genesis_hash = [0u8; 32];
    env::read_slice(&mut genesis_hash);
    let private_input_len: u32 = env::read();
    let private_input_len =
        usize::try_from(private_input_len).expect("private input length must fit usize");
    assert!(
        private_input_len > 0 && private_input_len <= MAX_CHECKPOINT_SEGMENT_PRIVATE_INPUT_BYTES,
        "invalid checkpoint segment private input length"
    );
    let mut private_input_bytes = vec![0u8; private_input_len];
    env::read_slice(&mut private_input_bytes);

    let transition = CheckpointSegmentTransition::from_bytes(&transition_bytes)
        .expect("invalid checkpoint segment transition");
    let private_input = CheckpointSegmentPrivateInput::from_bytes(&private_input_bytes)
        .expect("invalid checkpoint segment private input");
    let (aggregate, bindings) =
        checkpoint_segment_randomx_aggregate(&transition, &private_input, genesis_hash)
            .expect("invalid checkpoint segment RandomX aggregate");

    verify_checkpoint_segment_randomx_bindings_in_guest(&bindings)
        .expect("RandomX receipt assumption verification is infallible");

    env::commit_slice(&aggregate.commitment().expect("valid aggregate commitment"));
}

#[cfg(not(target_os = "zkvm"))]
fn guest_main() {
    panic!("RandomX aggregate guest must execute inside the RISC Zero zkVM");
}

risc0_zkvm::guest::entry!(guest_main);

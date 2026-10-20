//! RISC Zero guest for one bounded `UDECTN01` economic-state chunk.

#![no_main]

#[cfg(target_os = "zkvm")]
use dom_usdom_checkpoint_program::{
    execute_economic_chunk_portable, EconomicChunkTransition, EconomicChunkWitness,
    ECONOMIC_CHUNK_TRANSITION_BYTES, MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES,
    MAX_ECONOMIC_CHUNK_WITNESS_BYTES,
};
#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

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
    let mut transition_bytes = [0u8; ECONOMIC_CHUNK_TRANSITION_BYTES];
    env::read_slice(&mut transition_bytes);
    let package_bytes = read_bounded(MAX_CHECKPOINT_SEGMENT_PACKAGE_BYTES, "DOM v4 package");
    let witness_bytes = read_bounded(MAX_ECONOMIC_CHUNK_WITNESS_BYTES, "economic chunk witness");
    let transition = EconomicChunkTransition::from_bytes(&transition_bytes)
        .expect("invalid economic chunk transition");
    let witness =
        EconomicChunkWitness::from_bytes(&witness_bytes).expect("invalid economic chunk witness");
    let executed = execute_economic_chunk_portable(
        &package_bytes,
        &witness,
        transition.network_magic,
        transition.previous_roots,
    )
    .expect("economic chunk execution failed");
    assert_eq!(executed, transition, "economic chunk statement mismatch");
    env::commit_slice(&executed.commitment().expect("valid economic chunk journal"));
}

#[cfg(not(target_os = "zkvm"))]
#[allow(clippy::panic)]
fn guest_main() {
    panic!("economic chunk guest must execute inside the RISC Zero zkVM");
}

risc0_zkvm::guest::entry!(guest_main);

//! RISC Zero guest for one canonical DOM `UDCRXST1` RandomX statement.

#![no_main]

#[cfg(target_os = "zkvm")]
use dom_usdom_checkpoint_statement::{
    CheckpointRandomXStatement, CHECKPOINT_RANDOMX_STATEMENT_BYTES,
};
#[cfg(target_os = "zkvm")]
use dom_usdom_randomx_portable::{
    dataset::{build_randomx_argon_cache, calculate_randomx_light_hash},
    generate_randomx_superscalar_configuration,
};
#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

#[cfg(target_os = "zkvm")]
fn guest_main() {
    let mut statement_bytes = [0u8; CHECKPOINT_RANDOMX_STATEMENT_BYTES];
    env::read_slice(&mut statement_bytes);
    let statement = CheckpointRandomXStatement::from_bytes(&statement_bytes)
        .expect("canonical UDCRXST1 statement");

    let cache = build_randomx_argon_cache(&statement.seed_hash)
        .expect("canonical RandomX cache construction");
    let configuration = generate_randomx_superscalar_configuration(&statement.seed_hash);
    let actual = calculate_randomx_light_hash(&statement.pow_preimage, &cache, &configuration)
        .expect("canonical RandomX relation evaluation");
    assert_eq!(
        actual, statement.randomx_hash,
        "claimed RandomX digest mismatch"
    );

    let journal = statement
        .commitment()
        .expect("validated UDCRXST1 commitment");
    env::commit_slice(&journal);
}

#[cfg(not(target_os = "zkvm"))]
#[allow(clippy::panic)]
fn guest_main() {
    panic!("RandomX guest must execute inside the RISC Zero zkVM");
}

risc0_zkvm::guest::entry!(guest_main);

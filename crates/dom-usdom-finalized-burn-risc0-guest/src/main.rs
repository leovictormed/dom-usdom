//! RISC Zero guest for one canonical `UDFINL04` finalized-burn proof.
//!
//! The host transport is one zkVM-codec `u32` byte length followed by exactly
//! that many raw private bytes. The proven relation receives only the raw bytes
//! and the journal contains only the unframed 32-byte public statement hash.

#![no_main]

use dom_usdom_finalized_burn_program::{
    execute_with_checkpoint_assumption, MAX_FINALIZED_BURN_PROVER_INPUT_BYTES,
};
use risc0_zkvm::guest::env;

fn guest_main() {
    let input_len: u32 = env::read();
    let input_len = usize::try_from(input_len).expect("input length must fit usize");
    assert!(
        input_len > 0 && input_len <= MAX_FINALIZED_BURN_PROVER_INPUT_BYTES,
        "invalid finalized-burn input length"
    );

    let mut input = vec![0u8; input_len];
    env::read_slice(&mut input);
    let execution =
        execute_with_checkpoint_assumption(&input).expect("invalid finalized-burn proof input");
    let checkpoint = execution.checkpoint_receipt();
    env::verify(
        risc0_zkvm::sha::Digest::from(*checkpoint.image_id()),
        checkpoint.journal().as_slice(),
    )
    .expect("checkpoint-outer receipt assumption verification is infallible");
    env::commit_slice(execution.output().as_bytes());
}

risc0_zkvm::guest::entry!(guest_main);

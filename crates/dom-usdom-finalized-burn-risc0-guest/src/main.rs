//! RISC Zero guest for one canonical `UDFINL02` finalized-burn proof.
//!
//! The host transport is one zkVM-codec `u32` byte length followed by exactly
//! that many raw private bytes. The proven relation receives only the raw bytes
//! and the journal contains only the unframed 32-byte public statement hash.

#![no_main]

use dom_usdom_finalized_burn_program::{execute, MAX_FINALIZED_BURN_PROVER_INPUT_BYTES};
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
    let output = execute(&input).expect("invalid finalized-burn proof input");
    env::commit_slice(output.as_bytes());
}

risc0_zkvm::guest::entry!(guest_main);

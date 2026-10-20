//! Recursive RISC Zero aggregator for one complete economic block transition.

#![no_main]

#[cfg(target_os = "zkvm")]
use dom_usdom_economic_block_program::{
    validate_economic_block_chain, verify_economic_chunk_receipts_in_guest,
    EconomicBlockTransition, EconomicChunkChain, ECONOMIC_BLOCK_TRANSITION_BYTES,
    MAX_ECONOMIC_CHUNK_CHAIN_BYTES,
};
#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

#[cfg(target_os = "zkvm")]
const CHUNK_IMAGE_ID: [u8; 32] = [
    0x67, 0xd2, 0x86, 0xe0, 0x44, 0x44, 0xb5, 0x23, 0x05, 0xec, 0x40, 0x9d, 0xe3, 0xc0, 0xd2, 0x2b,
    0x21, 0x31, 0xa4, 0x2f, 0x2a, 0xa6, 0x70, 0x6f, 0x08, 0x7a, 0xce, 0x25, 0x30, 0x48, 0xe3, 0x50,
];

#[cfg(target_os = "zkvm")]
fn guest_main() {
    let mut block_bytes = [0u8; ECONOMIC_BLOCK_TRANSITION_BYTES];
    env::read_slice(&mut block_bytes);
    let length: u32 = env::read();
    let length = usize::try_from(length).expect("chain length must fit usize");
    assert!(
        length > 0 && length <= MAX_ECONOMIC_CHUNK_CHAIN_BYTES,
        "invalid chunk chain length"
    );
    let mut chain_bytes = vec![0u8; length];
    env::read_slice(&mut chain_bytes);
    let block = EconomicBlockTransition::from_bytes(&block_bytes)
        .expect("invalid economic block transition");
    let chain = EconomicChunkChain::from_bytes(&chain_bytes).expect("invalid economic chunk chain");
    let execution = validate_economic_block_chain(&block, &chain, CHUNK_IMAGE_ID)
        .expect("economic block composition failed");
    verify_economic_chunk_receipts_in_guest(execution.chunk_receipts())
        .expect("chunk receipt verification is infallible");
    env::commit_slice(&execution.block_commitment());
}

#[cfg(not(target_os = "zkvm"))]
#[allow(clippy::panic)]
fn guest_main() {
    panic!("economic block guest must execute inside the RISC Zero zkVM");
}

risc0_zkvm::guest::entry!(guest_main);

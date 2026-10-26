//! Explicit local proving lifecycle for authenticated economic jobs.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_economic_proof_host::{prove_receipt_set, ProofPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this economic prover accepts no arguments or field overrides".into());
    }
    let summary = prove_receipt_set(&ProofPaths::production())?;
    println!("status: proved-and-verified");
    println!("chunk_receipt_count: {}", summary.chunk_receipt_count);
    println!("block_receipt_count: {}", summary.block_receipt_count);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("receipt_index_sha256: {}", summary.receipt_index_sha256);
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("economic receipt-set proving failed");
        std::process::exit(1);
    }
}

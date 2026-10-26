//! Fixed production entry point for explicitly authorized local outer proving.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_checkpoint_proof_host::{prove_outer_checkpoint, OuterProofPaths};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().len() != 1 {
        return Err("this checkpoint outer prover accepts no arguments or field overrides".into());
    }
    let summary = prove_outer_checkpoint(&OuterProofPaths::production())?;
    println!("status: proved");
    println!("statement_hash: {}", summary.statement_hash);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("receipt_index_sha256: {}", summary.receipt_index_sha256);
    println!("receipt_kind: succinct");
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("checkpoint outer proving failed");
        std::process::exit(1);
    }
}

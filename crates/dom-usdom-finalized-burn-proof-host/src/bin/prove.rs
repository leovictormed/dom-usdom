//! Fixed entry point for explicitly authorized local finalized-burn proving.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_finalized_burn_proof_host::{prove_finalized_burn, ProofPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this finalized-burn prover accepts no arguments or field overrides".into());
    }
    let summary = prove_finalized_burn(&ProofPaths::production())?;
    println!("status: proved-and-verified");
    println!("statement_hash: {}", summary.statement_hash);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("receipt_index_sha256: {}", summary.receipt_index_sha256);
    println!("reused_receipt: {}", summary.reused_receipt);
    println!(
        "reused_composite_receipt: {}",
        summary.reused_composite_receipt
    );
    println!("segment_limit_po2: {}", summary.segment_limit_po2);
    println!("receipt_kind: succinct");
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("finalized-burn proving failed");
        std::process::exit(1);
    }
}

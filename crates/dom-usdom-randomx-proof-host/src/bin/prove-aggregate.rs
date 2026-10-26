//! Prove and verify every authenticated RandomX segment aggregate.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_randomx_proof_host::{prove_aggregate_set, AggregateProofPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this aggregate prover accepts no arguments or field overrides".into());
    }
    let summary = prove_aggregate_set(&AggregateProofPaths::production())?;
    println!("status: proved-and-verified");
    println!("aggregate_receipt_count: {}", summary.receipt_count);
    println!("aggregate_job_index_sha256: {}", summary.job_index_sha256);
    println!(
        "aggregate_receipt_index_sha256: {}",
        summary.receipt_index_sha256
    );
    println!("receipt_kind: succinct");
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("RandomX aggregate proving failed");
        std::process::exit(1);
    }
}

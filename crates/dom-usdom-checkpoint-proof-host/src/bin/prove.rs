//! Fixed production entry point for explicitly authorized local segment proving.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_checkpoint_proof_host::{prove_segment_set, SegmentProofPaths};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().len() != 1 {
        return Err(
            "this checkpoint segment prover accepts no arguments or field overrides".into(),
        );
    }
    let summary = prove_segment_set(&SegmentProofPaths::production())?;
    println!("status: proved");
    println!("segment_receipt_count: {}", summary.segment_receipt_count);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("receipt_index_sha256: {}", summary.receipt_index_sha256);
    println!("receipt_kind: succinct");
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("checkpoint segment proving failed");
        std::process::exit(1);
    }
}

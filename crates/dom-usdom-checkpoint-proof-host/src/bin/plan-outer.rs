//! Fixed production entry point for authenticated outer-checkpoint job planning.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_checkpoint_proof_host::{publish_outer_plan, OuterPlanPaths};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().len() != 1 {
        return Err("this checkpoint outer planner accepts no arguments or field overrides".into());
    }
    let summary = publish_outer_plan(&OuterPlanPaths::production())?;
    println!("status: planned");
    println!("segment_receipt_count: {}", summary.segment_receipt_count);
    println!("statement_hash: {}", summary.statement_hash);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("executes_guests: false");
    println!("generates_proofs: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("checkpoint outer planning failed");
        std::process::exit(1);
    }
}

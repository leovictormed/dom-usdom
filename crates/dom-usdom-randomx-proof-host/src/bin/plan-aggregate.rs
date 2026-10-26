//! Build aggregate proof jobs from verified per-block RandomX receipts.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_randomx_proof_host::{publish_aggregate_plan, AggregatePlanPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this aggregate planner accepts no arguments or field overrides".into());
    }
    let summary = publish_aggregate_plan(&AggregatePlanPaths::production())?;
    println!("status: planned");
    println!("aggregate_job_count: {}", summary.job_count);
    println!(
        "receipt_set_index_sha256: {}",
        summary.receipt_set_index_sha256
    );
    println!("aggregate_job_index_sha256: {}", summary.job_index_sha256);
    println!("proofs_generated: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("RandomX aggregate planning failed");
        std::process::exit(1);
    }
}

//! Build exact non-proving jobs for authenticated economic chunk and block sources.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_economic_proof_host::{publish_plan, PlanPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this economic planner accepts no arguments or field overrides".into());
    }
    let summary = publish_plan(&PlanPaths::production())?;
    println!("status: planned");
    println!("block_job_count: {}", summary.block_job_count);
    println!("chunk_job_count: {}", summary.chunk_job_count);
    println!(
        "economic_source_index_sha256: {}",
        summary.economic_source_index_sha256
    );
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("proofs_generated: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("economic receipt-set planning failed");
        std::process::exit(1);
    }
}

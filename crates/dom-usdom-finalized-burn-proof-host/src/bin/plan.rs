//! Fixed entry point for authenticated finalized-burn proof planning.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_finalized_burn_proof_host::{plan_finalized_burn, PlanPaths};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().len() != 1 {
        return Err("this finalized-burn planner accepts no arguments or field overrides".into());
    }
    let summary = plan_finalized_burn(&PlanPaths::production())?;
    println!("status: planned");
    println!("statement_hash: {}", summary.statement_hash);
    println!("input_sha256: {}", summary.input_sha256);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("generates_proofs: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("finalized-burn planning failed");
        std::process::exit(1);
    }
}

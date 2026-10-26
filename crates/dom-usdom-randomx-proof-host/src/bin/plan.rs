//! Build the exact non-proving job index for an authenticated RandomX statement set.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_randomx_proof_host::{publish_plan, PlanPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this planner accepts no arguments or field overrides".into());
    }
    let production = PlanPaths::production();
    let paths = PlanPaths {
        statement_index: production.statement_index,
        statement_directory: production.statement_directory,
        elf: production.elf,
        program: production.program,
        image_id: production.image_id,
        output_directory: production.output_directory,
    };
    let summary = publish_plan(&paths)?;
    println!("status: planned");
    println!("job_count: {}", summary.job_count);
    println!("statement_index_sha256: {}", summary.statement_index_sha256);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("proofs_generated: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("RandomX receipt-set planning failed");
        std::process::exit(1);
    }
}

//! Prove and verify every job in the exact RandomX receipt-set plan.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_randomx_proof_host::{prove_receipt_set, PlanPaths, ProofPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err("this prover accepts no arguments or field overrides".into());
    }
    let production = ProofPaths::production();
    let paths = ProofPaths {
        plan: PlanPaths {
            statement_index: production.plan.statement_index,
            statement_directory: production.plan.statement_directory,
            elf: production.plan.elf,
            program: production.plan.program,
            image_id: production.plan.image_id,
            output_directory: production.plan.output_directory,
        },
        job_index: production.job_index,
        output_directory: production.output_directory,
    };
    let summary = prove_receipt_set(&paths)?;
    println!("status: proved-and-verified");
    println!("receipt_count: {}", summary.receipt_count);
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("receipt_index_sha256: {}", summary.receipt_index_sha256);
    println!("receipt_kind: succinct");
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("RandomX receipt-set proving failed");
        std::process::exit(1);
    }
}

//! Fixed production entry point for authenticated checkpoint-segment job planning.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_checkpoint_proof_host::{publish_segment_plan, SegmentPlanPaths};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().len() != 1 {
        return Err(
            "this checkpoint segment planner accepts no arguments or field overrides".into(),
        );
    }
    let summary = publish_segment_plan(&SegmentPlanPaths::production())?;
    println!("status: planned");
    println!("segment_job_count: {}", summary.segment_job_count);
    println!("source_index_sha256: {}", summary.source_index_sha256);
    println!(
        "randomx_receipt_index_sha256: {}",
        summary.randomx_receipt_index_sha256
    );
    println!(
        "economic_receipt_index_sha256: {}",
        summary.economic_receipt_index_sha256
    );
    println!("job_index_sha256: {}", summary.job_index_sha256);
    println!("executes_guests: false");
    println!("generates_proofs: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("checkpoint segment planning failed");
        std::process::exit(1);
    }
}

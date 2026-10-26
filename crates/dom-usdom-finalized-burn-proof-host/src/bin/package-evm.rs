//! Fixed entry point for authorized finalized-burn Groth16 compression and EVM packaging.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_finalized_burn_proof_host::{package_finalized_burn_evm_proof, EvmProofPaths};

fn run() -> Result<(), String> {
    if env::args_os().len() != 1 {
        return Err(
            "this finalized-burn EVM packager accepts no arguments or field overrides".into(),
        );
    }
    let summary = package_finalized_burn_evm_proof(&EvmProofPaths::production())?;
    println!("status: packaged-and-verified");
    println!("statement_hash: {}", summary.statement_hash);
    println!("evm_seal_sha256: {}", summary.evm_seal_sha256);
    println!("package_index_sha256: {}", summary.package_index_sha256);
    println!("reused_groth16_receipt: {}", summary.reused_groth16_receipt);
    println!("receipt_kind: groth16");
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("finalized-burn EVM packaging failed");
        std::process::exit(1);
    }
}

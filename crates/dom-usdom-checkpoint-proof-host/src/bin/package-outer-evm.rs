//! Fixed entry point for authorized local Groth16 compression and EVM packaging.

#![deny(unsafe_code)]

use std::env;

use dom_usdom_checkpoint_proof_host::{package_outer_evm_proof, OuterEvmProofPaths};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().len() != 1 {
        return Err("this checkpoint EVM packager accepts no arguments or field overrides".into());
    }
    let summary = package_outer_evm_proof(&OuterEvmProofPaths::production())?;
    println!("status: packaged");
    println!("statement_hash: {}", summary.statement_hash);
    println!("evm_seal_sha256: {}", summary.evm_seal_sha256);
    println!("package_index_sha256: {}", summary.package_index_sha256);
    println!("receipt_kind: groth16");
    println!("dev_mode: false");
    println!("mines: false");
    Ok(())
}

fn main() {
    if let Err(_error) = run() {
        eprintln!("checkpoint EVM packaging failed");
        std::process::exit(1);
    }
}

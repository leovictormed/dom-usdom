//! Host reference entrypoint for the deterministic finalized-burn program.
//!
//! A future audited zkVM guest should call the library's `execute` function and
//! commit the same exact 32 output bytes through its backend-specific journal.

use std::io::{self, Read, Write};

use dom_usdom_finalized_burn_program::execute;
use dom_usdom_finalized_burn_program::MAX_FINALIZED_BURN_PROVER_INPUT_BYTES;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let maximum_read = MAX_FINALIZED_BURN_PROVER_INPUT_BYTES
        .checked_add(1)
        .ok_or("finalized-burn input limit overflow")?;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(maximum_read as u64)
        .read_to_end(&mut input)?;
    let output = execute(&input)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(output.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

//! Host reference for the canonical checkpoint public-statement hash.
//!
//! This executable is a codec/hash conformance tool, not a consensus verifier.

use std::io::{self, Read, Write};

use dom_usdom_checkpoint_statement::{hash_canonical_statement_v6, CHECKPOINT_STATEMENT_V6_BYTES};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((CHECKPOINT_STATEMENT_V6_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() != CHECKPOINT_STATEMENT_V6_BYTES {
        return Err("invalid checkpoint statement length".into());
    }
    let output = hash_canonical_statement_v6(&input)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.flush()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

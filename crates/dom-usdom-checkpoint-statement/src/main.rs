//! Host reference for the canonical checkpoint public-statement hash.
//!
//! This executable is a codec/hash conformance tool, not a consensus verifier.

use std::io::{self, Read, Write};

use dom_usdom_checkpoint_statement::{
    hash_canonical_statement, hash_canonical_statement_v4, CHECKPOINT_STATEMENT_BYTES,
    CHECKPOINT_STATEMENT_V4_BYTES,
};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((CHECKPOINT_STATEMENT_V4_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    let output = match input.len() {
        CHECKPOINT_STATEMENT_BYTES => hash_canonical_statement(&input)?,
        CHECKPOINT_STATEMENT_V4_BYTES => hash_canonical_statement_v4(&input)?,
        _ => return Err("invalid checkpoint statement length".into()),
    };
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

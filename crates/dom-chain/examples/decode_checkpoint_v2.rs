#[cfg(feature = "ethereum-checkpoint-poc")]
fn main() {
    let encoded = std::env::args()
        .nth(1)
        .unwrap_or_else(|| fail("expected one hex-encoded checkpoint"));
    let bytes = hex::decode(encoded).unwrap_or_else(|_| fail("invalid hex"));
    let checkpoint = dom_chain::ethereum_checkpoint_poc::decode_test_oracle_v2(&bytes)
        .unwrap_or_else(|error| fail(&error.to_string()));
    println!("height={}", checkpoint.height);
    println!("dom_block={}", hex::encode(checkpoint.dom_block.as_bytes()));
    println!("dom_network_magic={}", checkpoint.dom_network_magic);
    println!("ethereum_chain_id={}", checkpoint.ethereum_chain_id);
    println!("ethereum_block_number={}", checkpoint.ethereum_block_number);
    println!(
        "ethereum_block={}",
        hex::encode(checkpoint.ethereum_block.as_bytes())
    );
    println!("transaction_index={}", checkpoint.transaction_index);
    println!("receipt_log_index={}", checkpoint.receipt_log_index);
    println!(
        "checkpoint_contract={}",
        hex::encode(checkpoint.checkpoint_contract)
    );
    println!(
        "checkpoint_config_hash={}",
        hex::encode(checkpoint.checkpoint_config_hash.as_bytes())
    );
    println!(
        "checkpoint_event_digest={}",
        hex::encode(checkpoint.checkpoint_event_digest.as_bytes())
    );
}

#[cfg(feature = "ethereum-checkpoint-poc")]
fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2)
}

#[cfg(not(feature = "ethereum-checkpoint-poc"))]
fn main() {
    eprintln!("enable ethereum-checkpoint-poc");
    std::process::exit(2);
}

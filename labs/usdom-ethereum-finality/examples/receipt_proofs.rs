use std::{env, fs};

use alloy::primitives::{Bytes, B256};
use alloy_trie::{proof::ProofRetainer, root::adjust_index_for_rlp, HashBuilder, Nibbles};
use serde::Serialize;

#[derive(Serialize)]
struct Output {
    root: B256,
    proofs: Vec<Vec<Bytes>>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: receipt_proofs <json-file>")?;
    let values: Vec<String> = serde_json::from_slice(&fs::read(path)?)?;
    if values.is_empty() {
        return Err("empty receipt list".into());
    }
    let receipts: Vec<Bytes> = values
        .iter()
        .map(|value| value.parse())
        .collect::<Result<_, _>>()?;
    let mut proofs = Vec::with_capacity(receipts.len());
    let mut root = B256::ZERO;
    for target in 0..receipts.len() {
        let target_key = Nibbles::unpack(alloy_rlp::encode(target as u64));
        let retainer = ProofRetainer::new(vec![target_key]);
        let mut builder = HashBuilder::default().with_proof_retainer(retainer);
        for index in 0..receipts.len() {
            let adjusted = adjust_index_for_rlp(index, receipts.len());
            builder.add_leaf(
                Nibbles::unpack(alloy_rlp::encode(adjusted as u64)),
                receipts[adjusted].as_ref(),
            );
        }
        let candidate_root = builder.root();
        if target == 0 {
            root = candidate_root;
        } else if candidate_root != root {
            return Err("receipt trie root changed between proof builds".into());
        }
        proofs.push(
            builder
                .take_proof_nodes()
                .into_nodes_sorted()
                .into_iter()
                .map(|(_, node)| node)
                .collect(),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&Output { root, proofs })?
    );
    Ok(())
}

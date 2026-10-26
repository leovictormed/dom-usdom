import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const crates = path.join(repo, "crates");

function rustSources() {
  return fs.readdirSync(crates, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("dom-usdom-"))
    .flatMap((entry) => {
      const root = path.join(crates, entry.name);
      const pending = [root];
      const result = [];
      while (pending.length !== 0) {
        const current = pending.pop();
        for (const child of fs.readdirSync(current, { withFileTypes: true })) {
          if (child.name === "target" || child.name === "tests") continue;
          const absolute = path.join(current, child.name);
          if (child.isDirectory()) pending.push(absolute);
          else if (child.isFile() && child.name.endsWith(".rs")) result.push(absolute);
        }
      }
      return result;
    })
    .sort();
}

function production(source) {
  return source.split(/#\[cfg\(test\)\]\s*\nmod tests?\s*\{/u, 1)[0];
}

function inventory(sources) {
  const patterns = [
    "Sha256::new(",
    "Keccak256::new(",
    "Sha256::digest(",
    "Keccak256::digest(",
    "blake2b_256_tagged(",
    "blake2b_256(",
  ];
  const calls = Object.fromEntries(patterns.map((pattern) => [pattern, 0]));
  const domains = [];
  for (const file of sources) {
    const source = production(fs.readFileSync(file, "utf8"));
    for (const pattern of patterns) calls[pattern] += source.split(pattern).length - 1;
    for (const match of source.matchAll(/b?"(DOM:[^"\\]+)"/gu)) domains.push(match[1]);
  }
  return { calls, domains };
}

test("all Rust USDOM cryptographic constructions remain inventoried and domain literals unique", () => {
  const sources = rustSources();
  assert.equal(sources.length, 59);
  const { calls, domains } = inventory(sources);
  assert.deepEqual(calls, {
    "Sha256::new(": 4,
    "Keccak256::new(": 10,
    "Sha256::digest(": 4,
    "Keccak256::digest(": 14,
    "blake2b_256_tagged(": 34,
    "blake2b_256(": 5,
  });
  assert.equal(domains.length, 48);
  assert.equal(new Set(domains).size, domains.length, "a DOM hash-domain literal was reused");
});

test("variable and aggregate commitments bind canonical framing and cardinality", () => {
  const privacy = fs.readFileSync(path.join(crates, "dom-usdom-privacy/src/lib.rs"), "utf8");
  assert.match(privacy, /digest\.update\(HASH_TO_FIELD_TAG\);[\s\S]*digest\.update\(domain\.to_be_bytes\(\)\);[\s\S]*digest\.update\(\(bytes\.len\(\) as u64\)\.to_be_bytes\(\)\);[\s\S]*digest\.update\(bytes\);/u);

  const checkpoint = fs.readFileSync(path.join(crates, "dom-usdom-checkpoint-program/src/lib.rs"), "utf8");
  assert.match(checkpoint, /receipt_set\.update\(CHECKPOINT_RANDOMX_RECEIPT_SET_DOMAIN\);[\s\S]*receipt_set\.update\(transition\.block_count\.to_be_bytes\(\)\);/u);
  assert.match(checkpoint, /hasher\.update\(CHECKPOINT_RANDOMX_AGGREGATE_DOMAIN\);[\s\S]*hasher\.update\(self\.to_bytes\(\)\);/u);

  const chunks = fs.readFileSync(path.join(crates, "dom-usdom-checkpoint-program/src/economic_chunks.rs"), "utf8");
  assert.match(chunks, /input\.extend_from_slice\(PACKAGE_DOMAIN\);\s*input\.extend_from_slice\(package_bytes\);/u);
  assert.match(chunks, /transition\.validate\(\)\?;[\s\S]*transition\.to_bytes\(\)\?\.as_slice\(\) != bytes/u);
});

test("Ethereum-facing hashes retain typed fixed-width ABI encodings", () => {
  const state = fs.readFileSync(path.join(crates, "dom-usdom-state/src/lib.rs"), "utf8");
  assert.match(state, /Keccak256::digest\(BURN_INTENT_TYPE\.as_bytes\(\)\)[\s\S]*Vec::with_capacity\(9 \* 32\)/u);
  assert.match(state, /Keccak256::digest\(PRIVATE_BURN_ID_TYPE\.as_bytes\(\)\)[\s\S]*Vec::with_capacity\(11 \* 32\)/u);

  const burn = fs.readFileSync(path.join(crates, "dom-usdom-finalized-burn-program/src/lib.rs"), "utf8");
  assert.match(burn, /Keccak256::digest\(FINALIZED_BURN_STATEMENT_TYPE\.as_bytes\(\)\)[\s\S]*Vec::with_capacity\(14 \* 32\)/u);
});

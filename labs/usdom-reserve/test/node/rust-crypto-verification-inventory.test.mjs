import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const crates = path.join(repo, "crates");

function sources() {
  const pending = fs.readdirSync(crates, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("dom-usdom-"))
    .map((entry) => path.join(crates, entry.name));
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
  return result.sort();
}

function production(file) {
  return fs.readFileSync(file, "utf8").split(/#\[cfg\(test\)\]\s*\nmod tests?\s*\{/u, 1)[0];
}

function occurrences(text, needle) {
  return text.split(needle).length - 1;
}

test("all authoritative Rust verification primitives remain inventoried", () => {
  const files = sources();
  assert.equal(files.length, 59);
  const all = files.map(production).join("\n");
  assert.equal(occurrences(all, "Groth16::<Bn254>::verify_proof("), 1);
  assert.equal(occurrences(all, "risc0_zkvm::guest::env::verify("), 4);
  assert.equal(occurrences(all, "env::verify("), 5); // four qualified plus one direct guest call
  assert.equal(occurrences(all, ".verify(Risc0Digest::from("), 9);
  assert.equal(occurrences(all, ".verify(statement,"), 3);
  assert.equal(occurrences(all, "verify_membership("), 5); // definition plus four production consumers

  assert.doesNotMatch(all, /let\s+_\s*=\s*[^;]*verify/u);
});

test("Groth16 verification rejects malleable encodings before granting transitions", () => {
  const verifier = production(path.join(crates, "dom-usdom-privacy/src/verifier.rs"));
  assert.match(verifier, /proof_bytes\.len\(\) != GROTH16_PROOF_BYTES[\s\S]*deserialize_compressed[\s\S]*!reader\.is_empty\(\)[\s\S]*serialize_compressed[\s\S]*canonical\.as_slice\(\) != proof_bytes[\s\S]*Groth16::<Bn254>::verify_proof/u);

  const state = production(path.join(crates, "dom-usdom-state/src/lib.rs"));
  assert.match(state, /verifier\.config_hash\(\)\.as_bytes\(\) != &bridge\.privacy_verifier_config_hash[\s\S]*verifier\s*\.verify\(statement, proof\)[\s\S]*Ok\(VerifiedTransition::Transfer/u);
  assert.match(state, /derive_private_burn_id[\s\S]*verifier\s*\.verify\(statement, input\.proof\)[\s\S]*Ok\(VerifiedTransition::Burn/u);
});

test("RISC Zero receipts bind canonical bytes, kind, journal and ImageID before reuse", () => {
  const hostFiles = [
    "dom-usdom-checkpoint-proof-host/src/lib.rs",
    "dom-usdom-economic-proof-host/src/lib.rs",
    "dom-usdom-finalized-burn-proof-host/src/lib.rs",
    "dom-usdom-randomx-proof-host/src/lib.rs",
    "dom-usdom-randomx-proof-host/src/aggregate.rs",
  ];
  const host = hostFiles.map((file) => production(path.join(crates, file))).join("\n");
  assert.equal(occurrences(host, ".verify(Risc0Digest::from("), 9);
  // Eight decode boundaries reject trailing bytes. The ninth verification is
  // performed on a freshly returned typed receipt and then on its re-encoding.
  assert.equal(occurrences(host, ".reject_trailing_bytes()"), 8);
  assert.ok(occurrences(host, "is not canonically encoded") >= 9);
  assert.ok(occurrences(host, "journal") >= 9);
  for (const match of host.matchAll(/\.verify\(Risc0Digest::from\([^)]*\)\)/gu)) {
    const tail = host.slice(match.index, match.index + 300);
    assert.match(tail, /(?:map_err|\?)/u, "receipt verification result must be consumed");
  }
});

test("secret material is not used as a variable-time authentication comparison", () => {
  const all = sources().map(production).join("\n");
  assert.doesNotMatch(all, /\b(?:password|credential|bearer|auth_token)\b\s*(?:==|!=)/iu);
  assert.doesNotMatch(all, /(?:==|!=)\s*\b(?:password|credential|bearer|auth_token)\b/iu);
});

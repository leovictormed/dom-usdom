import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const source = (relative) => fs.readFileSync(path.join(repo, relative), "utf8");

test("hostile evidence JSON is bounded before serde allocation", () => {
  const lib = source("labs/usdom-ethereum-finality/src/lib.rs");
  assert.match(lib, /fn preflight_evidence_json/u);
  assert.match(lib, /MAX_EVIDENCE_JSON_DEPTH/u);
  assert.match(lib, /MAX_EVIDENCE_JSON_TOKENS/u);
  assert.match(lib, /MAX_EVIDENCE_JSON_STRING_BYTES/u);
  const transcriptPreflight = lib.indexOf("preflight_json(bytes, 64, 512 * 1024, MAX_UPDATE_BYTES + 2)?");
  const transcriptSerde = lib.indexOf("serde_json::from_slice(bytes)?", transcriptPreflight);
  assert.ok(transcriptPreflight >= 0 && transcriptSerde > transcriptPreflight);
  assert.match(lib, /count\(\)[\s\S]*<= MAX_TRANSCRIPT_UPDATES/u);

  for (const file of ["deposits.rs", "checkpoints.rs"]) {
    const body = source(`labs/usdom-ethereum-finality/src/${file}`);
    const preflight = body.indexOf("preflight_evidence_json(evidence_bytes)?");
    const deserialize = body.indexOf("serde_json::from_slice(evidence_bytes)?", preflight);
    assert.ok(preflight >= 0 && deserialize > preflight, file);
  }
});

test("all Ethereum proof families have count, item and aggregate limits before verification", () => {
  const ancestry = source("labs/usdom-ethereum-finality/src/ancestry.rs");
  const receipts = source("labs/usdom-ethereum-finality/src/receipts.rs");
  const state = source("labs/usdom-ethereum-finality/src/state.rs");
  const deposit = source("labs/usdom-ethereum-finality/src/deposits.rs");
  const checkpoint = source("labs/usdom-ethereum-finality/src/checkpoints.rs");

  assert.match(ancestry, /fn validate_ancestry_allocation_bounds/u);
  assert.match(receipts, /fn validate_receipt_allocation_bounds/u);
  assert.match(state, /fn validate_account_allocation_bounds/u);
  assert.match(state, /fn validate_storage_allocation_bounds/u);
  assert.match(state, /fn validate_runtime_code_allocation_bounds/u);
  for (const body of [deposit, checkpoint]) {
    assert.match(body, /validate_ancestry_allocation_bounds/u);
    assert.match(body, /validate_receipt_allocation_bounds/u);
    assert.match(body, /validate_account_allocation_bounds/u);
    assert.match(body, /validate_runtime_code_allocation_bounds/u);
  }
  assert.match(checkpoint, /validate_storage_allocation_bounds/u);
});

test("allocation-amplifier regressions cover depth, strings and token count", () => {
  const lib = source("labs/usdom-ethereum-finality/src/lib.rs");
  assert.match(lib, /fn evidence_json_preflight_rejects_allocation_amplifiers/u);
  assert.match(lib, /repeat\(33\)/u);
  assert.match(lib, /MAX_EVIDENCE_JSON_STRING_BYTES/u);
  assert.match(lib, /MAX_EVIDENCE_JSON_TOKENS \+ 1/u);
});

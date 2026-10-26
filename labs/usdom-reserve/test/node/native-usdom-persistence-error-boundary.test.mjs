import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const source = (relative) => fs.readFileSync(path.join(repo, relative), "utf8");

test("persisted Ethereum checkpoint corruption is classified as an internal fault", () => {
  const checkpoint = source("crates/dom-chain/src/ethereum_checkpoint_poc.rs");
  assert.match(checkpoint, /fn persisted_checkpoint_error[\s\S]*?DomError::Internal/u);
  assert.match(checkpoint, /fn decode_persisted_checkpoint[\s\S]*?persisted_checkpoint_error/u);
  assert.match(checkpoint, /decode_persisted_checkpoint\(bytes, "persisted checkpoint metadata is corrupt"\)/u);
  assert.match(checkpoint, /decode_persisted_checkpoint\(&bytes, "persisted consensus checkpoint is corrupt"\)/u);
  assert.match(checkpoint, /persisted checkpoint generations conflict/u);

  const regression = source("crates/dom-chain/tests/ethereum_checkpoint_poc.rs");
  assert.match(regression, /fn corrupt_persisted_checkpoint_is_internal_not_peer_invalidity/u);
  assert.equal((regression.match(/DomError::Internal\(_\)/gu) ?? []).length >= 2, true);
});

test("native USDOM persisted activation, snapshot, rewind and audit decoders map corruption to Internal", () => {
  const chain = source("crates/dom-chain/src/native_usdom_v4.rs");
  for (const diagnostic of [
    "persisted native USDOM v2 activation is corrupt",
    "native USDOM snapshot checkpoint is corrupt",
    "native USDOM snapshot tip header is corrupt",
    "native USDOM snapshot package is corrupt",
    "canonical native USDOM rewind package is corrupt",
    "canonical native USDOM audit header is corrupt",
    "native USDOM proof-audit package is corrupt",
    "native USDOM rewind ancestor header is corrupt",
    "native USDOM history package is corrupt",
  ]) {
    const offset = chain.indexOf(diagnostic);
    assert.notEqual(offset, -1, diagnostic);
    assert.match(chain.slice(Math.max(0, offset - 180), offset + diagnostic.length + 80), /DomError::Internal/u, diagnostic);
  }
});

test("hostile package and witness parsing remains peer-input classification and has no repair mutation", () => {
  const chain = source("crates/dom-chain/src/native_usdom_v4.rs");
  const hostile = chain.slice(
    chain.indexOf("impl NativeBurnBlockProverInput"),
    chain.indexOf("pub struct NativeUsdomV4HistoryAudit"),
  );
  assert.match(hostile, /UsdomV4BlockPackage::from_bytes\(&self\.package_bytes\)\?/u);
  assert.doesNotMatch(hostile, /delete_(?:metadata|consensus_state|block)|repair|rollback/u);
});

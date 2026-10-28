import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const roots = [
  "crates/dom-core/src",
  "crates/dom-consensus/src",
  "crates/dom-chain/src",
  "crates/dom-node/src",
  "crates/dom-store/src",
  "crates/dom-rpc/src",
  "crates/dom-wire/src",
  "crates/dom-usdom-rpc-protocol/src",
  ...fs.readdirSync(path.join(repo, "crates"))
    .filter((name) => name.startsWith("dom-usdom-"))
    .map((name) => `crates/${name}/src`),
];

function rustFiles(root) {
  const output = [];
  const pending = [path.join(repo, root)];
  while (pending.length) {
    const current = pending.pop();
    if (!fs.existsSync(current)) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (["tests", "fuzz", "target"].includes(entry.name)) continue;
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else if (entry.isFile() && entry.name.endsWith(".rs")) output.push(absolute);
    }
  }
  return output;
}

function source(relative) {
  return fs.readFileSync(path.join(repo, relative), "utf8");
}

test("all production JSON authority DTOs reject unknown fields and ambiguous enum forms", () => {
  const files = roots.flatMap(rustFiles).sort();
  let deserializeTypes = 0;
  for (const file of files) {
    const lines = fs.readFileSync(file, "utf8").split("\n");
    for (let index = 0; index < lines.length; index += 1) {
      if (!lines[index].includes("#[derive") || !/\bDeserialize\b/u.test(lines[index])) continue;
      deserializeTypes += 1;
      const declaration = lines.slice(index, index + 5).join("\n");
      assert.match(declaration, /#\[serde\([^\]]*deny_unknown_fields/u, `${file}:${index + 1}`);
    }
    const text = lines.join("\n");
    assert.doesNotMatch(text, /#\[serde\([^\]]*(?:untagged|alias)/u, file);
  }
  assert.equal(deserializeTypes, 95);
});

test("versioned USDOM scan and history requests have no silent policy fallback", () => {
  const rpc = source("crates/dom-rpc/src/lib.rs");
  for (const name of [
    "UsdomV4TransferScanAnchorRequestV1",
    "UsdomV4TransferScanRequestBodyV1",
    "UsdomV4HistoryTrustedTipRequestV1",
    "UsdomV4HistoryAnchorRequestV1",
    "UsdomV4HistoryRequestBodyV1",
  ]) {
    const offset = rpc.indexOf(`struct ${name}`);
    assert.notEqual(offset, -1, name);
    assert.match(rpc.slice(Math.max(0, offset - 100), offset), /deny_unknown_fields/u, name);
  }
  const history = rpc.slice(
    rpc.indexOf("struct UsdomV4HistoryRequestBodyV1"),
    rpc.indexOf("struct SubmitTxResponse"),
  );
  assert.match(history, /require_checkpoint_finality: bool/u);
  assert.doesNotMatch(history, /serde\(default\)/u);
});

test("unknown network and Hello versions fail closed", () => {
  const constants = source("crates/dom-core/src/constants.rs");
  const block = source("crates/dom-consensus/src/block.rs");
  const message = source("crates/dom-wire/src/message.rs");
  assert.match(constants, /NETWORK_MAGIC_MAINNET => MAINNET_V3_ACTIVATION_HEIGHT/u);
  assert.match(constants, /_ => return u32::MAX/u);
  assert.match(block, /block header names an unknown network/u);
  assert.match(block, /validate_header_syntax\(&dummy_header\(\), 0xdead_beef\)/u);
  assert.match(message, /if !matches!\(wire_version, 1 \| 2 \| 3 \| 4\)/u);
  assert.match(message, /to_bytes_for_wire_version\(u32::MAX\)\.is_err\(\)/u);
});

test("consensus and native binary tags preserve explicit reject arms", () => {
  const chain = source("crates/dom-chain/src/native_usdom_v4.rs");
  const state = source("crates/dom-usdom-state/src/lib.rs");
  const wallet = source("crates/dom-usdom-wallet/src/snapshot.rs");
  const ibd = source("crates/dom-chain/src/ibd.rs");
  assert.match(chain, /unknown native USDOM v4 proof kind/u);
  assert.match(chain, /invalid native USDOM snapshot boundary flag/u);
  assert.match(state, /_ => Err\(UsdomStateError::MalformedUndo\)/u);
  assert.match(state, /_ => return Err\(UsdomStateError::InvalidV2Commitment\)/u);
  assert.ok((wallet.match(/_ => return Err\(WalletSnapshotError::InvalidSnapshot\)/gu) ?? []).length >= 4);
  assert.match(ibd, /unknown IBD phase tag/u);
  assert.match(ibd, /unknown IBD interruption tag/u);
});

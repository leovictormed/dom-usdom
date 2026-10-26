import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");
const crates = path.join(repo, "crates");

function files() {
  const pending = fs.readdirSync(crates, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("dom-usdom-"))
    .map((entry) => path.join(crates, entry.name));
  const result = [];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name === "target" || entry.name === "tests") continue;
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else if (entry.isFile() && entry.name.endsWith(".rs")) result.push(absolute);
    }
  }
  return result.sort();
}

function production(file) {
  return fs.readFileSync(file, "utf8").split(/#\[cfg\(test\)\]\s*\nmod tests?\s*\{/u, 1)[0];
}

function count(source, needle) {
  return source.split(needle).length - 1;
}

test("Rust USDOM synchronization and publication boundaries remain inventoried", () => {
  const rust = files();
  assert.equal(rust.length, 59);
  const source = rust.map(production).join("\n");
  assert.deepEqual({
    exclusiveLocks: count(source, "lock_exclusive("),
    snapshotLocks: count(source, "SnapshotLock::acquire("),
    cloneCandidates: count(source, "let mut candidate = self.clone();"),
    candidateCommits: count(source, "*self = candidate;"),
    atomicPublishes: count(source, "atomic_publish("),
    atomicWrites: count(source, "atomic_write("),
    privateSaves: count(source, "save_private_bytes("),
    lmdbSnapshots: count(source, "begin_ro_txn("),
    metadataWrites: count(source, "put_metadata("),
  }, {
    exclusiveLocks: 5,
    snapshotLocks: 4,
    cloneCandidates: 6,
    candidateCommits: 5,
    atomicPublishes: 33,
    atomicWrites: 3,
    privateSaves: 5,
    lmdbSnapshots: 1,
    metadataWrites: 1,
  });
});

test("multi-block wallet updates either finish or restore the exact original tip", () => {
  const wallet = production(path.join(crates, "dom-usdom-wallet/src/lib.rs"));
  const history = wallet.slice(
    wallet.indexOf("pub fn apply_authenticated_history("),
    wallet.indexOf("pub fn apply_authenticated_history_and_recover_deposit("),
  );
  assert.ok(history.length > 0);
  assert.match(history, /let original_height = self\.tip_height;[\s\S]*let original_identifier = self\.tip_identifier;[\s\S]*self\.apply_block\(wallet, block\)[\s\S]*while self\.tip_height > original_height[\s\S]*self\.rollback_tip\(identifier\)[\s\S]*self\.tip_identifier != original_identifier/u);

  const recovery = wallet.slice(
    wallet.indexOf("pub fn apply_authenticated_history_and_recover_deposit("),
    wallet.indexOf("pub fn rollback_tip("),
  );
  assert.ok(recovery.length > 0);
  assert.match(recovery, /let original_height = self\.tip_height;[\s\S]*let original_identifier = self\.tip_identifier;[\s\S]*self\.apply_authenticated_history\(wallet, blocks\)\?;[\s\S]*self\.recover_canonical_deposit[\s\S]*while self\.tip_height > original_height[\s\S]*self\.rollback_tip\(identifier\)/u);
});

test("native state apply, batch and reorg commit only validated candidates", () => {
  const state = production(path.join(crates, "dom-usdom-state/src/lib.rs"));
  assert.match(state, /pub fn apply\([\s\S]*let mut candidate = self\.clone\(\);[\s\S]*candidate\.compute_state_root\(\)\?;[\s\S]*\*self = candidate;/u);
  assert.match(state, /pub fn apply_batch\([\s\S]*let mut candidate = self\.clone\(\);[\s\S]*for transition in transitions[\s\S]*\*self = candidate;/u);
  assert.match(state, /pub fn revert_batch\([\s\S]*expected_header_commitment[\s\S]*let mut candidate = self\.clone\(\);[\s\S]*candidate\.state_root != undo\.before_root[\s\S]*\*self = candidate;/u);
});

test("wallet snapshot and TPM authorities serialize their full critical sections", () => {
  const snapshot = production(path.join(crates, "dom-usdom-wallet/src/snapshot.rs"));
  assert.equal(count(snapshot, "SnapshotLock::acquire(path)?"), 4);
  assert.match(snapshot, /let _lock = SnapshotLock::acquire\(path\)\?;[\s\S]*authority\.prepare[\s\S]*save_envelope_bytes[\s\S]*authority\.commit/u);

  for (const file of ["tpm2_keystore.rs", "tpm2_authority.rs"]) {
    const source = production(path.join(crates, `dom-usdom-wallet/src/${file}`));
    assert.match(source, /fn with_lock<T>[\s\S]*lock_exclusive\(\)[\s\S]*operation\(self\)[\s\S]*FileExt::unlock/u);
  }
});

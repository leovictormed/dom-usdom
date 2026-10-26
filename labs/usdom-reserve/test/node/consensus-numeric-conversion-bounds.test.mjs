import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repo = path.resolve(import.meta.dirname, "../../../..");

function source(relative) {
  return fs.readFileSync(path.join(repo, relative), "utf8");
}

test("peer time comparison covers the complete u64 wire domain", () => {
  const scoring = source("crates/dom-node/src/peer_scoring.rs");
  const node = source("crates/dom-node/src/node.rs");
  assert.match(scoring, /local_timestamp\.abs_diff\(peer_timestamp\)/u);
  assert.match(node, /our_ts\.abs_diff\(peer_hello\.local_timestamp\)/u);
  assert.doesNotMatch(scoring, /local_timestamp as i64|peer_timestamp as i64/u);
  assert.doesNotMatch(node, /our_ts as i64|peer_hello\.local_timestamp as i64/u);
  assert.match(scoring, /evaluate_peer_drift\("peer1", 0, u64::MAX\)/u);
});

test("SNTP arithmetic is wide and unfolds the 2036 wire-era rollover", () => {
  const time = source("crates/dom-node/src/time_health.rs");
  assert.match(time, /i128::from\(local_time\) - i128::from\(ntp_time\)/u);
  assert.match(time, /fn unfold_ntp_seconds\(raw: u32, local_unix: u64\)/u);
  assert.match(time, /local_era\.checked_add\(1\)/u);
  assert.match(time, /era[\s\S]{0,120}?\.checked_mul\(NTP_ERA_SECS\)[\s\S]{0,100}?\.checked_add\(u64::from\(raw\)\)/u);
  assert.match(time, /ntp_era_unfolding_survives_the_2036_rollover/u);
  assert.doesNotMatch(time, /local_time - ntp_time as i64/u);
  assert.doesNotMatch(time, /\.as_secs\(\) as i64/u);
});

test("block locator never narrows canonical u64 heights", () => {
  const node = source("crates/dom-node/src/node.rs");
  const locator = node.slice(node.indexOf("async fn build_locator"), node.indexOf("async fn persist_ibd_state"));
  assert.match(locator, /let mut height = Some\(tip_height\)/u);
  assert.match(locator, /height = h\.checked_sub\(step\)/u);
  assert.doesNotMatch(locator, /as i64|as u64/u);
});

test("USDOM statement and checkpoint heights use checked portable arithmetic", () => {
  const randomx = source("crates/dom-usdom-randomx-proof-host/src/lib.rs");
  const portable = source("crates/dom-usdom-checkpoint-program/src/portable.rs");
  const outer = source("crates/dom-usdom-checkpoint-program/src/outer.rs");
  const exporter = source("crates/dom-node/src/bin/dom-usdom-export-randomx-statement-set.rs");

  assert.match(randomx, /u64::try_from\(expected_index\)[\s\S]{0,500}?\.checked_add\(expected_offset\)/u);
  assert.match(portable, /u64::try_from\(index\)[\s\S]{0,300}?\.checked_add\(height_offset\)/u);
  assert.match(outer, /let expected_next_height = current[\s\S]{0,120}?\.checked_add\(block_count\)/u);
  assert.match(exporter, /u64::try_from\(block_index\)[\s\S]{0,300}?\.checked_add\(height_offset\)/u);

  assert.doesNotMatch(randomx, /previous_height \+ expected_index as u64 \+ 1/u);
  assert.doesNotMatch(outer, /next\.height != current\.height \+ block_count/u);
  assert.doesNotMatch(exporter, /previous_height \+ block_index as u64 \+ 1/u);
});

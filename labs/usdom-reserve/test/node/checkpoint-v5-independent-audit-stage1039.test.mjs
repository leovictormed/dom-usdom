import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const root=new URL('../../../../',import.meta.url);
const read=path=>readFileSync(new URL(path,root),'utf8');
const json=path=>JSON.parse(read(path));

const statement=read('crates/dom-usdom-checkpoint-statement/src/lib.rs');
const outer=read('crates/dom-usdom-checkpoint-program/src/outer.rs');
const burn=read('crates/dom-usdom-finalized-burn-program/src/lib.rs');
const registry=read('labs/usdom-reserve/contracts/DOMCheckpointRegistry.sol');
const submission=read('labs/usdom-reserve/sdk/checkpoint-submission.mjs');
const segmentProvenance=json('crates/dom-usdom-checkpoint-segment-risc0-guest/PROVENANCE.json');
const outerProvenance=json('crates/dom-usdom-checkpoint-outer-risc0-guest/PROVENANCE.json');

// The public frame is disjoint from V4, fixes batch-v4 semantics, appends both
// target-height totals, and hashes them in the 25-word Solidity ABI position.
assert.match(statement,/V5_MAGIC[^\n]+UDCPST05/);
assert.match(statement,/V5_VERSION: u16 = 5/);
assert.match(statement,/CHECKPOINT_TRANSITION_BATCH_V5_VERSION: u16 = 4/);
assert.match(statement,/let mut encoded = \[0u8; 25 \* 32\]/);
assert.match(statement,/encoded\[496\.\.512\][\s\S]*total_issued/);
assert.match(statement,/encoded\[528\.\.544\][\s\S]*total_burned/);
assert.match(statement,/CheckpointStatementV5::from_bytes\(&v4_bytes\)\.is_err/);
assert.match(statement,/CheckpointStatementV4::from_bytes\(&v5_bytes\)\.is_err/);

// Recursive composition carries totals across every adjacent segment, captures
// them exactly at the target (not at the confirmation tip), and compares both
// against the V5 public statement.
assert.match(outer,/transition\.previous_total_issued != current_total_issued/);
assert.match(outer,/transition\.previous_total_burned != current_total_burned/);
assert.match(outer,/if current\.height == public\.height[\s\S]*target_totals/);
assert.match(outer,/target_total_issued != statement\.total_issued/);
assert.match(outer,/target_total_burned != statement\.total_burned/);

// Ethereum selection is monotonic and the finalized-burn relation opens the
// exact target state and its two public totals.
assert.match(registry,/checkpoint\.totalIssued < latestTotalIssued/);
assert.match(registry,/checkpoint\.totalBurned < latestTotalBurned/);
assert.match(registry,/checkpoint\.totalBurned > checkpoint\.totalIssued/);
assert.match(registry,/latestTotalIssued = current\.totalIssued/);
assert.match(registry,/latestTotalBurned = current\.totalBurned/);
assert.match(burn,/checkpoint_statement\.total_issued != state\.total_issued/);
assert.match(burn,/checkpoint_statement\.total_burned != state\.total_burned/);

// SDK offsets reproduce the append-only 550-byte frame and hash the totals in
// DOMCheckpointV3 order rather than their serialization order.
assert.match(submission,/statementBytes=551/);
assert.match(submission,/totalIssued:readUnsigned\(bytes,518,16/);
assert.match(submission,/totalBurned:readUnsigned\(bytes,534,16/);
assert.match(submission,/issuanceClosed:bytes\[550\]===1/);
assert.match(submission,/fixedUnsigned\(checkpoint\.totalIssued,128\)[\s\S]*fixedUnsigned\(checkpoint\.totalBurned,128\)/);
assert.match(submission,/identity\.registry\.toLowerCase\(\)===zeroAddress/);
assert.match(submission,/BigInt\(checkpoint\.height\)<=BigInt\(checkpoint\.previousHeight\)/);
assert.match(submission,/BigInt\(checkpoint\.totalBurned\)>BigInt\(checkpoint\.totalIssued\)/);

// Existing binaries predate V5/V3. They may remain as non-production evidence,
// but must never be represented as approved artifacts for the new relation.
const artifactsAreV5=
  segmentProvenance.transitionSchema==='UDCSTN03'
  && outerProvenance.statementSchema==='UDCPST05'
  && outerProvenance.segmentTransitionSchema==='UDCSTN03'
  && outerProvenance.journalSchema==='solidity-checkpoint-statement-v5-hash';
if(!artifactsAreV5) {
  assert.equal(segmentProvenance.productionApproved,false);
  assert.equal(outerProvenance.productionApproved,false);
  assert.match(registry,/PRODUCTION_VERIFIER_CODE_HASH = bytes32\(0\)/);
  assert.match(registry,/PRODUCTION_VERIFIER_CONFIG_HASH = bytes32\(0\)/);
  assert.match(registry,/PRODUCTION_CHECKPOINT_CONFIG_HASH = bytes32\(0\)/);
}

console.log(JSON.stringify({checkpointV5Semantics:'ok',artifactsAreV5,
  staleArtifactsFailClosed:!artifactsAreV5},null,2));

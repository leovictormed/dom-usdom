import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const root=new URL('../..',import.meta.url);
const generator=new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url);

function generatedPhase() {
  const result=spawnSync('/usr/bin/bash',[generator.pathname,'validate-local'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
  });
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stderr,'');
  return result.stdout;
}

test('validate-local authenticates tools and covers current artifacts and release gates',()=>{
  const source=generatedPhase();
  const required=[
    'node scripts/check-mainnet-toolchain.mjs',
    'npm ci --offline --ignore-scripts --audit=false',
    'npm test',
    'npm run --silent test:solidity',
    'cargo test --locked --offline -j1 -p dom-usdom-state -p dom-usdom-privacy -p dom-usdom-wallet -p dom-usdom-rpc-protocol -p dom-usdom-checkpoint-statement -p dom-usdom-checkpoint-program -p dom-usdom-checkpoint-proof-host -p dom-usdom-economic-block-program -p dom-usdom-economic-proof-host -p dom-usdom-finalized-burn-program -p dom-usdom-finalized-burn-proof-host -p dom-usdom-randomx-portable -p dom-usdom-randomx-proof-host',
    'cargo test --locked --offline -j1 -p dom-node --features native-usdom-v4-poc native_usdom_config --lib',
    'cargo test --locked --offline -j1 -p dom-node --features native-usdom-v4-poc --bin dom-usdom-manifest-check',
    'cargo test --locked --offline -j1 -p dom-usdom-checkpoint-program --features host-reference reference::tests::short_390_v6_target_binding_rejects_span_total_and_closure_drift -- --exact',
    'npm run --silent check:provenance',
  ];
  let previous=-1;
  for(const command of required) {
    const at=source.indexOf(command);
    assert(at>previous,`missing or out-of-order validation command: ${command}`);
    previous=at;
  }
  // npm test runs pretest, which performs the forced offline Solidity build;
  // the Node suite then derives and checks creation/runtime bytecode from it.
  assert.match(source,/export FOUNDRY_OFFLINE=true/);
  assert.match(source,/export CARGO_NET_OFFLINE=true/);
});

test('validate-local cannot create mainnet operational evidence or run long proofs',()=>{
  const source=generatedPhase();
  assert.doesNotMatch(source,/\b(?:materialize|collect|observe|execute|sign|deploy|broadcast|readiness):/);
  assert.doesNotMatch(source,/USDOM_RUN_LONG_RELEASE_TEST|--ignored|run-usdom-release-vectors|run-supervised-long-proof/);
  assert.doesNotMatch(source,/production_[A-Za-z0-9_]+\s*=\s*true/);
});

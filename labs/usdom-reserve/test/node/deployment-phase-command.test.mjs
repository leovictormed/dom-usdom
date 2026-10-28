import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const generator=path.join(root,'scripts/generate-closed-mainnet-phase-command.sh');

function phase(name) {
  const result=spawnSync('/usr/bin/bash',[generator,name],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
  });
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stderr,'');
  return result.stdout;
}

test('deployment identity phase fixes dual mainnet RPC observation and hardware derivation',()=>{
  const source=phase('derive-deployment-identity-secret');
  assert.match(source,/cast chain-id --rpc-url "\$ETHEREUM_RPC_URL"\)" = 1/);
  assert.match(source,/cast chain-id --rpc-url "\$ETHEREUM_RPC_URL_2"\)" = 1/);
  assert.match(source,/materialize:mainnet-deployment-identity/);
  assert.doesNotMatch(source,/wallet sign|send|broadcast|private[-_ ]?key/i);
});

test('deployment package publication is immutable, authenticated and resume-safe',()=>{
  const source=phase('prepare-deployment');
  const ordered=['materialize:production-release-core -- registry-pins',
    'materialize:production-solidity-pins -- checkpointRegistry',
    'forge build --offline contracts/DOMCheckpointRegistry.sol',
    'materialize:production-release-core -- reserve-pins',
    'materialize:production-solidity-pins -- reserve',
    'forge build --offline contracts/USDOMProofReserve.sol',
    'materialize:production-release-core -- final',
    'prepare-production-release-core-materialization.mjs final'];
  let position=-1;
  for(const marker of ordered){const next=source.indexOf(marker);assert.ok(next>position,marker);position=next;}
  assert.match(source,/read-private-file-stdout\.mjs "\$USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION" \| sha256sum/);
  assert.match(source,/test -s "\$USDOM_RESERVE_PIN_RATIFICATION_PROPOSAL"/);
  assert.match(source,/materialize:production-solidity-pins -- reserve \\\n\s+"\$USDOM_RESERVE_PIN_RATIFICATION_PROPOSAL"/);
  assert.match(source,/install-private-file-immutable-stdin\.mjs --json "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE" <"\$candidate"/);
  assert.equal((source.match(/prepare-mainnet-deployment\.mjs/g)??[]).length,2);
  assert.match(source,/cmp -s "\$candidate" "\$rechecked"/);
  assert.match(source,/read-release-config-file-stdout\.mjs/);
  assert.match(source,/\.releaseConfigSha256/);
  assert.match(source,/sha256sum "\$release_snapshot"/);
  assert.match(source,/read-private-file-stdout\.mjs "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE" >"\$installed"/);
  assert.match(source,/cmp -s "\$candidate" "\$installed"/);
  assert.match(source,/cmp -s "\$release_snapshot" -/);
  const builds=[...source.matchAll(/prepare-mainnet-deployment\.mjs/g)].map(match=>match.index);
  const publish=source.indexOf('install-private-file-immutable-stdin.mjs --json "$USDOM_MAINNET_DEPLOYMENT_PACKAGE"');
  assert.ok(builds[0]<builds[1]&&builds[1]<source.indexOf('cmp -s "$candidate" "$rechecked"')
    &&source.indexOf('sha256sum "$release_snapshot"')<publish);
  assert.match(source,/\.chainId=="1"/);
  assert.doesNotMatch(source,/if test -e "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE"/);
  assert.doesNotMatch(source,/jq -e .*"\$USDOM_MAINNET_DEPLOYMENT_PACKAGE"|sha256sum "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE"/);
  assert.doesNotMatch(source,/wallet sign|send|broadcast|private[-_ ]?key/i);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';

const oldPins=[
  '1d2a2b4b2e8cfffc96dee68d2cdf9d4f822f36f8a50707f3b7f2c8b005682498',
  'e4719f8fd72f041494b0ce88f4f51321e4d882b248e3ff02a3cefe88162b9fe0',
];
const consumers={
  release:'../../scripts/prepare-production-release-core-materialization.mjs',
  preactivation:'../../sdk/production-preactivation-core.mjs',
  deployment:'../../scripts/prepare-mainnet-deployment.mjs',
  readiness:'../../scripts/check-mainnet-readiness.mjs',
  preflight:'../../sdk/mainnet-preflight.mjs',
  reproducibleBuild:'../../scripts/prepare-reserve-reproducible-build-report.mjs',
  authorization:'../../sdk/mainnet-readiness.mjs',
};

test('every active reserve identity consumer rejects literal stale pins',async()=>{
  const sources=await Promise.all(Object.entries(consumers).map(async([name,relative])=>
    [name,await readFile(new URL(relative,import.meta.url),'utf8')]));
  for(const [name,source] of sources) {
    for(const pin of oldPins) assert.ok(!source.includes(pin),`${name} contains stale reserve pin ${pin}`);
  }
  const byName=Object.fromEntries(sources);
  assert.match(byName.release,/deriveReserveArtifactBinding/);
  assert.match(byName.release,/reserveBinding\.runtimeCodeHash/);
  assert.match(byName.release,/reserveBinding\.initcodeHash/);
  assert.match(byName.preactivation,/reserveRuntimeCodeHash','reserveInitcodeHash/);
  assert.match(byName.deployment,/deriveReserveArtifactBinding/);
  assert.match(byName.readiness,/deriveReserveArtifactBinding/);
  assert.match(byName.preflight,/reserveRuntimeCodeHash/);
  assert.match(byName.reproducibleBuild,/deriveReserveArtifactBinding/);
  assert.match(byName.authorization,/compiledReserveRuntimeCodeHash/);
  assert.match(byName.authorization,/compiledReserveInitcodeHash/);
});

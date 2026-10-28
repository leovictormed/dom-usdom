import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const read=relative=>readFile(new URL(`../../${relative}`,import.meta.url),'utf8');

test('checkpoint witness producer collects raw finalized proofs and publishes completion last',async()=>{
  const [collector,materializer,generator,pkg]=await Promise.all([
    read('scripts/collect-authenticated-checkpoint-witness-source.mjs'),
    read('scripts/materialize-authenticated-checkpoint-witness.sh'),
    read('scripts/generate-closed-mainnet-phase-command.sh'),
    read('package.json'),
  ]);
  for(const marker of ['/eth/v1/beacon/light_client/bootstrap/','/eth/v1/beacon/light_client/updates?',
    '/eth/v1/beacon/light_client/finality_update','eth_getBlockReceipts','eth_getProof','eth_getCode',
    'boundedTransactionHashes','independent checkpoint witness sources disagree','inputs changed during collection']) {
    assert.match(collector,new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  }
  assert.ok(collector.indexOf('writePrivateFileDurableNew(output')<collector.indexOf('writePrivateFileDurableNew(completion'),
    'source must precede completion publication');
  assert.match(materializer,/sourceSha256[\s\S]*cargo run[\s\S]*usdom-build-checkpoint-witness[\s\S]*cmp -s/);
  assert.match(materializer,/source "\$LAB_ROOT\/scripts\/pinned-shell-tool-functions\.sh"/);
  for(const tool of ['node','jq','cargo']) {
    assert.match(materializer,new RegExp(`pin_runtime_tool ${tool}`));
    assert.match(materializer,new RegExp(`${tool}\\(\\) \\{ assert_runtime_tool ${tool}; "\\$${tool}_bin" "\\$@"; \\}`));
  }
  assert.match(materializer,/node "\$LAB_ROOT\/scripts\/read-private-file-stdout\.mjs"/);
  assert.match(materializer,/snapshot_identity="\$\(stat -c '%u:%d:%i:%a' "\$snapshot"\)"/);
  assert.match(materializer,/stat -c '%u:%d:%i:%a' "\$snapshot" 2>\/dev\/null[\s\S]*== "\$snapshot_identity"/);
  assert.match(materializer,/else\n\s+# Do not let cleanup follow a pathname that another process replaced\.\n\s+status=1/);
  const phase=generator.slice(generator.indexOf('  produce-checkpoint-evidence-secret)'),generator.indexOf('\n  measure-release-capacity)'));
  const collect=phase.indexOf('collect:authenticated-checkpoint-witness-source');
  const build=phase.indexOf('materialize:authenticated-checkpoint-witness');
  const exportBurn=phase.indexOf('export:canonical-finalized-burn-source');
  assert.ok(collect>=0&&collect<build&&build<exportBurn,'collection, verification and burn export order is invalid');
  const scripts=JSON.parse(pkg).scripts;
  assert.ok(scripts['collect:authenticated-checkpoint-witness-source']);
  assert.ok(scripts['materialize:authenticated-checkpoint-witness']);
});

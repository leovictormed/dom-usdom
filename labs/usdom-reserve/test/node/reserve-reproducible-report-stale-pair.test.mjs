import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const writers=[
  ['reserve','write-reserve-reproducible-build-report.sh','reproducibleBuildReport','prepare-reserve-reproducible-build-report.mjs'],
  ['verifier','write-verifier-reproducible-build-report.sh','verifierReproducibleBuildReport','prepare-verifier-reproducible-build-report.mjs'],
  ['checkpoint verifier','write-checkpoint-verifier-reproducible-build-report.sh','checkpointVerifierReproducibleBuildReport','prepare-checkpoint-verifier-reproducible-build-report.mjs'],
  ['checkpoint registry','write-checkpoint-registry-reproducible-build-report.sh','checkpointRegistryReproducibleBuildReport','prepare-checkpoint-registry-reproducible-build-report.mjs'],
];

for(const [label,file,field,preparer] of writers)test(`${label} reproducible report invalidates stale pair and publishes pointer last`,()=>{
  const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
  const lock=source.indexOf('flock -n 9');
  const clear=source.indexOf(`jq '.${field}=null'`,lock);
  const clearInstall=source.indexOf('install-release-config-stdin.mjs',clear);
  const removal=source.indexOf('remove-private-file-durable.mjs',clearInstall);
  const generation=source.indexOf(preparer,removal);
  const reportInstall=source.indexOf('install-private-file-immutable-stdin.mjs',generation);
  const finalPointer=source.indexOf('install-release-config-stdin.mjs',reportInstall);
  const readback=source.indexOf('cmp -s "$next_metadata" "$metadata_installed"',finalPointer);

  for(const [name,position] of Object.entries({lock,clear,clearInstall,removal,generation,reportInstall,finalPointer,readback})){
    assert.notEqual(position,-1,`${name} step missing`);
  }
  assert.ok(lock<clear && clear<clearInstall && clearInstall<removal,
    'the old completion pointer must be cleared before the old report is removed');
  assert.ok(removal<generation && generation<reportInstall && reportInstall<finalPointer,
    'the report must be regenerated and installed before its completion pointer');
  assert.ok(finalPointer<readback,'the installed completion pointer must be read back');
});

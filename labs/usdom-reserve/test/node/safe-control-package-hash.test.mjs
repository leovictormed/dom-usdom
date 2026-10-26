import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {_safeControlObservationInternals} from '../../sdk/safe-control-observation.mjs';

const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const script=new URL('../../scripts/hash-safe-control-package.mjs',import.meta.url);
const packageValue={schema:'usdom-safe-controls-recoverable/v2',ethereumChainId:'1',threshold:'2',
  controls:[{role:'governance'},{role:'reserveGuardian'},{role:'checkpointGuardian'}]};
test('Safe generation hash uses the same canonical external commitment as observations',()=>{
  const dir=mkdtempSync(path.join(tmpdir(),'safe-package-hash-')),file=path.join(dir,'package.json');
  writeFileSync(file,JSON.stringify(packageValue));
  const result=spawnSync(node,[script.pathname,file],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stdout.trim(),_safeControlObservationInternals.documentHash(packageValue));
  const changed=structuredClone(packageValue); changed.controls[1].role='governance';
  writeFileSync(file,JSON.stringify(changed));
  assert.notEqual(spawnSync(node,[script.pathname,file]).status,0);
});

test('operator generator never reads a nonexistent self-referential packageHash',()=>{
  const source=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  assert.doesNotMatch(source,/jq -er '\.packageHash' "\$(?:target_package|candidate)"/);
  assert.ok((source.match(/hash-safe-control-package\.mjs/g)??[]).length>=3);
});

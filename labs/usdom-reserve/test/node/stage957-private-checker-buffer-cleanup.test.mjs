import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const checkers=[
  ['check-private-strict-json-file.mjs','privateJsonBytes'],
  ['check-private-rpc-proxy-ready.mjs','readinessBytes'],
  ['check-mainnet-deployment-package.mjs','deploymentPackageBytes'],
  ['check-mainnet-deployment-raw-transaction.mjs','rawTransactionBytes'],
];

test('standalone private authority checkers erase their file capture on every exit',async()=>{
  for(const [name,buffer] of checkers) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,new RegExp(`let ${buffer};`),name);
    assert.match(source,new RegExp(`finally \\{\\n  ${buffer}\\?\\.fill\\(0\\);\\n\\}`),name);
    assert.equal((source.match(new RegExp(`${buffer}\\?\\.fill\\(0\\)`,'g'))||[]).length,1,name);
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const scripts=[
  'initialize-closed-mainnet-genesis.mjs',
  'mine-closed-mainnet-issuance-block.mjs',
  'submit-finalized-deposit-issuance.mjs',
];

test('secret input readers register each resolved Buffer before Promise aggregation can fail',async()=>{
  for(const name of scripts) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.equal((source.match(/secretBuffers\.push\(/g)||[]).length,1,name);
    assert.match(source,/async function (?:secureRead|directRead)[\s\S]*secretBuffers\.push\(bytes\);[\s\S]*return bytes;/,name);
    assert.match(source,/finally \{\n  for\(const bytes of secretBuffers\) bytes\.fill\(0\);\n\}/,name);
  }
});

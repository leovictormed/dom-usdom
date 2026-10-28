import test from 'node:test';
import assert from 'node:assert/strict';
import {readdir,readFile} from 'node:fs/promises';

const roots=[
 '../../../../crates/dom-node/src/bin',
 '../../../../crates/dom-usdom-checkpoint-proof-host/src',
 '../../../../crates/dom-usdom-randomx-proof-host/src',
 '../../../../crates/dom-usdom-economic-proof-host/src',
 '../../../../crates/dom-usdom-finalized-burn-proof-host/src'
];
async function rustFiles(relative){
 const url=new URL(relative+'/',import.meta.url), out=[];
 for(const entry of await readdir(url,{withFileTypes:true})){
  if(entry.isDirectory()) out.push(...await rustFiles(relative+'/'+entry.name));
  else if(entry.name.endsWith('.rs')&&(relative.includes('proof-host')||entry.name.startsWith('dom-usdom-'))) out.push(new URL(entry.name,url));
 }
 return out;
}

test('internal Rust errors cannot cross stdout, stderr or serialized evidence boundaries',async()=>{
 const files=(await Promise.all(roots.map(rustFiles))).flat();
 const records=await Promise.all(files.map(async url=>({
  name:url.pathname.slice(url.pathname.indexOf('/crates/')+1),
  source:(await readFile(url)).toString('utf8').split('#[cfg(test)]')[0]
 })));
 const sources=records.map(record=>record.source);
 const joined=sources.join('\n');
 const signalPattern=/map_err\(|with_context\(|\.context\(|format!\([^\n]*(?:error|source)|anyhow!\([^\n]*(?:error|source)/;
 const inventory=Object.fromEntries(records.map(({name,source})=>[
  name,source.split('\n').filter(line=>signalPattern.test(line)).length
 ]).filter(([,count])=>count!==0).sort());
 assert.deepEqual(inventory,{
  'crates/dom-node/src/bin/dom-usdom-bootstrap-tpm-wallet-authority.rs':3,
  'crates/dom-node/src/bin/dom-usdom-build-finalized-deposit-witness.rs':12,
  'crates/dom-node/src/bin/dom-usdom-build-private-burn.rs':6,
  'crates/dom-node/src/bin/dom-usdom-export-checkpoint-source-set.rs':1,
  'crates/dom-node/src/bin/dom-usdom-export-checkpoint-source.rs':1,
  'crates/dom-node/src/bin/dom-usdom-export-finalized-burn-source.rs':6,
  'crates/dom-node/src/bin/dom-usdom-export-preactivation-anchor.rs':6,
  'crates/dom-node/src/bin/dom-usdom-export-randomx-statement-set.rs':17,
  'crates/dom-node/src/bin/dom-usdom-observe-finalized-deposit.rs':3,
  'crates/dom-node/src/bin/dom-usdom-recover-wallet-at-checkpoint.rs':7,
  'crates/dom-node/src/bin/dom-usdom-register-finalized-deposit.rs':6,
  'crates/dom-node/src/bin/dom-usdom-submit-private-burn.rs':3,
  'crates/dom-node/src/bin/dom-usdom-wallet-tpm-keystore.rs':3,
  'crates/dom-usdom-checkpoint-proof-host/src/bin/verify-rebuild-receipt.rs':3,
  'crates/dom-usdom-checkpoint-proof-host/src/lib.rs':70,
  'crates/dom-usdom-economic-proof-host/src/lib.rs':51,
  'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs':50,
  'crates/dom-usdom-randomx-proof-host/src/aggregate.rs':24,
  'crates/dom-usdom-randomx-proof-host/src/lib.rs':23
 },'fixed ETAPA927 per-file internal propagation inventory changed');
 assert.doesNotMatch(joined,/(?:print|eprint)ln!\([^;]*\{_?error(?::[^}]*)?\}/s);
 assert.doesNotMatch(joined,/json!\s*\(\s*\{[^}]*["']error["']\s*:/s);
 assert.doesNotMatch(joined,/fn main\(\)\s*->\s*(?:anyhow::)?Result/);
});

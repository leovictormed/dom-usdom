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
 const sources=await Promise.all(files.map(url=>readFile(url)).map(async p=>(await p).toString('utf8').split('#[cfg(test)]')[0]));
 const joined=sources.join('\n');
 const signalPattern=/map_err\(|with_context\(|\.context\(|format!\([^\n]*(?:error|source)|anyhow!\([^\n]*(?:error|source)/;
 const signals=joined.split('\n').filter(line=>signalPattern.test(line)).length;
 assert.equal(signals,291,'fixed ETAPA927 internal propagation inventory changed');
 assert.doesNotMatch(joined,/(?:print|eprint)ln!\([^;]*\{_?error(?::[^}]*)?\}/s);
 assert.doesNotMatch(joined,/json!\s*\(\s*\{[^}]*["']error["']\s*:/s);
 assert.doesNotMatch(joined,/fn main\(\)\s*->\s*(?:anyhow::)?Result/);
});

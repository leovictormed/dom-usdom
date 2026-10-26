import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const bins=[
 'dom-usdom-recover-wallet-at-checkpoint.rs',
 'dom-usdom-register-finalized-deposit.rs',
 'dom-usdom-build-finalized-deposit-witness.rs',
 'dom-usdom-bootstrap-tpm-wallet-authority.rs',
 'dom-usdom-build-private-burn.rs',
 'dom-usdom-observe-finalized-deposit.rs'
];

function printlnBodies(source){
 const bodies=[];
 for(let start=source.indexOf('println!(');start!==-1;start=source.indexOf('println!(',start+1)){
  let cursor=start+'println!('.length,depth=1,quoted=false,escaped=false;
  for(;cursor<source.length&&depth>0;cursor++){
   const byte=source[cursor];
   if(quoted){
    if(escaped) escaped=false;
    else if(byte==='\\') escaped=true;
    else if(byte==='"') quoted=false;
   }else if(byte==='"') quoted=true;
   else if(byte==='(') depth++;
   else if(byte===')') depth--;
  }
  bodies.push(source.slice(start,cursor));
 }
 return bodies.join('\n');
}

test('wallet and private-transition commands do not emit linkable values to stdout',async()=>{
 const sources=await Promise.all(bins.map(name=>readFile(
  new URL(`../../../../crates/dom-node/src/bin/${name}`,import.meta.url),'utf8')));
 const stdout=sources.map(printlnBodies).join('\n');
 for(const label of [
  'deposit_id:','note_commitment:','note_spent_at_checkpoint:',
  'available_balance_at_checkpoint:','available_balance_base_units:',
  'amount_base_units:','witness_sha256:','transition_id:','burn_id:','request_id:'
 ]) assert.doesNotMatch(stdout,new RegExp(label),label);
});

test('credential material remains file-addressed rather than a literal argv value',async()=>{
 const sources=await Promise.all(bins.map(name=>readFile(
  new URL(`../../../../crates/dom-node/src/bin/${name}`,import.meta.url),'utf8')));
 const joined=sources.join('\n');
 for(const forbidden of [
  '--password','--rpc-token','--owner-auth','--recovery-password',
  '--state-password','--proving-key','--credential'
 ]){
  const direct=new RegExp(`"${forbidden}"(?!-file)`);
  assert.doesNotMatch(joined,direct,forbidden);
 }
});

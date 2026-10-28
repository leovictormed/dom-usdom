import test from 'node:test';
import assert from 'node:assert/strict';
import {Wallet} from 'ethers';
import {uint, domain, normalizeBurn, digest, quorumSignatures, burnTypes} from '../../sdk/reserve.mjs';
const wallets = [101,102,103,104].map(n => new Wallet('0x'+n.toString(16).padStart(64,'0')));
const h = n => '0x'+n.toString(16).padStart(64,'0');
const address = '0x0000000000000000000000000000000000001234';
const burn = {burnId:h(1),requestId:h(2),recipient:wallets[0].address,amount:'9007199254740993',domDomain:h(3),height:'4',blockHash:h(5),epoch:'1',validUntil:'1800600000'};
test('uint64 precision is never coerced through Number', () => {
 assert.equal(normalizeBurn(burn).amount,9007199254740993n);
 for(const value of [9007199254740992, '01','1e6','-1','18446744073709551616',
   '9'.repeat(100000),null]) assert.throws(()=>uint(value));
 for(const bits of [0,257,1.5,'64']) assert.throws(()=>uint('1',bits));
});
test('domain separates deployments, chains and all certificate fields',()=>{
 const base = digest('1',address,burn);
 assert.throws(()=>domain('9'.repeat(100000),address));
 assert.throws(()=>domain((1n<<256n).toString(),address));
 assert.notEqual(base,digest('2',address,burn));
 assert.notEqual(base,digest('1',wallets[0].address,burn));
 for(const field of burnTypes.Burn) {
  const b={...burn}; b[field.name]=field.type==='address'?wallets[1].address:field.type==='bytes32'?h(99):'99';
  assert.notEqual(base,digest('1',address,b));
 }
 assert.throws(()=>normalizeBurn({...burn,extra:true})); assert.throws(()=>normalizeBurn({...burn,amount:'0'}));
});
test('canonical quorum rejects duplicate, foreign and wrong-domain signatures',async()=>{
 const signatures=await Promise.all(wallets.slice(0,3).map(w=>w.signTypedData(domain('1',address),burnTypes,burn)));
 const args={chainId:'1',reserve:address,burn,signatures,notaries:wallets.map(w=>w.address),threshold:3};
 assert.equal(quorumSignatures(args).length,3);
 assert.throws(()=>quorumSignatures({...args,signatures:[`0x${signatures[0].slice(2).toUpperCase()}`,...signatures.slice(1)]}),/canonical/);
 assert.throws(()=>quorumSignatures({...args,signatures:[`${signatures[0].slice(0,-2)}00`,...signatures.slice(1)]}),/canonical/);
 assert.throws(()=>quorumSignatures({...args,signatures:[signatures[0],signatures[0],signatures[1]]}));
 assert.throws(()=>quorumSignatures({...args,chainId:'2'}));
 assert.throws(()=>quorumSignatures({...args,burn:{...burn,amount:'1'}}));
 assert.throws(()=>quorumSignatures({...args,notaries:[wallets[0].address, wallets[1].address, wallets[3].address]}));
});

import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {validateDepositIssuanceAuthority} from '../../sdk/deposit-issuance-authority.mjs';

const read=relative=>readFile(new URL(relative,import.meta.url),'utf8');
const sources={
  reserve:await read('../../contracts/USDOMProofReserve.sol'),
  finality:await read('../../../usdom-ethereum-finality/src/deposits.rs'),
  state:await read('../../../../crates/dom-usdom-state/src/lib.rs'),
  chain:await read('../../../../crates/dom-chain/src/native_usdom_v4.rs'),
};

test('deposit to issuance authority is complete across proof, state and persistence',()=>{
  assert.deepEqual(validateDepositIssuanceAuthority(sources),[]);
});

test('gate rejects replay, recipient, runtime and restart boundary removal',()=>{
  const mutations=[
    ['reserve','deploymentChainId, address(this), funder, salt','funder, salt'],
    ['reserve','deploymentChainId = block.chainid','deploymentChainId = 1'],
    ['finality','code.code_hash() == policy.runtime_code_hash','true'],
    ['state','deposit.receiving_commitment().into()','[0; 32]'],
    ['state','self.consumed_deposits.contains_key(&value.deposit_id)','false'],
    ['state','suffix.strip_prefix(b"deposit/")','suffix.strip_prefix(b"lost-deposit/")'],
  ];
  for(const [name,before,after] of mutations) {
    assert.ok(sources[name].includes(before),`missing mutation anchor: ${before}`);
    const changed={...sources,[name]:sources[name].replace(before,after)};
    assert.notDeepEqual(validateDepositIssuanceAuthority(changed),[],before);
  }
});

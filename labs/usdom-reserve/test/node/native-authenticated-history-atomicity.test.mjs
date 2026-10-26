import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateNativeAuthenticatedHistoryAtomicity}
  from '../../sdk/native-authenticated-history-atomicity.mjs';

const sources={
  rpcClient:await readFile(new URL(
    '../../../../crates/dom-usdom-wallet/src/rpc_client.rs',import.meta.url),'utf8'),
  wallet:await readFile(new URL(
    '../../../../crates/dom-usdom-wallet/src/lib.rs',import.meta.url),'utf8'),
};

test('authenticated history is released and applied only as a complete terminal sequence',()=>{
  assert.deepEqual(validateNativeAuthenticatedHistoryAtomicity(sources),[]);
});

test('partial page release and rollback weakening are detected',()=>{
  const mutations=[
    ['rpcClient','    blocks: Vec<CanonicalWalletBlock>,','    pub blocks: Vec<CanonicalWalletBlock>,'],
    ['rpcClient','blocks.extend(page.blocks);','return Ok(AuthenticatedHistoryScan { trusted_tip, blocks: page.blocks, terminal_state_root: page.terminal_state_root });'],
    ['rpcClient','Some(trusted_tip)','None'],
    ['rpcClient','checked_history_rescan_bytes(response_bytes, page.response_bytes)?','response_bytes'],
    ['wallet','while self.tip_height > original_height {','while false {'],
    ['wallet','self.apply_authenticated_history(wallet, blocks)?;','for block in blocks { self.apply_block(wallet, block)?; }'],
  ];
  for(const [key,before,after] of mutations) {
    assert(sources[key].includes(before),`mutation anchor missing: ${before}`);
    const mutated={...sources,[key]:sources[key].replaceAll(before,after)};
    assert.notDeepEqual(validateNativeAuthenticatedHistoryAtomicity(mutated),[],before);
  }
});

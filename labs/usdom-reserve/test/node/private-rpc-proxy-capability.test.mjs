import test from 'node:test';
import assert from 'node:assert/strict';
import {matchPrivateRpcProxyCapabilityPath} from '../../sdk/private-rpc-proxy-capability.mjs';

test('private RPC capability path uses one exact 32-byte authority',()=>{
  const secret=Buffer.from('ab'.repeat(32),'hex');
  assert.equal(matchPrivateRpcProxyCapabilityPath(`/${'ab'.repeat(32)}/0`,secret,2),0);
  assert.equal(matchPrivateRpcProxyCapabilityPath(`/${'ab'.repeat(32)}/1`,secret,2),1);
  for(const value of [`/${'aa'.repeat(32)}/0`,`/${'ab'.repeat(32)}/2`,
    `/${'AB'.repeat(32)}/0`,`/${'ab'.repeat(31)}/0`,`/${'ab'.repeat(32)}/00`,
    `/${'ab'.repeat(32)}/0/extra`]) {
    assert.equal(matchPrivateRpcProxyCapabilityPath(value,secret,2),-1);
  }
});

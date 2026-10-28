import test from 'node:test';
import assert from 'node:assert/strict';
import {validatePrivateRpcProxyRequest,
  validatePrivateRpcProxyResponse} from '../../sdk/private-rpc-proxy-envelope.mjs';

const methods=new Set(['eth_chainId']);
test('private RPC proxy admits one exact request authority',()=>{
  const request={jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]};
  assert.equal(validatePrivateRpcProxyRequest(request,methods),request);
  for(const value of [{...request,extra:true},{...request,id:'1'},{...request,id:-1},
    {...request,method:'eth_sendRawTransaction'}]) {
    assert.throws(()=>validatePrivateRpcProxyRequest(value,methods));
  }
});

test('private RPC proxy distinguishes exact result, error and null envelopes',()=>{
  assert.equal(validatePrivateRpcProxyResponse({jsonrpc:'2.0',id:1,result:null},1).result,null);
  assert.equal(validatePrivateRpcProxyResponse({jsonrpc:'2.0',id:1,error:{code:-1,message:'failed'}},1).error.code,-1);
  for(const value of [
    {jsonrpc:'2.0',id:1,result:null,error:{code:-1,message:'failed'}},
    {jsonrpc:'2.0',id:1},
    {jsonrpc:'2.0',id:1,result:null,extra:true},
    {jsonrpc:'2.0',id:2,result:null},
    {jsonrpc:'2.0',id:1,error:{code:-1,message:'failed',extra:true}},
  ]) assert.throws(()=>validatePrivateRpcProxyResponse(value,1));
});

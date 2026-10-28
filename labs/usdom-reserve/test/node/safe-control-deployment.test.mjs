import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Interface} from 'ethers';
import {BoundedMainnetPreflightProvider} from '../../sdk/mainnet-preflight-rpc.mjs';
import {
  buildRecoverableSafeControlDeploymentPackage,
  RECOVERABLE_SAFE_CONTROL_SCHEMA,
  prepareRecoverableSafeControlDeployments,
  validateRecoverableSafeControlPackage,
} from '../../sdk/safe-control-deployment.mjs';

const recoveryOwners = [
  '0x0000000000000000000000000000000000010011',
  '0x0000000000000000000000000000000000010022',
  '0x0000000000000000000000000000000000010033',
];
const ownersByRole={
  governance:[...recoveryOwners],
  reserveGuardian:[...recoveryOwners],
  checkpointGuardian:[...recoveryOwners],
  usdtCustody:[...recoveryOwners],
};
const allOwners=recoveryOwners;
const factory = '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67';
const singleton = '0x41675C099F32341bf84BFc5382aF534df5C7461a';
const fallbackHandler = '0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99';
const safeCode = JSON.parse(readFileSync(
  new URL('../fixtures/safe-1.4.1-mainnet.json', import.meta.url),
  'utf8',
));
const factoryInterface = new Interface([
  'function createProxyWithNonce(address singleton,bytes initializer,uint256 saltNonce) returns (address proxy)',
  'function proxyCreationCode() view returns (bytes)',
]);

function fixture({chainId = 1n, codedOwner, factoryCode} = {}) {
  const codeQueries = [];
  let destroys=0;
  const provider = {
    getNetwork: async () => ({chainId}),
    getBlock: async () => ({number: 1,hash:'0x'+'ab'.repeat(32)}),
    getCode: async (address, blockTag) => {
      codeQueries.push({address, blockTag});
      switch (address.toLowerCase()) {
        case factory.toLowerCase(): return factoryCode ?? safeCode.factoryRuntimeCode;
        case singleton.toLowerCase(): return safeCode.singletonRuntimeCode;
        case fallbackHandler.toLowerCase(): return safeCode.fallbackHandlerRuntimeCode;
        default:
          if(allOwners.some(value=>value.toLowerCase()===address.toLowerCase())) {
            return address.toLowerCase()===codedOwner?.toLowerCase()?'0x6000':'0x';
          }
          return '0x6000';
      }
    },
    call: async (transaction) => {
      return factoryInterface.encodeFunctionResult(
        'proxyCreationCode', [safeCode.proxyCreationCode],
      );
    },
    destroy: async()=>{ destroys+=1; },
  };
  return {providerFactory: () => provider, codeQueries, destroyCount:()=>destroys};
}

test('destroys the bounded provider on success and failure',async()=>{
  const success=fixture();
  await prepareRecoverableSafeControlDeployments({
    ownersByRole,rpcUrl:'https://rpc.invalid',providerFactory:success.providerFactory,
  });
  assert.equal(success.destroyCount(),1);
  const failure=fixture({chainId:31337n});
  await assert.rejects(prepareRecoverableSafeControlDeployments({
    ownersByRole,rpcUrl:'https://rpc.invalid',providerFactory:failure.providerFactory,
  }),/expected Ethereum chain ID 1/);
  assert.equal(failure.destroyCount(),1);
});

test('rejects mainnet precompiles as Safe owners before deployment',async()=>{
  for(const reservedOwner of [
    '0x0000000000000000000000000000000000000000',
    '0x0000000000000000000000000000000000000001',
    '0x0000000000000000000000000000000000000011',
  ]) {
    await assert.rejects(prepareRecoverableSafeControlDeployments({
      ownersByRole:Object.fromEntries(Object.keys(ownersByRole).map(role=>[role,[reservedOwner,...recoveryOwners.slice(1)]])),
      rpcUrl:'https://rpc.invalid',providerFactory:fixture().providerFactory,
    }),/reserved precompile address/);
  }
});

test('rederivation never depends on whether predicted role addresses are already deployed', async () => {
  const dependencyFixture = fixture();
  const first = await prepareRecoverableSafeControlDeployments({
    ownersByRole, rpcUrl: 'https://rpc.invalid',
    providerFactory: dependencyFixture.providerFactory,
  });
  const second = await prepareRecoverableSafeControlDeployments({
    ownersByRole, rpcUrl: 'https://rpc.invalid',
    providerFactory: dependencyFixture.providerFactory,
  });
  assert.deepEqual(second, first);
  const queried = new Set(dependencyFixture.codeQueries.map(
    ({address}) => address.toLowerCase(),
  ));
  for (const {safe} of first.controls) assert.equal(queried.has(safe.toLowerCase()), false);
});

test('rejects a package that substitutes a predicted Safe address for a ratified owner',()=>{
  const baseline=buildRecoverableSafeControlDeploymentPackage({ownersByRole,
    proxyCreationCode:safeCode.proxyCreationCode});
  const checkpointSafe=baseline.controls.find(value=>value.role==='checkpointGuardian').safe;
  const changed=structuredClone(baseline);
  changed.ownersByRole=Object.fromEntries(Object.keys(ownersByRole)
    .map(role=>[role,[checkpointSafe,...recoveryOwners.slice(1)].sort()]));
  assert.throws(()=>validateRecoverableSafeControlPackage(changed),
    /predicted Safe addresses must not be Safe owners|deployment control|owners/);
});

test('prepares deterministic four-role 2-of-3 controls from three distinct EOAs',async()=>{
  const identityFixture=fixture();
  const result=await prepareRecoverableSafeControlDeployments({
    ownersByRole:Object.fromEntries(Object.keys(ownersByRole).map(role=>[role,[recoveryOwners[2],recoveryOwners[0],recoveryOwners[1]]])),
    rpcUrl:'https://rpc.invalid',providerFactory:identityFixture.providerFactory,
  });
  const reordered=await prepareRecoverableSafeControlDeployments({
    ownersByRole:Object.fromEntries(Object.keys(ownersByRole).map(role=>[role,[recoveryOwners[1],recoveryOwners[2],recoveryOwners[0]]])),
    rpcUrl:'https://rpc.invalid',providerFactory:identityFixture.providerFactory,
  });
  assert.equal(result.schema,RECOVERABLE_SAFE_CONTROL_SCHEMA);
  assert.equal(result.threshold,'2');
  assert.deepEqual(result.ownersByRole,ownersByRole);
  assert.deepEqual(reordered,result);
  assert.equal(new Set(result.controls.map(({safe})=>safe)).size,4);
  assert.ok(result.controls.every(({to,value})=>to===factory && value==='0'));
  assert.equal(validateRecoverableSafeControlPackage(result),result);
  for(const mutate of [
    value=>{ value.controls[1].safe=value.controls[0].safe; },
    value=>{ value.controls[0].saltNonce='2'; },
    value=>{ value.controls[0].dataHash='0x'+'00'.repeat(32); },
    value=>{ value.singleton='0x0000000000000000000000000000000000000001'; },
    value=>{ value.ownersByRole.governance.reverse(); },
  ]) {
    const changed=structuredClone(result); mutate(changed);
    assert.throws(()=>validateRecoverableSafeControlPackage(changed));
  }
});

test('recoverable controls reject duplicate, missing and contract owners',async()=>{
  for(const owners of [
    recoveryOwners.slice(0,2),
    [recoveryOwners[0],recoveryOwners[0],recoveryOwners[2]],
  ]) {
    await assert.rejects(prepareRecoverableSafeControlDeployments({
      ownersByRole:Object.fromEntries(Object.keys(ownersByRole).map(role=>[role,[...owners]])),rpcUrl:'https://rpc.invalid',...fixture(),
    }),/exactly 3|distinct/);
  }
  await assert.rejects(prepareRecoverableSafeControlDeployments({
    ownersByRole,rpcUrl:'https://rpc.invalid',
    ...fixture({codedOwner:recoveryOwners[1]}),
  }),/hardware-wallet EOA/);
});

test('rejects a non-mainnet RPC', async () => {
  await assert.rejects(
    prepareRecoverableSafeControlDeployments({
      ownersByRole, rpcUrl: 'https://rpc.invalid', ...fixture({chainId: 31337n}),
    }),
    /expected Ethereum chain ID 1/,
  );
});

test('rejects a Safe contract identity not equal to the production pin', async () => {
  await assert.rejects(
    prepareRecoverableSafeControlDeployments({
      ownersByRole,
      rpcUrl: 'https://rpc.invalid',
      ...fixture({factoryCode: `${safeCode.factoryRuntimeCode}00`}),
    }),
    /does not match the pinned identity/,
  );
});

function boundedFixture({changedSnapshot=false,changedNumber=false,regressedFinality=false}={}) {
  const requests=[];
  let finalizedReads=0;
  const hashFor=number=>'0x'+number.toString(16).padStart(64,'0');
  const block=number=>({
    number:`0x${number.toString(16)}`,hash:hashFor(number),parentHash:hashFor(number-1),
    timestamp:'0x65000000',nonce:'0x0000000000000000',difficulty:'0x0',
    gasLimit:'0x1c9c380',gasUsed:'0x0',miner:'0x'+'00'.repeat(20),
    extraData:'0x',transactions:[],baseFeePerGas:'0x1',
  });
  const provider=new BoundedMainnetPreflightProvider('https://rpc.example/',{
    environment:{},fetchImpl:async(_url,init)=>{
      const request=JSON.parse(init.body); requests.push(request);
      let result;
      if(request.method==='eth_chainId') result='0x1';
      else if(request.method==='eth_getBlockByNumber') {
        const tag=request.params[0];
        if(tag==='finalized') {
          finalizedReads+=1;
          result=block(regressedFinality && finalizedReads>1?15:16);
        } else {
          result=block(Number(tag));
          if(changedSnapshot) result.hash=hashFor(99);
          if(changedNumber) result.number='0x11';
        }
      } else if(request.method==='eth_getCode') {
        const address=request.params[0].toLowerCase();
        result=address===factory.toLowerCase()?safeCode.factoryRuntimeCode:
          address===singleton.toLowerCase()?safeCode.singletonRuntimeCode:
          address===fallbackHandler.toLowerCase()?safeCode.fallbackHandlerRuntimeCode:'0x';
      } else if(request.method==='eth_call') {
        assert.equal(request.params[0].to.toLowerCase(),factory.toLowerCase());
        result=factoryInterface.encodeFunctionResult('proxyCreationCode',[safeCode.proxyCreationCode]);
      } else assert.fail(`unexpected RPC method ${request.method}`);
      return new Response(JSON.stringify({jsonrpc:'2.0',id:request.id,result}));
    },
  });
  return {provider,requests,providerFactory:()=>provider};
}

test('real bounded provider pins every Safe preparation state read to its finalized numeric block',async()=>{
  const bounded=boundedFixture();
  const result=await prepareRecoverableSafeControlDeployments({ownersByRole,
    rpcUrl:'https://rpc.example/',providerFactory:bounded.providerFactory});
  assert.equal(result.controls.length,4);
  assert.deepEqual(bounded.provider.finalizedSnapshot,
    {tag:'0x10',hash:'0x'+(16).toString(16).padStart(64,'0'),allowPendingNonce:false});
  const reads=bounded.requests.filter(request=>['eth_getCode','eth_call'].includes(request.method));
  assert.ok(reads.length>=5);
  assert.ok(reads.every(request=>request.params[1]==='0x10'));
  assert.ok(bounded.requests.some(request=>request.method==='eth_getBlockByNumber'
    && request.params[0]==='0x10'));
  assert.equal(bounded.provider.destroyed,true);
});

test('explicit historical Safe snapshot uses its numeric block instead of the moving finalized tag',async()=>{
  const bounded=boundedFixture();
  await prepareRecoverableSafeControlDeployments({ownersByRole,blockTag:15,
    rpcUrl:'https://rpc.example/',providerFactory:bounded.providerFactory});
  const reads=bounded.requests.filter(request=>['eth_getCode','eth_call'].includes(request.method));
  assert.ok(reads.every(request=>request.params[1]==='0xf'));
  assert.equal(bounded.provider.finalizedSnapshot.tag,'0xf');
});

test('real bounded Safe preparation rejects a changed pinned block and regressed finality',async()=>{
  for(const options of [{changedSnapshot:true},{changedNumber:true},{regressedFinality:true}]) {
    const bounded=boundedFixture(options);
    await assert.rejects(prepareRecoverableSafeControlDeployments({ownersByRole,
      rpcUrl:'https://rpc.example/',providerFactory:bounded.providerFactory}),
    /changed|regressed|does not match its request/);
    assert.equal(bounded.provider.destroyed,true);
  }
});

test('Safe preparation rejects nonfinalized tags and missing block identity before reading state',async()=>{
  for(const blockTag of ['latest','pending',17,-1,Number.MAX_SAFE_INTEGER+1]) {
    const bounded=boundedFixture();
    await assert.rejects(prepareRecoverableSafeControlDeployments({ownersByRole,blockTag,
      rpcUrl:'https://rpc.example/',providerFactory:bounded.providerFactory}),/block tag|exceeds/);
    assert.equal(bounded.requests.some(request=>['eth_getCode','eth_call'].includes(request.method)),false);
  }
  const incomplete=fixture();
  incomplete.providerFactory().getBlock=async()=>({number:1});
  await assert.rejects(prepareRecoverableSafeControlDeployments({ownersByRole,
    rpcUrl:'https://rpc.invalid',providerFactory:incomplete.providerFactory}),/block identity is invalid/);
  assert.equal(incomplete.codeQueries.length,0);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Interface} from 'ethers';
import {
  RECOVERABLE_SAFE_CONTROL_SCHEMA,
  prepareRecoverableSafeControlDeployments,
} from '../../sdk/safe-control-deployment.mjs';

const recoveryOwners = [
  '0x0000000000000000000000000000000000000011',
  '0x0000000000000000000000000000000000000022',
  '0x0000000000000000000000000000000000000033',
];
const ownersByRole={
  governance:recoveryOwners,
  reserveGuardian:['0x0000000000000000000000000000000000000044','0x0000000000000000000000000000000000000055','0x0000000000000000000000000000000000000066'],
  checkpointGuardian:['0x0000000000000000000000000000000000000077','0x0000000000000000000000000000000000000088','0x0000000000000000000000000000000000000099'],
};
const allOwners=Object.values(ownersByRole).flat();
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
    getBlock: async () => ({number: 1}),
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

test('prepares deterministic three-role 2-of-3 recovery controls from independent EOAs',async()=>{
  const identityFixture=fixture();
  const result=await prepareRecoverableSafeControlDeployments({
    ownersByRole:{...ownersByRole,governance:[recoveryOwners[2],recoveryOwners[0],recoveryOwners[1]]},
    rpcUrl:'https://rpc.invalid',providerFactory:identityFixture.providerFactory,
  });
  const reordered=await prepareRecoverableSafeControlDeployments({
    ownersByRole:{...ownersByRole,governance:[recoveryOwners[1],recoveryOwners[2],recoveryOwners[0]]},
    rpcUrl:'https://rpc.invalid',providerFactory:identityFixture.providerFactory,
  });
  assert.equal(result.schema,RECOVERABLE_SAFE_CONTROL_SCHEMA);
  assert.equal(result.threshold,'2');
  assert.deepEqual(result.ownersByRole,ownersByRole);
  assert.deepEqual(reordered,result);
  assert.equal(new Set(result.controls.map(({safe})=>safe)).size,3);
  assert.ok(result.controls.every(({to,value})=>to===factory && value==='0'));
});

test('recoverable controls reject duplicate, missing and contract owners',async()=>{
  for(const owners of [
    recoveryOwners.slice(0,2),
    [recoveryOwners[0],recoveryOwners[0],recoveryOwners[2]],
  ]) {
    await assert.rejects(prepareRecoverableSafeControlDeployments({
      ownersByRole:{...ownersByRole,governance:owners},rpcUrl:'https://rpc.invalid',...fixture(),
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

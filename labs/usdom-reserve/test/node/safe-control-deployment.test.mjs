import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Interface,
  keccak256,
} from 'ethers';
import {
  SAFE_CONTROL_SCHEMA,
  SAFE_MAINNET_IDENTITY,
  prepareSafeControlDeployments,
} from '../../sdk/safe-control-deployment.mjs';

const owner = '0x000000000000000000000000000000000000dEaD';
const factory = '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67';
const singleton = '0x41675C099F32341bf84BFc5382aF534df5C7461a';
const fallbackHandler = '0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99';
const proxyCreationCode = '0x6080604052600080fd';
const factoryInterface = new Interface([
  'function createProxyWithNonce(address singleton,bytes initializer,uint256 saltNonce) returns (address proxy)',
  'function proxyCreationCode() view returns (bytes)',
]);
const fixtureIdentity = Object.freeze({
  factory,
  factoryCodeHash: keccak256('0x6000'),
  singleton,
  singletonCodeHash: keccak256('0x6000'),
  fallbackHandler,
  fallbackHandlerCodeHash: keccak256('0x6000'),
  proxyCreationCodeHash: keccak256(proxyCreationCode),
});

function fixture({chainId = 1n, ownerCode = '0x'} = {}) {
  const codeQueries = [];
  const provider = {
    getNetwork: async () => ({chainId}),
    getBlock: async () => ({number: 1}),
    getCode: async (address) => {
      codeQueries.push(address);
      return address.toLowerCase() === owner.toLowerCase() ? ownerCode : '0x6000';
    },
    call: async () => factoryInterface.encodeFunctionResult(
      'proxyCreationCode', [proxyCreationCode],
    ),
  };
  return {providerFactory: () => provider, codeQueries};
}

test('prepares three distinct 1-of-1 Safe factory calls with independent CREATE2 checks', async () => {
  const result = await prepareSafeControlDeployments({
    owner,
    rpcUrl: 'https://rpc.invalid',
    expectedIdentity: fixtureIdentity,
    ...fixture(),
  });
  assert.equal(result.schema, SAFE_CONTROL_SCHEMA);
  assert.equal(result.ethereumChainId, '1');
  assert.equal(result.threshold, '1');
  assert.deepEqual(result.controls.map(({role, saltNonce}) => ({role, saltNonce})), [
    {role: 'governance', saltNonce: '1'},
    {role: 'reserveGuardian', saltNonce: '2'},
    {role: 'checkpointGuardian', saltNonce: '3'},
  ]);
  assert.equal(new Set(result.controls.map(({safe}) => safe)).size, 3);
  assert.ok(result.controls.every(({to, value}) => to === factory && value === '0'));
});

test('rederivation never depends on whether predicted role addresses are already deployed', async () => {
  const dependencyFixture = fixture();
  const first = await prepareSafeControlDeployments({
    owner, rpcUrl: 'https://rpc.invalid', expectedIdentity: fixtureIdentity,
    providerFactory: dependencyFixture.providerFactory,
  });
  const second = await prepareSafeControlDeployments({
    owner, rpcUrl: 'https://rpc.invalid', expectedIdentity: fixtureIdentity,
    providerFactory: dependencyFixture.providerFactory,
  });
  assert.deepEqual(second, first);
  const queried = new Set(dependencyFixture.codeQueries.map((address) => address.toLowerCase()));
  for (const {safe} of first.controls) assert.equal(queried.has(safe.toLowerCase()), false);
});

test('rejects a contract as the sole control-plane owner', async () => {
  await assert.rejects(
    prepareSafeControlDeployments({
      owner, rpcUrl: 'https://rpc.invalid', ...fixture({ownerCode: '0x6000'}),
      expectedIdentity: fixtureIdentity,
    }),
    /hardware-wallet EOA/,
  );
});

test('rejects a non-mainnet RPC', async () => {
  await assert.rejects(
    prepareSafeControlDeployments({
      owner, rpcUrl: 'https://rpc.invalid', ...fixture({chainId: 31337n}),
      expectedIdentity: fixtureIdentity,
    }),
    /expected Ethereum chain ID 1/,
  );
});

test('rejects a Safe contract identity not equal to the production pin', async () => {
  await assert.rejects(
    prepareSafeControlDeployments({
      owner, rpcUrl: 'https://rpc.invalid', ...fixture(),
      expectedIdentity: SAFE_MAINNET_IDENTITY,
    }),
    /does not match the pinned identity/,
  );
});

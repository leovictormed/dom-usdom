import {
  Interface,
  concat,
  getAddress,
  getCreate2Address,
  isAddress,
  keccak256,
  solidityPacked,
  zeroPadValue,
} from 'ethers';
import {BoundedMainnetPreflightProvider} from './mainnet-preflight-rpc.mjs';

export const RECOVERABLE_SAFE_CONTROL_SCHEMA = 'usdom-safe-controls-recoverable/v2';
export const SAFE_VERSION = '1.4.1';
export const RECOVERABLE_SAFE_THRESHOLD = 2;
export const RECOVERABLE_SAFE_OWNER_COUNT = 3;
export const SAFE_MAINNET_IDENTITY = Object.freeze({
  factory: '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67',
  factoryCodeHash: '0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317',
  singleton: '0x41675C099F32341bf84BFc5382aF534df5C7461a',
  singletonCodeHash: '0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4',
  fallbackHandler: '0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99',
  fallbackHandlerCodeHash: '0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9',
  proxyCreationCodeHash: '0x1856e0ee08399d74e0ea0b03adca210aeade6f748969ac023cdcb4dd62dcaf5f',
});
export const SAFE_CONTROL_SPECS = Object.freeze([
  Object.freeze({role: 'governance', saltNonce: '1'}),
  Object.freeze({role: 'reserveGuardian', saltNonce: '2'}),
  Object.freeze({role: 'checkpointGuardian', saltNonce: '3'}),
]);

const zeroAddress = '0x0000000000000000000000000000000000000000';
const factoryInterface = new Interface([
  'function createProxyWithNonce(address singleton,bytes initializer,uint256 saltNonce) returns (address proxy)',
  'function proxyCreationCode() view returns (bytes)',
]);
const safeInterface = new Interface([
  'function setup(address[] owners,uint256 threshold,address to,bytes data,address fallbackHandler,address paymentToken,uint256 payment,address payable paymentReceiver)',
]);

function fail(message) {
  throw new Error(message);
}

function canonicalAddress(value, label) {
  if (typeof value !== 'string' || !isAddress(value)) fail(`${label} must be an address`);
  return getAddress(value);
}

function canonicalOwners(values, expectedCount) {
  if(!Array.isArray(values) || values.length!==expectedCount) {
    fail(`owners must contain exactly ${expectedCount} addresses`);
  }
  const owners=values.map((value,index)=>canonicalAddress(value,`owner ${index + 1}`))
    .sort((left,right)=>left.toLowerCase().localeCompare(right.toLowerCase()));
  if(new Set(owners.map(value=>value.toLowerCase())).size!==owners.length) {
    fail('Safe owners must be distinct');
  }
  return owners;
}

export function canonicalOwnersByRole(value) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify(
        SAFE_CONTROL_SPECS.map(({role})=>role).sort())) {
    fail('ownersByRole must contain exactly governance, reserveGuardian and checkpointGuardian');
  }
  const result=Object.fromEntries(SAFE_CONTROL_SPECS.map(({role})=>[
    role,canonicalOwners(value[role],RECOVERABLE_SAFE_OWNER_COUNT),
  ]));
  const all=Object.values(result).flat().map(owner=>owner.toLowerCase());
  if(new Set(all).size!==all.length) fail('Safe owner addresses must not be reused between roles');
  return result;
}

function canonicalTransaction(transaction) {
  if (!transaction || typeof transaction !== 'object') fail('Safe deployment transaction is missing');
  const to = canonicalAddress(transaction.to, 'Safe deployment target');
  if (transaction.value !== '0') fail('Safe deployment value must be the decimal string 0');
  if (typeof transaction.data !== 'string' || !/^0x[0-9a-fA-F]+$/.test(transaction.data)) {
    fail('Safe deployment calldata must be nonempty canonical hex');
  }
  return {to, value: '0', data: transaction.data.toLowerCase()};
}

function decodeAndValidateSetup({transaction, owners, threshold, saltNonce}) {
  let outer;
  try {
    outer = factoryInterface.decodeFunctionData('createProxyWithNonce', transaction.data);
  } catch {
    fail('Safe deployment calldata is not createProxyWithNonce');
  }
  if (outer.saltNonce !== BigInt(saltNonce)) fail('Safe deployment salt nonce mismatch');

  let setup;
  try {
    setup = safeInterface.decodeFunctionData('setup', outer.initializer);
  } catch {
    fail('Safe initializer is not setup');
  }
  if(setup.owners.length!==owners.length
      || setup.owners.some((value,index)=>getAddress(value)!==owners[index])) {
    fail('Safe initializer must contain exactly the approved ordered owners');
  }
  if(setup.threshold!==BigInt(threshold)) fail('Safe initializer threshold mismatch');
  if (getAddress(setup.to) !== zeroAddress || setup.data !== '0x') {
    fail('Safe initializer must not install a delegatecall');
  }
  if (getAddress(setup.paymentToken) !== zeroAddress || setup.payment !== 0n
      || getAddress(setup.paymentReceiver) !== zeroAddress) {
    fail('Safe initializer must not configure deployment payment');
  }
  return {
    singleton: getAddress(outer.singleton),
    initializer: outer.initializer.toLowerCase(),
    fallbackHandler: getAddress(setup.fallbackHandler),
  };
}

async function requireCode(provider, address, label, blockTag) {
  const code = await provider.getCode(address, blockTag);
  if (code === '0x') fail(`${label} has no code at the requested block`);
  return keccak256(code);
}

function requirePinnedIdentity(observed) {
  for (const key of Object.keys(SAFE_MAINNET_IDENTITY)) {
    if (observed[key] !== SAFE_MAINNET_IDENTITY[key]) {
      fail(`Safe mainnet ${key} does not match the pinned identity`);
    }
  }
}

async function prepareSafeControlDeploymentsForPolicy({
  ownersByRole,
  threshold,
  schema,
  rpcUrl,
  blockTag = 'finalized',
  providerFactory = (url) => new BoundedMainnetPreflightProvider(url),
} = {}) {
  if (typeof rpcUrl !== 'string' || rpcUrl.length === 0) fail('rpcUrl is required');
  const provider = providerFactory(rpcUrl);
  try {
  const network = await provider.getNetwork();
  if (network.chainId !== 1n) fail(`expected Ethereum chain ID 1, got ${network.chainId}`);
  if (!await provider.getBlock(blockTag)) fail('RPC did not return the requested block');
  const ownerCode=await Promise.all(Object.values(ownersByRole).flat()
    .map(value=>provider.getCode(value,blockTag)));
  if(ownerCode.some(code=>code!=='0x')) {
    fail('every Safe owner must be a hardware-wallet EOA, not a contract');
  }

  const proxyCreationResult = await provider.call({
    to: SAFE_MAINNET_IDENTITY.factory,
    data: factoryInterface.encodeFunctionData('proxyCreationCode'),
    blockTag,
  });
  const [proxyCreationCode] = factoryInterface.decodeFunctionResult(
    'proxyCreationCode', proxyCreationResult,
  );

  const controls = [];
  let shared;
  for (const spec of SAFE_CONTROL_SPECS) {
    const owners=ownersByRole[spec.role];
    const initializer = safeInterface.encodeFunctionData('setup', [
      owners, threshold, zeroAddress, '0x',
      SAFE_MAINNET_IDENTITY.fallbackHandler, zeroAddress, 0, zeroAddress,
    ]);
    const transaction = canonicalTransaction({
      to: SAFE_MAINNET_IDENTITY.factory,
      value: '0',
      data: factoryInterface.encodeFunctionData('createProxyWithNonce', [
        SAFE_MAINNET_IDENTITY.singleton, initializer, spec.saltNonce,
      ]),
    });
    const decoded = decodeAndValidateSetup({transaction,owners,threshold,saltNonce:spec.saltNonce});
    const initcode = concat([proxyCreationCode, zeroPadValue(decoded.singleton, 32)]);
    const salt = keccak256(solidityPacked(
      ['bytes32', 'uint256'], [keccak256(decoded.initializer), BigInt(spec.saltNonce)],
    ));
    const independentlyDerivedSafe = getCreate2Address(
      transaction.to, salt, keccak256(initcode),
    );
    const safe = canonicalAddress(independentlyDerivedSafe, `${spec.role} Safe`);

    const identity = {
      factory: transaction.to,
      singleton: decoded.singleton,
      fallbackHandler: decoded.fallbackHandler,
      proxyCreationCodeHash: keccak256(proxyCreationCode),
    };
    if (shared && JSON.stringify(shared) !== JSON.stringify(identity)) {
      fail('Safe deployment identities differ across control planes');
    }
    shared = identity;
    controls.push({
      role: spec.role,
      owners,
      saltNonce: spec.saltNonce,
      safe,
      to: transaction.to,
      value: transaction.value,
      data: transaction.data,
      dataHash: keccak256(transaction.data),
    });
  }

  if (new Set(controls.map(({safe}) => safe)).size !== controls.length) {
    fail('predicted Safe addresses are not distinct');
  }
  const observedIdentity = {
    ...shared,
    factoryCodeHash: await requireCode(provider, shared.factory, 'Safe proxy factory', blockTag),
    singletonCodeHash: await requireCode(provider, shared.singleton, 'Safe singleton', blockTag),
    fallbackHandlerCodeHash: await requireCode(
      provider, shared.fallbackHandler, 'Safe fallback handler', blockTag,
    ),
  };
  requirePinnedIdentity(observedIdentity);
  return {
    schema,
    ethereumChainId: '1',
    ownersByRole,
    threshold: String(threshold),
    safeVersion: SAFE_VERSION,
    ...observedIdentity,
    controls,
  };
  } finally {
    if (typeof provider?.destroy === 'function') await provider.destroy();
  }
}

/** Build the production control-plane package with three independent hardware
 * keys and a 2-of-3 threshold. Input order cannot change the CREATE2 addresses. */
export async function prepareRecoverableSafeControlDeployments({
  ownersByRole,rpcUrl,blockTag,providerFactory,
}={}) {
  return prepareSafeControlDeploymentsForPolicy({
    ownersByRole:canonicalOwnersByRole(ownersByRole),
    threshold:RECOVERABLE_SAFE_THRESHOLD,schema:RECOVERABLE_SAFE_CONTROL_SCHEMA,
    rpcUrl,blockTag,providerFactory,
  });
}

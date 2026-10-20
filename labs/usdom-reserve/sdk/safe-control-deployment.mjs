import {
  Interface,
  JsonRpcProvider,
  concat,
  getAddress,
  getCreate2Address,
  isAddress,
  keccak256,
  solidityPacked,
  zeroPadValue,
} from 'ethers';

export const SAFE_CONTROL_SCHEMA = 'usdom-safe-controls/v1';
export const SAFE_VERSION = '1.4.1';
export const SAFE_THRESHOLD = 1;
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

function canonicalTransaction(transaction) {
  if (!transaction || typeof transaction !== 'object') fail('Safe deployment transaction is missing');
  const to = canonicalAddress(transaction.to, 'Safe deployment target');
  if (transaction.value !== '0') fail('Safe deployment value must be the decimal string 0');
  if (typeof transaction.data !== 'string' || !/^0x[0-9a-fA-F]+$/.test(transaction.data)) {
    fail('Safe deployment calldata must be nonempty canonical hex');
  }
  return {to, value: '0', data: transaction.data.toLowerCase()};
}

function decodeAndValidateSetup({transaction, owner, saltNonce}) {
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
  if (setup.owners.length !== 1 || getAddress(setup.owners[0]) !== owner) {
    fail('Safe initializer must contain exactly the approved owner');
  }
  if (setup.threshold !== 1n) fail('Safe initializer threshold must be 1');
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

async function requireCode(provider, address, label) {
  const code = await provider.getCode(address, 'finalized');
  if (code === '0x') fail(`${label} has no code at finalized`);
  return keccak256(code);
}

function requirePinnedIdentity(observed, expected) {
  for (const key of Object.keys(SAFE_MAINNET_IDENTITY)) {
    if (observed[key] !== expected[key]) {
      fail(`Safe mainnet ${key} does not match the pinned identity`);
    }
  }
}

export async function prepareSafeControlDeployments({
  owner,
  rpcUrl,
  providerFactory = (url) => new JsonRpcProvider(url),
  expectedIdentity = SAFE_MAINNET_IDENTITY,
} = {}) {
  const canonicalOwner = canonicalAddress(owner, 'owner');
  if (typeof rpcUrl !== 'string' || rpcUrl.length === 0) fail('rpcUrl is required');
  const provider = providerFactory(rpcUrl);
  const network = await provider.getNetwork();
  if (network.chainId !== 1n) fail(`expected Ethereum chain ID 1, got ${network.chainId}`);
  if (!await provider.getBlock('finalized')) fail('RPC did not return a finalized block');
  if (await provider.getCode(canonicalOwner, 'finalized') !== '0x') {
    fail('the sole Safe owner must be the hardware-wallet EOA, not a contract');
  }

  const controls = [];
  let shared;
  for (const spec of SAFE_CONTROL_SPECS) {
    const initializer = safeInterface.encodeFunctionData('setup', [
      [canonicalOwner], SAFE_THRESHOLD, zeroAddress, '0x',
      SAFE_MAINNET_IDENTITY.fallbackHandler, zeroAddress, 0, zeroAddress,
    ]);
    const transaction = canonicalTransaction({
      to: SAFE_MAINNET_IDENTITY.factory,
      value: '0',
      data: factoryInterface.encodeFunctionData('createProxyWithNonce', [
        SAFE_MAINNET_IDENTITY.singleton, initializer, spec.saltNonce,
      ]),
    });
    const decoded = decodeAndValidateSetup({transaction, owner: canonicalOwner, saltNonce: spec.saltNonce});
    const proxyCreationResult = await provider.call({
      to: transaction.to,
      data: factoryInterface.encodeFunctionData('proxyCreationCode'),
    }, 'finalized');
    const [proxyCreationCode] = factoryInterface.decodeFunctionResult(
      'proxyCreationCode', proxyCreationResult,
    );
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
    factoryCodeHash: await requireCode(provider, shared.factory, 'Safe proxy factory'),
    singletonCodeHash: await requireCode(provider, shared.singleton, 'Safe singleton'),
    fallbackHandlerCodeHash: await requireCode(
      provider, shared.fallbackHandler, 'Safe fallback handler',
    ),
  };
  requirePinnedIdentity(observedIdentity, expectedIdentity);
  return {
    schema: SAFE_CONTROL_SCHEMA,
    ethereumChainId: '1',
    owner: canonicalOwner,
    threshold: String(SAFE_THRESHOLD),
    safeVersion: SAFE_VERSION,
    ...observedIdentity,
    controls,
  };
}

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
  Object.freeze({role: 'usdtCustody', saltNonce: '4'}),
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
  const address=getAddress(value);
  // Ethereum mainnet precompiles have empty code and therefore otherwise look
  // like EOAs to the deployment observer, despite being unable to sign.
  if(BigInt(address)<=0x11n) fail(`${label} must not be a reserved precompile address`);
  return address;
}

function canonicalOwners(values, expectedCount) {
  if(!Array.isArray(values) || values.length!==expectedCount) {
    fail(`owners must contain exactly ${expectedCount} addresses`);
  }
  const owners=values.map((value,index)=>canonicalAddress(value,`owner ${index + 1}`))
    .sort((left,right)=>{
      const a=left.toLowerCase(),b=right.toLowerCase();
      return a<b?-1:a>b?1:0;
    });
  if(new Set(owners.map(value=>value.toLowerCase())).size!==owners.length) {
    fail('Safe owners must be distinct');
  }
  return owners;
}

export function canonicalOwnersByRole(value) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      ||JSON.stringify(Object.keys(value).sort())!==JSON.stringify(
        SAFE_CONTROL_SPECS.map(({role})=>role).sort())) {
    fail('ownersByRole must contain exactly governance, reserveGuardian, checkpointGuardian and usdtCustody');
  }
  const result=Object.fromEntries(SAFE_CONTROL_SPECS.map(({role})=>[
    role,canonicalOwners(value[role],RECOVERABLE_SAFE_OWNER_COUNT),
  ]));
  const sets=Object.values(result).map(set=>set.map(owner=>owner.toLowerCase()).sort());
  if(sets.some(set=>JSON.stringify(set)!==JSON.stringify(sets[0]))) fail('all separated Safe roles must use the same ratified 2-of-3 owner set');
  return result;
}

/** Validate the complete deterministic deployment package without trusting a
 * previously computed package hash. This is used again by offline consumers
 * after the RPC-backed preparation ceremony. */
export function validateRecoverableSafeControlPackage(document) {
  const packageKeys=['schema','ethereumChainId','ownersByRole','threshold','safeVersion',
    'factory','singleton','fallbackHandler','proxyCreationCodeHash','factoryCodeHash',
    'singletonCodeHash','fallbackHandlerCodeHash','controls'];
  if(!document||typeof document!=='object'||Array.isArray(document)
      ||JSON.stringify(Object.keys(document).sort())!==JSON.stringify(packageKeys.sort())
      ||document.schema!==RECOVERABLE_SAFE_CONTROL_SCHEMA||document.ethereumChainId!=='1'
      ||document.threshold!==String(RECOVERABLE_SAFE_THRESHOLD)
      ||document.safeVersion!==SAFE_VERSION) fail('Safe package policy is invalid');
  const ownersByRole=canonicalOwnersByRole(document.ownersByRole);
  if(JSON.stringify(ownersByRole)!==JSON.stringify(document.ownersByRole)) {
    fail('Safe package owners must use canonical order and checksum');
  }
  for(const key of Object.keys(SAFE_MAINNET_IDENTITY)) {
    if(document[key]!==SAFE_MAINNET_IDENTITY[key]) fail(`Safe package ${key} is not pinned`);
  }
  if(!Array.isArray(document.controls)||document.controls.length!==SAFE_CONTROL_SPECS.length) {
    fail('Safe package controls are invalid');
  }
  const safes=[];
  for(let index=0;index<SAFE_CONTROL_SPECS.length;index++) {
    const spec=SAFE_CONTROL_SPECS[index],control=document.controls[index];
    if(!control||JSON.stringify(Object.keys(control).sort())!==JSON.stringify(
      ['role','owners','saltNonce','safe','to','value','data','dataHash'].sort())
        ||control.role!==spec.role||control.saltNonce!==spec.saltNonce
        ||JSON.stringify(control.owners)!==JSON.stringify(ownersByRole[spec.role])
        ||getAddress(control.safe)!==control.safe||getAddress(control.to)!==SAFE_MAINNET_IDENTITY.factory
        ||control.value!=='0'||control.dataHash!==keccak256(control.data)) {
      fail(`${spec.role} Safe deployment control is invalid`);
    }
    const transaction=canonicalTransaction(control);
    const decoded=decodeAndValidateSetup({transaction,owners:ownersByRole[spec.role],
      threshold:RECOVERABLE_SAFE_THRESHOLD,saltNonce:spec.saltNonce});
    if(decoded.singleton!==SAFE_MAINNET_IDENTITY.singleton
        ||decoded.fallbackHandler!==SAFE_MAINNET_IDENTITY.fallbackHandler) {
      fail(`${spec.role} Safe initializer identity is invalid`);
    }
    safes.push(control.safe.toLowerCase());
  }
  if(new Set(safes).size!==SAFE_CONTROL_SPECS.length) fail('predicted Safe addresses must be globally distinct');
  const owners=Object.values(ownersByRole).flat().map(value=>value.toLowerCase());
  if(safes.some(safe=>owners.includes(safe))) {
    fail('predicted Safe addresses must not be Safe owners');
  }
  return document;
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

function deploymentBlockIdentity(block, label) {
  if(!block || !Number.isSafeInteger(block.number) || block.number<0
      || typeof block.hash!=='string' || !/^0x[0-9a-fA-F]{64}$/.test(block.hash)) {
    fail(`${label} block identity is invalid`);
  }
  return {number:block.number,hash:block.hash.toLowerCase()};
}

function deploymentBlockNumber(blockTag, finalizedNumber) {
  if(blockTag==='finalized') return finalizedNumber;
  const validNumber=typeof blockTag==='number' && Number.isSafeInteger(blockTag) && blockTag>=0;
  const validHex=typeof blockTag==='string' && /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,13})$/.test(blockTag);
  if(!validNumber && !validHex) fail('Safe deployment block tag must be finalized or a numeric block');
  const number=Number(blockTag);
  if(!Number.isSafeInteger(number) || number>finalizedNumber) {
    fail('Safe deployment snapshot exceeds the finalized block');
  }
  return number;
}

function requirePinnedIdentity(observed) {
  for (const key of Object.keys(SAFE_MAINNET_IDENTITY)) {
    if (observed[key] !== SAFE_MAINNET_IDENTITY[key]) {
      fail(`Safe mainnet ${key} does not match the pinned identity`);
    }
  }
}

export function buildRecoverableSafeControlDeploymentPackage({ownersByRole,proxyCreationCode}={}) {
  const canonicalByRole=canonicalOwnersByRole(ownersByRole);
  if(typeof proxyCreationCode!=='string'||!/^0x(?:[0-9a-fA-F]{2})+$/.test(proxyCreationCode)
      ||keccak256(proxyCreationCode)!==SAFE_MAINNET_IDENTITY.proxyCreationCodeHash) {
    fail('Safe proxy creation code does not match the pinned identity');
  }
  const controls=SAFE_CONTROL_SPECS.map(spec=>{
    const owners=canonicalByRole[spec.role];
    const initializer=safeInterface.encodeFunctionData('setup',[owners,RECOVERABLE_SAFE_THRESHOLD,
      zeroAddress,'0x',SAFE_MAINNET_IDENTITY.fallbackHandler,zeroAddress,0,zeroAddress]);
    const transaction=canonicalTransaction({to:SAFE_MAINNET_IDENTITY.factory,value:'0',
      data:factoryInterface.encodeFunctionData('createProxyWithNonce',[
        SAFE_MAINNET_IDENTITY.singleton,initializer,spec.saltNonce])});
    const decoded=decodeAndValidateSetup({transaction,owners,threshold:RECOVERABLE_SAFE_THRESHOLD,
      saltNonce:spec.saltNonce});
    const initcode=concat([proxyCreationCode,zeroPadValue(decoded.singleton,32)]);
    const salt=keccak256(solidityPacked(['bytes32','uint256'],[
      keccak256(decoded.initializer),BigInt(spec.saltNonce)]));
    return {role:spec.role,owners,saltNonce:spec.saltNonce,
      safe:getCreate2Address(transaction.to,salt,keccak256(initcode)),to:transaction.to,
      value:transaction.value,data:transaction.data,dataHash:keccak256(transaction.data)};
  });
  if(new Set(controls.map(value=>value.safe.toLowerCase())).size!==controls.length) {
    fail('predicted Safe addresses must be globally distinct');
  }
  const owners=Object.values(canonicalByRole).flat().map(value=>value.toLowerCase());
  if(controls.some(value=>owners.includes(value.safe.toLowerCase()))) {
    fail('predicted Safe addresses must not be Safe owners');
  }
  return {schema:RECOVERABLE_SAFE_CONTROL_SCHEMA,ethereumChainId:'1',ownersByRole:canonicalByRole,
    threshold:String(RECOVERABLE_SAFE_THRESHOLD),safeVersion:SAFE_VERSION,...SAFE_MAINNET_IDENTITY,controls};
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
  const finalized=deploymentBlockIdentity(await provider.getBlock('finalized'),'initial finalized');
  const snapshotNumber=deploymentBlockNumber(blockTag,finalized.number);
  const snapshot=snapshotNumber===finalized.number?finalized:
    deploymentBlockIdentity(await provider.getBlock(snapshotNumber),'requested Safe snapshot');
  if(snapshot.number!==snapshotNumber) fail('Safe deployment snapshot number does not match its request');
  provider.pinFinalizedSnapshot?.(snapshot.number,snapshot.hash);
  blockTag=snapshot.number;
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

  const deterministic=buildRecoverableSafeControlDeploymentPackage({ownersByRole,proxyCreationCode});

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
  const result={...deterministic,schema,...observedIdentity,controls};
  validateRecoverableSafeControlPackage(result);
  const ending=deploymentBlockIdentity(await provider.getBlock(blockTag),'ending Safe snapshot');
  if(ending.number!==snapshot.number || ending.hash!==snapshot.hash) {
    fail('Safe deployment finalized snapshot changed during preparation');
  }
  const finalizedAfter=deploymentBlockIdentity(await provider.getBlock('finalized'),'ending finalized');
  if(finalizedAfter.number<finalized.number
      || (finalizedAfter.number===finalized.number && finalizedAfter.hash!==finalized.hash)) {
    fail('Safe deployment finalized snapshot changed or regressed during preparation');
  }
  return result;
  } finally {
    if (typeof provider?.destroy === 'function') await provider.destroy();
  }
}

/** Build each production control role from three distinct hardware-wallet EOA
 * identities and a 2-of-3 threshold. This describes key separation, not three
 * different human operators. Input order cannot change the CREATE2 addresses. */
export async function prepareRecoverableSafeControlDeployments({
  ownersByRole,rpcUrl,blockTag,providerFactory,
}={}) {
  return prepareSafeControlDeploymentsForPolicy({
    ownersByRole:canonicalOwnersByRole(ownersByRole),
    threshold:RECOVERABLE_SAFE_THRESHOLD,schema:RECOVERABLE_SAFE_CONTROL_SCHEMA,
    rpcUrl,blockTag,providerFactory,
  });
}

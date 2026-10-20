import {
  AbiCoder,concat,getAddress,getBytes,hexlify,keccak256,toBeHex,zeroPadBytes,zeroPadValue,toUtf8Bytes,
} from 'ethers';
import {finalizedBurnVerifierConfigHash} from './verifier-config.mjs';
import {checkpointVerifierConfigHash} from './checkpoint-verifier-config.mjs';

const immutableFields={
  token:['token','address'],tokenCodeHash:['tokenCodeHash','bytes32'],verifier:['verifier','address'],
  verifierCodeHash:['verifierCodeHash','bytes32'],verifierConfigHash:['verifierConfigHash','bytes32'],
  reserveConfigHash:['reserveConfigHash','bytes32'],domDomain:['domDomain','bytes32'],
  activationScheduleCommitment:['activationScheduleCommitment','bytes32'],
  governance:['governance','address'],governanceCodeHash:['governanceCodeHash','bytes32'],
  guardian:['guardian','address'],guardianCodeHash:['guardianCodeHash','bytes32'],
  withdrawalDelay:['withdrawalDelaySeconds','uint64'],governanceDelay:['governanceDelaySeconds','uint64'],
  maxOutstanding:['maxOutstandingBaseUnits','uint64'],outflowCapacity:['outflowCapacityBaseUnitsPerDay','uint64'],
};
const checkpointRegistryImmutableFields={
  bridgeDomain:['domDomain','bytes32'],domNetworkMagic:['checkpointDomNetworkMagic','uint32'],
  domChainId:['checkpointDomChainId','bytes32'],firstV4Height:['checkpointFirstV4Height','uint64'],
  activationEmptyStateRoot:['checkpointActivationEmptyStateRoot','bytes32'],
  activationScheduleCommitment:['activationScheduleCommitment','bytes32'],
  checkpointInterval:['checkpointIntervalBlocks','uint32'],
  confirmationDepth:['checkpointConfirmationDepthBlocks','uint32'],
  challengePeriod:['checkpointChallengePeriodSeconds','uint64'],
  verifier:['checkpointVerifier','address'],verifierCodeHash:['checkpointVerifierCodeHash','bytes32'],
  verifierConfigHash:['checkpointVerifierConfigHash','bytes32'],
  guardian:['checkpointGuardian','address'],guardianCodeHash:['checkpointGuardianCodeHash','bytes32'],
};
const finalizedBurnAdapterImmutableFields={
  riscZeroVerifier:['riscZeroVerifier','address'],
  riscZeroVerifierCodeHash:['riscZeroVerifierCodeHash','bytes32'],
  verifierSelector:['riscZeroVerifierSelector','bytes4'],
  imageId:['finalizedBurnGuestImageId','bytes32'],deploymentChainId:['ethereumChainId','uint256'],
  verifierConfigHash:['verifierConfigHash','bytes32'],
};
const checkpointAdapterImmutableFields={
  riscZeroVerifier:['riscZeroVerifier','address'],
  riscZeroVerifierCodeHash:['riscZeroVerifierCodeHash','bytes32'],
  verifierSelector:['riscZeroVerifierSelector','bytes4'],
  imageId:['checkpointGuestImageId','bytes32'],deploymentChainId:['ethereumChainId','uint256'],
  verifierConfigHash:['verifierConfigHash','bytes32'],
};
const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const expectedCompiler='0.8.37+commit.f401782d';
const expectedTarget='contracts/USDOMProofReserve.sol';

export function verifyCompilerSettings(artifact,{target=expectedTarget,contract='USDOMProofReserve'}={}) {
  const metadata=artifact?.metadata;
  const settings=metadata?.settings;
  if (metadata?.compiler?.version!==expectedCompiler) throw new Error('unexpected Solidity compiler version');
  if (settings?.optimizer?.enabled!==true || settings.optimizer.runs!==200) {
    throw new Error('unexpected optimizer configuration');
  }
  if (settings?.evmVersion!=='cancun') throw new Error('unexpected EVM version');
  if (settings?.metadata?.bytecodeHash!=='none') throw new Error('unexpected bytecode metadata hash mode');
  if (settings?.viaIR===true) throw new Error('unexpected via-IR compilation');
  const targets=settings?.compilationTarget;
  if (!targets || Object.keys(targets).length!==1 || targets[target]!==contract) {
    throw new Error('unexpected compilation target');
  }
  if (!settings.libraries || Object.keys(settings.libraries).length!==0) throw new Error('linked libraries are forbidden');
  const remappings=settings.remappings;
  const expectedRemapping='@openzeppelin/contracts/=vendor/openzeppelin-contracts-5.6.1/';
  if (!Array.isArray(remappings) || !remappings.includes(expectedRemapping)
      || remappings.some(value=>value.startsWith('@openzeppelin/contracts/=') && value!==expectedRemapping)) {
    throw new Error('unexpected OpenZeppelin remapping');
  }
  return {compilerVersion:expectedCompiler,evmVersion:'cancun',optimizerRuns:200,bytecodeHash:'none'};
}

function immutableDeclarations(ast) {
  const declarations=new Map();
  const walk=value=>{
    if (Array.isArray(value)) for(const item of value) walk(item);
    else if (value && typeof value==='object') {
      if (value.nodeType==='VariableDeclaration' && value.mutability==='immutable') {
        declarations.set(String(value.id),value.name);
      }
      for(const child of Object.values(value)) walk(child);
    }
  };
  walk(ast);
  return declarations;
}

function encodeImmutable(value,type) {
  if (type==='address') return getBytes(zeroPadValue(getAddress(value),32));
  if (type==='bytes32') {
    if (!bytes32Pattern.test(value??'')) throw new Error('immutable bytes32 is not canonical');
    return getBytes(value);
  }
  if(type==='bytes4') {
    if(typeof value!=='string' || !/^0x[0-9a-fA-F]{8}$/.test(value)) {
      throw new Error('immutable bytes4 is not canonical');
    }
    return getBytes(zeroPadBytes(value,32));
  }
  let integer;
  try { integer=BigInt(value); } catch { throw new Error('immutable integer is not canonical'); }
  const bits=type==='uint32'?32:type==='uint64'?64:256;
  if (integer<0n || integer>=(1n<<BigInt(bits))) throw new Error(`immutable ${type} is out of range`);
  return getBytes(zeroPadValue(toBeHex(integer),32));
}

function bytecodeObject(section,label) {
  const object=typeof section?.object==='string' && section.object.startsWith('0x')
    ? section.object.slice(2) : section?.object;
  if (typeof object!=='string' || object.length===0 || object.length%2!==0 || !/^[0-9a-fA-F]+$/.test(object)) {
    throw new Error(`${label} bytecode is absent or malformed`);
  }
  if (Object.keys(section.linkReferences??{}).length!==0) throw new Error(`linked ${label} libraries are unsupported`);
  return '0x'+object;
}

export function verifyArtifactSources(artifact,sourceContents) {
  const sources=artifact?.metadata?.sources;
  if (!sources || typeof sources!=='object') throw new Error('artifact metadata sources are absent');
  for(const [name,metadata] of Object.entries(sources)) {
    const content=sourceContents?.[name];
    if (typeof content!=='string' && !(content instanceof Uint8Array)) {
      throw new Error(`artifact source is absent: ${name}`);
    }
    if (keccak256(typeof content==='string'?toUtf8Bytes(content):content)!==metadata.keccak256) {
      throw new Error(`artifact source hash mismatch: ${name}`);
    }
  }
  return Object.keys(sources).length;
}

function deriveRuntimeCodeHash({artifact,releaseConfig,sourceContents,fields,target,contract}) {
  const compiler=verifyCompilerSettings(artifact,{target,contract});
  if (!artifact?.ast) throw new Error('artifact AST is absent; build with ast=true');
  const deployed=artifact?.deployedBytecode;
  const object=bytecodeObject(deployed,'deployed runtime');
  const declarations=immutableDeclarations(artifact.ast);
  const references=deployed.immutableReferences;
  if (!references || typeof references!=='object') throw new Error('immutable references are absent');
  if (declarations.size!==Object.keys(fields).length
      || Object.keys(references).length!==Object.keys(fields).length) {
    throw new Error('unexpected immutable declaration or reference count');
  }
  const runtime=getBytes(object);
  const seen=new Set();
  for(const [id,locations] of Object.entries(references)) {
    const name=declarations.get(id);
    const field=fields[name];
    if (!field || seen.has(name) || !Array.isArray(locations) || locations.length===0) {
      throw new Error(`unexpected immutable reference: ${id}`);
    }
    seen.add(name);
    const encoded=encodeImmutable(releaseConfig?.[field[0]],field[1]);
    for(const location of locations) {
      if (!Number.isSafeInteger(location?.start) || location.start<0 || location.length!==32
          || location.start+32>runtime.length) throw new Error(`invalid immutable location: ${name}`);
      runtime.set(encoded,location.start);
    }
  }
  if (seen.size!==Object.keys(fields).length) throw new Error('not every immutable was patched');
  const sourceCount=sourceContents===undefined?null:verifyArtifactSources(artifact,sourceContents);
  return {runtimeCodeHash:keccak256(runtime),runtimeSize:runtime.length,
    compilerVersion:compiler.compilerVersion,sourceCount,runtimeBytecode:hexlify(runtime)};
}

export function deriveReserveRuntimeCodeHash({artifact,releaseConfig,sourceContents}) {
  return deriveRuntimeCodeHash({artifact,releaseConfig,sourceContents,fields:immutableFields,
    target:expectedTarget,contract:'USDOMProofReserve'});
}

export function deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig,sourceContents}) {
  return deriveRuntimeCodeHash({artifact,releaseConfig,sourceContents,fields:checkpointRegistryImmutableFields,
    target:'contracts/DOMCheckpointRegistry.sol',contract:'DOMCheckpointRegistry'});
}

export function deriveFinalizedBurnVerifierRuntimeCodeHash({artifact,verifierConfig,sourceContents}) {
  const computed=finalizedBurnVerifierConfigHash(verifierConfig);
  return deriveRuntimeCodeHash({artifact,releaseConfig:computed,sourceContents,
    fields:finalizedBurnAdapterImmutableFields,
    target:'contracts/DOMFinalizedBurnRiscZeroVerifier.sol',contract:'DOMFinalizedBurnRiscZeroVerifier'});
}

export function deriveCheckpointVerifierRuntimeCodeHash({artifact,verifierConfig,sourceContents}) {
  const computed=checkpointVerifierConfigHash(verifierConfig);
  return deriveRuntimeCodeHash({artifact,releaseConfig:computed,sourceContents,
    fields:checkpointAdapterImmutableFields,
    target:'contracts/DOMCheckpointRiscZeroVerifier.sol',contract:'DOMCheckpointRiscZeroVerifier'});
}

function deriveRiscZeroAdapterInitcode({
  artifact,verifierConfig,sourceContents,target,contract,imageIdField,configuration,
}) {
  const compiler=verifyCompilerSettings(artifact,{target,contract});
  const creation=bytecodeObject(artifact?.bytecode,`${contract} creation`);
  const sourceCount=sourceContents===undefined?null:verifyArtifactSources(artifact,sourceContents);
  const computed=configuration(verifierConfig);
  const encoded=AbiCoder.defaultAbiCoder().encode(
    ['address','bytes32'],[getAddress(computed.riscZeroVerifier),computed[imageIdField]],
  );
  const initcode=concat([creation,encoded]);
  return {initcodeHash:keccak256(initcode),initcodeSize:getBytes(initcode).length,
    compilerVersion:compiler.compilerVersion,sourceCount,initcode};
}

export function deriveFinalizedBurnVerifierInitcodeHash({artifact,verifierConfig,sourceContents}) {
  return deriveRiscZeroAdapterInitcode({artifact,verifierConfig,sourceContents,
    target:'contracts/DOMFinalizedBurnRiscZeroVerifier.sol',contract:'DOMFinalizedBurnRiscZeroVerifier',
    imageIdField:'finalizedBurnGuestImageId',configuration:finalizedBurnVerifierConfigHash});
}

export function deriveCheckpointVerifierInitcodeHash({artifact,verifierConfig,sourceContents}) {
  return deriveRiscZeroAdapterInitcode({artifact,verifierConfig,sourceContents,
    target:'contracts/DOMCheckpointRiscZeroVerifier.sol',contract:'DOMCheckpointRiscZeroVerifier',
    imageIdField:'checkpointGuestImageId',configuration:checkpointVerifierConfigHash});
}

export function deriveReserveInitcodeHash({artifact,releaseConfig,sourceContents}) {
  const compiler=verifyCompilerSettings(artifact);
  const creation=bytecodeObject(artifact?.bytecode,'creation');
  const sourceCount=sourceContents===undefined?null:verifyArtifactSources(artifact,sourceContents);
  const bytes32=name=>{
    const value=releaseConfig?.[name];
    if (!bytes32Pattern.test(value??'')) throw new Error(`constructor ${name} is not canonical bytes32`);
    return value;
  };
  const uint64=name=>{
    let value;
    try { value=BigInt(releaseConfig?.[name]); } catch { throw new Error(`constructor ${name} is not canonical uint64`); }
    if (value<0n || value>=(1n<<64n)) throw new Error(`constructor ${name} is out of uint64 range`);
    return value;
  };
  const tuple='tuple(address token,address verifier,bytes32 domDomain,bytes32 activationScheduleCommitment,address governance,address guardian,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity)';
  const encoded=AbiCoder.defaultAbiCoder().encode([tuple],[{
    token:getAddress(releaseConfig?.token),verifier:getAddress(releaseConfig?.verifier),
    domDomain:bytes32('domDomain'),activationScheduleCommitment:bytes32('activationScheduleCommitment'),
    governance:getAddress(releaseConfig?.governance),
    guardian:getAddress(releaseConfig?.guardian),withdrawalDelay:uint64('withdrawalDelaySeconds'),
    governanceDelay:uint64('governanceDelaySeconds'),maxOutstanding:uint64('maxOutstandingBaseUnits'),
    outflowCapacity:uint64('outflowCapacityBaseUnitsPerDay'),
  }]);
  const initcode=concat([creation,encoded]);
  return {initcodeHash:keccak256(initcode),initcodeSize:getBytes(initcode).length,
    compilerVersion:compiler.compilerVersion,sourceCount,initcode};
}

export function deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig,sourceContents}) {
  const compiler=verifyCompilerSettings(artifact,{
    target:'contracts/DOMCheckpointRegistry.sol',contract:'DOMCheckpointRegistry',
  });
  const creation=bytecodeObject(artifact?.bytecode,'checkpoint registry creation');
  const sourceCount=sourceContents===undefined?null:verifyArtifactSources(artifact,sourceContents);
  const bytes32=name=>{
    const value=releaseConfig?.[name];
    if (!bytes32Pattern.test(value??'')) throw new Error(`constructor ${name} is not canonical bytes32`);
    return value;
  };
  const integer=(name,bits)=>{
    let value;
    try { value=BigInt(releaseConfig?.[name]); }
    catch { throw new Error(`constructor ${name} is not canonical uint${bits}`); }
    if (value<0n || value>=(1n<<BigInt(bits))) throw new Error(`constructor ${name} is out of uint${bits} range`);
    return value;
  };
  const tuple='tuple(bytes32 bridgeDomain,uint32 domNetworkMagic,bytes32 domChainId,uint64 firstV4Height,bytes32 activationEmptyStateRoot,bytes32 activationScheduleCommitment,uint32 checkpointInterval,uint32 confirmationDepth,uint64 challengePeriod,address verifier,address guardian,uint64 initialHeight,bytes32 initialBlock,bytes32 initialStateRoot,bytes32 initialContextHash,uint256 initialTotalDifficulty)';
  const encoded=AbiCoder.defaultAbiCoder().encode([tuple],[{
    bridgeDomain:bytes32('domDomain'),domNetworkMagic:integer('checkpointDomNetworkMagic',32),
    domChainId:bytes32('checkpointDomChainId'),firstV4Height:integer('checkpointFirstV4Height',64),
    activationEmptyStateRoot:bytes32('checkpointActivationEmptyStateRoot'),
    activationScheduleCommitment:bytes32('activationScheduleCommitment'),
    checkpointInterval:integer('checkpointIntervalBlocks',32),
    confirmationDepth:integer('checkpointConfirmationDepthBlocks',32),
    challengePeriod:integer('checkpointChallengePeriodSeconds',64),
    verifier:getAddress(releaseConfig?.checkpointVerifier),guardian:getAddress(releaseConfig?.checkpointGuardian),
    initialHeight:integer('checkpointInitialHeight',64),initialBlock:bytes32('checkpointInitialBlock'),
    initialStateRoot:bytes32('checkpointInitialStateRoot'),
    initialContextHash:bytes32('checkpointInitialContextHash'),
    initialTotalDifficulty:integer('checkpointInitialTotalDifficulty',256),
  }]);
  const initcode=concat([creation,encoded]);
  return {initcodeHash:keccak256(initcode),initcodeSize:getBytes(initcode).length,
    compilerVersion:compiler.compilerVersion,sourceCount,initcode};
}

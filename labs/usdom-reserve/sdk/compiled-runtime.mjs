import {
  AbiCoder,concat,getAddress,getBytes,hexlify,keccak256,toBeHex,zeroPadBytes,zeroPadValue,toUtf8Bytes,
} from 'ethers';
import {finalizedBurnAdapterConfigHash,finalizedBurnVerifierConfigHash} from './verifier-config.mjs';
import {checkpointAdapterConfigHash,checkpointVerifierConfigHash} from './checkpoint-verifier-config.mjs';
import {checkpointRegistryConfigHash} from './checkpoint-registry.mjs';
import {proofReserveDeploymentConfigHash,safeOwnersCommitment} from './configuration.mjs';

const immutableFields={
  token:['token','address'],deploymentChainId:['ethereumChainId','uint256'],
  tokenCodeHash:['tokenCodeHash','bytes32'],verifier:['verifier','address'],
  verifierCodeHash:['verifierCodeHash','bytes32'],verifierConfigHash:['verifierConfigHash','bytes32'],
  checkpointRegistry:['checkpointRegistry','address'],
  checkpointRegistryCodeHash:['checkpointRegistryRuntimeCodeHash','bytes32'],
  checkpointRegistryConfigHash:['checkpointRegistryConfigHash','bytes32'],
  domDomain:['domDomain','bytes32'],
  governance:['governance','address'],governanceCodeHash:['governanceCodeHash','bytes32'],
  governanceImplementation:['governanceImplementation','address'],
  governanceImplementationCodeHash:['governanceImplementationCodeHash','bytes32'],
  governanceOwnersCommitment:['governanceOwnersCommitment','bytes32'],
  guardian:['guardian','address'],guardianCodeHash:['guardianCodeHash','bytes32'],
  guardianImplementation:['guardianImplementation','address'],
  guardianImplementationCodeHash:['guardianImplementationCodeHash','bytes32'],
  guardianOwnersCommitment:['guardianOwnersCommitment','bytes32'],
  withdrawalDelay:['withdrawalDelaySeconds','uint64'],governanceDelay:['governanceDelaySeconds','uint64'],
  maxOutstanding:['maxOutstandingBaseUnits','uint64'],outflowCapacity:['outflowCapacityBaseUnitsPerDay','uint64'],
  pilotRestrictedDeployment:['pilotRestricted','bool'],
};
const checkpointRegistryImmutableFields={
  bridgeDomain:['domDomain','bytes32'],deploymentChainId:['ethereumChainId','uint256'],
  domNetworkMagic:['checkpointDomNetworkMagic','uint32'],
  domChainId:['checkpointDomChainId','bytes32'],firstV4Height:['checkpointFirstV4Height','uint64'],
  checkpointInterval:['checkpointIntervalBlocks','uint32'],
  confirmationDepth:['checkpointConfirmationDepthBlocks','uint32'],
  challengePeriod:['checkpointChallengePeriodSeconds','uint64'],
  verifier:['checkpointVerifier','address'],verifierCodeHash:['checkpointVerifierCodeHash','bytes32'],
  verifierConfigHash:['checkpointVerifierConfigHash','bytes32'],
  guardian:['checkpointGuardian','address'],guardianCodeHash:['checkpointGuardianCodeHash','bytes32'],
  guardianImplementation:['checkpointGuardianImplementation','address'],
  guardianImplementationCodeHash:['checkpointGuardianImplementationCodeHash','bytes32'],
  guardianOwnersCommitment:['checkpointGuardianOwnersCommitment','bytes32'],
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
  if (!settings || Object.keys(settings).sort().join(',')
      !=='compilationTarget,evmVersion,libraries,metadata,optimizer,remappings,viaIR') {
    throw new Error('unexpected Solidity compiler settings schema');
  }
  if (Object.keys(settings.optimizer??{}).sort().join(',')!=='enabled,runs'
      || settings.optimizer.enabled!==true || settings.optimizer.runs!==1) {
    throw new Error('unexpected optimizer configuration');
  }
  if (settings?.evmVersion!=='cancun') throw new Error('unexpected EVM version');
  if (Object.keys(settings.metadata??{}).join(',')!=='bytecodeHash'
      || settings.metadata.bytecodeHash!=='none') throw new Error('unexpected bytecode metadata configuration');
  if (settings?.viaIR!==true) throw new Error('unexpected non-via-IR compilation');
  const targets=settings?.compilationTarget;
  if (!targets || Object.keys(targets).length!==1 || targets[target]!==contract) {
    throw new Error('unexpected compilation target');
  }
  if (!settings.libraries || Object.keys(settings.libraries).length!==0) throw new Error('linked libraries are forbidden');
  const remappings=settings.remappings;
  const expectedRemappings=[
    '@openzeppelin/contracts/=vendor/openzeppelin-contracts-5.6.1/',
  ];
  if (!Array.isArray(remappings) || remappings.length!==expectedRemappings.length
      || remappings.some((value,index)=>value!==expectedRemappings[index])) {
    throw new Error('unexpected OpenZeppelin remapping');
  }
  return {compilerVersion:expectedCompiler,evmVersion:'cancun',optimizerRuns:1,viaIR:true,bytecodeHash:'none'};
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

function verifyConstructorInputs(artifact,inputs,label) {
  const constructors=artifact?.abi?.filter(item=>item?.type==='constructor')??[];
  const actual=constructors[0]?.inputs??[];
  if(constructors.length!==1 || actual.length!==inputs.length
      ||actual.some((value,index)=>value.name!==inputs[index][0]||value.type!==inputs[index][1])) {
    throw new Error(`${label} constructor ABI order or type drifted`);
  }
  return actual;
}

function verifyFunctionAbi(artifact,{name,inputs,outputs,stateMutability},label) {
  const matches=artifact?.abi?.filter(item=>item?.type==='function'&&item.name===name)??[];
  const item=matches[0];
  if(matches.length!==1 || item.stateMutability!==stateMutability
      || (item.inputs??[]).length!==inputs.length || (item.outputs??[]).length!==outputs.length
      || item.inputs.some((value,index)=>value.type!==inputs[index])
      || item.outputs.some((value,index)=>value.type!==outputs[index])) {
    throw new Error(`${label} ABI drifted`);
  }
}

/** The deployment binding consumes more than constructor encoding: operators,
 * monitors and parent contracts rely on this exact external ABI. Reject an
 * artifact whose ABI metadata describes another return convention or preimage
 * entrypoint before deriving any release hash from it. */
function verifyRiscZeroAdapterAbi(artifact,contract) {
  const proofFunction=contract==='DOMFinalizedBurnRiscZeroVerifier'
    ? 'verifyFinalizedBurn':'verifyDOMCheckpoint';
  for(const requirement of [
    {name:proofFunction,inputs:['bytes32','bytes'],outputs:['bytes32'],stateMutability:'view'},
    {name:'journalDigest',inputs:['bytes32'],outputs:['bytes32'],stateMutability:'pure'},
    {name:'verifierConfigHash',inputs:[],outputs:['bytes32'],stateMutability:'view'},
    {name:'riscZeroVerifier',inputs:[],outputs:['address'],stateMutability:'view'},
    {name:'riscZeroVerifierCodeHash',inputs:[],outputs:['bytes32'],stateMutability:'view'},
    {name:'verifierSelector',inputs:[],outputs:['bytes4'],stateMutability:'view'},
    {name:'imageId',inputs:[],outputs:['bytes32'],stateMutability:'view'},
    {name:'deploymentChainId',inputs:[],outputs:['uint256'],stateMutability:'view'},
  ]) verifyFunctionAbi(artifact,requirement,`${contract}.${requirement.name}`);
}

function verifyConstructorTuple(artifact,components,label) {
  const input=verifyConstructorInputs(artifact,[['config','tuple']],label)[0];
  const actual=input.components??[];
  if(actual.length!==components.length || actual.some((value,index)=>
    value.name!==components[index][0]||value.type!==components[index][1])) {
    throw new Error(`${label} constructor tuple order or type drifted`);
  }
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
  const occupied=[];
  const immutablePatchManifest=[];
  for(const [id,locations] of Object.entries(references)) {
    const name=declarations.get(id);
    const field=fields[name];
    if (!field || seen.has(name) || !Array.isArray(locations) || locations.length===0) {
      throw new Error(`unexpected immutable reference: ${id}`);
    }
    seen.add(name);
    const encoded=encodeImmutable(releaseConfig?.[field[0]],field[1]);
    const starts=[];
    for(const location of locations) {
      if (!Number.isSafeInteger(location?.start) || location.start<0 || location.length!==32
          || location.start+32>runtime.length) throw new Error(`invalid immutable location: ${name}`);
      const overlapping=occupied.find(value=>location.start<value.end&&location.start+32>value.start);
      if(overlapping) throw new Error(`overlapping immutable locations: ${overlapping.name}/${name}`);
      if(runtime.subarray(location.start,location.start+32).some(byte=>byte!==0)) {
        throw new Error(`immutable placeholder is not zero-filled: ${name}`);
      }
      occupied.push({start:location.start,end:location.start+32,name});
      runtime.set(encoded,location.start);
      if(!runtime.subarray(location.start,location.start+32).every((byte,index)=>byte===encoded[index])) {
        throw new Error(`immutable patch verification failed: ${name}`);
      }
      starts.push(location.start);
    }
    immutablePatchManifest.push({name,configField:field[0],type:field[1],encoded:hexlify(encoded),
      locations:starts.sort((a,b)=>a-b)});
  }
  if (seen.size!==Object.keys(fields).length) throw new Error('not every immutable was patched');
  occupied.sort((a,b)=>a.start-b.start);
  for(let index=1;index<occupied.length;index++) {
    if(occupied[index].start<occupied[index-1].end) {
      throw new Error(`overlapping immutable locations: ${occupied[index-1].name}/${occupied[index].name}`);
    }
  }
  immutablePatchManifest.sort((a,b)=>a.name.localeCompare(b.name));
  const sourceCount=sourceContents===undefined?null:verifyArtifactSources(artifact,sourceContents);
  return {runtimeCodeHash:keccak256(runtime),runtimeSize:runtime.length,
    compilerVersion:compiler.compilerVersion,sourceCount,runtimeBytecode:hexlify(runtime),
    immutableReferenceCount:occupied.length,immutablePatchManifest,
    immutablePatchManifestHash:keccak256(toUtf8Bytes(JSON.stringify(immutablePatchManifest)))};
}

export function deriveReserveRuntimeCodeHash({artifact,releaseConfig,sourceContents}) {
  return deriveRuntimeCodeHash({artifact,releaseConfig:{...releaseConfig,pilotRestricted:true},sourceContents,fields:immutableFields,
    target:expectedTarget,contract:'USDOMProofReserve'});
}

/** Revalidate a derived immutable manifest without relying on contract-version
 * counts. Every compiler reference must be represented once, occupy one exact
 * 32-byte word and contain the canonical ABI word installed in the runtime. */
export function validateImmutablePatchManifest(binding) {
  const manifest=binding?.immutablePatchManifest;
  const runtime=getBytes(binding?.runtimeBytecode??'0x');
  if(!Array.isArray(manifest)||manifest.length===0
      ||!Number.isSafeInteger(binding?.immutableReferenceCount)
      ||binding.immutableReferenceCount<=0
      ||!bytes32Pattern.test(binding?.immutablePatchManifestHash??'')) {
    throw new Error('immutable patch manifest is incomplete');
  }
  const canonical={
    address:/^0x0{24}[0-9a-f]{40}$/,bytes32:/^0x[0-9a-f]{64}$/,
    uint256:/^0x[0-9a-f]{64}$/,uint64:/^0x0{48}[0-9a-f]{16}$/,
    uint32:/^0x0{56}[0-9a-f]{8}$/,bytes4:/^0x[0-9a-f]{8}0{56}$/,
    bool:/^0x0{62}(?:00|01)$/,
  };
  const names=new Set(),fields=new Set(),locations=[];
  let previousName='';
  for(const entry of manifest) {
    if(!entry||typeof entry!=='object'||Array.isArray(entry)
        ||Object.keys(entry).sort().join(',')!=='configField,encoded,locations,name,type'
        ||typeof entry.name!=='string'||!/^[A-Za-z_][A-Za-z0-9_]*$/.test(entry.name)
        ||entry.name.localeCompare(previousName)<=0||names.has(entry.name)
        ||typeof entry.configField!=='string'||!/^[A-Za-z_][A-Za-z0-9_]*$/.test(entry.configField)
        ||fields.has(entry.configField)||!(entry.type in canonical)
        ||!canonical[entry.type].test(entry.encoded??'')
        ||!Array.isArray(entry.locations)||entry.locations.length===0) {
      throw new Error('immutable patch manifest is noncanonical');
    }
    names.add(entry.name);fields.add(entry.configField);previousName=entry.name;
    let previous=-1;
    const encoded=getBytes(entry.encoded);
    for(const start of entry.locations) {
      if(!Number.isSafeInteger(start)||start<=previous||start<0||start+32>runtime.length) {
        throw new Error('immutable patch manifest location is invalid');
      }
      previous=start;
      locations.push({start,end:start+32,name:entry.name,encoded});
    }
  }
  locations.sort((left,right)=>left.start-right.start);
  if(locations.length!==binding.immutableReferenceCount) {
    throw new Error('immutable patch manifest does not cover every reference');
  }
  for(let index=1;index<locations.length;index++) {
    if(locations[index].start<locations[index-1].end) {
      throw new Error('immutable patch manifest locations overlap');
    }
  }
  for(const location of locations) {
    if(!runtime.subarray(location.start,location.end)
      .every((byte,index)=>byte===location.encoded[index])) {
      throw new Error('immutable patch manifest differs from runtime');
    }
  }
  const manifestHash=keccak256(toUtf8Bytes(JSON.stringify(manifest)));
  if(manifestHash.toLowerCase()!==binding.immutablePatchManifestHash.toLowerCase()) {
    throw new Error('immutable patch manifest hash mismatch');
  }
  return binding;
}

/** Derive both reserve bytecode identities only after proving that the release
 * fields (including canonical Safe owner-set commitments) form its declared config. */
export function deriveReserveArtifactBinding({artifact,releaseConfig,sourceContents}) {
  const configuration=proofReserveDeploymentConfigHash({
    ethereumChainId:releaseConfig?.ethereumChainId,reserve:releaseConfig?.reserve,
    token:releaseConfig?.token,tokenCodeHash:releaseConfig?.tokenCodeHash,
    verifier:releaseConfig?.verifier,verifierCodeHash:releaseConfig?.verifierCodeHash,
    verifierConfigHash:releaseConfig?.verifierConfigHash,
    checkpointRegistry:releaseConfig?.checkpointRegistry,
    checkpointRegistryRuntimeCodeHash:releaseConfig?.checkpointRegistryRuntimeCodeHash,
    checkpointRegistryConfigHash:releaseConfig?.checkpointRegistryConfigHash,
    domDomain:releaseConfig?.domDomain,
    activationScheduleCommitment:releaseConfig?.activationScheduleCommitment,
    governance:releaseConfig?.governance,governanceCodeHash:releaseConfig?.governanceCodeHash,
    governanceImplementation:releaseConfig?.governanceImplementation,
    governanceImplementationCodeHash:releaseConfig?.governanceImplementationCodeHash,
    governanceOwnersCommitment:releaseConfig?.governanceOwnersCommitment,
    guardian:releaseConfig?.guardian,guardianCodeHash:releaseConfig?.guardianCodeHash,
    guardianImplementation:releaseConfig?.guardianImplementation,
    guardianImplementationCodeHash:releaseConfig?.guardianImplementationCodeHash,
    guardianOwnersCommitment:releaseConfig?.guardianOwnersCommitment,
    withdrawalDelaySeconds:releaseConfig?.withdrawalDelaySeconds,
    governanceDelaySeconds:releaseConfig?.governanceDelaySeconds,
    maxOutstandingBaseUnits:releaseConfig?.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerDay:releaseConfig?.outflowCapacityBaseUnitsPerDay,
  });
  if(typeof releaseConfig?.reserveConfigHash!=='string'
      || releaseConfig.reserveConfigHash.toLowerCase()!==configuration.reserveConfigHash) {
    throw new Error('reserveConfigHash does not match the exact owner-bound release');
  }
  const runtime=deriveReserveRuntimeCodeHash({artifact,releaseConfig,sourceContents});
  const initcode=deriveReserveInitcodeHash({artifact,releaseConfig,sourceContents});
  return {...runtime,initcodeHash:initcode.initcodeHash,initcodeSize:initcode.initcodeSize,
    initcode:initcode.initcode,reserveConfigHash:configuration.reserveConfigHash};
}

export function deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig,sourceContents}) {
  const boundRelease={...releaseConfig,checkpointGuardianOwnersCommitment:
    safeOwnersCommitment(releaseConfig?.checkpointGuardianOwners)};
  return deriveRuntimeCodeHash({artifact,releaseConfig:boundRelease,sourceContents,fields:checkpointRegistryImmutableFields,
    target:'contracts/DOMCheckpointRegistry.sol',contract:'DOMCheckpointRegistry'});
}

export function deriveFinalizedBurnVerifierRuntimeCodeHash({artifact,verifierConfig,sourceContents}) {
  verifyRiscZeroAdapterAbi(artifact,'DOMFinalizedBurnRiscZeroVerifier');
  const computed=finalizedBurnVerifierConfigHash(verifierConfig);
  return deriveRuntimeCodeHash({artifact,releaseConfig:computed,sourceContents,
    fields:finalizedBurnAdapterImmutableFields,
    target:'contracts/DOMFinalizedBurnRiscZeroVerifier.sol',contract:'DOMFinalizedBurnRiscZeroVerifier'});
}

export function deriveFinalizedBurnAdapterRuntimeCodeHash({artifact,adapterConfig,sourceContents}) {
  verifyRiscZeroAdapterAbi(artifact,'DOMFinalizedBurnRiscZeroVerifier');
  const computed=finalizedBurnAdapterConfigHash(adapterConfig);
  return deriveRuntimeCodeHash({artifact,releaseConfig:computed,sourceContents,
    fields:finalizedBurnAdapterImmutableFields,
    target:'contracts/DOMFinalizedBurnRiscZeroVerifier.sol',contract:'DOMFinalizedBurnRiscZeroVerifier'});
}

export function deriveCheckpointVerifierRuntimeCodeHash({artifact,verifierConfig,sourceContents}) {
  verifyRiscZeroAdapterAbi(artifact,'DOMCheckpointRiscZeroVerifier');
  const computed=checkpointVerifierConfigHash(verifierConfig);
  return deriveRuntimeCodeHash({artifact,releaseConfig:computed,sourceContents,
    fields:checkpointAdapterImmutableFields,
    target:'contracts/DOMCheckpointRiscZeroVerifier.sol',contract:'DOMCheckpointRiscZeroVerifier'});
}

export function deriveCheckpointAdapterRuntimeCodeHash({artifact,adapterConfig,sourceContents}) {
  verifyRiscZeroAdapterAbi(artifact,'DOMCheckpointRiscZeroVerifier');
  const computed=checkpointAdapterConfigHash(adapterConfig);
  return deriveRuntimeCodeHash({artifact,releaseConfig:computed,sourceContents,
    fields:checkpointAdapterImmutableFields,
    target:'contracts/DOMCheckpointRiscZeroVerifier.sol',contract:'DOMCheckpointRiscZeroVerifier'});
}

function verifierArtifactBinding({artifact,verifierConfig,sourceContents,expectedConfigHash,
  runtimeDeriver,initcodeDeriver,label}) {
  const computed=label==='finalized-burn'
    ? finalizedBurnVerifierConfigHash(verifierConfig) : checkpointVerifierConfigHash(verifierConfig);
  if(typeof expectedConfigHash!=='string'
      || computed.verifierConfigHash!==expectedConfigHash.toLowerCase()) {
    throw new Error(`${label} verifier config hash differs from exact release`);
  }
  const runtime=runtimeDeriver({artifact,verifierConfig,sourceContents});
  const initcode=initcodeDeriver({artifact,verifierConfig,sourceContents});
  if(runtime.sourceCount!==initcode.sourceCount) throw new Error(`${label} verifier source sets disagree`);
  return Object.freeze({...runtime,initcodeHash:initcode.initcodeHash,initcodeSize:initcode.initcodeSize,
    initcode:initcode.initcode,verifierConfigHash:computed.verifierConfigHash});
}

export function deriveFinalizedBurnVerifierArtifactBinding({artifact,verifierConfig,sourceContents,
  expectedConfigHash}) {
  return verifierArtifactBinding({artifact,verifierConfig,sourceContents,expectedConfigHash,
    runtimeDeriver:deriveFinalizedBurnVerifierRuntimeCodeHash,
    initcodeDeriver:deriveFinalizedBurnVerifierInitcodeHash,label:'finalized-burn'});
}

export function deriveCheckpointVerifierArtifactBinding({artifact,verifierConfig,sourceContents,
  expectedConfigHash}) {
  return verifierArtifactBinding({artifact,verifierConfig,sourceContents,expectedConfigHash,
    runtimeDeriver:deriveCheckpointVerifierRuntimeCodeHash,
    initcodeDeriver:deriveCheckpointVerifierInitcodeHash,label:'checkpoint'});
}

function deriveRiscZeroAdapterInitcode({
  artifact,verifierConfig,sourceContents,target,contract,imageIdField,configuration,
}) {
  const compiler=verifyCompilerSettings(artifact,{target,contract});
  const creation=bytecodeObject(artifact?.bytecode,`${contract} creation`);
  verifyConstructorInputs(artifact,[['verifier_','address'],['imageId_','bytes32']],contract);
  verifyRiscZeroAdapterAbi(artifact,contract);
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

export function deriveFinalizedBurnAdapterInitcodeHash({artifact,adapterConfig,sourceContents}) {
  return deriveRiscZeroAdapterInitcode({artifact,verifierConfig:adapterConfig,sourceContents,
    target:'contracts/DOMFinalizedBurnRiscZeroVerifier.sol',contract:'DOMFinalizedBurnRiscZeroVerifier',
    imageIdField:'finalizedBurnGuestImageId',configuration:finalizedBurnAdapterConfigHash});
}

export function deriveCheckpointAdapterInitcodeHash({artifact,adapterConfig,sourceContents}) {
  return deriveRiscZeroAdapterInitcode({artifact,verifierConfig:adapterConfig,sourceContents,
    target:'contracts/DOMCheckpointRiscZeroVerifier.sol',contract:'DOMCheckpointRiscZeroVerifier',
    imageIdField:'checkpointGuestImageId',configuration:checkpointAdapterConfigHash});
}

export function deriveFinalizedBurnAdapterArtifactBinding({artifact,adapterConfig,sourceContents,
  expectedConfigHash}) {
  const computed=finalizedBurnAdapterConfigHash(adapterConfig);
  if(typeof expectedConfigHash!=='string'||computed.verifierConfigHash!==expectedConfigHash.toLowerCase()) {
    throw new Error('finalized-burn adapter config hash differs from exact preactivation release');
  }
  const runtime=deriveFinalizedBurnAdapterRuntimeCodeHash({artifact,adapterConfig,sourceContents});
  const initcode=deriveFinalizedBurnAdapterInitcodeHash({artifact,adapterConfig,sourceContents});
  return Object.freeze({...runtime,initcodeHash:initcode.initcodeHash,initcodeSize:initcode.initcodeSize,
    initcode:initcode.initcode,verifierConfigHash:computed.verifierConfigHash});
}

export function deriveCheckpointAdapterArtifactBinding({artifact,adapterConfig,sourceContents,
  expectedConfigHash}) {
  const computed=checkpointAdapterConfigHash(adapterConfig);
  if(typeof expectedConfigHash!=='string'||computed.verifierConfigHash!==expectedConfigHash.toLowerCase()) {
    throw new Error('checkpoint adapter config hash differs from exact preactivation release');
  }
  const runtime=deriveCheckpointAdapterRuntimeCodeHash({artifact,adapterConfig,sourceContents});
  const initcode=deriveCheckpointAdapterInitcodeHash({artifact,adapterConfig,sourceContents});
  return Object.freeze({...runtime,initcodeHash:initcode.initcodeHash,initcodeSize:initcode.initcodeSize,
    initcode:initcode.initcode,verifierConfigHash:computed.verifierConfigHash});
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
  const components=[['token','address'],['verifier','address'],['checkpointRegistry','address'],
    ['domDomain','bytes32'],['activationScheduleCommitment','bytes32'],['governance','address'],
    ['guardian','address'],['withdrawalDelay','uint64'],['governanceDelay','uint64'],
    ['maxOutstanding','uint64'],['outflowCapacity','uint64'],['pilotRestricted','bool']];
  verifyConstructorTuple(artifact,components,'reserve');
  const tuple='tuple(address token,address verifier,address checkpointRegistry,bytes32 domDomain,bytes32 activationScheduleCommitment,address governance,address guardian,uint64 withdrawalDelay,uint64 governanceDelay,uint64 maxOutstanding,uint64 outflowCapacity,bool pilotRestricted)';
  const encoded=AbiCoder.defaultAbiCoder().encode([tuple],[{
    token:getAddress(releaseConfig?.token),verifier:getAddress(releaseConfig?.verifier),
    checkpointRegistry:getAddress(releaseConfig?.checkpointRegistry),
    domDomain:bytes32('domDomain'),activationScheduleCommitment:bytes32('activationScheduleCommitment'),
    governance:getAddress(releaseConfig?.governance),
    guardian:getAddress(releaseConfig?.guardian),withdrawalDelay:uint64('withdrawalDelaySeconds'),
    governanceDelay:uint64('governanceDelaySeconds'),maxOutstanding:uint64('maxOutstandingBaseUnits'),
    outflowCapacity:uint64('outflowCapacityBaseUnitsPerDay'),
    pilotRestricted:true,
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
  const components=[['bridgeDomain','bytes32'],['domNetworkMagic','uint32'],['domChainId','bytes32'],
    ['firstV4Height','uint64'],['activationEmptyStateRoot','bytes32'],
    ['activationScheduleCommitment','bytes32'],['checkpointInterval','uint32'],
    ['confirmationDepth','uint32'],['challengePeriod','uint64'],['verifier','address'],
    ['guardian','address'],['initialHeight','uint64'],['initialBlock','bytes32'],
    ['initialStateRoot','bytes32'],['initialContextHash','bytes32'],['initialTotalDifficulty','uint256']];
  verifyConstructorTuple(artifact,components,'checkpoint registry');
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

/**
 * Derive the complete checkpoint-registry artifact identity in one operation.
 * This prevents callers from accepting runtime/initcode derived from one set
 * of constructor fields while separately trusting a stale configuration hash.
 */
export function deriveCheckpointRegistryArtifactBinding({artifact,releaseConfig,sourceContents}) {
  const configuration=checkpointRegistryConfigHash({
    ethereumChainId:releaseConfig?.ethereumChainId,registry:releaseConfig?.checkpointRegistry,
    bridgeDomain:releaseConfig?.domDomain,domNetworkMagic:releaseConfig?.checkpointDomNetworkMagic,
    domChainId:releaseConfig?.checkpointDomChainId,firstV4Height:releaseConfig?.checkpointFirstV4Height,
    activationEmptyStateRoot:releaseConfig?.checkpointActivationEmptyStateRoot,
    activationScheduleCommitment:releaseConfig?.activationScheduleCommitment,
    checkpointInterval:releaseConfig?.checkpointIntervalBlocks,
    confirmationDepth:releaseConfig?.checkpointConfirmationDepthBlocks,
    challengePeriod:releaseConfig?.checkpointChallengePeriodSeconds,
    verifier:releaseConfig?.checkpointVerifier,verifierCodeHash:releaseConfig?.checkpointVerifierCodeHash,
    verifierConfigHash:releaseConfig?.checkpointVerifierConfigHash,
    guardian:releaseConfig?.checkpointGuardian,guardianCodeHash:releaseConfig?.checkpointGuardianCodeHash,
    guardianImplementation:releaseConfig?.checkpointGuardianImplementation,
    guardianImplementationCodeHash:releaseConfig?.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(releaseConfig?.checkpointGuardianOwners),
    initialHeight:releaseConfig?.checkpointInitialHeight,initialBlock:releaseConfig?.checkpointInitialBlock,
    initialStateRoot:releaseConfig?.checkpointInitialStateRoot,
    initialContextHash:releaseConfig?.checkpointInitialContextHash,
    initialTotalDifficulty:releaseConfig?.checkpointInitialTotalDifficulty,
  });
  if(typeof releaseConfig?.checkpointRegistryConfigHash!=='string'
      || configuration.checkpointConfigHash!==releaseConfig.checkpointRegistryConfigHash.toLowerCase()) {
    throw new Error('checkpoint registry configuration hash differs from exact release fields');
  }
  const runtime=deriveCheckpointRegistryRuntimeCodeHash({artifact,releaseConfig,sourceContents});
  const initcode=deriveCheckpointRegistryInitcodeHash({artifact,releaseConfig,sourceContents});
  if(runtime.sourceCount!==initcode.sourceCount) {
    throw new Error('checkpoint registry runtime and initcode source sets disagree');
  }
  return Object.freeze({
    checkpointRegistryConfigHash:configuration.checkpointConfigHash,
    runtimeCodeHash:runtime.runtimeCodeHash,runtimeSize:runtime.runtimeSize,
    initcodeHash:initcode.initcodeHash,initcodeSize:initcode.initcodeSize,
    compilerVersion:runtime.compilerVersion,sourceCount:runtime.sourceCount,
    runtimeBytecode:runtime.runtimeBytecode,initcode:initcode.initcode,
  });
}

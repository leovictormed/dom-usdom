import {createHash} from 'node:crypto';
import {
  Interface,concat,getAddress,getBytes,hexlify,keccak256,sha256,toBeHex,zeroPadValue,
} from 'ethers';
import {checkpointRegistryConfigHash,checkpointStatementHash} from './checkpoint-registry.mjs';
import {
  CHECKPOINT_EVM_SEAL_BYTES,CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,checkpointVerifierConfigHash,
  checkpointOuterAdapterBinding,
} from './checkpoint-verifier-config.mjs';
import {uint} from './reserve.mjs';
import {safeOwnersCommitment} from './configuration.mjs';
import {parseStrictJson} from './strict-json.mjs';

const zeroHash='0x'+'00'.repeat(32);
const zeroAddress='0x0000000000000000000000000000000000000000';
const statementBytes=551;
const statementMagic=Buffer.from('UDCPST06','ascii');
const groth16VerifierParameters=
  '73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc';
const outerImageId='e59d68487386939b2ac379f04528acb6b3138697e17adfda3ad23ebe195af3df';
const proofIndexFields=Object.freeze([
  'schema','outer_receipt_index_path','outer_receipt_index_sha256','outer_image_id',
  'statement_hash','journal_digest','risc0_zkvm_version','receipt_kind',
  'groth16_verifier_parameters','evm_verifier_selector','groth16_receipt_file',
  'groth16_receipt_sha256','groth16_receipt_bytes','evm_seal_file','evm_seal_sha256',
  'evm_seal_bytes','receipt_verified','dev_mode','generates_proofs','mines',
]);
const packageFields=Object.freeze([
  'schema','ethereumChainId','to','value','method','checkpoint','proof','statementHash',
  'journalDigest','data','dataKeccak256','source','broadcastAuthorized',
]);
const checkpointFields=Object.freeze([
  'previousHeight','previousBlock','previousStateRoot','previousContextHash','previousTotalDifficulty',
  'height','blockHash','stateRoot','contextHash','totalDifficulty','totalIssued','totalBurned','issuanceClosed','confirmationHeight',
  'confirmationBlock','confirmationTotalDifficulty','confirmationTimestamp',
]);
const packageProofFields=Object.freeze(['selector','bytes','sha256']);
const packageSourceFields=Object.freeze([
  'releaseConfigSha256','verifierManifestSha256','statementPath','statementSha256',
  'proofIndexPath','proofIndexSha256','sealPath','outerImageId','groth16VerifierParameters',
]);
const checkpointTuple=
  '(uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,'+
  'uint256 previousTotalDifficulty,uint64 height,bytes32 blockHash,bytes32 stateRoot,bytes32 contextHash,'+
  'uint256 totalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,uint64 confirmationHeight,bytes32 confirmationBlock,'+
  'uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp)';
const registryInterface=new Interface([
  `function checkpointStatementHash(${checkpointTuple} checkpoint) view returns (bytes32)`,
  `function submitCheckpointCandidate(${checkpointTuple} checkpoint,bytes proof)`,
]);

export const CHECKPOINT_SUBMISSION_SCHEMA='usdom-authenticated-checkpoint-submission-v1';
export {CHECKPOINT_EVM_SEAL_BYTES};
export const CHECKPOINT_STATEMENT_V6_BYTES=statementBytes;
export const CHECKPOINT_OUTER_IMAGE_ID='0x'+outerImageId;
export const CHECKPOINT_GROTH16_VERIFIER_PARAMETERS='0x'+groth16VerifierParameters;

function exact(value,fields,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...fields].sort())) {
    throw new Error(`exact ${label} fields required`);
  }
}

function rawHash(value,label,{nonzero=true}={}) {
  if(typeof value!=='string' || !/^[0-9a-f]{64}$/.test(value)
      || (nonzero && value==='0'.repeat(64))) throw new Error(`${label} must be canonical raw bytes32`);
  return value;
}

function bytes32(value,label,{nonzero=true}={}) {
  if(typeof value!=='string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be bytes32`);
  }
  const normalized=value.toLowerCase();
  if(nonzero && normalized===zeroHash) throw new Error(`${label} must be nonzero`);
  return normalized;
}

function canonicalCount(value,label,{zero=false,max=Number.MAX_SAFE_INTEGER}={}) {
  if(!Number.isSafeInteger(value) || value<0 || (!zero && value===0) || value>max) {
    throw new Error(`${label} must be a bounded canonical integer`);
  }
  return value;
}

function sha256Raw(value) {
  return createHash('sha256').update(value).digest('hex');
}

function readUnsigned(bytes,offset,length,label,bits) {
  const value=BigInt('0x'+Buffer.from(bytes.subarray(offset,offset+length)).toString('hex'));
  return uint(value,bits).toString();
}

function readHash(bytes,offset,label) {
  return bytes32(hexlify(bytes.subarray(offset,offset+32)),label);
}

function fixedUnsigned(value,bits) {
  const canonical=typeof value==='number' && Number.isSafeInteger(value) ? BigInt(value) : value;
  return getBytes(zeroPadValue(toBeHex(uint(canonical,bits)),bits/8));
}

/** Decode and validate the exact 551-byte economic checkpoint statement. */
export function parseCheckpointStatementV6(input) {
  const bytes=Buffer.from(input);
  if(bytes.length!==statementBytes || !bytes.subarray(0,8).equals(statementMagic)
      || bytes.readUInt16BE(8)!==6 || bytes.readUInt16BE(10)!==3 || bytes.readUInt16BE(12)!==4) {
    throw new Error('invalid UDCPST06 framing or version');
  }
  const identity={
    bridgeDomain:readHash(bytes,14,'bridgeDomain'),
    domNetworkMagic:readUnsigned(bytes,46,4,'domNetworkMagic',32),
    ethereumChainId:readUnsigned(bytes,402,32,'ethereumChainId',256),
    registry:getAddress(hexlify(bytes.subarray(434,454))),
    activationScheduleCommitment:readHash(bytes,454,'activationScheduleCommitment'),
    checkpointConfigHash:readHash(bytes,486,'checkpointConfigHash'),
  };
  if(identity.domNetworkMagic==='0' || identity.ethereumChainId==='0') {
    throw new Error('UDCPST06 has a zero network identity');
  }
  const checkpoint={
    previousHeight:readUnsigned(bytes,50,8,'previousHeight',64),
    previousBlock:readHash(bytes,58,'previousBlock'),
    previousStateRoot:readHash(bytes,90,'previousStateRoot'),
    previousContextHash:readHash(bytes,122,'previousContextHash'),
    previousTotalDifficulty:readUnsigned(bytes,154,32,'previousTotalDifficulty',256),
    height:readUnsigned(bytes,186,8,'height',64),
    blockHash:readHash(bytes,194,'blockHash'),
    stateRoot:readHash(bytes,226,'stateRoot'),
    contextHash:readHash(bytes,258,'contextHash'),
    totalDifficulty:readUnsigned(bytes,290,32,'totalDifficulty',256),
    confirmationHeight:readUnsigned(bytes,322,8,'confirmationHeight',64),
    confirmationBlock:readHash(bytes,330,'confirmationBlock'),
    confirmationTotalDifficulty:readUnsigned(bytes,362,32,'confirmationTotalDifficulty',256),
    confirmationTimestamp:readUnsigned(bytes,394,8,'confirmationTimestamp',64),
    totalIssued:readUnsigned(bytes,518,16,'totalIssued',128),
    totalBurned:readUnsigned(bytes,534,16,'totalBurned',128),
    issuanceClosed:bytes[550]===1,
  };
  if((bytes[550]!==0 && bytes[550]!==1)
      || identity.registry.toLowerCase()===zeroAddress
      || checkpoint.previousHeight==='0' || checkpoint.previousTotalDifficulty==='0'
      || BigInt(checkpoint.height)<=BigInt(checkpoint.previousHeight)
      || BigInt(checkpoint.confirmationHeight)<=BigInt(checkpoint.height)
      || checkpoint.blockHash===checkpoint.previousBlock
      || checkpoint.contextHash===checkpoint.previousContextHash
      || checkpoint.confirmationBlock===checkpoint.blockHash
      || BigInt(checkpoint.totalDifficulty)<=BigInt(checkpoint.previousTotalDifficulty)
      || BigInt(checkpoint.confirmationTotalDifficulty)<=BigInt(checkpoint.totalDifficulty)
      || checkpoint.confirmationTimestamp==='0'
      || BigInt(checkpoint.totalBurned)>BigInt(checkpoint.totalIssued)) {
    throw new Error('UDCPST06 has an invalid identity or extension relation');
  }
  return {identity,checkpoint};
}

/** Encode one exact statement from a registry configuration and checkpoint. */
export function encodeCheckpointStatementV6(registryConfiguration,checkpoint) {
  const configuration=checkpointRegistryConfigHash(registryConfiguration);
  const statementHash=checkpointStatementHash(registryConfiguration,checkpoint);
  const result=concat([
    statementMagic,fixedUnsigned(6,16),fixedUnsigned(3,16),fixedUnsigned(4,16),
    getBytes(configuration.bridgeDomain),fixedUnsigned(configuration.domNetworkMagic,32),
    fixedUnsigned(checkpoint.previousHeight,64),getBytes(checkpoint.previousBlock),
    getBytes(checkpoint.previousStateRoot),getBytes(checkpoint.previousContextHash),
    fixedUnsigned(checkpoint.previousTotalDifficulty,256),fixedUnsigned(checkpoint.height,64),
    getBytes(checkpoint.blockHash),getBytes(checkpoint.stateRoot),getBytes(checkpoint.contextHash),
    fixedUnsigned(checkpoint.totalDifficulty,256),fixedUnsigned(checkpoint.confirmationHeight,64),
    getBytes(checkpoint.confirmationBlock),fixedUnsigned(checkpoint.confirmationTotalDifficulty,256),
    fixedUnsigned(checkpoint.confirmationTimestamp,64),fixedUnsigned(configuration.ethereumChainId,256),
    getBytes(configuration.registry),getBytes(configuration.activationScheduleCommitment),
    getBytes(configuration.checkpointConfigHash),fixedUnsigned(checkpoint.totalIssued,128),
    fixedUnsigned(checkpoint.totalBurned,128),fixedUnsigned(checkpoint.issuanceClosed ? 1 : 0,8),
  ]);
  if(getBytes(result).length!==statementBytes) throw new Error('UDCPST06 encoder length mismatch');
  const parsed=parseCheckpointStatementV6(getBytes(result));
  if(checkpointStatementHash(registryConfiguration,parsed.checkpoint)!==statementHash) {
    throw new Error('UDCPST06 encoder hash mismatch');
  }
  return getBytes(result);
}

/** Extract the exact immutable checkpoint registry configuration from a release. */
export function checkpointRegistryConfigurationFromRelease(release) {
  if(!release || typeof release!=='object' || Array.isArray(release)) {
    throw new Error('release configuration must be an object');
  }
  const configuration={
    ethereumChainId:release.ethereumChainId,registry:release.checkpointRegistry,
    bridgeDomain:release.domDomain,domNetworkMagic:release.checkpointDomNetworkMagic,
    domChainId:release.checkpointDomChainId,firstV4Height:release.checkpointFirstV4Height,
    activationEmptyStateRoot:release.checkpointActivationEmptyStateRoot,
    activationScheduleCommitment:release.activationScheduleCommitment,
    checkpointInterval:release.checkpointIntervalBlocks,
    confirmationDepth:release.checkpointConfirmationDepthBlocks,
    challengePeriod:release.checkpointChallengePeriodSeconds,
    verifier:release.checkpointVerifier,verifierCodeHash:release.checkpointVerifierCodeHash,
    verifierConfigHash:release.checkpointVerifierConfigHash,
    guardian:release.checkpointGuardian,guardianCodeHash:release.checkpointGuardianCodeHash,
    guardianImplementation:release.checkpointGuardianImplementation,
    guardianImplementationCodeHash:release.checkpointGuardianImplementationCodeHash,
    guardianOwnersCommitment:safeOwnersCommitment(release.checkpointGuardianOwners),
    initialHeight:release.checkpointInitialHeight,initialBlock:release.checkpointInitialBlock,
    initialStateRoot:release.checkpointInitialStateRoot,
    initialContextHash:release.checkpointInitialContextHash,
    initialTotalDifficulty:release.checkpointInitialTotalDifficulty,
  };
  const computed=checkpointRegistryConfigHash(configuration);
  if(bytes32(release.checkpointRegistryConfigHash,'checkpointRegistryConfigHash')
      !==computed.checkpointConfigHash) {
    throw new Error('release checkpointRegistryConfigHash does not match its exact fields');
  }
  return configuration;
}

function verifyProtocolAgreement(configuration,verifier) {
  const pairs=[
    [configuration.ethereumChainId,verifier.ethereumChainId,'Ethereum chain ID'],
    [configuration.bridgeDomain,null,'bridge domain'],
    [configuration.domNetworkMagic,verifier.domNetworkMagic,'DOM network magic'],
    [configuration.domChainId,verifier.domChainId,'DOM chain ID'],
    [configuration.firstV4Height,verifier.firstV4Height,'first V4 height'],
    [configuration.activationEmptyStateRoot,verifier.activationEmptyStateRoot,'activation state root'],
    [configuration.activationScheduleCommitment,verifier.activationScheduleCommitment,'activation schedule'],
    [configuration.checkpointInterval,verifier.checkpointInterval,'checkpoint interval'],
    [configuration.confirmationDepth,verifier.confirmationDepth,'confirmation depth'],
    [configuration.challengePeriod,verifier.challengePeriod,'challenge period'],
  ];
  for(const [actual,expected,label] of pairs) {
    if(expected!==null && String(actual).toLowerCase()!==String(expected).toLowerCase()) {
      throw new Error(`${label} differs between registry and verifier configuration`);
    }
  }
}

function parseProofIndex(input) {
  const bytes=Buffer.from(input);
  if(bytes.length===0 || bytes.length>1024*1024) throw new Error('EVM proof index size is invalid');
  let json;
  try { json=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error('checkpoint outer EVM proof index contains invalid UTF-8'); }
  const index=parseStrictJson(json,{label:'checkpoint outer EVM proof index'});
  exact(index,proofIndexFields,'checkpoint outer EVM proof index');
  for(const field of [
    'outer_receipt_index_sha256','outer_image_id','statement_hash','journal_digest',
    'groth16_verifier_parameters','groth16_receipt_sha256','evm_seal_sha256',
  ]) rawHash(index[field],field);
  canonicalCount(index.groth16_receipt_bytes,'groth16_receipt_bytes',{max:256*1024*1024});
  canonicalCount(index.evm_seal_bytes,'evm_seal_bytes',{max:CHECKPOINT_EVM_SEAL_BYTES});
  if(index.schema!=='usdom-checkpoint-outer-evm-proof-v1'
      || index.outer_receipt_index_path
        !=='evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json'
      || index.outer_image_id!==outerImageId || index.risc0_zkvm_version!=='3.0.6'
      || index.receipt_kind!=='groth16'
      || index.groth16_verifier_parameters!==groth16VerifierParameters
      || index.evm_verifier_selector!==CHECKPOINT_RISC0_GROTH16_V3_SELECTOR.slice(2)
      || index.groth16_receipt_file!=='checkpoint-outer-groth16-receipt.bin'
      || index.evm_seal_file!=='checkpoint-outer-evm-seal.bin'
      || index.evm_seal_bytes!==CHECKPOINT_EVM_SEAL_BYTES
      || index.receipt_verified!==true || index.dev_mode!==false
      || index.generates_proofs!==true || index.mines!==false) {
    throw new Error('EVM proof index identity or verification claims are invalid');
  }
  return {bytes,index};
}

/**
 * Validate an authenticated outer proof package and emit deterministic,
 * unsigned calldata for the permissionless checkpoint registry entry point.
 */
export function buildAuthenticatedCheckpointSubmission({
  registryConfiguration,verifierConfiguration,statement,proofIndex,evmSeal,
  releaseConfigSha256='0'.repeat(64),verifierManifestSha256,
}) {
  const configuration=checkpointRegistryConfigHash(registryConfiguration);
  const verifier=checkpointVerifierConfigHash(verifierConfiguration);
  checkpointOuterAdapterBinding(verifierConfiguration,CHECKPOINT_OUTER_IMAGE_ID);
  rawHash(releaseConfigSha256,'releaseConfigSha256',{nonzero:false});
  const manifestSha=verifierManifestSha256??verifier.manifestSha256.slice(2);
  rawHash(manifestSha,'verifierManifestSha256');
  if(manifestSha!==verifier.manifestSha256.slice(2)) {
    throw new Error('checkpoint verifier manifest bytes are not canonical');
  }
  if(verifier.verifierConfigHash!==configuration.verifierConfigHash) {
    throw new Error('checkpoint verifier configuration hash differs from the registry');
  }
  verifyProtocolAgreement(configuration,verifier);
  const statementBuffer=Buffer.from(statement);
  const parsed=parseCheckpointStatementV6(statementBuffer);
  const expectedIdentity={
    bridgeDomain:configuration.bridgeDomain,domNetworkMagic:configuration.domNetworkMagic.toString(),
    ethereumChainId:configuration.ethereumChainId.toString(),registry:configuration.registry,
    activationScheduleCommitment:configuration.activationScheduleCommitment,
    checkpointConfigHash:configuration.checkpointConfigHash,
  };
  for(const [field,expected] of Object.entries(expectedIdentity)) {
    if(String(parsed.identity[field]).toLowerCase()!==String(expected).toLowerCase()) {
      throw new Error(`UDCPST06 ${field} differs from the exact registry release`);
    }
  }
  const statementHash=checkpointStatementHash(registryConfiguration,parsed.checkpoint);
  const parsedProof=parseProofIndex(proofIndex);
  const journalDigest=sha256(statementHash);
  if(parsedProof.index.statement_hash!==statementHash.slice(2)
      || parsedProof.index.journal_digest!==journalDigest.slice(2)) {
    throw new Error('EVM proof index does not bind the canonical checkpoint statement');
  }
  const seal=Buffer.from(evmSeal);
  if(seal.length!==CHECKPOINT_EVM_SEAL_BYTES
      || hexlify(seal.subarray(0,4)).toLowerCase()!==CHECKPOINT_RISC0_GROTH16_V3_SELECTOR
      || parsedProof.index.evm_seal_bytes!==seal.length
      || parsedProof.index.evm_seal_sha256!==sha256Raw(seal)) {
    throw new Error('EVM seal does not match the bounded selector-prefixed proof index');
  }
  const data=registryInterface.encodeFunctionData('submitCheckpointCandidate',[parsed.checkpoint,seal]);
  return {
    schema:CHECKPOINT_SUBMISSION_SCHEMA,
    ethereumChainId:configuration.ethereumChainId.toString(),
    to:configuration.registry,value:'0',method:'submitCheckpointCandidate',
    checkpoint:parsed.checkpoint,
    proof:{selector:CHECKPOINT_RISC0_GROTH16_V3_SELECTOR,bytes:seal.length,sha256:sha256Raw(seal)},
    statementHash,journalDigest,data,dataKeccak256:keccak256(data),
    source:{
      releaseConfigSha256,verifierManifestSha256:manifestSha,
      statementPath:'evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin',
      statementSha256:sha256Raw(statementBuffer),
      proofIndexPath:'evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-proof-index.json',
      proofIndexSha256:sha256Raw(parsedProof.bytes),
      sealPath:'evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-seal.bin',
      outerImageId:CHECKPOINT_OUTER_IMAGE_ID,
      groth16VerifierParameters:CHECKPOINT_GROTH16_VERIFIER_PARAMETERS,
    },
    broadcastAuthorized:false,
  };
}

/** Validate one serialized unsigned submission package without making an RPC call. */
export function validateAuthenticatedCheckpointSubmission(submission) {
  exact(submission,packageFields,'authenticated checkpoint submission');
  exact(submission.checkpoint,checkpointFields,'checkpoint submission checkpoint');
  exact(submission.proof,packageProofFields,'checkpoint submission proof');
  exact(submission.source,packageSourceFields,'checkpoint submission source');
  let decoded;
  try { decoded=registryInterface.decodeFunctionData('submitCheckpointCandidate',submission.data); }
  catch { throw new Error('checkpoint submission calldata is not decodable'); }
  const decodedProof=decoded[1];
  canonicalCount(submission.proof.bytes,'submission proof bytes',{max:CHECKPOINT_EVM_SEAL_BYTES});
  rawHash(submission.proof.sha256,'submission proof sha256');
  bytes32(submission.statementHash,'submission statementHash');
  bytes32(submission.journalDigest,'submission journalDigest');
  if(submission.schema!==CHECKPOINT_SUBMISSION_SCHEMA || submission.value!=='0'
      || submission.method!=='submitCheckpointCandidate' || submission.broadcastAuthorized!==false
      || submission.to!==getAddress(submission.to)
      || submission.proof.selector!==CHECKPOINT_RISC0_GROTH16_V3_SELECTOR
      || submission.proof.bytes!==CHECKPOINT_EVM_SEAL_BYTES
      || hexlify(getBytes(decodedProof).slice(0,4))!==submission.proof.selector
      || getBytes(decodedProof).length!==submission.proof.bytes
      || sha256Raw(getBytes(decodedProof))!==submission.proof.sha256
      || sha256(submission.statementHash)!==submission.journalDigest
      || registryInterface.encodeFunctionData('submitCheckpointCandidate',[
        submission.checkpoint,decodedProof,
      ])!==submission.data || keccak256(submission.data)!==submission.dataKeccak256) {
    throw new Error('checkpoint submission package is not canonical');
  }
  return {proof:decodedProof};
}

/** Re-run registry hashing and complete submission as a read-only local EVM call. */
export async function verifyAuthenticatedCheckpointSubmissionOnEvm(provider,submission) {
  validateAuthenticatedCheckpointSubmission(submission);
  const network=await provider.getNetwork();
  if(network.chainId.toString()!==submission.ethereumChainId) {
    throw new Error('local EVM chain ID differs from the submission package');
  }
  const code=await provider.getCode(submission.to);
  if(code==='0x') throw new Error('checkpoint registry has no EVM code');
  const hashCall=registryInterface.encodeFunctionData('checkpointStatementHash',[submission.checkpoint]);
  const returned=await provider.call({to:submission.to,data:hashCall});
  const [onchainHash]=registryInterface.decodeFunctionResult('checkpointStatementHash',returned);
  if(onchainHash.toLowerCase()!==submission.statementHash.toLowerCase()) {
    throw new Error('local EVM registry statement hash differs from the authenticated package');
  }
  await provider.call({to:submission.to,data:submission.data,value:0n});
  return {
    chainId:network.chainId.toString(),registry:submission.to,
    registryCodeHash:keccak256(code),statementHash:onchainHash.toLowerCase(),callAccepted:true,
  };
}

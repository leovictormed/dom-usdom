import {createHash} from 'node:crypto';
import {Interface,getAddress,getBytes,hexlify,keccak256,sha256} from 'ethers';
import {proofReserveDeploymentConfigHash} from './configuration.mjs';
import {finalizedBurnStatementHash,normalizeFinalizedBurn} from './proof-reserve.mjs';
import {parseStrictJson} from './strict-json.mjs';
import {uint} from './reserve.mjs';
import {
  FINALIZED_BURN_EVM_SEAL_BYTES,FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,
  finalizedBurnVerifierConfigHash,
} from './verifier-config.mjs';

const finalizedBurnImageId='2e26f74497b54b680dfff4c116d56280d016f01d0125329f49bf6d744b1c18ea';
const groth16VerifierParameters=
  '73c457ba541936f0d907daf0c7253a39a9c5c427c225ba7709e44702d3c6eedc';
const sourceIndexFields=Object.freeze([
  'schema','network','manifest_sha256','candidate_v2_first_height','burn_id',
  'checkpoint_dom_height','checkpoint_dom_block','checkpoint_dom_state_root',
  'checkpoint_ethereum_block_number','checkpoint_ethereum_block','checkpoint_beacon_slot',
  'checkpoint_witness_sha256','statement_hash','burn','ethereum_chain_id','reserve',
  'activation_schedule_commitment','input_file','input_sha256','input_length',
]);
const burnFields=Object.freeze([
  'burnId','requestId','recipient','amount','domDomain','height','blockHash','stateRoot',
  'finalityBeaconSlot','validUntil',
]);
const receiptIndexFields=Object.freeze([
  'schema','proof_job_index_path','proof_job_index_sha256','input_path','input_sha256',
  'statement_hash','program_path','program_sha256','image_id','risc0_zkvm_version',
  'receipt_kind','segment_limit_po2','receipt_file','receipt_sha256','receipt_bytes',
  'relation_executed','receipt_verified','dev_mode','generates_proofs','mines',
]);
const proofIndexFields=Object.freeze([
  'schema','receipt_index_path','receipt_index_sha256','image_id','statement_hash',
  'journal_digest','risc0_zkvm_version','receipt_kind','groth16_verifier_parameters',
  'evm_verifier_selector','groth16_receipt_file','groth16_receipt_sha256',
  'groth16_receipt_bytes','evm_seal_file','evm_seal_sha256','evm_seal_bytes',
  'receipt_verified','dev_mode','generates_proofs','mines',
]);
const packageFields=Object.freeze([
  'schema','ethereumChainId','to','value','method','burn','proof','statementHash',
  'journalDigest','data','dataKeccak256','source','broadcastAuthorized',
]);
const packageProofFields=Object.freeze(['selector','bytes','sha256']);
const packageSourceFields=Object.freeze([
  'releaseConfigSha256','verifierManifestSha256','sourceIndexPath','sourceIndexSha256',
  'inputPath','inputSha256','receiptIndexPath','receiptIndexSha256','proofIndexPath',
  'proofIndexSha256','sealPath','imageId','groth16VerifierParameters',
]);
const burnTuple=
  '(bytes32 burnId,bytes32 requestId,address recipient,uint64 amount,bytes32 domDomain,'+
  'uint64 height,bytes32 blockHash,bytes32 stateRoot,uint64 finalityBeaconSlot,uint64 validUntil)';
const reserveInterface=new Interface([
  `function burnStatementHash(${burnTuple} burn) view returns (bytes32)`,
  `function queueWithdrawal(${burnTuple} burn,bytes proof)`,
]);

export const FINALIZED_BURN_SUBMISSION_SCHEMA='usdom-authenticated-finalized-burn-submission-v1';
export const FINALIZED_BURN_IMAGE_ID='0x'+finalizedBurnImageId;
export const FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS='0x'+groth16VerifierParameters;
export {FINALIZED_BURN_EVM_SEAL_BYTES};

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
  if(nonzero && normalized==='0x'+'00'.repeat(32)) throw new Error(`${label} must be nonzero`);
  return normalized;
}

function canonicalCount(value,label,{max=Number.MAX_SAFE_INTEGER}={}) {
  if(!Number.isSafeInteger(value) || value<=0 || value>max) {
    throw new Error(`${label} must be a positive bounded canonical integer`);
  }
  return value;
}

function sha256Raw(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parseStrictIndex(bytes,label) {
  let json;
  try { json=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} contains invalid UTF-8`); }
  return parseStrictJson(json,{label});
}

/** Extract and independently hash the exact immutable reserve release fields. */
export function proofReserveConfigurationFromRelease(release) {
  if(!release || typeof release!=='object' || Array.isArray(release)) {
    throw new Error('release configuration must be an object');
  }
  const configuration={
    ethereumChainId:release.ethereumChainId,reserve:release.reserve,token:release.token,
    tokenCodeHash:release.tokenCodeHash,verifier:release.verifier,
    verifierCodeHash:release.verifierCodeHash,verifierConfigHash:release.verifierConfigHash,
    checkpointRegistry:release.checkpointRegistry,
    checkpointRegistryRuntimeCodeHash:release.checkpointRegistryRuntimeCodeHash,
    checkpointRegistryConfigHash:release.checkpointRegistryConfigHash,
    domDomain:release.domDomain,activationScheduleCommitment:release.activationScheduleCommitment,
    governance:release.governance,governanceCodeHash:release.governanceCodeHash,
    governanceImplementation:release.governanceImplementation,
    governanceImplementationCodeHash:release.governanceImplementationCodeHash,
    governanceOwnersCommitment:release.governanceOwnersCommitment,
    guardian:release.guardian,guardianCodeHash:release.guardianCodeHash,
    guardianImplementation:release.guardianImplementation,
    guardianImplementationCodeHash:release.guardianImplementationCodeHash,
    guardianOwnersCommitment:release.guardianOwnersCommitment,
    withdrawalDelaySeconds:release.withdrawalDelaySeconds,
    governanceDelaySeconds:release.governanceDelaySeconds,
    maxOutstandingBaseUnits:release.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerDay:release.outflowCapacityBaseUnitsPerDay,
  };
  const computed=proofReserveDeploymentConfigHash(configuration);
  if(bytes32(release.reserveConfigHash,'reserveConfigHash')!==computed.reserveConfigHash) {
    throw new Error('release reserveConfigHash does not match its exact fields');
  }
  return configuration;
}

function parseSourceIndex(input,sourceInput,configuration) {
  const bytes=Buffer.from(input);
  if(bytes.length===0 || bytes.length>1024*1024) throw new Error('finalized-burn source index size is invalid');
  const index=parseStrictIndex(bytes,'finalized-burn source index');
  exact(index,sourceIndexFields,'finalized-burn source index');
  exact(index.burn,burnFields,'finalized-burn source burn');
  for(const field of [
    'manifest_sha256','burn_id','checkpoint_dom_block','checkpoint_dom_state_root',
    'checkpoint_ethereum_block','checkpoint_witness_sha256','statement_hash','input_sha256',
  ]) rawHash(index[field],field);
  canonicalCount(index.candidate_v2_first_height,'candidate_v2_first_height');
  canonicalCount(index.checkpoint_dom_height,'checkpoint_dom_height');
  canonicalCount(index.checkpoint_ethereum_block_number,'checkpoint_ethereum_block_number');
  canonicalCount(index.checkpoint_beacon_slot,'checkpoint_beacon_slot');
  canonicalCount(index.input_length,'input_length',{max:16*1024*1024});
  const expectedNetwork=uint(configuration.ethereumChainId,256)===1n?'mainnet':'regtest';
  if(index.schema!=='usdom-finalized-burn-source-v3' || index.network!==expectedNetwork
      || index.input_file!=='finalized-burn-input.bin'
      || index.burn_id!==(index.burn.burnId.slice(2).toLowerCase())
      || uint(index.ethereum_chain_id,256)!==uint(configuration.ethereumChainId,256)
      || getAddress(index.reserve)!==getAddress(configuration.reserve)
      || bytes32(index.activation_schedule_commitment,'activation_schedule_commitment')
        !==bytes32(configuration.activationScheduleCommitment,'activationScheduleCommitment')) {
    throw new Error('finalized-burn source identity differs from the exact reserve release');
  }
  const source=Buffer.from(sourceInput);
  if(source.length!==index.input_length || sha256Raw(source)!==index.input_sha256) {
    throw new Error('UDFINL04 input does not match its authenticated source index');
  }
  const burn=normalizeFinalizedBurn(index.burn);
  if(BigInt(index.candidate_v2_first_height)>burn.height
      || BigInt(index.checkpoint_dom_height)!==burn.height
      || '0x'+index.checkpoint_dom_block!==burn.blockHash
      || '0x'+index.checkpoint_dom_state_root!==burn.stateRoot
      || BigInt(index.checkpoint_beacon_slot)!==burn.finalityBeaconSlot) {
    throw new Error('source checkpoint metadata differs from the proved burn checkpoint');
  }
  const statementHash=finalizedBurnStatementHash({
    chainId:configuration.ethereumChainId,reserve:configuration.reserve,
    activationScheduleCommitment:configuration.activationScheduleCommitment,burn,
  });
  if(statementHash.slice(2)!==index.statement_hash) {
    throw new Error('source burn fields do not reproduce the proved statement hash');
  }
  return {bytes,index,burn,statementHash};
}

function parseReceiptIndex(input,source,provingProgramSha256) {
  const bytes=Buffer.from(input);
  if(bytes.length===0 || bytes.length>1024*1024) throw new Error('receipt index size is invalid');
  const index=parseStrictIndex(bytes,'finalized-burn receipt index');
  exact(index,receiptIndexFields,'finalized-burn receipt index');
  for(const field of [
    'proof_job_index_sha256','input_sha256','statement_hash','program_sha256','image_id','receipt_sha256',
  ]) rawHash(index[field],field);
  canonicalCount(index.segment_limit_po2,'segment_limit_po2',{max:24});
  canonicalCount(index.receipt_bytes,'receipt_bytes',{max:256*1024*1024});
  if(index.schema!=='usdom-finalized-burn-receipt-v1'
      || index.proof_job_index_path
        !=='evidence/finalized-burn-proof-job/finalized-burn-proof-job-index.json'
      || index.input_path!=='evidence/finalized-burn-proof-job/finalized-burn-input.bin'
      || index.input_sha256!==source.index.input_sha256
      || index.statement_hash!==source.index.statement_hash
      || index.program_path!=='evidence/finalized-burn-guest/usdom-finalized-burn.elf'
      || index.program_sha256!==provingProgramSha256
      || index.image_id!==finalizedBurnImageId || index.risc0_zkvm_version!=='3.0.6'
      || index.receipt_kind!=='succinct' || index.segment_limit_po2!==18
      || index.receipt_file!=='finalized-burn-receipt.bin'
      || index.relation_executed!==true || index.receipt_verified!==true
      || index.dev_mode!==false || index.generates_proofs!==true || index.mines!==false) {
    throw new Error('finalized-burn receipt index identity or verification claims are invalid');
  }
  return {bytes,index};
}

function parseProofIndex(input,receipt) {
  const bytes=Buffer.from(input);
  if(bytes.length===0 || bytes.length>1024*1024) throw new Error('EVM proof index size is invalid');
  const index=parseStrictIndex(bytes,'finalized-burn EVM proof index');
  exact(index,proofIndexFields,'finalized-burn EVM proof index');
  for(const field of [
    'receipt_index_sha256','image_id','statement_hash','journal_digest',
    'groth16_verifier_parameters','groth16_receipt_sha256','evm_seal_sha256',
  ]) rawHash(index[field],field);
  canonicalCount(index.groth16_receipt_bytes,'groth16_receipt_bytes',{max:256*1024*1024});
  canonicalCount(index.evm_seal_bytes,'evm_seal_bytes',{max:FINALIZED_BURN_EVM_SEAL_BYTES});
  if(index.schema!=='usdom-finalized-burn-evm-proof-v1'
      || index.receipt_index_path
        !=='evidence/finalized-burn-receipt/finalized-burn-receipt-index.json'
      || index.receipt_index_sha256!==sha256Raw(receipt.bytes)
      || index.image_id!==finalizedBurnImageId
      || index.statement_hash!==receipt.index.statement_hash
      || index.journal_digest!==sha256('0x'+index.statement_hash).slice(2)
      || index.risc0_zkvm_version!=='3.0.6' || index.receipt_kind!=='groth16'
      || index.groth16_verifier_parameters!==groth16VerifierParameters
      || index.evm_verifier_selector!==FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR.slice(2)
      || index.groth16_receipt_file!=='finalized-burn-groth16-receipt.bin'
      || index.evm_seal_file!=='finalized-burn-evm-seal.bin'
      || index.evm_seal_bytes!==FINALIZED_BURN_EVM_SEAL_BYTES
      || index.receipt_verified!==true || index.dev_mode!==false
      || index.generates_proofs!==true || index.mines!==false) {
    throw new Error('finalized-burn EVM proof index identity or verification claims are invalid');
  }
  return {bytes,index};
}

/** Validate authenticated proof artifacts and build deterministic unsigned queue calldata. */
export function buildAuthenticatedFinalizedBurnSubmission({
  reserveConfiguration,verifierConfiguration,sourceIndex,sourceInput,receiptIndex,proofIndex,
  evmSeal,releaseConfigSha256='0'.repeat(64),verifierManifestSha256,
}) {
  const configuration=proofReserveDeploymentConfigHash(reserveConfiguration);
  const verifier=finalizedBurnVerifierConfigHash(verifierConfiguration);
  rawHash(releaseConfigSha256,'releaseConfigSha256',{nonzero:false});
  const manifestSha=verifierManifestSha256??verifier.manifestSha256.slice(2);
  rawHash(manifestSha,'verifierManifestSha256');
  if(manifestSha!==verifier.manifestSha256.slice(2)
      || verifier.verifierConfigHash!==configuration.verifierConfigHash
      || verifier.finalizedBurnGuestImageId.toLowerCase()!==FINALIZED_BURN_IMAGE_ID
      || uint(verifier.ethereumChainId,256)!==uint(configuration.ethereumChainId,256)
      || verifier.activationScheduleCommitment.toLowerCase()
        !==configuration.activationScheduleCommitment.toLowerCase()) {
    throw new Error('verifier manifest differs from the exact reserve release');
  }
  const source=parseSourceIndex(sourceIndex,sourceInput,configuration);
  const provingProgramSha256=
    bytes32(verifierConfiguration.provingProgramSha256,'provingProgramSha256').slice(2);
  const receipt=parseReceiptIndex(receiptIndex,source,provingProgramSha256);
  const proof=parseProofIndex(proofIndex,receipt);
  const seal=Buffer.from(evmSeal);
  if(seal.length!==FINALIZED_BURN_EVM_SEAL_BYTES
      || hexlify(seal.subarray(0,4)).toLowerCase()!==FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR
      || proof.index.evm_seal_bytes!==seal.length
      || proof.index.evm_seal_sha256!==sha256Raw(seal)) {
    throw new Error('EVM seal does not match the bounded selector-prefixed proof index');
  }
  const data=reserveInterface.encodeFunctionData('queueWithdrawal',[source.burn,seal]);
  return {
    schema:FINALIZED_BURN_SUBMISSION_SCHEMA,
    ethereumChainId:configuration.ethereumChainId.toString(),
    to:configuration.reserve,value:'0',method:'queueWithdrawal',burn:Object.fromEntries(
      burnFields.map(field=>[field,typeof source.burn[field]==='bigint'
        ? source.burn[field].toString():source.burn[field]]),
    ),
    proof:{selector:FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR,bytes:seal.length,sha256:sha256Raw(seal)},
    statementHash:source.statementHash,journalDigest:sha256(source.statementHash),
    data,dataKeccak256:keccak256(data),
    source:{
      releaseConfigSha256,verifierManifestSha256:manifestSha,
      sourceIndexPath:'evidence/finalized-burn-source/finalized-burn-source-index.json',
      sourceIndexSha256:sha256Raw(source.bytes),
      inputPath:'evidence/finalized-burn-source/finalized-burn-input.bin',
      inputSha256:source.index.input_sha256,
      receiptIndexPath:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',
      receiptIndexSha256:sha256Raw(receipt.bytes),
      proofIndexPath:'evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json',
      proofIndexSha256:sha256Raw(proof.bytes),
      sealPath:'evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin',
      imageId:FINALIZED_BURN_IMAGE_ID,
      groth16VerifierParameters:FINALIZED_BURN_GROTH16_VERIFIER_PARAMETERS,
    },
    broadcastAuthorized:false,
  };
}

/** Validate one serialized unsigned submission package without reading files or making RPC calls. */
export function validateAuthenticatedFinalizedBurnSubmission(submission) {
  exact(submission,packageFields,'authenticated finalized-burn submission');
  exact(submission.burn,burnFields,'finalized-burn submission burn');
  exact(submission.proof,packageProofFields,'finalized-burn submission proof');
  exact(submission.source,packageSourceFields,'finalized-burn submission source');
  const burn=normalizeFinalizedBurn(submission.burn);
  let decoded;
  try { decoded=reserveInterface.decodeFunctionData('queueWithdrawal',submission.data); }
  catch { throw new Error('finalized-burn submission calldata is not decodable'); }
  const decodedBurn=normalizeFinalizedBurn(Object.fromEntries(
    burnFields.map(field=>[field,decoded[0][field]]),
  ));
  const decodedProof=getBytes(decoded[1]);
  canonicalCount(submission.proof.bytes,'submission proof bytes',{
    max:FINALIZED_BURN_EVM_SEAL_BYTES,
  });
  rawHash(submission.proof.sha256,'submission proof sha256');
  bytes32(submission.statementHash,'submission statementHash');
  bytes32(submission.journalDigest,'submission journalDigest');
  const canonicalBurn=Object.fromEntries(burnFields.map(field=>[
    field,typeof burn[field]==='bigint'?burn[field].toString():burn[field],
  ]));
  const canonicalDecoded=Object.fromEntries(burnFields.map(field=>[
    field,typeof decodedBurn[field]==='bigint'?decodedBurn[field].toString():decodedBurn[field],
  ]));
  if(submission.schema!==FINALIZED_BURN_SUBMISSION_SCHEMA || submission.value!=='0'
      || submission.method!=='queueWithdrawal' || submission.broadcastAuthorized!==false
      || submission.to!==getAddress(submission.to)
      || JSON.stringify(canonicalBurn)!==JSON.stringify(canonicalDecoded)
      || submission.proof.selector!==FINALIZED_BURN_RISC0_GROTH16_V3_SELECTOR
      || submission.proof.bytes!==FINALIZED_BURN_EVM_SEAL_BYTES
      || hexlify(decodedProof.slice(0,4))!==submission.proof.selector
      || decodedProof.length!==submission.proof.bytes
      || sha256Raw(decodedProof)!==submission.proof.sha256
      || sha256(submission.statementHash)!==submission.journalDigest
      || reserveInterface.encodeFunctionData('queueWithdrawal',[burn,decodedProof])!==submission.data
      || keccak256(submission.data)!==submission.dataKeccak256) {
    throw new Error('finalized-burn submission package is not canonical');
  }
  return {burn,proof:decodedProof};
}

/** Re-run reserve hashing and the complete queue call against a read-only EVM endpoint. */
export async function verifyAuthenticatedFinalizedBurnSubmissionOnEvm(provider,submission) {
  const parsed=validateAuthenticatedFinalizedBurnSubmission(submission);
  const network=await provider.getNetwork();
  if(network.chainId.toString()!==submission.ethereumChainId) {
    throw new Error('EVM chain ID differs from the finalized-burn submission package');
  }
  const code=await provider.getCode(submission.to);
  if(code==='0x') throw new Error('proof reserve has no EVM code');
  const hashCall=reserveInterface.encodeFunctionData('burnStatementHash',[parsed.burn]);
  const returned=await provider.call({to:submission.to,data:hashCall});
  const [onchainHash]=reserveInterface.decodeFunctionResult('burnStatementHash',returned);
  if(onchainHash.toLowerCase()!==submission.statementHash.toLowerCase()) {
    throw new Error('on-chain finalized-burn statement hash differs from the authenticated package');
  }
  await provider.call({to:submission.to,data:submission.data,value:0n});
  return {
    chainId:network.chainId.toString(),reserve:submission.to,reserveCodeHash:keccak256(code),
    statementHash:onchainHash.toLowerCase(),callAccepted:true,
  };
}

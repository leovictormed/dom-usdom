import {TypedDataEncoder,getAddress} from 'ethers';
import {createHash} from 'node:crypto';
import {
  EIP1271_MAGIC_VALUE,MAX_EIP1271_SIGNATURE_BYTES,collectFinalizedEip1271Approvals,
  validEip1271Signature,
} from './finalized-eip1271-approval.mjs';
import {validateRecoverableSafeControlReleaseEvidence} from './safe-control-release-evidence.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export {EIP1271_MAGIC_VALUE};
export const NATIVE_ATTESTATION_DOMAIN_NAME='USDOM Native Release Attestation';
export const NATIVE_ATTESTATION_DOMAIN_VERSION='2';
export const MAX_NATIVE_ATTESTATION_SIGNATURE_BYTES=MAX_EIP1271_SIGNATURE_BYTES;

const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const canonicalUint256Pattern=/^(0|[1-9][0-9]{0,77})$/;
const nonzeroUint64Pattern=/^[1-9][0-9]{0,19}$/;
function nonzeroUint64(value) {
  return typeof value==='string'&&nonzeroUint64Pattern.test(value)&&BigInt(value)<(1n<<64n);
}
const types={NativeReleaseAttestation:[
  {name:'kind',type:'string'},
  {name:'releaseId',type:'string'},
  {name:'sourceCommit',type:'string'},
  {name:'reserveConfigHash',type:'bytes32'},
  {name:'checkpointRegistryConfigHash',type:'bytes32'},
  {name:'completedAt',type:'uint64'},
  {name:'subjectCommitment',type:'bytes32'},
  {name:'approvedBy',type:'address'},
]};
const supportedKinds=new Set([
  'native-privacy-trusted-setup','native-scheduled-runtime-activation',
  'native-wallet-custody','native-wallet-recovery',
]);
const requestNames=Object.freeze({
  nativePrivacyTrustedSetup:'native-privacy-trusted-setup',
  nativeScheduledRuntimeActivation:'native-scheduled-runtime-activation',
  nativeWalletCustody:'native-wallet-custody',nativeWalletRecovery:'native-wallet-recovery',
});
const sha256Pattern=/^[0-9a-f]{64}$/;

function exactKeys(value,keys,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    throw new Error(`${label} schema is invalid`);
  }
}

export function validateNativeReleaseAttestationSigningRequest({request,bundle,bundleBytes,bundleSha256,
  releaseConfig,releaseEvidence,privacyVerifierConfigHash,nativeRuntimeManifestSha256,
  walletPublicIdentitySha256,walletCustodyEvidenceSha256,walletRecoveryEvidenceSha256}={}) {
  exactKeys(request,['schema','releaseId','sourceCommit','finalizedAnchor','subjects','requests'],
    'native release-attestation request');
  if(request.schema!=='usdom-native-release-attestation-requests/v3') {
    throw new Error('native release-attestation request version is invalid');
  }
  exactKeys(request.finalizedAnchor,
    ['blockNumber','blockHash','blockTimestamp','governance','governanceCodeHash','rpcConsensus'],
    'native release-attestation finalized anchor');
  validateRpcConsensusEvidence(request.finalizedAnchor.rpcConsensus);
  if(!nonzeroUint64(request.finalizedAnchor.blockNumber)
      || !bytes32Pattern.test(request.finalizedAnchor.blockHash??'')
      || !nonzeroUint64(request.finalizedAnchor.blockTimestamp)
      || !bytes32Pattern.test(request.finalizedAnchor.governanceCodeHash??'')) {
    throw new Error('native release-attestation finalized anchor is invalid');
  }
  if(!Buffer.isBuffer(bundleBytes)
      ||JSON.stringify(parseStrictJsonBytes(bundleBytes,{label:'Safe evidence bundle',
        maxBytes:4*1024*1024,maxDepth:64}))!==JSON.stringify(bundle)
      ||createHash('sha256').update(bundleBytes).digest('hex')!==bundleSha256) {
    throw new Error('Safe evidence bundle bytes differ from parsed authority');
  }
  validateRecoverableSafeControlReleaseEvidence(bundle);
  const bundleDocument=releaseEvidence?.controlPlaneEvidenceBundle;
  exactKeys(bundleDocument,['path','sha256'],'Safe evidence bundle document');
  if(bundleDocument.path!=='evidence/control-plane/safe-control-release-evidence-bundle.json'
      || !sha256Pattern.test(bundleSha256??'')||bundleDocument.sha256!==bundleSha256
      || bundle.ethereumChainId!==releaseConfig?.ethereumChainId) {
    throw new Error('Safe evidence bundle differs from the native attestation release');
  }
  const governance=bundle.roleReports.governance;
  if(getAddress(governance.address)!==getAddress(releaseConfig?.governance)
      || governance.ownersAfter.some((owner,index)=>
        getAddress(owner)!==getAddress(releaseConfig?.governanceOwners?.[index]))) {
    throw new Error('native attestation governance or owners differ from Safe evidence');
  }
  if(getAddress(request.finalizedAnchor.governance)!==getAddress(releaseConfig.governance)
      || request.finalizedAnchor.governanceCodeHash.toLowerCase()
        !==String(releaseConfig.governanceCodeHash).toLowerCase()) {
    throw new Error('native attestation finalized governance differs from the release');
  }
  if(request.releaseId!==releaseEvidence?.releaseId
      || request.sourceCommit!==releaseEvidence?.sourceCommit) {
    throw new Error('native attestation request provenance differs from release evidence');
  }
  for(const [value,label] of [[privacyVerifierConfigHash,'privacy verifier configuration'],
    [nativeRuntimeManifestSha256,'native runtime manifest'],
    [walletPublicIdentitySha256,'wallet public identity'],
    [walletCustodyEvidenceSha256,'wallet custody evidence'],
    [walletRecoveryEvidenceSha256,'wallet recovery evidence']]) {
    if(!sha256Pattern.test(value??'')) throw new Error(`${label} hash is invalid`);
  }
  const expectedSubjects={nativePrivacyTrustedSetup:`0x${privacyVerifierConfigHash}`,
    nativeScheduledRuntimeActivation:`0x${nativeRuntimeManifestSha256}`,
    nativeWalletCustody:`0x${walletCustodyEvidenceSha256}`,
    nativeWalletRecovery:`0x${walletRecoveryEvidenceSha256}`,
    walletPublicIdentitySha256,walletCustodyEvidenceSha256,walletRecoveryEvidenceSha256};
  exactKeys(request.subjects,Object.keys(expectedSubjects),'native attestation subjects');
  if(JSON.stringify(request.subjects)!==JSON.stringify(expectedSubjects)) {
    throw new Error('native attestation subjects differ from independently derived artifacts');
  }
  exactKeys(request.requests,Object.keys(requestNames),'native attestation request set');
  for(const [name,kind] of Object.entries(requestNames)) {
    const item=request.requests[name];
    exactKeys(item,['attestation','digest','typedData'],`${name} request`);
    const built=buildNativeReleaseAttestation({kind,releaseEvidence,releaseConfig,
      completedAt:request.finalizedAnchor.blockTimestamp,
      subjectCommitment:expectedSubjects[name]});
    if(JSON.stringify(item.attestation)!==JSON.stringify(built.attestation)) {
      throw new Error(`${name} attestation differs from independently derived inputs`);
    }
    if(String(item.digest).toLowerCase()!==built.digest.toLowerCase()) {
      throw new Error(`${name} digest differs from its EIP-712 payload`);
    }
    const typed=nativeReleaseAttestationTypedData(built.attestation,releaseConfig);
    if(JSON.stringify(item.typedData)
        !==JSON.stringify(TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message))) {
      throw new Error(`${name} typed data differs from independently derived inputs`);
    }
  }
  return {digests:Object.fromEntries(Object.keys(requestNames).map(name=>
    [name,request.requests[name].digest]))};
}

function canonicalChainId(value) {
  if(typeof value!=='string' || !canonicalUint256Pattern.test(value) || value==='0') {
    throw new Error('ethereumChainId must be a nonzero canonical integer string');
  }
  const parsed=BigInt(value);
  if(parsed>=(1n<<256n)) throw new Error('ethereumChainId must fit uint256');
  return parsed;
}

function bytes32(value,name) {
  if(!bytes32Pattern.test(value??'')) throw new Error(`${name} must be bytes32`);
  return value;
}

export function validNativeAttestationSignature(value) {
  return validEip1271Signature(value);
}

export function nativeReleaseAttestationDigest(attestation,releaseConfig) {
  const typed=nativeReleaseAttestationTypedData(attestation,releaseConfig);
  return TypedDataEncoder.hash(typed.domain,typed.types,typed.message);
}

export function nativeReleaseAttestationTypedData(attestation,releaseConfig) {
  if(!attestation || typeof attestation!=='object' || Array.isArray(attestation)) {
    throw new Error('native release attestation is missing');
  }
  if(!nonzeroUint64(attestation.completedAt)) {
    throw new Error('completedAt must be a nonzero canonical uint64 string');
  }
  const governance=getAddress(releaseConfig?.governance);
  if(getAddress(attestation.approvedBy)!==governance) {
    throw new Error('approvedBy does not match release governance');
  }
  if(!supportedKinds.has(attestation.kind)) throw new Error('native attestation kind is unsupported');
  if(typeof attestation.releaseId!=='string'||attestation.releaseId.length===0) {
    throw new Error('releaseId must be nonempty');
  }
  if(typeof attestation.sourceCommit!=='string'||!/^[0-9a-f]{40}$/.test(attestation.sourceCommit)) {
    throw new Error('sourceCommit must be an exact lowercase Git object name');
  }
  return {domain:{
    name:NATIVE_ATTESTATION_DOMAIN_NAME,version:NATIVE_ATTESTATION_DOMAIN_VERSION,
    chainId:canonicalChainId(releaseConfig?.ethereumChainId),verifyingContract:governance,
  },types:structuredClone(types),message:{
    kind:attestation.kind,releaseId:attestation.releaseId,sourceCommit:attestation.sourceCommit,
    reserveConfigHash:bytes32(attestation.reserveConfigHash,'reserveConfigHash'),
    checkpointRegistryConfigHash:bytes32(
      attestation.checkpointRegistryConfigHash,'checkpointRegistryConfigHash',
    ),
    completedAt:attestation.completedAt,
    subjectCommitment:bytes32(attestation.subjectCommitment,'subjectCommitment'),
    approvedBy:governance,
  }};
}

export function buildNativeReleaseAttestation({kind,releaseEvidence,releaseConfig,completedAt,
  subjectCommitment,signature=null}={}) {
  const attestation={approvedBy:releaseConfig?.governance,
    checkpointRegistryConfigHash:releaseConfig?.checkpointRegistryConfigHash,completedAt,kind,
    releaseId:releaseEvidence?.releaseId,reserveConfigHash:releaseConfig?.reserveConfigHash,
    schema:1,signature,sourceCommit:releaseEvidence?.sourceCommit,subjectCommitment};
  const digest=nativeReleaseAttestationDigest(attestation,releaseConfig);
  if(signature!==null&&!validNativeAttestationSignature(signature)) {
    throw new Error('signature is malformed or oversized');
  }
  return {attestation,digest};
}

export async function collectNativeAttestationApprovals({provider,releaseConfig,attestations}) {
  if(!attestations || typeof attestations!=='object' || Array.isArray(attestations)
      || Object.keys(attestations).length===0) throw new Error('native attestations are required');
  const requests=Object.fromEntries(Object.entries(attestations).map(([name,attestation])=>{
    if(!validNativeAttestationSignature(attestation?.signature)) {
      throw new Error(`${name} signature is malformed or oversized`);
    }
    return [name,{digest:nativeReleaseAttestationDigest(attestation,releaseConfig),
      signature:attestation.signature}];
  }));
  return collectFinalizedEip1271Approvals({provider,chainId:releaseConfig?.ethereumChainId,
    governance:releaseConfig?.governance,
    governanceImplementation:releaseConfig?.governanceImplementation,
    governanceImplementationCodeHash:releaseConfig?.governanceImplementationCodeHash,requests});
}

import {AbiCoder,TypedDataEncoder,getAddress,keccak256,toUtf8Bytes} from 'ethers';
import {
  collectFinalizedEip1271Approvals,validEip1271Signature,
} from './finalized-eip1271-approval.mjs';
import {validateRecoverableSafeControlReleaseEvidence} from './safe-control-release-evidence.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';
import {isCanonicalReleaseEvidenceDocumentPath as canonicalEvidencePath}
  from './release-evidence-document-paths.mjs';

export const RELEASE_AUTHORIZATION_DOMAIN_NAME='USDOM Production Release Authorization';
export const RELEASE_AUTHORIZATION_DOMAIN_VERSION='4';

const bytes32Pattern=/^0x[0-9a-fA-F]{64}$/;
const commitPattern=/^[0-9a-f]{40}$/;
const sha256Pattern=/^[0-9a-f]{64}$/;
const canonicalUintPattern=/^[1-9][0-9]*$/;
const types={ReleaseAuthorization:[
  {name:'releaseId',type:'string'},
  {name:'sourceCommit',type:'string'},
  {name:'sourceTag',type:'string'},
  {name:'releaseEvidenceCommitment',type:'bytes32'},
  {name:'reserveConfigHash',type:'bytes32'},
  {name:'checkpointRegistryConfigHash',type:'bytes32'},
  {name:'governanceOwnersHash',type:'bytes32'},
  {name:'guardianOwnersHash',type:'bytes32'},
  {name:'checkpointGuardianOwnersHash',type:'bytes32'},
  {name:'residualRiskReportSha256',type:'bytes32'},
  {name:'acceptedAt',type:'uint64'},
  {name:'approvedBy',type:'address'},
  {name:'productionApproved',type:'bool'},
  {name:'deployAuthorized',type:'bool'},
  {name:'realFundsAuthorized',type:'bool'},
]};

function fail(message) { throw new Error(message); }
function canonicalChainId(value) {
  if(typeof value!=='string'||!canonicalUintPattern.test(value)) {
    fail('ethereumChainId must be a nonzero canonical integer string');
  }
  return BigInt(value);
}
function bytes32(value,name) {
  if(typeof value!=='string'||!bytes32Pattern.test(value)) fail(`${name} must be bytes32`);
  return value;
}

const abi=AbiCoder.defaultAbiCoder();

export function releaseRoleOwnersHash(releaseConfig,role) {
  const field=`${role}Owners`;
  if(!Array.isArray(releaseConfig?.[field])||releaseConfig[field].length!==3) {
    fail(`${field} must contain exactly three addresses`);
  }
  const owners=releaseConfig[field].map(getAddress);
  if(new Set(owners).size!==3 || owners.some(owner=>BigInt(owner)===0n)) {
    fail(`${field} must contain three distinct nonzero addresses`);
  }
  owners.sort((left,right)=>BigInt(left)<BigInt(right)?-1:BigInt(left)>BigInt(right)?1:0);
  return keccak256(abi.encode(['address[]'],[owners]));
}
export const releaseControlPlaneOwnersHash=releaseConfig=>keccak256(abi.encode(['bytes32','bytes32','bytes32'],[
  releaseRoleOwnersHash(releaseConfig,'governance'),releaseRoleOwnersHash(releaseConfig,'guardian'),
  releaseRoleOwnersHash(releaseConfig,'checkpointGuardian'),
]));

function canonicalJson(value,{stack=new WeakSet(),depth=0,budget={nodes:0}}={}) {
  if(depth>64||++budget.nodes>100_000) fail('release evidence exceeds canonicalization bounds');
  if(value===null||typeof value==='boolean'||typeof value==='string') return JSON.stringify(value);
  if(typeof value==='number') {
    if(!Number.isSafeInteger(value)||Object.is(value,-0)) fail('release evidence contains a noncanonical number');
    return JSON.stringify(value);
  }
  if(typeof value!=='object') fail('release evidence contains a non-JSON value');
  if(stack.has(value)) fail('release evidence contains a cycle');
  const prototype=Object.getPrototypeOf(value);
  if(prototype!==Object.prototype&&prototype!==Array.prototype) fail('release evidence contains a non-plain object');
  stack.add(value);
  let encoded;
  if(Array.isArray(value)) {
    encoded=`[${value.map(item=>canonicalJson(item,{stack,depth:depth+1,budget})).join(',')}]`;
  } else {
    const keys=Object.keys(value).sort();
    if(keys.includes('path')||keys.includes('sha256')) {
      if(JSON.stringify(keys)!==JSON.stringify(['path','sha256'])
          ||!canonicalEvidencePath(value.path)||!sha256Pattern.test(value.sha256??'')) {
        fail('release evidence contains an invalid hash-addressed document');
      }
    }
    encoded=`{${keys.map(key=>`${JSON.stringify(key)}:${canonicalJson(value[key],{
      stack,depth:depth+1,budget})}`).join(',')}}`;
  }
  stack.delete(value);
  return encoded;
}

/** Commits the complete release-evidence manifest, including tag and every artifact path/hash. */
export function releaseEvidenceCommitment(releaseEvidence) {
  if(!releaseEvidence||typeof releaseEvidence!=='object'||Array.isArray(releaseEvidence)) {
    fail('release evidence is invalid');
  }
  for(const forbidden of ['authorization','releaseAuthorization','releaseEvidenceCommitment','signature']) {
    if(Object.hasOwn(releaseEvidence,forbidden)) fail(`release evidence cannot contain ${forbidden}`);
  }
  if(!/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/.test(releaseEvidence.sourceTag??'')) {
    fail('release sourceTag is invalid');
  }
  const encoded=canonicalJson(releaseEvidence);
  if(Buffer.byteLength(encoded,'utf8')>4*1024*1024) fail('release evidence canonical form is oversized');
  return keccak256(toUtf8Bytes(encoded));
}

export function validateReleaseAuthorizationSigningRequest({
  request,bundle,bundleSha256,releaseConfig,releaseEvidence,
}={}) {
  const keys=value=>value&&typeof value==='object'&&!Array.isArray(value)
    ?JSON.stringify(Object.keys(value).sort()):'';
  if(keys(request)!==JSON.stringify([
    'authorization','digest','finalizedAnchor','releaseId','schema','sourceCommit','typedData',
  ])) fail('release authorization request schema is invalid');
  if(request.schema!=='usdom-release-authorization-request/v2') fail('request version is invalid');
  if(keys(request.finalizedAnchor)!==JSON.stringify([
    'blockHash','blockNumber','blockTimestamp','governance','governanceCodeHash','rpcConsensus',
  ])) fail('release authorization finalized anchor schema is invalid');
  validateRpcConsensusEvidence(request.finalizedAnchor.rpcConsensus);
  if(typeof request.finalizedAnchor.blockNumber!=='string'
      || !canonicalUintPattern.test(request.finalizedAnchor.blockNumber)
      || !bytes32Pattern.test(request.finalizedAnchor.blockHash??'')
      || typeof request.finalizedAnchor.blockTimestamp!=='string'
      || !canonicalUintPattern.test(request.finalizedAnchor.blockTimestamp)
      || !bytes32Pattern.test(request.finalizedAnchor.governanceCodeHash??'')) {
    fail('release authorization finalized anchor is invalid');
  }
  validateRecoverableSafeControlReleaseEvidence(bundle);
  const bundleDocument=releaseEvidence?.controlPlaneEvidenceBundle;
  if(keys(bundleDocument)!==JSON.stringify(['path','sha256'])
      || bundleDocument.path
        !=='evidence/control-plane/safe-control-release-evidence-bundle.json'
      || typeof bundleSha256!=='string'||!sha256Pattern.test(bundleSha256)
      || bundleDocument.sha256!==bundleSha256) {
    fail('Safe evidence bundle bytes differ from the release evidence');
  }
  if(bundle.ethereumChainId!==releaseConfig?.ethereumChainId) {
    fail('Safe evidence bundle chain differs from the release');
  }
  const role=bundle.roleReports.governance;
  if(getAddress(role.address)!==getAddress(releaseConfig?.governance)
      || role.ownersAfter.some((owner,index)=>
        getAddress(owner)!==getAddress(releaseConfig?.governanceOwners?.[index]))) {
    fail('release governance or owners differ from the Safe evidence bundle');
  }
  if(getAddress(request.finalizedAnchor.governance)!==getAddress(releaseConfig.governance)
      || String(request.finalizedAnchor.governanceCodeHash).toLowerCase()
        !==String(releaseConfig.governanceCodeHash).toLowerCase()
      || request.finalizedAnchor.blockTimestamp!==request.authorization?.acceptedAt) {
    fail('request finalized governance anchor differs from the release');
  }
  const evidenceCommitment=releaseEvidenceCommitment(releaseEvidence);
  if(request.releaseId!==releaseEvidence?.releaseId
      || request.sourceCommit!==releaseEvidence?.sourceCommit
      || request.authorization?.releaseId!==releaseEvidence?.releaseId
      || request.authorization?.sourceCommit!==releaseEvidence?.sourceCommit
      || request.authorization?.sourceTag!==releaseEvidence?.sourceTag
      || String(request.authorization?.releaseEvidenceCommitment).toLowerCase()
        !==evidenceCommitment.toLowerCase()) {
    fail('request provenance differs from the release evidence');
  }
  if(request.authorization?.reportSha256!==releaseEvidence?.residualRiskAcceptanceReport?.sha256) {
    fail('request residual-risk report differs from the release evidence');
  }
  const typed=releaseAuthorizationTypedData(request.authorization,releaseConfig);
  const expectedPayload=TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message);
  if(JSON.stringify(request.typedData)!==JSON.stringify(expectedPayload)) {
    fail('request typed data differs from its authenticated inputs');
  }
  const digest=releaseAuthorizationDigest(request.authorization,releaseConfig);
  if(String(request.digest).toLowerCase()!==digest.toLowerCase()) {
    fail('request digest differs from its EIP-712 payload');
  }
  return {digest,ownersHash:releaseControlPlaneOwnersHash(releaseConfig)};
}

export function releaseAuthorizationDigest(authorization,releaseConfig) {
  const typed=releaseAuthorizationTypedData(authorization,releaseConfig);
  return TypedDataEncoder.hash(typed.domain,typed.types,typed.message);
}

export function releaseAuthorizationTypedData(authorization,releaseConfig) {
  if(!authorization||typeof authorization!=='object'||Array.isArray(authorization)) {
    fail('release authorization is missing');
  }
  if(typeof authorization.releaseId!=='string'||authorization.releaseId.length===0) {
    fail('releaseId must be nonempty');
  }
  if(!commitPattern.test(authorization.sourceCommit??'')) fail('sourceCommit is invalid');
  if(!/^usdom-v[0-9]+\.[0-9]+\.[0-9]+$/.test(authorization.sourceTag??'')) fail('sourceTag is invalid');
  bytes32(authorization.releaseEvidenceCommitment,'releaseEvidenceCommitment');
  if(!sha256Pattern.test(authorization.reportSha256??'')) fail('reportSha256 is invalid');
  if(typeof authorization.acceptedAt!=='string'||!canonicalUintPattern.test(authorization.acceptedAt)
      || BigInt(authorization.acceptedAt)>0xffffffffffffffffn) {
    fail('acceptedAt must be a nonzero canonical uint64 string');
  }
  const governance=getAddress(releaseConfig?.governance);
  if(getAddress(authorization.acceptingAuthority)!==governance) {
    fail('acceptingAuthority does not match release governance');
  }
  for(const field of ['reserveConfigHash','checkpointRegistryConfigHash']) {
    const authorized=bytes32(authorization[field],field).toLowerCase();
    const released=bytes32(releaseConfig?.[field],`release ${field}`).toLowerCase();
    if(authorized!==released) fail(`${field} differs from the release`);
  }
  for(const field of ['productionApproved','deployAuthorized','realFundsAuthorized']) {
    if(authorization[field]!==true) fail(`${field} must be true`);
  }
  return {domain:{
    name:RELEASE_AUTHORIZATION_DOMAIN_NAME,version:RELEASE_AUTHORIZATION_DOMAIN_VERSION,
    chainId:canonicalChainId(releaseConfig?.ethereumChainId),verifyingContract:governance,
  },types:structuredClone(types),message:{
    releaseId:authorization.releaseId,sourceCommit:authorization.sourceCommit,
    sourceTag:authorization.sourceTag,releaseEvidenceCommitment:authorization.releaseEvidenceCommitment,
    reserveConfigHash:authorization.reserveConfigHash,
    checkpointRegistryConfigHash:authorization.checkpointRegistryConfigHash,
    governanceOwnersHash:releaseRoleOwnersHash(releaseConfig,'governance'),
    guardianOwnersHash:releaseRoleOwnersHash(releaseConfig,'guardian'),
    checkpointGuardianOwnersHash:releaseRoleOwnersHash(releaseConfig,'checkpointGuardian'),
    residualRiskReportSha256:`0x${authorization.reportSha256}`,
    acceptedAt:authorization.acceptedAt,approvedBy:governance,
    productionApproved:true,deployAuthorized:true,realFundsAuthorized:true,
  }};
}

export function buildReleaseAuthorization({releaseEvidence,releaseConfig,operatorIntent,
  acceptedAt,signature=null}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1) fail('release evidence is invalid');
  if(!operatorIntent||operatorIntent.schema!==1) fail('operator intent is invalid');
  if(!releaseEvidence.residualRiskAcceptanceReport
      || !sha256Pattern.test(releaseEvidence.residualRiskAcceptanceReport.sha256??'')) {
    fail('hash-addressed residual-risk report is required');
  }
  if(!Array.isArray(operatorIntent.undefined)||operatorIntent.undefined.length!==0) {
    fail('production parameters remain undefined');
  }
  const authorization={
    accepted:true,releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,releaseEvidenceCommitment:releaseEvidenceCommitment(releaseEvidence),
    reserveConfigHash:releaseConfig?.reserveConfigHash,
    checkpointRegistryConfigHash:releaseConfig?.checkpointRegistryConfigHash,
    reportSha256:releaseEvidence.residualRiskAcceptanceReport.sha256,
    acceptingAuthority:releaseConfig?.governance,acceptedAt,
    productionApproved:true,deployAuthorized:true,realFundsAuthorized:true,
    signature,
    rule:'Governance EIP-1271 approval binds production, deployment, real funds and documented residual risk to this exact release; it cannot waive a failed technical gate.',
  };
  const digest=releaseAuthorizationDigest(authorization,releaseConfig);
  if(signature!==null&&!validEip1271Signature(signature)) fail('signature is malformed or oversized');
  return {authorization,digest};
}

export async function collectReleaseAuthorizationApproval({provider,releaseConfig,authorization}) {
  if(!validEip1271Signature(authorization?.signature)) {
    fail('release authorization signature is malformed or oversized');
  }
  return collectFinalizedEip1271Approvals({provider,chainId:releaseConfig?.ethereumChainId,
    governance:releaseConfig?.governance,requests:{releaseAuthorization:{
      digest:releaseAuthorizationDigest(authorization,releaseConfig),
      signature:authorization.signature,
    }}});
}

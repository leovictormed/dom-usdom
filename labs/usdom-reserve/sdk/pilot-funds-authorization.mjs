import {createHash} from 'node:crypto';
import {TypedDataEncoder,getAddress,keccak256,solidityPacked,toUtf8Bytes} from 'ethers';
import {releaseControlPlaneOwnersHash} from './release-authorization.mjs';
import {validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';
import {reserveDepositId} from './proof-reserve.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

export const PILOT_FUNDS_DOMAIN_NAME='USDOM Closed Mainnet Pilot Funds';
export const PILOT_FUNDS_DOMAIN_VERSION='1';
export const MAX_PILOT_AUTHORIZATION_AGE_SECONDS=24n*60n*60n;
const hash=/^0x[0-9a-fA-F]{64}$/;
const sha=/^[0-9a-f]{64}$/;
const uint64=/^(0|[1-9][0-9]{0,19})$/;
const signature=/^0x(?:[0-9a-f]{2}){1,32768}$/;
const snapshotKeys=['schema','releaseConfigSha256','deploymentPackageSha256','safeControlBundleSha256',
  'nativePrivacyInstallationSha256','checkpointCapacityEvidenceSha256','finalizedBurnCapacityEvidenceSha256',
  'operationalGasEvidenceSha256','residualRiskDraftSha256','reserveConfigHash',
  'checkpointRegistryConfigHash','controlPlaneOwnersHash','governance','reserve','token',
  'maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay','pilotDepositBaseUnits','funder','salt','depositId',
  'receivingCommitment','planSha256','phaseCatalogSha256','releaseValidationReportSha256'];
const authorizationKeys=['schema','snapshotCommitment','releaseId','validAfter','validUntil','governance',
  'pilotDepositBaseUnits','funder','salt','receivingCommitment','nonce','signature'];
const stateKeys=['schema','authorization','digest','finalizedObservation','consumed'];
const requestKeys=['schema','authorization','digest','finalizedAnchor','typedData'];
const anchorKeys=['blockNumber','blockHash','blockTimestamp','governance','governanceCodeHash','rpcConsensus'];
const observationKeys=['approvals','chainId','finalizedBlockHash','finalizedBlockNumber',
  'finalizedBlockTimestamp','governance','governanceCodeHash','rpcConsensus','snapshotBlockHashAfter'];
const approvalKeys=['digest','valid'];
const types={PilotFundsAuthorization:[
  {name:'snapshotCommitment',type:'bytes32'},{name:'releaseId',type:'bytes32'},
  {name:'validAfter',type:'uint64'},{name:'validUntil',type:'uint64'},
  {name:'governance',type:'address'},{name:'pilotDepositBaseUnits',type:'uint64'},
  {name:'funder',type:'address'},{name:'salt',type:'bytes32'},{name:'receivingCommitment',type:'bytes32'},
  {name:'nonce',type:'bytes32'},
]};
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
function fail(message){throw new Error(message);}
function u64(value,label,{nonzero=true}={}) {
  if(typeof value!=='string'||!uint64.test(value)||BigInt(value)>=(1n<<64n)
      ||(nonzero&&BigInt(value)===0n)) fail(`${label} must be canonical uint64`);
  return value;
}
function bytes32(value,label){if(!hash.test(value??'')||BigInt(value)===0n)fail(`${label} must be nonzero bytes32`);return value.toLowerCase();}
function sha256(value,label){
  if(!sha.test(value??'')||BigInt(`0x${value}`)===0n)fail(`${label} must be nonzero SHA-256`);
  return value;
}
function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
  return value;
}

export function buildPilotFundsSnapshot({releaseConfig,releaseConfigSha256,deploymentPackageSha256,
  safeControlBundleSha256,nativePrivacyInstallationSha256,checkpointCapacityEvidenceSha256,
  finalizedBurnCapacityEvidenceSha256,operationalGasEvidenceSha256,residualRiskDraftSha256,
  pilotDepositBaseUnits,funder,salt,receivingCommitment,planSha256,phaseCatalogSha256,releaseValidationReportSha256}={}) {
  if(releaseConfig?.ethereumChainId!=='1'||releaseConfig.productionReady!==true
      ||releaseConfig.realFundsAuthorized!==false) fail('pilot snapshot requires technical pre-funds release');
  const amount=u64(pilotDepositBaseUnits,'pilotDepositBaseUnits');
  if(BigInt(amount)>BigInt(u64(releaseConfig.maxOutstandingBaseUnits,'maxOutstandingBaseUnits'))
      ||BigInt(amount)>BigInt(u64(releaseConfig.outflowCapacityBaseUnitsPerDay,'outflowCapacityBaseUnitsPerDay'))) {
    fail('pilot deposit exceeds exact production financial limits');
  }
  const normalizedFunder=getAddress(funder),normalizedSalt=bytes32(salt,'salt');
  if(BigInt(normalizedFunder)===0n) fail('funder must be nonzero');
  const depositId=reserveDepositId({chainId:1n,reserve:releaseConfig.reserve,
    funder:normalizedFunder,salt:normalizedSalt});
  return Object.freeze({schema:'usdom-pilot-funds-snapshot/v1',
    releaseConfigSha256:sha256(releaseConfigSha256,'releaseConfigSha256'),
    deploymentPackageSha256:sha256(deploymentPackageSha256,'deploymentPackageSha256'),
    safeControlBundleSha256:sha256(safeControlBundleSha256,'safeControlBundleSha256'),
    nativePrivacyInstallationSha256:sha256(nativePrivacyInstallationSha256,'nativePrivacyInstallationSha256'),
    checkpointCapacityEvidenceSha256:sha256(checkpointCapacityEvidenceSha256,'checkpointCapacityEvidenceSha256'),
    finalizedBurnCapacityEvidenceSha256:sha256(finalizedBurnCapacityEvidenceSha256,'finalizedBurnCapacityEvidenceSha256'),
    operationalGasEvidenceSha256:sha256(operationalGasEvidenceSha256,'operationalGasEvidenceSha256'),
    residualRiskDraftSha256:sha256(residualRiskDraftSha256,'residualRiskDraftSha256'),
    reserveConfigHash:bytes32(releaseConfig.reserveConfigHash,'reserveConfigHash'),
    checkpointRegistryConfigHash:bytes32(releaseConfig.checkpointRegistryConfigHash,'checkpointRegistryConfigHash'),
    controlPlaneOwnersHash:releaseControlPlaneOwnersHash(releaseConfig).toLowerCase(),
    governance:getAddress(releaseConfig.governance),reserve:getAddress(releaseConfig.reserve),
    token:getAddress(releaseConfig.token),maxOutstandingBaseUnits:releaseConfig.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerDay:releaseConfig.outflowCapacityBaseUnitsPerDay,
    pilotDepositBaseUnits:amount,funder:normalizedFunder,salt:normalizedSalt,depositId,
    receivingCommitment:bytes32(receivingCommitment,'receivingCommitment'),
    planSha256:sha256(planSha256,'planSha256'),phaseCatalogSha256:sha256(phaseCatalogSha256,'phaseCatalogSha256'),
    releaseValidationReportSha256:sha256(releaseValidationReportSha256,'releaseValidationReportSha256')});
}

export function pilotFundsSnapshotCommitment(snapshot){
  if(!exact(snapshot,snapshotKeys)||snapshot.schema!=='usdom-pilot-funds-snapshot/v1')fail('pilot snapshot schema is invalid');
  return keccak256(toUtf8Bytes(JSON.stringify(canonical(snapshot))));
}

export const pilotFundsReleaseId=snapshotCommitment=>keccak256(solidityPacked(
  ['string','bytes32'],['USDOM_PILOT_RELEASE',bytes32(snapshotCommitment,'snapshotCommitment')],
));
export const pilotFundsAuthorizationNonce=(snapshotCommitment,finalizedBlockHash)=>keccak256(solidityPacked(
  ['bytes32','bytes32'],[bytes32(snapshotCommitment,'snapshotCommitment'),
    bytes32(finalizedBlockHash,'finalizedBlockHash')],
));

export function validatePilotFundsPlanBinding(snapshot,generationIdentity) {
  pilotFundsSnapshotCommitment(snapshot);
  if(!generationIdentity||generationIdentity.schema!=='usdom-closed-mainnet-phase-generation/v1'
      ||snapshot.planSha256!==generationIdentity.planSha256
      ||snapshot.phaseCatalogSha256!==generationIdentity.phaseCatalogSha256) {
    fail('pilot authorization belongs to a different execution-plan generation');
  }
  return {planSha256:snapshot.planSha256,phaseCatalogSha256:snapshot.phaseCatalogSha256};
}

export function validatePilotFundsReleaseBinding(snapshot,currentReleaseConfigSha256) {
  pilotFundsSnapshotCommitment(snapshot);
  if(sha256(currentReleaseConfigSha256,'currentReleaseConfigSha256')!==snapshot.releaseConfigSha256) {
    fail('pilot authorization belongs to a different release configuration');
  }
  return currentReleaseConfigSha256;
}

/** Binds the signing ceremony's current Safe/release objects to the exact snapshot documents. */
export function validatePilotFundsSigningDocumentBindings({snapshot,bundle,bundleBytes,
  releaseConfig,releaseConfigBytes}={}) {
  pilotFundsSnapshotCommitment(snapshot);
  const bind=(value,bytes,label,expectedSha256)=>{
    if(!Buffer.isBuffer(bytes)) fail(`${label} bytes are required`);
    const parsed=parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64});
    if(JSON.stringify(parsed)!==JSON.stringify(value)) fail(`${label} object differs from fixed bytes`);
    const actual=createHash('sha256').update(bytes).digest('hex');
    if(actual!==sha256(expectedSha256,`${label} SHA-256`)) {
      fail(`${label} bytes differ from the pilot snapshot`);
    }
  };
  bind(bundle,bundleBytes,'Safe control bundle',snapshot.safeControlBundleSha256);
  bind(releaseConfig,releaseConfigBytes,'release configuration',snapshot.releaseConfigSha256);
  if(getAddress(bundle?.roleReports?.governance?.address)!==getAddress(releaseConfig?.governance)) {
    fail('Safe control bundle governance differs from release configuration');
  }
  return {safeControlBundleSha256:snapshot.safeControlBundleSha256,
    releaseConfigSha256:snapshot.releaseConfigSha256};
}

/** Re-derives every release field copied into the signed pilot snapshot. */
export function validatePilotFundsSnapshotReleaseSemantics(snapshot,releaseConfig) {
  pilotFundsSnapshotCommitment(snapshot);
  if(releaseConfig?.ethereumChainId!=='1'||releaseConfig.productionReady!==true
      ||releaseConfig.realFundsAuthorized!==false) {
    fail('pilot snapshot requires the current technical pre-funds release');
  }
  for(const field of ['governance','reserve','token']) {
    if(getAddress(snapshot[field])!==getAddress(releaseConfig[field])) {
      fail(`pilot snapshot ${field} differs from the current release`);
    }
  }
  for(const field of ['reserveConfigHash','checkpointRegistryConfigHash']) {
    if(bytes32(snapshot[field],`snapshot ${field}`)!==bytes32(releaseConfig[field],`release ${field}`)) {
      fail(`pilot snapshot ${field} differs from the current release`);
    }
  }
  if(snapshot.controlPlaneOwnersHash.toLowerCase()
      !==releaseControlPlaneOwnersHash(releaseConfig).toLowerCase()) {
    fail('pilot snapshot control plane differs from the current release');
  }
  for(const field of ['maxOutstandingBaseUnits','outflowCapacityBaseUnitsPerDay']) {
    if(u64(snapshot[field],`snapshot ${field}`)!==u64(releaseConfig[field],`release ${field}`)) {
      fail(`pilot snapshot ${field} differs from the current release`);
    }
  }
  for(const field of ['releaseConfigSha256','deploymentPackageSha256','safeControlBundleSha256',
    'nativePrivacyInstallationSha256','checkpointCapacityEvidenceSha256',
    'finalizedBurnCapacityEvidenceSha256','operationalGasEvidenceSha256',
    'residualRiskDraftSha256','planSha256','phaseCatalogSha256','releaseValidationReportSha256']) {
    sha256(snapshot[field],`snapshot ${field}`);
  }
  const amount=BigInt(u64(snapshot.pilotDepositBaseUnits,'snapshot pilotDepositBaseUnits'));
  if(amount>BigInt(snapshot.maxOutstandingBaseUnits)
      ||amount>BigInt(snapshot.outflowCapacityBaseUnitsPerDay)) {
    fail('pilot snapshot amount exceeds the current release limits');
  }
  if(BigInt(getAddress(snapshot.funder))===0n) fail('pilot snapshot funder must be nonzero');
  bytes32(snapshot.receivingCommitment,'snapshot receivingCommitment');
  const expectedDepositId=reserveDepositId({chainId:1n,reserve:releaseConfig.reserve,
    funder:getAddress(snapshot.funder),salt:bytes32(snapshot.salt,'snapshot salt')});
  if(snapshot.depositId.toLowerCase()!==expectedDepositId.toLowerCase()) {
    fail('pilot snapshot depositId differs from its current release tuple');
  }
  return snapshot;
}

export function pilotFundsAuthorizationTypedData(authorization,releaseConfig){
  if(!exact(authorization,authorizationKeys)||authorization.schema!=='usdom-pilot-funds-authorization/v1')fail('pilot authorization schema is invalid');
  const governance=getAddress(releaseConfig?.governance);
  if(getAddress(authorization.governance)!==governance)fail('pilot authorization governance differs');
  bytes32(authorization.snapshotCommitment,'snapshotCommitment'); bytes32(authorization.releaseId,'releaseId');
  if(authorization.releaseId.toLowerCase()!==pilotFundsReleaseId(authorization.snapshotCommitment)) {
    fail('pilot authorization releaseId is not canonical');
  }
  bytes32(authorization.nonce,'nonce'); u64(authorization.validAfter,'validAfter',{nonzero:false});
  if(BigInt(getAddress(authorization.funder))===0n) fail('funder must be nonzero');
  bytes32(authorization.salt,'salt');
  bytes32(authorization.receivingCommitment,'receivingCommitment');
  u64(authorization.validUntil,'validUntil'); u64(authorization.pilotDepositBaseUnits,'pilotDepositBaseUnits');
  if(BigInt(authorization.validUntil)<=BigInt(authorization.validAfter)
      ||BigInt(authorization.validUntil)-BigInt(authorization.validAfter)>MAX_PILOT_AUTHORIZATION_AGE_SECONDS)fail('pilot authorization validity window is invalid');
  return {domain:{name:PILOT_FUNDS_DOMAIN_NAME,version:PILOT_FUNDS_DOMAIN_VERSION,chainId:1n,verifyingContract:governance},types,message:{
    snapshotCommitment:authorization.snapshotCommitment,releaseId:authorization.releaseId,
    validAfter:authorization.validAfter,validUntil:authorization.validUntil,governance,
    pilotDepositBaseUnits:authorization.pilotDepositBaseUnits,funder:authorization.funder,
    salt:authorization.salt,receivingCommitment:authorization.receivingCommitment,nonce:authorization.nonce}};
}
export const pilotFundsAuthorizationDigest=(authorization,releaseConfig)=>{const t=pilotFundsAuthorizationTypedData(authorization,releaseConfig);return TypedDataEncoder.hash(t.domain,t.types,t.message);};

export function validatePilotFundsAuthorizationFreshness({authorization,observation}={}) {
  const finalized=BigInt(u64(observation?.finalizedBlockTimestamp,'finalizedBlockTimestamp'));
  const validAfter=BigInt(u64(authorization?.validAfter,'validAfter',{nonzero:false}));
  const validUntil=BigInt(u64(authorization?.validUntil,'validUntil'));
  if(finalized<validAfter||finalized>validUntil) {
    fail('pilot authorization is not fresh at finalized state');
  }
  return {validAfter:validAfter.toString(),validUntil:validUntil.toString(),
    finalizedBlockTimestamp:finalized.toString()};
}

export function validatePilotFundsAuthorizationRequest({request,snapshot,releaseConfig}={}) {
  if(!exact(request,requestKeys)||request.schema!=='usdom-pilot-funds-authorization-request/v1'
      ||!exact(request.finalizedAnchor,anchorKeys)||request.authorization?.signature!==null) {
    fail('pilot authorization request schema is invalid');
  }
  const commitment=pilotFundsSnapshotCommitment(snapshot),anchor=request.finalizedAnchor;
  validatePilotFundsSnapshotReleaseSemantics(snapshot,releaseConfig);
  if(releaseConfig?.ethereumChainId!=='1') fail('pilot authorization requires Ethereum mainnet');
  validateRpcConsensusEvidence(anchor.rpcConsensus);
  if(request.authorization.snapshotCommitment.toLowerCase()!==commitment
      ||request.authorization.nonce.toLowerCase()!==pilotFundsAuthorizationNonce(commitment,anchor.blockHash)
      ||request.authorization.validAfter!==u64(anchor.blockTimestamp,'finalized block timestamp')
      ||BigInt(request.authorization.validUntil)!==BigInt(request.authorization.validAfter)+3600n
      ||getAddress(anchor.governance)!==getAddress(releaseConfig.governance)
      ||String(anchor.governanceCodeHash).toLowerCase()!==String(releaseConfig.governanceCodeHash).toLowerCase()
      ||getAddress(request.authorization.funder)!==snapshot.funder
      ||request.authorization.pilotDepositBaseUnits!==snapshot.pilotDepositBaseUnits
      ||request.authorization.salt.toLowerCase()!==snapshot.salt
      ||request.authorization.receivingCommitment.toLowerCase()!==snapshot.receivingCommitment) {
    fail('pilot authorization request differs from its exact snapshot or finalized anchor');
  }
  u64(anchor.blockNumber,'finalized block number');
  bytes32(anchor.blockHash,'finalized block hash');
  bytes32(anchor.governanceCodeHash,'governance code hash');
  const typed=pilotFundsAuthorizationTypedData(request.authorization,releaseConfig);
  const digest=TypedDataEncoder.hash(typed.domain,typed.types,typed.message);
  if(request.digest.toLowerCase()!==digest.toLowerCase()
      ||JSON.stringify(canonical(request.typedData))!==JSON.stringify(canonical(
        TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message)))) {
    fail('pilot authorization request digest or typed data differs');
  }
  return request;
}

export function validatePilotFundsAuthorizationState({state,snapshot,releaseConfig,depositAmountBaseUnits}={}) {
  if(!exact(state,stateKeys)||state.schema!=='usdom-pilot-funds-authorization-state/v1'||state.consumed!==false)fail('pilot authorization state is invalid or consumed');
  if(!signature.test(state.authorization?.signature??'')) fail('pilot authorization signature is invalid');
  validatePilotFundsSnapshotReleaseSemantics(snapshot,releaseConfig);
  if(pilotFundsSnapshotCommitment(snapshot)!==state.authorization.snapshotCommitment.toLowerCase())fail('pilot authorization snapshot differs');
  if(state.authorization.pilotDepositBaseUnits!==snapshot.pilotDepositBaseUnits
      ||state.authorization.pilotDepositBaseUnits!==depositAmountBaseUnits)fail('pilot authorization amount differs');
  if(getAddress(state.authorization.funder)!==snapshot.funder||state.authorization.salt.toLowerCase()!==snapshot.salt
      ||state.authorization.receivingCommitment.toLowerCase()!==snapshot.receivingCommitment)fail('pilot authorization tuple differs');
  const digest=pilotFundsAuthorizationDigest(state.authorization,releaseConfig);
  if(digest.toLowerCase()!==String(state.digest).toLowerCase())fail('pilot authorization digest differs');
  const o=state.finalizedObservation;
  if(!exact(o,observationKeys)||!exact(o.approvals?.pilotFundsAuthorization,approvalKeys)) {
    fail('finalized pilot EIP-1271 observation schema is invalid');
  }
  if(o.chainId!=='1'||releaseConfig?.ethereumChainId!=='1'
      ||getAddress(o.governance)!==getAddress(releaseConfig.governance)
      ||String(o.governanceCodeHash).toLowerCase()!==String(releaseConfig.governanceCodeHash).toLowerCase()
      ||bytes32(o.finalizedBlockHash,'finalizedBlockHash')
        !==bytes32(o.snapshotBlockHashAfter,'snapshotBlockHashAfter')
      ||o.approvals?.pilotFundsAuthorization?.valid!==true
      ||String(o.approvals.pilotFundsAuthorization.digest).toLowerCase()!==digest.toLowerCase())fail('finalized pilot EIP-1271 approval is invalid or revoked');
  u64(o.finalizedBlockNumber,'finalizedBlockNumber');
  validateRpcConsensusEvidence(o.rpcConsensus);
  validatePilotFundsAuthorizationFreshness({authorization:state.authorization,observation:o});
  return {digest,amount:depositAmountBaseUnits};
}

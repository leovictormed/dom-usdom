import assert from 'node:assert/strict'; import test from 'node:test';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs'; import path from 'node:path'; import {fileURLToPath} from 'node:url';
import {TypedDataEncoder} from 'ethers';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
import {buildPilotFundsSnapshot,pilotFundsSnapshotCommitment,pilotFundsAuthorizationDigest,
  pilotFundsAuthorizationNonce,pilotFundsAuthorizationTypedData,pilotFundsReleaseId,
  validatePilotFundsAuthorizationRequest,validatePilotFundsAuthorizationState,
  validatePilotFundsSigningDocumentBindings} from '../../sdk/pilot-funds-authorization.mjs';
const address=n=>'0x'+n.toString(16).padStart(40,'0'), hash=n=>'0x'+n.toString(16).padStart(64,'0'), sha=n=>n.toString(16).padStart(64,'0');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const release=()=>({ethereumChainId:'1',productionReady:true,realFundsAuthorized:false,
 governance:address(1),governanceCodeHash:hash(2),reserve:address(3),token:address(4),
 reserveConfigHash:hash(5),checkpointRegistryConfigHash:hash(6),maxOutstandingBaseUnits:'100000000000',
 outflowCapacityBaseUnitsPerDay:'2000000000',governanceOwners:[address(10),address(11),address(12)],
 guardianOwners:[address(13),address(14),address(15)],checkpointGuardianOwners:[address(16),address(17),address(18)]});
const make=()=>{const r=release(),snapshot=buildPilotFundsSnapshot({releaseConfig:r,releaseConfigSha256:sha(1),deploymentPackageSha256:sha(2),safeControlBundleSha256:sha(3),nativePrivacyInstallationSha256:sha(4),checkpointCapacityEvidenceSha256:sha(5),finalizedBurnCapacityEvidenceSha256:sha(6),operationalGasEvidenceSha256:sha(7),residualRiskDraftSha256:sha(8),pilotDepositBaseUnits:'1000000',funder:address(60),salt:hash(61),receivingCommitment:hash(62),planSha256:sha(9),phaseCatalogSha256:sha(10),releaseValidationReportSha256:sha(11)}); const snapshotCommitment=pilotFundsSnapshotCommitment(snapshot); const authorization={schema:'usdom-pilot-funds-authorization/v1',snapshotCommitment,releaseId:pilotFundsReleaseId(snapshotCommitment),validAfter:'1000',validUntil:'2000',governance:r.governance,pilotDepositBaseUnits:'1000000',funder:snapshot.funder,salt:snapshot.salt,receivingCommitment:snapshot.receivingCommitment,nonce:hash(21),signature:'0x1234'}; const digest=pilotFundsAuthorizationDigest(authorization,r); const rpcConsensus=rpcConsensusEvidence([{sourceId:'a',originKeccak256:hash(30)},{sourceId:'b',originKeccak256:hash(31)}]); const state={schema:'usdom-pilot-funds-authorization-state/v1',authorization,digest,consumed:false,finalizedObservation:{chainId:'1',governance:r.governance,governanceCodeHash:r.governanceCodeHash,finalizedBlockHash:hash(40),finalizedBlockNumber:'99',snapshotBlockHashAfter:hash(40),finalizedBlockTimestamp:'1500',rpcConsensus,approvals:{pilotFundsAuthorization:{digest,valid:true}}}}; return {r,snapshot,state};};
test('pilot authorization binds the exact technical snapshot and amount',()=>{const {r,snapshot,state}=make();assert.equal(validatePilotFundsAuthorizationState({state,snapshot,releaseConfig:r,depositAmountBaseUnits:'1000000'}).amount,'1000000'); for(const mutate of [s=>s.consumed=true,s=>s.authorization.nonce=hash(99),s=>s.authorization.releaseId=hash(99),s=>s.authorization.receivingCommitment=hash(99),s=>s.finalizedObservation.approvals.pilotFundsAuthorization.valid=false,s=>s.finalizedObservation.finalizedBlockTimestamp='2001']){const copy=structuredClone(state);mutate(copy);assert.throws(()=>validatePilotFundsAuthorizationState({state:copy,snapshot,releaseConfig:r,depositAmountBaseUnits:'1000000'}));}});
test('pilot authorization cannot be replayed across a coordinated release snapshot substitution',()=>{
 const {r,snapshot,state}=make();
 for(const mutate of [
  value=>{value.reserveConfigHash=hash(90);},
  value=>{value.checkpointRegistryConfigHash=hash(91);},
  value=>{value.controlPlaneOwnersHash=hash(92);},
  value=>{value.token=address(93);},
  value=>{value.maxOutstandingBaseUnits='99999999999';},
  value=>{value.releaseConfigSha256=sha(0);},
  value=>{value.pilotDepositBaseUnits='2000000001';},
 ]) {
  const changed=structuredClone(snapshot); mutate(changed);
  const snapshotCommitment=pilotFundsSnapshotCommitment(changed);
  const authorization={...state.authorization,snapshotCommitment,
   releaseId:pilotFundsReleaseId(snapshotCommitment),
   pilotDepositBaseUnits:changed.pilotDepositBaseUnits,funder:changed.funder,
   salt:changed.salt,receivingCommitment:changed.receivingCommitment};
  const digest=pilotFundsAuthorizationDigest(authorization,r);
  const coordinated={...state,authorization,digest,finalizedObservation:{...state.finalizedObservation,
   approvals:{pilotFundsAuthorization:{digest,valid:true}}}};
  assert.throws(()=>validatePilotFundsAuthorizationState({state:coordinated,snapshot:changed,
   releaseConfig:r,depositAmountBaseUnits:changed.pilotDepositBaseUnits}));
 }
});
test('pilot state rejects missing, empty, noncanonical and malformed EIP-1271 signature bytes',()=>{const {r,snapshot,state}=make();for(const value of [null,'0x','0x1','0xABCD','not-hex']){const copy=structuredClone(state);copy.authorization.signature=value;assert.throws(()=>validatePilotFundsAuthorizationState({state:copy,snapshot,releaseConfig:r,depositAmountBaseUnits:'1000000'}),/signature/);}});
test('pilot state requires one exact nonzero finalized EIP-1271 observation',()=>{const {r,snapshot,state}=make();for(const mutate of [
 s=>{s.finalizedObservation.extra=true;},s=>{s.finalizedObservation.finalizedBlockNumber='0';},
 s=>{s.finalizedObservation.finalizedBlockNumber='01';},s=>{s.finalizedObservation.finalizedBlockHash=hash(0);},
 s=>{s.finalizedObservation.approvals.pilotFundsAuthorization.extra=true;},
 s=>{delete s.finalizedObservation.approvals.pilotFundsAuthorization.digest;},
]){const copy=structuredClone(state);mutate(copy);assert.throws(()=>validatePilotFundsAuthorizationState({state:copy,snapshot,releaseConfig:r,depositAmountBaseUnits:'1000000'}));}});
test('signing request fixes release id, nonce, anchor and typed payload canonically',()=>{const {r,snapshot,state}=make();const authorization={...state.authorization,signature:null,validAfter:'1000',validUntil:'4600'};const rpcConsensus=state.finalizedObservation.rpcConsensus;const finalizedAnchor={blockNumber:'99',blockHash:hash(70),blockTimestamp:'1000',governance:r.governance,governanceCodeHash:r.governanceCodeHash,rpcConsensus};authorization.nonce=pilotFundsAuthorizationNonce(authorization.snapshotCommitment,finalizedAnchor.blockHash);const typed=pilotFundsAuthorizationTypedData(authorization,r);const request={schema:'usdom-pilot-funds-authorization-request/v1',authorization,digest:pilotFundsAuthorizationDigest(authorization,r),finalizedAnchor,typedData:TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message)};assert.equal(validatePilotFundsAuthorizationRequest({request,snapshot,releaseConfig:r}),request);for(const mutate of [v=>{v.authorization.releaseId=hash(90);},v=>{v.authorization.nonce=hash(91);},v=>{v.authorization.validUntil='4601';},v=>{v.finalizedAnchor.blockHash=hash(92);},v=>{v.finalizedAnchor.blockNumber='0';},v=>{v.typedData.message.nonce=hash(93);}]){const copy=structuredClone(request);mutate(copy);assert.throws(()=>validatePilotFundsAuthorizationRequest({request:copy,snapshot,releaseConfig:r}));}});
test('pilot signing binds current Safe custody and release to snapshot document hashes',()=>{
 const r=release(),bundle={roleReports:{governance:{address:r.governance}}};
 const fixed=value=>Buffer.from(`${JSON.stringify(value,null,2)}\n`);
 const digest=value=>createHash('sha256').update(value).digest('hex');
 const bundleBytes=fixed(bundle),releaseConfigBytes=fixed(r);
 const snapshot=buildPilotFundsSnapshot({releaseConfig:r,releaseConfigSha256:digest(releaseConfigBytes),
  deploymentPackageSha256:sha(2),safeControlBundleSha256:digest(bundleBytes),
  nativePrivacyInstallationSha256:sha(4),checkpointCapacityEvidenceSha256:sha(5),
  finalizedBurnCapacityEvidenceSha256:sha(6),operationalGasEvidenceSha256:sha(7),
  residualRiskDraftSha256:sha(8),pilotDepositBaseUnits:'1000000',funder:address(60),salt:hash(61),
  receivingCommitment:hash(62),planSha256:sha(9),phaseCatalogSha256:sha(10),
  releaseValidationReportSha256:sha(11)});
 const args={snapshot,bundle,bundleBytes,releaseConfig:r,releaseConfigBytes};
 assert.deepEqual(validatePilotFundsSigningDocumentBindings(args),{
  safeControlBundleSha256:digest(bundleBytes),releaseConfigSha256:digest(releaseConfigBytes)});
 assert.throws(()=>validatePilotFundsSigningDocumentBindings({...args,
  bundle:{roleReports:{governance:{address:address(99)}}}}),/object differs from fixed bytes/);
 const changedBundleBytes=fixed({...bundle,unexpected:true});
 assert.throws(()=>validatePilotFundsSigningDocumentBindings({...args,bundleBytes:changedBundleBytes,
  bundle:{...bundle,unexpected:true}}),/bytes differ from the pilot snapshot/);
 const changedReleaseBytes=fixed({...r,sourceTag:'substituted'});
 assert.throws(()=>validatePilotFundsSigningDocumentBindings({...args,
  releaseConfigBytes:changedReleaseBytes,releaseConfig:{...r,sourceTag:'substituted'}}),
 /bytes differ from the pilot snapshot/);
});
test('snapshot rejects excess pilot exposure, zero identities and post-authorization config',()=>{const args={releaseConfig:release(),releaseConfigSha256:sha(1),deploymentPackageSha256:sha(2),safeControlBundleSha256:sha(3),nativePrivacyInstallationSha256:sha(4),checkpointCapacityEvidenceSha256:sha(5),finalizedBurnCapacityEvidenceSha256:sha(6),operationalGasEvidenceSha256:sha(7),residualRiskDraftSha256:sha(8),pilotDepositBaseUnits:'2000000001',funder:address(60),salt:hash(61),receivingCommitment:hash(62),planSha256:sha(9),phaseCatalogSha256:sha(10),releaseValidationReportSha256:sha(11)};assert.throws(()=>buildPilotFundsSnapshot(args),/financial limits/);args.pilotDepositBaseUnits='1000000';args.deploymentPackageSha256=sha(0);assert.throws(()=>buildPilotFundsSnapshot(args),/nonzero SHA-256/);args.deploymentPackageSha256=sha(2);args.funder=address(0);assert.throws(()=>buildPilotFundsSnapshot(args),/funder must be nonzero/);args.funder=address(60);args.releaseConfig.realFundsAuthorized=true;assert.throws(()=>buildPilotFundsSnapshot(args),/pre-funds/);});
test('executor revalidates authorization after human approval at the last signing and publication boundaries',()=>{
 const source=readFileSync(path.join(root,'scripts/execute-closed-mainnet-deposit.sh'),'utf8');
 const signingApproval=source.indexOf('test "$answer" = "AUTORIZO ASSINAR DEPOSITO ETAPA $index AUTH $authorization_hash"');
 const signingRecheck=source.indexOf('check-pilot-funds-authorization-live.mjs',signingApproval);
 const signing=source.indexOf('sign-onekey-mainnet-transaction.mjs',signingApproval);
 assert.ok(signingApproval>=0&&signingRecheck>signingApproval&&signingRecheck<signing);
 const signingWindow=source.slice(signingApproval,signing);
 assert.match(signingWindow,/recheck_live_authorities/);
 assert.match(signingWindow,/read_nonce "\$funder" pending/);
 assert.match(source.slice(signingApproval,signing+200),/"\$onekey_identity" "\$prepared" "\$raw_candidate"/);
 const broadcastApproval=source.indexOf('test "$answer" = "AUTORIZO TRANSMITIR DEPOSITO ETAPA $index TX $expected_hash"');
 const broadcastRecheck=source.indexOf('check-pilot-funds-authorization-live.mjs',broadcastApproval);
 const broadcast=source.indexOf('publish-private-raw-transaction.mjs',broadcastApproval);
 assert.ok(broadcastApproval>=0&&broadcastRecheck>broadcastApproval&&broadcastRecheck<broadcast);
});
test('signing request checker captures all four files as one descriptor-held set',()=>{const source=readFileSync(path.join(root,'scripts/check-pilot-funds-authorization-signing-request.mjs'),'utf8');assert.match(source,/O_NOFOLLOW/);assert.match(source,/const captures=process\.argv\.slice\(2\)\.map/);assert.match(source,/for\(const \[index,\{p,fd,before\}\] of captures\.entries\(\)\)/);assert.match(source,/after\.dev!==named\.dev\|\|after\.ino!==named\.ino/);});

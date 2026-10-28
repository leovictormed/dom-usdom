import assert from 'node:assert/strict'; import test from 'node:test'; import {readFileSync} from 'node:fs'; import path from 'node:path'; import {fileURLToPath} from 'node:url';
import {AbiCoder,Wallet,keccak256} from 'ethers';
import {buildPilotFundsSnapshot,pilotFundsAuthorizationDigest,pilotFundsReleaseId,
 pilotFundsSnapshotCommitment} from '../../sdk/pilot-funds-authorization.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
import {buildPilotDepositGatePlan,validatePilotDepositGatePlan} from '../../sdk/pilot-deposit-gate.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..'),address=n=>'0x'+n.toString(16).padStart(40,'0'),hash=n=>'0x'+n.toString(16).padStart(64,'0'),sha=n=>n.toString(16).padStart(64,'0');
const owners=[new Wallet(hash(201)),new Wallet(hash(202)),new Wallet(hash(203))],release={ethereumChainId:'1',productionReady:true,realFundsAuthorized:false,governance:address(1),governanceCodeHash:hash(30),reserve:address(2),token:address(3),reserveConfigHash:hash(4),checkpointRegistryConfigHash:hash(5),maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'1000000',governanceOwners:owners.map(v=>v.address),guardianOwners:[address(11),address(12),address(13)],checkpointGuardianOwners:[address(14),address(15),address(16)]};
const snapshot=buildPilotFundsSnapshot({releaseConfig:release,releaseConfigSha256:sha(1),deploymentPackageSha256:sha(2),safeControlBundleSha256:sha(3),nativePrivacyInstallationSha256:sha(4),checkpointCapacityEvidenceSha256:sha(5),finalizedBurnCapacityEvidenceSha256:sha(6),operationalGasEvidenceSha256:sha(7),residualRiskDraftSha256:sha(8),pilotDepositBaseUnits:'1000000',funder:address(20),salt:hash(21),receivingCommitment:hash(22),planSha256:sha(9),phaseCatalogSha256:sha(10),releaseValidationReportSha256:sha(11)});
const snapshotCommitment=pilotFundsSnapshotCommitment(snapshot);
const authorization={schema:'usdom-pilot-funds-authorization/v1',snapshotCommitment,
 releaseId:pilotFundsReleaseId(snapshotCommitment),validAfter:'1000',validUntil:'2000',
 governance:release.governance,pilotDepositBaseUnits:snapshot.pilotDepositBaseUnits,
 funder:snapshot.funder,salt:snapshot.salt,receivingCommitment:snapshot.receivingCommitment,
 nonce:hash(31),signature:'0x1234'};
const digest=pilotFundsAuthorizationDigest(authorization,release);
const rpcConsensus=rpcConsensusEvidence([{sourceId:'a',originKeccak256:hash(32)},
 {sourceId:'b',originKeccak256:hash(33)}]);
const state={schema:'usdom-pilot-funds-authorization-state/v1',authorization,digest,consumed:false,
 finalizedObservation:{chainId:'1',governance:release.governance,
 governanceCodeHash:release.governanceCodeHash,finalizedBlockHash:hash(34),finalizedBlockNumber:'99',
 snapshotBlockHashAfter:hash(34),finalizedBlockTimestamp:'1500',rpcConsensus,
 approvals:{pilotFundsAuthorization:{digest,valid:true}}}};
const safe={threshold:'2',ownersByRole:{governance:owners.map(v=>v.address)},controls:[{role:'governance',safe:release.governance}]},generation='7';
const expected=keccak256(AbiCoder.defaultAbiCoder().encode(['uint256','address','address','uint64','bytes32','bytes32','uint64','uint64'],[1n,release.reserve,snapshot.funder,snapshot.pilotDepositBaseUnits,snapshot.salt,snapshot.receivingCommitment,state.authorization.validUntil,generation]));
const plan=buildPilotDepositGatePlan({snapshot,authorizationState:state,releaseConfig:release,safePackage:safe,safeNonce:'9',pilotAuthorizationGeneration:generation,finalizedBlockNumber:'100',finalizedBlockHash:hash(23),observedAuthorization:expected});

test('deterministic mutation fuzz rejects every plan field and nested Safe transaction drift',()=>{
 const paths=[['schema'],['chainId'],['snapshotCommitment'],['validUntil'],['generation'],['governanceSafe'],['reserve'],['authorizedOwners'],['safeTransaction','to'],['safeTransaction','value'],['safeTransaction','data'],['safeTransaction','nonce'],['safeTxHash'],['expectedAuthorization'],['finalizedBlockNumber'],['finalizedBlockHash'],['planHash']];
 for(let round=0;round<128;round++){const copy=structuredClone(plan),parts=paths[round%paths.length]; let target=copy; for(const key of parts.slice(0,-1)) target=target[key]; const key=parts.at(-1); target[key]=Array.isArray(target[key])?[...target[key]].reverse():typeof target[key]==='string'?target[key]+'0':null; assert.throws(()=>validatePilotDepositGatePlan(copy,{snapshot,authorizationState:state,releaseConfig:release,safePackage:safe}),`mutation ${round} ${parts.join('.')}`);}
});

test('truncation, trailing data and duplicate JSON keys fail closed',()=>{
 const encoded=Buffer.from(JSON.stringify(plan));
 for(let offset=0;offset<encoded.length;offset+=Math.max(1,Math.floor(encoded.length/97))) assert.throws(()=>parseStrictJsonBytes(encoded.subarray(0,offset),{label:'mutated gate plan'}));
 assert.throws(()=>parseStrictJsonBytes(Buffer.concat([encoded,Buffer.from('{}')]),{label:'trailing gate plan'}));
 assert.throws(()=>parseStrictJsonBytes(Buffer.from('{"schema":"a","schema":"b"}'),{label:'duplicate gate plan'}));
});

test('durable attempt transition is completion-first, restartable and descriptor strict',()=>{
 const rotate=readFileSync(path.join(root,'scripts/rotate-expired-pilot-funds-authorization.mjs'),'utf8'),clear=readFileSync(path.join(root,'scripts/execute-expired-pilot-gate-clear.sh'),'utf8'),gate=readFileSync(path.join(root,'scripts/execute-pilot-deposit-gate.sh'),'utf8');
 for(const marker of ['.pilot-funds-rotation.json','writePrivateFileDurableNewOrEqual(markerPath','copyOrVerify','unlinkEqual','before the first source is removed','before.dev!==after.dev','before.nlink!==1']) assert.ok(rotate.includes(marker),marker);
 assert.ok(rotate.indexOf("path.join(directory,'generation.json')")<rotate.indexOf('unlinkEqual(path.join(root,relative[i])'));
 for(const source of [clear,gate]) for(const marker of ["stat -c '%u:%a:%h'",'cast receipt "$txhash"','cast tx "$txhash"','cast block finalized']) assert.ok(source.includes(marker),marker);
 for(const marker of ['keys==["blockHash"','pilotAuthorizationGeneration()(uint64)','pilotAuthorizationGeneration()(uint64)','assert_plan_prestate "$tmp/pre-send-a.json"']) assert.ok(gate.includes(marker),marker);
 for(const marker of ['clearExpiredPilotDepositAuthorization(bytes32,uint64)','pilot-deposit-gate-clear-finalized.json','stored_finalized','transactionIndex','usdom-pilot-deposit-gate-clear-finalized/v2','exit 0']) assert.ok(clear.includes(marker),marker);
});

test('expired clear snapshots every persistent authority before operational reads',()=>{
 const clear=readFileSync(path.join(root,'scripts/execute-expired-pilot-gate-clear.sh'),'utf8');
 assert.match(clear,/snapshot_authority\(\).*check-direct-strict-json-file\.mjs --stdout "\$source"/);
 for(const name of ['gate-plan.json','gate-completion.json','release.json','rpc-sources.json','rpc-catalog.json']) {
  assert.ok(clear.includes(`$tmp/${name}`),name);
 }
 assert.match(clear,/materialize-private-foundry-rpc-aliases\.mjs "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "\$rpc_catalog"/);
 assert.match(clear,/publish-private-raw-transaction\.mjs "\$raw" "\$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE" "\$rpc_catalog"/);
});

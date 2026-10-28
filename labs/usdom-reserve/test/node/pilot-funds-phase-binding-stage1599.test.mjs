import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {buildPilotFundsSnapshot,validatePilotFundsPlanBinding,validatePilotFundsReleaseBinding}
  from '../../sdk/pilot-funds-authorization.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const address=n=>'0x'+n.toString(16).padStart(40,'0');
const hash=n=>'0x'+n.toString(16).padStart(64,'0');
const sha=n=>n.toString(16).padStart(64,'0');
const release={ethereumChainId:'1',productionReady:true,realFundsAuthorized:false,
  governance:address(1),reserve:address(2),token:address(3),reserveConfigHash:hash(4),
  checkpointRegistryConfigHash:hash(5),maxOutstandingBaseUnits:'1000000',
  outflowCapacityBaseUnitsPerDay:'1000000',governanceOwners:[address(10),address(11),address(12)],
  guardianOwners:[address(13),address(14),address(15)],checkpointGuardianOwners:[address(16),address(17),address(18)]};
const snapshot=buildPilotFundsSnapshot({releaseConfig:release,releaseConfigSha256:sha(1),
  deploymentPackageSha256:sha(2),safeControlBundleSha256:sha(3),nativePrivacyInstallationSha256:sha(4),
  checkpointCapacityEvidenceSha256:sha(5),finalizedBurnCapacityEvidenceSha256:sha(6),
  operationalGasEvidenceSha256:sha(7),residualRiskDraftSha256:sha(8),pilotDepositBaseUnits:'1000000',
  funder:address(20),salt:hash(21),receivingCommitment:hash(24),planSha256:sha(22),phaseCatalogSha256:sha(23),
  releaseValidationReportSha256:sha(24)});

test('authorization snapshot is inseparable from its exact phase generation',()=>{
  const identity={schema:'usdom-closed-mainnet-phase-generation/v1',planSha256:sha(22),
    phaseCatalogSha256:sha(23)};
  assert.deepEqual(validatePilotFundsPlanBinding(snapshot,identity),
    {planSha256:sha(22),phaseCatalogSha256:sha(23)});
  assert.throws(()=>validatePilotFundsPlanBinding(snapshot,{...identity,planSha256:sha(99)}),
    /different execution-plan generation/);
  assert.throws(()=>validatePilotFundsPlanBinding(snapshot,{...identity,phaseCatalogSha256:sha(99)}),
    /different execution-plan generation/);
  assert.equal(validatePilotFundsReleaseBinding(snapshot,sha(1)),sha(1));
  assert.throws(()=>validatePilotFundsReleaseBinding(snapshot,sha(99)),
    /different release configuration/);
});

test('authorization phase is immediately before deposit and has every exact predecessor',()=>{
  const result=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024});
  assert.equal(result.status,0,result.stderr);
  const plan=JSON.parse(result.stdout),authorization=plan.phaseOrder.indexOf('authorize-pilot-funds-secret');
  assert.equal(plan.phaseOrder[authorization+1],'execute-pilot-deposit-secret');
  assert.deepEqual(plan.phaseArtifacts[authorization].prerequisitePhases,
    plan.phaseOrder.slice(0,authorization));
  assert.ok(plan.phaseArtifacts[authorization].generatedScriptSha256);
});

test('phase has active producer, materializer, validator and current-generation hooks',()=>{
  const result=spawnSync('/usr/bin/bash',['--noprofile','--norc',
    'scripts/generate-closed-mainnet-phase-command.sh','authorize-pilot-funds-secret'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(result.status,0,result.stderr);
  const source=result.stdout;
  const ordered=['check-closed-mainnet-phase-dependency.mjs begin','prepare-pilot-funds-snapshot.mjs',
    'prepare-pilot-funds-authorization-request.mjs','sign:pilot-funds-authorization',
    'materialize:pilot-funds-authorization','prepare-closed-mainnet-deposit.mjs',
    'check-closed-mainnet-phase-dependency.mjs complete'];
  let cursor=-1;
  for(const marker of ordered) { const next=source.indexOf(marker,cursor+1); assert.ok(next>cursor,marker); cursor=next; }
  assert.match(source,/\.phase-generation\.json/);
});

test('all RPC-backed authorization paths recheck exact inputs after observation',()=>{
  for(const name of ['prepare-pilot-funds-authorization-request.mjs',
    'materialize-pilot-funds-authorization.mjs','check-pilot-funds-authorization-live.mjs']) {
    const source=readFileSync(path.join(root,'scripts',name),'utf8');
    const observation=Math.max(source.indexOf('collectReleaseAuthorizationAnchor'),
      source.indexOf('collectPilotFundsAuthorizationApprovalConsensus'));
    const recheck=source.lastIndexOf('changed during finalized observation');
    assert.ok(observation>=0&&recheck>observation,name);
    assert.match(source,/rpcBytes/);
  }
});

test('private pilot tuple never crosses a child-process argument boundary',()=>{
  const generated=spawnSync('/usr/bin/bash',['--noprofile','--norc',
    'scripts/generate-closed-mainnet-phase-command.sh','authorize-pilot-funds-secret'],{
    cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  assert.equal(generated.status,0,generated.stderr);
  const source=generated.stdout;
  assert.match(source,/mktemp -p \/dev\/shm usdom-pilot-private-tuple/);
  assert.match(source,/chmod 0600 "\$private_tuple"/);
  assert.match(source,/prepare-pilot-funds-snapshot\.mjs[\s\S]{0,500}"\$private_tuple"/);
  assert.doesNotMatch(source,/prepare-pilot-funds-snapshot\.mjs[\s\S]{0,500}"\$(?:salt|receiving_commitment|funder)"/);
  const entrypoint=readFileSync(path.join(root,'scripts/prepare-pilot-funds-snapshot.mjs'),'utf8');
  assert.match(entrypoint,/PRIVATE_TUPLE/);
  assert.doesNotMatch(entrypoint,/process\.argv\[(?:7|8|9)\].*(?:salt|receivingCommitment|funder)/);
});

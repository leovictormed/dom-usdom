import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {Wallet,getAddress} from 'ethers';
import {
  SAFE_MAINNET_IDENTITY,buildRecoverableSafeControlDeploymentPackage,
} from '../../sdk/safe-control-deployment.mjs';
import {
  SAFE_CONTROL_SNAPSHOT_SCHEMA,_safeControlObservationInternals,safeControlConfigurationHash,
} from '../../sdk/safe-control-observation.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
import {
  buildProofBundle,buildRecoveryRosterDrill,proofEnvelope,recoveryStepEnvelope,
} from '../../sdk/safe-recovery-roster-drill.mjs';
import {
  buildSafeControlReleaseEvidenceV3,validateSafeControlReleaseArtifactSetV3,
  validateSafeControlReleaseEvidenceV3,
} from '../../sdk/safe-control-release-evidence-v3.mjs';
import {
  materializeSafeControlReleaseConfig,validateSafeControlReleaseFragment,
} from '../../sdk/safe-control-materialization.mjs';

const fixtureDocument=JSON.parse(readFileSync(
  new URL('../fixtures/safe-1.4.1-mainnet.json',import.meta.url),'utf8',
));
const hashByte=value=>`0x${value.toString(16).padStart(2,'0').repeat(32)}`;

async function fixture() {
  const old=[Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom()]
    .sort((a,b)=>a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
  const replacements=[Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom()]
    .sort((a,b)=>a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
  const roles=['governance','reserveGuardian','checkpointGuardian','usdtCustody'];
  const ownersByRole=Object.fromEntries(roles.map(role=>[role,old.map(wallet=>wallet.address)]));
  const packageDocument=buildRecoverableSafeControlDeploymentPackage({
    ownersByRole,proxyCreationCode:fixtureDocument.proxyCreationCode,
  });
  const packageHash=_safeControlObservationInternals.documentHash(packageDocument);
  const roleStates=packageDocument.controls.map(control=>{
    const role={
      role:control.role,address:control.safe,runtimeCodeHash:hashByte(0x41),
      singleton:SAFE_MAINNET_IDENTITY.singleton,
      fallbackHandler:SAFE_MAINNET_IDENTITY.fallbackHandler,
      guard:getAddress('0x0000000000000000000000000000000000000000'),
      owners:[...ownersByRole[control.role]],threshold:'2',nonce:'0',modules:[],
    };
    return {...role,configurationHash:safeControlConfigurationHash({
      ...role,safe:role.address,packageHash,
    })};
  });
  const baselineUnsigned={
    schema:SAFE_CONTROL_SNAPSHOT_SCHEMA,ethereumChainId:'1',packageHash,
    finalizedBlockNumber:'21999000',finalizedBlockHash:hashByte(0x42),
    proxyRuntimeCodeHash:hashByte(0x41),roles:roleStates,
    rpcConsensus:rpcConsensusEvidence([
      {sourceId:'operator-a',originKeccak256:hashByte(0x43)},
      {sourceId:'operator-b',originKeccak256:hashByte(0x44)},
    ]),
  };
  const baselineSnapshot={
    ...baselineUnsigned,snapshotHash:_safeControlObservationInternals.documentHash(baselineUnsigned),
  };
  const plan=buildRecoveryRosterDrill(
    packageDocument,baselineSnapshot,replacements.map(wallet=>wallet.address),[],
  );
  const signatures=[];
  for(let slot=0;slot<3;slot++) {
    const envelope=proofEnvelope(plan,slot);
    signatures.push({
      signer:replacements[slot].address,
      signature:await replacements[slot].signTypedData(
        envelope.typedData.domain,envelope.typedData.types,envelope.typedData.message,
      ),
    });
  }
  const proofs=buildProofBundle(plan,signatures);
  const completions=[];
  for(let ordinal=0;ordinal<12;ordinal++) {
    const roleIndex=Math.floor(ordinal/3),stepIndex=ordinal%3;
    const envelope=recoveryStepEnvelope(plan,roleIndex,stepIndex),role=plan.roles[roleIndex];
    const ownersAfter=role.steps.slice(0,stepIndex+1).reduce(
      (owners,step)=>owners.map(owner=>owner===step.oldOwner?step.newOwner:owner),
      [...plan.initialOwners],
    );
    completions.push({
      ordinal,planHash:plan.planHash,safeTxHash:envelope.safeTxHash,
      status:'finalized-dual-rpc',ownersAfter,transactionHash:hashByte(0x50+ordinal),
      blockNumber:String(22000000+ordinal),blockHash:hashByte(0x70+ordinal),
      finalizedBlockNumber:String(22000100+ordinal),finalizedBlockHash:hashByte(0x90+ordinal),
    });
  }
  return {packageDocument,baselineSnapshot,plan,proofs,completions};
}

test('v3 release evidence derives four Safe roles from 3 proofs and 12 finalized completions',async()=>{
  const input=await fixture();
  const bundle=buildSafeControlReleaseEvidenceV3(input);
  assert.equal(validateSafeControlReleaseEvidenceV3(bundle),bundle);
  assert.equal(bundle.recoveryDrillReport.finalizedStepCount,12);
  assert.deepEqual(Object.keys(bundle.roleReports),[
    'governance','guardian','checkpointGuardian','usdtCustody',
  ]);
  for(const report of Object.values(bundle.roleReports)) {
    assert.equal(report.recoveryTransactions.length,3);
    assert.equal(report.nonceBefore,'0');
    assert.equal(report.nonceAfter,'3');
    assert.deepEqual(report.ownersAfter,input.plan.replacementOwners);
  }
  assert.equal(validateSafeControlReleaseArtifactSetV3({
    bundle,roleReports:bundle.roleReports,separationReport:bundle.separationReport,
    recoveryDrillReport:bundle.recoveryDrillReport,
  }),bundle);
});

test('v3 release evidence rejects plan drift, replay, incomplete finality and cross-document mutation',async()=>{
  const input=await fixture();
  const badPlan=structuredClone(input);
  badPlan.plan.offlineDrillOnly=false;
  assert.throws(()=>buildSafeControlReleaseEvidenceV3(badPlan),/plan drift/u);

  const replay=structuredClone(input);
  replay.completions[1].transactionHash=replay.completions[0].transactionHash;
  assert.throws(()=>buildSafeControlReleaseEvidenceV3(replay),/replay/u);

  const unfinalized=structuredClone(input);
  unfinalized.completions[2].finalizedBlockNumber='1';
  assert.throws(()=>buildSafeControlReleaseEvidenceV3(unfinalized),/not finalized/u);

  const extra=structuredClone(input);
  extra.completions[3].unexpected=true;
  assert.throws(()=>buildSafeControlReleaseEvidenceV3(extra),/schema/u);

  const bundle=buildSafeControlReleaseEvidenceV3(input);
  const mutated=structuredClone(bundle);
  mutated.recoveryDrillReport.roles[0].transactions[0].transactionHash=hashByte(0xfe);
  assert.throws(()=>validateSafeControlReleaseEvidenceV3(mutated),/identity|rejected/u);
});

test('v3 fragment and release config use the common replacement roster and reject v2 schema',async()=>{
  const input=await fixture(),bundle=buildSafeControlReleaseEvidenceV3(input);
  const pointer=name=>({
    path:`evidence/control-plane/${name}.json`,sha256:'ab'.repeat(32),
  });
  const fragment={
    schema:'usdom-safe-control-release-fragment/v3',bundleHash:bundle.bundleHash,
    controlPlaneEvidenceBundle:pointer('safe-control-release-evidence-bundle'),
    controlPlane:Object.fromEntries(
      ['governance','guardian','checkpointGuardian','usdtCustody'].map(role=>[role,{
        address:bundle.roleReports[role].address,
        runtimeCodeHash:bundle.roleReports[role].runtimeCodeHash,
        configurationHash:bundle.roleReports[role].configurationHash,
        configurationReport:pointer({
          governance:'governance-configuration',guardian:'guardian-configuration',
          checkpointGuardian:'checkpoint-guardian-configuration',
          usdtCustody:'usdt-custody-configuration',
        }[role]),
      }]),
    ),
    controlPlaneSeparationReport:pointer('control-plane-separation'),
    controlPlaneRecoveryDrillReport:pointer('control-plane-recovery-drill'),
  };
  assert.equal(validateSafeControlReleaseFragment(fragment,bundle),fragment);
  assert.throws(()=>validateSafeControlReleaseFragment({...fragment,
    schema:'usdom-safe-control-release-fragment/v2'},bundle),/identity/u);
  const releaseConfig={productionReady:false,realFundsAuthorized:false};
  for(const role of ['governance','guardian','checkpointGuardian']) {
    releaseConfig[role]=null; releaseConfig[`${role}CodeHash`]=null;
    releaseConfig[`${role}Implementation`]=null;
    releaseConfig[`${role}ImplementationCodeHash`]=null;
    releaseConfig[`${role}Owners`]=null;
  }
  const result=materializeSafeControlReleaseConfig({
    releaseConfig,artifactSet:{bundle,roleReports:bundle.roleReports,
      separationReport:bundle.separationReport,recoveryDrillReport:bundle.recoveryDrillReport},
  });
  for(const role of ['governance','guardian','checkpointGuardian']) {
    assert.deepEqual(result[`${role}Owners`],input.plan.replacementOwners);
    assert.equal(result[role],bundle.roleReports[role].address);
  }
  assert.equal(result.productionReady,false);
  assert.equal(result.realFundsAuthorized,false);
});

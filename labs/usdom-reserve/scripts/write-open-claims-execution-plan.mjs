import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {assertClassifiedOpenReadinessClaims} from '../sdk/readiness-open-claims.mjs';
import {readinessRequirementKeys} from '../sdk/mainnet-readiness.mjs';
import {checkpointEvidenceClaimCoverage} from '../sdk/checkpoint-evidence-phase-coverage.mjs';
import {finalizedBurnEvidenceClaimCoverage} from '../sdk/finalized-burn-evidence-phase-coverage.mjs';
import {openClaimSemanticContract} from '../sdk/open-claim-route-semantics.mjs';

const requirements=JSON.parse(await readFile(new URL('../config/production-requirements.json',import.meta.url)));
const claims=assertClassifiedOpenReadinessClaims(requirements);
const cleanBash='env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc';
const generator=`${cleanBash} scripts/generate-closed-mainnet-phase-command.sh`;
const materializer=`${cleanBash} scripts/materialize-closed-mainnet-phase-script.sh`;
const phaseDirectory='/home/leonardov/usdom-mainnet-private/operator-phases';
const phaseOrder=['prerequisites','enroll-safe-owners-secret','migrate-safe-owners-hardware-secret',
  'prepare-safe-controls','execute-safe-controls-deployment-secret','prepare-safe-recovery-secret',
  'execute-safe-recovery-secret','materialize-safe-control-config',
  'validate-local','verify-risc0-trusted-setup','derive-deployment-identity-secret','prepare-deployment',
  'execute-mainnet-deployment-secret',
  'execute-reserve-resume-secret','measure-release-capacity','prepare-native-wallet-secret',
  'finalize-native-privacy-ceremony-secret','authorize-pilot-funds-secret','execute-pilot-deposit-secret','submit-pilot-burn-secret','produce-checkpoint-evidence-secret',
  'execute-pilot-redemption-secret','readiness'];
const phaseArtifacts=phaseOrder.map((phase,index)=>{
  const generated=spawnSync('/usr/bin/bash',['--noprofile','--norc',
    'scripts/generate-closed-mainnet-phase-command.sh',phase],{
    cwd:new URL('..',import.meta.url),encoding:null,env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
  });
  if(generated.status!==0||generated.stderr.length!==0||generated.stdout.length===0) {
    throw new Error(`cannot materialize deterministic phase: ${phase}`);
  }
  return Object.freeze({phase,ordinal:index+1,prerequisitePhases:Object.freeze(phaseOrder.slice(0,index)),
    generatedScriptSha256:createHash('sha256').update(generated.stdout).digest('hex'),
    generatedScriptBytes:generated.stdout.length});
});
const artifactByPhase=new Map(phaseArtifacts.map(value=>[value.phase,value]));
const checkpointCoverage=new Map(checkpointEvidenceClaimCoverage.map(row=>[row.claim,row]));
const burnCoverage=new Map(finalizedBurnEvidenceClaimCoverage.map(row=>[row.claim,row]));

function executable(command) {
  if (/^[a-z0-9][a-z0-9._-]*\.mjs(?:\s|$)/.test(command)) return `node scripts/${command}`;
  if (/^[a-z0-9][a-z0-9:_-]*$/.test(command) && command.includes(':')) {
    return `npm run --silent ${command}`;
  }
  return command;
}

function route(key,category) {
  const ceremonyFinalize='node scripts/assemble-native-privacy-ceremony.mjs finalize "$draft" "$finalization_signatures" "$circuit" "$final_pk" "$vk" "$transcript"';
  const ceremonyCheck='npm run --silent check:native-privacy-ceremony -- "$transcript" "$circuit" "$final_pk" "$vk" "$artifacts" "$verifier"';
  const vkInstall='npm run --silent install:native-privacy-verifying-key -- "$transcript" "$circuit" "$final_pk" "$vk" "$runtime_manifest" "$installation" "$artifacts" "$verifier"';
  const installedReceiptCheck=`${ceremonyCheck} | jq -S 'del(.schema)' | cmp -s - <(jq -S 'del(.schema,.nativeRuntimeManifestSha256,.ceremonyTranscriptSha256)' "$installation/installation.json")`;
  if(key==='native_privacy_trusted_setup_ceremony_completed') return ['finalize-native-privacy-ceremony-secret','externally contributed multiparty transcript, cryptographically assembled and independently reverified',[ceremonyFinalize],[ceremonyCheck],'external-operation'];
  if(key==='native_privacy_production_verifying_key_installed') return ['finalize-native-privacy-ceremony-secret','create-once release-bound VK installation with completion-last receipt and byte comparison',[vkInstall],[installedReceiptCheck,'cmp -s "$transcript" "$installation/ceremony-transcript.json"','cmp -s "$vk" "$installation/spend-verifying-key.bin"','cmp -s "$runtime_manifest" "$installation/native-usdom-v2.json"'],'external-operation'];
  if(key==='production_control_plane_recovery_drill_passed') return ['execute-safe-recovery-secret','twelve-step common-roster Safe recovery and finalized dual-RPC observation',['bash scripts/execute-safe-recovery-roster-v3-step.sh'],['node scripts/check-safe-recovery-roster-v3-completion.mjs'],'external-operation'];
  if(key==='production_mainnet_predeployment_preflight_passed') return ['execute-mainnet-deployment-secret','two finalized adapters and signed intermediate predeployment attestation',['materialize:mainnet-predeployment-attestation'],['check:mainnet-predeploy'],'external-operation'];
  if(key.startsWith('production_onekey_ios_safe_custody_')) return ['execute-pilot-deposit-secret','finalized Safe USDT custody, exact EIP-712 approve/deposit and dual-RPC accounting evidence',['node scripts/run-operational-status78-cycle.mjs deposit'],['node scripts/check-closed-mainnet-phase-artifacts.mjs require-deposit-complete'],'external-operation'];
  if(key.startsWith('production_onekey_ios_relayer_')) return ['authorize-pilot-funds-secret','ratified gas-only relayer separation, exact SafeTx, economic caps, nonce recovery and emergency rotation',[
    'node scripts/run-operational-status78-cycle.mjs pilot-gate',
    'node scripts/run-operational-status78-cycle.mjs pilot-gate-cancel',
    'node scripts/run-operational-status78-cycle.mjs pilot-gate-clear',
  ],['node scripts/check-pilot-funds-authorization-live.mjs'],'external-operation'];
  if(key.startsWith('production_onekey_')) return ['migrate-safe-owners-hardware-secret','three physical OneKey owner onboarding records and twelve EIP-712 Safe custody proofs',['bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --advance-onboarding','bash scripts/prepare-onekey-ios-safe-mainnet-pilot.sh --advance-custody'],['node scripts/check-safe-owner-hardware-custody-proofs.mjs'],'external-operation'];
  if(key.includes('mining_real')||key.includes('reserve_deposit_native')) return ['execute-pilot-deposit-secret','native finalized-deposit, wallet and privacy evidence',['observe:finalized-deposit-wallet'],['check:native-finalized-deposit-vector'],'external-operation'];
  if(key.includes('gas_measured')||key.includes('proving_capacity')||key.includes('proving_cost')) {
    if(key.startsWith('production_checkpoint_')) return ['measure-release-capacity','checkpoint capacity report and release evidence',['check:checkpoint-capacity-e2e','materialize:checkpoint-capacity-release-evidence'],['check:checkpoint-capacity-release-evidence'],'external-operation'];
    if(key.startsWith('production_finalized_burn_')) return ['measure-release-capacity','finalized-burn capacity report with isolated EVM receipt',['check:finalized-burn-capacity-e2e'],['USDOM_FINALIZED_BURN_PROOF_RUN_ID="$USDOM_FINALIZED_BURN_PROOF_RUN_ID" npm run --silent check:finalized-burn-capacity-evidence'],'external-operation'];
    return ['measure-release-capacity','two-run, two-provider finalized operational gas evidence',
      ['node scripts/collect-production-operational-gas-evidence.mjs "$USDOM_OPERATIONAL_GAS_JOB" "$USDOM_OPERATIONAL_GAS_RPC_SOURCES" "$USDOM_OPERATIONAL_GAS_EVIDENCE"'],
      ['node scripts/check-production-operational-gas-evidence.mjs "$USDOM_OPERATIONAL_GAS_JOB" "$USDOM_OPERATIONAL_GAS_EVIDENCE"'],
      'external-operation'];
  }
  if(burnCoverage.has(key)) { const row=burnCoverage.get(key); return ['execute-pilot-redemption-secret','authenticated finalized-burn receipt and redemption evidence',[row.producer],[row.validator],'external-operation']; }
  if(checkpointCoverage.has(key)) { const row=checkpointCoverage.get(key); return ['produce-checkpoint-evidence-secret','checkpoint proof, registry ratification or finalized-event release evidence',[row.producer],[row.validator],'external-operation']; }
  if(category==='configuration') return ['prepare-deployment','source-bound release configuration',[
    'npm run --silent materialize:production-release-core -- registry-pins',
    'npm run --silent materialize:production-release-core -- reserve-pins',
    'npm run --silent materialize:production-release-core -- final',
  ],['node scripts/prepare-production-release-core-materialization.mjs final | cmp -s - config/proof-reserve.unconfigured.json'], 'external-operation'];
  throw new Error(`open claim has no execution route: ${key}`);
}

const entries=claims.map(({key,category})=>{
  const [phase,evidence,evidenceProducerCommands=[],independentValidatorCommands=[],implementationStatus='external-operation']=route(key,category);
  const artifact=artifactByPhase.get(phase);
  return {claim:key,category,phase,
    phaseOrdinal:artifact.ordinal,phaseScriptSha256:artifact.generatedScriptSha256,
    phaseScriptBytes:artifact.generatedScriptBytes,
    generateCommand:`${materializer} ${phase}`,
    validateCommand:`${cleanBash} -n ${phaseDirectory}/${phase}.sh`,
    executeCommand:`${cleanBash} ${phaseDirectory}/${phase}.sh`,
    completionEvidence:evidence,
    evidenceProducerCommands:evidenceProducerCommands.map(executable),
    independentValidatorCommands:independentValidatorCommands.map(executable),implementationStatus,
    semanticEvidence:openClaimSemanticContract(key),
    readinessConsumer:'readinessRequirementKeys(real-funds)',
    closingClaim:`operational-claims-ledger.json#/${key}`};
});

const readinessClaims=new Set(readinessRequirementKeys('real-funds'));
if(entries.some(({claim})=>!readinessClaims.has(claim))) throw new Error('open claim is not consumed by real-funds readiness');
process.stdout.write(`${JSON.stringify({schema:'usdom-open-claims-execution-plan/v1',claimCount:entries.length,
  phaseOrder,phaseArtifacts,entries},null,2)}\n`);

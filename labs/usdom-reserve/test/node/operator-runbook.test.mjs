import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,cpSync,existsSync,linkSync,mkdirSync,mkdtempSync,readFileSync,readdirSync,rmSync,statSync,symlinkSync,
  writeFileSync,
} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import os from 'node:os';
import path from 'node:path';

const runbookPath=fileURLToPath(new URL('../../docs/CLOSED-MAINNET-LINUX-RUNBOOK.md',import.meta.url));
function accountHomeTestEnvironment(temporary,home) {
  const binaries=path.join(temporary,'test-bin');
  mkdirSync(binaries,{recursive:true,mode:0o700});
  const python=path.join(binaries,'python3');
  writeFileSync(python,`#!/usr/bin/env bash
if [[ \$1 == -c && \$2 == *'pwd.getpwuid'* ]]; then printf '%s\\n' "\$USDOM_TEST_ACCOUNT_HOME"; exit 0; fi
exec /usr/bin/python3 "\$@"
`,{mode:0o700});
  chmodSync(python,0o700);
  const nodeShim=path.join(binaries,'node');
  if(!existsSync(nodeShim)) symlinkSync(process.execPath,nodeShim);
  return {...process.env,HOME:home,USDOM_TEST_ACCOUNT_HOME:home,
    PATH:`${binaries}:${process.env.PATH}`};
}
const projectGitignore=fileURLToPath(new URL('../../.gitignore',import.meta.url));
const repositoryGitignore=fileURLToPath(new URL('../../../../.gitignore',import.meta.url));
const signingScript=fileURLToPath(new URL('../../scripts/configure-release-signing-key.sh',import.meta.url));
const privateFileInstaller=fileURLToPath(new URL(
  '../../scripts/install-private-file-stdin.mjs',import.meta.url,
));
const privateFileNewInstaller=fileURLToPath(new URL(
  '../../scripts/install-private-file-new-stdin.mjs',import.meta.url,
));
const immutablePrivateFileInstaller=fileURLToPath(new URL(
  '../../scripts/install-private-file-immutable-stdin.mjs',import.meta.url,
));
const releaseConfigInstaller=fileURLToPath(new URL(
  '../../scripts/install-release-config-stdin.mjs',import.meta.url,
));
const privateFileReader=fileURLToPath(new URL(
  '../../scripts/read-private-file-stdout.mjs',import.meta.url,
));
const durablePrivateFileSdk=fileURLToPath(new URL(
  '../../sdk/durable-private-file.mjs',import.meta.url,
));
const directProjectFileSdk=fileURLToPath(new URL(
  '../../sdk/direct-project-file.mjs',import.meta.url,
));
const releaseSourceCommitScript=fileURLToPath(new URL(
  '../../scripts/commit-release-source.sh',import.meta.url,
));
const releaseEvidenceCommitScript=fileURLToPath(new URL(
  '../../scripts/commit-release-evidence.sh',import.meta.url,
));
const releaseGitBoundaryScript=fileURLToPath(new URL(
  '../../scripts/git-release-ceremony-boundary.sh',import.meta.url,
));
const residualRiskWriter=fileURLToPath(new URL(
  '../../scripts/write-residual-risk-report.sh',import.meta.url,
));
const releaseAuthorizationRequestWriter=fileURLToPath(new URL(
  '../../scripts/write-release-authorization-request.sh',import.meta.url,
));
const releaseAuthorizationMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-release-authorization.sh',import.meta.url,
));
const nativeAttestationRequestWriter=fileURLToPath(new URL(
  '../../scripts/write-native-release-attestation-requests.sh',import.meta.url,
));
const nativeAttestationMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-native-release-attestations.sh',import.meta.url,
));
const releaseAuthorizationSigner=fileURLToPath(new URL(
  '../../scripts/sign-release-authorizations.sh',import.meta.url,
));
const nativeAuthorizationSigner=fileURLToPath(new URL(
  '../../scripts/sign-native-release-attestations.sh',import.meta.url,
));
const productionAuthorizationSigner=fileURLToPath(new URL(
  '../../scripts/sign-production-release-authorization.sh',import.meta.url,
));
const nativeReceivingWalletScript=fileURLToPath(new URL(
  '../../scripts/prepare-native-receiving-wallet.sh',import.meta.url,
));
const closedMainnetDepositScript=fileURLToPath(new URL(
  '../../scripts/prepare-closed-mainnet-deposit.sh',import.meta.url,
));
const recoverableSafeControlsScript=fileURLToPath(new URL(
  '../../scripts/prepare-recoverable-safe-controls.mjs',import.meta.url,
));
const unsafeSingleOwnerSafeControlsScript=fileURLToPath(new URL(
  '../../scripts/prepare-safe-controls.mjs',import.meta.url,
));
const safeControlDeploymentSdk=fileURLToPath(new URL(
  '../../sdk/safe-control-deployment.mjs',import.meta.url,
));
const mainnetPreflightMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-mainnet-preflight-attestation.mjs',import.meta.url,
));
const mainnetPreflightMaterializerWrapper=fileURLToPath(new URL(
  '../../scripts/materialize-mainnet-preflight-attestation.sh',import.meta.url,
));
const mainnetPreflightMaterializationSdk=fileURLToPath(new URL(
  '../../sdk/mainnet-preflight-materialization.mjs',import.meta.url,
));
const mainnetDeploymentPreparer=fileURLToPath(new URL(
  '../../scripts/prepare-mainnet-deployment.mjs',import.meta.url,
));
const mainnetDeploymentTransactionPreparer=fileURLToPath(new URL(
  '../../scripts/prepare-mainnet-deployment-transaction.mjs',import.meta.url,
));
const mainnetDeploymentRawValidator=fileURLToPath(new URL(
  '../../scripts/check-mainnet-deployment-raw-transaction.mjs',import.meta.url,
));
const mainnetDeploymentExecutor=fileURLToPath(new URL(
  '../../scripts/execute-mainnet-deployment.sh',import.meta.url,
));
const limitedMainnetPolicyMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-limited-mainnet-policy.sh',import.meta.url,
));
const limitedMainnetPolicyPreparer=fileURLToPath(new URL(
  '../../scripts/prepare-limited-mainnet-policy-materialization.mjs',import.meta.url,
));
const mainnetDeploymentIdentityMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-mainnet-deployment-identity.sh',import.meta.url,
));
const mainnetDeploymentIdentityPreparer=fileURLToPath(new URL(
  '../../scripts/prepare-mainnet-deployment-identity-materialization.mjs',import.meta.url,
));
const recoverableSafeCollector=fileURLToPath(new URL(
  '../../scripts/collect-recoverable-safe-controls.mjs',import.meta.url,
));
const recoverableSafeRecoveryCollector=fileURLToPath(new URL(
  '../../scripts/collect-recoverable-safe-recovery.mjs',import.meta.url,
));
const recoverableSafeRecoveryPlanner=fileURLToPath(new URL(
  '../../scripts/prepare-recoverable-safe-recovery.mjs',import.meta.url,
));
const recoverableSafeRecoveryAssembler=fileURLToPath(new URL(
  '../../scripts/assemble-recoverable-safe-recovery.mjs',import.meta.url,
));
const recoverableSafeRecoverySigner=fileURLToPath(new URL(
  '../../scripts/sign-recoverable-safe-recovery.sh',import.meta.url,
));
const recoverableSafeRecoveryExecutor=fileURLToPath(new URL(
  '../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url,
));
const recoverableSafeReleaseEvidenceWriter=fileURLToPath(new URL(
  '../../scripts/write-recoverable-safe-release-evidence.sh',import.meta.url,
));
const safeControlReleaseConfigMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-safe-control-release-config.sh',import.meta.url,
));
const safeControlReleaseMetadataMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-safe-control-release-metadata.sh',import.meta.url,
));
const releaseProvenanceMaterializer=fileURLToPath(new URL(
  '../../scripts/materialize-release-provenance.sh',import.meta.url,
));
const finalizedDepositCollector=fileURLToPath(new URL(
  '../../scripts/collect-finalized-deposit-source.sh',import.meta.url,
));
const finalizedDepositCollectorImplementation=fileURLToPath(new URL(
  '../../scripts/collect-finalized-deposit-source.mjs',import.meta.url,
));
const finalizedDepositBuilder=fileURLToPath(new URL(
  '../../scripts/build-finalized-deposit-witness.sh',import.meta.url,
));
const finalizedDepositBuilderBinary=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-build-finalized-deposit-witness.rs',import.meta.url,
));
const finalizedDepositWalletRegistration=fileURLToPath(new URL(
  '../../scripts/register-finalized-deposit-wallet.sh',import.meta.url,
));
const finalizedDepositSubmission=fileURLToPath(new URL(
  '../../scripts/submit-finalized-deposit-issuance.mjs',import.meta.url,
));
const closedMainnetNodeScript=fileURLToPath(new URL(
  '../../scripts/run-closed-mainnet-node.sh',import.meta.url,
));
const rpcTokenSource=fileURLToPath(new URL(
  '../../../../crates/dom-rpc/src/token.rs',import.meta.url,
));
const nodeMainSource=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/main.rs',import.meta.url,
));
const walletRescanSource=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/bin/dom-wallet-rescan.rs',import.meta.url,
));
const closedMainnetGenesisScript=fileURLToPath(new URL(
  '../../scripts/initialize-closed-mainnet-genesis.mjs',import.meta.url,
));
const closedMainnetIssuanceBlockScript=fileURLToPath(new URL(
  '../../scripts/mine-closed-mainnet-issuance-block.mjs',import.meta.url,
));
const finalizedDepositObservation=fileURLToPath(new URL(
  '../../scripts/observe-finalized-deposit-wallet.sh',import.meta.url,
));
const closedMainnetTpmKeystoreScript=fileURLToPath(new URL(
  '../../scripts/provision-closed-mainnet-tpm-keystore.sh',import.meta.url,
));
const closedMainnetTpmKeystoreBinary=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-wallet-tpm-keystore.rs',import.meta.url,
));
const nativeTpmKeystoreLibrary=fileURLToPath(new URL(
  '../../../../crates/dom-usdom-wallet/src/tpm2_keystore.rs',import.meta.url,
));
const closedMainnetWalletRecoveryScript=fileURLToPath(new URL(
  '../../scripts/drill-closed-mainnet-wallet-recovery.sh',import.meta.url,
));
const closedMainnetWalletRecoveryBinary=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-recover-wallet-at-checkpoint.rs',import.meta.url,
));
const closedMainnetPrivateBurnScript=fileURLToPath(new URL(
  '../../scripts/prepare-closed-mainnet-private-burn.sh',import.meta.url,
));
const closedMainnetPrivateBurnBuilder=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-build-private-burn.rs',import.meta.url,
));
const privateStagingDirectory=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/private_staging_directory.rs',import.meta.url,
));
const closedMainnetTpmBootstrapScript=fileURLToPath(new URL(
  '../../scripts/bootstrap-closed-mainnet-tpm-authority.sh',import.meta.url,
));
const closedMainnetTpmBootstrapBinary=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-bootstrap-tpm-wallet-authority.rs',import.meta.url,
));
const closedMainnetPrivateBurnSubmitScript=fileURLToPath(new URL(
  '../../scripts/submit-closed-mainnet-private-burn.sh',import.meta.url,
));
const closedMainnetPrivateBurnSubmitBinary=fileURLToPath(new URL(
  '../../../../crates/dom-node/src/bin/dom-usdom-submit-private-burn.rs',import.meta.url,
));
const randomxExportScript=fileURLToPath(new URL(
  '../../scripts/export-authenticated-randomx-statement.sh',import.meta.url,
));
const checkpointSourceExportScript=fileURLToPath(new URL(
  '../../scripts/export-canonical-checkpoint-source.sh',import.meta.url,
));
const checkpointSourceSetExportScript=fileURLToPath(new URL(
  '../../scripts/export-canonical-checkpoint-source-set.sh',import.meta.url,
));
const finalizedBurnSourceExportScript=fileURLToPath(new URL(
  '../../scripts/export-canonical-finalized-burn-source.sh',import.meta.url,
));
const randomxStatementSetExportScript=fileURLToPath(new URL(
  '../../scripts/export-authenticated-randomx-statement-set.sh',import.meta.url,
));
const randomxReceiptPlanScript=fileURLToPath(new URL(
  '../../scripts/plan-authenticated-randomx-receipt-set.sh',import.meta.url,
));
const randomxReceiptProveScript=fileURLToPath(new URL(
  '../../scripts/prove-authenticated-randomx-receipt-set.sh',import.meta.url,
));
const risc0RecursionArtifactCheck=fileURLToPath(new URL(
  '../../scripts/require-risc0-recursion-artifact.sh',import.meta.url,
));
const randomxAggregatePlanScript=fileURLToPath(new URL(
  '../../scripts/plan-authenticated-randomx-aggregate-set.sh',import.meta.url,
));
const randomxAggregateProveScript=fileURLToPath(new URL(
  '../../scripts/prove-authenticated-randomx-aggregate-set.sh',import.meta.url,
));
const economicReceiptPlanScript=fileURLToPath(new URL(
  '../../scripts/plan-authenticated-economic-receipt-set.sh',import.meta.url,
));
const economicReceiptProveScript=fileURLToPath(new URL(
  '../../scripts/prove-authenticated-economic-receipt-set.sh',import.meta.url,
));
const checkpointSegmentPlanScript=fileURLToPath(new URL(
  '../../scripts/plan-authenticated-checkpoint-segment-set.sh',import.meta.url,
));
const checkpointSegmentProveScript=fileURLToPath(new URL(
  '../../scripts/prove-authenticated-checkpoint-segment-set.sh',import.meta.url,
));
const checkpointOuterPlanScript=fileURLToPath(new URL(
  '../../scripts/plan-authenticated-checkpoint-outer.sh',import.meta.url,
));
const checkpointOuterProveScript=fileURLToPath(new URL(
  '../../scripts/prove-authenticated-checkpoint-outer.sh',import.meta.url,
));
const checkpointOuterEvmPackageScript=fileURLToPath(new URL(
  '../../scripts/package-authenticated-checkpoint-outer-evm-proof.sh',import.meta.url,
));
const checkpointSegmentProverBinary=fileURLToPath(new URL(
  '../../../../crates/dom-usdom-checkpoint-proof-host/src/bin/prove.rs',import.meta.url,
));
const checkpointSegmentPlannerBinary=fileURLToPath(new URL(
  '../../../../crates/dom-usdom-checkpoint-proof-host/src/bin/plan.rs',import.meta.url,
));
const checkpointOuterProverBinary=fileURLToPath(new URL(
  '../../../../crates/dom-usdom-checkpoint-proof-host/src/bin/prove-outer.rs',import.meta.url,
));
const checkpointOuterPlannerBinary=fileURLToPath(new URL(
  '../../../../crates/dom-usdom-checkpoint-proof-host/src/bin/plan-outer.rs',import.meta.url,
));
const checkpointOuterPackagerBinary=fileURLToPath(new URL(
  '../../../../crates/dom-usdom-checkpoint-proof-host/src/bin/package-outer-evm.rs',import.meta.url,
));
const checkpointSubmissionScript=fileURLToPath(new URL(
  '../../scripts/prepare-authenticated-checkpoint-submission.mjs',import.meta.url,
));
const checkpointObserverScript=fileURLToPath(new URL(
  '../../scripts/observe-authenticated-checkpoint.mjs',import.meta.url,
));
const checkpointObserverLauncher=fileURLToPath(new URL(
  '../../scripts/observe-authenticated-checkpoint.sh',import.meta.url,
));
const finalizedBurnPlanScript=fileURLToPath(new URL(
  '../../scripts/plan-authenticated-finalized-burn.sh',import.meta.url,
));
const finalizedBurnProveScript=fileURLToPath(new URL(
  '../../scripts/prove-authenticated-finalized-burn.sh',import.meta.url,
));
const finalizedBurnProofHostSource=fileURLToPath(new URL(
  '../../../../crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',import.meta.url,
));
const finalizedBurnEvmPackageScript=fileURLToPath(new URL(
  '../../scripts/package-authenticated-finalized-burn-evm-proof.sh',import.meta.url,
));
const finalizedBurnSubmissionScript=fileURLToPath(new URL(
  '../../scripts/prepare-authenticated-finalized-burn-submission.mjs',import.meta.url,
));
const finalizedBurnHandoffScript=fileURLToPath(new URL(
  '../../scripts/check-finalized-burn-planner-handoff.sh',import.meta.url,
));
const finalizedBurnProverE2eScript=fileURLToPath(new URL(
  '../../scripts/check-finalized-burn-prover-e2e.sh',import.meta.url,
));

test('operator runbook contains no manual substitution markers',()=>{
  const runbook=readFileSync(runbookPath,'utf8');
  const phaseGenerator=readFileSync(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  const safeDeploymentExecutor=readFileSync(new URL('../../scripts/execute-safe-control-deployment.sh',import.meta.url),'utf8');
  for(const forbidden of [
    '0x_SUBSTITUA','FINGERPRINT_FORA_DO_REPOSITORIO','Preencha os arquivos',
    'INDEX=0  # execute novamente','execute o mesmo bloco de broadcast',
    'USDOM_SAFE_DEPLOY_AUTHORIZED','atualize seu arquivo',"read -rsp 'RPC Ethereum",
    '1-de-1','prepare-safe-controls.mjs','AUTORIZO TRES SAFES 1-DE-1',
  ]) assert.equal(runbook.includes(forbidden),false,forbidden);
  assert.match(runbook,/npm run --silent configure:release-signing-key/);
  assert.match(runbook,/npm run --silent materialize:limited-mainnet-policy/);
  assert.match(runbook,/npm run --silent materialize:mainnet-deployment-identity/);
  assert.match(runbook,/for INDEX in 0 1; do/);
  assert.match(runbook,/for INDEX in 2 3; do/);
  assert.match(runbook,/migrate-safe-owners-hardware-secret/);
  assert.doesNotMatch(runbook,/> "\$USDOM_SAFE_OWNER_IDENTITIES"|chmod 0600 "\$USDOM_SAFE_OWNER_IDENTITIES"/);
  for(const artifact of ['USDOM_SAFE_BASELINE','USDOM_SAFE_BASELINE_SECONDARY']) {
    assert.match(runbook,new RegExp(`install-private-file-new-stdin\\.mjs "\\$${artifact}"`));
    assert.doesNotMatch(runbook,new RegExp(`> "\\$${artifact}"|chmod 0600[^\\n]*"\\$${artifact}"`));
  }
  assert.match(runbook,/materialize-closed-mainnet-phase-script\.sh prepare-safe-recovery-secret/);
  assert.match(runbook,/materialize-closed-mainnet-phase-script\.sh execute-safe-recovery-secret/);
  assert.doesNotMatch(runbook,/> "\$USDOM_SAFE_RECOVERY_PLAN"|chmod 0600[^\n]*"\$USDOM_SAFE_RECOVERY_PLAN"/);
  assert.match(runbook,/install-private-file-new-stdin\.mjs \\\n+      "\$USDOM_CONTROL_EVIDENCE_DIRECTORY\/\$role-configuration\.json"/);
  assert.doesNotMatch(runbook,/> "\$USDOM_CONTROL_EVIDENCE_DIRECTORY\/\$role-configuration\.json"/);
  assert.doesNotMatch(runbook,/\/tmp\/usdom-recoverable-safe-controls/);
  assert.match(runbook,/USDOM_SAFE_PACKAGE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY\/safe-package\.json"/);
  assert.match(runbook,/materialize-closed-mainnet-phase-script\.sh prepare-deployment/);
  assert.match(runbook,/\/usr\/bin\/bash --noprofile --norc \/home\/leonardov\/usdom-mainnet-private\/operator-phases\/prepare-deployment\.sh/);
  assert.doesNotMatch(runbook,/\/tmp\/usdom-mainnet-deployment-package\.json/);
  assert.doesNotMatch(runbook,/\/tmp\/usdom-release-signing-public-identity\.json/);
  assert.doesNotMatch(runbook,/> "\$USDOM_MAINNET_DEPLOYMENT_PACKAGE"|chmod 0600[^\n]*"\$USDOM_MAINNET_DEPLOYMENT_PACKAGE"/);
  assert.equal((runbook.match(/execute:mainnet-deployment -- "\$INDEX"/g)??[]).length,2);
  assert.doesNotMatch(runbook,/REBUILT_PACKAGE=/);
  assert.doesNotMatch(runbook,/\/tmp\/usdom-deploy-|\/tmp\/usdom-recoverable-safe-[^\s"]*-receipt\.json/);
  assert.match(runbook,/execute-safe-controls-deployment-secret/);
  assert.match(safeDeploymentExecutor,/safe-deployment-\$role-receipt\.json/);
  assert.match(safeDeploymentExecutor,/safe-deployment-\$role-journal\.json/);
  assert.match(safeDeploymentExecutor,/AUTORIZO ASSINAR SAFE/);
  assert.match(safeDeploymentExecutor,/AUTORIZO TRANSMITIR SAFE/);
  assert.match(safeDeploymentExecutor,/check-safe-control-deployment-raw-transaction\.mjs/);
  assert.match(safeDeploymentExecutor,/check-safe-control-deployment-target\.mjs/);
  assert.match(safeDeploymentExecutor,/publish-private-raw-transaction\.mjs/);
  assert.doesNotMatch(runbook,/cast send "\$to"/);
  assert.match(runbook,/USDOM_RELEASE_SIGNING_PUBLIC_IDENTITY="\$USDOM_CONTROL_EVIDENCE_DIRECTORY\/release-signing-public-identity\.json"/);
  assert.match(runbook,/install-private-file-immutable-stdin\.mjs "\$USDOM_RELEASE_SIGNING_PUBLIC_IDENTITY"/);
  assert.match(runbook,/read-private-file-stdout\.mjs "\$USDOM_RELEASE_SIGNING_PUBLIC_IDENTITY" \| jq -er '\.fingerprint'/);
  assert.doesNotMatch(runbook,/\/tmp\/usdom-predeployment\.json|\/tmp\/usdom-cold-start\.json/);
  assert.doesNotMatch(runbook,/\/tmp\/usdom-real-funds\.json|\/tmp\/usdom-native-receiving-wallet-public\.json|\/tmp\/usdom-closed-mainnet-deposit\.json/);
  for(const [variable,name,command] of [
    ['USDOM_PREDEPLOYMENT_ATTESTATION','mainnet-predeployment-attestation','materialize:mainnet-predeployment-attestation'],
    ['USDOM_COLD_START_ATTESTATION','mainnet-cold-start-attestation','materialize:mainnet-cold-start-attestation'],
  ]) {
    assert.match(runbook,new RegExp(`${variable}="\\$USDOM_CONTROL_EVIDENCE_DIRECTORY\\/${name}\\.json"`));
    assert.match(runbook,new RegExp(`install-private-file-new-stdin\\.mjs "\\$${variable}"`));
    assert.match(runbook,new RegExp(`read-private-file-stdout\\.mjs "\\$${variable}"`));
    assert.match(runbook,new RegExp(`npm run --silent ${command}`));
  }
  assert.match(phaseGenerator,/USDOM_NATIVE_RECEIVING_WALLET_PUBLIC="\\\$USDOM_CONTROL_EVIDENCE_DIRECTORY\/native-receiving-wallet-public\.json"/);
  assert.match(phaseGenerator,/install-private-file-immutable-stdin\.mjs "\$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC"/);
  assert.match(phaseGenerator,/read-private-file-stdout\.mjs "\$USDOM_NATIVE_RECEIVING_WALLET_PUBLIC"/);
  assert.match(runbook,/USDOM_CLOSED_MAINNET_DEPOSIT_PACKAGE="\$USDOM_CONTROL_EVIDENCE_DIRECTORY\/closed-mainnet-deposit-package\.json"/);
  assert.match(runbook,/install-private-file-new-stdin\.mjs "\$USDOM_CLOSED_MAINNET_DEPOSIT_PACKAGE"/);
  assert.match(runbook,/read-private-file-stdout\.mjs "\$USDOM_CLOSED_MAINNET_DEPOSIT_PACKAGE"/);
  assert.match(runbook,/REAL_FUNDS_CANDIDATE=\$\(mktemp\)/);
  for(const former of [
    'usdom-finalized-deposit-source-summary.json','usdom-finalized-deposit-witness-summary.txt',
    'usdom-closed-mainnet-genesis.json','usdom-tpm-wallet-keystore.txt',
    'usdom-expected-deposit-registration.txt','usdom-finalized-deposit-issuance-submission.json',
    'usdom-closed-mainnet-issuance-block.json','usdom-finalized-deposit-observation.txt',
    'usdom-wallet-recovery-drill.txt',
  ]) assert.equal(runbook.includes(`/tmp/${former}`),false,former);
  for(const variable of ['SOURCE_SUMMARY','GENESIS_SUMMARY','TPM_SUMMARY','REGISTRATION_SUMMARY',
    'ISSUANCE_SUMMARY','MINING_SUMMARY','OBSERVATION_SUMMARY','RECOVERY_SUMMARY']) {
    assert.match(runbook,new RegExp(`${variable}=\\$\\(mktemp\\)`));
    assert.match(runbook,new RegExp(`rm -f "\\$${variable}"`));
  }
  assert.doesNotMatch(runbook,/build:finalized-deposit-witness[^\n]*\\\n\s*\| tee/);
  assert.doesNotMatch(runbook,/\/tmp\/usdom-release-(?:source|evidence)-commit\.json/);
  for(const [variable,name] of [
    ['USDOM_RELEASE_SOURCE_COMMIT_RESULT','release-source-commit-result'],
    ['USDOM_RELEASE_EVIDENCE_COMMIT_RESULT','release-evidence-commit-result'],
  ]) {
    assert.match(runbook,new RegExp(`${variable}="\\$USDOM_CONTROL_EVIDENCE_DIRECTORY\\/${name}\\.json"`));
    assert.match(runbook,new RegExp(`install-private-file-new-stdin\\.mjs "\\$${variable}"`));
    assert.match(runbook,new RegExp(`read-private-file-stdout\\.mjs "\\$${variable}"`));
  }
  assert.doesNotMatch(runbook,/\/tmp\/usdom-(?:recoverable-safe-controls|mainnet-deployment-package|release-signing-public-identity)\.json/);
  assert.match(runbook,/CLOSED_MAINNET_DIAGNOSTIC=\$\(mktemp\)/);
  assert.match(runbook,/test "\$diagnostic_status" -eq 1/);
  assert.match(runbook,/\.ready == false and \.blockerCount > 0/);
});

test('Safe raw-transaction validator rejects ambiguous envelope bytes before Ledger output',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-safe-raw-json-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  const envelope=path.join(temporary,'envelope.json');
  const unused=path.join(temporary,'unused');
  writeFileSync(unused,'{}\n',{mode:0o600});
  const validator=fileURLToPath(new URL(
    '../../scripts/check-recoverable-safe-recovery-raw-transaction.mjs',import.meta.url));
  for(const [bytes,pattern] of [
    [Buffer.from('{"role":"one","\\u0072ole":"two"}\n'),/duplicate object key "role"/],
    [Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),/invalid UTF-8/],
  ]) {
    writeFileSync(envelope,bytes,{mode:0o600});
    const result=spawnSync(process.execPath,[validator],{encoding:'utf8',env:{...process.env,
      USDOM_SAFE_RECOVERY_ENVELOPE:envelope,USDOM_SAFE_RECOVERY_PLAN:unused,
      USDOM_SAFE_RECOVERY_TRANSACTIONS:unused,USDOM_SAFE_RECOVERY_RAW_TRANSACTION:unused,
    }});
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/RELEASE_OPERATION_REJECTED/);
  }
});

test('mainnet deployment handoff rederives one direct immutable package before Ledger use',()=>{
  for(const script of [mainnetDeploymentPreparer,mainnetDeploymentTransactionPreparer,
    mainnetDeploymentRawValidator]) {
    const parsed=spawnSync(process.execPath,['--check',script],{encoding:'utf8'});
    assert.equal(parsed.status,0,parsed.stderr);
  }
  const preparer=readFileSync(mainnetDeploymentPreparer,'utf8');
  assert.match(preparer,/inputSnapshots=new Map/);
  assert.match(preparer,/deployment input stability check/);
  const handoff=readFileSync(mainnetDeploymentTransactionPreparer,'utf8');
  assert.match(handoff,/readDirectFile\(packagePath/);
  assert.match(handoff,/exactMode:0o600/);
  assert.match(handoff,/prepared\.stdout\.equals\(packageBytes\)/);
  assert.match(handoff,/USDOM_PACKAGE_SHA256/);
  assert.match(handoff,/USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION/);
  assert.doesNotMatch(handoff,/process\.env\.USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256/);
  assert.match(handoff,/expectedObservationSha=packageValue\.observationDocumentSha256/);
  assert.match(handoff,/observationDocumentSha256!==observationSha/);
  assert.match(handoff,/observationAfter\.equals\(observationBytes\)/);
  assert.match(handoff,/new TextDecoder\('utf-8',\{fatal:true\}\)/);
  assert.match(handoff,/usdom-mainnet-deployment-ledger-handoff-v1/);
  for(const forbidden of ['cast send','eth_sendRawTransaction','--ledger','--private-key','--mnemonic']) {
    assert.equal(handoff.includes(forbidden),false,forbidden);
  }
});

test('deployment raw validator rejects invalid UTF-8 and noncanonical hex before handoff',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-deployment-raw-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  const rawPath=path.join(temporary,'raw.txt');
  for(const [bytes,pattern] of [
    [Buffer.from([0x30,0x78,0x01,0xff,0x0a]),/invalid UTF-8/],
    [Buffer.from('0xAABB\n'),/framing is invalid/],
    [Buffer.from('0xaabb\n\n'),/framing is invalid/],
  ]) {
    writeFileSync(rawPath,bytes,{mode:0o600});
    const result=spawnSync(process.execPath,[mainnetDeploymentRawValidator,'0'],{
      encoding:'utf8',env:{...process.env,USDOM_MAINNET_DEPLOYMENT_RAW_TRANSACTION:rawPath},
    });
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/RELEASE_OPERATION_REJECTED/);
  }
});

test('deployment receipt authority rejects identical malformed RPC JSON',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-deployment-receipt-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  const receipt=path.join(temporary,'receipt.json');
  const checker=fileURLToPath(new URL(
    '../../scripts/check-private-strict-json-file.mjs',import.meta.url));
  for(const bytes of [
    Buffer.from('{"status":"0x1","\\u0073tatus":"0x0"}\n'),
    Buffer.from('{"hash":"0x01","\\u0068ash":"0x02"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    writeFileSync(receipt,bytes,{mode:0o600});
    const first=spawnSync(process.execPath,[checker,receipt],{encoding:'utf8'});
    const identical=spawnSync(process.execPath,[checker,receipt],{encoding:'utf8'});
    assert.notEqual(first.status,0);
    assert.notEqual(identical.status,0);
  }
  const executor=readFileSync(mainnetDeploymentExecutor,'utf8');
  const strictJsonChecks=(executor.match(/check-private-strict-json-file\.mjs/g)??[]).length;
  const pinnedStrictJsonChecks=(executor.match(
    /run_node_empty_authority (?:generated-(?:jq-)?json|strict-json) scripts\/check-private-strict-json-file\.mjs/g)??[]).length;
  assert.ok(strictJsonChecks>=14);
  assert.equal(pinnedStrictJsonChecks,strictJsonChecks);
  assert.doesNotMatch(executor,/(?:^|\n)\s*node scripts\/check-private-strict-json-file\.mjs/m);
  assert.doesNotMatch(executor,/\w+=\$\(rpc rpc eth_getTransactionByHash/);
  assert.doesNotMatch(executor,/jq[^\n]*<<<"\$(?:seen|transmit_seen)"/);
  assert.match(executor,/eth_getTransactionByHash[^\n]*\\\n\s*> "\$seen_file"/);
  assert.match(executor,/eth_getTransactionByHash[^\n]*\\\n\s*> "\$transmit_seen_file"/);
  assert.doesNotMatch(executor,/rpc block finalized --json[^\n]*\| jq[^\n]*baseFeePerGas/);
  assert.match(executor,/check-private-strict-json-file\.mjs "\$fee_block"/);
  assert.match(executor,/check-private-strict-json-file\.mjs "\$presign_fee_block"/);
  assert.match(executor,/check-private-strict-json-file\.mjs "\$transmit_fee_block"/);
  assert.doesNotMatch(executor,/rpc block [^\n]*--json[^\n]*\| jq/);
  assert.doesNotMatch(executor,/jq[^\n]*<<<"\$(?:finalized|finalized_recheck)"/);
  for(const authority of [
    'finalized','canonical','finalized_recheck','canonical_recheck',
    'stable_finalized','stable_canonical',
  ]) {
    assert.match(executor,new RegExp(
      `check-private-strict-json-file\\.mjs "\\$${authority}"`));
  }
});

test('mainnet deployment handoff rejects ambiguous package bytes before transaction use',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-deployment-json-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  // Do not name attacker-controlled bytes package.json: Node parses ancestor
  // package manifests before the tested strict parser executes.
  const packagePath=path.join(temporary,'deployment-package-input.json');
  const observationPath=path.join(temporary,'observation.json');
  writeFileSync(observationPath,'{}\n',{mode:0o600});
  for(const [bytes,pattern] of [
    [Buffer.from('{"schema":"one","\\u0073chema":"two"}\n'),/duplicate object key "schema"/],
    [Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),/invalid UTF-8/],
  ]) {
    writeFileSync(packagePath,bytes,{mode:0o600});
    // Malformed package bytes reject before the preparer accesses its catalog.
    const result=spawnSync(process.execPath,[mainnetDeploymentTransactionPreparer,'0'],{
      encoding:'utf8',env:{...process.env,USDOM_MAINNET_DEPLOYMENT_PACKAGE:packagePath,
        USDOM_PACKAGE_SHA256:createHash('sha256').update(bytes).digest('hex'),
        USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION:observationPath},
    });
    assert.notEqual(result.status,0);
    assert.match(result.stderr,/RELEASE_OPERATION_REJECTED/);
  }
  for(const [observationBytes,pattern] of [
    [Buffer.from('{"observationHash":"one","\\u006fbservationHash":"two"}\n'),
      /duplicate object key "observationHash"/],
    [Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),/invalid UTF-8/],
  ]) {
    writeFileSync(observationPath,observationBytes,{mode:0o600});
    const strictJsonUrl=new URL('../../sdk/strict-json.mjs',import.meta.url).href;
    const parser=`import {readFileSync} from 'node:fs';
import {parseStrictJsonBytes} from ${JSON.stringify(strictJsonUrl)};
parseStrictJsonBytes(readFileSync(process.argv[1]),{label:'deployment observation'});`;
    const result=spawnSync(process.execPath,['--input-type=module','--eval',parser,observationPath],
      {encoding:'utf8'});
    assert.notEqual(result.status,0);
    assert.match(result.stderr,pattern);
  }
});

test('mainnet deployment executor journals the exact gas-relayer transaction before publish',()=>{
  const source=readFileSync(mainnetDeploymentExecutor,'utf8');
  assert.match(source,/\[\[ ! -t 0 \|\| ! -t 1 \]\]/);
  assert.match(source,/authorization requires an interactive terminal/);
  const redirected=spawnSync('bash',[mainnetDeploymentExecutor,'0'],{
    cwd:path.dirname(path.dirname(mainnetDeploymentExecutor)),encoding:'utf8',
    stdio:['pipe','pipe','pipe'],
  });
  assert.equal(redirected.status,1);
  assert.match(redirected.stderr,/authorization requires an interactive terminal/);
  assert.equal(spawnSync('bash',['-n',mainnetDeploymentExecutor]).status,0);
  assert.doesNotMatch(source,/\$\{USDOM_PACKAGE_SHA256:\?/);
  assert.match(source,/USDOM_PACKAGE_SHA256=\$\(sha256_file "\$package_snapshot"\)/);
  assert.doesNotMatch(source,/USDOM_PACKAGE_SHA256=\$\(sha256sum /);
  assert.match(source,/export USDOM_MAINNET_DEPLOYMENT_PACKAGE=\$package_snapshot/);
  assert.match(source,/snapshot "\$observation_source" "\$observation_snapshot"/);
  assert.match(source,/expected_observation_sha=\$\("\$jq_bin" -er '\.observationDocumentSha256' "\$package_snapshot"\)/);
  assert.match(source,/export USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION=\$observation_snapshot/);
  assert.match(source,/prepare-mainnet-deployment-transaction\.mjs "\$index"/);
  assert.match(source,/check-mainnet-deployment-raw-transaction\.mjs "\$index"/);
  assert.match(source,/relayer_envelope="\$evidence_directory\/contract-deployment-\$index-relayer-envelope\.json"/);
  assert.match(source,/prepare-private-mainnet-create\.mjs prepare/);
  assert.match(source,/"\$nonce" "\$gas_limit" "\$max_fee" "\$priority_fee"/);
  assert.match(source,/relayer_external_raw="\$evidence_directory\/contract-deployment-\$index-relayer-external-raw\.txt"/);
  assert.doesNotMatch(source,/wallet (?:address|sign)[^\n]*--ledger|assemble-private-mainnet-create/);
  assert.match(source,/persist_new "\$raw_draft" "\$raw_file"/);
  assert.match(source,/persist_new "\$temporary\/hash\.txt" "\$hash_file"/);
  assert.match(source,/publish-private-raw-transaction\.mjs "\$raw_snapshot"/);
  assert.ok(source.indexOf('persist_new "$raw_draft" "$raw_file"')
    < source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
  assert.ok(source.indexOf('persist_new "$temporary/hash.txt" "$hash_file"')
    < source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
  assert.match(source,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
  assert.match(source,/serve-private-rpc-catalog-proxy\.mjs/);
  assert.match(source,/rpc_urls\[@\]/);
  assert.doesNotMatch(source,/ETHEREUM_RPC_URL_2|ETHEREUM_RPC_URL[^S]/);
  assert.match(source,/--block pending/);
  assert.match(source,/--block finalized/);
  assert.match(source,/"\$cast_bin" keccak "\$code"/);
  assert.match(source,/expected_runtime_hash/);
  assert.match(source,/canonical_quantity "\$receipt_number" "\$finalized_number" >\/dev\/null/);
  assert.match(source,/canonical_hash.*receipt_hash/);
  assert.match(source,/transaction\.presign\.json/);
  assert.match(source,/transaction\.prepublish\.json/);
  assert.match(source,/transaction\.prereceipt\.json/);
  assert.match(source,/USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION/);
  assert.doesNotMatch(source,/USDOM_MAINNET_DEPLOYMENT_IDENTITY_OBSERVATION_SHA256/);
  assert.match(source,/canonical_quantity "\$stable_number" "\$stable_finalized_number" >\/dev\/null/);
  assert.match(source,/test "\$stable_code" = "\$code_consensus"/);
  assert.match(source,/\[redacted RPC URL\]/);
  assert.match(source,/AUTORIZO ASSINAR DEPLOY INDICE \$index/);
  assert.match(source,/presign_maximum_estimate=0/);
  assert.match(source,/presign_maximum_base=0/);
  assert.match(source,/test "\$presign_gas_limit" = "\$gas_limit"/);
  assert.match(source,/test "\$presign_max_fee" = "\$max_fee"/);
  assert.ok(source.indexOf('signing_authorization')
    < source.indexOf('presign_maximum_estimate=0'));
  assert.ok(source.indexOf('presign_maximum_estimate=0')
    < source.indexOf('prepare-private-mainnet-create.mjs prepare'));
  assert.ok(source.indexOf('deployment_broadcast_state=signed-unresolved')
    > source.indexOf('check-mainnet-deployment-raw-transaction.mjs'));
  assert.match(source,/AUTORIZO TRANSMITIR DEPLOY INDICE \$index/);
  assert.ok(source.indexOf('AUTORIZO ASSINAR DEPLOY INDICE $index')
    < source.indexOf('prepare-private-mainnet-create.mjs prepare'));
  assert.ok(source.indexOf('AUTORIZO TRANSMITIR DEPLOY INDICE $index')
    < source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
  assert.match(source,/transaction\.transmit\.json/);
  assert.match(source,/eth_getTransactionByHash[^\n]*\\\n\s*> "\$transmit_seen_file"/);
  assert.match(source,/raw\.transmit\.txt/);
  const transmitAuthorization=source.indexOf('test "$transmission_authorization" =');
  const transmitReobservation=source.indexOf('transaction.transmit.json',transmitAuthorization);
  assert.ok(transmitAuthorization<transmitReobservation);
  assert.ok(transmitReobservation<source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
  assert.match(source,/if\(fee>100000000000n\)process\.exit\(1\)/);
  assert.match(source,/600000000000000000n/);
  assert.match(source,/gas_limit <= 20000000/);
  for(const forbidden of ['cast send','--private-key','--mnemonic','eth_sendRawTransaction']) {
    assert.equal(source.includes(forbidden),false,forbidden);
  }
  const validator=readFileSync(mainnetDeploymentRawValidator,'utf8');
  assert.match(validator,/validateMainnetDeploymentRawTransaction/);
  assert.match(validator,/rawSha256:createHash\('sha256'\)/);
});

test('limited mainnet pilot policy is fixed, atomic and cannot authorize or transmit',()=>{
  const wrapper=readFileSync(limitedMainnetPolicyMaterializer,'utf8');
  const preparer=readFileSync(limitedMainnetPolicyPreparer,'utf8');
  assert.equal(spawnSync('bash',['-n',limitedMainnetPolicyMaterializer]).status,0);
  assert.equal(spawnSync(process.execPath,['--check',limitedMainnetPolicyPreparer]).status,0);
  assert.match(wrapper,/replace-locked-source-stdin\.mjs/);
  assert.match(wrapper,/\.productionReady == false and \.realFundsAuthorized == false/);
  assert.match(wrapper,/\.maxOutstandingBaseUnits == "1000000"/);
  assert.match(wrapper,/flock -n 9/);
  assert.match(wrapper,/sync -f "\$target"/);
  assert.match(preparer,/readDirectProjectFile/);
  assert.match(preparer,/current\.equals\(before\)/);
  for(const forbidden of ['cast ','--ledger','--private-key','--mnemonic','eth_sendRawTransaction',
    'cast send','cast publish','productionReady = true','realFundsAuthorized = true']) {
    assert.equal(wrapper.includes(forbidden),false,forbidden);
    assert.equal(preparer.includes(forbidden),false,forbidden);
  }
});

test('mainnet deployment identity is rederived before each durable write without signing',()=>{
  const wrapper=readFileSync(mainnetDeploymentIdentityMaterializer,'utf8');
  const preparer=readFileSync(mainnetDeploymentIdentityPreparer,'utf8');
  assert.equal(spawnSync('bash',['-n',mainnetDeploymentIdentityMaterializer]).status,0);
  assert.equal(spawnSync(process.execPath,['--check',mainnetDeploymentIdentityPreparer]).status,0);
  assert.equal((wrapper.match(/read-mainnet-gas-relayer-identity\.mjs/g)??[]).length,4);
  assert.doesNotMatch(wrapper,/--ledger|Ledger/);
  assert.match(wrapper,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
  assert.match(wrapper,/replace-locked-source-stdin\.mjs/);
  assert.match(wrapper,/install-private-file-immutable-stdin\.mjs --json "\$observation_target"/);
  assert.match(wrapper,/envelope\.final\.json/);
  assert.match(wrapper,/envelope\.preconfig\.json/);
  assert.match(wrapper,/observation\.installed\.json/);
  assert.match(wrapper,/configuration\.installed\.json/);
  assert.match(wrapper,/observation\.final\.json/);
  assert.ok(wrapper.indexOf('install-private-file-immutable-stdin.mjs --json "$observation_target"')
    <wrapper.indexOf('replace-locked-source-stdin.mjs "$target"'));
  assert.ok(wrapper.indexOf('replace-locked-source-stdin.mjs "$target"')
    <wrapper.indexOf('observation.final.json'));
  assert.equal((wrapper.match(/prepare-mainnet-deployment-identity-materialization\.mjs/g)??[]).length,3);
  assert.match(preparer,/observeMainnetDeploymentIdentity/);
  assert.match(preparer,/BoundedMainnetPreflightProvider/);
  assert.match(preparer,/matchMainnetPreflightRpcSources/);
  assert.match(preparer,/current\.equals\(before\)/);
  for(const forbidden of ['cast send','cast publish','cast mktx','--private-key','--mnemonic',
    'eth_sendRawTransaction','signTransaction','productionReady = true','realFundsAuthorized = true']) {
    assert.equal(wrapper.includes(forbidden),false,forbidden);
    assert.equal(preparer.includes(forbidden),false,forbidden);
  }
});

test('single-owner Safe operator path is disabled fail closed',()=>{
  const source=readFileSync(unsafeSingleOwnerSafeControlsScript,'utf8');
  const sdkSource=readFileSync(safeControlDeploymentSdk,'utf8');
  assert.doesNotMatch(source,/prepareSafeControlDeployments|ETHEREUM_RPC_URL|USDOM_SAFE_OWNER/);
  assert.match(source,/Unsafe 1-of-1 Safe preparation is disabled/);
  assert.doesNotMatch(sdkSource,/export const SAFE_CONTROL_SCHEMA\b|SAFE_THRESHOLD = 1|prepareSafeControlDeployments\b|owners\.length===1/);
  assert.match(sdkSource,/RECOVERABLE_SAFE_OWNER_COUNT = 3/);
  assert.match(sdkSource,/RECOVERABLE_SAFE_THRESHOLD = 2/);
  const rejected=spawnSync(process.execPath,[unsafeSingleOwnerSafeControlsScript],{encoding:'utf8'});
  assert.notEqual(rejected.status,0);
  assert.equal(rejected.stdout,'');
  assert.match(rejected.stderr,/prepare:recoverable-safe-controls/);
});

test('mainnet preflight materializer is fixed, local and cannot broadcast',()=>{
  const source=readFileSync(mainnetPreflightMaterializer,'utf8');
  const wrapper=readFileSync(mainnetPreflightMaterializerWrapper,'utf8');
  const sdkSource=readFileSync(mainnetPreflightMaterializationSdk,'utf8');
  assert.equal(spawnSync('bash',['-n',mainnetPreflightMaterializerWrapper]).status,0);
  for(const forbidden of ['JsonRpcProvider','cast ','eth_send','sendTransaction','fetch(','http://','https://']) {
    assert.equal(source.includes(forbidden),false,forbidden);
    assert.equal(wrapper.includes(forbidden),false,forbidden);
  }
  assert.match(source,/prepareMainnetPreflightMaterialization/);
  assert.match(sdkSource,/assessMainnetPreflight/);
  assert.match(source,/writeFileDurable/);
  assert.match(source,/replace:false/);
  assert.match(wrapper,/flock -n 9/);
  assert.match(wrapper,/\[\[ \$1 != predeployment && \$1 != postdeployment \]\]/);
});

test('mutable continuation state cannot make a release repository dirty',()=>{
  const ignored=readFileSync(projectGitignore,'utf8').split(/\r?\n/).filter(Boolean);
  assert.equal(ignored.filter(value=>value==='docs/CONTINUATION-STATE.md').length,1);
  const repositoryIgnored=readFileSync(repositoryGitignore,'utf8').split(/\r?\n/).filter(Boolean);
  assert.equal(repositoryIgnored.filter(value=>value==='/docs/CONTINUATION-STATE.md').length,1);
  for(const scriptPath of [releaseSourceCommitScript,releaseEvidenceCommitScript]) {
    const source=readFileSync(scriptPath,'utf8');
    assert.match(source,/check-ignore -q "docs\/CONTINUATION-STATE\.md"/);
  }
});

test('native receiving-wallet command keeps secrets interactive and returns a fixed deposit commitment',()=>{
  const parsed=spawnSync('bash',['-n',nativeReceivingWalletScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(nativeReceivingWalletScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','PRIVATE KEY','MNEMONIC','--seed','--private-key',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/read -r -s -p/);
  assert.match(source,/\[\[ ! -t 0 \|\| ! -t 2 \]\]/);
  assert.match(source,/mktemp -d -p \/dev\/shm/);
  assert.match(source,/--password-file "\$PASSWORD_FILE"/);
  assert.match(source,/receiving_commitment/);
  assert.match(source,/Existing public identity is not a direct owner-only 0600 file/);
  assert.match(source,/dom-usdom-wallet-recovery/);
  assert.match(source,/ensure-private-child-directory\.py/);
  assert.match(source,/install-private-file-immutable-stdin\.mjs/);
  assert.match(source,/read-release-config-file-stdout\.mjs/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.doesNotMatch(source,/\bmkdir -p\b|\bchmod 0700 -- "\$WALLET_DIRECTORY"|\bmv -f\b/);
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-wallet-command-'));
  try {
    const rejected=spawnSync('bash',[nativeReceivingWalletScript],{
      encoding:'utf8',env:{...process.env,HOME:temporary},input:'must-not-be-read\n',
    });
    assert.notEqual(rejected.status,0);
    assert.equal(rejected.stdout,'');
    assert.equal(existsSync(path.join(temporary,'.local')),false);
  } finally { rmSync(temporary,{recursive:true,force:true}); }
});

test('closed mainnet deposit command derives one stable Safe custody address and cannot broadcast',()=>{
  const parsed=spawnSync('bash',['-n',closedMainnetDepositScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(closedMainnetDepositScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','--private-key','--mnemonic','cast send','eth_sendRawTransaction',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.equal((source.match(/read-safe-usdt-custody-address\.mjs/g)??[]).length,2);
  assert.doesNotMatch(source,/--ledger|Ledger/);
  assert.match(source,/"\$FIRST_ADDRESS" != "\$SECOND_ADDRESS"/);
  assert.match(source,/node scripts\/prepare-closed-mainnet-deposit\.mjs/);
});

test('recoverable production Safe package is fixed at three distinct owners per role and threshold two',()=>{
  const source=readFileSync(recoverableSafeControlsScript,'utf8');
  for(const forbidden of [
    'PRIVATE KEY','MNEMONIC','--private-key','--mnemonic','eth_sendRawTransaction','cast send',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/prepareRecoverableSafeControlDeployments/);
  assert.match(source,/USDOM_SAFE_OWNER_IDENTITIES/);
  assert.match(source,/readDirectFile\(ownerIdentityPath/);
  assert.match(source,/Safe deployment inputs changed during preparation/);
  assert.match(source,/readRuntimeSecretJsonFile\('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES'/);
  assert.match(source,/BoundedMainnetPreflightProvider/);
});

test('recoverable Safe collectors are read-only and bind the finalized recovery transition',()=>{
  for(const script of [recoverableSafeCollector,recoverableSafeRecoveryCollector]) {
    const source=readFileSync(script,'utf8');
    for(const forbidden of [
      'PRIVATE KEY','MNEMONIC','--private-key','--mnemonic','eth_sendRawTransaction','cast send',
      'sendTransaction','broadcast',
    ]) assert.equal(source.includes(forbidden),false,`${script}: ${forbidden}`);
    assert.match(source,script===recoverableSafeCollector
      ?/readDirectFile\(packagePath/
      :/strictFile\(process\.env\.USDOM_SAFE_PACKAGE/);
  assert.match(source,/readRuntimeSecretJsonFile\('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES'/);
    assert.match(source,/matchMainnetPreflightRpcSources/);
    assert.match(source,script===recoverableSafeCollector
      ?/collectRecoverableSafeControlSnapshotConsensus/
      :/collectRecoverableSafeControlRecoveryConsensus/);
    assert.match(source,/USDOM_SAFE_PACKAGE/);
  }
  const recovery=readFileSync(recoverableSafeRecoveryCollector,'utf8');
  assert.match(recovery,/USDOM_SAFE_BASELINE/);
  assert.match(recovery,/USDOM_SAFE_RECOVERY_PLAN/);
  assert.match(recovery,/validateRecoverableSafeRecoveryPlan/);
  assert.doesNotMatch(recovery,/USDOM_SAFE_LOST_OWNER/);
  assert.doesNotMatch(recovery,/USDOM_SAFE_REPLACEMENT_OWNER/);
  assert.match(recovery,/USDOM_CONTROL_EVIDENCE_DIRECTORY/);
  assert.match(recovery,/\$\{role\}-finalized-execution\.json/);
  assert.doesNotMatch(recovery,/USDOM_GOVERNANCE_RECOVERY_TX/);
  assert.doesNotMatch(recovery,/USDOM_RESERVE_GUARDIAN_RECOVERY_TX/);
  assert.doesNotMatch(recovery,/USDOM_CHECKPOINT_GUARDIAN_RECOVERY_TX/);
});

test('Safe recovery planning and OneKey iOS EIP-712 handoff cannot transmit a transaction',()=>{
  for(const script of [recoverableSafeRecoveryPlanner,recoverableSafeRecoveryAssembler]) {
    const source=readFileSync(script,'utf8');
    for(const forbidden of [
      'PRIVATE KEY','MNEMONIC','--private-key','--mnemonic','eth_sendRawTransaction',
      'cast send','sendTransaction',
    ]) assert.equal(source.includes(forbidden),false,`${script}: ${forbidden}`);
  }
  const parsed=spawnSync('bash',['-n',recoverableSafeRecoverySigner],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const signer=readFileSync(recoverableSafeRecoverySigner,'utf8');
  for(const forbidden of [
    'PRIVATE KEY','MNEMONIC','--private-key','--mnemonic','eth_sendRawTransaction','cast send',
  ]) assert.equal(signer.includes(forbidden),false,forbidden);
  assert.match(signer,/\(\(\$# != 0\)\)/);
  assert.match(signer,/ASSINO RECUPERACAO SAFE SEM TRANSMITIR AUTH \$authorization_hash/);
  assert.match(signer,/\[\[ -t 0 && -t 2 \]\]/);
  assert.match(signer,/umask 077/);
  assert.match(signer,/sign-onekey-ios-walletconnect-typed-data\.mjs/);
  assert.match(signer,/prepare-onekey-ios-walletconnect-request\.mjs/);
  assert.match(signer,/read-onekey-ios-walletconnect-signature\.mjs/);
  assert.match(signer,/artifact_prefix="\$signatures_output\.onekey-\$role-\$signer_index"/);
  assert.match(signer,/response="\$artifact_prefix\.response\.json"/);
  assert.doesNotMatch(signer,/--ledger|wallet address|wallet sign/i);
  assert.match(signer,/read-private-file-stdout\.mjs/);
  assert.match(signer,/"\$cmp_bin" -s "\$plan_snapshot"/);
  assert.match(signer,/assert_signing_inputs_unchanged/);
  assert.match(signer,/install-private-file-new-stdin\.mjs/);
  assert.doesNotMatch(signer,/install-private-file-stdin\.mjs/);
  assert.match(signer,/assemble-recoverable-safe-recovery\.mjs/);
  assert.match(signer,/check-recoverable-safe-recovery-plan\.mjs/);
  assert.match(signer,/prepare-recoverable-safe-recovery\.mjs/);
  assert.match(signer,/reobserve_safe_recovery_network\(\)/);
  assert.match(signer,/"\$cmp_bin" -s "\$normalized_plan" "\$normalized_rebuilt"/);
  assert.doesNotMatch(signer,/\$\{USDOM_SAFE_LOST_OWNER:\?/);
  assert.doesNotMatch(signer,/\$\{USDOM_SAFE_REPLACEMENT_OWNER:\?/);
  assert.match(signer,/\.transitionsByRole/);
  assert.match(signer,/\.roles\[\]\|select\(\.role==\$role\)\|\.requiredSigners\[\$index\]/);
  assert.ok(signer.lastIndexOf('reobserve_safe_recovery_network')
    < signer.indexOf('scripts/sign-onekey-ios-walletconnect-typed-data.mjs'));
  assert.match(signer,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
  assert.doesNotMatch(signer,/ETHEREUM_RPC_URL_2/);
});

test('Safe recovery executor journals before publish and requires exact authorization',()=>{
  const parsed=spawnSync('bash',['-n',recoverableSafeRecoveryExecutor],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(recoverableSafeRecoveryExecutor,'utf8');
  for(const forbidden of ['PRIVATE KEY','MNEMONIC','--private-key','--mnemonic']) {
    assert.equal(source.includes(forbidden),false,forbidden);
  }
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.doesNotMatch(source,/\$\{USDOM_SAFE_LOST_OWNER:\?/);
  assert.doesNotMatch(source,/\$\{USDOM_SAFE_REPLACEMENT_OWNER:\?/);
  assert.doesNotMatch(source,/\$\{USDOM_SAFE_RELAYER_OWNER:\?/);
  assert.match(source,/USDOM_SAFE_RELAYER_OWNER=\$\(run_bounded_ledger_address "\$role-initial"\)/);
  assert.match(source,/\.requiredSigners[\s\S]*any\(\(ascii_downcase\) == \(\$owner \| ascii_downcase\)\)/);
  assert.match(source,/AUTORIZO ASSINAR SWAPOWNER \$role ENVELOPE \$envelope_hash/);
  assert.match(source,/\[\[ ! -t 0 \|\| ! -t 1 \]\]/);
  assert.match(source,/Safe recovery authorization requires an interactive terminal/);
  const redirected=spawnSync('bash',[recoverableSafeRecoveryExecutor],{
    cwd:path.dirname(path.dirname(recoverableSafeRecoveryExecutor)),encoding:'utf8',
    stdio:['pipe','pipe','pipe'],
  });
  assert.equal(redirected.status,1);
  assert.match(redirected.stderr,/authorization requires an interactive terminal/);
  assert.match(source,/assert_flock_unchanged[\s\S]*"\$flock_bin" -n 9/);
  assert.doesNotMatch(source,/(?:^|\n)\s*flock -n 9/m);
  assert.match(source,/prepare-safe-recovery-private-input\.mjs/);
  assert.match(source,/prepare-ledger-eip1559-transaction\.mjs/);
  assert.match(source,/wallet sign --no-hash "\$signing_hash" --ledger/);
  assert.doesNotMatch(source,/rpc mktx "\$to" "\$data"/);
  assert.match(source,/persist_private_new "\$raw_draft" "\$raw_file"/);
  assert.match(source,/install-private-file-new-stdin\.mjs/);
  assert.match(source,/install-private-file-new-stdin\.mjs/);
  assert.doesNotMatch(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/assert_sources_unchanged/);
  assert.match(source,/assert_private_snapshot_unchanged/);
  assert.match(source,/persist_private_create_once_or_identical/);
  assert.match(source,/assert_cmp_unchanged; "\$cmp_bin" -s "\$source" "\$recorded"/);
  assert.doesNotMatch(source,/(?:^|\n)\s*cmp -s/m);
  assert.match(source,/envelope_snapshot=/);
  assert.match(source,/raw_snapshot=/);
  assert.match(source,/hash_snapshot=/);
  assert.match(source,/prepare-recoverable-safe-recovery-envelope\.mjs/);
  assert.match(source,/recovery-envelope\.presign\.json/);
  assert.ok(source.indexOf('test "$authorization" = "AUTORIZO ASSINAR SWAPOWNER $role ENVELOPE $envelope_hash"')
    < source.indexOf('recovery-envelope.presign.json'));
  assert.ok(source.indexOf('recovery-envelope.presign.json')
    < source.lastIndexOf('run_bounded_ledger_address "$role-presign"'));
  assert.match(source,/check-recoverable-safe-recovery-envelope\.mjs/);
  assert.match(source,/check-recoverable-safe-recovery-raw-transaction\.mjs/);
  const rawValidator=readFileSync(new URL('../../scripts/check-recoverable-safe-recovery-raw-transaction.mjs',
    import.meta.url),'utf8');
  assert.match(rawValidator,/role:envelopePlan\.role/);
  assert.match(rawValidator,/relayerOwner:envelopePlan\.relayerOwner/);
  assert.match(rawValidator,/new TextDecoder\('utf-8',\{fatal:true\}\)/);
  assert.doesNotMatch(rawValidator,/process\.env\.USDOM_SAFE_RECOVERY_ROLE/);
  assert.doesNotMatch(rawValidator,/process\.env\.USDOM_SAFE_RELAYER_OWNER/);
  assert.match(source,/prepare-ledger-eip1559-transaction\.mjs[\s\S]*"\$nonce" "\$gas_limit" \\\n+        "\$max_fee_per_gas" "\$max_priority_fee_per_gas"/);
  assert.match(source,/wallet sign --no-hash "\$signing_hash" --ledger/);
  assert.match(source,/publish-private-raw-transaction\.mjs "\$raw_snapshot"/);
  assert.match(source,/check-private-strict-json-file\.mjs "\$seen_file"/);
  assert.doesNotMatch(source,/seen=\$\(rpc rpc eth_getTransactionByHash/);
  assert.doesNotMatch(source,/jq[^\n]*<<<"\$seen"/);
  assert.match(source,/eth_getTransactionByHash[^\n]*\\\n\s*> "\$seen_file"/);
  assert.ok(source.indexOf('persist_private_new "$raw_draft" "$raw_file"')
    < source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
  assert.ok(source.lastIndexOf('assert_private_snapshot_unchanged "$raw_file"')
    < source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
  assert.equal(source.includes(
    '$USDOM_CONTROL_EVIDENCE_DIRECTORY/governance-finalized-execution.json'),false);
  assert.equal(source.trimEnd().endsWith(`final_summary=$(<"$final_summary_file")
printf '%s\\n' "$final_summary"`),true);
  assert.match(source,/observe-recoverable-safe-recovery-execution\.mjs/);
  const executionObserver=readFileSync(new URL(
    '../../scripts/observe-recoverable-safe-recovery-execution.mjs',import.meta.url),'utf8');
  assert.match(executionObserver,/validateRecoverableSafeRecoveryEnvelope/);
  assert.match(executionObserver,/role:envelopeInput\.value\.role/);
  assert.doesNotMatch(executionObserver,/process\.env\.USDOM_SAFE_RECOVERY_ROLE/);
  assert.match(source,/check-recoverable-safe-recovery-target\.mjs/);
  assert.match(source,/target-consensus\.prepublish\.json/);
  assert.match(source,/del\(\.finalizedBlockNumber,\.finalizedBlockHash\)/);
  assert.match(source,/target-consensus\.prepublish\.state\.json/);
  const targetReobservation=source.indexOf('target-consensus.prepublish.json');
  const recoveryPublish=source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"');
  assert.ok(targetReobservation>source.indexOf('assert_sources_unchanged',
    source.indexOf('recovery-submission-hash.prepublish.txt')));
  assert.ok(targetReobservation<recoveryPublish);
  const targetPreflight=readFileSync(new URL(
    '../../scripts/check-recoverable-safe-recovery-target.mjs',import.meta.url),'utf8');
  assert.match(targetPreflight,/validateRecoverableSafeRecoveryEnvelope/);
  assert.match(targetPreflight,/role:envelope\.role/);
  assert.doesNotMatch(targetPreflight,/process\.env\.USDOM_SAFE_RECOVERY_ROLE/);
  assert.match(source,/collect-recoverable-safe-recovery\.mjs/);
  assert.match(source,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
  assert.match(source,/serve-private-rpc-catalog-proxy\.mjs/);
  assert.match(source,/rpc_urls\[@\]/);
  assert.match(source,/\[redacted RPC URL\]/);
  assert.doesNotMatch(source,/ETHEREUM_RPC_URL/);
  assert.equal((source.match(/"\$cast_bin" wallet address --ledger/g)??[]).length,1);
  assert.equal((source.match(/run_bounded_ledger_address "\$role-(?:initial|confirm|presign)"/g)??[]).length,3);
  assert.doesNotMatch(source,/persist_private_replace "\$observed_consensus"/);
  assert.doesNotMatch(source,/persist_private_replace "\$final_consensus"/);
});

test('Safe recovery transaction observation rejects identical ambiguous RPC JSON',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-safe-recovery-rpc-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  const response=path.join(temporary,'seen.json');
  const checker=fileURLToPath(new URL(
    '../../scripts/check-private-strict-json-file.mjs',import.meta.url));
  for(const bytes of [
    Buffer.from('{"hash":"0x01","\\u0068ash":"0x02"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    writeFileSync(response,bytes,{mode:0o600});
    for(let attempt=0;attempt<2;attempt+=1) {
      const checked=spawnSync(process.execPath,[checker,response],{encoding:'utf8'});
      assert.notEqual(checked.status,0);
    }
  }
});

test('Safe release-evidence writer is fixed, atomic and has no transaction capability',()=>{
  const parsed=spawnSync('bash',['-n',recoverableSafeReleaseEvidenceWriter],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(recoverableSafeReleaseEvidenceWriter,'utf8');
  for(const forbidden of [
    'PRIVATE KEY','MNEMONIC','--private-key','--mnemonic','cast send','cast publish',
    'eth_sendRawTransaction','ETHEREUM_RPC_URL',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/flock -n 9/);
  assert.match(source,/prepare-recoverable-safe-release-evidence\.mjs/);
  assert.match(source,/check-recoverable-safe-release-evidence\.mjs/);
  assert.match(source,/publish_immutable/);
  assert.match(source,/install-private-file-immutable-stdin\.mjs/);
  assert.match(source,/install-private-file-immutable-stdin\.mjs" --json "\$destination"/);
  assert.equal(source.includes('/install-private-file-stdin.mjs'),false);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/assert_inputs_unchanged/);
  assert.match(source,/safe-control-release-evidence-bundle\.json/);
  assert.match(source,/release-evidence-fragment\.json/);
  assert.ok(source.lastIndexOf('publish_and_verify_immutable "$fragment"')
    > source.lastIndexOf('publish_and_verify_immutable "$bundle"'));
  assert.match(source,/publish_and_verify_immutable/);
  assert.match(source,/verify_supporting_outputs/);
  assert.match(source,/snapshot_private "\$destination" "\$installed"/);
  assert.match(source,/cmp -s "\$source" "\$installed"/);
  assert.match(source,/"\$temporary\/\$file\.rechecked"/);
  assert.ok(source.lastIndexOf('assert_inputs_unchanged')
    < source.lastIndexOf('publish_and_verify_immutable "$fragment"'));
  assert.equal(source.trimEnd().endsWith('"$fragment"'),true);
});

test('Safe source and evidence materializers preserve the two-commit boundary',()=>{
  const pairs=[
    [safeControlReleaseConfigMaterializer,'proof-reserve.unconfigured.json'],
    [safeControlReleaseMetadataMaterializer,'mainnet-release-evidence.unconfigured.json'],
  ];
  for(const [script,expectedTarget] of pairs) {
    const parsed=spawnSync('bash',['-n',script],{encoding:'utf8'});
    assert.equal(parsed.status,0,parsed.stderr);
    const source=readFileSync(script,'utf8');
    for(const forbidden of [
      'PRIVATE KEY','MNEMONIC','--private-key','--mnemonic','cast send','cast publish',
      'eth_sendRawTransaction','ETHEREUM_RPC_URL',
    ]) assert.equal(source.includes(forbidden),false,`${script}: ${forbidden}`);
    assert.match(source,/\(\(\$# != 0\)\)/);
    assert.match(source,/flock -n 9/);
    assert.match(source,/sync -f/);
    assert.match(source,/replace-locked-source-stdin\.mjs/);
    assert.match(source,new RegExp(expectedTarget.replaceAll('.','\\.')));
  }
  const sourceMaterializer=readFileSync(safeControlReleaseConfigMaterializer,'utf8');
  const evidenceMaterializer=readFileSync(safeControlReleaseMetadataMaterializer,'utf8');
  assert.equal(sourceMaterializer.includes('mainnet-release-evidence.unconfigured.json'),false);
  assert.match(evidenceMaterializer,
    /git -C "\$repository" diff --quiet HEAD --[\s\S]*proof-reserve\.unconfigured\.json/);
  assert.equal(/target=.*proof-reserve\.unconfigured\.json/.test(evidenceMaterializer),false);
  assert.equal(evidenceMaterializer.includes(
    'prepare-safe-control-release-config-materialization.mjs'),false);
  for(const forbidden of ['git commit','git tag','git push','git add']) {
    assert.equal(evidenceMaterializer.includes(forbidden),false,forbidden);
  }
  assert.match(sourceMaterializer,/productionReady == false/);
  assert.match(sourceMaterializer,/realFundsAuthorized == false/);
});

test('release provenance materializer authenticates source and cannot publish',()=>{
  const parsed=spawnSync('bash',['-n',releaseProvenanceMaterializer],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(releaseProvenanceMaterializer,'utf8');
  for(const forbidden of [
    'PRIVATE KEY','MNEMONIC','--private-key','--mnemonic','cast send','cast publish',
    'eth_sendRawTransaction','ETHEREUM_RPC_URL','git add','git commit','git tag','git push',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/git -C "\$repository" diff --cached --quiet HEAD/);
  assert.match(source,/scripts\/verify-import\.py/);
  assert.match(source,/scripts\/source-manifest\.py/);
  assert.match(source,/flock -n 9/);
  assert.match(source,/mainnet-release-evidence\.unconfigured\.json/);
  assert.match(source,/operator-intent\.json/);
  assert.match(source,/prepare-release-provenance-materialization\.mjs/);
  assert.match(source,/replace-locked-source-stdin\.mjs/);
  assert.match(source,/replace-locked-private-stdin\.mjs/);
  assert.match(source,/read-release-config-file-stdout\.mjs/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/assert_targets_unchanged/);
  assert.match(source,/cmp -s "\$evidence_temporary" "\$evidence_observed"/);
  assert.match(source,/cmp -s "\$intent_snapshot" "\$intent_observed"/);
  assert.match(source,/cmp -s "\$intent_temporary" "\$intent_observed"/);
});

test('release source ceremony signs locally and has no remote capability',()=>{
  const parsed=spawnSync('bash',['-n',releaseSourceCommitScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(releaseSourceCommitScript,'utf8');
  const boundary=readFileSync(releaseGitBoundaryScript,'utf8');
  for(const forbidden of [
    'git push','git fetch','git pull','git remote','curl ','wget ',
    'ETHEREUM_RPC_URL','eth_sendRawTransaction','cast send','cast publish',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/npm test/);
  assert.match(source,/npm run check:provenance/);
  assert.match(source,/gpg\.ssh\.program=\$ssh_keygen_bin/);
  assert.match(source,/commit-tree -S -p "\$before" -m "USDOM \$source_tag immutable source" "\$staged_tree"/);
  assert.match(source,/update-ref HEAD "\$created" "\$before"/);
  assert.match(source,/verify-commit --raw HEAD/);
  assert.match(source,/diff --check HEAD\^ HEAD/);
  assert.match(source,/rollback_release_index_and_head "\$created" "\$before"/);
  assert.match(source,/read-tree --reset "\$before"/);
  assert.doesNotMatch(source,/reset --mixed/);
  assert.match(boundary,/update-ref HEAD "\$restored_head" "\$expected_head"/);
  assert.match(source,/\(top,exclude\).*evidence\/\*\*/);
  assert.match(source,/CONTINUATION-STATE\.md/);
  assert.match(source,/\[\[ ! -t 0 \|\| ! -t 2 \]\]/);
  assert.match(source,/ASSINO COMMIT DE FONTE USDOM/);
  assert.match(source,/authorization_state=\$\("\$git_bin"/);
  assert.match(source,/status --porcelain=v1 --untracked-files=all/);
  const redirected=spawnSync('bash',[releaseSourceCommitScript],{
    encoding:'utf8',stdio:['pipe','pipe','pipe'],
  });
  assert.equal(redirected.status,1);
  assert.match(redirected.stderr,/requires an interactive terminal/);
});

test('release evidence ceremony gates, signs, tags and cannot publish',()=>{
  const parsed=spawnSync('bash',['-n',releaseEvidenceCommitScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(releaseEvidenceCommitScript,'utf8');
  const boundary=readFileSync(releaseGitBoundaryScript,'utf8');
  for(const forbidden of [
    'git push','git fetch','git pull','git remote','curl ','wget ',
    'eth_sendRawTransaction','cast send','cast publish',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/npm run check:provenance/);
  assert.match(source,/commit-tree -S -p "\$source_commit"/);
  assert.match(source,/update-ref HEAD "\$evidence_commit" "\$source_commit"/);
  assert.match(source,/gpg\.ssh\.program=\$ssh_keygen_bin/);
  assert.match(source,/tag -s -a/);
  assert.match(source,/verify-commit --raw/);
  assert.match(source,/verify-tag --raw/);
  assert.match(source,/check-mainnet-readiness\.mjs closed-mainnet/);
  assert.match(source,/check-mainnet-readiness\.mjs real-funds/);
  assert.match(source,/rollback_release_index_and_head "\$evidence_commit" "\$source_commit"/);
  assert.match(source,/read-tree --reset "\$source_commit"/);
  assert.match(source,/update-ref -d "refs\/tags\/\$source_tag" "\$tag_object"/);
  assert.doesNotMatch(source,/reset --mixed|tag -d/);
  assert.match(boundary,/update-ref HEAD "\$restored_head" "\$expected_head"/);
  assert.match(source,/\[\[ ! -t 0 \|\| ! -t 2 \]\]/);
  assert.match(source,/ASSINO EVIDENCIA E TAG USDOM/);
  assert.match(source,/authorization_state=\$\("\$git_bin"/);
  assert.match(source,/status --porcelain=v1 --untracked-files=all/);
  const redirected=spawnSync('bash',[releaseEvidenceCommitScript],{
    encoding:'utf8',stdio:['pipe','pipe','pipe'],
  });
  assert.equal(redirected.status,1);
  assert.match(redirected.stderr,/requires an interactive terminal/);
});

test('release authorization writers are fixed, finalized and cannot transmit',()=>{
  const scripts=[residualRiskWriter,releaseAuthorizationRequestWriter,
    releaseAuthorizationMaterializer,nativeAttestationRequestWriter,nativeAttestationMaterializer];
  for(const script of scripts) {
    const parsed=spawnSync('bash',['-n',script],{encoding:'utf8'});
    assert.equal(parsed.status,0,parsed.stderr);
    const source=readFileSync(script,'utf8');
    for(const forbidden of ['git push','git commit','git tag','eth_sendRawTransaction','cast send',
      'cast publish','--private-key','--mnemonic']) assert.equal(source.includes(forbidden),false,
      `${path.basename(script)}: ${forbidden}`);
    assert.match(source,/\(\(\$# != 0\)\)/);
    assert.match(source,/flock -n/);
    assert.match(source,/install-private-file-immutable-stdin\.mjs/);
  }
  assert.match(readFileSync(residualRiskWriter,'utf8'),/residual-risk-acceptance-report\.json/);
  assert.match(readFileSync(residualRiskWriter,'utf8'),/replace-locked-source-stdin\.mjs/);
  assert.match(readFileSync(residualRiskWriter,'utf8'),/read-release-config-file-stdout\.mjs/);
  assert.match(readFileSync(residualRiskWriter,'utf8'),/cmp -s "\$metadata_snapshot"/);
  assert.match(readFileSync(releaseAuthorizationRequestWriter,'utf8'),/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
  assert.match(readFileSync(releaseAuthorizationRequestWriter,'utf8'),
    /install-private-file-immutable-stdin\.mjs" --json "\$target"/);
  assert.match(readFileSync(nativeAttestationRequestWriter,'utf8'),
    /install-private-file-immutable-stdin\.mjs" --json "\$target"/);
  assert.match(readFileSync(releaseAuthorizationMaterializer,'utf8'),
    /release-authorization-signature\.hex/);
  assert.match(readFileSync(releaseAuthorizationMaterializer,'utf8'),/assert_inputs_unchanged/);
  assert.match(readFileSync(releaseAuthorizationMaterializer,'utf8'),
    /read-release-config-file-stdout\.mjs/);
  assert.match(readFileSync(releaseAuthorizationMaterializer,'utf8'),
    /safe-control-release-evidence-bundle\.json/);
  assert.match(readFileSync(releaseAuthorizationMaterializer,'utf8'),
    /safe_bundle_snapshot/);
  const releaseAuthorizationMaterializerSource=readFileSync(
    releaseAuthorizationMaterializer,'utf8');
  assert.ok((releaseAuthorizationMaterializerSource.match(/assert_inputs_unchanged/g) ?? [])
    .length>=5);
  assert.match(releaseAuthorizationMaterializerSource,
    /release-authorization\.installed\.json/);
  assert.match(releaseAuthorizationMaterializerSource,
    /release-authorization\.rechecked\.json/);
  assert.match(releaseAuthorizationMaterializerSource,
    /release-authorization-finalized-observation\.installed\.json/);
  assert.match(releaseAuthorizationMaterializerSource,/envelope\.prepublish\.json/);
  assert.match(releaseAuthorizationMaterializerSource,
    /\.observation\.approvals\.releaseAuthorization\.valid == true/);
  assert.ok(releaseAuthorizationMaterializerSource.indexOf('envelope.prepublish.json')
    < releaseAuthorizationMaterializerSource.indexOf(
      'publish_immutable "$authorization"'));
  assert.match(releaseAuthorizationMaterializerSource,
    /cmp -s "\$authorization" "\$temporary\/release-authorization\.rechecked\.json"/);
  assert.match(releaseAuthorizationMaterializerSource,
    /cmp -s "\$observation"[\s\\]*"\$temporary\/release-authorization-finalized-observation\.installed\.json"/);
  assert.match(readFileSync(nativeAttestationMaterializer,'utf8'),
    /signatures=\(native-privacy-trusted-setup native-scheduled-runtime-activation native-wallet-custody native-wallet-recovery\)/);
  assert.match(readFileSync(nativeAttestationMaterializer,'utf8'),/replace-locked-source-stdin\.mjs/);
  assert.match(readFileSync(nativeAttestationMaterializer,'utf8'),/assert_inputs_unchanged/);
  assert.match(readFileSync(nativeAttestationMaterializer,'utf8'),
    /read-release-config-file-stdout\.mjs/);
  assert.match(readFileSync(nativeAttestationMaterializer,'utf8'),
    /safe-control-release-evidence-bundle\.json/);
  const nativeAttestationMaterializerSource=readFileSync(nativeAttestationMaterializer,'utf8');
  assert.match(nativeAttestationMaterializerSource,/publish_and_verify_immutable/);
  assert.match(nativeAttestationMaterializerSource,/verify_published_outputs/);
  assert.match(nativeAttestationMaterializerSource,
    /snapshot_private "\$destination" "\$installed"/);
  assert.match(nativeAttestationMaterializerSource,/cmp -s "\$source" "\$installed"/);
  assert.match(nativeAttestationMaterializerSource,
    /native-attestation-finalized-observation\.rechecked\.json/);
  assert.match(nativeAttestationMaterializerSource,/envelope\.prepublish\.json/);
  assert.match(nativeAttestationMaterializerSource,
    /attestations\.prepublish\.signed\.json/);
  assert.ok(nativeAttestationMaterializerSource.indexOf('envelope.prepublish.json')
    < nativeAttestationMaterializerSource.indexOf(
      'publish_and_verify_immutable "$temporary/$file"'));
  assert.ok((nativeAttestationMaterializerSource.match(/assert_inputs_unchanged/g) ?? [])
    .length>=6);
  assert.equal((readFileSync(nativeAttestationMaterializer,'utf8').match(
    /check-native-release-attestation-signing-request\.mjs/g) ?? []).length,2);
});

test('release authorization signer uses two Safe hardware owners and never broadcasts',()=>{
  for(const script of [releaseAuthorizationSigner,nativeAuthorizationSigner,
    productionAuthorizationSigner]) {
    const parsed=spawnSync('bash',['-n',script],{encoding:'utf8'});
    assert.equal(parsed.status,0,parsed.stderr);
  }
  const source=readFileSync(releaseAuthorizationSigner,'utf8');
  for(const forbidden of ['git push','eth_sendRawTransaction','cast send','cast publish',
    '--private-key','--mnemonic']) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\.roleReports\.governance\.threshold/);
  assert.match(source,/\.roleReports\.governance\.ownersAfter \| map\(ascii_downcase\) \| sort \| \.\[\]/);
  assert.match(source,/test "\$\{owners\[0\]\}" '<' "\$\{owners\[1\]\}"/);
  assert.match(source,/test "\$\{owners\[1\]\}" '<' "\$\{owners\[2\]\}"/);
  assert.match(source,/for index in 0 1/);
  assert.match(source,/"\$cast_bin" wallet sign --no-hash/);
  assert.match(source,/"\$cast_bin" wallet verify --address/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/install-private-file-new-stdin\.mjs/);
  assert.doesNotMatch(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/assert_release_signing_inputs_unchanged/);
  assert.match(source,/check-release-signing-network\.mjs/);
  assert.ok(source.indexOf('check-release-signing-network.mjs')
    < source.indexOf('"$cast_bin" wallet sign --no-hash'));
  assert.match(source,/"\$cmp_bin" -s "\$request_snapshot"/);
  assert.match(source,/check-release-authorization-signing-request\.mjs/);
  assert.match(source,/proof-reserve\.unconfigured\.json/);
  assert.match(source,/mainnet-release-evidence\.unconfigured\.json/);
  assert.equal((source.match(/check-release-authorization-signing-request\.mjs/g) ?? []).length,2);
  assert.equal((source.match(/check-native-release-attestation-signing-request\.mjs/g) ?? []).length,2);
  assert.match(source,/AUTORIZO RELEASE USDOM COM FUNDOS REAIS/);
  assert.match(readFileSync(nativeAuthorizationSigner,'utf8'),
    /sign-release-authorizations\.sh native/);
  assert.match(readFileSync(productionAuthorizationSigner,'utf8'),
    /sign-release-authorizations\.sh release/);
});

test('finalized-deposit collector keeps RPC URLs in memory and has no transaction capability',()=>{
  const parsed=spawnSync('bash',['-n',finalizedDepositCollector],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedDepositCollector,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','--private-key','--mnemonic','cast send','tee ',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.doesNotMatch(source,/Finalized-deposit source JSON/);
  assert.match(source,/while IFS= read -r operator_id/);
  assert.match(source,/read -r -s -p "Secret execution RPC URL for \$operator_id: " execution_url/);
  assert.match(source,/read -r -s -p "Secret Beacon RPC URL for \$operator_id: " beacon_url/);
  assert.match(source,/pin_runtime_tool jq[\s\S]*run_pinned_jq\(\) \{ assert_runtime_tool jq; "\$jq_bin" "\$@"; \}/);
  assert.equal((source.match(/run_pinned_jq /g)??[]).length,2);
  assert.match(source,/done < <\(run_pinned_jq -er '\.sources\[\]\.operatorId' "\$catalog"\)/);
  assert.match(source,/unset execution_url beacon_url/);
  assert.match(source,/printf '%s' "\$USDOM_FINALIZED_DEPOSIT_SOURCES"/);
  assert.match(source,/\| run_pinned_timeout[\s\S]*node scripts\/collect-finalized-deposit-source\.mjs/);
  assert.doesNotMatch(source,/export USDOM_FINALIZED_DEPOSIT_SOURCES/);
  const implementation=readFileSync(finalizedDepositCollectorImplementation,'utf8');
  assert.doesNotMatch(implementation,/process\.env\.USDOM_FINALIZED_DEPOSIT_SOURCES/);
  assert.match(implementation,/await boundedStdin\(64\*1024\)/);
  assert.match(implementation,/runtimeSourceBytes\.fill\(0\)/);
  assert.match(implementation,/matchFinalizedDepositSourceCatalog/);
  assert.match(implementation,/reconcileFinalizedDepositObservations/);
  assert.match(implementation,/catalogReread\.equals\(catalogBytes\)/);
});

test('credential-bearing operational entrypoints disable trace, backtraces and core dumps',()=>{
  const scripts=[
    closedMainnetTpmBootstrapScript,finalizedDepositCollector,
    closedMainnetWalletRecoveryScript,finalizedDepositObservation,
    closedMainnetPrivateBurnScript,nativeReceivingWalletScript,
    closedMainnetTpmKeystoreScript,finalizedDepositWalletRegistration,
    closedMainnetNodeScript,closedMainnetPrivateBurnSubmitScript,
  ];
  for(const script of scripts) {
    const source=readFileSync(script,'utf8');
    assert.match(source,/set \+x/);
    assert.match(source,/unset BASH_XTRACEFD/);
    assert.match(source,/export RUST_BACKTRACE=0/);
    assert.match(source,/export RUST_LIB_BACKTRACE=0/);
    assert.match(source,/ulimit -c 0/);
    assert.ok(source.indexOf('set +x') < source.search(/read -r -s|DOM_RPC_BEARER_TOKEN_FILE|--rpc-token-file|--password-file/),
      `${path.basename(script)} enables a secret-bearing action before disabling xtrace`);
  }
  const nodeSource=readFileSync(closedMainnetNodeScript,'utf8');
  assert.match(nodeSource,/export DOM_LOG=info/);
  const tokenSource=readFileSync(rpcTokenSource,'utf8');
  assert.doesNotMatch(tokenSource,/std::env::var\("DOM_RPC_TOKEN"\)/);
  assert.match(tokenSource,/Reusable credentials are deliberately never accepted from the process/);
  for(const sourcePath of [nodeMainSource,walletRescanSource]) {
    const source=readFileSync(sourcePath,'utf8');
    assert.doesNotMatch(source,/std::env::var\("DOM_WALLET_PASSWORD"\)/);
    assert.match(source,/std::env::var_os\("DOM_WALLET_PASSWORD"\)/);
    assert.match(source,/DOM_WALLET_PASSWORD is forbidden/);
    assert.match(source,/DOM_WALLET_PASSWORD_FILE/);
  }
  assert.match(readFileSync(walletRescanSource,'utf8'),/Zeroizing::new/);
  const secretNodeLauncher=readFileSync(fileURLToPath(new URL(
    '../../scripts/run-secret-node-entrypoint.sh',import.meta.url)),'utf8');
  for(const marker of ['set +x','unset BASH_XTRACEFD','ulimit -c 0','umask 077',
    'USDOM_SECRET_NODE_LAUNCHER=1']) assert.match(secretNodeLauncher,new RegExp(marker.replace('+','\\+')));
  const packageScripts=JSON.parse(readFileSync(fileURLToPath(new URL(
    '../../package.json',import.meta.url)),'utf8')).scripts;
  for(const [name,entrypoint] of [
    ['submit:finalized-deposit-issuance','submit-finalized-deposit-issuance.mjs'],
    ['initialize:closed-mainnet-genesis','initialize-closed-mainnet-genesis.mjs'],
    ['mine:closed-mainnet-issuance-block','mine-closed-mainnet-issuance-block.mjs'],
  ]) assert.equal(packageScripts[name],`./scripts/mainnet-tool-dispatcher bash scripts/run-secret-node-entrypoint.sh ${entrypoint}`);
  for(const sourcePath of [finalizedDepositSubmission,closedMainnetGenesisScript,
    closedMainnetIssuanceBlockScript]) {
    const source=readFileSync(sourcePath,'utf8');
    assert.match(source,/USDOM_SECRET_NODE_LAUNCHER/);
    assert.match(source,/for\(const bytes of secretBuffers\) bytes\.fill\(0\)/);
  }
  const bootstrap=readFileSync(fileURLToPath(new URL(
    '../../../../crates/dom-node/src/bin/dom-wallet-bootstrap.rs',import.meta.url)),'utf8');
  assert.match(bootstrap,/Zeroizing::new\(load_owner_only_utf8_secret_file/);
});

test('finalized-deposit witness builder is fixed, local and replays under native policy',()=>{
  const parsed=spawnSync('bash',['-n',finalizedDepositBuilder],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedDepositBuilder,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','cast send','RPC_URL','RISC0_PROVER',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/native-usdom-v2\.manifest\.sha256/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/read-private-file-stdout\.mjs" "\$SOURCE"/);
  assert.match(source,/MANIFEST="\$SNAPSHOT_DIRECTORY\/native-usdom-v2\.json"/);
  assert.doesNotMatch(source,/exec cargo run/);
  assert.match(source,/dom-usdom-build-finalized-deposit-witness/);
  assert.match(source,/--network mainnet/);
  const binary=readFileSync(finalizedDepositBuilderBinary,'utf8');
  assert.match(binary,/PrivateDirectoryAuthority::open\(directory\)\?\.replace_files\(files, &\[INDEX_NAME\]\)/);
  assert.doesNotMatch(binary,/fs::rename\(&temporary/);
});

test('finalized-deposit wallet registration is fixed and cannot submit or mine',()=>{
  const parsed=spawnSync('bash',['-n',finalizedDepositWalletRegistration],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedDepositWalletRegistration,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','cast send','eth_sendRawTransaction',
    '/usdom/v4/issuance/submit/v1','/regtest/mine/v1',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/read -r -s -p 'Native USDOM recovery password: '/);
  assert.match(source,/http:\/\/127\.0\.0\.1:33372\/chain\/identity/);
  assert.match(source,/"\$keystore_binary" unlock/);
  assert.match(source,/--recovery-password-file "\$RECOVERY_PASSWORD_FILE"/);
  assert.match(source,/--state-password-file "\$STATE_PASSWORD_FILE"/);
  assert.match(source,/dom-usdom-register-finalized-deposit/);
  assert.match(source,/fixed_input_commitment/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SECRET_DIRECTORY\/native-usdom-v2\.json"/);
  assert.match(source,/MANIFEST_PIN="\$SECRET_DIRECTORY\/native-usdom-v2\.manifest\.sha256"/);
  assert.match(source,/register_binary_sha256/);
  assert.match(source,/--max-filesize 65536/);
  assert.match(source,/cmp -s "\$NODE_IDENTITY" "\$NODE_IDENTITY_RECHECK"/);
  assert.match(source,/Registered wallet state already exists; refusing replacement/);
  assert.match(source,/Registered wallet state mode is unsafe/);
});

test('finalized-deposit submission uses only fixed loopback authenticated issuance ingress',()=>{
  const source=readFileSync(finalizedDepositSubmission,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','PRIVATE KEY','MNEMONIC','cast send','eth_sendRawTransaction',
    '/regtest/mine/v1','child_process','exec(','spawn(',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/process\.argv\.length!==2/);
  assert.match(source,/hostname:'127\.0\.0\.1',port:33372/);
  assert.match(source,/authorization:`Bearer \$\{token\}`/);
  assert.match(source,/\/usdom\/v4\/issuance\/submit\/v1/);
  assert.match(source,/validateFinalizedDepositIssuance/);
  assert.match(source,/expected-deposit-registration\.json/);
  assert.match(source,/readDirectFile\(file,\{minimum:1,maximum,privateMode:secret/);
  assert.match(source,/writePrivateFileDurableNew\(file,value,\{maximum:1024\*1024\}\)/);
  assert.match(source,/mined:false,broadcastsEthereum:false/);
});

test('closed mainnet node command creates its token and disables mining and discovery',()=>{
  const parsed=spawnSync('bash',['-n',closedMainnetNodeScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(closedMainnetNodeScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','DOM_RPC_TOKEN=',
    'DOM_MINE=true','0.0.0.0:33369',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/secrets\.token_hex\(32\)/);
  assert.match(source,/os\.O_DIRECTORY \| os\.O_NOFOLLOW/);
  assert.match(source,/os\.O_EXCL \| os\.O_NOFOLLOW \| os\.O_CLOEXEC/);
  assert.match(source,/dir_fd=root_fd/);
  assert.match(source,/token_opened\.st_nlink != 1/);
  assert.match(source,/os\.fsync\(root_fd\)/);
  assert.doesNotMatch(source,/grep -Eq|stat -c|wc -l < "\$TOKEN_FILE"/);
  assert.match(source,/DOM_NETWORK=mainnet/);
  assert.match(source,/DOM_P2P_LISTEN_ADDR=127\.0\.0\.1:33369/);
  assert.match(source,/DOM_MIN_OUTBOUND=0/);
  assert.match(source,/DOM_MAX_INBOUND=0/);
  assert.match(source,/DOM_DISABLE_DNS_SEEDS=true/);
  assert.match(source,/DOM_MINE=false/);
  assert.match(source,/DOM_CLOSED_MAINNET_TEST=true/);
  assert.match(source,/DOM_RPC_LISTEN_ADDR=default/);
  assert.match(source,/DOM_USDOM_V4_MANIFEST_SHA256="\$manifest_sha256"/);
});

test('closed mainnet block commands are fixed, loopback-only and exactly bounded',()=>{
  for(const script of [closedMainnetGenesisScript,closedMainnetIssuanceBlockScript]) {
    const source=readFileSync(script,'utf8');
    for(const forbidden of [
      'PLACEHOLDER','SUBSTITUA','PRIVATE KEY','MNEMONIC','eth_sendRawTransaction',
      'DOM_MINE=true','child_process','exec(','spawn(',
    ]) assert.equal(source.includes(forbidden),false,`${path.basename(script)}: ${forbidden}`);
    assert.match(source,/process\.argv\.length!==2/);
    assert.match(source,/hostname:'127\.0\.0\.1',port:33372/);
    assert.match(source,/\/closed-mainnet\/mine-one\/v1/);
    assert.match(source,/authorization:`Bearer \$\{token\}`/);
    assert.match(source,/validateClosedMainnetMineResponse/);
  }
  const genesis=readFileSync(closedMainnetGenesisScript,'utf8');
  assert.match(genesis,/readDirectFile\(file,\{minimum:1,maximum,privateMode:true/);
  const issuance=readFileSync(closedMainnetIssuanceBlockScript,'utf8');
  assert.match(issuance,/readDirectFile\(file,\{minimum:1,maximum,privateMode:secret/);
  for(const source of [genesis,issuance]) {
    assert.match(source,/writePrivateFileDurableNew\(file,value,\{maximum:1024\*1024\}\)/);
    assert.doesNotMatch(source,/rename\(temporary,file\)|open\(temporary,'wx'/);
  }
  assert.match(issuance,/before\.tip_height!==0/);
  assert.match(issuance,/exactlyOneBlock:true,continuousMining:false/);
  assert.match(issuance,/issuanceObserved:false/);
});

test('finalized-deposit observation authenticates history without mining or broadcasting',()=>{
  const parsed=spawnSync('bash',['-n',finalizedDepositObservation],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedDepositObservation,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','eth_sendRawTransaction',
    '/closed-mainnet/mine-one/v1','DOM_MINE=true','cast send',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/read -r -s -p 'Native USDOM recovery password: '/);
  assert.match(source,/http:\/\/127\.0\.0\.1:33372\/chain\/identity/);
  assert.match(source,/"\$keystore_binary" unlock/);
  assert.match(source,/--password-file "\$STATE_PASSWORD_FILE"/);
  assert.match(source,/dom-usdom-observe-finalized-deposit/);
  assert.match(source,/observed-state-v1/);
  assert.match(source,/fixed_input_commitment/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SECRET_DIRECTORY\/native-usdom-v2\.json"/);
  assert.match(source,/MANIFEST_PIN="\$SECRET_DIRECTORY\/native-usdom-v2\.manifest\.sha256"/);
  assert.match(source,/observer_binary_sha256/);
  assert.match(source,/--max-filesize 65536/);
  assert.match(source,/cmp -s "\$IDENTITY_FILE" "\$IDENTITY_RECHECK_FILE"/);
  assert.match(source,/Registered wallet state contains a symbolic link or multiply-linked file/);
  assert.match(source,/Observed wallet state mode is unsafe/);
});

test('closed mainnet private burn is exact, offline, proof-backed and cannot submit',()=>{
  const parsed=spawnSync('bash',['-n',closedMainnetPrivateBurnScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(closedMainnetPrivateBurnScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','--private-key','--mnemonic',
    'cast send','eth_sendRawTransaction','curl ','wget ','/regtest/mine/v1',
    '/usdom/v4/private-burn/submit/v1',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/HOME must be a current-user direct absolute directory/);
  assert.equal((source.match(/read-onekey-ios-hardware-address\.mjs/g)??[]).length,2);
  assert.doesNotMatch(source,/--ledger|Ledger/);
  assert.match(source,/"\$FIRST_RECIPIENT" != "\$SECOND_RECIPIENT"/);
  assert.match(source,/mktemp -d -p \/dev\/shm usdom-private-burn/);
  assert.match(source,/read -r -s -p 'Native USDOM recovery password: '/);
  assert.match(source,/--bin dom-usdom-wallet-tpm-keystore/);
  assert.match(source,/--bin dom-usdom-build-private-burn/);
  assert.match(source,/observed-state-v1/);
  assert.match(source,/spend-proving-key\.sha256/);
  assert.match(source,/prepared-burn-state-v1/);
  assert.match(source,/--password-file "\$STATE_PASSWORD_FILE"/);
  assert.match(source,/--recipient-file "\$RECIPIENT_FILE"/);
  assert.match(source,/fixed_input_commitment/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SECRET_DIRECTORY\/native-usdom-v2\.json"/);
  assert.match(source,/MANIFEST_PIN="\$SECRET_DIRECTORY\/native-usdom-v2\.manifest\.sha256"/);
  assert.match(source,/Observed wallet state contains a symbolic link or multiply-linked file/);
  assert.match(source,/builder_binary_sha256/);
  assert.match(source,/Prepared burn output mode is unsafe/);

  const builder=readFileSync(closedMainnetPrivateBurnBuilder,'utf8');
  for(const forbidden of ['TcpStream','UdpSocket','reqwest','eth_sendRawTransaction']) {
    assert.equal(builder.includes(forbidden),false,forbidden);
  }
  assert.match(builder,/const AMOUNT_BASE_UNITS: u64 = 1_000_000/);
  assert.match(builder,/dac17f958d2ee523a2206206994597c13d831ec7/);
  assert.match(builder,/SpendProver::from_bytes/);
  assert.match(builder,/build_private_burn/);
  assert.match(builder,/WalletState::load_encrypted_snapshot_bytes\(\s*&snapshot_bytes/);
  assert.doesNotMatch(builder,/WalletState::load_encrypted_snapshot\(&snapshot_path/);
  assert.match(builder,/PrivateStagingDirectory::create\(&arguments\.output_directory\)/);
  assert.match(builder,/staging\.publish\(\)/);
  assert.doesNotMatch(builder,/std::fs::rename\(&temporary/);
  assert.match(builder,/validate_redemption_recipient/);
  assert.match(builder,/"exact_value_burn": true/);
  assert.match(builder,/"submission_authorized": false/);
  assert.match(builder,/"submits": false/);
  assert.match(builder,/"mines": false/);
  assert.match(builder,/"broadcasts": false/);

  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-private-burn-command-'));
  try {
    const rejected=spawnSync('bash',[closedMainnetPrivateBurnScript],{
      encoding:'utf8',env:{...process.env,HOME:temporary},input:'must-not-be-read\n',
    });
    assert.notEqual(rejected.status,0);
    assert.equal(rejected.stdout,'');
    assert.equal(existsSync(path.join(temporary,'.local')),false);
  } finally { rmSync(temporary,{recursive:true,force:true}); }
});

test('private state directories publish through one retained parent without replacement',()=>{
  const source=readFileSync(privateStagingDirectory,'utf8');
  assert.match(source,/mkdirat\(/);
  assert.match(source,/Mode::from_raw_mode\(0o700\)/);
  assert.match(source,/OFlags::DIRECTORY \| OFlags::NOFOLLOW \| OFlags::CLOEXEC/);
  assert.match(source,/\/proc\/self\/fd\/\{\}/);
  assert.match(source,/RenameFlags::NOREPLACE/);
  assert.match(source,/expected\.ino\(\) != actual\.ino\(\)/);
  assert.match(source,/fsync\(self\.parent\.as_fd\(\)\)/);
  assert.match(source,/pub struct PrivateDirectoryAuthority/);
  assert.match(source,/pub fn write_child_noclobber/);
  assert.match(source,/pub fn replace_files/);
  assert.match(source,/OFlags::CREATE\s*\| OFlags::EXCL/);
  assert.match(source,/renameat\(/);
  assert.match(source,/actual\.as_slice\(\) != \*expected/);
  assert.match(source,/invalidate_where/);
  assert.doesNotMatch(source,/std::fs::rename\(/);
});

test('closed mainnet TPM wallet keystore requires recovery knowledge and hardware',()=>{
  const parsed=spawnSync('bash',['-n',closedMainnetTpmKeystoreScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(closedMainnetTpmKeystoreScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','--private-key','--mnemonic',
    'cast send','eth_sendRawTransaction','curl ','wget ','DOM_MINE=true',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/\/dev\/tpmrm0/);
  assert.match(source,/\/usr\/bin\/tpm2_nvdefine/);
  assert.match(source,/read -r -s -p 'Native USDOM recovery password: '/);
  assert.match(source,/read -r -s -p 'TPM owner authorization \(press Enter if unset\): '/);
  assert.match(source,/"\$keystore_binary" provision/);
  assert.match(source,/tpm2-keystore-credential\.usdom/);
  assert.match(source,/tpm2-keystore-v1\.json/);
  assert.match(source,/fixed_input_commitment\(\)/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SECRET_DIRECTORY\/native-usdom-v2\.json"/);
  assert.match(source,/MANIFEST_PIN="\$SECRET_DIRECTORY\/native-usdom-v2\.manifest\.sha256"/);
  assert.match(source,/tpm_tool_commitment\(\)/);
  assert.match(source,/keystore_binary_sha256=\$\(sha256sum/);
  assert.match(source,/TPM keystore output already exists; refusing to replace it/);
  assert.match(source,/test ! -e "\$output"; test ! -L "\$output"/);
  assert.match(source,/stat -c '%u:%a:%h'/);

  const binary=readFileSync(closedMainnetTpmKeystoreBinary,'utf8');
  for(const forbidden of ['TcpStream','UdpSocket','reqwest','eth_sendRawTransaction']) {
    assert.equal(binary.includes(forbidden),false,forbidden);
  }
  assert.match(binary,/WalletRecoverySeed::load_encrypted_backup/);
  assert.match(binary,/WalletRecoverySeed::load_encrypted_backup_bytes\(&backup/);
  assert.match(binary,/Tpm2NvAuthorization::load_encrypted_bytes\(/);
  assert.match(binary,/sha256: sha256_hex\(&bytes\)/);
  assert.match(binary,/save_private_bytes_noclobber\(path, bytes\)/);
  assert.match(binary,/Tpm2WalletKeystore::initialize/);
  assert.match(binary,/Tpm2WalletKeystore::open/);
  assert.match(binary,/write_operational_passphrase_create_only/);
  assert.match(binary,/operational_password_exported/);
  assert.match(binary,/ethereum_broadcasts/);
  const keystore=readFileSync(nativeTpmKeystoreLibrary,'utf8');
  assert.match(keystore,/save_private_bytes_noclobber\(path, passphrase\.expose\(\)\.as_bytes\(\)\)/);
  assert.doesNotMatch(keystore,/remove_file\(path\)/);
});

test('closed mainnet wallet recovery ignores old snapshots and ends at a verified checkpoint',()=>{
  const parsed=spawnSync('bash',['-n',closedMainnetWalletRecoveryScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(closedMainnetWalletRecoveryScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','--private-key','--mnemonic',
    'cast send','eth_sendRawTransaction','/regtest/mine/v1','DOM_MINE=true',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/\/dev\/tpmrm0/);
  assert.match(source,/read -r -s -p 'Native USDOM recovery password: '/);
  assert.match(source,/"target\/release\/dom-usdom-wallet-tpm-keystore" "\$keystore_binary_sha256" -- unlock/);
  assert.match(source,/dom-usdom-recover-wallet-at-checkpoint/);
  assert.match(source,/recovery-drill-v1/);
  assert.match(source,/--state-password-file "\$STATE_PASSWORD_FILE"/);
  assert.match(source,/fixed_input_commitment/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SECRET_DIRECTORY\/native-usdom-v2\.json"/);
  assert.match(source,/MANIFEST_PIN="\$SECRET_DIRECTORY\/native-usdom-v2\.manifest\.sha256"/);
  assert.match(source,/recovery_binary_sha256/);
  assert.match(source,/Recovery-drill output mode is unsafe/);

  const binary=readFileSync(closedMainnetWalletRecoveryBinary,'utf8');
  for(const forbidden of ['eth_sendRawTransaction','cast send','/regtest/mine/v1']) {
    assert.equal(binary.includes(forbidden),false,forbidden);
  }
  assert.match(binary,/WalletRecoverySeed::load_encrypted_backup/);
  assert.match(binary,/verify_deposit_witness/);
  assert.match(binary,/verify_checkpoint_witness/);
  assert.match(binary,/VerifiedCheckpointHistoryAnchor::from_verified_checkpoint/);
  assert.match(binary,/recover_historical_deposit_at_verified_checkpoint/);
  assert.match(binary,/"existing_operational_snapshot_read": false/);
  assert.match(binary,/"ethereum_broadcasts": false/);
  assert.match(binary,/"submits": false/);
  assert.match(binary,/"mines": false/);
});

test('closed mainnet TPM bootstrap authenticates all snapshots without network or funds',()=>{
  const parsed=spawnSync('bash',['-n',closedMainnetTpmBootstrapScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(closedMainnetTpmBootstrapScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','--private-key','--mnemonic',
    'cast send','eth_sendRawTransaction','curl ','wget ','/regtest/mine/v1',
    '/usdom/v4/burn/submit/v1','DOM_MINE=true',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/\/dev\/tpmrm0/);
  assert.match(source,/\/usr\/bin\/tpm2_nvdefine/);
  assert.match(source,/read -r -s -p 'Native USDOM recovery password: '/);
  assert.match(source,/read -r -s -p 'TPM owner authorization \(press Enter if unset\): '/);
  assert.match(source,/registered-state-v1/);
  assert.match(source,/observed-state-v1/);
  assert.match(source,/prepared-burn-state-v1/);
  assert.match(source,/dom-usdom-bootstrap-tpm-wallet-authority/);
  assert.match(source,/"\$keystore_binary" unlock/);
  assert.match(source,/--password-file "\$STATE_PASSWORD_FILE"/);
  assert.match(source,/state_tree_commitment\(\)/);
  assert.match(source,/fixed_input_commitment\(\)/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SECRET_DIRECTORY\/native-usdom-v2\.json"/);
  assert.match(source,/MANIFEST_PIN="\$SECRET_DIRECTORY\/native-usdom-v2\.manifest\.sha256"/);
  assert.match(source,/tpm_tool_commitment\(\)/);
  assert.match(source,/bootstrap_binary_sha256=\$\(sha256sum/);
  assert.match(source,/TPM authority output already exists; refusing to replace it/);
  assert.match(source,/test ! -e "\$output"; test ! -L "\$output"/);
  assert.match(source,/stat -c '%u:%a:%h'/);

  const binary=readFileSync(closedMainnetTpmBootstrapBinary,'utf8');
  for(const forbidden of ['TcpStream','UdpSocket','reqwest','eth_sendRawTransaction']) {
    assert.equal(binary.includes(forbidden),false,forbidden);
  }
  assert.match(binary,/validate_snapshot_chain/);
  assert.match(binary,/validate_closed_states/);
  assert.match(binary,/WalletState::load_encrypted_snapshot_bytes\(&snapshot_before/);
  assert.doesNotMatch(binary,/WalletState::load_encrypted_snapshot\(&snapshot_path/);
  assert.match(binary,/Tpm2AuthorityBinding::derive/);
  assert.match(binary,/Tpm2NvSealAuthority::initialize/);
  assert.match(binary,/Tpm2NvAuthorization::load_encrypted_bytes\(/);
  assert.match(binary,/sha256: sha256_hex\(&bytes\)/);
  assert.match(binary,/save_private_bytes_noclobber\(path, bytes\)/);
  assert.match(binary,/"complete_snapshot_chain_authenticated": true/);
  assert.match(binary,/"submission_authorized": false/);
  assert.match(binary,/"submits": false/);
  assert.match(binary,/"mines": false/);
  assert.match(binary,/"ethereum_broadcasts": false/);
});

test('closed mainnet private-burn submission is durable and restricted to authenticated loopback',()=>{
  const parsed=spawnSync('bash',['-n',closedMainnetPrivateBurnSubmitScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(closedMainnetPrivateBurnSubmitScript,'utf8');
  for(const forbidden of [
    'PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','--private-key','--mnemonic',
    'cast send','eth_sendRawTransaction','curl ','wget ','/regtest/mine/v1','DOM_MINE=true',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/\/dev\/tpmrm0/);
  assert.match(source,/read -r -s -p 'Native USDOM recovery password: '/);
  assert.match(source,/tpm2-authority-bootstrap-v1\.json/);
  assert.match(source,/private-burn-submission-v1\.json/);
  assert.match(source,/private-burn-submission-intent-v1\.json/);
  assert.match(source,/install-private-file-immutable-stdin\.mjs" --json "\$SUBMISSION_INTENT"/);
  assert.match(source,/fixed_input_commitment/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SECRET_DIRECTORY\/native-usdom-v2\.json"/);
  assert.match(source,/MANIFEST_PIN="\$SECRET_DIRECTORY\/native-usdom-v2\.manifest\.sha256"/);
  assert.match(source,/submitBinarySha256/);
  assert.match(source,/dom-usdom-submit-private-burn/);
  assert.match(source,/"\$keystore_binary" unlock/);
  assert.match(source,/--password-file "\$STATE_PASSWORD_FILE"/);

  const binary=readFileSync(closedMainnetPrivateBurnSubmitBinary,'utf8');
  for(const forbidden of ['TcpStream','UdpSocket','eth_sendRawTransaction','cast send']) {
    assert.equal(binary.includes(forbidden),false,forbidden);
  }
  assert.match(binary,/const LOOPBACK_RPC: &str = "http:\/\/127\.0\.0\.1:33372\/"/);
  assert.match(binary,/Tpm2NvAuthorization::load_encrypted_bytes\(\s*&credential_bytes/);
  assert.doesNotMatch(binary,/Tpm2NvAuthorization::load_encrypted\(/);
  assert.match(binary,/reconcile_encrypted_snapshot_authority/);
  assert.match(binary,/persist_pending_burn_for_submission/);
  assert.match(binary,/pending_burn_submission_permit/);
  assert.match(binary,/submit_pending_private_burn/);
  assert.match(binary,/save_private_bytes\(path, &seal\.to_bytes\(\)\)/);
  assert.match(binary,/save_private_bytes_noclobber\(path, &bytes\)/);
  assert.doesNotMatch(binary,/std::fs::rename\(&temporary, path\)/);
  assert.match(binary,/"queued"/);
  assert.match(binary,/mines: false/);
  assert.match(binary,/ethereum_broadcasts: false/);
});

test('authenticated RandomX exporter command is fixed and has no field prompts',()=>{
  const parsed=spawnSync('bash',['-n',randomxExportScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(randomxExportScript,'utf8');
  for(const forbidden of ['read -','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC']) {
    assert.equal(source.includes(forbidden),false,forbidden);
  }
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/cargo run --quiet --locked/);
  assert.match(source,/--bin dom-usdom-export-randomx-statement/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/usdom-randomx-statement\.XXXXXX/);
  assert.match(source,/cd "\$SNAPSHOT_ROOT"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.doesNotMatch(source,/cd "\$LAB_ROOT"\s*\ncargo run/);
});

test('canonical checkpoint-source exporter is fixed and has no field prompts',()=>{
  const parsed=spawnSync('bash',['-n',checkpointSourceExportScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointSourceExportScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','--block','--height',
    '--seed','--state','--image-id',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/native-usdom-v2\.manifest\.sha256/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SNAPSHOT_DIRECTORY\/native-usdom-v2\.json"/);
  assert.doesNotMatch(source,/exec cargo run/);
  assert.match(source,/--bin dom-usdom-export-checkpoint-source/);
  assert.match(source,/--network mainnet/);
});

test('canonical checkpoint-source-set exporter is fixed and has no field prompts',()=>{
  const parsed=spawnSync('bash',['-n',checkpointSourceSetExportScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointSourceSetExportScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--block','--height','--seed','--state','--image-id','--interval','--confirmation',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/native-usdom-v2\.manifest\.sha256/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SNAPSHOT_DIRECTORY\/native-usdom-v2\.json"/);
  assert.doesNotMatch(source,/exec cargo run/);
  assert.match(source,/--bin dom-usdom-export-checkpoint-source-set/);
  assert.match(source,/--network mainnet/);
});

test('canonical finalized-burn source exporter is fixed and has no field prompts',()=>{
  const parsed=spawnSync('bash',['-n',finalizedBurnSourceExportScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedBurnSourceExportScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--block','--height','--state','--checkpoint-slot','--burn-id ',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/native-usdom-v2\.manifest\.sha256/);
  assert.match(source,/read-release-config-file-stdout\.mjs" "\$MANIFEST"/);
  assert.match(source,/MANIFEST="\$SNAPSHOT_DIRECTORY\/native-usdom-v2\.json"/);
  assert.doesNotMatch(source,/exec cargo run/);
  assert.match(source,/checkpoint-witness\.bin/);
  assert.match(source,/read-private-file-stdout\.mjs" "\$CHECKPOINT_WITNESS"/);
  assert.match(source,/read-private-file-stdout\.mjs" "\$CHECKPOINT_STATEMENT"/);
  assert.match(source,/read-private-file-stdout\.mjs" "\$BURN_ID"/);
  assert.match(source,/CHECKPOINT_WITNESS="\$SNAPSHOT_DIRECTORY\/checkpoint-witness\.bin"/);
  assert.match(source,/checkpoint-statement-v6\.bin/);
  assert.match(source,/--checkpoint-statement-file/);
  assert.match(source,/burn-id\.hex/);
  assert.match(source,/--bin dom-usdom-export-finalized-burn-source/);
  assert.match(source,/--network mainnet/);
});

test('authenticated RandomX statement-set exporter is fixed and has no prompts',()=>{
  const parsed=spawnSync('bash',['-n',randomxStatementSetExportScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(randomxStatementSetExportScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--index','--segment','--block','--height','--statement',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/checkpoint-source-set-index\.json/);
  assert.match(source,/--bin dom-usdom-export-randomx-statement-set/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/usdom-randomx-statement-set\.XXXXXX/);
  assert.match(source,/--evidence-dir "\$SNAPSHOT_ROOT\/evidence"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.ok(source.indexOf('for name in "${statement_files[@]}"')
    <source.indexOf('"$OUTPUT_DIR/randomx-statement-set-index.json"'));
});

test('authenticated RandomX receipt plan and prover are fixed and secret-free',()=>{
  for(const [script,binary] of [
    [randomxReceiptPlanScript,'dom-usdom-plan-randomx-receipt-set'],
    [randomxReceiptProveScript,'dom-usdom-prove-randomx-receipt-set'],
  ]) {
    const parsed=spawnSync('bash',['-n',script],{encoding:'utf8'});
    assert.equal(parsed.status,0,parsed.stderr);
    const source=readFileSync(script,'utf8');
    for(const forbidden of [
      'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','PRIVATE KEY','MNEMONIC',
      '--index','--segment','--block','--height','--statement','BONSAI_API_KEY=',
    ]) assert.equal(source.includes(forbidden),false,`${path.basename(script)}: ${forbidden}`);
    assert.match(source,/\(\(\$# != 0\)\)/);
    assert.match(source,new RegExp(`--bin ${binary}`));
  }
  const planner=readFileSync(randomxReceiptPlanScript,'utf8');
  assert.match(planner,/read-private-file-stdout\.mjs/);
  assert.match(planner,/usdom-randomx-plan\.XXXXXX/);
  assert.match(planner,/cd "\$SNAPSHOT_LAB"/);
  assert.match(planner,/install-private-file-stdin\.mjs/);
  assert.match(planner,/usdom-randomx\.elf usdom-randomx\.bin usdom-randomx\.iid/);
  const prover=readFileSync(randomxReceiptProveScript,'utf8');
  assert.match(prover,/RISC0_PROVER=local/);
  assert.match(prover,/RISC0_DEV_MODE=0/);
  assert.match(prover,/-u RISC0_SERVER_ADDR/);
  assert.match(prover,/RAYON_NUM_THREADS=1/);
  assert.match(prover,/--release --locked/);
  assert.match(prover,/--features prove/);
  assert.match(prover,/read-private-file-stdout\.mjs/);
  assert.match(prover,/usdom-randomx-prove\.XXXXXX/);
  assert.match(prover,/cd "\$SNAPSHOT_LAB"/);
  assert.match(prover,/install-private-file-stdin\.mjs/);
  for(const tool of ['cargo','cp','jq','node','env']) {
    assert.match(prover,new RegExp(`pin_tool "\\$\\{?${tool}\\}?"|pin_tool "\\$command"`));
    assert.match(prover,new RegExp(`assert_tool_unchanged ${tool}`));
  }
  assert.match(prover,/dom-usdom-plan-randomx-receipt-set/);
  assert.match(prover,/cmp -s "\$reviewed_job_index" "\$snapshot_job_index"/);
  assert.match(prover,/randomx-critical-inputs\.sha256/);
  assert.match(prover,/"\$sha256sum_bin" "\$snapshot_artifacts\/usdom-randomx\.elf"[\s\S]*usdom-randomx\.bin[\s\S]*usdom-randomx\.iid/);
  assert.match(prover,/"\$sha256sum_bin" -c "\$critical_snapshot"[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  assert.doesNotMatch(prover,/(^|[;(]\s*)cargo run/m);
  assert.doesNotMatch(prover,/(^|[|;(]\s*)jq\s/m);
  assert.doesNotMatch(prover,/(^|[|;(]\s*)node\s/m);
  const receiptInstall=prover.indexOf('for record in "${publication_records[@]}"');
  assert.ok(receiptInstall>=0);
  assert.match(prover,/usdom-randomx-receipt-set-v1/);
  assert.match(prover,/receipt_sha256/);
  assert.match(prover,/receipt_bytes/);
  assert.match(prover,/RandomX receipt publication order differs from the reviewed proof jobs/);
  assert.match(prover,/"\$stat_bin" -Lc '%s' "\$OUTPUT_DIR\/\$name"/);
  assert.match(prover,/sha256_file "\$OUTPUT_DIR\/\$name"/);
  assert.match(prover,/install-private-file-stdin\.mjs"[\s\S]{0,80}"\$final_index"[\s\S]*for record in "\$\{publication_records\[@\]\}"/);
  assert.ok(prover.lastIndexOf('for record in "${publication_records[@]}"')>receiptInstall,
    'receipts must be rechecked after the completion index is installed');
});

test('authenticated RandomX aggregate plan and prover are fixed and secret-free',()=>{
  for(const [script,binary] of [
    [randomxAggregatePlanScript,'dom-usdom-plan-randomx-aggregate-set'],
    [randomxAggregateProveScript,'dom-usdom-prove-randomx-aggregate-set'],
  ]) {
    const parsed=spawnSync('bash',['-n',script],{encoding:'utf8'});
    assert.equal(parsed.status,0,parsed.stderr);
    const source=readFileSync(script,'utf8');
    for(const forbidden of [
      'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','PRIVATE KEY','MNEMONIC',
      '--index','--segment','--block','--height','--statement','BONSAI_API_KEY=',
    ]) assert.equal(source.includes(forbidden),false,`${path.basename(script)}: ${forbidden}`);
    assert.match(source,/\(\(\$# != 0\)\)/);
    assert.match(source,/randomx-receipt-set-index\.json/);
    assert.match(source,new RegExp(`--bin ${binary}`));
  }
  const planner=readFileSync(randomxAggregatePlanScript,'utf8');
  assert.match(planner,/--features verify/);
  const prover=readFileSync(randomxAggregateProveScript,'utf8');
  assert.match(prover,/RISC0_PROVER=local/);
  assert.match(prover,/RISC0_DEV_MODE=0/);
  assert.match(prover,/-u RISC0_SERVER_ADDR/);
  assert.match(prover,/RAYON_NUM_THREADS=1/);
  assert.match(prover,/--release --locked/);
  assert.match(prover,/--features prove/);
  assert.match(prover,/usdom-randomx-aggregate-prove\.XXXXXX/);
  assert.match(prover,/assert_tool_unchanged cargo/);
  assert.match(prover,/dom-usdom-plan-randomx-aggregate-set/);
  assert.match(prover,/cmp -s "\$reviewed" evidence\/randomx-aggregate-jobs\/randomx-aggregate-job-index\.json/);
  assert.match(prover,/randomx-aggregate-critical-inputs\.sha256/);
  assert.match(prover,/evidence\/randomx-receipt-set[\s\S]*evidence\/checkpoint-source-set/);
  assert.match(prover,/usdom-randomx-aggregate\.elf usdom-randomx-aggregate\.bin usdom-randomx-aggregate\.iid/);
  assert.match(prover,/"\$sha256sum_bin" -c "\$critical"[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  const receiptInstall=prover.indexOf('for record in "${publication_records[@]}"');
  assert.ok(receiptInstall>=0);
  assert.match(prover,/usdom-randomx-aggregate-receipt-set-v1/);
  assert.match(prover,/receipt_sha256/);
  assert.match(prover,/receipt_bytes/);
  assert.match(prover,/"\$stat_bin" -Lc '%s' "\$OUTPUT_DIR\/\$name"/);
  assert.match(prover,/sha256_file "\$OUTPUT_DIR\/\$name"/);
  assert.match(prover,/install-private-file-stdin\.mjs" "\$final_index"[\s\S]*for record in "\$\{publication_records\[@\]\}"/);
  assert.ok(prover.lastIndexOf('for record in "${publication_records[@]}"')>receiptInstall,
    'aggregate receipts must be rechecked after the completion index is installed');
  assert.doesNotMatch(prover,/(^|[;(]\s*)cargo run/m);
  assert.doesNotMatch(prover,/(^|[|;(]\s*)node\s/m);
});

test('authenticated economic receipt planner is fixed, non-proving and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',economicReceiptPlanScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(economicReceiptPlanScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--index','--segment','--block','--height','BONSAI_API_KEY=','RISC0_PROVER=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/checkpoint-economic-source-set-index\.json/);
  assert.match(source,/--bin dom-usdom-plan-economic-receipt-set/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/usdom-economic-plan\.XXXXXX/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/for guest in chunk block/);
  assert.equal(source.includes('--release'),false);
  assert.equal(source.includes('--features prove'),false);
});

test('authenticated economic receipt prover is fixed, local and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',economicReceiptProveScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(economicReceiptProveScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--index','--segment','--block','--height','BONSAI_API_KEY=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/economic-proof-job-index\.json/);
  assert.match(source,/RISC0_PROVER=local/);
  assert.match(source,/RISC0_DEV_MODE=0/);
  assert.match(source,/-u RISC0_SERVER_ADDR/);
  assert.match(source,/RAYON_NUM_THREADS=1/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features prove/);
  assert.match(source,/--bin dom-usdom-prove-economic-receipt-set/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/usdom-economic-prove\.XXXXXX/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/assert_tool_unchanged cargo/);
  assert.match(source,/dom-usdom-plan-economic-receipt-set/);
  assert.match(source,/cmp -s "\$reviewed_job_index" "\$snapshot_job_index"/);
  assert.match(source,/economic-critical-inputs\.sha256/);
  assert.match(source,/"\$sha256sum_bin" "\$chunk_artifacts"\/\* "\$block_artifacts"\/\*/);
  assert.match(source,/"\$sha256sum_bin" -c "\$critical_snapshot"[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cargo run/m);
  assert.doesNotMatch(source,/(^|[|;(]\s*)node\s/m);
  assert.ok(source.indexOf('for name in "${receipt_files[@]}"')
    <source.lastIndexOf('"$OUTPUT_DIR/economic-receipt-set-index.json"'));
  assert.match(source,/usdom-economic-receipt-set-v1/);
  assert.match(source,/chunk_receipt_count/);
  assert.match(source,/block_receipt_count/);
  assert.match(source,/receipt_sha256/);
  assert.match(source,/receipt_bytes/);
  assert.match(source,/Economic completion index differs from reviewed proof-job order/);
  assert.match(source,/sha256_file "\$final_index"/);
  const firstPublication=source.indexOf('for record in "${publication_records[@]}"');
  assert.ok(firstPublication>=0);
  assert.ok(source.lastIndexOf('for record in "${publication_records[@]}"')>firstPublication,
    'economic receipts must be rechecked after the completion index is installed');
});

test('authenticated checkpoint segment planner is fixed, verify-only and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',checkpointSegmentPlanScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointSegmentPlanScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--index','--segment','--block','--height','BONSAI_API_KEY=','RISC0_PROVER=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/randomx-receipt-set-index\.json/);
  assert.match(source,/economic-receipt-set-index\.json/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features verify/);
  assert.match(source,/--bin dom-usdom-plan-checkpoint-segment-set/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/usdom-segment-plan\.XXXXXX/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/randomx_receipts/);
  assert.match(source,/economic_receipts/);
  assert.equal(source.includes('--features prove'),false);
});

test('authenticated checkpoint segment prover is fixed, local and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',checkpointSegmentProveScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointSegmentProveScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--index','--segment','--block','--height','BONSAI_API_KEY=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/checkpoint-segment-proof-job-index\.json/);
  assert.match(source,/RISC0_PROVER=local/);
  assert.match(source,/RISC0_DEV_MODE=0/);
  assert.match(source,/-u RISC0_SERVER_ADDR/);
  assert.match(source,/RAYON_NUM_THREADS=1/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features prove/);
  assert.match(source,/--bin dom-usdom-prove-checkpoint-segment-set/);
  assert.match(source,/usdom-segment-prove\.XXXXXX/);
  assert.match(source,/read-private-file-stdout\.mjs" "\$JOB_INDEX"/);
  assert.match(source,/length>0 and length<=720/);
  assert.match(source,/length==\(unique\|length\)/);
  assert.match(source,/\^evidence\/checkpoint-source-set\/checkpoint-segment-\[0-9\]\{4\}-transition/);
  assert.match(source,/\^randomx-receipt-\[0-9\]\{4\}/);
  assert.match(source,/\^economic-block-receipt-\[0-9\]\{4\}/);
  assert.match(source,/\^checkpoint-segment-receipt-\[0-9\]\{4\}/);
  assert.match(source,/for logical_path in "\$\{source_files\[@\]\}"/);
  assert.match(source,/for name in "\$\{randomx_receipts\[@\]\}"/);
  assert.match(source,/for name in "\$\{economic_receipts\[@\]\}"/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/rm -- "\$final_index"/);
  assert.match(source,/sync -d "\$OUTPUT_DIR"/);
  assert.match(source,/assert_tool_unchanged cargo/);
  assert.match(source,/dom-usdom-plan-checkpoint-segment-set/);
  assert.match(source,/cmp -s "\$reviewed_job_index" "\$snapshot_jobs\/checkpoint-segment-proof-job-index\.json"/);
  assert.match(source,/checkpoint-segment-critical-inputs\.sha256/);
  assert.match(source,/"\$sha256sum_bin" -c "\$critical"[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cargo run/m);
  assert.doesNotMatch(source,/(^|[|;(]\s*)node\s/m);
  assert.ok(source.indexOf('RISC0_DEV_MODE=0 "$cargo_bin" run')
    <source.indexOf('rm -- "$final_index"'));
  assert.ok(source.indexOf('for name in "${receipt_files[@]}"')
    <source.lastIndexOf('"$OUTPUT_DIR/checkpoint-segment-receipt-set-index.json"'));
  assert.equal(source.slice(source.indexOf('cd "$SNAPSHOT_LAB"')).includes('$SOURCE_DIR/'),false);
});

test('checkpoint segment prover rejects catalog substitution and closes its proof TOCTOU window',()=>{
  const source=readFileSync(checkpointSegmentProveScript,'utf8');
  const snapshot=source.indexOf('read-private-file-stdout.mjs" "$JOB_INDEX"');
  const validation=source.indexOf('"$jq_bin" -e \'',snapshot);
  const proof=source.indexOf('cd "$SNAPSHOT_LAB"',validation);
  const proofEnd=source.indexOf('final_index="$OUTPUT_DIR/',proof);
  const receiptInstall=source.indexOf('for name in "${receipt_files[@]}"',proof);
  const indexInstall=source.lastIndexOf('"$OUTPUT_DIR/checkpoint-segment-receipt-set-index.json"');
  assert.ok(snapshot>=0 && snapshot<validation && validation<proof);
  assert.ok(proof<receiptInstall && receiptInstall<indexInstall);
  assert.match(source,/usdom-checkpoint-segment-receipt-set-v1/);
  assert.match(source,/completion_catalog/);
  assert.match(source,/receipt_sha256/);
  assert.match(source,/receipt_bytes/);
  assert.match(source,/sha256_file "\$final_index"/);
  assert.match(source,/Checkpoint segment receipt changed before completion publication/);
  assert.doesNotMatch(source.slice(proof,proofEnd),
    /\$(SOURCE_DIR|RANDOMX_RECEIPT_DIR|ECONOMIC_RECEIPT_DIR|JOB_INDEX|OUTPUT_DIR)\//);
});

test('authenticated checkpoint outer planner is fixed, verify-only and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',checkpointOuterPlanScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointOuterPlanScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--index','--segment','--block','--height','BONSAI_API_KEY=','RISC0_PROVER=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/checkpoint-segment-proof-job-index\.json/);
  assert.match(source,/checkpoint-segment-receipt-set-index\.json/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features verify/);
  assert.match(source,/--bin dom-usdom-plan-checkpoint-outer/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/usdom-outer-plan\.XXXXXX/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/segment_receipts/);
  assert.match(source,/checkpoint-segment-receipt-/);
  assert.ok(source.indexOf('checkpoint-statement-v6.bin checkpoint-outer-chain.bin checkpoint-outer-proof-job-index.json')
    <source.lastIndexOf('install-private-file-stdin.mjs'));
  assert.equal(source.includes('--features prove'),false);
});

test('checkpoint outer planner snapshots substitution, TOCTOU and receipt catalogs',()=>{
  const source=readFileSync(checkpointOuterPlanScript,'utf8');
  for(const index of [
    'checkpoint-source-set-index.json','randomx-proof-job-index.json',
    'randomx-receipt-set-index.json','economic-proof-job-index.json',
    'economic-receipt-set-index.json','checkpoint-segment-proof-job-index.json',
    'checkpoint-segment-receipt-set-index.json',
  ]) assert.match(source,new RegExp(`capture_private .*${index.replaceAll('.','\\.')}`));
  assert.match(source,/all\(\.\[\]; type == "string" and test\("\^checkpoint-segment-receipt-/);
  assert.match(source,/length == \(unique \| length\)/);
  assert.match(source,/for name in "\$\{segment_receipts\[@\]\}"/);
  assert.match(source,/crates\/dom-usdom-\$\{guest\}-risc0-guest\/elfs/);
  assert.ok(source.indexOf('cd "$SNAPSHOT_LAB"')
    <source.indexOf('--bin dom-usdom-plan-checkpoint-outer'));
  assert.ok(source.indexOf('checkpoint-statement-v6.bin checkpoint-outer-chain.bin checkpoint-outer-proof-job-index.json')
    <source.lastIndexOf('install-private-file-stdin.mjs'));
});

test('checkpoint outer prover validates and publishes its receipt catalog atomically',()=>{
  const source=readFileSync(checkpointOuterProveScript,'utf8');
  const proof=source.indexOf('--bin dom-usdom-prove-checkpoint-outer');
  const catalog=source.indexOf('usdom-checkpoint-outer-receipt-set-v1',proof);
  const receiptInstall=source.lastIndexOf('install-private-file-stdin.mjs" "$OUTPUT_DIR/$completion_receipt"');
  const indexInstall=source.lastIndexOf('install-private-file-stdin.mjs" "$final_index"');
  assert.ok(proof>=0 && proof<catalog && catalog<receiptInstall && receiptInstall<indexInstall);
  assert.match(source,/receipt_sha256/);
  assert.match(source,/receipt_bytes/);
  assert.match(source,/sha256_file "\$final_index"/);
  assert.match(source,/Checkpoint outer receipt changed before completion publication/);
  assert.match(source,/for command in cargo cp jq node env sha256sum stat/);
});

test('authenticated finalized-burn planner is fixed, non-proving and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',finalizedBurnPlanScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedBurnPlanScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    'BONSAI_API_KEY=','RISC0_PROVER=','RISC0_DEV_MODE=','--features prove',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/finalized-burn-input\.bin/);
  assert.match(source,/--release --locked/);
  assert.match(source,/-p dom-usdom-finalized-burn-proof-host/);
  assert.match(source,/--bin dom-usdom-plan-finalized-burn-proof/);
  assert.match(source,/usdom-finalized-burn-plan\.XXXXXX/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/usdom-finalized-burn\.elf/);
  assert.match(source,/usdom-finalized-burn\.iid/);
  assert.match(source,/input_bytes > 67108864/);
  assert.match(source,/program_bytes > 4194304/);
  assert.match(source,/image_id_bytes != 32/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/sync -d "\$OUTPUT_DIR"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.ok(source.indexOf('"$OUTPUT_DIR/finalized-burn-input.bin"')
    <source.lastIndexOf('"$OUTPUT_DIR/finalized-burn-proof-job-index.json"'));
});

test('finalized-burn planner closes source and guest substitution before output-last publication',()=>{
  const source=readFileSync(finalizedBurnPlanScript,'utf8');
  const capture=source.indexOf('> "$snapshot_source/finalized-burn-input.bin"');
  const proof=source.indexOf('cd "$SNAPSHOT_LAB"',capture);
  const invalidate=source.indexOf('for name in finalized-burn-proof-job-index.json',proof);
  const inputInstall=source.lastIndexOf('"$OUTPUT_DIR/finalized-burn-input.bin"');
  const indexInstall=source.lastIndexOf('"$OUTPUT_DIR/finalized-burn-proof-job-index.json"');
  assert.ok(capture>=0 && capture<proof && proof<invalidate);
  assert.ok(invalidate<inputInstall && inputInstall<indexInstall);
  assert.doesNotMatch(source.slice(proof,invalidate),
    /\$(SOURCE_FILE|SOURCE_DIR|ARTIFACT_DIR|OUTPUT_DIR)\//);
});

test('authenticated finalized-burn prover is fixed, local and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',finalizedBurnProveScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedBurnProveScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--input','--statement','--program','BONSAI_API_KEY=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/finalized-burn-input\.bin/);
  assert.match(source,/finalized-burn-proof-job-index\.json/);
  assert.match(source,/checkpoint-outer-receipt\.bin/);
  assert.match(source,/RAYON_NUM_THREADS=1/);
  assert.match(source,/RISC0_PROVER=local/);
  assert.match(source,/RISC0_DEV_MODE=0/);
  assert.match(source,/-u RISC0_SERVER_ADDR/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features prove/);
  assert.match(source,/--bin dom-usdom-prove-finalized-burn/);
  assert.match(source,/usdom-finalized-burn-prove\.XXXXXX/);
  assert.match(source,/finalized-burn-source\/finalized-burn-input\.bin/);
  assert.match(source,/checkpoint-outer-proof-job\/checkpoint-statement-v6\.bin/);
  assert.match(source,/checkpoint-outer-receipt-set\/checkpoint-outer-receipt\.bin/);
  assert.match(source,/usdom-finalized-burn\.elf/);
  assert.match(source,/usdom-finalized-burn\.iid/);
  assert.match(source,/finalized-burn-composite-receipt\.bin/);
  assert.match(source,/source_input_path == "evidence\/finalized-burn-source/);
  assert.match(source,/receipt_file == "finalized-burn-receipt\.bin"/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/rm -- "\$final_index"/);
  assert.match(source,/sync -d "\$OUTPUT_DIR"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/assert_tool_unchanged cargo/);
  assert.match(source,/dom-usdom-plan-finalized-burn-proof/);
  assert.match(source,/"\$cmp_bin" -s "\$reviewed_job_index"/);
  assert.match(source,/finalized-burn-critical-inputs\.sha256/);
  assert.match(source,/checkpoint-outer-receipt\.bin[\s\S]*usdom-finalized-burn\.elf[\s\S]*usdom-finalized-burn\.iid/);
  assert.match(source,/"\$sha256sum_bin" -c "\$critical"[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cargo run/m);
  assert.ok(source.indexOf('install-private-file-stdin.mjs" "$OUTPUT_DIR/$completion_receipt"')
    <source.lastIndexOf('install-private-file-stdin.mjs" "$final_index"'));
});

test('finalized-burn prover binds one replica and publishes its verified completion index last',()=>{
  const source=readFileSync(finalizedBurnProveScript,'utf8');
  const jobCapture=source.indexOf('"$JOB_INDEX" > "$snapshot_jobs/finalized-burn-proof-job-index.json"');
  const catalog=source.indexOf('"$jq_bin" -e --arg input_sha',jobCapture);
  const proof=source.indexOf('cd "$SNAPSHOT_LAB"',catalog);
  const proofEnd=source.indexOf('final_index="$OUTPUT_DIR/',proof);
  const receiptInstall=source.lastIndexOf('install-private-file-stdin.mjs" "$OUTPUT_DIR/$completion_receipt"');
  const indexInstall=source.lastIndexOf('install-private-file-stdin.mjs" "$final_index"');
  assert.ok(jobCapture>=0 && jobCapture<catalog && catalog<proof);
  assert.ok(proofEnd>proof);
  assert.ok(proof<receiptInstall && receiptInstall<indexInstall);
  assert.match(source,/usdom-finalized-burn-receipt-v1/);
  assert.match(source,/receipt_sha256/);
  assert.match(source,/receipt_bytes/);
  assert.match(source,/sha256_file "\$final_index"/);
  assert.match(source,/Finalized-burn receipt changed before completion publication/);
  assert.doesNotMatch(source.slice(proof,proofEnd),
    /\$(SOURCE_INPUT|JOB_INPUT|JOB_INDEX|CHECKPOINT_STATEMENT|CHECKPOINT_OUTER_RECEIPT|ARTIFACT_DIR)\b/);
});

test('finalized-burn proof host supplies the authenticated checkpoint receipt assumption',()=>{
  const source=readFileSync(finalizedBurnProofHostSource,'utf8');
  assert.match(source,/checkpoint-outer-receipt-set\/checkpoint-outer-receipt\.bin/);
  assert.match(source,/execute_with_checkpoint_assumption\(&input\)/);
  assert.match(source,/verify_receipt\([\s\S]*recursive\.image_id\(\)[\s\S]*recursive\.journal\(\)/);
  assert.match(source,/builder\.add_assumption\(checkpoint_receipt\)/);
  assert.match(source,/bf3202187d7c0643204bcb936b34a53b41b871cc4d633781dc96956c7de9d511/);
  assert.match(source,/f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae/);
  assert.equal(source.includes('LEGACY_UNCOMPOSED_IMAGE_ID'),false);
});

test('finalized-burn EVM packager is fixed, local and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',finalizedBurnEvmPackageScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedBurnEvmPackageScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    'BONSAI_API_KEY=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/finalized-burn-receipt-index\.json/);
  assert.match(source,/finalized-burn-receipt\.bin/);
  assert.match(source,/RAYON_NUM_THREADS=1/);
  assert.match(source,/RISC0_PROVER=local/);
  assert.match(source,/RISC0_DEV_MODE=0/);
  assert.match(source,/-u RISC0_SERVER_ADDR/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features prove/);
  assert.match(source,/--bin dom-usdom-package-finalized-burn-evm-proof/);
  assert.match(source,/usdom-finalized-burn-evm\.XXXXXX/);
  assert.match(source,/finalized-burn-proof-job-index\.json/);
  assert.match(source,/usdom-finalized-burn\.elf/);
  assert.match(source,/usdom-finalized-burn\.iid/);
  assert.match(source,/finalized-burn-groth16-receipt\.bin/);
  assert.match(source,/proof_job_index_sha256 == \$job_sha/);
  assert.match(source,/receipt_sha256 == \$receipt_sha/);
  assert.match(source,/program_sha256 == \$program_sha/);
  assert.match(source,/cd "\$SNAPSHOT_LAB"/);
  assert.match(source,/remove_output_file\(\) \{[\s\S]*case \$file in[\s\S]*finalized-burn-evm-proof-index\.json[\s\S]*finalized-burn-groth16-receipt\.bin[\s\S]*finalized-burn-evm-seal\.bin[\s\S]*\*\) return 1/);
  assert.match(source,/remove_output_file\(\) \{[\s\S]*assert_tool_unchanged rm; assert_tool_unchanged timeout[\s\S]*"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$rm_bin" -- "\$file"[\s\S]*\[\[ ! -e \$file && ! -L \$file \]\]/);
  assert.match(source,/remove_output_file "\$final_index"; sync_output_directory/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/assert_tool_unchanged cargo/);
  assert.match(source,/finalized-burn-evm-critical-inputs\.sha256/);
  assert.match(source,/assert_tool_unchanged sha256sum; assert_tool_unchanged timeout[\s\S]*"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$sha256sum_bin" -c "\$critical"[\s\S]*assert_tool_unchanged sha256sum[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cargo run/m);
  assert.ok(source.indexOf('RISC0_DEV_MODE=0 "$cargo_bin" run') < source.indexOf('remove_output_file "$final_index"'));
  assert.ok(source.indexOf('for record in "$groth_name"')
    <source.lastIndexOf('"$final_index"'));
});

test('finalized-burn EVM packager binds one receipt graph and publishes metadata last',()=>{
  const source=readFileSync(finalizedBurnEvmPackageScript,'utf8');
  const capture=source.indexOf('"$RECEIPT_DIR/finalized-burn-receipt-index.json" > "$snapshot_receipts');
  const catalog=source.indexOf('"$jq_bin" -e --arg job_sha',capture);
  const compression=source.indexOf('cd "$SNAPSHOT_LAB"',catalog);
  const compressionEnd=source.indexOf('final_index="$OUTPUT_DIR/',compression);
  const artifacts=source.indexOf('for record in "$groth_name"',compression);
  const completion=source.lastIndexOf('"$final_index"');
  assert.ok(capture>=0 && capture<catalog && catalog<compression);
  assert.ok(compressionEnd>compression);
  assert.ok(compression<artifacts && artifacts<completion);
  assert.doesNotMatch(source.slice(compression,compressionEnd),
    /\$(JOB_DIR|RECEIPT_DIR|ARTIFACT_DIR|OUTPUT_DIR)\//);
  assert.match(source,/usdom-finalized-burn-evm-proof-v1/);
  assert.match(source,/receipt_index_sha256 == \$receipt_index_sha/);
  assert.match(source,/groth16_receipt_sha256/);
  assert.match(source,/evm_seal_sha256/);
  assert.match(source,/sha256_file "\$final_index"/);
  assert.match(source,/Finalized-burn EVM artifact changed before completion publication/);
});

test('finalized-burn submission command is fixed, unsigned and secret-free',()=>{
  const parsed=spawnSync(process.execPath,['--check',finalizedBurnSubmissionScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedBurnSubmissionScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    'sendTransaction','broadcastTransaction','eth_sendRawTransaction','RISC0_PROVER',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/process\.argv\.length!==2/);
  assert.match(source,/finalized-burn-source-index\.json/);
  assert.match(source,/finalized-burn-receipt-index\.json/);
  assert.match(source,/finalized-burn-evm-proof-index\.json/);
  assert.match(source,/finalized-burn-evm-seal\.bin/);
  assert.match(source,/privateInputReplica\(authenticatedInputs\)/);
  assert.match(source,/readDirectFile\(outputPath/);
  assert.match(source,/packageSha256/);
  assert.match(source,/broadcastAuthorized:false/);
});

test('finalized-burn source-to-planner handoff check is fixed, temporary and non-proving',()=>{
  const parsed=spawnSync('bash',['-n',finalizedBurnHandoffScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedBurnHandoffScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    'BONSAI_API_KEY=','RISC0_PROVER=','RISC0_DEV_MODE=','--features prove',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/mktemp -d \/dev\/shm\/usdom-finalized-burn-handoff/);
  assert.match(source,/chmod 0700 -- "\$WORK_ROOT"/);
  assert.match(source,/USDOM_RAW_CHECKPOINT_VECTOR_OUT/);
  assert.match(source,/raw_ethereum_checkpoint_executes_udfinl04_end_to_end/);
  assert.match(source,/dom-usdom-plan-finalized-burn-proof/);
  assert.match(source,/test ! -e .*finalized-burn-receipt\.bin/);
  assert.match(source,/find "\$WORK_ROOT" -depth -delete/);
});

test('finalized-burn prover E2E check is fixed, local, durable and proof-producing',()=>{
  const parsed=spawnSync('bash',['-n',finalizedBurnProverE2eScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(finalizedBurnProverE2eScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','PRIVATE KEY','MNEMONIC',
    'BONSAI_API_KEY=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/mktemp -d \/dev\/shm\/usdom-finalized-burn-proof/);
  assert.match(source,/chmod 0700 -- "\$WORK_ROOT"/);
  assert.match(source,/raw_ethereum_checkpoint_executes_udfinl04_end_to_end/);
  assert.match(source,/RAYON_NUM_THREADS="\$RAYON_WORKERS"/);
  assert.match(source,/ONE_WORKER_MIN_AVAILABLE_KIB=\$\(\(3 \* 1024 \* 1024\)\)/);
  assert.match(source,/TWO_WORKER_MIN_AVAILABLE_KIB=\$\(\(4 \* 1024 \* 1024\)\)/);
  assert.match(source,/current_workers="\$\(select_rayon_workers\)"/);
  assert.match(source,/rayonWorkers:\$rayon_workers/);
  assert.match(source,/finalized-burn-composite-receipt\.bin/);
  assert.match(source,/checkpoint-outer-receipt\.bin/);
  assert.match(source,/required for recursive UDFINL04 proving/);
  assert.match(source,/RISC0_PROVER=local/);
  assert.match(source,/RISC0_DEV_MODE=0/);
  assert.match(source,/--features prove/);
  assert.match(source,/--bin dom-usdom-prove-finalized-burn/);
  assert.match(source,/receipt_verified == true/);
  assert.match(source,/prover-capacity\/finalized-burn/);
  assert.match(source,/ensure_owned_directory/);
  assert.match(source,/must deny group\/other access/);
  assert.match(source,/trap finalize_run EXIT/);
  assert.match(source,/trap 'exit 143' TERM/);
  assert.match(source,/finalized-burn-receipt\.bin/);
  assert.match(source,/copy_artifact/);
  assert.match(source,/write_run_status failed "\$status"/);
  const statusSync=source.indexOf('sync -f "$temporary"',source.indexOf('write_run_status()'));
  const statusRename=source.indexOf('mv -f -- "$temporary" "$RUN_ROOT/run-status.json"');
  const statusDirectorySync=source.indexOf('sync -f "$RUN_ROOT"',statusRename);
  assert.ok(statusSync<statusRename&&statusRename<statusDirectorySync);
  const artifactFunction=source.indexOf('atomic_copy_to()');
  const artifactSync=source.indexOf('sync -f "$temporary"',artifactFunction);
  const artifactRename=source.indexOf('mv -f -- "$temporary" "$destination"',artifactFunction);
  const artifactDirectorySync=source.indexOf('sync -f "$(dirname -- "$destination")"',artifactRename);
  assert.ok(artifactSync<artifactRename&&artifactRename<artifactDirectorySync);
  assert.match(source,/durable_artifact_directory/);
  assert.match(source,/find "\$WORK_ROOT" -depth -delete/);
});

test('finalized-burn prover E2E preserves private diagnostics on pre-proof failure',()=>{
  const home=mkdtempSync(path.join(os.tmpdir(),'usdom-prover-diagnostics-home-'));
  const fakeBin=mkdtempSync(path.join(os.tmpdir(),'usdom-prover-diagnostics-bin-'));
  try {
    const fakeCargo=path.join(fakeBin,'cargo');
    const fakeAwk=path.join(fakeBin,'awk');
    writeFileSync(fakeCargo,'#!/usr/bin/env bash\nexit 42\n',{mode:0o700});
    writeFileSync(fakeAwk,'#!/usr/bin/env bash\nprintf "%s\\n" 8388608\n',{mode:0o700});
    const result=spawnSync('bash',[finalizedBurnProverE2eScript],{
      encoding:'utf8',
      env:{...process.env,HOME:home,PATH:`${fakeBin}:${process.env.PATH}`},
    });
    assert.equal(result.status,1,result.stderr);
    const runs=path.join(home,'.local/share/dom-usdom/prover-capacity/finalized-burn/runs');
    const runNames=readdirSync(runs);
    assert.equal(runNames.length,1);
    const runRoot=path.join(runs,runNames[0]);
    const status=JSON.parse(readFileSync(path.join(runRoot,'run-status.json'),'utf8'));
    assert.equal(status.schema,'usdom-finalized-burn-prover-run-v1');
    assert.equal(status.status,'failed');
    assert.equal(status.exitStatus,1);
    assert.equal(statSync(runRoot).mode&0o077,0);
    assert.equal(statSync(path.join(runRoot,'run-status.json')).mode&0o077,0);
    assert.equal(existsSync(path.join(runRoot,'vector.log')),true);

    const cacheRoot=path.join(home,'.local/share/dom-usdom/prover-capacity/finalized-burn/cache');
    const cachedComposite=path.join(cacheRoot,'finalized-burn-composite-receipt.bin');
    const checkpoint=Buffer.from('interrupted-composite-checkpoint');
    writeFileSync(cachedComposite,checkpoint,{mode:0o600});
    const retry=spawnSync('bash',[finalizedBurnProverE2eScript],{
      encoding:'utf8',
      env:{...process.env,HOME:home,PATH:`${fakeBin}:${process.env.PATH}`},
    });
    assert.equal(retry.status,1,retry.stderr);
    assert.deepEqual(readFileSync(cachedComposite),checkpoint);
    assert.equal(readdirSync(runs).length,2);
  } finally {
    rmSync(home,{recursive:true,force:true});
    rmSync(fakeBin,{recursive:true,force:true});
  }
});

test('finalized-burn prover records low-memory preflight and preserves its resumable cache',()=>{
  const home=mkdtempSync(path.join(os.tmpdir(),'usdom-prover-low-memory-home-'));
  const fakeBin=mkdtempSync(path.join(os.tmpdir(),'usdom-prover-low-memory-bin-'));
  try {
    const fakeAwk=path.join(fakeBin,'awk');
    writeFileSync(fakeAwk,'#!/usr/bin/env bash\nprintf "%s\\n" 1\n',{mode:0o700});
    const cacheRoot=path.join(home,'.local/share/dom-usdom/prover-capacity/finalized-burn/cache');
    mkdirSync(cacheRoot,{recursive:true,mode:0o700});
    for(const directory of [
      path.join(home,'.local'),path.join(home,'.local/share'),path.join(home,'.local/share/dom-usdom'),
      path.join(home,'.local/share/dom-usdom/prover-capacity'),
      path.join(home,'.local/share/dom-usdom/prover-capacity/finalized-burn'),cacheRoot,
    ]) chmodSync(directory,0o700);
    const cachedComposite=path.join(cacheRoot,'finalized-burn-composite-receipt.bin');
    const checkpoint=Buffer.from('verified-resumable-composite');
    writeFileSync(cachedComposite,checkpoint,{mode:0o600});
    const result=spawnSync('bash',[finalizedBurnProverE2eScript],{
      encoding:'utf8',env:{...process.env,HOME:home,PATH:`${fakeBin}:${process.env.PATH}`},
    });
    assert.equal(result.status,1);
    assert.match(result.stderr,/3 GiB of available RAM/);
    const runs=path.join(home,'.local/share/dom-usdom/prover-capacity/finalized-burn/runs');
    const runNames=readdirSync(runs);
    assert.equal(runNames.length,1);
    const status=JSON.parse(readFileSync(path.join(runs,runNames[0],'run-status.json'),'utf8'));
    assert.equal(status.status,'failed');
    assert.equal(status.exitStatus,1);
    assert.equal(status.rayonWorkers,0);
    assert.deepEqual(readFileSync(cachedComposite),checkpoint);
  } finally {
    rmSync(home,{recursive:true,force:true});
    rmSync(fakeBin,{recursive:true,force:true});
  }
});

test('finalized-burn prover E2E rejects a symlinked durable project directory',()=>{
  const home=mkdtempSync(path.join(os.tmpdir(),'usdom-prover-symlink-home-'));
  const target=mkdtempSync(path.join(os.tmpdir(),'usdom-prover-symlink-target-'));
  try {
    mkdirSync(path.join(home,'.local/share'),{recursive:true});
    symlinkSync(target,path.join(home,'.local/share/dom-usdom'));
    const result=spawnSync('bash',[finalizedBurnProverE2eScript],{
      encoding:'utf8',env:{...process.env,HOME:home},
    });
    assert.equal(result.status,1);
    assert.match(result.stderr,/Unsafe durable prover directory/);
  } finally {
    rmSync(home,{recursive:true,force:true});
    rmSync(target,{recursive:true,force:true});
  }
});

test('authenticated checkpoint outer prover is fixed, local and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',checkpointOuterProveScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointOuterProveScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','read -e','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    '--index','--segment','--block','--height','BONSAI_API_KEY=',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/checkpoint-outer-proof-job-index\.json/);
  assert.match(source,/checkpoint-statement-v6\.bin/);
  assert.match(source,/checkpoint-outer-chain\.bin/);
  assert.match(source,/RISC0_PROVER=local/);
  assert.match(source,/RISC0_DEV_MODE=0/);
  assert.match(source,/-u RISC0_SERVER_ADDR/);
  assert.match(source,/RAYON_NUM_THREADS=1/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features prove/);
  assert.match(source,/--bin dom-usdom-prove-checkpoint-outer/);
  assert.match(source,/usdom-outer-prove\.XXXXXX/);
  assert.match(source,/read-private-file-stdout\.mjs/);
  assert.match(source,/length>0 and length<=720/);
  assert.match(source,/length==\(unique\|length\)/);
  assert.match(source,/for name in "\$\{segment_receipts\[@\]\}"/);
  assert.match(source,/crates\/dom-usdom-\$\{guest\}-risc0-guest\/elfs/);
  assert.match(source,/rm -- "\$final_index"/);
  assert.match(source,/sync -d "\$OUTPUT_DIR"/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/assert_tool_unchanged cargo/);
  assert.match(source,/dom-usdom-plan-checkpoint-outer/);
  assert.match(source,/cmp -s "\$reviewed_job_index" "\$snapshot_jobs\/checkpoint-outer-proof-job-index\.json"/);
  assert.match(source,/checkpoint-outer-critical-inputs\.sha256/);
  assert.match(source,/"\$sha256sum_bin" -c "\$critical"[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  assert.ok(source.indexOf('RISC0_DEV_MODE=0 "$cargo_bin" run') < source.indexOf('rm -- "$final_index"'));
  assert.doesNotMatch(source,/(^|[;(]\s*)cargo run/m);
});

test('checkpoint outer prover rejects substitution and closes its long-proof TOCTOU window',()=>{
  const source=readFileSync(checkpointOuterProveScript,'utf8');
  for(const input of [
    'checkpoint-source-set-index.json','randomx-proof-job-index.json',
    'randomx-receipt-set-index.json','economic-proof-job-index.json',
    'economic-receipt-set-index.json','checkpoint-segment-proof-job-index.json',
    'checkpoint-segment-receipt-set-index.json','checkpoint-outer-proof-job-index.json',
    'checkpoint-statement-v6.bin','checkpoint-outer-chain.bin',
  ]) assert.match(source,new RegExp(`capture_private .*${input.replaceAll('.','\\.')}`));
  const snapshot=source.indexOf('capture_private "$JOB_DIR/checkpoint-outer-proof-job-index.json"');
  const validation=source.indexOf('"$jq_bin" -e \'',snapshot);
  const proof=source.indexOf('--bin dom-usdom-prove-checkpoint-outer',validation);
  const proofEnd=source.indexOf('final_index="$OUTPUT_DIR/',proof);
  const receiptInstall=source.indexOf('install-private-file-stdin.mjs" "$OUTPUT_DIR/$completion_receipt"',proofEnd);
  const receiptValidation=source.indexOf('Published checkpoint outer receipt failed integrity verification',receiptInstall);
  const indexInstall=source.indexOf('install-private-file-stdin.mjs" "$final_index"',receiptValidation);
  const indexValidation=source.indexOf('Published checkpoint outer completion index changed during installation',indexInstall);
  const postIndexReceiptValidation=source.indexOf('Checkpoint outer receipt changed before completion publication',indexValidation);
  assert.ok(snapshot>=0 && snapshot<validation && validation<proof);
  assert.ok(proof<proofEnd && proofEnd<receiptInstall && receiptInstall<receiptValidation);
  assert.ok(receiptValidation<indexInstall && indexInstall<indexValidation
    && indexValidation<postIndexReceiptValidation);
  assert.ok(proofEnd>proof);
  assert.doesNotMatch(source.slice(proof,proofEnd),
    /\$(SOURCE_DIR|RANDOMX_RECEIPT_DIR|ECONOMIC_RECEIPT_DIR|SEGMENT_RECEIPT_DIR|JOB_DIR|OUTPUT_DIR)\//);
});

test('checkpoint outer EVM packager is fixed, local and secret-free',()=>{
  const parsed=spawnSync('bash',['-n',checkpointOuterEvmPackageScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointOuterEvmPackageScript,'utf8');
  for(const forbidden of ['read -p','read -s','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','BONSAI_API_KEY=']) {
    assert.equal(source.includes(forbidden),false,forbidden);
  }
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/checkpoint-outer-receipt-set-index\.json/);
  assert.match(source,/RISC0_PROVER=local/);
  assert.match(source,/RISC0_DEV_MODE=0/);
  assert.match(source,/-u RISC0_SERVER_ADDR/);
  assert.match(source,/RAYON_NUM_THREADS=1/);
  assert.match(source,/--release --locked/);
  assert.match(source,/--features prove/);
  assert.match(source,/--bin dom-usdom-package-checkpoint-outer-evm-proof/);
  assert.match(source,/checkpoint-outer-evm-critical-inputs\.sha256/);
  assert.match(source,/usdom-checkpoint-outer\.elf usdom-checkpoint-outer\.bin usdom-checkpoint-outer\.iid/);
  assert.match(source,/assert_tool_unchanged cargo/);
  assert.match(source,/assert_tool_unchanged sha256sum; assert_tool_unchanged timeout[\s\S]*"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$sha256sum_bin" -c "\$critical"[\s\S]*assert_tool_unchanged sha256sum[\s\S]*"\$env_bin"[\s\S]*"\$cargo_bin" run/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cargo run/m);
  const packageStart=source.indexOf('RISC0_DEV_MODE=0 "$cargo_bin" run');
  const completionInvalidation=source.indexOf('final_index="$OUTPUT_DIR/',packageStart);
  const artifactInstall=source.indexOf('for name in checkpoint-outer-groth16-receipt.bin',completionInvalidation);
  const indexInstall=source.lastIndexOf('"$final_index"');
  assert.ok(packageStart>=0 && packageStart<completionInvalidation);
  assert.ok(completionInvalidation<artifactInstall && artifactInstall<indexInstall);
  assert.doesNotMatch(source.slice(packageStart,completionInvalidation),
    /\$(JOB_DIR|RECEIPT_DIR|ARTIFACT_DIR|OUTPUT_DIR)\//);
});

test('checkpoint planning and proving binaries reject all direct field overrides',()=>{
  for(const binary of [
    checkpointSegmentPlannerBinary,checkpointSegmentProverBinary,
    checkpointOuterPlannerBinary,checkpointOuterProverBinary,checkpointOuterPackagerBinary,
  ]) {
    const source=readFileSync(binary,'utf8');
    assert.match(source,/#!\[deny\(unsafe_code\)\]/);
    assert.match(source,/env::args_os\(\)\.len\(\) != 1/);
    assert.match(source,/accepts no arguments or field overrides/);
  }
});

test('all fixed and adaptive proof launchers clear executor overrides',()=>{
  for(const script of [
    randomxReceiptProveScript,randomxAggregateProveScript,economicReceiptProveScript,
    checkpointSegmentProveScript,checkpointOuterProveScript,checkpointOuterEvmPackageScript,
    finalizedBurnProveScript,finalizedBurnEvmPackageScript,finalizedBurnProverE2eScript,
  ]) {
    const source=readFileSync(script,'utf8');
    assert.match(source,/-u RISC0_EXECUTOR/);
  }
});

test('all proof launchers fail early unless the pinned RISC Zero recursion artifact exists',()=>{
  const launchers=[
    randomxReceiptProveScript,randomxAggregateProveScript,economicReceiptProveScript,
    checkpointSegmentProveScript,checkpointOuterProveScript,checkpointOuterEvmPackageScript,
    finalizedBurnProveScript,finalizedBurnEvmPackageScript,finalizedBurnProverE2eScript,
  ];
  for(const script of launchers) {
    const source=readFileSync(script,'utf8');
    assert.match(source,/source "\$LAB_ROOT\/scripts\/require-risc0-recursion-artifact\.sh"/);
    assert.match(source,/require_risc0_recursion_artifact/);
    assert.ok(source.indexOf('require_risc0_recursion_artifact')<source.indexOf('--features prove'));
  }

  const check=readFileSync(risc0RecursionArtifactCheck,'utf8');
  assert.match(check,/744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849/);
  assert.match(check,/USDOM_RISC0_RECURSION_BYTES=59768781/);
  assert.match(check,/sha256sum/);
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-recursion-artifact-'));
  try {
    const invalid=path.join(temporary,'recursion_zkr.zip');
    writeFileSync(invalid,'not the pinned artifact',{mode:0o600});
    const result=spawnSync('bash',['-c',
      'set -euo pipefail; source "$1"; require_risc0_recursion_artifact',
      '_',risc0RecursionArtifactCheck],{
      encoding:'utf8',env:{...process.env,RECURSION_SRC_PATH:invalid},
    });
    assert.equal(result.status,1);
    assert.match(result.stderr,/artifact has .* bytes; expected 59768781/);
  } finally {
    rmSync(temporary,{recursive:true,force:true});
  }
});

test('all proof-data commands use an owner-only filesystem boundary',()=>{
  for(const script of [
    checkpointSourceExportScript,checkpointSourceSetExportScript,finalizedBurnSourceExportScript,
    randomxExportScript,randomxStatementSetExportScript,
    randomxReceiptPlanScript,randomxAggregatePlanScript,economicReceiptPlanScript,
    checkpointSegmentPlanScript,checkpointOuterPlanScript,finalizedBurnPlanScript,
    randomxReceiptProveScript,randomxAggregateProveScript,economicReceiptProveScript,
    checkpointSegmentProveScript,checkpointOuterProveScript,checkpointOuterEvmPackageScript,
    finalizedBurnProveScript,finalizedBurnEvmPackageScript,finalizedBurnProverE2eScript,
  ]) assert.match(readFileSync(script,'utf8'),/^umask 077$/m,path.basename(script));
});

test('authenticated checkpoint submission command is fixed, unsigned and secret-free',()=>{
  const parsed=spawnSync(process.execPath,['--check',checkpointSubmissionScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointSubmissionScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    'sendTransaction','broadcastTransaction','eth_sendRawTransaction','RISC0_PROVER',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/process\.argv\.length!==2/);
  assert.match(source,/checkpoint-statement-v6\.bin/);
  assert.match(source,/checkpoint-outer-evm-proof-index\.json/);
  assert.match(source,/checkpoint-outer-evm-seal\.bin/);
  assert.match(source,/broadcastAuthorized:false/);
});

test('authenticated checkpoint observer is finalized-snapshot read-only and secret-free',()=>{
  const parsed=spawnSync(process.execPath,['--check',checkpointObserverScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointObserverScript,'utf8');
  for(const forbidden of [
    'read -p','read -s','PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC',
    'sendTransaction','broadcastTransaction','eth_sendRawTransaction','RISC0_PROVER',
  ]) assert.equal(source.includes(forbidden),false,forbidden);
  assert.match(source,/process\.argv\.length!==2/);
  assert.match(source,/eth_getBlockByNumber.*finalized/);
  assert.match(source,/snapshotBlockHashAfter/);
  assert.match(source,/provider\.call/);
  assert.match(source,/broadcastAuthorized:false/);
});

test('checkpoint observer launcher obtains cataloged RPC endpoints only from an owner-only file',()=>{
  const parsed=spawnSync('bash',['-n',checkpointObserverLauncher],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(checkpointObserverLauncher,'utf8');
  for(const forbidden of ['PLACEHOLDER','SUBSTITUA','$1','PRIVATE KEY','MNEMONIC','tee ','set -x']) {
    assert.equal(source.includes(forbidden),false,forbidden);
  }
  assert.match(source,/\(\(\$# != 0\)\)/);
  assert.match(source,/USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE/);
  assert.doesNotMatch(source,/read -r|ETHEREUM_RPC_URL/);
  assert.match(source,/exec "\$ENV_BIN" -i[\s\S]*"\$NODE_BIN" scripts\/observe-authenticated-checkpoint\.mjs/);
  const noninteractive=spawnSync('bash',[checkpointObserverLauncher],{
    encoding:'utf8',env:{...process.env,USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE:''},input:'',
  });
  assert.equal(noninteractive.status,2);
  assert.match(noninteractive.stderr,/is required/);
});

test('release-signing key configurator parses and never embeds secret material',()=>{
  const parsed=spawnSync('bash',['-n',signingScript],{encoding:'utf8'});
  assert.equal(parsed.status,0,parsed.stderr);
  const source=readFileSync(signingScript,'utf8');
  for(const forbidden of ['PRIVATE KEY','BEGIN OPENSSH PRIVATE KEY','--no-passphrase','-N \'\'']) {
    assert.equal(source.includes(forbidden),false,forbidden);
  }
  assert.match(source,/ssh-keygen -q -t ed25519 -a 100/);
  assert.match(source,/Creating the dedicated USDOM release-signing key\.\\n' >&2/);
  assert.match(source,/os\.O_DIRECTORY\|os\.O_NOFOLLOW/);
  assert.match(source,/stat -c '%u:%h'/);
  assert.match(source,/private_fingerprint/);
  assert.match(source,/install-private-file-stdin\.mjs/);
  assert.match(source,/commit\.gpgsign true/);
  assert.match(source,/tag\.gpgsign true/);
});

test('private stdin installer pins its directory and rejects indirect targets',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-private-installer-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  const target=path.join(temporary,'installed.json');
  const installed=spawnSync(process.execPath,[privateFileInstaller,target],{
    encoding:'utf8',input:'{"safe":true}\n',
  });
  assert.equal(installed.status,0,installed.stderr);
  assert.equal(readFileSync(target,'utf8'),'{"safe":true}\n');
  assert.equal(statSync(target).mode&0o777,0o600);
  const jsonTarget=path.join(temporary,'typed-private.json');
  for(const ambiguous of [
    Buffer.from('{"chainId":"1","\\u0063hainId":"2"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    const rejected=spawnSync(process.execPath,[immutablePrivateFileInstaller,'--json',jsonTarget],{
      input:ambiguous,
    });
    assert.notEqual(rejected.status,0);
    assert.equal(existsSync(jsonTarget),false);
  }
  const installedJson=spawnSync(process.execPath,[immutablePrivateFileInstaller,'--json',jsonTarget],{
    input:'{"chainId":"1"}\n',encoding:'utf8',
  });
  assert.equal(installedJson.status,0,installedJson.stderr);
  assert.equal(readFileSync(jsonTarget,'utf8'),'{"chainId":"1"}\n');
  const rejectedReplacement=spawnSync(process.execPath,
    [immutablePrivateFileInstaller,'--json',jsonTarget],{
      input:'{"chainId":"1","\\u0063hainId":"2"}\n',encoding:'utf8',
    });
  assert.notEqual(rejectedReplacement.status,0);
  assert.equal(readFileSync(jsonTarget,'utf8'),'{"chainId":"1"}\n');
  const rejectedUtf8Replacement=spawnSync(process.execPath,
    [immutablePrivateFileInstaller,'--json',jsonTarget],{
      input:Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
    });
  assert.notEqual(rejectedUtf8Replacement.status,0);
  assert.equal(readFileSync(jsonTarget,'utf8'),'{"chainId":"1"}\n');
  const replacement=spawnSync(process.execPath,[privateFileNewInstaller,target],{
    encoding:'utf8',input:'replacement-blocked\n',
  });
  assert.notEqual(replacement.status,0);
  assert.equal(readFileSync(target,'utf8'),'{"safe":true}\n');
  const newTarget=path.join(temporary,'new-only.json');
  const created=spawnSync(process.execPath,[privateFileNewInstaller,newTarget],{
    encoding:'utf8',input:'created-once\n',
  });
  assert.equal(created.status,0,created.stderr);
  assert.equal(readFileSync(newTarget,'utf8'),'created-once\n');
  assert.equal(statSync(newTarget).nlink,1);
  const typedNewTarget=path.join(temporary,'typed-new.json');
  const typedCreated=spawnSync(process.execPath,[privateFileNewInstaller,'--json',typedNewTarget],{
    input:'{"package":"mainnet"}\n',encoding:'utf8',
  });
  assert.equal(typedCreated.status,0,typedCreated.stderr);
  for(const ambiguous of [
    Buffer.from('{"package":"mainnet","\\u0070ackage":"other"}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    const rejectedTyped=spawnSync(process.execPath,
      [privateFileNewInstaller,'--json',typedNewTarget],{input:ambiguous});
    assert.notEqual(rejectedTyped.status,0);
    assert.equal(readFileSync(typedNewTarget,'utf8'),'{"package":"mainnet"}\n');
  }

  const victim=path.join(temporary,'victim');
  writeFileSync(victim,'unchanged\n',{mode:0o600});
  rmSync(target);
  symlinkSync(victim,target);
  const linked=spawnSync(process.execPath,[privateFileInstaller,target],{
    encoding:'utf8',input:'blocked\n',
  });
  assert.notEqual(linked.status,0);
  assert.equal(readFileSync(victim,'utf8'),'unchanged\n');

  rmSync(target);
  linkSync(victim,target);
  const hardlinked=spawnSync(process.execPath,[privateFileInstaller,target],{
    encoding:'utf8',input:'blocked\n',
  });
  assert.notEqual(hardlinked.status,0);
  assert.equal(readFileSync(victim,'utf8'),'unchanged\n');
});

test('private stdout reader binds one owner-only inode and rejects links',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-private-reader-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  const source=path.join(temporary,'source.json');
  writeFileSync(source,'{"direct":true}\n',{mode:0o600});
  chmodSync(source,0o600);
  const direct=spawnSync(process.execPath,[privateFileReader,source],{encoding:'utf8'});
  assert.equal(direct.status,0,direct.stderr);
  assert.equal(direct.stdout,'{"direct":true}\n');
  const linked=path.join(temporary,'linked.json');
  symlinkSync(source,linked);
  assert.notEqual(spawnSync(process.execPath,[privateFileReader,linked]).status,0);
  rmSync(linked);
  linkSync(source,linked);
  assert.notEqual(spawnSync(process.execPath,[privateFileReader,linked]).status,0);
});

test('release-config installer writes exact 0644 files and rejects unsafe directories',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-config-installer-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  chmodSync(temporary,0o700);
  const target=path.join(temporary,'release.json');
  const installed=spawnSync(process.execPath,[releaseConfigInstaller,target],{
    encoding:'utf8',input:'{"release":true}\n',
  });
  assert.equal(installed.status,0,installed.stderr);
  assert.equal(readFileSync(target,'utf8'),'{"release":true}\n');
  assert.equal(statSync(target).mode&0o777,0o644);
  for(const ambiguous of [
    Buffer.from('{"release":true,"\\u0072elease":false}\n'),
    Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
  ]) {
    const rejectedAmbiguous=spawnSync(process.execPath,[releaseConfigInstaller,target],{
      input:ambiguous,
    });
    assert.notEqual(rejectedAmbiguous.status,0);
    assert.equal(readFileSync(target,'utf8'),'{"release":true}\n');
  }
  const unsafe=path.join(temporary,'unsafe');
  mkdirSync(unsafe,{mode:0o700});
  chmodSync(unsafe,0o770);
  const rejected=spawnSync(process.execPath,[releaseConfigInstaller,path.join(unsafe,'blocked')],{
    encoding:'utf8',input:'{"blocked":true}\n',
  });
  assert.notEqual(rejected.status,0);
  assert.match(rejected.stderr,/directory is unsafe/);
});

test('release-signing configurator reuses an existing key and emits only public identity',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-signing-test-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  const project=path.join(temporary,'project');
  const component=path.join(project,'labs','usdom-reserve');
  const home=path.join(temporary,'home');
  mkdirSync(path.join(component,'scripts'),{recursive:true});
  mkdirSync(path.join(component,'sdk'),{recursive:true});
  mkdirSync(path.join(home,'.ssh'),{recursive:true});
  cpSync(signingScript,path.join(component,'scripts','configure-release-signing-key.sh'));
  cpSync(privateFileInstaller,path.join(component,'scripts','install-private-file-stdin.mjs'));
  cpSync(durablePrivateFileSdk,path.join(component,'sdk','durable-private-file.mjs'));
  cpSync(directProjectFileSdk,path.join(component,'sdk','direct-project-file.mjs'));
  assert.equal(spawnSync('git',['init','-q',project]).status,0);
  const key=path.join(home,'.ssh','usdom-release-signing-ed25519');
  const generated=spawnSync('ssh-keygen',[
    '-q','-t','ed25519','-a','100','-N','','-C','Soren Planck <sorenplanck@tutamail.com>',
    '-f',key,
  ],{encoding:'utf8'});
  assert.equal(generated.status,0,generated.stderr);
  const result=spawnSync('bash',[path.join(component,'scripts','configure-release-signing-key.sh')],{
    encoding:'utf8',env:accountHomeTestEnvironment(temporary,home),
  });
  assert.equal(result.status,0,result.stderr);
  const output=JSON.parse(result.stdout);
  assert.equal(output.schema,'usdom-release-signing-public-identity-v1');
  assert.match(output.fingerprint,/^SHA256:[A-Za-z0-9+/]{43}$/);
  assert.equal(result.stdout.includes('OPENSSH PRIVATE KEY'),false);
  assert.equal(spawnSync('git',['-C',project,'config','--get','gpg.format'],{encoding:'utf8'}).stdout.trim(),'ssh');
  assert.equal(spawnSync('git',['-C',project,'config','--get','commit.gpgsign'],{encoding:'utf8'}).stdout.trim(),'true');
  assert.equal(spawnSync('git',['-C',project,'config','--get','tag.gpgsign'],{encoding:'utf8'}).stdout.trim(),'true');
});

test('release ceremony rejects a HOME that differs from the operating-system account',()=>{
  const source=readFileSync(signingScript,'utf8');
  assert.match(source,/pwd\.getpwuid\(os\.getuid\(\)\)\.pw_dir/);
  assert.doesNotMatch(source,/XDG_CONFIG_HOME/);
  for(const script of [signingScript,releaseSourceCommitScript,releaseEvidenceCommitScript,
    releaseProvenanceMaterializer]) {
    const content=readFileSync(script,'utf8');
    assert.match(content,/test "\$HOME" = "\$account_home"/);
    assert.match(content,/stat -c '%u:%a:%h'/);
  }
  const rejected=spawnSync('bash',[signingScript],{
    encoding:'utf8',env:{...process.env,HOME:'/tmp/usdom-forged-home'},
  });
  assert.notEqual(rejected.status,0);
});

test('release-signing configurator rejects linked key material without changing its target',t=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-signing-link-test-'));
  t.after(()=>rmSync(temporary,{recursive:true,force:true}));
  const project=path.join(temporary,'project');
  const component=path.join(project,'labs','usdom-reserve');
  const home=path.join(temporary,'home');
  const sshDirectory=path.join(home,'.ssh');
  mkdirSync(path.join(component,'scripts'),{recursive:true});
  mkdirSync(sshDirectory,{recursive:true,mode:0o700});
  chmodSync(sshDirectory,0o700);
  cpSync(signingScript,path.join(component,'scripts','configure-release-signing-key.sh'));
  assert.equal(spawnSync('git',['init','-q',project]).status,0);
  const victim=path.join(temporary,'victim');
  const privateKey=path.join(sshDirectory,'usdom-release-signing-ed25519');
  const publicKey=`${privateKey}.pub`;
  writeFileSync(victim,'do-not-change\n',{mode:0o644});
  chmodSync(victim,0o644);
  symlinkSync(victim,privateKey);
  writeFileSync(publicKey,'invalid\n',{mode:0o600});
  const result=spawnSync('bash',[path.join(component,'scripts','configure-release-signing-key.sh')],{
    encoding:'utf8',env:accountHomeTestEnvironment(temporary,home),
  });
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/direct owner-only single-link file/);
  assert.equal(readFileSync(victim,'utf8'),'do-not-change\n');
  assert.equal(statSync(victim).mode&0o777,0o644);

  rmSync(privateKey);
  writeFileSync(privateKey,'not-a-key\n',{mode:0o600});
  const secondLink=path.join(temporary,'second-link');
  linkSync(privateKey,secondLink);
  const hardlinkResult=spawnSync('bash',[path.join(component,'scripts','configure-release-signing-key.sh')],{
    encoding:'utf8',env:accountHomeTestEnvironment(temporary,home),
  });
  assert.notEqual(hardlinkResult.status,0);
  assert.match(hardlinkResult.stderr,/direct owner-only single-link file/);
});

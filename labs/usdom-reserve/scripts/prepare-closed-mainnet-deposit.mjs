process.stderr.write('BLOCKED: direct EOA-funded mainnet deposit is retired; use the OneKey iOS Safe custody workflow entrypoints\n'); process.exit(78);
import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  buildClosedMainnetDepositPackage,validateClosedMainnetDepositPackage,
} from '../sdk/closed-mainnet-deposit.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {validatePilotFundsPlanBinding,validatePilotFundsReleaseBinding} from '../sdk/pilot-funds-authorization.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const releasePath='config/proof-reserve.unconfigured.json';
const requirementsPath='config/production-requirements.json';
const pilotSnapshotPath='evidence/authorization/pilot-funds-snapshot.json';
const pilotAuthorizationPath='evidence/authorization/pilot-funds-authorization-state.json';
const phaseGenerationPath='/home/leonardov/usdom-mainnet-private/control-plane/.phase-generation.json';
const walletPath=path.join(os.homedir(),'.local','share','dom-usdom','mainnet-wallet','public-identity.json');

const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');

async function readPublicWallet() {
  return readDirectFile(walletPath,{
    minimum:1,maximum:64*1024,privateMode:true,label:'public wallet identity',
  });
}

if(process.argv.length!==2) {
  console.error('Usage: npm run --silent prepare:closed-mainnet-deposit');
  process.exitCode=2;
} else {
  try {
    const funder=process.env.USDOM_DEPOSIT_FUNDER;
    if(typeof funder!=='string') throw new Error('Ledger funder address was not derived');
    const [releaseBytes,requirementsBytes,walletBytes,pilotSnapshotBytes,pilotAuthorizationBytes,
      phaseGenerationBytes]=await Promise.all([
      readDirectProjectFile(root,releasePath),readDirectProjectFile(root,requirementsPath),readPublicWallet(),
      readDirectProjectFile(root,pilotSnapshotPath,{exactMode:0o600}),
      readDirectProjectFile(root,pilotAuthorizationPath,{exactMode:0o600}),
      readDirectFile(phaseGenerationPath,{minimum:2,maximum:64*1024,exactMode:0o600,
        label:'phase generation identity'}),
    ]);
    const release=parseStrictJson(releaseBytes.toString('utf8'),{
      label:releasePath,maxBytes:256*1024,
    });
    const wallet=parseStrictJson(walletBytes.toString('utf8'),{
      label:walletPath,maxBytes:64*1024,
    });
    const requirements=parseStrictJson(requirementsBytes.toString('utf8'),{
      label:requirementsPath,maxBytes:256*1024,
    });
    const pilotFundsSnapshot=parseStrictJson(pilotSnapshotBytes.toString('utf8'),{label:pilotSnapshotPath});
    const pilotFundsAuthorizationState=parseStrictJson(pilotAuthorizationBytes.toString('utf8'),{label:pilotAuthorizationPath});
    const phaseGeneration=parseStrictJson(phaseGenerationBytes.toString('utf8'),{label:phaseGenerationPath});
    validatePilotFundsPlanBinding(pilotFundsSnapshot,phaseGeneration);
    validatePilotFundsReleaseBinding(pilotFundsSnapshot,sha256(releaseBytes));
    const salt=pilotFundsSnapshot.salt;
    const deposit=buildClosedMainnetDepositPackage({
      release,wallet,funder,salt,releaseConfigSha256:sha256(releaseBytes),
      walletIdentitySha256:sha256(walletBytes),
      expectedPrivacyPolicyHash:`0x${requirements.native_privacy_policy_hash}`,
      pilotFundsSnapshot,pilotFundsAuthorizationState,
    });
    validateClosedMainnetDepositPackage(deposit);
    const [currentReleaseBytes,currentRequirementsBytes,currentWalletBytes,currentPilotSnapshotBytes,
      currentPilotAuthorizationBytes,currentPhaseGenerationBytes]=await Promise.all([
      readDirectProjectFile(root,releasePath,{minimum:releaseBytes.length,
        maximum:releaseBytes.length,label:releasePath}),
      readDirectProjectFile(root,requirementsPath,{minimum:requirementsBytes.length,
        maximum:requirementsBytes.length,label:requirementsPath}),readPublicWallet(),
      readDirectProjectFile(root,pilotSnapshotPath,{minimum:pilotSnapshotBytes.length,
        maximum:pilotSnapshotBytes.length,exactMode:0o600}),
      readDirectProjectFile(root,pilotAuthorizationPath,{minimum:pilotAuthorizationBytes.length,
        maximum:pilotAuthorizationBytes.length,exactMode:0o600}),
      readDirectFile(phaseGenerationPath,{minimum:phaseGenerationBytes.length,
        maximum:phaseGenerationBytes.length,exactMode:0o600,label:'phase generation identity'}),
    ]);
    if(!currentReleaseBytes.equals(releaseBytes)
        ||!currentRequirementsBytes.equals(requirementsBytes)||!currentWalletBytes.equals(walletBytes)
        ||!currentPilotSnapshotBytes.equals(pilotSnapshotBytes)
        ||!currentPilotAuthorizationBytes.equals(pilotAuthorizationBytes)
        ||!currentPhaseGenerationBytes.equals(phaseGenerationBytes)) {
      throw new Error('closed mainnet deposit inputs changed during preparation');
    }
    process.stdout.write(JSON.stringify(deposit,null,2)+'\n');
  } catch(error) {
    writePilotFailure('closed-mainnet-deposit-prepare',error);
    process.exitCode=1;
  }
}

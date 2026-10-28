#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto'; import path from 'node:path'; import {fileURLToPath} from 'node:url';
import {readDirectProjectFile,readDirectFile} from '../sdk/direct-project-file.mjs'; import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildPilotFundsSnapshot} from '../sdk/pilot-funds-authorization.mjs';
import {validatePilotFundsReleaseValidation} from '../sdk/pilot-funds-release-validation.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'), sha=b=>createHash('sha256').update(b).digest('hex');
try {if(process.argv.length!==10)throw new Error('usage: prepare-pilot-funds-snapshot.mjs DEPLOYMENT SAFE PRIVACY CHECKPOINT_CAPACITY BURN_CAPACITY PRIVATE_TUPLE PHASE_GENERATION RELEASE_VALIDATION');
 const [release,deployment,safe,privacy,checkpoint,burn,gas,risk,evidence,toolchain,cargoLock]=await Promise.all([
  readDirectProjectFile(root,'config/proof-reserve.unconfigured.json'),...process.argv.slice(2,7).map(p=>readDirectFile(p,{minimum:1,maximum:8*1024*1024,exactMode:0o600})),
  readDirectFile(process.env.USDOM_OPERATIONAL_GAS_EVIDENCE,{minimum:1,maximum:8*1024*1024,exactMode:0o600}),
  readDirectProjectFile(root,'docs/RESIDUAL-RISK-ACCEPTANCE-DRAFT-2026-10-16.md'),
  readDirectProjectFile(root,'config/mainnet-release-evidence.unconfigured.json'),
  readDirectProjectFile(root,'config/mainnet-toolchain-lock.json'),
  readDirectFile(path.resolve(root,'../../Cargo.lock'))]);
 const config=parseStrictJsonBytes(release,{label:'release config'});
 const tuple=parseStrictJsonBytes(await readDirectFile(process.argv[7],{minimum:2,maximum:4096,exactMode:0o600}),{label:'private pilot tuple'});
 if(Object.keys(tuple).sort().join(',')!=='funder,receivingCommitment,salt')throw new Error('private pilot tuple fields are invalid');
 const {funder,salt,receivingCommitment}=tuple;
 const generation=parseStrictJsonBytes(await readDirectFile(process.argv[8],{minimum:1,maximum:65536,exactMode:0o600}),{label:'phase generation'});
 const releaseValidation=await readDirectFile(process.argv[9],{minimum:1,maximum:8*1024*1024,exactMode:0o600});
 const reportAbsolute=path.resolve(process.argv[9]),reportRelative=path.relative(root,reportAbsolute).split(path.sep).join('/');
 if(reportRelative.startsWith('../')||path.resolve(root,reportRelative)!==reportAbsolute)throw new Error('release validation report must be a direct project file');
 validatePilotFundsReleaseValidation({reportBytes:releaseValidation,releaseEvidenceBytes:evidence,
  toolchainLockBytes:toolchain,cargoLockBytes:cargoLock,reportRelativePath:reportRelative});
 process.stdout.write(JSON.stringify(buildPilotFundsSnapshot({releaseConfig:config,releaseConfigSha256:sha(release),deploymentPackageSha256:sha(deployment),safeControlBundleSha256:sha(safe),nativePrivacyInstallationSha256:sha(privacy),checkpointCapacityEvidenceSha256:sha(checkpoint),finalizedBurnCapacityEvidenceSha256:sha(burn),operationalGasEvidenceSha256:sha(gas),residualRiskDraftSha256:sha(risk),pilotDepositBaseUnits:'1000000',funder,salt,receivingCommitment,planSha256:generation.planSha256,phaseCatalogSha256:generation.phaseCatalogSha256,releaseValidationReportSha256:sha(releaseValidation)}),null,2)+'\n');
}catch(e){writeReleaseFailure('prepare-pilot-funds-snapshot',e);process.exitCode=1;}

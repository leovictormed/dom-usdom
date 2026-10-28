import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {
  CHECKPOINT_CAPACITY_EVIDENCE_PATH,
  CHECKPOINT_CAPACITY_MANIFEST_PATH,
  validateInstalledCheckpointCapacityReleaseEvidence,
} from '../sdk/checkpoint-capacity-release-evidence-materialization.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../sdk/risc0-verifier-reference.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const files=Object.freeze({
  evidence:'config/mainnet-release-evidence.unconfigured.json',
  release:'config/proof-reserve.unconfigured.json',
  verifier:'config/checkpoint-verifier.unconfigured.json',
});

async function main() {
  if(process.argv.length!==2) throw new Error('fixed checkpoint capacity validator accepts no arguments');
  const [evidenceBytes,releaseBytes,verifierBytes,reportBytes,manifestBytes]=await Promise.all([
    readDirectProjectFile(root,files.evidence,{minimum:2,maximum:4*1024*1024,label:'release evidence'}),
    readDirectProjectFile(root,files.release,{minimum:2,maximum:1024*1024,label:'release config'}),
    readDirectProjectFile(root,files.verifier,{minimum:2,maximum:1024*1024,label:'checkpoint verifier config'}),
    readDirectProjectFile(root,CHECKPOINT_CAPACITY_EVIDENCE_PATH,{
      minimum:2,maximum:4*1024*1024,privateMode:true,label:'checkpoint capacity release report',
    }),
    readDirectProjectFile(root,CHECKPOINT_CAPACITY_MANIFEST_PATH,{minimum:2,maximum:16*1024*1024,privateMode:true,label:'checkpoint capacity artifact manifest'}),
  ]);
  const result=validateInstalledCheckpointCapacityReleaseEvidence({
    reportBytes,manifestBytes,
    evidenceBytes,releaseConfigBytes:releaseBytes,checkpointVerifierConfigBytes:verifierBytes,
    evidence:parseStrictJsonBytes(evidenceBytes,{label:'release evidence',maxBytes:4*1024*1024,maxDepth:64}),
    releaseConfig:parseStrictJsonBytes(releaseBytes,{label:'release config',maxBytes:1024*1024,maxDepth:32}),
    checkpointVerifierConfig:parseStrictJsonBytes(verifierBytes,{label:'checkpoint verifier config',maxBytes:1024*1024,maxDepth:32}),
    riscZeroReference:PINNED_RISC0_MAINNET_V3,
  });
  process.stdout.write(`${JSON.stringify({status:'verified',path:CHECKPOINT_CAPACITY_EVIDENCE_PATH,
    sha256:result.sha256})}\n`);
}

try { await main(); }
catch(error) {
  writeReleaseFailure('check-checkpoint-capacity-release-evidence',error);
  process.exitCode=1;
}

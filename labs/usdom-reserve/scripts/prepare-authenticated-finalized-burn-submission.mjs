import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {chmod,lstat,mkdir,mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  buildAuthenticatedFinalizedBurnSubmission,proofReserveConfigurationFromRelease,
} from '../sdk/finalized-burn-submission.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {
  removePrivateFileDurableIfExists,writePrivateFileDurableNew,
} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const releasePath='config/proof-reserve.unconfigured.json';
const verifierPath='config/finalized-burn-verifier.unconfigured.json';
const sourceIndexPath='evidence/finalized-burn-source/finalized-burn-source-index.json';
const sourceInputPath='evidence/finalized-burn-source/finalized-burn-input.bin';
const receiptIndexPath='evidence/finalized-burn-receipt/finalized-burn-receipt-index.json';
const proofIndexPath='evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json';
const sealPath='evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin';
const outputDirectory=path.join(root,'evidence','finalized-burn-submission');
const outputPath=path.join(outputDirectory,'finalized-burn-submission.json');

async function directOutputDirectory() {
  await mkdir(outputDirectory,{recursive:true,mode:0o700});
  const metadata=await lstat(outputDirectory);
  if(!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode&0o077)!==0) {
    throw new Error('finalized-burn submission output is not a direct directory');
  }
}

async function atomicWrite(bytes) {
  await writePrivateFileDurableNew(outputPath,bytes,{maximum:4*1024*1024});
}

async function privateInputReplica(inputs) {
  const directory=await mkdtemp(path.join(os.tmpdir(),'usdom-finalized-burn-submission.'));
  await chmod(directory,0o700);
  const names=[
    'release.json','verifier.json','source-index.json','source-input.bin',
    'receipt-index.json','proof-index.json','evm-seal.bin',
  ];
  try {
    await Promise.all(names.map((name,index)=>writePrivateFileDurableNew(
      path.join(directory,name),inputs[index],{maximum:512*1024*1024},
    )));
    const snapshots=await Promise.all(names.map(name=>readDirectFile(path.join(directory,name),{
      privateMode:true,minimum:1,maximum:512*1024*1024,label:'submission snapshot '+name,
    })));
    return {directory,snapshots};
  } catch(error) {
    await rm(directory,{recursive:true,force:true});
    throw error;
  }
}

if(process.argv.length!==2) {
  console.error('Usage: npm run --silent prepare:authenticated-finalized-burn-submission');
  process.exitCode=2;
} else {
  let snapshotDirectory;
  try {
    await directOutputDirectory();
    await removePrivateFileDurableIfExists(outputPath);
    const authenticatedInputs=await Promise.all([
        readDirectProjectFile(root,releasePath),readDirectProjectFile(root,verifierPath),
        readDirectProjectFile(root,sourceIndexPath),readDirectProjectFile(root,sourceInputPath),
        readDirectProjectFile(root,receiptIndexPath),readDirectProjectFile(root,proofIndexPath),
        readDirectProjectFile(root,sealPath),
      ]);
    const replica=await privateInputReplica(authenticatedInputs);
    snapshotDirectory=replica.directory;
    const [releaseBytes,verifierBytes,sourceIndex,sourceInput,receiptIndex,proofIndex,evmSeal]=
      replica.snapshots;
    const release=parseStrictJson(releaseBytes.toString('utf8'),{label:releasePath});
    const verifier=parseStrictJson(verifierBytes.toString('utf8'),{label:verifierPath});
    if(release.productionReady!==true || release.ethereumChainId!=='1') {
      throw new Error('the exact Ethereum mainnet finalized-burn release is not production-ready');
    }
    const reserveConfiguration=proofReserveConfigurationFromRelease(release);
    const submission=buildAuthenticatedFinalizedBurnSubmission({
      reserveConfiguration,verifierConfiguration:verifier,sourceIndex,sourceInput,receiptIndex,
      proofIndex,evmSeal,
      releaseConfigSha256:createHash('sha256').update(releaseBytes).digest('hex'),
      verifierManifestSha256:createHash('sha256').update(verifierBytes).digest('hex'),
    });
    const output=Buffer.from(JSON.stringify(submission,null,2)+'\n');
    const currentInputs=await Promise.all([
      readDirectProjectFile(root,releasePath),readDirectProjectFile(root,verifierPath),
      readDirectProjectFile(root,sourceIndexPath),readDirectProjectFile(root,sourceInputPath),
      readDirectProjectFile(root,receiptIndexPath),readDirectProjectFile(root,proofIndexPath),
      readDirectProjectFile(root,sealPath),
    ]);
    if(currentInputs.some((bytes,index)=>!bytes.equals(authenticatedInputs[index]))) {
      throw new Error('authenticated finalized-burn submission inputs changed during preparation');
    }
    await atomicWrite(output);
    const installed=await readDirectFile(outputPath,{
      privateMode:true,minimum:1,maximum:4*1024*1024,label:'finalized-burn submission package',
    });
    if(!installed.equals(output)) {
      throw new Error('installed finalized-burn submission differs from its authenticated package');
    }
    const packageSha256=createHash('sha256').update(installed).digest('hex');
    console.log(JSON.stringify({
      status:'prepared',
      output:'evidence/finalized-burn-submission/finalized-burn-submission.json',
      statementHash:submission.statementHash,dataKeccak256:submission.dataKeccak256,
      packageSha256,
      broadcastAuthorized:false,mines:false,generatesProofs:false,
    },null,2));
  } catch(error) {
    writePilotFailure('finalized-burn-submission-prepare',error);
    process.exitCode=1;
  } finally {
    if(snapshotDirectory) await rm(snapshotDirectory,{recursive:true,force:true});
  }
}

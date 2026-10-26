import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import {lstat,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Contract,keccak256} from 'ethers';
import {assessCheckpointCandidateObservation} from '../sdk/checkpoint-candidate-observer.mjs';
import {
  buildAuthenticatedCheckpointSubmission,checkpointRegistryConfigurationFromRelease,
} from '../sdk/checkpoint-submission.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {
  removePrivateFileDurableIfExists,writePrivateFileDurableNew,
} from '../sdk/durable-private-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {BoundedMainnetPreflightProvider,mainnetPreflightRpcSourceSet,
  matchMainnetPreflightRpcSources}
  from '../sdk/mainnet-preflight-rpc.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const releasePath='config/proof-reserve.unconfigured.json';
const verifierPath='config/checkpoint-verifier.unconfigured.json';
const statementPath='evidence/checkpoint-outer-proof-job/checkpoint-statement-v6.bin';
const proofIndexPath='evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-proof-index.json';
const sealPath='evidence/checkpoint-outer-evm-proof/checkpoint-outer-evm-seal.bin';
const submissionPath='evidence/checkpoint-submission/checkpoint-submission.json';
const outputDirectory=path.join(root,'evidence','checkpoint-submission-observation');
const outputPath=path.join(outputDirectory,'checkpoint-submission-observation.json');
const catalogPath='config/mainnet-preflight-rpc-catalog.json';
const authenticatedInputPaths=[releasePath,verifierPath,statementPath,proofIndexPath,sealPath,
  submissionPath,catalogPath];
const zeroHash='0x'+'00'.repeat(32);
const checkpointTuple=
  '(uint64 previousHeight,bytes32 previousBlock,bytes32 previousStateRoot,bytes32 previousContextHash,'+
  'uint256 previousTotalDifficulty,uint64 height,bytes32 blockHash,bytes32 stateRoot,bytes32 contextHash,'+
  'uint256 totalDifficulty,uint128 totalIssued,uint128 totalBurned,bool issuanceClosed,'+
  'uint64 confirmationHeight,bytes32 confirmationBlock,'+
  'uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp)';
const registryAbi=[
  `function checkpointStatementHash(${checkpointTuple} checkpoint) view returns (bytes32)`,
  'function checkpointConfigHash() view returns (bytes32)','function halted() view returns (bool)',
  'function gracefullyShutdown() view returns (bool)','function latestIssuanceClosed() view returns (bool)',
  'function latestHeight() view returns (uint64)','function latestBlock() view returns (bytes32)',
  'function latestStateRoot() view returns (bytes32)','function latestContextHash() view returns (bytes32)',
  'function latestTotalDifficulty() view returns (uint256)',
  'function latestTotalIssued() view returns (uint128)','function latestTotalBurned() view returns (uint128)',
  'function candidateIssuanceClosed() view returns (bool)',
  'function candidate() view returns (bytes32 statementHash,uint64 height,uint64 readyAt,bytes32 blockHash,bytes32 stateRoot,bytes32 contextHash,uint256 totalDifficulty,uint128 totalIssued,uint128 totalBurned,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp)',
];

const sha=value=>createHash('sha256').update(value).digest('hex');
const decimal=value=>value.toString();

async function prepareOutput() {
  await mkdir(outputDirectory,{recursive:true,mode:0o700});
  const metadata=await lstat(outputDirectory);
  if(!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error('checkpoint observation output is not a direct directory');
  }
  if((metadata.mode&0o777)!==0o700) throw new Error('checkpoint observation directory mode is unsafe');
  await removePrivateFileDurableIfExists(outputPath);
}

async function atomicWrite(value) {
  await writePrivateFileDurableNew(outputPath,value,{maximum:4*1024*1024});
}

const readAuthenticatedInputs=()=>Promise.all(authenticatedInputPaths.map(relative=>
  readDirectProjectFile(root,relative,{minimum:1,maximum:64*1024*1024,label:relative})));

async function loadAuthenticatedPackage(releaseBytes,release,verifierBytes,verifier,
  statement,proofIndex,evmSeal,publishedBytes) {
  const registryConfiguration=checkpointRegistryConfigurationFromRelease(release);
  const rebuilt=buildAuthenticatedCheckpointSubmission({
    registryConfiguration,verifierConfiguration:verifier,statement,proofIndex,evmSeal,
    releaseConfigSha256:sha(releaseBytes),verifierManifestSha256:sha(verifierBytes),
  });
  const exact=Buffer.from(JSON.stringify(rebuilt,null,2)+'\n');
  if(!publishedBytes.equals(exact)) {
    throw new Error('published checkpoint submission differs from its authenticated rebuild');
  }
  parseStrictJson(publishedBytes.toString('utf8'),{label:submissionPath});
  return rebuilt;
}

async function collect(provider,submission) {
  const [chainId,finalized]=await Promise.all([
    provider.send('eth_chainId',[]).then(BigInt),provider.send('eth_getBlockByNumber',['finalized',false]),
  ]);
  if(!finalized?.hash || !/^0x[0-9a-fA-F]+$/.test(finalized.number??'')
      || !/^0x[0-9a-fA-F]+$/.test(finalized.timestamp??'')) {
    throw new Error('RPC did not return a canonical finalized block');
  }
  const blockTag=finalized.number;
  const calls={blockTag};
  const registry=new Contract(submission.to,registryAbi,provider);
  const [code,onchainStatementHash,checkpointConfigHash,halted,gracefullyShutdown,
    latestIssuanceClosed,latestHeight,latestBlock,latestStateRoot,latestContextHash,
    latestTotalDifficulty,latestTotalIssued,latestTotalBurned,candidate,candidateIssuanceClosed]=await Promise.all([
    provider.send('eth_getCode',[submission.to,blockTag]),
    registry.checkpointStatementHash(submission.checkpoint,calls),registry.checkpointConfigHash(calls),
    registry.halted(calls),registry.gracefullyShutdown(calls),registry.latestIssuanceClosed(calls),
    registry.latestHeight(calls),registry.latestBlock(calls),
    registry.latestStateRoot(calls),registry.latestContextHash(calls),
    registry.latestTotalDifficulty(calls),registry.latestTotalIssued(calls),registry.latestTotalBurned(calls),
    registry.candidate(calls),registry.candidateIssuanceClosed(calls),
  ]);
  if(code==='0x') throw new Error('release checkpoint registry has no finalized EVM code');
  let submissionCallAccepted=null;
  if(candidate.statementHash===zeroHash) {
    try {
      await provider.call({to:submission.to,data:submission.data,value:0n,blockTag});
      submissionCallAccepted=true;
    } catch { submissionCallAccepted=false; }
  }
  const snapshotAfter=await provider.send('eth_getBlockByNumber',[blockTag,false]);
  return {
    chainId:chainId.toString(),finalizedBlockNumber:BigInt(finalized.number).toString(),
    finalizedBlockHash:finalized.hash,finalizedBlockTimestamp:BigInt(finalized.timestamp).toString(),
    snapshotBlockHashAfter:snapshotAfter?.hash??null,registryRuntimeCodeHash:keccak256(code),
    onchainStatementHash,submissionCallAccepted,
    registry:{checkpointConfigHash,halted,gracefullyShutdown,latestIssuanceClosed,
      latestHeight:decimal(latestHeight),latestBlock,latestStateRoot,latestContextHash,
      latestTotalDifficulty:decimal(latestTotalDifficulty),latestTotalIssued:decimal(latestTotalIssued),
      latestTotalBurned:decimal(latestTotalBurned)},
    candidate:{statementHash:candidate.statementHash,height:decimal(candidate.height),
      readyAt:decimal(candidate.readyAt),blockHash:candidate.blockHash,stateRoot:candidate.stateRoot,
      contextHash:candidate.contextHash,totalDifficulty:decimal(candidate.totalDifficulty),
      totalIssued:decimal(candidate.totalIssued),totalBurned:decimal(candidate.totalBurned),
      issuanceClosed:candidateIssuanceClosed,
      confirmationHeight:decimal(candidate.confirmationHeight),confirmationBlock:candidate.confirmationBlock,
      confirmationTotalDifficulty:decimal(candidate.confirmationTotalDifficulty),
      confirmationTimestamp:decimal(candidate.confirmationTimestamp)},
  };
}

if(process.argv.length!==2) {
  console.error('Usage: USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE=<absolute-owner-only-file> npm run --silent observe:authenticated-checkpoint');
  process.exitCode=2;
} else {
  const providers=[]; let rpcSources=[];
  try {
    // An observation is a completion artifact. Make any prior generation
    // durably absent before authenticating inputs or issuing the first RPC.
    await prepareOutput();
    const initialConfiguration=await Promise.all(authenticatedInputPaths.slice(0,2).map(relative=>
      readDirectProjectFile(root,relative,{minimum:1,maximum:64*1024*1024,label:relative})));
    const [releaseBytes,verifierBytes]=initialConfiguration;
    const release=parseStrictJson(releaseBytes.toString('utf8'),{label:releasePath});
    const verifier=parseStrictJson(verifierBytes.toString('utf8'),{label:verifierPath});
    if(release.productionReady!==true || release.ethereumChainId!=='1') {
      throw new Error('the exact Ethereum mainnet checkpoint release is not production-ready');
    }
    const remainingInputs=await Promise.all(authenticatedInputPaths.slice(2).map(relative=>
      readDirectProjectFile(root,relative,{minimum:1,maximum:64*1024*1024,label:relative})));
    const authenticatedInputs=[...initialConfiguration,...remainingInputs];
    const [statementBytes,proofIndexBytes,sealBytes,submissionBytes,catalogBytes]=remainingInputs;
    if(!process.env.USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE) {
      throw new Error('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE is required');
    }
    const catalog=parseStrictJson(catalogBytes.toString('utf8'),
      {label:catalogPath,maxBytes:1024*1024,maxDepth:16});
    const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
    rpcSources=matchMainnetPreflightRpcSources(catalog,runtimeSources);
    const rpcSourceSet=mainnetPreflightRpcSourceSet(catalog);
    const submission=await loadAuthenticatedPackage(releaseBytes,release,verifierBytes,verifier,
      statementBytes,proofIndexBytes,sealBytes,submissionBytes);
    providers.push(...rpcSources.map(source=>new BoundedMainnetPreflightProvider(source.url)));
    const observations=await Promise.all(providers.map(provider=>collect(provider,submission)));
    const canonical=observations.map(value=>JSON.stringify(value));
    if(canonical.some(value=>value!==canonical[0])) {
      throw new Error('cataloged finalized RPC observations disagree');
    }
    const observation=observations[0];
    const assessment=assessCheckpointCandidateObservation({releaseConfig:release,submission,observation});
    const report={...assessment,observation,rpcSourceCount:rpcSourceSet.sourceCount,
      rpcSourceSetCommitment:rpcSourceSet.sourceSetCommitment,
      rpcSources:rpcSourceSet.sources,broadcastAuthorized:false};
    const output=Buffer.from(JSON.stringify(report,null,2)+'\n');
    const currentInputs=await readAuthenticatedInputs();
    if(currentInputs.some((bytes,index)=>!bytes.equals(authenticatedInputs[index]))) {
      throw new Error('authenticated checkpoint inputs changed during observation');
    }
    await atomicWrite(output);
    console.log(output.toString('utf8').trimEnd());
    if(!assessment.valid) process.exitCode=1;
  } catch(error) {
    writeReleaseFailure('observe-authenticated-checkpoint',error);
    process.exitCode=2;
  } finally {
    for(const provider of providers) provider.destroy();
  }
}

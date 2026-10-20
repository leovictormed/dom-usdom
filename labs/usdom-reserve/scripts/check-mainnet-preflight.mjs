import {Contract,Interface,JsonRpcProvider,getAddress,getCreateAddress,keccak256} from 'ethers';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessMainnetPreflight} from '../sdk/mainnet-preflight.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const phase=process.argv[2];
const rpcUrl=process.env.ETHEREUM_RPC_URL;
const finalizedBurnVerifierDeploymentTransactionHash=
  process.env.USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH;
const checkpointVerifierDeploymentTransactionHash=
  process.env.USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH;
const deploymentTransactionHash=process.env.USDOM_DEPLOYMENT_TX_HASH;
const checkpointRegistryDeploymentTransactionHash=process.env.USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH;

const tokenAbi=[
  'function decimals() view returns (uint8)','function paused() view returns (bool)',
  'function deprecated() view returns (bool)','function basisPointsRate() view returns (uint256)',
  'function maximumFee() view returns (uint256)','function isBlackListed(address) view returns (bool)',
  'function balanceOf(address) view returns (uint256)',
];
const verifierAbi=['function verifierConfigHash() view returns (bytes32)'];
const riscZeroVerifierAbi=[
  'function SELECTOR() view returns (bytes4)','function VERSION() view returns (string)',
];
const riscZeroEmergencyStopAbi=[
  'function paused() view returns (bool)','function verifier() view returns (address)',
];
const checkpointRegistryAbi=[
  'function checkpointConfigHash() view returns (bytes32)',
  'function bridgeDomain() view returns (bytes32)','function domNetworkMagic() view returns (uint32)',
  'function domChainId() view returns (bytes32)','function firstV4Height() view returns (uint64)',
  'function activationEmptyStateRoot() view returns (bytes32)',
  'function activationScheduleCommitment() view returns (bytes32)',
  'function checkpointInterval() view returns (uint32)','function confirmationDepth() view returns (uint32)',
  'function challengePeriod() view returns (uint64)','function verifier() view returns (address)',
  'function verifierCodeHash() view returns (bytes32)','function verifierConfigHash() view returns (bytes32)',
  'function guardian() view returns (address)','function guardianCodeHash() view returns (bytes32)',
  'function latestHeight() view returns (uint64)','function checkpointCount() view returns (uint64)',
  'function halted() view returns (bool)','function latestBlock() view returns (bytes32)',
  'function latestStateRoot() view returns (bytes32)',
  'function latestContextHash() view returns (bytes32)',
  'function latestTotalDifficulty() view returns (uint256)',
  'function candidate() view returns (bytes32 statementHash,uint64 height,uint64 readyAt,bytes32 blockHash,bytes32 stateRoot,bytes32 contextHash,uint256 totalDifficulty,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp)',
];
const checkpointEventInterface=new Interface([
  'event CheckpointBootstrap(bytes32 indexed bridgeDomain,uint32 indexed domNetworkMagic,uint64 domHeight,bytes32 domBlock,bytes32 domStateRoot,bytes32 checkpointConfigHash)',
]);
const reserveAbi=[
  'function token() view returns (address)','function tokenCodeHash() view returns (bytes32)',
  'function verifier() view returns (address)','function verifierCodeHash() view returns (bytes32)',
  'function verifierConfigHash() view returns (bytes32)','function reserveConfigHash() view returns (bytes32)',
  'function domDomain() view returns (bytes32)','function activationScheduleCommitment() view returns (bytes32)',
  'function governance() view returns (address)',
  'function governanceCodeHash() view returns (bytes32)','function guardian() view returns (address)',
  'function guardianCodeHash() view returns (bytes32)','function withdrawalDelay() view returns (uint64)',
  'function governanceDelay() view returns (uint64)','function maxOutstanding() view returns (uint64)',
  'function outflowCapacity() view returns (uint64)','function paused() view returns (bool)',
  'function queueEpoch() view returns (uint64)','function resumeReadyAt() view returns (uint64)',
  'function totalDeposited() view returns (uint256)','function totalReleased() view returns (uint256)',
  'function totalPendingAmount() view returns (uint256)','function pendingCount() view returns (uint256)',
];

const stringify=value=>typeof value==='bigint'?value.toString():value;
const codeHash=async(provider,address,blockTag)=>keccak256(await provider.send('eth_getCode',[address,blockTag]));

async function observeDeployment(provider, transactionHash, checkpointRegistryAddress=null) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash??'')) throw new Error('deployment transaction hash must be canonical');
  const [transaction,receipt]=await Promise.all([
    provider.getTransaction(transactionHash),provider.getTransactionReceipt(transactionHash),
  ]);
  if (!transaction || !receipt) throw new Error('deployment transaction or receipt is unavailable');
  const canonicalBlock=await provider.getBlock(receipt.blockNumber);
  const result={status:receipt.status===1,from:transaction.from,nonce:transaction.nonce.toString(),
    creates:receipt.contractAddress??null,
    derivedCreateAddress:getCreateAddress({from:transaction.from,nonce:transaction.nonce}),
    blockNumber:receipt.blockNumber.toString(),blockHash:receipt.blockHash,
    canonicalBlockHash:canonicalBlock?.hash??null,transactionHash,to:transaction.to??null,
    value:transaction.value.toString(),inputHash:keccak256(transaction.data)};
  if (checkpointRegistryAddress!==null) {
    const matching=[];
    for (const log of receipt.logs) {
      if (getAddress(log.address)!==getAddress(checkpointRegistryAddress)) continue;
      try {
        const parsed=checkpointEventInterface.parseLog(log);
        if (parsed?.name!=='CheckpointBootstrap') continue;
        matching.push({address:log.address,bridgeDomain:parsed.args.bridgeDomain,
          domNetworkMagic:parsed.args.domNetworkMagic.toString(),domHeight:parsed.args.domHeight.toString(),
          domBlock:parsed.args.domBlock,domStateRoot:parsed.args.domStateRoot,
          checkpointConfigHash:parsed.args.checkpointConfigHash});
      } catch { /* another event from the exact registry */ }
    }
    result.checkpointEventCount=matching.length.toString();
    result.checkpointEvent=matching.length===1?matching[0]:null;
  }
  return result;
}

async function observe(releaseConfig,riscZeroReference) {
  const provider=new JsonRpcProvider(rpcUrl);
  const [chainId,finalized]=await Promise.all([
    provider.send('eth_chainId',[]).then(BigInt),provider.send('eth_getBlockByNumber',['finalized',false]),
  ]);
  if (!finalized?.hash || !/^0x[0-9a-fA-F]+$/.test(finalized.number??'')) {
    throw new Error('RPC did not return a canonical finalized block');
  }
  const finalizedTag=finalized.number;
  const callOptions={blockTag:finalizedTag};
  const token=new Contract(releaseConfig.token,tokenAbi,provider);
  const verifier=new Contract(releaseConfig.verifier,verifierAbi,provider);
  const checkpointVerifier=new Contract(releaseConfig.checkpointVerifier,verifierAbi,provider);
  const riscZeroVerifier=new Contract(riscZeroReference.verifier_address,riscZeroVerifierAbi,provider);
  const riscZeroEmergencyStop=new Contract(
    riscZeroReference.emergency_stop_wrapper_address,riscZeroEmergencyStopAbi,provider,
  );
  const [deployerNonce,checkpointRegistryDeployerNonce,tokenCodeHash,verifierCodeHash,governanceCodeHash,
    guardianCodeHash,reserveCodeHash,checkpointRegistryCodeHash,checkpointVerifierCodeHash,
    checkpointGuardianCodeHash,verifierConfigHash,checkpointVerifierConfigHash,decimals,paused,deprecated,
    basisPointsRate,maximumFee,reserveBlacklisted,reserveBalance,riscZeroVerifierCodeHash,
    riscZeroVerifierSelector,riscZeroVerifierVersion,riscZeroEmergencyStopCodeHash,
    riscZeroEmergencyStopPaused,riscZeroEmergencyStopVerifier]
    =await Promise.all([
      provider.send('eth_getTransactionCount',[releaseConfig.deployer,finalizedTag]).then(BigInt),
      provider.send('eth_getTransactionCount',[releaseConfig.checkpointRegistryDeployer,finalizedTag]).then(BigInt),
      codeHash(provider,releaseConfig.token,finalizedTag),codeHash(provider,releaseConfig.verifier,finalizedTag),
      codeHash(provider,releaseConfig.governance,finalizedTag),codeHash(provider,releaseConfig.guardian,finalizedTag),
      codeHash(provider,releaseConfig.reserve,finalizedTag),codeHash(provider,releaseConfig.checkpointRegistry,finalizedTag),
      codeHash(provider,releaseConfig.checkpointVerifier,finalizedTag),
      codeHash(provider,releaseConfig.checkpointGuardian,finalizedTag),
      verifier.verifierConfigHash(callOptions),checkpointVerifier.verifierConfigHash(callOptions),token.decimals(callOptions),
      token.paused(callOptions),token.deprecated(callOptions),token.basisPointsRate(callOptions),
      token.maximumFee(callOptions),token.isBlackListed(releaseConfig.reserve,callOptions),
      token.balanceOf(releaseConfig.reserve,callOptions),
      codeHash(provider,riscZeroReference.verifier_address,finalizedTag),riscZeroVerifier.SELECTOR(callOptions),
      riscZeroVerifier.VERSION(callOptions),
      codeHash(provider,riscZeroReference.emergency_stop_wrapper_address,finalizedTag),
      riscZeroEmergencyStop.paused(callOptions),riscZeroEmergencyStop.verifier(callOptions),
    ]);
  const observation={chainId:chainId.toString(),finalizedBlockNumber:BigInt(finalized.number).toString(),
    finalizedBlockHash:finalized.hash,deployerNonce:deployerNonce.toString(),
    checkpointRegistryDeployerNonce:checkpointRegistryDeployerNonce.toString(),
    codeHashes:{reserve:reserveCodeHash,token:tokenCodeHash,verifier:verifierCodeHash,
      governance:governanceCodeHash,guardian:guardianCodeHash,checkpointRegistry:checkpointRegistryCodeHash,
      checkpointVerifier:checkpointVerifierCodeHash,checkpointGuardian:checkpointGuardianCodeHash},
    verifierConfigHash,checkpointVerifierConfigHash,
    riscZeroVerifier:{address:riscZeroReference.verifier_address,codeHash:riscZeroVerifierCodeHash,
      selector:riscZeroVerifierSelector,version:riscZeroVerifierVersion},
    riscZeroEmergencyStop:{address:riscZeroReference.emergency_stop_wrapper_address,
      codeHash:riscZeroEmergencyStopCodeHash,paused:riscZeroEmergencyStopPaused,
      verifier:riscZeroEmergencyStopVerifier},
    token:{decimals:decimals.toString(),paused,deprecated,basisPointsRate:basisPointsRate.toString(),
      maximumFee:maximumFee.toString(),reserveBlacklisted,reserveBalance:reserveBalance.toString()}};

  if (!/^0x[0-9a-fA-F]{64}$/.test(finalizedBurnVerifierDeploymentTransactionHash??'')) {
    throw new Error('USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH must be a canonical transaction hash');
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(checkpointVerifierDeploymentTransactionHash??'')) {
    throw new Error('USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH must be a canonical transaction hash');
  }
  [observation.finalizedBurnVerifierDeployment,observation.checkpointVerifierDeployment]=await Promise.all([
    observeDeployment(provider,finalizedBurnVerifierDeploymentTransactionHash),
    observeDeployment(provider,checkpointVerifierDeploymentTransactionHash),
  ]);

  if (phase==='postdeployment') {
    if (!/^0x[0-9a-fA-F]{64}$/.test(deploymentTransactionHash??'')) {
      throw new Error('USDOM_DEPLOYMENT_TX_HASH must be a canonical transaction hash');
    }
    if (!/^0x[0-9a-fA-F]{64}$/.test(checkpointRegistryDeploymentTransactionHash??'')) {
      throw new Error('USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH must be a canonical transaction hash');
    }
    [observation.deployment,observation.checkpointRegistryDeployment]=await Promise.all([
      observeDeployment(provider,deploymentTransactionHash),
      observeDeployment(provider,checkpointRegistryDeploymentTransactionHash,releaseConfig.checkpointRegistry),
    ]);
    const reserve=new Contract(releaseConfig.reserve,reserveAbi,provider);
    const names=['token','tokenCodeHash','verifier','verifierCodeHash','verifierConfigHash','reserveConfigHash',
      'domDomain','activationScheduleCommitment','governance','governanceCodeHash','guardian','guardianCodeHash','withdrawalDelay','governanceDelay',
      'maxOutstanding','outflowCapacity','paused','queueEpoch','resumeReadyAt','totalDeposited','totalReleased',
      'totalPendingAmount','pendingCount'];
    const values=await Promise.all(names.map(name=>reserve[name](callOptions)));
    observation.reserve=Object.fromEntries(names.map((name,index)=>[name,stringify(values[index])]));
    const checkpointRegistry=new Contract(releaseConfig.checkpointRegistry,checkpointRegistryAbi,provider);
    const registryNames=['checkpointConfigHash','bridgeDomain','domNetworkMagic','domChainId','firstV4Height',
      'activationEmptyStateRoot','activationScheduleCommitment','checkpointInterval','confirmationDepth','challengePeriod',
      'verifier','verifierCodeHash','verifierConfigHash','guardian','guardianCodeHash','latestHeight',
      'checkpointCount','halted','latestBlock','latestStateRoot','latestContextHash','latestTotalDifficulty'];
    const [registryValues,candidate,slot0]=await Promise.all([
      Promise.all(registryNames.map(name=>checkpointRegistry[name](callOptions))),
      checkpointRegistry.candidate(callOptions),
      provider.send('eth_getStorageAt',[releaseConfig.checkpointRegistry,'0x0',finalizedTag]),
    ]);
    observation.checkpointRegistry=Object.fromEntries(
      registryNames.map((name,index)=>[name,stringify(registryValues[index])]));
    observation.checkpointRegistryCandidate={statementHash:candidate.statementHash,
      height:candidate.height.toString(),readyAt:candidate.readyAt.toString(),blockHash:candidate.blockHash,
      stateRoot:candidate.stateRoot,contextHash:candidate.contextHash,
      totalDifficulty:candidate.totalDifficulty.toString(),
      confirmationHeight:candidate.confirmationHeight.toString(),confirmationBlock:candidate.confirmationBlock,
      confirmationTotalDifficulty:candidate.confirmationTotalDifficulty.toString(),
      confirmationTimestamp:candidate.confirmationTimestamp.toString()};
    observation.checkpointRegistrySlot0=slot0;
  }
  const snapshotAfter=await provider.send('eth_getBlockByNumber',[finalizedTag,false]);
  observation.snapshotBlockHashAfter=snapshotAfter?.hash??null;
  await provider.destroy();
  return observation;
}

if (!['predeployment','postdeployment'].includes(phase) || process.argv.length!==3 || !rpcUrl) {
  console.error('Usage: ETHEREUM_RPC_URL=<url> USDOM_FINALIZED_BURN_VERIFIER_DEPLOYMENT_TX_HASH=<hash> USDOM_CHECKPOINT_VERIFIER_DEPLOYMENT_TX_HASH=<hash> [USDOM_DEPLOYMENT_TX_HASH=<postdeployment-hash> USDOM_CHECKPOINT_REGISTRY_DEPLOYMENT_TX_HASH=<postdeployment-hash>] node scripts/check-mainnet-preflight.mjs <predeployment|postdeployment>');
  process.exitCode=2;
} else {
  try {
    const [releaseConfig,riscZeroReference]=await Promise.all([
      readFile(path.join(root,'config/proof-reserve.unconfigured.json'),'utf8').then(value=>parseStrictJson(
        value,{label:'config/proof-reserve.unconfigured.json'})),
      readFile(path.join(root,'config/risc0-ethereum-mainnet-v3.json'),'utf8').then(value=>parseStrictJson(
        value,{label:'config/risc0-ethereum-mainnet-v3.json'})),
    ]);
    const observation=await observe(releaseConfig,riscZeroReference);
    const report=assessMainnetPreflight({phase,releaseConfig,observation,riscZeroReference});
    console.log(JSON.stringify({...report,observation},null,2));
    if (!report.ready) process.exitCode=1;
  } catch(error) {
    const message=String(error?.message??error).split(rpcUrl).join('[redacted RPC URL]');
    console.error(JSON.stringify({phase,ready:false,error:message},null,2));
    process.exitCode=2;
  }
}

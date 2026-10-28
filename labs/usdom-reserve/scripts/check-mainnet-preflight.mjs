import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {Contract,Interface,getAddress,getCreateAddress,id,keccak256,toBeHex} from 'ethers';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessMainnetPreflight} from '../sdk/mainnet-preflight.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {BoundedMainnetPreflightProvider,matchMainnetPreflightRpcSources,
  validateMainnetPreflightClientIdentity,validateMainnetPreflightTimeConsensus}
  from '../sdk/mainnet-preflight-rpc.mjs';
import {rpcConsensusEvidence} from '../sdk/rpc-consensus-evidence.mjs';
import {canonicalEthereumQuantity,MAX_UINT256} from '../sdk/ethereum-quantity.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const phase=process.argv[2];
let rpcSources=[];
const preflightInputPaths=[
  'config/proof-reserve.unconfigured.json','config/risc0-ethereum-mainnet-v3.json',
  'config/mainnet-preflight-rpc-catalog.json',
];
const readPreflightInputs=()=>Promise.all(preflightInputPaths.map(relative=>
  readDirectProjectFile(root,relative,{minimum:1,maximum:4*1024*1024,label:relative})));
let finalizedBurnVerifierDeploymentTransactionHash;
let checkpointVerifierDeploymentTransactionHash;
let deploymentTransactionHash;
let checkpointRegistryDeploymentTransactionHash;
async function readDeploymentEvidence() {
  const directory=process.env.USDOM_MAINNET_DEPLOYMENT_EVIDENCE_DIRECTORY;
  if(typeof directory!=='string'||!path.isAbsolute(directory)) {
    throw new Error('USDOM_MAINNET_DEPLOYMENT_EVIDENCE_DIRECTORY must be an absolute path');
  }
  const count=phase==='postdeployment'?4:2;
  const inputs=[];
  for(let index=0;index<count;index++) {
    const validationPath=path.join(directory,`contract-deployment-${index}-raw-validation.json`);
    const hashPath=path.join(directory,`contract-deployment-${index}-submission-hash.txt`);
    const [validationBytes,hashBytes]=await Promise.all([
      readDirectFile(validationPath,{minimum:2,maximum:4*1024*1024,exactMode:0o600,
        label:`deployment ${index} raw validation`}),
      readDirectFile(hashPath,{minimum:2,maximum:256,exactMode:0o600,
        label:`deployment ${index} submission hash`}),
    ]);
    const validation=parseStrictJsonBytes(validationBytes,{
      label:`deployment ${index} raw validation`,maxBytes:4*1024*1024,maxDepth:32});
    const hash=hashBytes.toString('ascii').trim().toLowerCase();
    if(!/^0x[0-9a-f]{64}$/.test(hash)||hashBytes.toString('ascii')!==`${hash}\n`
        ||String(validation.transactionHash).toLowerCase()!==hash
        ||typeof validation.packageSha256!=='string'||!/^[0-9a-f]{64}$/.test(validation.packageSha256)
        ||typeof validation.observationDocumentSha256!=='string'
        ||!/^[0-9a-f]{64}$/.test(validation.observationDocumentSha256)
        ||!/^0x[0-9a-f]{64}$/.test(validation.observationHash??'')) {
      throw new Error(`deployment ${index} durable transaction reference is invalid`);
    }
    inputs.push({validationPath,hashPath,validationBytes,hashBytes,hash});
  }
  return inputs;
}
async function assertDeploymentEvidenceUnchanged(inputs) {
  for(const input of inputs) {
    const [validation,hash]=await Promise.all([
      readDirectFile(input.validationPath,{minimum:input.validationBytes.length,
        maximum:input.validationBytes.length,exactMode:0o600,label:'deployment raw validation'}),
      readDirectFile(input.hashPath,{minimum:input.hashBytes.length,maximum:input.hashBytes.length,
        exactMode:0o600,label:'deployment submission hash'}),
    ]);
    if(!validation.equals(input.validationBytes)||!hash.equals(input.hashBytes)) {
      throw new Error('deployment durable transaction reference changed during preflight');
    }
  }
}

const tokenAbi=[
  'function name() view returns (string)','function symbol() view returns (string)',
  'function decimals() view returns (uint8)','function paused() view returns (bool)',
  'function deprecated() view returns (bool)','function basisPointsRate() view returns (uint256)',
  'function maximumFee() view returns (uint256)','function isBlackListed(address) view returns (bool)',
  'function balanceOf(address) view returns (uint256)','function totalSupply() view returns (uint256)',
  'function owner() view returns (address)','function upgradedAddress() view returns (address)',
];
const verifierAbi=[
  'function verifierConfigHash() view returns (bytes32)',
  'function PROOF_ACCEPTED() view returns (bytes32)',
  'function riscZeroVerifier() view returns (address)',
  'function riscZeroVerifierCodeHash() view returns (bytes32)',
  'function verifierSelector() view returns (bytes4)',
  'function imageId() view returns (bytes32)',
  'function deploymentChainId() view returns (uint256)',
];
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
  'function guardianImplementation() view returns (address)',
  'function guardianImplementationCodeHash() view returns (bytes32)',
  'function guardianOwnersCommitment() view returns (bytes32)',
  'function latestHeight() view returns (uint64)','function checkpointCount() view returns (uint64)',
  'function halted() view returns (bool)','function gracefullyShutdown() view returns (bool)',
  'function latestIssuanceClosed() view returns (bool)','function latestBlock() view returns (bytes32)',
  'function latestStateRoot() view returns (bytes32)',
  'function latestContextHash() view returns (bytes32)',
  'function latestTotalDifficulty() view returns (uint256)',
  'function latestTotalIssued() view returns (uint128)','function latestTotalBurned() view returns (uint128)',
  'function previousTotalIssued() view returns (uint128)','function previousTotalBurned() view returns (uint128)',
  'function guardianControlHealthy() view returns (bool)',
  'function candidateIssuanceClosed() view returns (bool)',
  'function candidate() view returns (bytes32 statementHash,uint64 height,uint64 readyAt,bytes32 blockHash,bytes32 stateRoot,bytes32 contextHash,uint256 totalDifficulty,uint128 totalIssued,uint128 totalBurned,uint64 confirmationHeight,bytes32 confirmationBlock,uint256 confirmationTotalDifficulty,uint64 confirmationTimestamp)',
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
  'function governanceImplementation() view returns (address)',
  'function governanceImplementationCodeHash() view returns (bytes32)',
  'function governanceOwnersCommitment() view returns (bytes32)',
  'function guardianCodeHash() view returns (bytes32)','function guardianImplementation() view returns (address)',
  'function guardianImplementationCodeHash() view returns (bytes32)',
  'function guardianOwnersCommitment() view returns (bytes32)','function withdrawalDelay() view returns (uint64)',
  'function governanceDelay() view returns (uint64)','function maxOutstanding() view returns (uint64)',
  'function outflowCapacity() view returns (uint64)','function paused() view returns (bool)',
  'function pilotRestrictedDeployment() view returns (bool)',
  'function permissionlessDeposits() view returns (bool)',
  'function pilotDepositConsumed() view returns (bool)',
  'function authorizedPilotDeposit() view returns (bytes32)',
  'function authorizedPilotSnapshot() view returns (bytes32)',
  'function authorizedPilotValidUntil() view returns (uint64)',
  'function pilotAuthorizationGeneration() view returns (uint64)',
  'function permissionlessDepositsReadyAt() view returns (uint64)',
  'function depositsClosed() view returns (bool)','function gracefullyShutdown() view returns (bool)',
  'function controlPlaneHealthy() view returns (bool)',
  'function queueEpoch() view returns (uint64)','function resumeReadyAt() view returns (uint64)',
  'function totalDeposited() view returns (uint256)','function totalReleased() view returns (uint256)',
  'function totalProvedDebtAmount() view returns (uint256)',
  'function pendingQueueSnapshot() view returns (uint64 epoch,uint256 count,uint256 amount,bytes32 firstBurnId,bytes32 lastBurnId)',
  'function outstanding() view returns (uint256)','function unreservedCollateral() view returns (uint256)',
  'function availableOutflow() view returns (uint256)',
];
const safeProxyAbi=[
  'function masterCopy() view returns (address)',
  'function nonce() view returns (uint256)',
  'function getThreshold() view returns (uint256)',
  'function getOwners() view returns (address[])',
  'function getModulesPaginated(address,uint256) view returns (address[] array,address next)',
];
const safeSentinel='0x0000000000000000000000000000000000000001';
const safeGuardStorageSlot='0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8';
const safeFallbackHandlerStorageSlot=
  '0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5';
const eip1967Slot=label=>toBeHex(BigInt(id(label))-1n,32);
const eip1967ImplementationSlot=eip1967Slot('eip1967.proxy.implementation');
const eip1967AdminSlot=eip1967Slot('eip1967.proxy.admin');
const eip1967BeaconSlot=eip1967Slot('eip1967.proxy.beacon');

const stringify=value=>typeof value==='bigint'?value.toString():value;
const codeHash=async(provider,address,blockTag)=>keccak256(await provider.send('eth_getCode',[address,blockTag]));
const storageAddress=word=>{
  if(typeof word!=='string'||!/^0x[0-9a-fA-F]{64}$/.test(word)||!/^0x0{24}/.test(word.toLowerCase())) {
    throw new Error('Safe guard storage word is not a canonical address');
  }
  return getAddress(`0x${word.slice(-40)}`);
};

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

async function observe(releaseConfig,riscZeroReference,rpcSource) {
  const collectedBeforeMs=Date.now();
  const provider=new BoundedMainnetPreflightProvider(rpcSource.url);
  try {
  const [chainIdRaw,genesis,finalized,clientIdentity]=await Promise.all([
    provider.send('eth_chainId',[]),provider.send('eth_getBlockByNumber',['0x0',false]),
    provider.send('eth_getBlockByNumber',['finalized',false]),
    provider.send('web3_clientVersion',[]).then(value=>
      validateMainnetPreflightClientIdentity(value,rpcSource.clientPolicy)),
  ]);
  let chainId,finalizedBlockNumber;
  try {
    chainId=canonicalEthereumQuantity(chainIdRaw,{maximum:MAX_UINT256});
    finalizedBlockNumber=canonicalEthereumQuantity(finalized?.number);
    canonicalEthereumQuantity(finalized?.timestamp);
  } catch { throw new Error('RPC did not return canonical bounded quantities'); }
  if (chainId!=='1'||!genesis?.hash||!finalized?.hash
      ||!/^0x[0-9a-fA-F]{64}$/.test(finalized.hash)) {
    throw new Error('RPC did not return a canonical finalized block');
  }
  const {tag:finalizedTag}=provider.pinFinalizedSnapshot(finalized.number,finalized.hash);
  const callOptions={blockTag:finalizedTag};
  const token=new Contract(releaseConfig.token,tokenAbi,provider);
  const verifier=new Contract(releaseConfig.verifier,verifierAbi,provider);
  const checkpointVerifier=new Contract(releaseConfig.checkpointVerifier,verifierAbi,provider);
  const governanceControl=new Contract(releaseConfig.governance,safeProxyAbi,provider);
  const guardianControl=new Contract(releaseConfig.guardian,safeProxyAbi,provider);
  const checkpointGuardianControl=new Contract(releaseConfig.checkpointGuardian,safeProxyAbi,provider);
  const riscZeroVerifier=new Contract(riscZeroReference.verifier_address,riscZeroVerifierAbi,provider);
  const riscZeroEmergencyStop=new Contract(
    riscZeroReference.emergency_stop_wrapper_address,riscZeroEmergencyStopAbi,provider,
  );
  const [deployerNonce,checkpointRegistryDeployerNonce,tokenCodeHash,verifierCodeHash,governanceCodeHash,
    governanceImplementationCodeHash,guardianCodeHash,guardianImplementationCodeHash,
    reserveCodeHash,checkpointRegistryCodeHash,checkpointVerifierCodeHash,
    checkpointGuardianCodeHash,checkpointGuardianImplementationCodeHash,
    verifierConfigHash,checkpointVerifierConfigHash,verifierProofAccepted,
    checkpointVerifierProofAccepted,tokenName,tokenSymbol,decimals,totalSupply,tokenOwner,paused,deprecated,
    upgradedAddress,
    basisPointsRate,maximumFee,reserveBlacklisted,reserveBalance,riscZeroVerifierCodeHash,
    riscZeroVerifierSelector,riscZeroVerifierVersion,riscZeroEmergencyStopCodeHash,
    riscZeroEmergencyStopPaused,riscZeroEmergencyStopVerifier,governanceImplementation,
    guardianImplementation,checkpointGuardianImplementation,governanceThreshold,governanceOwners,
    governanceModules,guardianThreshold,guardianOwners,guardianModules,checkpointGuardianThreshold,
    checkpointGuardianOwners,checkpointGuardianModules,eip1967Implementation,eip1967Admin,eip1967Beacon]
    =await Promise.all([
      provider.send('eth_getTransactionCount',[releaseConfig.deployer,finalizedTag]).then(BigInt),
      provider.send('eth_getTransactionCount',[releaseConfig.checkpointRegistryDeployer,finalizedTag]).then(BigInt),
      codeHash(provider,releaseConfig.token,finalizedTag),codeHash(provider,releaseConfig.verifier,finalizedTag),
      codeHash(provider,releaseConfig.governance,finalizedTag),
      codeHash(provider,releaseConfig.governanceImplementation,finalizedTag),
      codeHash(provider,releaseConfig.guardian,finalizedTag),
      codeHash(provider,releaseConfig.guardianImplementation,finalizedTag),
      codeHash(provider,releaseConfig.reserve,finalizedTag),codeHash(provider,releaseConfig.checkpointRegistry,finalizedTag),
      codeHash(provider,releaseConfig.checkpointVerifier,finalizedTag),
      codeHash(provider,releaseConfig.checkpointGuardian,finalizedTag),
      codeHash(provider,releaseConfig.checkpointGuardianImplementation,finalizedTag),
      verifier.verifierConfigHash(callOptions),checkpointVerifier.verifierConfigHash(callOptions),
      verifier.PROOF_ACCEPTED(callOptions),checkpointVerifier.PROOF_ACCEPTED(callOptions),
      token.name(callOptions),token.symbol(callOptions),token.decimals(callOptions),token.totalSupply(callOptions),
      token.owner(callOptions),token.paused(callOptions),token.deprecated(callOptions),token.upgradedAddress(callOptions),
      token.basisPointsRate(callOptions),
      token.maximumFee(callOptions),token.isBlackListed(releaseConfig.reserve,callOptions),
      token.balanceOf(releaseConfig.reserve,callOptions),
      codeHash(provider,riscZeroReference.verifier_address,finalizedTag),riscZeroVerifier.SELECTOR(callOptions),
      riscZeroVerifier.VERSION(callOptions),
      codeHash(provider,riscZeroReference.emergency_stop_wrapper_address,finalizedTag),
      riscZeroEmergencyStop.paused(callOptions),riscZeroEmergencyStop.verifier(callOptions),
      governanceControl.masterCopy(callOptions),guardianControl.masterCopy(callOptions),
      checkpointGuardianControl.masterCopy(callOptions),
      governanceControl.getThreshold(callOptions),governanceControl.getOwners(callOptions),
      governanceControl.getModulesPaginated(safeSentinel,1,callOptions),
      guardianControl.getThreshold(callOptions),guardianControl.getOwners(callOptions),
      guardianControl.getModulesPaginated(safeSentinel,1,callOptions),
      checkpointGuardianControl.getThreshold(callOptions),checkpointGuardianControl.getOwners(callOptions),
      checkpointGuardianControl.getModulesPaginated(safeSentinel,1,callOptions),
      provider.send('eth_getStorageAt',[releaseConfig.token,eip1967ImplementationSlot,finalizedTag]),
      provider.send('eth_getStorageAt',[releaseConfig.token,eip1967AdminSlot,finalizedTag]),
      provider.send('eth_getStorageAt',[releaseConfig.token,eip1967BeaconSlot,finalizedTag]),
    ]);
  const observedOwnersByRole={governance:[...governanceOwners],guardian:[...guardianOwners],
    checkpointGuardian:[...checkpointGuardianOwners]};
  const controlPlaneOwnerCodeHashes=Object.fromEntries(await Promise.all(
    Object.entries(observedOwnersByRole).map(async([role,owners])=>[
      role,await Promise.all(owners.map(owner=>codeHash(provider,owner,finalizedTag))),
    ]),
  ));
  const controlPlaneGuards=Object.fromEntries(await Promise.all(
    Object.entries({governance:releaseConfig.governance,guardian:releaseConfig.guardian,
      checkpointGuardian:releaseConfig.checkpointGuardian}).map(async([role,safe])=>[
      role,storageAddress(await provider.send('eth_getStorageAt',[safe,safeGuardStorageSlot,finalizedTag])),
    ]),
  ));
  const controlPlaneFallbackHandlers=Object.fromEntries(await Promise.all(
    Object.entries({governance:releaseConfig.governance,guardian:releaseConfig.guardian,
      checkpointGuardian:releaseConfig.checkpointGuardian}).map(async([role,safe])=>{
      const handler=storageAddress(await provider.send(
        'eth_getStorageAt',[safe,safeFallbackHandlerStorageSlot,finalizedTag],
      ));
      return [role,{address:handler,codeHash:await codeHash(provider,handler,finalizedTag)}];
    }),
  ));
  const observation={chainId,genesisBlockHash:genesis.hash,
    finalizedBlockNumber,
    finalizedBlockHash:finalized.hash,deployerNonce:deployerNonce.toString(),
    checkpointRegistryDeployerNonce:checkpointRegistryDeployerNonce.toString(),
    codeHashes:{reserve:reserveCodeHash,token:tokenCodeHash,verifier:verifierCodeHash,
      governance:governanceCodeHash,governanceImplementation:governanceImplementationCodeHash,
      guardian:guardianCodeHash,guardianImplementation:guardianImplementationCodeHash,
      checkpointRegistry:checkpointRegistryCodeHash,checkpointVerifier:checkpointVerifierCodeHash,
      checkpointGuardian:checkpointGuardianCodeHash,
      checkpointGuardianImplementation:checkpointGuardianImplementationCodeHash},
    verifierConfigHash,checkpointVerifierConfigHash,verifierProofAccepted,checkpointVerifierProofAccepted,
    riscZeroVerifier:{address:riscZeroReference.verifier_address,codeHash:riscZeroVerifierCodeHash,
      selector:riscZeroVerifierSelector,version:riscZeroVerifierVersion},
    riscZeroEmergencyStop:{address:riscZeroReference.emergency_stop_wrapper_address,
      codeHash:riscZeroEmergencyStopCodeHash,paused:riscZeroEmergencyStopPaused,
      verifier:riscZeroEmergencyStopVerifier},
    token:{name:tokenName,symbol:tokenSymbol,decimals:decimals.toString(),totalSupply:totalSupply.toString(),
      owner:tokenOwner,ownerCodeHash:await codeHash(provider,tokenOwner,finalizedTag),paused,deprecated,
      upgradedAddress,basisPointsRate:basisPointsRate.toString(),maximumFee:maximumFee.toString(),
      reserveBlacklisted,reserveBalance:reserveBalance.toString(),eip1967Implementation,
      eip1967Admin,eip1967Beacon},
    controlPlaneImplementations:{governance:governanceImplementation,guardian:guardianImplementation,
      checkpointGuardian:checkpointGuardianImplementation},
    controlPlanePolicies:{
      governance:{threshold:governanceThreshold.toString(),owners:observedOwnersByRole.governance,
        ownerCodeHashes:controlPlaneOwnerCodeHashes.governance,
        modules:[...governanceModules.array],modulesNext:governanceModules.next,guard:controlPlaneGuards.governance,
        fallbackHandler:controlPlaneFallbackHandlers.governance.address,
        fallbackHandlerCodeHash:controlPlaneFallbackHandlers.governance.codeHash},
      guardian:{threshold:guardianThreshold.toString(),owners:observedOwnersByRole.guardian,
        ownerCodeHashes:controlPlaneOwnerCodeHashes.guardian,
        modules:[...guardianModules.array],modulesNext:guardianModules.next,guard:controlPlaneGuards.guardian,
        fallbackHandler:controlPlaneFallbackHandlers.guardian.address,
        fallbackHandlerCodeHash:controlPlaneFallbackHandlers.guardian.codeHash},
      checkpointGuardian:{threshold:checkpointGuardianThreshold.toString(),owners:observedOwnersByRole.checkpointGuardian,
        ownerCodeHashes:controlPlaneOwnerCodeHashes.checkpointGuardian,
        modules:[...checkpointGuardianModules.array],modulesNext:checkpointGuardianModules.next,
        guard:controlPlaneGuards.checkpointGuardian,
        fallbackHandler:controlPlaneFallbackHandlers.checkpointGuardian.address,
        fallbackHandlerCodeHash:controlPlaneFallbackHandlers.checkpointGuardian.codeHash},
    }};

  const [governanceSafeNonce,guardianSafeNonce,checkpointGuardianSafeNonce]=await Promise.all([
    governanceControl.nonce(callOptions),guardianControl.nonce(callOptions),
    checkpointGuardianControl.nonce(callOptions),
  ]);
  observation.controlPlanePolicies.governance.nonce=governanceSafeNonce.toString();
  observation.controlPlanePolicies.guardian.nonce=guardianSafeNonce.toString();
  observation.controlPlanePolicies.checkpointGuardian.nonce=checkpointGuardianSafeNonce.toString();

  const adapterNames=['riscZeroVerifier','riscZeroVerifierCodeHash','verifierSelector','imageId',
    'deploymentChainId','verifierConfigHash','PROOF_ACCEPTED'];
  const [finalizedAdapterValues,checkpointAdapterValues]=await Promise.all([
    Promise.all(adapterNames.map(name=>verifier[name](callOptions))),
    Promise.all(adapterNames.map(name=>checkpointVerifier[name](callOptions))),
  ]);
  const adapterObservation=(address,values)=>({address,
    riscZeroVerifier:values[0],riscZeroVerifierCodeHash:values[1],verifierSelector:values[2],
    imageId:values[3],deploymentChainId:values[4].toString(),verifierConfigHash:values[5],
    proofAccepted:values[6]});
  observation.finalizedBurnVerifier=adapterObservation(releaseConfig.verifier,finalizedAdapterValues);
  observation.checkpointVerifier=adapterObservation(releaseConfig.checkpointVerifier,checkpointAdapterValues);

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
      'domDomain','activationScheduleCommitment','governance','governanceCodeHash',
      'governanceImplementation','governanceImplementationCodeHash','governanceOwnersCommitment',
      'guardian','guardianCodeHash','guardianImplementation','guardianImplementationCodeHash',
      'guardianOwnersCommitment','withdrawalDelay','governanceDelay',
      'maxOutstanding','outflowCapacity','paused','pilotRestrictedDeployment','permissionlessDeposits',
      'pilotDepositConsumed','authorizedPilotDeposit','authorizedPilotSnapshot',
      'authorizedPilotValidUntil','pilotAuthorizationGeneration','permissionlessDepositsReadyAt',
      'depositsClosed','gracefullyShutdown','resumeReadyAt',
      'totalDeposited','totalReleased','outstanding',
      'unreservedCollateral','availableOutflow','totalProvedDebtAmount','controlPlaneHealthy'];
    const [values,pendingQueue]=await Promise.all([
      Promise.all(names.map(name=>reserve[name](callOptions))),reserve.pendingQueueSnapshot(callOptions),
    ]);
    observation.reserve=Object.fromEntries(names.map((name,index)=>[name,stringify(values[index])]));
    observation.reserve.pendingQueue={epoch:pendingQueue.epoch.toString(),count:pendingQueue.count.toString(),
      amount:pendingQueue.amount.toString(),firstBurnId:pendingQueue.firstBurnId,lastBurnId:pendingQueue.lastBurnId};
    const checkpointRegistry=new Contract(releaseConfig.checkpointRegistry,checkpointRegistryAbi,provider);
    const registryNames=['checkpointConfigHash','bridgeDomain','domNetworkMagic','domChainId','firstV4Height',
      'activationEmptyStateRoot','activationScheduleCommitment','checkpointInterval','confirmationDepth','challengePeriod',
      'verifier','verifierCodeHash','verifierConfigHash','guardian','guardianCodeHash',
      'guardianImplementation','guardianImplementationCodeHash','guardianOwnersCommitment','latestHeight',
      'checkpointCount','halted','gracefullyShutdown','latestIssuanceClosed','latestBlock','latestStateRoot',
      'latestContextHash','latestTotalDifficulty','latestTotalIssued','latestTotalBurned',
      'previousTotalIssued','previousTotalBurned','guardianControlHealthy'];
    const [registryValues,candidate,candidateIssuanceClosed,slot0]=await Promise.all([
      Promise.all(registryNames.map(name=>checkpointRegistry[name](callOptions))),
      checkpointRegistry.candidate(callOptions),
      checkpointRegistry.candidateIssuanceClosed(callOptions),
      provider.send('eth_getStorageAt',[releaseConfig.checkpointRegistry,'0x0',finalizedTag]),
    ]);
    observation.checkpointRegistry=Object.fromEntries(
      registryNames.map((name,index)=>[name,stringify(registryValues[index])]));
    observation.checkpointRegistryCandidate={statementHash:candidate.statementHash,
      height:candidate.height.toString(),readyAt:candidate.readyAt.toString(),blockHash:candidate.blockHash,
      stateRoot:candidate.stateRoot,contextHash:candidate.contextHash,
      totalDifficulty:candidate.totalDifficulty.toString(),
      totalIssued:candidate.totalIssued.toString(),totalBurned:candidate.totalBurned.toString(),
      issuanceClosed:Boolean(candidateIssuanceClosed),
      confirmationHeight:candidate.confirmationHeight.toString(),confirmationBlock:candidate.confirmationBlock,
      confirmationTotalDifficulty:candidate.confirmationTotalDifficulty.toString(),
      confirmationTimestamp:candidate.confirmationTimestamp.toString()};
    observation.checkpointRegistrySlot0=slot0;
  }
  const snapshotAfter=await provider.send('eth_getBlockByNumber',[finalizedTag,false]);
  const clientIdentityAfter=validateMainnetPreflightClientIdentity(
    await provider.send('web3_clientVersion',[]),rpcSource.clientPolicy);
  if(clientIdentityAfter!==clientIdentity) {
    throw new Error('RPC execution client identity changed during observation');
  }
  observation.snapshotBlockHashAfter=snapshotAfter?.hash??null;
  if(snapshotAfter?.timestamp!==finalized.timestamp) {
    throw new Error('RPC finalized timestamp changed during observation');
  }
  return {observation,timeSample:{sourceId:rpcSource.sourceId,
    finalizedTimestamp:finalized.timestamp,collectedBeforeMs,collectedAfterMs:Date.now()}};
  } finally {
    await provider.destroy();
  }
}

if (!['predeployment','postdeployment','authority-recheck'].includes(phase) || process.argv.length!==3) {
  console.error('Usage: USDOM_MAINNET_DEPLOYMENT_EVIDENCE_DIRECTORY=<absolute-path> node scripts/check-mainnet-preflight.mjs <predeployment|postdeployment|authority-recheck>');
  process.exitCode=2;
} else {
  try {
    const deploymentEvidence=await readDeploymentEvidence();
    [finalizedBurnVerifierDeploymentTransactionHash,
      checkpointVerifierDeploymentTransactionHash,
      deploymentTransactionHash,
      checkpointRegistryDeploymentTransactionHash]=deploymentEvidence.map(value=>value.hash);
    const preflightInputBytes=await readPreflightInputs();
    const [releaseConfig,riscZeroReference,rpcCatalog]=preflightInputBytes.map((value,index)=>
      parseStrictJsonBytes(value,{label:preflightInputPaths[index],
        maxBytes:1024*1024,maxDepth:64}));
    const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
    rpcSources=matchMainnetPreflightRpcSources(rpcCatalog,runtimeSources);
    const collected=await Promise.all(
      rpcSources.map(source=>observe(releaseConfig,riscZeroReference,source)),
    );
    validateMainnetPreflightTimeConsensus(collected.map(value=>value.timeSample));
    const observations=collected.map(value=>value.observation);
    const canonical=observations.map(value=>JSON.stringify(value));
    if(canonical.some(value=>value!==canonical[0])) {
      throw new Error('independent finalized RPC observations disagree');
    }
    const observation=observations[0];
    const report=assessMainnetPreflight({phase,releaseConfig,observation,riscZeroReference});
    const currentInputBytes=await readPreflightInputs();
    if(currentInputBytes.some((value,index)=>!value.equals(preflightInputBytes[index]))) {
      throw new Error('mainnet preflight inputs changed during observation');
    }
    await assertDeploymentEvidenceUnchanged(deploymentEvidence);
    console.log(JSON.stringify({...report,
      collectionStartedAtMs:Math.min(...collected.map(value=>value.timeSample.collectedBeforeMs)),
      collectionCompletedAtMs:Math.max(...collected.map(value=>value.timeSample.collectedAfterMs)),
      observation,rpcConsensus:rpcConsensusEvidence(rpcSources)},null,2));
    if (!report.ready) process.exitCode=1;
  } catch(error) {
    writePilotFailure('mainnet-preflight',error);
    process.exitCode=2;
  }
}

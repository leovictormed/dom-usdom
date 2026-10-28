import {AbiCoder,TypedDataEncoder,getAddress,keccak256,toUtf8Bytes} from 'ethers';

export const CHECKPOINT_BOOTSTRAP_RATIFICATION_OBSERVATION_SCHEMA=
  'usdom-checkpoint-bootstrap-ratification-observation-v1';
export const CHECKPOINT_BOOTSTRAP_RATIFICATION_REPORT_SCHEMA=
  'usdom-checkpoint-bootstrap-ratification-report-v1';
export const CHECKPOINT_BOOTSTRAP_RATIFICATION_TYPE=
  'USDOMCheckpointBootstrapRatification(bytes32 releaseIdHash,bytes20 sourceCommit,bytes32 sourceTagHash,uint256 ethereumChainId,address governance,bytes32 reserveConfigHash,bytes32 checkpointRegistryConfigHash,bytes32 activationScheduleCommitment,bytes32 ethereumCheckpointRoot,bytes32 ethereumSourceSetCommitment,bytes32 domChainId,uint64 firstV4Height)';
export const CHECKPOINT_BOOTSTRAP_RATIFICATION_TYPEHASH=keccak256(
  toUtf8Bytes(CHECKPOINT_BOOTSTRAP_RATIFICATION_TYPE));
const abi=AbiCoder.defaultAbiCoder();
const hash=/^0x[0-9a-f]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const address=/^0x[0-9a-fA-F]{40}$/;
const identifier=/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const consensusFields=['schema','network','checkpointEpoch','checkpointSlot','checkpointRoot',
  'sourceCount','sourceSetCommitment','observedAtUnix'];
const nativeFields=['schema','nativeEthereumTrustedCheckpoint','domDomain','checkpointDomNetworkMagic',
  'checkpointDomChainId','checkpointFirstV4Height','checkpointIntervalBlocks',
  'checkpointConfirmationDepthBlocks','checkpointChallengePeriodSeconds','checkpointInitialHeight',
  'checkpointInitialBlock','checkpointInitialContextHash','checkpointInitialTotalDifficulty'];
const observationFields=['schema','releaseId','sourceCommit','sourceTag','ethereumChainId','governance',
  'ratificationDigest','snapshotBlockNumber','snapshotBlockHash','snapshotBlockTimestamp',
  'sourceSetCommitment','approvals'];
const approvalFields=['operatorId','originKeccak256','snapshotBlockNumber','snapshotBlockHash','snapshotBlockTimestamp',
  'governanceCodeHash','eip1271MagicValue','observedAtUnix'];
const reportFields=['schema','status','releaseId','sourceCommit','sourceTag','ethereumChainId','governance',
  'governanceCodeHash','ratificationDigest','ethereumCheckpointRoot','ethereumCheckpointEpoch',
  'ethereumCheckpointSlot','checkpointSourceCount','checkpointSourceSetCommitment','domDomain',
  'domChainId','firstV4Height','reserveConfigHash','checkpointRegistryConfigHash',
  'activationScheduleCommitment','snapshotBlockNumber','snapshotBlockHash','snapshotBlockTimestamp',
  'ratificationSourceSetCommitment','approvalCount','approvals','rule'];

function fail(message) { throw new Error(message); }
function exact(value,fields,label) {
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==fields.length
      ||fields.some(field=>!(field in value))) fail(`${label} must use the exact supported schema`);
}
function bytes32(value,label) {
  if(!hash.test(value??'')||BigInt(value)===0n) fail(`${label} must be nonzero lowercase bytes32`);
  return value;
}
function decimal(value,bits,label,{nonzero=true}={}) {
  const maxDigits={8:3,64:20,128:39,256:78}[bits];
  if(maxDigits===undefined||typeof value!=='string'||value.length>maxDigits
      ||!/^(0|[1-9][0-9]*)$/.test(value)) fail(`${label} must be canonical decimal`);
  const parsed=BigInt(value);
  if((nonzero&&parsed===0n)||parsed>=(1n<<BigInt(bits))) fail(`${label} is outside uint${bits}`);
  return parsed;
}
function normalizedAddress(value,label) {
  if(!address.test(value??'')||BigInt(value)===0n) fail(`${label} must be a nonzero address`);
  return getAddress(value);
}
function stable(value) {
  if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,stable(value[key])]),
  );
  return value;
}

export function checkpointBootstrapRatificationCommitment({releaseEvidence,releaseConfig,
  checkpointConsensus,nativeFacts}={}) {
  if(!releaseEvidence||releaseEvidence.schema!==1||!identifier.test(releaseEvidence.releaseId??'')
      ||!identifier.test(releaseEvidence.sourceTag??'')||!commit.test(releaseEvidence.sourceCommit??'')) {
    fail('release provenance is invalid');
  }
  if(!releaseConfig||releaseConfig.ethereumChainId!=='1') fail('Ethereum mainnet release is required');
  exact(checkpointConsensus,consensusFields,'Ethereum checkpoint consensus');
  exact(nativeFacts,nativeFields,'native pre-activation facts');
  if(checkpointConsensus.schema!=='usdom-ethereum-checkpoint-consensus-v1'
      ||checkpointConsensus.network!=='ethereum-mainnet'
      ||nativeFacts.schema!=='usdom-native-preactivation-facts-v1') fail('bootstrap source schema is invalid');
  const epoch=decimal(checkpointConsensus.checkpointEpoch,64,'checkpointEpoch');
  if(decimal(checkpointConsensus.checkpointSlot,64,'checkpointSlot')!==epoch*32n
      ||decimal(checkpointConsensus.sourceCount,8,'sourceCount')<3n) fail('checkpoint consensus is insufficient');
  for(const field of ['reserveConfigHash','checkpointRegistryConfigHash','activationScheduleCommitment']) {
    bytes32(releaseConfig[field],field);
  }
  const trusted=bytes32(checkpointConsensus.checkpointRoot,'checkpointRoot');
  if(trusted!==releaseConfig.nativeEthereumTrustedCheckpoint
      ||trusted!==nativeFacts.nativeEthereumTrustedCheckpoint) fail('trusted checkpoint differs across release sources');
  if(nativeFacts.domDomain!==releaseConfig.domDomain
      ||nativeFacts.checkpointDomChainId!==releaseConfig.checkpointDomChainId
      ||nativeFacts.checkpointFirstV4Height!==releaseConfig.checkpointFirstV4Height) {
    fail('native checkpoint identity differs from release config');
  }
  for(const field of ['checkpointDomNetworkMagic','checkpointIntervalBlocks',
    'checkpointConfirmationDepthBlocks','checkpointChallengePeriodSeconds','checkpointInitialHeight',
    'checkpointInitialBlock','checkpointInitialContextHash','checkpointInitialTotalDifficulty']) {
    if(nativeFacts[field]!==releaseConfig[field]) fail(`${field} differs from release config`);
  }
  const first=decimal(nativeFacts.checkpointFirstV4Height,64,'checkpointFirstV4Height');
  return keccak256(abi.encode(
    ['bytes32','bytes32','bytes20','bytes32','uint256','address','bytes32','bytes32','bytes32','bytes32',
      'bytes32','bytes32','uint64'],
    [CHECKPOINT_BOOTSTRAP_RATIFICATION_TYPEHASH,keccak256(toUtf8Bytes(releaseEvidence.releaseId)),
      `0x${releaseEvidence.sourceCommit}`,keccak256(toUtf8Bytes(releaseEvidence.sourceTag)),1n,
      normalizedAddress(releaseConfig.governance,'governance'),releaseConfig.reserveConfigHash,
      releaseConfig.checkpointRegistryConfigHash,releaseConfig.activationScheduleCommitment,trusted,
      bytes32(checkpointConsensus.sourceSetCommitment,'sourceSetCommitment'),
      bytes32(nativeFacts.checkpointDomChainId,'checkpointDomChainId'),first]));
}

export function checkpointBootstrapRatificationTypedData(args={}) {
  const commitment=checkpointBootstrapRatificationCommitment(args);
  return TypedDataEncoder.getPayload({name:'USDOM Checkpoint Bootstrap Ratification',version:'1',
    chainId:1,verifyingContract:normalizedAddress(args.releaseConfig?.governance,'governance')},
  {CheckpointBootstrapRatification:[{name:'ratificationCommitment',type:'bytes32'}]},
  {ratificationCommitment:commitment});
}

export function checkpointBootstrapRatificationDigest(args={}) {
  const payload=checkpointBootstrapRatificationTypedData(args);
  const types={...payload.types}; delete types.EIP712Domain;
  return TypedDataEncoder.hash(payload.domain,types,payload.message);
}

export function buildCheckpointBootstrapRatificationReport({releaseEvidence,releaseConfig,
  checkpointConsensus,nativeFacts,observation}={}) {
  const digest=checkpointBootstrapRatificationDigest({releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts});
  exact(observation,observationFields,'checkpoint bootstrap ratification observation');
  if(observation.schema!==CHECKPOINT_BOOTSTRAP_RATIFICATION_OBSERVATION_SCHEMA
      ||observation.releaseId!==releaseEvidence.releaseId
      ||observation.sourceCommit!==releaseEvidence.sourceCommit
      ||observation.sourceTag!==releaseEvidence.sourceTag||observation.ethereumChainId!=='1'
      ||normalizedAddress(observation.governance,'observed governance')
        !==normalizedAddress(releaseConfig.governance,'governance')
      ||observation.ratificationDigest!==digest) fail('ratification observation release binding differs');
  const block=decimal(observation.snapshotBlockNumber,64,'snapshotBlockNumber');
  const timestamp=decimal(observation.snapshotBlockTimestamp,64,'snapshotBlockTimestamp');
  bytes32(observation.snapshotBlockHash,'snapshotBlockHash');
  bytes32(observation.sourceSetCommitment,'ratification sourceSetCommitment');
  if(!Array.isArray(observation.approvals)||observation.approvals.length<2
      ||observation.approvals.length>5) fail('at least two independent EIP-1271 observations are required');
  const ids=new Set(),origins=new Set();
  for(const [index,approval] of observation.approvals.entries()) {
    exact(approval,approvalFields,`ratification approval ${index+1}`);
    if(typeof approval.operatorId!=='string'||!identifier.test(approval.operatorId)
        ||ids.has(approval.operatorId)) fail('ratification operators must be distinct canonical identities');
    ids.add(approval.operatorId);
    const origin=bytes32(approval.originKeccak256,'approval originKeccak256');
    if(origins.has(origin)) fail('ratification RPC origins must be distinct');
    origins.add(origin);
    if(decimal(approval.snapshotBlockNumber,64,'approval snapshotBlockNumber')!==block
        ||bytes32(approval.snapshotBlockHash,'approval snapshotBlockHash')!==observation.snapshotBlockHash
        ||decimal(approval.snapshotBlockTimestamp,64,'approval snapshotBlockTimestamp')!==timestamp
        ||bytes32(approval.governanceCodeHash,'approval governanceCodeHash')
          !==bytes32(releaseConfig.governanceCodeHash,'governanceCodeHash')
        ||approval.eip1271MagicValue!=='0x1626ba7e') fail('independent EIP-1271 ratification observations disagree');
    const observed=decimal(approval.observedAtUnix,64,'approval observedAtUnix');
    if(observed<timestamp||observed-timestamp>86400n) fail('ratification observation is stale or predates snapshot');
  }
  const canonical=[...observation.approvals].sort((left,right)=>
    left.operatorId<right.operatorId?-1:left.operatorId>right.operatorId?1:0);
  if(observation.approvals.some((approval,index)=>approval.operatorId!==canonical[index].operatorId)) {
    fail('ratification approvals must use canonical operator order');
  }
  const expectedSourceSet=keccak256(toUtf8Bytes(
    `USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES_V1\n${canonical.map(approval=>
      `${approval.operatorId}\u0000${approval.originKeccak256}`).join('\n')}`));
  if(observation.sourceSetCommitment!==expectedSourceSet) fail('ratification source set commitment differs');
  const checkpointObserved=decimal(checkpointConsensus.observedAtUnix,64,'checkpoint observedAtUnix');
  if(timestamp<checkpointObserved||timestamp-checkpointObserved>30n*86400n) {
    fail('ratification snapshot is outside the checkpoint ratification window');
  }
  return Object.freeze({schema:CHECKPOINT_BOOTSTRAP_RATIFICATION_REPORT_SCHEMA,status:'ratified',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    sourceTag:releaseEvidence.sourceTag,ethereumChainId:'1',governance:getAddress(releaseConfig.governance),
    governanceCodeHash:releaseConfig.governanceCodeHash,ratificationDigest:digest,
    ethereumCheckpointRoot:checkpointConsensus.checkpointRoot,
    ethereumCheckpointEpoch:checkpointConsensus.checkpointEpoch,
    ethereumCheckpointSlot:checkpointConsensus.checkpointSlot,
    checkpointSourceCount:checkpointConsensus.sourceCount,
    checkpointSourceSetCommitment:checkpointConsensus.sourceSetCommitment,
    domDomain:nativeFacts.domDomain,domChainId:nativeFacts.checkpointDomChainId,
    firstV4Height:nativeFacts.checkpointFirstV4Height,
    reserveConfigHash:releaseConfig.reserveConfigHash,
    checkpointRegistryConfigHash:releaseConfig.checkpointRegistryConfigHash,
    activationScheduleCommitment:releaseConfig.activationScheduleCommitment,
    snapshotBlockNumber:observation.snapshotBlockNumber,snapshotBlockHash:observation.snapshotBlockHash,
    snapshotBlockTimestamp:observation.snapshotBlockTimestamp,
    ratificationSourceSetCommitment:observation.sourceSetCommitment,
    approvalCount:observation.approvals.length.toString(),approvals:structuredClone(observation.approvals),
    rule:'The exact release bootstrap is ratified only when independent finalized RPC observations return EIP-1271 magic for this digest and identical governance code and snapshot.',
  });
}

export function serializeCheckpointBootstrapRatificationReport(report) {
  return Buffer.from(`${JSON.stringify(stable(report),null,2)}\n`);
}

export function validateCheckpointBootstrapRatificationReport({report,releaseEvidence,releaseConfig,
  checkpointConsensus,nativeFacts}={}) {
  exact(report,reportFields,'checkpoint bootstrap ratification report');
  if(report.schema!==CHECKPOINT_BOOTSTRAP_RATIFICATION_REPORT_SCHEMA||report.status!=='ratified') {
    fail('checkpoint bootstrap ratification report status or schema is invalid');
  }
  const observation={schema:CHECKPOINT_BOOTSTRAP_RATIFICATION_OBSERVATION_SCHEMA,
    releaseId:report.releaseId,sourceCommit:report.sourceCommit,sourceTag:report.sourceTag,
    ethereumChainId:report.ethereumChainId,governance:report.governance,
    ratificationDigest:report.ratificationDigest,snapshotBlockNumber:report.snapshotBlockNumber,
    snapshotBlockHash:report.snapshotBlockHash,snapshotBlockTimestamp:report.snapshotBlockTimestamp,
    sourceSetCommitment:report.ratificationSourceSetCommitment,approvals:structuredClone(report.approvals)};
  const expected=buildCheckpointBootstrapRatificationReport({releaseEvidence,releaseConfig,
    checkpointConsensus,nativeFacts,observation});
  if(JSON.stringify(stable(report))!==JSON.stringify(stable(expected))) {
    fail('checkpoint bootstrap ratification report is not the canonical release-bound report');
  }
  return true;
}

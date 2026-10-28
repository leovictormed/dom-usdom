const decimal=value=>typeof value==='string'&&value.length<=78
  &&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<(1n<<256n);
const uint64=value=>typeof value==='string'&&value.length<=20
  &&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<(1n<<64n);
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const address=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{40}$/.test(value);
const hash32=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{64}$/.test(value);
const baselineFields=['schema','chainId','packageSha256','token','reserve','recipient',
  'recipientBalanceBaseUnits','reserveBalanceBaseUnits','totalReleasedBaseUnits',
  'outstandingBaseUnits','totalProvedDebtBaseUnits','observedAt','rpcCount',
  'snapshotBlockNumber','snapshotBlockHash'];
const executionFields=['schema','chainId','packageSha256','burnId','requestId','amountBaseUnits',
  'token','recipient','payoutBaselineSha256','recipientBalanceBefore','recipientBalanceAfter',
  'reserveBalanceBefore','reserveBalanceAfter','totalReleasedBefore','totalReleasedAfter',
  'outstandingBefore','outstandingAfter','totalProvedDebtBefore','totalProvedDebtAfter','steps',
  'finalizedAcrossRpcCount','outputLast','executeFinalitySha256','snapshotBlockNumber','snapshotBlockHash'];
const finalityFields=['schema','transactionHash','blockNumber','blockHash','transactionIndex',
  'finalizedRpcCount','gasUsed','effectiveGasPrice','actualCost','maximumCost'];
const exact=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort());
export function validateClosedMainnetPayoutEvidence({baseline,baselineSha256,packageSha256,
  execution,packageValue,packageBytes,baselineBytes,executionBytes,submission,submissionBytes,
  executeFinality,executeFinalityBytes,executeFinalitySha256,release,releaseBytes,releaseConfigSha256,
  verifierManifestBytes,verifierManifestSha256}) {
  const bind=(value,bytes,digest,label)=>{
    if(!Buffer.isBuffer(bytes)||createHash('sha256').update(bytes).digest('hex')!==digest
        ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64,
          maxNodes:100_000,maxStringBytes:4*1024*1024,maxObjectEntries:10_000,
          maxArrayEntries:10_000}))!==JSON.stringify(value)) {
      throw new Error(`${label} bytes differ from terminal evidence authority`);
    }
  };
  bind(packageValue,packageBytes,packageSha256,'closed redemption package');
  bind(baseline,baselineBytes,baselineSha256,'closed redemption payout baseline');
  bind(execution,executionBytes,createHash('sha256').update(executionBytes??Buffer.alloc(0)).digest('hex'),
    'closed redemption payout execution');
  bind(executeFinality,executeFinalityBytes,executeFinalitySha256,'closed redemption execute finality');
  if(!Buffer.isBuffer(verifierManifestBytes)
      ||createHash('sha256').update(verifierManifestBytes).digest('hex')!==verifierManifestSha256) {
    throw new Error('finalized burn verifier bytes differ from terminal evidence authority');
  }
  validateClosedMainnetRedemptionPackage(packageValue,submission);
  validateClosedMainnetRedemptionRelease({submission,packageValue,release,submissionBytes,
    packageBytes,releaseBytes,releaseConfigSha256,verifierManifestSha256});
  if(!packageValue||packageValue.ethereumChainId!=='1'||packageValue.amountBaseUnits!=='1000000'
      ||packageValue.broadcastAuthorized!==false||!address(packageValue.token)||!raw32(packageSha256)) {
    throw new Error('closed redemption package binding is required');
  }
  if(!exact(baseline,baselineFields)
      ||baseline.schema!=='usdom-closed-mainnet-redemption-payout-baseline-v1'
      ||baseline.chainId!=='1'||baseline.observedAt!=='finalized'||baseline.rpcCount!==2
      ||!uint64(baseline.snapshotBlockNumber)||!hash32(baseline.snapshotBlockHash)
      ||!raw32(baseline.packageSha256)||!address(baseline.token)||!address(baseline.recipient)
      ||!address(baseline.reserve)
      ||!['recipientBalanceBaseUnits','reserveBalanceBaseUnits','totalReleasedBaseUnits','outstandingBaseUnits','totalProvedDebtBaseUnits'].every(field=>decimal(baseline[field]))
      ||baseline.packageSha256!==packageSha256||baseline.totalProvedDebtBaseUnits!=='1000000'
      ||!raw32(baselineSha256)) {
    throw new Error('closed redemption payout baseline is invalid');
  }
  if(baseline.reserve.toLowerCase()!==packageValue.reserve.toLowerCase()
      ||baseline.recipient.toLowerCase()!==packageValue.recipient.toLowerCase()
      ||baseline.token.toLowerCase()!==packageValue.token.toLowerCase()) {
    throw new Error('closed redemption payout baseline belongs to another package');
  }
  if(!exact(execution,executionFields)
      ||execution.schema!=='usdom-closed-mainnet-redemption-execution-v2'
      ||execution.packageSha256!==baseline.packageSha256
      ||execution.payoutBaselineSha256!==baselineSha256
      ||execution.token?.toLowerCase()!==baseline.token.toLowerCase()
      ||execution.recipient?.toLowerCase()!==baseline.recipient.toLowerCase()
      ||execution.recipientBalanceBefore!==baseline.recipientBalanceBaseUnits
      ||!decimal(execution.recipientBalanceAfter)
      ||BigInt(execution.recipientBalanceAfter)!==BigInt(execution.recipientBalanceBefore)+1_000_000n
      ||execution.reserveBalanceBefore!==baseline.reserveBalanceBaseUnits
      ||execution.totalReleasedBefore!==baseline.totalReleasedBaseUnits
      ||execution.outstandingBefore!==baseline.outstandingBaseUnits
      ||execution.totalProvedDebtBefore!==baseline.totalProvedDebtBaseUnits
      ||!decimal(execution.reserveBalanceAfter)||!decimal(execution.totalReleasedAfter)||!decimal(execution.outstandingAfter)
      ||!decimal(execution.totalProvedDebtAfter)
      ||BigInt(execution.reserveBalanceAfter)!==BigInt(execution.reserveBalanceBefore)-1_000_000n
      ||BigInt(execution.totalReleasedAfter)!==BigInt(execution.totalReleasedBefore)+1_000_000n
      ||BigInt(execution.outstandingAfter)!==BigInt(execution.outstandingBefore)-1_000_000n
      ||BigInt(execution.totalProvedDebtAfter)!==BigInt(execution.totalProvedDebtBefore)-1_000_000n
      ||execution.chainId!=='1'||execution.steps!==2
      ||execution.burnId!==packageValue.burnId||execution.requestId!==packageValue.requestId
      ||execution.amountBaseUnits!=='1000000'||execution.finalizedAcrossRpcCount!==2
      ||!uint64(execution.snapshotBlockNumber)||!hash32(execution.snapshotBlockHash)
      ||BigInt(execution.snapshotBlockNumber)<=BigInt(baseline.snapshotBlockNumber)
      ||execution.outputLast!==true) throw new Error('closed redemption payout delta is invalid');
  if(!exact(executeFinality,finalityFields)
      ||executeFinality.schema!=='usdom-closed-mainnet-redemption-finality-v2'
      ||!hash32(executeFinality.transactionHash)||!uint64(executeFinality.blockNumber)
      ||!hash32(executeFinality.blockHash)||!uint64(executeFinality.transactionIndex)
      ||executeFinality.finalizedRpcCount!==2
      ||!['gasUsed','effectiveGasPrice','actualCost','maximumCost'].every(field=>decimal(executeFinality[field]))
      ||!raw32(executeFinalitySha256)||execution.executeFinalitySha256!==executeFinalitySha256
      ||BigInt(executeFinality.blockNumber)<=BigInt(baseline.snapshotBlockNumber)
      ||BigInt(execution.snapshotBlockNumber)<BigInt(executeFinality.blockNumber)
      ||(execution.snapshotBlockNumber===executeFinality.blockNumber
        &&execution.snapshotBlockHash.toLowerCase()!==executeFinality.blockHash.toLowerCase())) {
    throw new Error('closed redemption execute finality authority is invalid');
  }
  return execution;
}
import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {validateClosedMainnetRedemptionPackage} from './closed-mainnet-redemption-execution.mjs';
import {validateClosedMainnetRedemptionRelease} from './closed-mainnet-redemption-release.mjs';

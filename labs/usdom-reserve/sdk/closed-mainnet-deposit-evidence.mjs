const decimal=value=>typeof value==='string'&&value.length<=78
  &&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<1n<<256n;
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const address=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{40}$/.test(value);
const baselineFields=['schema','chainId','packageSha256','funder','token','reserve',
  'funderBalanceBaseUnits','reserveBalanceBaseUnits','totalDepositedBaseUnits',
  'outstandingBaseUnits','allowanceBaseUnits','observedAt','rpcCount'];
baselineFields.push('snapshotBlockNumber','snapshotBlockHash');
const executionFields=['schema','packageSha256','chainId','steps','amountBaseUnits',
  'financialBaselineSha256','funderBalanceBefore','funderBalanceAfter','reserveBalanceBefore',
  'reserveBalanceAfter','totalDepositedBefore','totalDepositedAfter','outstandingBefore',
  'outstandingAfter','allowanceBefore','allowanceAfter','outputLast','transactionHashes',
  'depositFinalitySha256','snapshotBlockNumber','snapshotBlockHash'];
const finalityFields=['schema','transactionHash','blockNumber','blockHash','transactionIndex',
  'finalizedRpcCount','gasUsed','effectiveGasPrice','actualCost','maximumCost'];
const exact=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...fields].sort());
export function validateClosedMainnetDepositEvidence({baseline,baselineSha256,packageSha256,
  execution,packageValue,packageBytes,baselineBytes,executionBytes,depositFinality,
  depositFinalityBytes,depositFinalitySha256,...authority}) {
  const bind=(value,bytes,digest,label)=>{
    if(!Buffer.isBuffer(bytes)||createHash('sha256').update(bytes).digest('hex')!==digest
        ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64,
          maxNodes:100_000,maxStringBytes:4*1024*1024,maxObjectEntries:10_000,
          maxArrayEntries:10_000}))!==JSON.stringify(value)) {
      throw new Error(`${label} bytes differ from terminal evidence authority`);
    }
  };
  bind(packageValue,packageBytes,packageSha256,'closed deposit package');
  bind(baseline,baselineBytes,baselineSha256,'closed deposit baseline');
  const executionSha256=createHash('sha256').update(executionBytes??Buffer.alloc(0)).digest('hex');
  bind(execution,executionBytes,executionSha256,'closed deposit execution');
  bind(depositFinality,depositFinalityBytes,depositFinalitySha256,'closed deposit finality');
  validateClosedMainnetDepositAuthority({packageValue,...authority});
  if(!packageValue||packageValue.ethereumChainId!=='1'||packageValue.amountBaseUnits!=='1000000'
      ||packageValue.broadcastAuthorized!==false||packageValue.releaseConfigSha256===undefined
      ||!raw32(packageSha256)) {
    throw new Error('closed deposit package binding is required');
  }
  if(!exact(baseline,baselineFields)
      ||baseline.schema!=='usdom-closed-mainnet-deposit-financial-baseline-v2'
      ||baseline.chainId!=='1'||baseline.observedAt!=='finalized'||baseline.rpcCount!==2
      ||!raw32(baseline.packageSha256)||!address(baseline.funder)||!address(baseline.token)
      ||!address(baseline.reserve)||!raw32(baselineSha256)
      ||!uint64(baseline.snapshotBlockNumber)||!hash32(baseline.snapshotBlockHash)
      ||baseline.packageSha256!==packageSha256||baseline.allowanceBaseUnits!=='0'
      ||!['funderBalanceBaseUnits','reserveBalanceBaseUnits','totalDepositedBaseUnits','outstandingBaseUnits']
        .every(field=>decimal(baseline[field]))) throw new Error('closed deposit financial baseline is invalid');
  if(baseline.funder.toLowerCase()!==packageValue.funder.toLowerCase()
      ||baseline.token.toLowerCase()!==packageValue.token.toLowerCase()
      ||baseline.reserve.toLowerCase()!==packageValue.reserve.toLowerCase()) {
    throw new Error('closed deposit financial baseline belongs to another package');
  }
  const pairs=[['funderBalanceBefore','funderBalanceAfter',-1_000_000n],
    ['reserveBalanceBefore','reserveBalanceAfter',1_000_000n],
    ['totalDepositedBefore','totalDepositedAfter',1_000_000n],
    ['outstandingBefore','outstandingAfter',1_000_000n]];
  if(!exact(execution,executionFields)
      ||execution.schema!=='usdom-closed-mainnet-deposit-execution-v3'
      ||execution.packageSha256!==baseline.packageSha256||execution.financialBaselineSha256!==baselineSha256
      ||execution.chainId!=='1'||execution.steps!==3||execution.amountBaseUnits!=='1000000'
      ||execution.allowanceBefore!=='0'||execution.allowanceAfter!=='0'||execution.outputLast!==true
      ||!Array.isArray(execution.transactionHashes)||execution.transactionHashes.length!==3
      ||execution.transactionHashes.some(value=>typeof value!=='string'||!/^0x[0-9a-f]{64}$/.test(value))
      ||new Set(execution.transactionHashes).size!==3) {
    throw new Error('closed deposit execution identity is invalid');
  }
  const balanceFields=['funderBalanceBaseUnits','reserveBalanceBaseUnits','totalDepositedBaseUnits','outstandingBaseUnits'];
  for(let index=0;index<pairs.length;index++) {
    const [before,after,delta]=pairs[index];
    if(!decimal(execution[before])||!decimal(execution[after])
        ||execution[before]!==baseline[balanceFields[index]]
        ||BigInt(execution[after])!==BigInt(execution[before])+delta) {
      throw new Error('closed deposit exact financial delta is invalid');
    }
  }
  if(!exact(depositFinality,finalityFields)
      ||depositFinality.schema!=='usdom-closed-mainnet-deposit-finality-v2'
      ||!hash32(depositFinality.transactionHash)||!uint64(depositFinality.blockNumber)
      ||!hash32(depositFinality.blockHash)||!uint64(depositFinality.transactionIndex)
      ||depositFinality.finalizedRpcCount!==2
      ||!['gasUsed','effectiveGasPrice','actualCost','maximumCost'].every(field=>decimal(depositFinality[field]))
      ||!raw32(depositFinalitySha256)||execution.depositFinalitySha256!==depositFinalitySha256
      ||execution.transactionHashes[2]!==depositFinality.transactionHash
      ||!uint64(execution.snapshotBlockNumber)||!hash32(execution.snapshotBlockHash)
      ||BigInt(depositFinality.blockNumber)<=BigInt(baseline.snapshotBlockNumber)
      ||BigInt(execution.snapshotBlockNumber)<BigInt(depositFinality.blockNumber)
      ||(execution.snapshotBlockNumber===depositFinality.blockNumber
        &&execution.snapshotBlockHash.toLowerCase()!==depositFinality.blockHash.toLowerCase())) {
    throw new Error('closed deposit finality authority is invalid');
  }
  return execution;
}
import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {validateClosedMainnetDepositAuthority} from './closed-mainnet-deposit-execution.mjs';
const uint64=value=>typeof value==='string'&&value.length<=20&&/^(0|[1-9][0-9]*)$/.test(value)
  &&BigInt(value)<(1n<<64n);
const hash32=value=>typeof value==='string'&&/^0x[0-9a-fA-F]{64}$/.test(value);

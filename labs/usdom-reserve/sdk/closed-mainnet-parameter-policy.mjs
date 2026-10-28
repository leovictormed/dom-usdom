import {closeSync,constants,fstatSync,openSync,readFileSync,statSync} from 'node:fs';
import {getAddress} from 'ethers';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {LIMITED_MAINNET_POLICY} from './limited-mainnet-policy.mjs';
import {
  PILOT_DEPOSIT_TRANSACTION_CAP_WEI,PILOT_REDEMPTION_TRANSACTION_CAP_WEI,
  PILOT_DEPOSIT_CUMULATIVE_CAP_WEI,PILOT_REDEMPTION_CUMULATIVE_CAP_WEI,
  PILOT_TOTAL_CUMULATIVE_CAP_WEI,
} from './closed-mainnet-pilot-budget.mjs';
import {
  MAINNET_DEPLOYMENT_MAX_GAS_LIMIT,MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT,
  MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS,MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST,
  MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST,
} from './mainnet-deployment-execution.mjs';

const expected={
  schema:'usdom-closed-mainnet-pilot-parameter-policy-v1',
  ethereum:{chainId:'1',token:'0xdAC17F958D2ee523a2206206994597C13D831ec7',tokenDecimals:'6',pilotAmountBaseUnits:'1000000'},
  reserve:{maxOutstandingBaseUnits:LIMITED_MAINNET_POLICY.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerRefillPeriod:LIMITED_MAINNET_POLICY.outflowCapacityBaseUnitsPerDay,
    refillPeriodSeconds:'86400',withdrawalDelaySeconds:LIMITED_MAINNET_POLICY.withdrawalDelaySeconds,
    governanceDelaySeconds:LIMITED_MAINNET_POLICY.governanceDelaySeconds,
    maximumCertificateLifetimeSeconds:'604800',minimumExecutionWindowSeconds:'3600',
    maximumFinalityAgeSlots:'50400',ethereumSecondsPerSlot:'12'},
  nativeFinality:{relaySafetyMarginSeconds:LIMITED_MAINNET_POLICY.nativeRelaySafetyMarginSeconds,
    maximumEthereumAnchorAgeSeconds:LIMITED_MAINNET_POLICY.nativeMaxEthereumAnchorAgeSeconds,
    maximumDomClockLeadSeconds:LIMITED_MAINNET_POLICY.nativeMaxDomClockLeadSeconds,
    checkpointIntervalBlocks:'360',confirmationDepthBlocks:'30',maximumCheckpointSpanBlocks:'390',challengePeriodSeconds:'172800'},
  proof:{maximumProofBytes:'260',verifierGasLimit:'5000000',maximumPruneBatch:'256'},
  safe:{roleCount:'3',ownersPerRole:'3',thresholdPerRole:'2',minimumDistinctOwnersAcrossRoles:'9'},
  transactionGas:{tokenCallGasLimit:'500000',registryCallGasLimit:'100000',controlPlaneCallGasLimit:'50000',
    depositGasLimit:'500000',redemptionGasLimit:'2500000',maximumFeePerGasWei:MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS.toString(),
    deploymentMaximumGasLimit:MAINNET_DEPLOYMENT_MAX_GAS_LIMIT.toString(),
    deploymentSequenceMaximumGasLimit:MAINNET_DEPLOYMENT_SEQUENCE_MAX_GAS_LIMIT.toString(),
    deploymentMaximumTransactionCostWei:MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST.toString(),
    deploymentMaximumSequenceCostWei:MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST.toString()},
  pilotBudget:{depositTransactionCapWei:PILOT_DEPOSIT_TRANSACTION_CAP_WEI.toString(),
    depositCumulativeCapWei:PILOT_DEPOSIT_CUMULATIVE_CAP_WEI.toString(),depositMaximumTransactions:'3',
    redemptionTransactionCapWei:PILOT_REDEMPTION_TRANSACTION_CAP_WEI.toString(),
    redemptionCumulativeCapWei:PILOT_REDEMPTION_CUMULATIVE_CAP_WEI.toString(),redemptionMaximumTransactions:'2',
    totalCumulativeCapWei:PILOT_TOTAL_CUMULATIVE_CAP_WEI.toString()},
  capacityAcceptance:{releaseSpecificEvidenceRequired:true,syntheticOrExampleMeasurementsAccepted:false,authorizationImplied:false},
};

export const CLOSED_MAINNET_PARAMETER_POLICY=Object.freeze(expected);

export function validateClosedMainnetParameterPolicy(value) {
  if(JSON.stringify(value)!==JSON.stringify(expected)) throw new Error('closed-mainnet parameter policy differs from canonical exact values');
  if(getAddress(value.ethereum.token)!==getAddress(expected.ethereum.token)) throw new Error('USDT address mismatch');
  const r=value.reserve,n=value.nativeFinality,s=value.safe,b=value.pilotBudget;
  if(BigInt(r.outflowCapacityBaseUnitsPerRefillPeriod)>BigInt(r.maxOutstandingBaseUnits)
      ||BigInt(r.withdrawalDelaySeconds)+BigInt(r.minimumExecutionWindowSeconds)>BigInt(r.maximumCertificateLifetimeSeconds)
      ||BigInt(n.checkpointIntervalBlocks)+BigInt(n.confirmationDepthBlocks)!==BigInt(n.maximumCheckpointSpanBlocks)
      ||BigInt(s.thresholdPerRole)*3n<BigInt(s.ownersPerRole)*2n
      ||BigInt(s.minimumDistinctOwnersAcrossRoles)!==BigInt(s.roleCount)*BigInt(s.ownersPerRole)
      ||BigInt(b.depositTransactionCapWei)*BigInt(b.depositMaximumTransactions)!==BigInt(b.depositCumulativeCapWei)
      ||BigInt(b.redemptionTransactionCapWei)*BigInt(b.redemptionMaximumTransactions)!==BigInt(b.redemptionCumulativeCapWei)
      ||BigInt(b.depositCumulativeCapWei)+BigInt(b.redemptionCumulativeCapWei)!==BigInt(b.totalCumulativeCapWei)) {
    throw new Error('closed-mainnet parameter policy is internally inconsistent');
  }
  return true;
}

export function readAndValidateClosedMainnetParameterPolicy(path) {
  const descriptor=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  let bytes;
  try {
    const before=fstatSync(descriptor,{bigint:true}),named=statSync(path,{bigint:true,throwIfNoEntry:true});
    if(!before.isFile()||before.nlink!==1n||before.size<2n||before.size>1024n*1024n
        ||before.dev!==named.dev||before.ino!==named.ino) throw new Error('closed-mainnet parameter policy is not a bounded direct file');
    bytes=readFileSync(descriptor);const after=fstatSync(descriptor,{bigint:true}),namedAfter=statSync(path,{bigint:true,throwIfNoEntry:true});
    if(before.dev!==after.dev||before.ino!==after.ino||before.size!==after.size
        ||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs
        ||after.dev!==namedAfter.dev||after.ino!==namedAfter.ino||BigInt(bytes.length)!==before.size) {
      throw new Error('closed-mainnet parameter policy changed during captured read');
    }
  } finally {closeSync(descriptor);}
  const value=parseStrictJsonBytes(bytes,{
    label:'closed-mainnet parameter policy',maxDepth:16,
  });
  validateClosedMainnetParameterPolicy(value);
  return value;
}

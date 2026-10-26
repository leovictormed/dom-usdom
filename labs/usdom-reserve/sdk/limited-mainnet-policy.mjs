import {getAddress} from 'ethers';

export const LIMITED_MAINNET_POLICY=Object.freeze({
  withdrawalDelaySeconds:'86400',
  governanceDelaySeconds:'172800',
  maxOutstandingBaseUnits:'1000000',
  outflowCapacityBaseUnitsPerDay:'1000000',
  nativeRelaySafetyMarginSeconds:'3600',
  nativeMaxEthereumAnchorAgeSeconds:'1800',
  nativeMaxDomClockLeadSeconds:'7200',
});

const MAINNET_USDT=getAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7');

/** Fill only the fixed, bounded policy for the first isolated real-funds
 * mainnet pilot. This function cannot approve production, deployment or funds. */
export function materializeLimitedMainnetPolicy(releaseConfig) {
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)) {
    throw new Error('release configuration is required');
  }
  if(releaseConfig.productionReady!==false||releaseConfig.realFundsAuthorized!==false
      ||releaseConfig.ethereumChainId!=='1'||getAddress(releaseConfig.token)!==MAINNET_USDT) {
    throw new Error('limited pilot policy requires the unapproved Ethereum mainnet USDT template');
  }
  const result={...releaseConfig};
  for(const [field,value] of Object.entries(LIMITED_MAINNET_POLICY)) {
    if(result[field]!==null&&result[field]!==value) {
      throw new Error(`${field} already differs from the fixed limited pilot policy`);
    }
    result[field]=value;
  }
  if(result.productionReady!==false||result.realFundsAuthorized!==false) {
    throw new Error('limited pilot policy cannot change authorization');
  }
  return result;
}

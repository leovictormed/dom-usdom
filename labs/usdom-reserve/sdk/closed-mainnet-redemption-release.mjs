import {getAddress} from 'ethers';
import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const MAINNET_USDT=getAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7');
const bindJson=(value,bytes,label)=>{
  if(!Buffer.isBuffer(bytes)
      ||JSON.stringify(parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64}))
        !==JSON.stringify(value)) throw new Error(`${label} bytes differ from parsed authority`);
};
export function validateClosedMainnetRedemptionRelease({submission,packageValue,release,
  submissionBytes,packageBytes,releaseBytes,releaseConfigSha256,verifierManifestSha256}) {
  bindJson(submission,submissionBytes,'finalized burn submission');
  bindJson(packageValue,packageBytes,'closed redemption package');
  bindJson(release,releaseBytes,'proof reserve release configuration');
  if(!raw32(releaseConfigSha256)||!raw32(verifierManifestSha256)
      ||createHash('sha256').update(releaseBytes).digest('hex')!==releaseConfigSha256
      ||release?.ethereumChainId!=='1'||release.productionReady!==true
      ||release.realFundsAuthorized!==true||getAddress(release.token)!==MAINNET_USDT
      ||BigInt(getAddress(release.reserve))===0n||submission?.ethereumChainId!=='1'
      ||packageValue?.ethereumChainId!=='1'||submission.source?.releaseConfigSha256!==releaseConfigSha256
      ||submission.source?.verifierManifestSha256!==verifierManifestSha256
      ||getAddress(packageValue.reserve)!==getAddress(release.reserve)
      ||getAddress(packageValue.token)!==getAddress(release.token)
      ||getAddress(submission.to)!==getAddress(release.reserve)
      ||packageValue.statementHash!==submission.statementHash
      ||packageValue.submissionDataKeccak256!==submission.dataKeccak256
      ||packageValue.broadcastAuthorized!==false||submission.broadcastAuthorized!==false) {
    throw new Error('closed redemption is stale or foreign to the current release');
  }
  return {ethereumChainId:'1',reserve:getAddress(release.reserve),token:getAddress(release.token),
    releaseConfigSha256,verifierManifestSha256};
}

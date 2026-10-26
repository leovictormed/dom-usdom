import {getAddress} from 'ethers';
const raw32=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
export function validateClosedMainnetRedemptionRelease({submission,packageValue,release,
  releaseConfigSha256,verifierManifestSha256}) {
  if(!raw32(releaseConfigSha256)||!raw32(verifierManifestSha256)
      ||release?.ethereumChainId!=='1'||submission?.ethereumChainId!=='1'
      ||packageValue?.ethereumChainId!=='1'||submission.source?.releaseConfigSha256!==releaseConfigSha256
      ||submission.source?.verifierManifestSha256!==verifierManifestSha256
      ||getAddress(packageValue.reserve)!==getAddress(release.reserve)
      ||getAddress(submission.to)!==getAddress(release.reserve)
      ||packageValue.statementHash!==submission.statementHash
      ||packageValue.submissionDataKeccak256!==submission.dataKeccak256
      ||packageValue.broadcastAuthorized!==false||submission.broadcastAuthorized!==false) {
    throw new Error('closed redemption is stale or foreign to the current release');
  }
  return {ethereumChainId:'1',reserve:getAddress(release.reserve),token:getAddress(release.token),
    releaseConfigSha256,verifierManifestSha256};
}

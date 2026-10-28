import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {validateClosedMainnetRedemptionRelease} from '../../sdk/closed-mainnet-redemption-release.mjs';
const raw=n=>n.repeat(64),hash=n=>'0x'+raw(n),reserve='0x'+'11'.repeat(20),
  token='0xdAC17F958D2ee523a2206206994597C13D831ec7';
function fixture(){
  const release={ethereumChainId:'1',reserve,token,productionReady:true,realFundsAuthorized:true};
  const releaseBytes=Buffer.from(JSON.stringify(release));
  const releaseConfigSha256=createHash('sha256').update(releaseBytes).digest('hex');
  const verifierManifestSha256=raw('b');
  const submission={ethereumChainId:'1',to:reserve,statementHash:hash('c'),dataKeccak256:hash('d'),
    source:{releaseConfigSha256,verifierManifestSha256},broadcastAuthorized:false};
  const packageValue={ethereumChainId:'1',reserve,token,statementHash:submission.statementHash,
    submissionDataKeccak256:submission.dataKeccak256,broadcastAuthorized:false};
  return {submission,submissionBytes:Buffer.from(JSON.stringify(submission)),packageValue,
    packageBytes:Buffer.from(JSON.stringify(packageValue)),release,releaseBytes,releaseConfigSha256,
    verifierManifestSha256};
}
test('redemption is bound again to the current release and verifier manifest',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetRedemptionRelease(value).reserve,reserve);
  for(const mutate of [v=>v.releaseConfigSha256=raw('e'),v=>v.verifierManifestSha256=raw('e'),
    v=>v.submission.source.releaseConfigSha256=raw('e'),v=>v.submission.source.verifierManifestSha256=raw('e'),
    v=>v.release.reserve='0x'+'33'.repeat(20),v=>v.packageValue.reserve='0x'+'33'.repeat(20),
    v=>v.packageValue.token='0x'+'33'.repeat(20),
    v=>v.packageValue.statementHash=hash('e'),v=>v.packageValue.submissionDataKeccak256=hash('e'),
    v=>v.packageValue.broadcastAuthorized=true,v=>v.release.ethereumChainId='31337',
    v=>v.release.productionReady=false,v=>v.release.realFundsAuthorized=false,
    v=>v.release.token='0x'+'33'.repeat(20),v=>v.release.reserve='0x'+'00'.repeat(20)]) {
    const changed=structuredClone(value); mutate(changed);
    changed.submissionBytes=value.submissionBytes; changed.packageBytes=value.packageBytes;
    changed.releaseBytes=value.releaseBytes;
    assert.throws(()=>validateClosedMainnetRedemptionRelease(changed));
  }
  const detached=structuredClone(value);
  detached.submissionBytes=value.submissionBytes; detached.packageBytes=value.packageBytes;
  detached.releaseBytes=value.releaseBytes;
  detached.packageValue.statementHash=hash('e');
  assert.throws(()=>validateClosedMainnetRedemptionRelease(detached),/bytes differ from parsed authority/);
});
test('executor checks current release before OneKey identity, nonce or publication',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  const gate=source.indexOf('check-closed-mainnet-redemption-release.mjs');
  assert.ok(gate>0); assert.ok(gate<source.indexOf('[[ -f $onekey_identity'));
  assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-closed-mainnet-redemption-release\.mjs/);
  assert.ok(gate<source.indexOf('read_nonce "$signer"')); assert.ok(gate<source.indexOf('publish-private-raw-transaction.mjs'));
  assert.match(source,/finalized-burn-verifier\.unconfigured\.json/);
  const checker=readFileSync(new URL('../../scripts/check-closed-mainnet-redemption-release.mjs',
    import.meta.url),'utf8');
  assert.match(checker,/readDirectFile/); assert.match(checker,/parseStrictJsonBytes/);
  assert.doesNotMatch(checker,/JSON\.parse|readFileSync/);
});

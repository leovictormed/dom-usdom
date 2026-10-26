import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateClosedMainnetRedemptionRelease} from '../../sdk/closed-mainnet-redemption-release.mjs';
const raw=n=>n.repeat(64),hash=n=>'0x'+raw(n),reserve='0x'+'11'.repeat(20),token='0x'+'22'.repeat(20);
function fixture(){
  const releaseConfigSha256=raw('a'),verifierManifestSha256=raw('b');
  const release={ethereumChainId:'1',reserve,token};
  const submission={ethereumChainId:'1',to:reserve,statementHash:hash('c'),dataKeccak256:hash('d'),
    source:{releaseConfigSha256,verifierManifestSha256},broadcastAuthorized:false};
  const packageValue={ethereumChainId:'1',reserve,statementHash:submission.statementHash,
    submissionDataKeccak256:submission.dataKeccak256,broadcastAuthorized:false};
  return {submission,packageValue,release,releaseConfigSha256,verifierManifestSha256};
}
test('redemption is bound again to the current release and verifier manifest',()=>{
  const value=fixture(); assert.equal(validateClosedMainnetRedemptionRelease(value).reserve,reserve);
  for(const mutate of [v=>v.releaseConfigSha256=raw('e'),v=>v.verifierManifestSha256=raw('e'),
    v=>v.submission.source.releaseConfigSha256=raw('e'),v=>v.submission.source.verifierManifestSha256=raw('e'),
    v=>v.release.reserve='0x'+'33'.repeat(20),v=>v.packageValue.reserve='0x'+'33'.repeat(20),
    v=>v.packageValue.statementHash=hash('e'),v=>v.packageValue.submissionDataKeccak256=hash('e'),
    v=>v.packageValue.broadcastAuthorized=true,v=>v.release.ethereumChainId='31337']) {
    const changed=structuredClone(value); mutate(changed);
    assert.throws(()=>validateClosedMainnetRedemptionRelease(changed));
  }
});
test('executor checks current release before Ledger identity, nonce or publication',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  const gate=source.indexOf('check-closed-mainnet-redemption-release.mjs');
  assert.ok(gate>0); assert.ok(gate<source.indexOf('cast wallet address --ledger'));
  assert.ok(gate<source.indexOf('cast nonce')); assert.ok(gate<source.indexOf('publish-private-raw-transaction.mjs'));
  assert.match(source,/finalized-burn-verifier\.unconfigured\.json/);
});

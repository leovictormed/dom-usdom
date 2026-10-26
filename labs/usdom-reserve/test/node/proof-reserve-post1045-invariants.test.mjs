import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url),'utf8');
test('post-1045 reserve retains economic, token and closure invariants',()=>{
  for(const signature of ['function deposit(','function queueWithdrawal(','function executeWithdrawal(']) {
    const start=source.indexOf(signature),end=source.indexOf('\n    function ',start+20);
    assert.match(source.slice(start,end),/nonReentrant/);
  }
  assert.match(source,/if \(depositsClosed\) revert DepositsClosed\(\)/);
  assert.match(source,/outstanding\(\) \+ amount > maxOutstanding/);
  assert.match(source,/burn\.amount > unreservedCollateral\(\)/);
  assert.match(source,/totalPendingAmount \+= burn\.amount/);
  assert.match(source,/totalReleased \+= burn\.amount/);
  assert.match(source,/_removePending\(burn\.burnId, pending\);[\s\S]*_callToken/);
  assert.match(source,/_tokenBalanceOf\(address\(this\)\) \+ burn\.amount != reserveBefore/);
  assert.match(source,/_tokenBalanceOf\(burn\.recipient\) != recipientBefore \+ burn\.amount/);
  for(const policy of ['paused','deprecated','basisPointsRate','maximumFee','isBlackListed']) {
    assert.ok(source.includes(`IUSDTPolicy.${policy}`));
  }
  assert.match(source,/returnSize != 0 && \(returnSize != 32 \|\| result != bytes32\(uint256\(1\)\)\)/);
  assert.match(source,/!depositsClosed \|\| paused \|\| totalDeposited != totalReleased/);
  assert.match(source,/latestTotalIssued[\s\S]*latestTotalBurned/);
  assert.match(source,/if \(!paused\) \{[\s\S]*\+\+queueEpoch;[\s\S]*pendingCount = 0;[\s\S]*totalPendingAmount = 0/);
  assert.match(source,/executeResume\(\)[\s\S]*_requireControlPlaneUnchanged\(\);[\s\S]*_requireVerifierUnchanged\(\);[\s\S]*_requireTokenUsable/);
});

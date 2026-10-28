import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const source=readFileSync(new URL('../../scripts/materialize-mainnet-preflight-attestation.mjs',import.meta.url),'utf8');

test('preflight attestation invalidates derived pointer and report before private input capture',()=>{
  const policy=source.indexOf('const policy=MAINNET_PREFLIGHT_MATERIALIZATION[phase]');
  const clear=source.indexOf('[policy.evidenceField]:null',policy);
  const clearInstall=source.indexOf('compareAndSwapReleaseEvidence(invalidated,currentEvidenceBytes)',clear);
  const removal=source.indexOf('removePrivateFileDurableIfExists(path.join(root,policy.evidencePath))',clearInstall);
  const secret=source.indexOf("path.join(accountHome,'usdom-mainnet-private/control-plane'",removal);
  const capture=source.indexOf('captureMainnetPreflightInputs(',secret);
  const report=source.indexOf('installEvidence(prepared.evidencePath',capture);
  const completion=source.indexOf('compareAndSwapReleaseEvidence(prepared.evidenceContent,snapshot.evidence)',report);
  for(const [name,position] of Object.entries({policy,clear,clearInstall,removal,secret,capture,report,completion})) {
    assert.notEqual(position,-1,`${name} step missing`);
  }
  assert.ok(policy<clear && clear<clearInstall && clearInstall<removal && removal<secret,
    'stale completion and report must be invalidated before the secret input path is used');
  assert.ok(secret<capture && capture<report && report<completion,
    'the regenerated report must be installed before its completion pointer');
});

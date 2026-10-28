import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {validateCheckpointRegistryArtifactPins} from '../../sdk/checkpoint-registry-artifact-pins.mjs';
import {validateCheckpointRandomxImageRatification} from '../../sdk/checkpoint-randomx-image-ratification.mjs';
import {validateCheckpointRestartWitnessReport} from '../../sdk/checkpoint-restart-witness-report.mjs';

const h='1'.repeat(64),x='0x'+h;
const reports=[
  [validateCheckpointRegistryArtifactPins,{schema:'usdom-checkpoint-registry-artifact-pins/v1',artifactPath:'out/DOMCheckpointRegistry.sol/DOMCheckpointRegistry.json',artifactSha256:h,releaseConfigPath:'config/proof-reserve.unconfigured.json',releaseConfigSha256:h,runtimeCodeHash:x,runtimeSize:1,initcodeHash:x,initcodeSize:1,checkpointRegistryConfigHash:x,compilerVersion:'solc',sourceCount:1}],
  [validateCheckpointRandomxImageRatification,{schema:'usdom-checkpoint-randomx-image-ratification/v1',imageId:h,imageIdPath:'../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid',imageIdFileSha256:h,receiptIndexPath:'evidence/randomx-receipt-set/randomx-receipt-set-index.json',receiptIndexSha256:h,receiptCount:1,randomxRelationsExecuted:true,receiptsVerified:true}],
  [validateCheckpointRestartWitnessReport,{schema:'usdom-checkpoint-restart-witness-live-exercise/v1',manifestSha256:h,witnessSha256:h,firstProcessPid:2,secondProcessPid:3,firstStartupAccepted:true,secondStartupAccepted:true,sameDataDirectory:true,checkpointWitnessRequired:true}],
];

test('every private readiness claim class rejects partial-prefix and generation-field substitution',()=>{
  for(const [validate,value] of reports) {
    assert.equal(validate(value),value);
    const extra={...value,oldGenerationAccepted:true};
    assert.throws(()=>validate(extra));
    const partial={...value}; delete partial[Object.keys(partial).at(-1)];
    assert.throws(()=>validate(partial));
  }
});

test('terminal pilot checker uses direct inode snapshots, complete prefixes and final recheck',async()=>{
  const source=await readFile(new URL('../../scripts/check-closed-mainnet-phase-artifacts.mjs',import.meta.url),'utf8');
  for(const token of ['O_NOFOLLOW','nlink!==1n','named.dev','named.ino','assertSnapshotsUnchanged()',
    'deposit receipt prefix has a hole','redemption receipt prefix has a hole',
    'deposit receipt/validation/finality set is incomplete',
    'redemption receipt/validation/finality set is incomplete',
    'receipt nonce sequence regressed or skipped']) assert.match(source,new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.doesNotMatch(source,/readFileSync\(submissionPath/);
});

test('readiness rebinds terminal reports to current authoritative bytes',async()=>{
  const source=await readFile(new URL('../../scripts/check-mainnet-readiness.mjs',import.meta.url),'utf8');
  for(const token of ['artifactBytes,releaseConfigBytes:releaseBytes',
    'imageIdFileSha256:createHash','receiptIndexSha256:createHash',
    'receiptBytes.push','checkpointRandomxImageRatificationAuthority',
    'checkpointRegistryArtifactPinsAuthority','checkpointRestartWitnessAuthority',
    'restart witness report differs from current manifest or witness bytes',
    'finalized-burn recursive completion differs from current bytes',
    'finalized-burn recursive completion receipt/index binding is stale',
    'finalized-burn recursive completion Groth16 receipt binding is stale',
    'buildAuthenticatedFinalizedBurnSubmission',
    'finalizedBurnSourceIndexSha256','finalizedBurnSourceInputSha256',
    'finalizedBurnEvmSealSha256','finalizedBurnGroth16ReceiptSha256',
    'releaseConfigSha256','verifierConfigSha256',
    'externalAuthorityFileBytes']) assert.match(source,new RegExp(token));
});

import test from 'node:test'; import assert from 'node:assert/strict'; import {readFile} from 'node:fs/promises'; import {createHash} from 'node:crypto';
import {buildCheckpointRandomxImageRatification,validateCheckpointRandomxImageRatification} from '../../sdk/checkpoint-randomx-image-ratification.mjs';
const h=c=>c.repeat(64),sha=v=>createHash('sha256').update(v).digest('hex'),receipt=Buffer.from('receipt-a');
const index={schema:'usdom-randomx-receipt-set-v1',randomx_receipt_image_id:h('1'),dev_mode:false,generates_proofs:true,mines:false,
  randomx_relations_executed:true,receipts_verified:true,receipt_count:1,receipts:[{index:0,receipt_file:'receipt.bin',receipt_sha256:sha(receipt),receipt_bytes:receipt.length}]};
test('RandomX ImageID ratification requires a positive matching receipt set',()=>{
 const imageIdBytes=Buffer.from(`${h('1')}\n`),indexBytes=Buffer.from(JSON.stringify(index));
 const report=buildCheckpointRandomxImageRatification({imageId:h('1'),imageIdFileSha256:sha(imageIdBytes),receiptIndexSha256:sha(indexBytes),receiptIndex:index});
 const authority={imageId:h('1'),imageIdBytes,receiptIndexBytes:indexBytes,receiptBytes:[receipt]};
 assert.equal(validateCheckpointRandomxImageRatification(report,authority),report);
 assert.throws(()=>buildCheckpointRandomxImageRatification({imageId:h('4'),imageIdFileSha256:h('2'),receiptIndexSha256:h('3'),receiptIndex:index}));
 assert.throws(()=>buildCheckpointRandomxImageRatification({imageId:h('1'),imageIdFileSha256:h('2'),receiptIndexSha256:h('3'),receiptIndex:{...index,receipts_verified:false}}));
 for(const field of ['imageId','imageIdFileSha256','receiptIndexSha256']) {
  assert.throws(()=>validateCheckpointRandomxImageRatification({...report,[field]:h('0')}));
 }
 assert.throws(()=>validateCheckpointRandomxImageRatification({...report,receiptIndexSha256:sha(Buffer.from('{}'))},authority));
 assert.throws(()=>validateCheckpointRandomxImageRatification(report,{...authority,receiptBytes:[Buffer.from('receipt-b')]}));
});
test('phase ratifies ImageID after proof and readiness consumes it',async()=>{
 const generator=await readFile(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
 const prove=generator.indexOf('prove:authenticated-randomx-receipt-set'),ratify=generator.indexOf('materialize:checkpoint-randomx-image-ratification');
 assert(prove>0&&ratify>prove);
 const readiness=await readFile(new URL('../../scripts/check-mainnet-readiness.mjs',import.meta.url),'utf8');
 assert.match(readiness,/USDOM_CHECKPOINT_RANDOMX_IMAGE_RATIFICATION/);
 assert.match(readiness,/buildCheckpointRandomxImageRatification/);
 assert.match(readiness,/ImageID file differs from the current checkpoint verifier configuration/);
 assert.match(readiness,/ratification differs from current receipt artifacts/);
 const materializer=await readFile(new URL('../../scripts/materialize-checkpoint-randomx-image-ratification.mjs',import.meta.url),'utf8');
 assert.match(materializer,/ImageID, receipt index or receipt changed during ratification/);
 assert.match(materializer,/receiptBytes\.push/);
 assert.match(materializer,/readDirectFile/);assert.match(materializer,/maximum:4\*1024\*1024/);
});

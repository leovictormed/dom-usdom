#!/usr/bin/env node
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {CHECKPOINT_RANDOMX_IMAGE_ID} from '../sdk/checkpoint-proof-capacity-report.mjs';
import {buildCheckpointRandomxImageRatification,validateCheckpointRandomxImageRatification} from '../sdk/checkpoint-randomx-image-ratification.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),repo=path.resolve(root,'../..');
if(process.argv.length!==2) throw new Error('fixed RandomX ImageID ratifier accepts no arguments');
const iidPath=path.join(repo,'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid');
const indexPath=path.join(root,'evidence/randomx-receipt-set/randomx-receipt-set-index.json');
const iid=await readDirectFile(iidPath,{minimum:65,maximum:256,label:'RandomX ImageID'});
if(iid.toString('ascii')!==CHECKPOINT_RANDOMX_IMAGE_ID+'\n') throw new Error('RandomX ImageID file differs from selected release ImageID');
const indexBytes=await readDirectFile(indexPath,{minimum:2,maximum:4*1024*1024,label:'RandomX receipt index'});
const index=parseStrictJsonBytes(indexBytes,{label:'RandomX receipt index',maxBytes:4*1024*1024,maxDepth:32});
const receiptPaths=[],receiptBytes=[];
for(const record of index.receipts??[]) {
  if(typeof record?.receipt_file!=='string'||!/^[A-Za-z0-9._-]+$/.test(record.receipt_file)) throw new Error('RandomX receipt index path is invalid');
  const receiptPath=path.join(path.dirname(indexPath),record.receipt_file);
  receiptPaths.push(receiptPath);
  receiptBytes.push(await readDirectFile(receiptPath,{minimum:1,maximum:64*1024*1024,label:'RandomX receipt'}));
}
const sha=b=>createHash('sha256').update(b).digest('hex');
const report=buildCheckpointRandomxImageRatification({imageId:CHECKPOINT_RANDOMX_IMAGE_ID,
  imageIdFileSha256:sha(iid),receiptIndexSha256:sha(indexBytes),receiptIndex:index});
validateCheckpointRandomxImageRatification(report,{imageIdBytes:iid,receiptIndexBytes:indexBytes,receiptBytes});
const target=process.env.USDOM_CHECKPOINT_RANDOMX_IMAGE_RATIFICATION;
if(typeof target!=='string'||!path.isAbsolute(target)) throw new Error('USDOM_CHECKPOINT_RANDOMX_IMAGE_RATIFICATION must be absolute');
await writePrivateFileDurableNewOrEqual(target,Buffer.from(JSON.stringify(report)+'\n'),{maximum:64*1024});
const [currentIid,currentIndex,...currentReceipts]=await Promise.all([
  readDirectFile(iidPath,{minimum:65,maximum:256,label:'RandomX ImageID'}),
  readDirectFile(indexPath,{minimum:2,maximum:4*1024*1024,label:'RandomX receipt index'}),
  ...receiptPaths.map(receiptPath=>readDirectFile(receiptPath,{minimum:1,maximum:64*1024*1024,label:'RandomX receipt'})),
]);
if(!currentIid.equals(iid)||!currentIndex.equals(indexBytes)
    ||currentReceipts.some((bytes,index)=>!bytes.equals(receiptBytes[index]))) {
  throw new Error('RandomX ImageID, receipt index or receipt changed during ratification');
}
process.stdout.write(`${JSON.stringify({schema:report.schema,path:target,imageId:report.imageId})}\n`);

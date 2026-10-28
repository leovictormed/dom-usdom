import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
const hex=/^[0-9a-f]{64}$/;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const nonzeroHex=value=>hex.test(value)&&value!=='0'.repeat(64);
const exact=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&JSON.stringify(Object.keys(v).sort())===JSON.stringify([...k].sort());
export function buildCheckpointRandomxImageRatification({imageId,imageIdFileSha256,receiptIndexSha256,receiptIndex}) {
  if(receiptIndex?.schema!=='usdom-randomx-receipt-set-v1'||receiptIndex.randomx_receipt_image_id!==imageId
      ||receiptIndex.randomx_relations_executed!==true||receiptIndex.receipts_verified!==true
      ||!Number.isSafeInteger(receiptIndex.receipt_count)||receiptIndex.receipt_count<1
      ||receiptIndex.receipt_count!==receiptIndex.receipts?.length) throw new Error('RandomX receipt index does not ratify the selected ImageID');
  const report={schema:'usdom-checkpoint-randomx-image-ratification/v1',imageId,
    imageIdPath:'../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid',imageIdFileSha256,
    receiptIndexPath:'evidence/randomx-receipt-set/randomx-receipt-set-index.json',receiptIndexSha256,
    receiptCount:receiptIndex.receipt_count,randomxRelationsExecuted:true,receiptsVerified:true};
  return validateCheckpointRandomxImageRatification(report);
}
export function validateCheckpointRandomxImageRatification(v,expected={}) {
  const keys=['schema','imageId','imageIdPath','imageIdFileSha256','receiptIndexPath','receiptIndexSha256',
    'receiptCount','randomxRelationsExecuted','receiptsVerified'];
  if(!exact(v,keys)||v.schema!=='usdom-checkpoint-randomx-image-ratification/v1'||!nonzeroHex(v.imageId)
      ||!nonzeroHex(v.imageIdFileSha256)||!nonzeroHex(v.receiptIndexSha256)||v.imageIdPath!=='../../crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid'
      ||v.receiptIndexPath!=='evidence/randomx-receipt-set/randomx-receipt-set-index.json'
      ||!Number.isSafeInteger(v.receiptCount)||v.receiptCount<1||v.randomxRelationsExecuted!==true||v.receiptsVerified!==true) throw new Error('RandomX ImageID ratification is invalid');
  for(const key of ['imageId','imageIdFileSha256','receiptIndexSha256']) if(expected[key]&&v[key]!==expected[key]) throw new Error(`RandomX ImageID ratification ${key} mismatch`);
  if(expected.reportBytes!==undefined) {
    if(!Buffer.isBuffer(expected.reportBytes)) throw new Error('RandomX ratification report authority bytes are invalid');
    const parsed=parseStrictJsonBytes(expected.reportBytes,{label:'RandomX ImageID ratification report',maxBytes:64*1024,maxDepth:8});
    if(JSON.stringify(parsed)!==JSON.stringify(v)) throw new Error('RandomX ratification report differs from authority bytes');
  }
  if(expected.imageIdBytes!==undefined||expected.receiptIndexBytes!==undefined||expected.receiptBytes!==undefined) {
    if(!Buffer.isBuffer(expected.imageIdBytes)||!Buffer.isBuffer(expected.receiptIndexBytes)
        ||!Array.isArray(expected.receiptBytes)||expected.receiptBytes.some(bytes=>!Buffer.isBuffer(bytes))) {
      throw new Error('RandomX ImageID ratification authority bytes are invalid');
    }
    if(expected.imageIdBytes.toString('ascii')!==`${v.imageId}\n`
        ||sha(expected.imageIdBytes)!==v.imageIdFileSha256||sha(expected.receiptIndexBytes)!==v.receiptIndexSha256) {
      throw new Error('RandomX ImageID ratification differs from authority bytes');
    }
    const index=parseStrictJsonBytes(expected.receiptIndexBytes,{label:'RandomX receipt index',maxBytes:4*1024*1024,maxDepth:32});
    if(index.schema!=='usdom-randomx-receipt-set-v1'||index.randomx_receipt_image_id!==v.imageId
        ||index.randomx_relations_executed!==true||index.receipts_verified!==true
        ||index.dev_mode!==false||index.generates_proofs!==true||index.mines!==false
        ||index.receipt_count!==v.receiptCount||index.receipt_count!==index.receipts?.length
        ||index.receipt_count!==expected.receiptBytes.length) throw new Error('RandomX receipt index authority is invalid');
    for(let i=0;i<index.receipts.length;i++) {
      const record=index.receipts[i],bytes=expected.receiptBytes[i];
      if(record?.index!==i||typeof record.receipt_file!=='string'||!/^[A-Za-z0-9._-]+$/.test(record.receipt_file)
          ||record.receipt_sha256!==sha(bytes)||record.receipt_bytes!==bytes.length||bytes.length<1) {
        throw new Error('RandomX receipt bytes differ from their index');
      }
    }
  }
  return v;
}

import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {buildAuthenticatedFinalizedBurnSubmission,proofReserveConfigurationFromRelease} from './finalized-burn-submission.mjs';
const h=/^0x[0-9a-f]{64}$/,d=/^[0-9a-f]{64}$/;
const fields={checkpointOuterReceiptSha256:'checkpointOuterReceipt',checkpointOuterReceiptIndexSha256:'checkpointOuterReceiptIndex',finalizedBurnReceiptSha256:'finalizedBurnReceipt',finalizedBurnReceiptIndexSha256:'finalizedBurnReceiptIndex',finalizedBurnProofIndexSha256:'finalizedBurnProofIndex',finalizedBurnSourceIndexSha256:'finalizedBurnSourceIndex',finalizedBurnSourceInputSha256:'finalizedBurnSourceInput',finalizedBurnEvmSealSha256:'finalizedBurnEvmSeal',finalizedBurnGroth16ReceiptSha256:'finalizedBurnGroth16Receipt',releaseConfigSha256:'releaseConfig',verifierConfigSha256:'verifierConfig'};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function validateFinalizedBurnRecursiveCompletion(v,authority) {
 const required=['schema',...Object.keys(fields),'checkpointOuterReceiptVerified','finalizedBurnReceiptVerified','evmReceiptVerified','adapterRuntimeCodeHash','adapterInitcodeHash','adapterConfigHash'];
 if(!v||JSON.stringify(Object.keys(v).sort())!==JSON.stringify(required.sort())||v.schema!=='usdom-finalized-burn-recursive-completion/v3'
   ||Object.keys(fields).some(x=>!d.test(v[x])||v[x]==='0'.repeat(64))
   ||['adapterRuntimeCodeHash','adapterInitcodeHash','adapterConfigHash'].some(x=>!h.test(v[x])||v[x]==='0x'+'0'.repeat(64))
   ||v.checkpointOuterReceiptVerified!==true||v.finalizedBurnReceiptVerified!==true||v.evmReceiptVerified!==true
   ||!authority||typeof authority!=='object'||Array.isArray(authority)) throw new Error('finalized-burn recursive completion is invalid');
 if(!Buffer.isBuffer(authority.completionBytes)
     ||JSON.stringify(parseStrictJsonBytes(authority.completionBytes,{label:'finalized-burn recursive completion',maxBytes:64*1024,maxDepth:8}))
       !==JSON.stringify(v)) throw new Error('finalized-burn recursive completion differs from authority bytes');
 for(const [field,name] of Object.entries(fields)) {
   const bytes=authority[name];
   if(!Buffer.isBuffer(bytes)||bytes.length===0||sha(bytes)!==v[field]) throw new Error(`finalized-burn recursive ${name} authority differs`);
 }
 const outer=parseStrictJsonBytes(authority.checkpointOuterReceiptIndex,{label:'outer receipt index',maxBytes:4*1024*1024,maxDepth:32});
 const receipt=parseStrictJsonBytes(authority.finalizedBurnReceiptIndex,{label:'burn receipt index',maxBytes:1024*1024,maxDepth:16});
 const proof=parseStrictJsonBytes(authority.finalizedBurnProofIndex,{label:'burn proof index',maxBytes:1024*1024,maxDepth:16});
 if(outer.outer_receipt_verified!==true||outer.dev_mode!==false||receipt.receipt_verified!==true
   ||receipt.dev_mode!==false||proof.receipt_verified!==true||proof.dev_mode!==false
   ||outer.receipt_file!=='checkpoint-outer-receipt.bin'||outer.receipt_sha256!==v.checkpointOuterReceiptSha256
   ||receipt.receipt_file!=='finalized-burn-receipt.bin'||receipt.receipt_sha256!==v.finalizedBurnReceiptSha256
   ||proof.groth16_receipt_file!=='finalized-burn-groth16-receipt.bin'
   ||proof.groth16_receipt_sha256!==v.finalizedBurnGroth16ReceiptSha256
   ||proof.groth16_receipt_bytes!==authority.finalizedBurnGroth16Receipt.length) {
   throw new Error('finalized-burn recursive receipt graph is invalid');
 }
 const release=parseStrictJsonBytes(authority.releaseConfig,{label:'reserve release',maxBytes:4*1024*1024,maxDepth:32});
 const config=parseStrictJsonBytes(authority.verifierConfig,{label:'verifier config',maxBytes:4*1024*1024,maxDepth:32});
 buildAuthenticatedFinalizedBurnSubmission({reserveConfiguration:proofReserveConfigurationFromRelease(release),
   verifierConfiguration:config,sourceIndex:authority.finalizedBurnSourceIndex,
   sourceInput:authority.finalizedBurnSourceInput,receiptIndex:authority.finalizedBurnReceiptIndex,
   proofIndex:authority.finalizedBurnProofIndex,evmSeal:authority.finalizedBurnEvmSeal,
   releaseConfigSha256:v.releaseConfigSha256});
 return v;
}

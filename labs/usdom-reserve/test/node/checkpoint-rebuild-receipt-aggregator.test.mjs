import test from 'node:test'; import assert from 'node:assert/strict';
import {createHash} from 'node:crypto'; import {mkdtemp,readFile,writeFile} from 'node:fs/promises';
import os from 'node:os'; import path from 'node:path'; import {spawnSync} from 'node:child_process';
const script=path.resolve(import.meta.dirname,'../../scripts/aggregate-checkpoint-rebuild-receipts.py');
const sha=value=>createHash('sha256').update(value).digest('hex');
async function fixture(mutator=()=>{}) {
 const root=await mkdtemp(path.join(os.tmpdir(),'receipt-aggregate-')); const old=process.cwd(); process.chdir(root);
 try {
  const predecessor=sha('predecessor'),receipt=Buffer.from('real receipt bytes'),receiptHash=sha(receipt);
  const program={schema:'usdom-rebuild-program-verification-v1',imageId:sha('image'),journal:sha('journal'),programBinarySha256:sha('program')};
  await writeFile('program.json',JSON.stringify(program));
  const verification={schema:'usdom-rebuild-receipt-verification-v1',receiptSha256:receiptHash,receiptBytes:receipt.length,methodImageId:program.imageId,journal:program.journal,predecessorSha256:predecessor,cryptographicallyVerified:true};
  await writeFile('receipt.bin',receipt); await writeFile('verified.json',JSON.stringify(verification));
  const index={schema:'usdom-rebuild-receipt-aggregation-v1',predecessorSha256:predecessor,receipts:[{receipt:'receipt.bin',verification:'verified.json',programVerification:'program.json',programVerificationSha256:sha(await readFile('program.json'))}]};
  mutator({index,verification,program}); await writeFile('index.json',JSON.stringify(index)); await writeFile('verified.json',JSON.stringify(verification)); await writeFile('program.json',JSON.stringify(program));
  index.receipts[0].programVerificationSha256=sha(await readFile('program.json')); await writeFile('index.json',JSON.stringify(index));
  const env={...process.env,USDOM_AUTHENTICATED_STAGE_INPUTS:JSON.stringify({'index.json':sha(await readFile('index.json'))}),USDOM_AUTHENTICATED_STAGE_OUTPUTS:JSON.stringify({'receipt.bin':receiptHash,'verified.json':sha(await readFile('verified.json'))})};
  return {root,env};
 } finally {process.chdir(old);}
}
const run=value=>spawnSync('/usr/bin/python3',[script,'index.json','aggregate.json'],{cwd:value.root,env:value.env,encoding:'utf8'});
test('aggregates only exact cryptographically verified receipt chain',async()=>{const value=await fixture();const result=run(value);assert.equal(result.status,0,result.stderr);const record=JSON.parse(await readFile(path.join(value.root,'aggregate.json')));assert.equal(record.claims.receiptsCryptographicallyVerified,true);});
test('rejects a self-declared cryptographic claim even with correct artifact hashes',async()=>{const value=await fixture(({verification})=>{verification.cryptographicallyVerified=false;});const result=run(value);assert.notEqual(result.status,0);assert.match(result.stderr,/does not bind the exact chain/);});
test('rejects cross-method receipt replay',async()=>{const value=await fixture(({verification})=>{verification.methodImageId=sha('other image');});const result=run(value);assert.notEqual(result.status,0);assert.match(result.stderr,/method\/journal differs/);});
test('rejects duplicate keys and floats in authenticated index and environment maps',async()=>{
 let value=await fixture();let raw=Buffer.from('{"schema":"usdom-rebuild-receipt-aggregation-v1","schema":"shadow"}');
 await writeFile(path.join(value.root,'index.json'),raw);value.env.USDOM_AUTHENTICATED_STAGE_INPUTS=JSON.stringify({'index.json':sha(raw)});
 let result=run(value);assert.notEqual(result.status,0);assert.match(result.stderr,/duplicate JSON key/);
 value=await fixture();value.env.USDOM_AUTHENTICATED_STAGE_INPUTS='{"index.json":"'+sha(await readFile(path.join(value.root,'index.json')))+'","x":1.0}';
 result=run(value);assert.notEqual(result.status,0);assert.match(result.stderr,/AUTHENTICATED_STAGE_INPUTS is invalid/);
});

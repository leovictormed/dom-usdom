import path from 'node:path';
import process from 'node:process';
import {mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';

if(process.argv.length!==2||!process.env.HOME) throw new Error('fixed burn checkpoint input materializer takes no arguments');
const root=path.resolve(new URL('..',import.meta.url).pathname);
const wallet=path.join(process.env.HOME,'.local/share/dom-usdom/mainnet-wallet');
const indexFile=path.join(wallet,'prepared-burn-state-v1/private-burn-index.json');
const blockFile=path.join(wallet,'private-burn-block-production-v1.json');
const submissionFile=path.join(wallet,'private-burn-submission-v1.json');
const payloadFile=path.join(wallet,'prepared-burn-state-v1/private-burn-payload.bin');
const output=path.join(root,'evidence/finalized-burn-source');
const [indexBytes,blockBytes,submissionBytes,payloadBytes]=await Promise.all([
  readDirectFile(indexFile,{minimum:1,maximum:128*1024,privateMode:true,label:'private burn index'}),
  readDirectFile(blockFile,{minimum:1,maximum:128*1024,privateMode:true,label:'private burn block receipt'}),
  readDirectFile(submissionFile,{minimum:1,maximum:128*1024,privateMode:true,label:'private burn submission'}),
  readDirectFile(payloadFile,{minimum:1,maximum:8*1024*1024,privateMode:true,label:'private burn payload'}),
]);
const index=parseStrictJson(indexBytes.toString('utf8'),{label:'private burn index',maxBytes:128*1024,maxDepth:32});
const block=parseStrictJson(blockBytes.toString('utf8'),{label:'private burn block receipt',maxBytes:128*1024,maxDepth:32});
const submission=parseStrictJson(submissionBytes.toString('utf8'),{label:'private burn submission',maxBytes:128*1024,maxDepth:32});
if(index.schema!=='usdom-closed-mainnet-private-burn-v1'||!/^0x[0-9a-f]{64}$/.test(index.burn?.burnId)
  ||block.schema!=='usdom-closed-mainnet-private-burn-block-v1'||block.transitionId!==index.transition_id
  ||submission.schema!=='usdom-closed-mainnet-private-burn-submission-v1'||submission.transition_id!==index.transition_id
  ||submission.candidate_id!==block.candidateId||submission.authority_binding!==block.authorityBinding
  ||submission.tpm_nv_index!=='0x01500020'||block.tpmNvIndex!==submission.tpm_nv_index
  ||submission.authorized_snapshot_generation!==block.authorizedSnapshotGeneration
  ||submission.authorized_snapshot_generation!==index.snapshot_generation
  ||createHash('sha256').update(Buffer.from(submission.authorized_snapshot_seal,'hex')).digest('hex')!==block.authorizedSnapshotSealSha256
  ||submission.payload_sha256!==index.payload_sha256
  ||createHash('sha256').update(payloadBytes).digest('hex')!==index.payload_sha256
  ||block.exactlyOneBlock!==true||block.continuousMining!==false
  ||BigInt(block.blockHeight)!==BigInt(block.parentHeight)+1n) throw new Error('burn block does not bind exact TPM-authorized prepared burn');
await mkdir(output,{recursive:true,mode:0o700});
const target=path.join(output,'burn-id.hex'),encoded=Buffer.from(`${index.burn.burnId.slice(2)}\n`);
try { const prior=await readDirectFile(target,{minimum:encoded.length,maximum:encoded.length,privateMode:true,label:'burn id'}); if(!prior.equals(encoded)) throw new Error('existing burn id differs'); }
catch(error) { if(error?.code!=='ENOENT') throw error; await writePrivateFileDurableNew(target,encoded,{maximum:128}); }
process.stdout.write(`${JSON.stringify({schema:'usdom-burn-checkpoint-input-v1',burnId:index.burn.burnId,
  blockHeight:block.blockHeight,blockHash:block.blockHash},null,2)}\n`);

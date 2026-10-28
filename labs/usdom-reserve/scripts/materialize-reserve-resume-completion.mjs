import path from 'node:path';
import {createHash} from 'node:crypto';
import {id} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildReserveResumeCompletion,validateReserveResumeCompletion} from '../sdk/reserve-resume-completion.mjs';
const dir=process.env.USDOM_CONTROL_EVIDENCE_DIRECTORY;if(!dir||!path.isAbsolute(dir))throw new Error('USDOM_CONTROL_EVIDENCE_DIRECTORY must be absolute');
async function read(name){const bytes=await readDirectFile(path.join(dir,name),{minimum:2,maximum:4*1024*1024,exactMode:0o600,label:name});return {bytes,value:parseStrictJsonBytes(bytes,{label:name,maxBytes:4*1024*1024,maxDepth:32})};}
const [s,e,sr,er]=await Promise.all([read('reserve-resume-schedule-finalized.json'),read('reserve-resume-execute-finalized.json'),read('reserve-resume-schedule-receipt.json'),read('reserve-resume-execute-receipt.json')]);
for(const [step,record,receipt,event] of [['schedule',s,sr,'ResumeScheduled(uint64)'],['execute',e,er,'Resumed()']]){
 const expectedTarget=step==='schedule'?record.value.governanceSafe:record.value.reserve;
 if(createHash('sha256').update(receipt.bytes).digest('hex')!==record.value.receiptSha256||String(receipt.value.status).toLowerCase()!=='0x1'||String(receipt.value.transactionHash).toLowerCase()!==record.value.ethereumTransactionHash||BigInt(receipt.value.blockNumber)!==BigInt(record.value.blockNumber)||String(receipt.value.blockHash).toLowerCase()!==record.value.blockHash||BigInt(receipt.value.transactionIndex)!==BigInt(record.value.transactionIndex)||String(receipt.value.to).toLowerCase()!==expectedTarget.toLowerCase())throw new Error(`${step} receipt binding is invalid`);
 const matching=(receipt.value.logs??[]).filter(log=>String(log.address).toLowerCase()===record.value.reserve.toLowerCase()&&String(log.topics?.[0]).toLowerCase()===id(event).toLowerCase());if(matching.length!==1||matching[0].topics.length!==1)throw new Error(`${step} event evidence is invalid`);
 const log=matching[0];
 if(BigInt(log.logIndex)!==BigInt(record.value.eventLogIndex)||BigInt(log.transactionIndex)!==BigInt(record.value.transactionIndex)||(log.transactionHash!==undefined&&String(log.transactionHash).toLowerCase()!==record.value.ethereumTransactionHash)||(log.blockHash!==undefined&&String(log.blockHash).toLowerCase()!==record.value.blockHash)||(log.blockNumber!==undefined&&BigInt(log.blockNumber)!==BigInt(record.value.blockNumber))||log.removed===true)throw new Error(`${step} event identity is invalid`);
 if(step==='schedule') { if(!/^0x[0-9a-fA-F]{64}$/.test(log.data)||BigInt(log.data)!==BigInt(record.value.after.resumeReadyAt))throw new Error('schedule event readyAt differs from storage'); }
 else if(log.data!=='0x') throw new Error('Resumed event data is noncanonical');
}
const out=buildReserveResumeCompletion({schedule:s.value,scheduleBytes:s.bytes,execute:e.value,executeBytes:e.bytes,governanceDelaySeconds:process.env.USDOM_GOVERNANCE_DELAY_SECONDS??'172800'});validateReserveResumeCompletion(out);
const [s2,e2,sr2,er2]=await Promise.all([read('reserve-resume-schedule-finalized.json'),read('reserve-resume-execute-finalized.json'),read('reserve-resume-schedule-receipt.json'),read('reserve-resume-execute-receipt.json')]);
if(!s2.bytes.equals(s.bytes)||!e2.bytes.equals(e.bytes)||!sr2.bytes.equals(sr.bytes)||!er2.bytes.equals(er.bytes)) {
  throw new Error('resume evidence changed during completion');
}
process.stdout.write(`${JSON.stringify(out,null,2)}\n`);

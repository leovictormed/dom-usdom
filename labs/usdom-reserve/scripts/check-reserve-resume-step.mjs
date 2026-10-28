#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {id,Interface,Transaction,ZeroAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateResumeStep} from '../sdk/reserve-resume-completion.mjs';

const [step,recordPath,receiptPath,journalPath]=process.argv.slice(2);
if(!['schedule','execute'].includes(step)||!recordPath||!receiptPath||!journalPath) process.exit(64);
const read=async(path,label)=>{const bytes=await readDirectFile(path,{minimum:2,maximum:4*1024*1024,exactMode:0o600,label});return {bytes,value:parseStrictJsonBytes(bytes,{label,maxDepth:32})};};
const [record,receipt,journal]=await Promise.all([read(recordPath,'resume step'),read(receiptPath,'resume receipt'),read(journalPath,'resume raw journal')]);
validateResumeStep(record.value,step);
if(JSON.stringify(Object.keys(journal.value).sort())!==JSON.stringify(['calldata','raw','safeTxHash','schema','step'].sort())||journal.value.schema!=='usdom-reserve-resume-raw-journal/v1'||journal.value.step!==step||journal.value.calldata!==record.value.calldata||String(journal.value.safeTxHash).toLowerCase()!==record.value.safeTransactionHash||!/^0x[0-9a-fA-F]+$/.test(journal.value.raw))throw new Error('resume raw journal binding is invalid');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
if(sha(journal.bytes)!==record.value.rawJournalSha256||sha(receipt.bytes)!==record.value.receiptSha256)throw new Error('resume durable byte binding is invalid');
const expectedTarget=step==='schedule'?record.value.governanceSafe:record.value.reserve;
const transaction=Transaction.from(journal.value.raw);
if(transaction.hash?.toLowerCase()!==record.value.ethereumTransactionHash||transaction.chainId!==1n||transaction.value!==0n||transaction.to?.toLowerCase()!==expectedTarget.toLowerCase())throw new Error('resume raw transaction identity is invalid');
if(step==='execute'){
  if(transaction.data.toLowerCase()!==record.value.calldata)throw new Error('resume execution calldata differs from raw transaction');
}else{
  const safe=new Interface(['function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)']);
  const decoded=safe.decodeFunctionData('execTransaction',transaction.data);
  if(String(decoded[0]).toLowerCase()!==record.value.reserve.toLowerCase()||decoded[1]!==0n||String(decoded[2]).toLowerCase()!==record.value.calldata||decoded[3]!==0n||decoded[4]!==0n||decoded[5]!==0n||decoded[6]!==0n||String(decoded[7]).toLowerCase()!==ZeroAddress.toLowerCase()||String(decoded[8]).toLowerCase()!==ZeroAddress.toLowerCase()||decoded[9].length<=2)throw new Error('resume Safe execution differs from raw transaction');
}
if(String(receipt.value.status).toLowerCase()!=='0x1'||String(receipt.value.transactionHash).toLowerCase()!==transaction.hash?.toLowerCase()||String(receipt.value.from).toLowerCase()!==transaction.from?.toLowerCase()||BigInt(receipt.value.blockNumber)!==BigInt(record.value.blockNumber)||String(receipt.value.blockHash).toLowerCase()!==record.value.blockHash||BigInt(receipt.value.transactionIndex)!==BigInt(record.value.transactionIndex)||String(receipt.value.to).toLowerCase()!==transaction.to?.toLowerCase())throw new Error('resume receipt binding is invalid');
const event=step==='schedule'?'ResumeScheduled(uint64)':'Resumed()';
const matches=(receipt.value.logs??[]).filter(log=>String(log.address).toLowerCase()===record.value.reserve.toLowerCase()&&String(log.topics?.[0]).toLowerCase()===id(event).toLowerCase());
if(matches.length!==1||matches[0].topics.length!==1||BigInt(matches[0].logIndex)!==BigInt(record.value.eventLogIndex)||BigInt(matches[0].transactionIndex)!==BigInt(record.value.transactionIndex)||(matches[0].transactionHash!==undefined&&String(matches[0].transactionHash).toLowerCase()!==transaction.hash?.toLowerCase())||(matches[0].blockHash!==undefined&&String(matches[0].blockHash).toLowerCase()!==record.value.blockHash)||(matches[0].blockNumber!==undefined&&BigInt(matches[0].blockNumber)!==BigInt(record.value.blockNumber))||matches[0].removed===true)throw new Error('resume event binding is invalid');
if(step==='schedule'&&BigInt(matches[0].data)!==BigInt(record.value.after.resumeReadyAt)||step==='execute'&&matches[0].data!=='0x')throw new Error('resume event data is invalid');

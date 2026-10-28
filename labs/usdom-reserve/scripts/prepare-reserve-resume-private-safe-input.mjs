#!/usr/bin/env node
import {Interface,getAddress,keccak256} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
const UINT=/^(?:0|[1-9][0-9]*)$/;
const iface=new Interface(['function getTransactionHash(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce) view returns (bytes32)']);
try {
  const [mode,file,governance,reserve,nonce]=process.argv.slice(2);
  if(!['hash','call'].includes(mode)||typeof file!=='string') throw new Error('private Safe input mode and file required');
  const calldata=new TextDecoder('utf-8',{fatal:true}).decode(await readDirectFile(file,{minimum:3,
    maximum:1024*1024,exactMode:0o600,label:'private reserve resume calldata'})).trim();
  if(!/^0x(?:[0-9a-fA-F]{2})+$/.test(calldata)) throw new Error('private reserve resume calldata invalid');
  if(mode==='hash') {
    if(process.argv.length!==4) throw new Error('hash mode takes no metadata');
    process.stdout.write(`${keccak256(calldata)}\n`);
  } else {
    if(process.argv.length!==7||!UINT.test(nonce??'')) throw new Error('Safe call metadata invalid');
    const to=getAddress(governance),destination=getAddress(reserve),zero='0x'+'00'.repeat(20);
    const data=iface.encodeFunctionData('getTransactionHash',[destination,0,calldata,0,0,0,0,zero,zero,nonce]);
    process.stdout.write(`${JSON.stringify([{to,data},'latest'])}\n`);
  }
} catch(error) { writeReleaseFailure('prepare-reserve-resume-private-safe-input',error);process.exitCode=1; }

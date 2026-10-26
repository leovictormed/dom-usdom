#!/usr/bin/env node
import path from 'node:path';
import {Transaction,getAddress,keccak256} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

try {
  const [role,nonceText]=process.argv.slice(2);
  const packagePath=process.env.USDOM_SAFE_PACKAGE,rawPath=process.env.USDOM_SAFE_DEPLOYMENT_RAW;
  const sender=process.env.USDOM_SAFE_PRIMARY_OWNER;
  if(process.argv.length!==4||!path.isAbsolute(packagePath??'')||!path.isAbsolute(rawPath??'')
      ||!/^(0|[1-9][0-9]*)$/.test(nonceText??'')) throw new Error('Safe raw validator inputs invalid');
  const [packageBytes,rawBytes]=await Promise.all([
    readDirectFile(packagePath,{minimum:1,maximum:1024*1024,exactMode:0o600,label:'Safe package'}),
    readDirectFile(rawPath,{minimum:3,maximum:1024*1024,exactMode:0o600,label:'Safe raw transaction'}),
  ]);
  const document=parseStrictJson(packageBytes.toString('utf8'),{label:'Safe package'});
  const control=document.controls?.find(value=>value.role===role);
  const raw=rawBytes.toString('utf8').trim();
  const nonce=BigInt(nonceText);
  if(!control||nonce>BigInt(Number.MAX_SAFE_INTEGER)||!/^0x[0-9a-fA-F]+$/.test(raw)
      ||`${raw}\n`!==rawBytes.toString('utf8')) {
    throw new Error('Safe raw transaction or role invalid');
  }
  const tx=Transaction.from(raw);
  if(tx.chainId!==1n||tx.type!==2||tx.to!==getAddress(control.to)||tx.value!==0n
      ||tx.data.toLowerCase()!==control.data.toLowerCase()||tx.nonce!==Number(nonce)
      ||tx.from!==getAddress(sender)||tx.gasLimit===0n||tx.gasLimit>1_000_000n
      ||tx.maxFeePerGas===null||tx.maxFeePerGas>100_000_000_000n
      ||tx.maxPriorityFeePerGas!==2_000_000_000n||tx.accessList.length!==0) {
    throw new Error('signed Safe deployment differs from the bounded package');
  }
  process.stdout.write(`${JSON.stringify({schema:'usdom-safe-deployment-raw/v1',role,
    safe:getAddress(control.safe),from:tx.from,nonce:nonceText,to:tx.to,dataHash:keccak256(tx.data),
    transactionHash:tx.hash,gasLimit:tx.gasLimit.toString(),maxFeePerGas:tx.maxFeePerGas.toString(),
    rawHash:keccak256(raw)})}\n`);
} catch(error) {
  writeReleaseFailure('check-safe-control-deployment-raw-transaction',error);
  process.exitCode=1;
}

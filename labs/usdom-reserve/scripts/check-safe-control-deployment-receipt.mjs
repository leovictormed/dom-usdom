#!/usr/bin/env node
import path from 'node:path';
import {getAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {canonicalEthereumQuantity,canonicalUnsignedDecimal} from '../sdk/ethereum-quantity.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

const bytes32=/^0x[0-9a-fA-F]{64}$/;
const outputKeys=['schema','role','transactionHash','blockNumber','blockHash','transactionIndex','status','from','to'];
const validationKeys=['schema','role','safe','from','nonce','to','dataHash','transactionHash',
  'gasLimit','maxFeePerGas','rawHash'];

try {
  const [role,receiptPath,validationPath]=process.argv.slice(2);
  const packagePath=process.env.USDOM_SAFE_PACKAGE;
  if(process.argv.length!==5||!path.isAbsolute(packagePath??'')||!path.isAbsolute(receiptPath??'')
      ||!path.isAbsolute(validationPath??'')) throw new Error('Safe receipt validator inputs invalid');
  const [packageBytes,receiptBytes,validationBytes]=await Promise.all([
    readDirectFile(packagePath,{minimum:1,maximum:1024*1024,exactMode:0o600,label:'Safe package'}),
    readDirectFile(receiptPath,{minimum:2,maximum:1024*1024,exactMode:0o600,label:'Safe receipt'}),
    readDirectFile(validationPath,{minimum:2,maximum:1024*1024,exactMode:0o600,label:'Safe raw validation'}),
  ]);
  const packageDocument=parseStrictJsonBytes(packageBytes,{label:'Safe package',maxDepth:16});
  const receipt=parseStrictJsonBytes(receiptBytes,{label:'Safe receipt',maxDepth:32});
  const validation=parseStrictJsonBytes(validationBytes,{label:'Safe raw validation',maxDepth:8});
  const control=packageDocument.controls?.find(value=>value.role===role);
  const exactValidation=validation&&typeof validation==='object'&&!Array.isArray(validation)
    &&JSON.stringify(Object.keys(validation).sort())===JSON.stringify([...validationKeys].sort());
  let validationNonce,validationGas,validationFee;
  try {
    validationNonce=canonicalUnsignedDecimal(validation?.nonce,{maximum:BigInt(Number.MAX_SAFE_INTEGER)});
    validationGas=canonicalUnsignedDecimal(validation?.gasLimit,{maximum:1_000_000n});
    validationFee=canonicalUnsignedDecimal(validation?.maxFeePerGas,{maximum:100_000_000_000n});
  } catch { throw new Error('Safe receipt authority is invalid'); }
  if(!control||!exactValidation||validation.schema!=='usdom-safe-deployment-raw/v1'
      ||validation.role!==role||getAddress(validation.safe)!==getAddress(control.safe)
      ||getAddress(validation.to)!==getAddress(control.to)
      ||validationNonce!==validation.nonce||validationGas==='0'||validationFee==='0'
      ||![validation.dataHash,validation.transactionHash,validation.rawHash].every(value=>
        bytes32.test(value??'')&&BigInt(value)!==0n)) {
    throw new Error('Safe receipt authority is invalid');
  }
  if(receipt?.schema!==undefined
      &&(receipt.schema!=='usdom-safe-deployment-receipt/v1'
        ||JSON.stringify(Object.keys(receipt).sort())!==JSON.stringify([...outputKeys].sort()))) {
    throw new Error('canonical Safe receipt schema is invalid');
  }
  const transactionHash=String(receipt.transactionHash??'').toLowerCase();
  const blockHash=String(receipt.blockHash??'').toLowerCase();
  canonicalEthereumQuantity(receipt.blockNumber);
  canonicalEthereumQuantity(receipt.transactionIndex);
  const blockNumber=receipt.blockNumber;
  const from=getAddress(receipt.from),to=getAddress(receipt.to);
  if(!bytes32.test(transactionHash)||BigInt(transactionHash)===0n||!bytes32.test(blockHash)
      ||BigInt(blockHash)===0n||receipt.status!=='0x1'
      ||transactionHash!==String(validation.transactionHash).toLowerCase()
      ||from!==getAddress(validation.from)||to!==getAddress(control.to)) {
    throw new Error('Safe receipt differs from the authenticated deployment transaction');
  }
  const projected={schema:'usdom-safe-deployment-receipt/v1',role,transactionHash,
    blockNumber,blockHash,transactionIndex:receipt.transactionIndex,status:'0x1',from,to};
  const [packageAfter,receiptAfter,validationAfter]=await Promise.all([
    readDirectFile(packagePath,{minimum:packageBytes.length,maximum:packageBytes.length,exactMode:0o600,label:'Safe package'}),
    readDirectFile(receiptPath,{minimum:receiptBytes.length,maximum:receiptBytes.length,exactMode:0o600,label:'Safe receipt'}),
    readDirectFile(validationPath,{minimum:validationBytes.length,maximum:validationBytes.length,exactMode:0o600,label:'Safe raw validation'}),
  ]);
  if(!packageAfter.equals(packageBytes)||!receiptAfter.equals(receiptBytes)
      ||!validationAfter.equals(validationBytes)) throw new Error('Safe receipt inputs changed');
  process.stdout.write(`${JSON.stringify(projected)}\n`);
} catch(error) {
  writeReleaseFailure('check-safe-control-deployment-receipt',error);
  process.exitCode=1;
}

#!/usr/bin/env node
import {Signature,getAddress,recoverAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
try {
 if(process.argv.length!==7) throw new Error('usage: PLAN IDENTITY SIGNATURE EXPECTED_INDEX OUTPUT');
 const [planBytes,identityBytes,signatureBytes]=await Promise.all([
  readDirectFile(process.argv[2],{minimum:2,maximum:2*1024*1024,exactMode:0o600,label:'private pilot plan'}),
  readDirectFile(process.argv[3],{minimum:2,maximum:16384,exactMode:0o600,label:'private OneKey identity'}),
  readDirectFile(process.argv[4],{minimum:133,maximum:133,exactMode:0o600,label:'private OneKey signature'}),
 ]);
 const plan=parseStrictJsonBytes(planBytes,{label:'private pilot plan'}),identity=parseStrictJsonBytes(identityBytes,{label:'private OneKey identity'});
 if(!/^[12]$/.test(process.argv[5])||identity?.schema!=='usdom-onekey-classic-1s-identity/v1') throw new Error('pilot owner identity is invalid');
 const signatureText=signatureBytes.toString('ascii');
 if(!/^0x[0-9a-f]{130}\n$/.test(signatureText)) throw new Error('pilot owner signature is noncanonical');
 const signature=Signature.from(signatureText.trim()),signer=getAddress(recoverAddress(plan.safeTxHash,signature));
 const ownerIndex=Number(process.argv[5])-1;
 if(signature.serialized!==signatureText.trim()||signer!==getAddress(identity.expectedAddress)
   ||!plan.authorizedOwners?.includes(signer)||signer!==plan.authorizedOwners[ownerIndex]) throw new Error('pilot owner signer mismatch');
 try {await writePrivateFileDurableNew(process.argv[6],Buffer.from(`${JSON.stringify({signer,signature:signature.serialized})}\n`),{maximum:2048});}
 catch(cause){const error=new Error('OneKey owner signature exists but its pilot record was not durably installed',{cause});error.exitCode=80;throw error;}
} catch(error){process.stderr.write(`${error?.message??'pilot owner signature materialization failed'}\n`);process.exit(error?.exitCode===80?80:1);}

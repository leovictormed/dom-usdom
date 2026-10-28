#!/usr/bin/env node
import {Signature,Transaction,getAddress,recoverAddress} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
try {
 if(process.argv.length!==3)throw new Error('usage: SIGNING_REQUEST');
 const request=parseStrictJsonBytes(await readDirectFile(process.argv[2],{minimum:2,maximum:8*1024*1024,exactMode:0o600,label:'relayer signing request'}),{label:'relayer signing request'});
 let signature='';for await(const chunk of process.stdin)signature+=chunk;signature=signature.trim();
 if(!/^0x[0-9a-f]{130}$/u.test(signature))throw new Error('relayer signature is not canonical');
 const parsed=Signature.from(signature);if(parsed.serialized!==signature||recoverAddress(request.unsignedHash,parsed)!==getAddress(request.relayer))throw new Error('relayer signature mismatch');
 const unsigned=Transaction.from(request.unsignedSerialized);if(unsigned.unsignedHash!==request.unsignedHash||unsigned.signature!==null)throw new Error('unsigned transaction mismatch');
 unsigned.signature=parsed;const raw=unsigned.serialized,tx=Transaction.from(raw);
 if(tx.serialized!==raw||tx.from!==getAddress(request.relayer)||tx.chainId!==1n||tx.type!==2||tx.value!==0n||tx.accessList.length!==0)throw new Error('assembled relayer transaction rejected');
 process.stdout.write(`${raw}\n`);
} catch(error){console.error(error.message);process.exitCode=1;}

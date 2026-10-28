#!/usr/bin/env node
import {constants,open,readFile} from 'node:fs/promises';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateReownProjectResponse} from '../sdk/onekey-ios-onboarding.mjs';
try{
 const phraseMode=process.argv[2]==='--approval-phrase';
 if(phraseMode?process.argv.length!==4:process.argv.length!==4)throw new Error('usage: materialize-onekey-ios-walletconnect-client-config [--approval-phrase] RESPONSE|OUTPUT');
 const responsePath=phraseMode?process.argv[3]:process.argv[2],outputPath=process.argv[3];
 const response=parseStrictJsonBytes(await readFile(responsePath),{label:'public Reown project response',maxBytes:4096,maxDepth:4});
 const projectId=validateReownProjectResponse(response);
 if(phraseMode){process.stdout.write(`AUTORIZO WALLETCONNECT EIP712 MAINNET PROJECT ${projectId}\n`);process.exit(0);}
 let approval='';for await(const chunk of process.stdin){approval+=chunk;if(Buffer.byteLength(approval)>256)throw new Error('operator approval is oversized');}
 if(approval.trim()!==`AUTORIZO WALLETCONNECT EIP712 MAINNET PROJECT ${projectId}`)throw new Error('exact operator approval is required');
 const config={schema:'usdom-onekey-ios-walletconnect-client-config/v1',projectId,metadata:{name:'USDOM Safe pilot',description:'OneKey Classic 1S iPhone EIP-712 signing',url:'https://github.com/leovictormed/dom-usdom',icons:['https://github.com/favicon.ico']},communityLicenseAccepted:true,networkExecutionApproved:true};
 const bytes=Buffer.from(`${JSON.stringify(config,null,2)}\n`),handle=await open(outputPath,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
 try{await handle.writeFile(bytes);await handle.sync();}finally{await handle.close();}
 process.stdout.write(`${outputPath}\n`);
}catch(error){console.error(`WALLETCONNECT_CONFIG_REJECTED: ${error.message}`);process.exitCode=1;}

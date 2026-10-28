#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildSafeDeploymentRelayerEnvelope} from '../sdk/safe-control-deployment-relayer.mjs';
try {const [role,inputPath,packagePath,policyPath,keystorePath,nonce,gas,fee,priority]=process.argv.slice(2);
 if(process.argv.length!==11)throw new Error('usage: prepare safe relayer envelope');
 const bytes=await Promise.all([inputPath,packagePath,policyPath,keystorePath].map((path,index)=>readDirectFile(path,{minimum:2,maximum:2*1024*1024,exactMode:0o600,label:['input','package','policy','keystore'][index]})));
 const [input,pkg,policy,keystore]=bytes.map((value,index)=>parseStrictJsonBytes(value,{label:['input','package','policy','keystore'][index]}));
 process.stdout.write(`${JSON.stringify(buildSafeDeploymentRelayerEnvelope({role,input,pkg,packageBytes:bytes[1],policy,policyBytes:bytes[2],keystore,keystoreBytes:bytes[3],nonce,gasLimit:gas,maxFeePerGas:fee,maxPriorityFeePerGas:priority}))}\n`);
}catch(error){console.error(error.message);process.exit(1);}

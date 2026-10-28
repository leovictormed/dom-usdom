#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateSafeDeploymentRelayerRaw} from '../sdk/safe-control-deployment-relayer.mjs';
try {const [role,rawPath,envelopePath,inputPath,packagePath,policyPath,keystorePath]=process.argv.slice(2);
 if(process.argv.length!==9)throw new Error('usage: check safe relayer raw');
 const paths=[rawPath,envelopePath,inputPath,packagePath,policyPath,keystorePath];
 const bytes=await Promise.all(paths.map((path,index)=>readDirectFile(path,{minimum:2,maximum:2*1024*1024,exactMode:0o600,label:['raw','envelope','input','package','policy','keystore'][index]})));
 const [envelope,input,pkg,policy,keystore]=bytes.slice(1).map((value,index)=>parseStrictJsonBytes(value,{label:['envelope','input','package','policy','keystore'][index]}));
 process.stdout.write(`${JSON.stringify(validateSafeDeploymentRelayerRaw({role,rawBytes:bytes[0],envelope,input,pkg,packageBytes:bytes[3],policy,policyBytes:bytes[4],keystore,keystoreBytes:bytes[5]}))}\n`);
}catch(error){console.error(error.message);process.exit(1);}

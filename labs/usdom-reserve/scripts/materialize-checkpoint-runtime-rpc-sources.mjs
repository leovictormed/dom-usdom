#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';

try {
  if(process.argv.length!==4) throw new Error('usage: materialize-checkpoint-runtime-rpc-sources.mjs INPUT OUTPUT');
  const input=parseStrictJsonBytes(await readDirectFile(process.argv[2],{
    minimum:2,maximum:32768,exactMode:0o600,label:'mainnet RPC sources'}),{
    label:'mainnet RPC sources',maxBytes:32768,maxDepth:8});
  if(!Array.isArray(input)||input.length<2||input.length>5) throw new Error('two to five RPC sources required');
  const output=input.map((row,index)=>{
    if(!row||typeof row!=='object'||Array.isArray(row)
        ||typeof row.operatorId!=='string'||typeof row.url!=='string') {
      throw new Error(`RPC source ${index+1} is invalid`);
    }
    return {operatorId:row.operatorId,url:row.url};
  });
  await writePrivateFileDurableNewOrEqual(process.argv[3],
    Buffer.from(`${JSON.stringify(output)}\n`),{maximum:32768});
} catch(error) {
  writeReleaseFailure('materialize-checkpoint-runtime-rpc-sources',error);
  process.exitCode=1;
}

#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateCheckpointBootstrapRatificationSigningRequest}
  from '../sdk/checkpoint-bootstrap-ratification-request.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const inputs=['config/mainnet-release-evidence.unconfigured.json','config/proof-reserve.unconfigured.json',
  'evidence/native-preactivation/ethereum-checkpoint-consensus.json',
  'config/native-preactivation-facts.unconfigured.json'];
const modes=[0o644,0o644,0o600,0o600];
const readInputs=()=>Promise.all(inputs.map((relative,index)=>readDirectProjectFile(root,relative,
  {minimum:2,maximum:4*1024*1024,exactMode:modes[index],label:relative})));
const parse=(bytes,label)=>parseStrictJsonBytes(bytes,{label,maxBytes:4*1024*1024,maxDepth:64});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
try {
  if(process.argv.length!==3) throw new Error('usage: check-checkpoint-bootstrap-ratification-request REQUEST');
  const requestBytes=await readDirectFile(path.resolve(process.argv[2]),{
    minimum:2,maximum:4*1024*1024,exactMode:0o600,label:'ratification request snapshot'});
  const inputBytes=await readInputs();
  const [releaseEvidence,releaseConfig,checkpointConsensus,nativeFacts]=inputBytes.map(
    (bytes,index)=>parse(bytes,inputs[index]));
  const request=parse(requestBytes,'ratification request snapshot');
  const result=validateCheckpointBootstrapRatificationSigningRequest({request,releaseEvidence,
    releaseEvidenceBytes:inputBytes[0],releaseConfig,releaseConfigBytes:inputBytes[1],
    checkpointConsensus,checkpointConsensusBytes:inputBytes[2],nativeFacts,
    nativeFactsBytes:inputBytes[3],finalizedAnchor:request.finalizedAnchor,
    inputDocuments:{releaseEvidenceSha256:sha(inputBytes[0]),releaseConfigSha256:sha(inputBytes[1]),
      checkpointConsensusSha256:sha(inputBytes[2]),nativeFactsSha256:sha(inputBytes[3])}});
  const [requestAfter,...inputsAfter]=await Promise.all([
    readDirectFile(path.resolve(process.argv[2]),{minimum:requestBytes.length,maximum:requestBytes.length,
      exactMode:0o600,label:'ratification request snapshot'}),readInputs(),
  ]).then(([request,current])=>[request,...current]);
  if(!requestAfter.equals(requestBytes)||inputsAfter.some((bytes,index)=>!bytes.equals(inputBytes[index]))) {
    throw new Error('ratification request inputs changed during validation');
  }
  process.stdout.write(`PASS: checkpoint bootstrap ratification request ${result.digest}\n`);
} catch(error) {
  writeReleaseFailure('check-checkpoint-bootstrap-ratification-request',error);
  process.exitCode=1;
}

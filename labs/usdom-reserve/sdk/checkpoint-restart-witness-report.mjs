import {createHash} from 'node:crypto';
import {parseStrictJsonBytes} from './strict-json.mjs';
const sha=/^[0-9a-f]{64}$/;
const nonzeroSha=value=>sha.test(value)&&value!=='0'.repeat(64);
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
export function validateCheckpointRestartWitnessReport(v,{reportBytes,manifestBytes,witnessBytes}={}) {
  const keys=['schema','manifestSha256','witnessSha256','firstProcessPid','secondProcessPid','firstStartupAccepted','secondStartupAccepted','sameDataDirectory','checkpointWitnessRequired'];
  if(!v||JSON.stringify(Object.keys(v).sort())!==JSON.stringify(keys.sort())
      ||v.schema!=='usdom-checkpoint-restart-witness-live-exercise/v1'||!nonzeroSha(v.manifestSha256)
      ||!nonzeroSha(v.witnessSha256)||!Number.isSafeInteger(v.firstProcessPid)||v.firstProcessPid<=1
      ||!Number.isSafeInteger(v.secondProcessPid)||v.secondProcessPid<=1||v.firstProcessPid===v.secondProcessPid
      ||v.firstStartupAccepted!==true||v.secondStartupAccepted!==true||v.sameDataDirectory!==true
      ||v.checkpointWitnessRequired!==true) throw new Error('checkpoint restart witness report is invalid');
  if(reportBytes!==undefined) {
    if(!Buffer.isBuffer(reportBytes)) throw new Error('checkpoint restart report authority bytes are invalid');
    const parsed=parseStrictJsonBytes(reportBytes,{label:'checkpoint restart witness report',maxBytes:64*1024,maxDepth:8});
    if(JSON.stringify(parsed)!==JSON.stringify(v)) throw new Error('checkpoint restart report differs from authority bytes');
  }
  if(manifestBytes!==undefined||witnessBytes!==undefined) {
    if(!Buffer.isBuffer(manifestBytes)||!Buffer.isBuffer(witnessBytes)||witnessBytes.length<1) throw new Error('checkpoint restart witness authority bytes are invalid');
    const manifest=parseStrictJsonBytes(manifestBytes,{label:'native runtime manifest',maxBytes:4*1024*1024,maxDepth:32});
    const witnessName=manifest.restart_checkpoint?.witness_file;
    if(typeof witnessName!=='string'||!/^[A-Za-z0-9._-]+$/.test(witnessName)
        ||digest(manifestBytes)!==v.manifestSha256||digest(witnessBytes)!==v.witnessSha256
        ||manifest.restart_checkpoint?.witness_sha256!==v.witnessSha256) throw new Error('checkpoint restart witness differs from authority bytes');
  }
  return v;
}

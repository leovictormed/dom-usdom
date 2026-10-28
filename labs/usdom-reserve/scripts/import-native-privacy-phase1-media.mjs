#!/usr/bin/env node
import path from 'node:path';
import {createHash} from 'node:crypto';
import {mkdir,lstat,realpath} from 'node:fs/promises';
import {getAddress,verifyMessage} from 'ethers';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {phase1ContributionMessage,phase1DestructionMessage} from '../sdk/native-privacy-ceremony.mjs';

if(process.argv.length!==6) throw new Error('usage: import-native-privacy-phase1-media.mjs RECORD ARTIFACT ACCUMULATOR DESTINATION');
const [recordPath,artifactPath,accumulatorPath,destination]=process.argv.slice(2);
const sha=value=>createHash('sha256').update(value).digest('hex');
const [recordBytes,artifactBytes,accumulatorBytes]=await Promise.all([
  readDirectFile(recordPath,{minimum:2,maximum:1024*1024,privateMode:true,label:'Phase1 signed record'}),
  readDirectFile(artifactPath,{minimum:1,maximum:512*1024*1024,privateMode:true,label:'Phase1 contribution media'}),
  readDirectFile(accumulatorPath,{minimum:1,maximum:512*1024*1024,privateMode:true,label:'Phase1 accumulator media'}),
]);
const record=parseStrictJsonBytes(recordBytes,{label:'Phase1 signed record'});
const keys=['ordinal','participant','participantCommitment','previousRecordHash','previousAccumulatorSha256','artifactSha256','accumulatorSha256','signature','destruction'];
if(JSON.stringify(Object.keys(record).sort())!==JSON.stringify(keys.sort())||!Number.isSafeInteger(record.ordinal)||record.ordinal<1)
  throw new Error('invalid Phase1 signed record');
const participant=getAddress(record.participant);
if(sha(Buffer.from(participant))!==record.participantCommitment
    ||getAddress(verifyMessage(phase1ContributionMessage(record),record.signature))!==participant)
  throw new Error('invalid Phase1 media identity signature');
const destruction=record.destruction;
if(!destruction||destruction.participant!==participant||destruction.artifactSha256!==record.artifactSha256
    ||typeof destruction.method!=='string'||destruction.method.length<16
    ||getAddress(verifyMessage(phase1DestructionMessage(destruction),destruction.signature))!==participant)
  throw new Error('invalid Phase1 media erasure attestation');
if(sha(artifactBytes)!==record.artifactSha256||sha(accumulatorBytes)!==record.accumulatorSha256)
  throw new Error('Phase1 media hash mismatch');
try{await mkdir(destination,{mode:0o700});}catch(error){if(error?.code!=='EEXIST')throw error;}
const stat=await lstat(destination);
if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o700
    ||await realpath(destination)!==path.resolve(destination)) throw new Error('unsafe Phase1 import directory');
const ordinal=String(record.ordinal).padStart(3,'0');
await writePrivateFileDurableNewOrEqual(path.join(destination,`phase1-record-${ordinal}.json`),recordBytes,{maximum:1024*1024});
await writePrivateFileDurableNewOrEqual(path.join(destination,`phase1-contribution-${ordinal}.bin`),artifactBytes,{maximum:512*1024*1024});
await writePrivateFileDurableNewOrEqual(path.join(destination,`phase1-accumulator-${ordinal}.bin`),accumulatorBytes,{maximum:512*1024*1024});
process.stdout.write(`${JSON.stringify({schema:'usdom-native-privacy-phase1-media-import/v1',ordinal:record.ordinal,
  participant,participantCommitment:record.participantCommitment,artifactSha256:record.artifactSha256,
  accumulatorSha256:record.accumulatorSha256})}\n`);

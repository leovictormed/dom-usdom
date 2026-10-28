#!/usr/bin/env node
import path from 'node:path';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {ceremonyObjectHash,validateNativePrivacyCeremony} from '../sdk/native-privacy-ceremony.mjs';

const json=value=>Buffer.from(`${JSON.stringify(value,null,2)}\n`);
if(process.argv[2]==='draft') {
  if(process.argv.length!==7) throw new Error('usage: assemble-native-privacy-ceremony.mjs draft HEADER RECORD_DIRECTORY COUNT OUTPUT');
  const [,headerPath,directory,countText,output]=process.argv.slice(2);
  const count=Number(countText);if(!Number.isSafeInteger(count)||count<3) throw new Error('at least three Phase2 records are required');
  const header=parseStrictJsonBytes(await readDirectFile(headerPath,{minimum:2,maximum:8*1024*1024,privateMode:true,label:'ceremony header'}),{label:'ceremony header'});
  const contributions=[];for(let i=1;i<=count;i++){const ordinal=String(i).padStart(3,'0');contributions.push(parseStrictJsonBytes(
    await readDirectFile(path.join(directory,`phase2-record-${ordinal}.json`),{minimum:2,maximum:1024*1024,privateMode:true,label:`Phase2 record ${ordinal}`}),{label:`Phase2 record ${ordinal}`}));}
  let previous='0'.repeat(64);for(const [index,record] of contributions.entries()){if(record.ordinal!==index+1||record.previousTranscriptHash!==previous)throw new Error('Phase2 record order/predecessor mismatch');previous=ceremonyObjectHash(record);}
  const transcript={...header,contributions,finalTranscriptHash:'',finalizationSignatures:[]};
  transcript.finalTranscriptHash=ceremonyObjectHash({previousTranscriptHash:previous,beacon:transcript.beacon,
    finalProvingKeySha256:transcript.finalProvingKeySha256,verifyingKeySha256:transcript.verifyingKeySha256,
    circuitSha256:transcript.circuitSha256,releaseCommitment:transcript.releaseCommitment,
    privacyVerifierConfigHash:transcript.privacyVerifierConfigHash,r1csFingerprintSha256:transcript.r1csFingerprintSha256,
    initialProvingKeySha256:transcript.initialProvingKeySha256,initialKeyProvenance:transcript.initialKeyProvenance,
    ceremonyVerifierBinarySha256:transcript.ceremonyVerifierBinarySha256});
  await writePrivateFileDurableNewOrEqual(output,json(transcript),{maximum:8*1024*1024});
  process.stdout.write(`${transcript.finalTranscriptHash}\n`);
} else if(process.argv[2]==='finalize') {
  if(process.argv.length!==9) throw new Error('usage: assemble-native-privacy-ceremony.mjs finalize DRAFT SIGNATURE_DIRECTORY CIRCUIT FINAL_PK VK OUTPUT');
  const [,draftPath,directory,circuitPath,pkPath,vkPath,output]=process.argv.slice(2);
  const transcript=parseStrictJsonBytes(await readDirectFile(draftPath,{minimum:2,maximum:8*1024*1024,privateMode:true,label:'ceremony draft'}),{label:'ceremony draft'});
  const signatures=[];for(let i=1;i<=transcript.contributions.length;i++){const ordinal=String(i).padStart(3,'0');signatures.push(parseStrictJsonBytes(
    await readDirectFile(path.join(directory,`finalization-${ordinal}.json`),{minimum:2,maximum:1024*1024,privateMode:true,label:`finalization ${ordinal}`}),{label:`finalization ${ordinal}`}));}
  transcript.finalizationSignatures=signatures;
  const [circuitBytes,finalProvingKeyBytes,verifyingKeyBytes]=await Promise.all([circuitPath,pkPath,vkPath].map(value=>readDirectFile(value,{minimum:1,maximum:64*1024*1024,privateMode:true,label:'ceremony final artifact'})));
  validateNativePrivacyCeremony(transcript,{circuitBytes,finalProvingKeyBytes,verifyingKeyBytes});
  await writePrivateFileDurableNewOrEqual(output,json(transcript),{maximum:8*1024*1024});
  process.stdout.write(`${transcript.finalTranscriptHash}\n`);
} else throw new Error('expected draft or finalize');

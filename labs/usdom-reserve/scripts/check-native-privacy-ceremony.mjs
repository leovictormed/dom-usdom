#!/usr/bin/env node
import {readFile} from 'node:fs/promises';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateNativePrivacyCeremony,validateNativePrivacyCeremonyArtifacts} from '../sdk/native-privacy-ceremony.mjs';
if(process.argv.length!==8) throw new Error('usage: check-native-privacy-ceremony.mjs TRANSCRIPT CIRCUIT FINAL_PK VK ARTIFACT_DIR VERIFIER_BIN');
const [transcriptFile,circuitFile,pkFile,vkFile,artifactDirectory,verifierBinary]=process.argv.slice(2);
const [tb,circuitBytes,finalProvingKeyBytes,verifyingKeyBytes]=await Promise.all(
  [transcriptFile,circuitFile,pkFile,vkFile].map(value=>readFile(value)));
const transcript=parseStrictJsonBytes(tb,{label:'native privacy ceremony transcript',maxBytes:8*1024*1024});
const result=validateNativePrivacyCeremony(transcript,{circuitBytes,finalProvingKeyBytes,verifyingKeyBytes});
await validateNativePrivacyCeremonyArtifacts(transcript,{artifactDirectory,verifierBinary,finalProvingKeyBytes,verifyingKeyBytes});
process.stdout.write(`${JSON.stringify({schema:'usdom-native-privacy-ceremony-validation-v1',...result},null,2)}\n`);

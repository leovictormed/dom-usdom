#!/usr/bin/env node
import path from 'node:path';
import {mkdir,lstat,realpath} from 'node:fs/promises';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildNativePrivacyInstallationReceipt,validateNativePrivacyCeremony,
  validateNativePrivacyCeremonyArtifacts} from '../sdk/native-privacy-ceremony.mjs';
import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
if(process.argv.length!==10) throw new Error('usage: install-native-privacy-verifying-key.mjs TRANSCRIPT CIRCUIT FINAL_PK VK RUNTIME_MANIFEST TARGET_DIRECTORY ARTIFACT_DIR VERIFIER_BIN');
const [transcriptFile,circuitFile,pkFile,vkFile,manifestFile,target,artifactDirectory,verifierBinary]=process.argv.slice(2);
const [tb,circuitBytes,finalProvingKeyBytes,verifyingKeyBytes,manifestBytes]=await Promise.all(
  [transcriptFile,circuitFile,pkFile,vkFile].map((value,index)=>readDirectFile(value,{minimum:1,
    maximum:[8,64,64,16][index]*1024*1024,privateMode:true,label:'native privacy ceremony installation input'}))
    .concat(readDirectFile(manifestFile,{minimum:1,maximum:4*1024*1024,privateMode:false,
      label:'native runtime manifest'})));
const transcript=parseStrictJsonBytes(tb,{label:'ceremony transcript'});
const validated=validateNativePrivacyCeremony(transcript,{circuitBytes,finalProvingKeyBytes,verifyingKeyBytes});
await validateNativePrivacyCeremonyArtifacts(transcript,{artifactDirectory,verifierBinary,finalProvingKeyBytes,verifyingKeyBytes});
const manifest=parseStrictJsonBytes(manifestBytes,{label:'native runtime manifest'});
if(manifest.spend_verifying_key_sha256!==validated.verifyingKeySha256
    ||manifest.privacy_verifier_config_hash!==validated.privacyVerifierConfigHash)
  throw new Error('runtime manifest does not bind ceremony verifying key/configuration');
try { await mkdir(target,{mode:0o700}); } catch(error) { if(error?.code!=='EEXIST') throw error; }
const targetStat=await lstat(target);
if(!targetStat.isDirectory()||targetStat.isSymbolicLink()||(targetStat.mode&0o777)!==0o700
    ||targetStat.uid!==process.getuid()||await realpath(target)!==path.resolve(target))
  throw new Error('installation directory is not a direct current-user mode-0700 directory');
for(const [name,bytes,max] of [['ceremony-transcript.json',tb,8*1024*1024],
  ['spend-verifying-key.bin',verifyingKeyBytes,16*1024*1024],['native-usdom-v2.json',manifestBytes,4*1024*1024]])
  await writePrivateFileDurableNewOrEqual(path.join(target,name),bytes,{maximum:max});
const receipt=Buffer.from(`${JSON.stringify(
  buildNativePrivacyInstallationReceipt(validated,manifestBytes,tb),null,2)}\n`);
await writePrivateFileDurableNewOrEqual(path.join(target,'installation.json'),receipt,{maximum:1024*1024});
process.stdout.write(receipt);

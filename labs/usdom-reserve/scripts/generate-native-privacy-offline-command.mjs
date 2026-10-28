#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {getAddress} from 'ethers';
import {snapshotExecutablePath,assertExecutableUnchanged} from '../sdk/stable-executable.mjs';
const [mode,binary,directory,ordinalText,release,circuit,participantText,previous]=process.argv.slice(2);
if(process.argv.length!==10||!['phase1','phase2'].includes(mode)) throw new Error('usage: generate-native-privacy-offline-command.mjs phase1|phase2 BINARY DIRECTORY ORDINAL RELEASE CIRCUIT PARTICIPANT PREVIOUS_RECORD');
if(!binary.startsWith('/')||!directory.startsWith('/')) throw new Error('binary and directory must be absolute');
const executable=await snapshotExecutablePath(binary);
if(executable.path!==binary) throw new Error('unsafe ceremony binary');
const pin=executable.sha256;
const ordinal=Number(ordinalText);if(!Number.isSafeInteger(ordinal)||ordinal<1) throw new Error('invalid ordinal');
for(const value of [release,circuit,previous])if(!/^[0-9a-f]{64}$/.test(value))throw new Error('invalid transcript binding');
const participant=getAddress(participantText),identity=createHash('sha256').update(participant).digest('hex');
const quote=value=>`'${String(value).replaceAll("'",`'"'"'`)}'`;
const operation=mode==='phase1'?'contribute':'phase2-contribute';
const runner=new URL('./run-native-privacy-phase1-offline.sh',import.meta.url).pathname;
await assertExecutableUnchanged(executable);
process.stdout.write(['/usr/bin/bash',runner,operation,executable.path,pin,directory,String(ordinal),release,circuit,identity,previous].map(quote).join(' ')+'\n');

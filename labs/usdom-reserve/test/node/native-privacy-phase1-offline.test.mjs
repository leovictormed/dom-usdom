import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,writeFile,readFile,rm,chmod} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {Wallet} from 'ethers';
import {phase1ContributionMessage,phase1DestructionMessage} from '../../sdk/native-privacy-ceremony.mjs';
import os from 'node:os';import path from 'node:path';

const runner=new URL('../../scripts/run-native-privacy-phase1-offline.sh',import.meta.url).pathname;
const sha=value=>createHash('sha256').update(value).digest('hex');
test('offline Phase1 runner keeps entropy internal and publishes create-once artifacts',async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),'usdom-phase1-offline-'));
  try{
    const binary=path.join(root,'verifier');
    const source=`#!/bin/sh\ncase "$1" in\n phase1-init) printf initial;;\n phase1-verify-initial) exit 0;;\n phase1-contribute) printf artifact;;\n phase1-extract) printf accumulator;;\n phase1-verify) exit 0;;\n phase1-specialize) printf pk0;;\n phase2-contribute) printf phase2-artifact;;\n phase2-extract) printf pk1;;\n phase2-verify) exit 0;;\n *) exit 2;; esac\n`;
    await writeFile(binary,source,{mode:0o700});await chmod(binary,0o700);
    const pin=sha(Buffer.from(source)),dir=path.join(root,'artifacts'),h='11'.repeat(32);
    const run=args=>spawnSync('/bin/bash',[runner,...args],{encoding:'utf8'});
    assert.equal(run(['init',binary,pin,dir,'8']).status,0);
    assert.equal(run(['contribute',binary,pin,dir,'1',h,h,h,'0'.repeat(64)]).status,0);
    assert.equal((await readFile(path.join(dir,'phase1-contribution-001.bin'))).toString(),'artifact');
    assert.equal((await readFile(path.join(dir,'phase1-accumulator-001.bin'))).toString(),'accumulator');
    assert.equal(run(['contribute',binary,pin,dir,'1',h,h,h,'0'.repeat(64)]).status,0,'equal rerun resumes safely');
    assert.equal(run(['verify-specialize',binary,pin,dir,'1',sha(Buffer.from('pk0'))]).status,0);
    assert.equal(run(['phase2-contribute',binary,pin,dir,'1',h,h,h,'0'.repeat(64)]).status,0);
    assert.equal((await readFile(path.join(dir,'pk-001.bin'))).toString(),'pk1');
    assert.equal(run(['phase2-contribute',binary,pin,dir,'1',h,h,h,'0'.repeat(64)]).status,0,'equal Phase2 rerun resumes safely');

    const wallet=Wallet.createRandom(),participant=wallet.address;
    const generator=new URL('../../scripts/generate-native-privacy-offline-command.mjs',import.meta.url).pathname;
    const generated=spawnSync('/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node',
      [generator,'phase2',binary,dir,'2',h,h,participant,'22'.repeat(32)],{encoding:'utf8'});
    assert.equal(generated.status,0,generated.stderr);assert.doesNotMatch(generated.stdout,/PLACEHOLDER|CHANGE_ME|PRIVATE_KEY|SECRET_KEY/i);
    const generatorSource=await readFile(generator,'utf8');assert.match(generatorSource,/snapshotExecutablePath/);assert.match(generatorSource,/assertExecutableUnchanged/);
    assert.equal(spawnSync('/bin/bash',['-n'],{input:generated.stdout}).status,0);
    const artifact=path.join(dir,'phase1-contribution-001.bin'),accumulator=path.join(dir,'phase1-accumulator-001.bin');
    const record={ordinal:1,participant,participantCommitment:sha(Buffer.from(participant)),previousRecordHash:'0'.repeat(64),
      previousAccumulatorSha256:sha(Buffer.from('initial')),artifactSha256:sha(await readFile(artifact)),
      accumulatorSha256:sha(await readFile(accumulator)),signature:'',destruction:null};
    record.destruction={participant,artifactSha256:record.artifactSha256,method:'isolated host entropy erased and independently witnessed',destroyedAt:'2026-10-27T15:00:00.000Z',signature:''};
    record.destruction.signature=await wallet.signMessage(phase1DestructionMessage(record.destruction));
    record.signature=await wallet.signMessage(phase1ContributionMessage(record));
    const recordPath=path.join(root,'record.json');await writeFile(recordPath,`${JSON.stringify(record)}\n`,{mode:0o600});
    const imported=path.join(root,'imported');
    const importedResult=spawnSync('/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node',
      [new URL('../../scripts/import-native-privacy-phase1-media.mjs',import.meta.url).pathname,recordPath,artifact,accumulator,imported],{encoding:'utf8'});
    assert.equal(importedResult.status,0,importedResult.stderr);
    const bad={...record,artifactSha256:'ff'.repeat(32)};bad.signature=await wallet.signMessage(phase1ContributionMessage(bad));
    const badPath=path.join(root,'bad.json');await writeFile(badPath,`${JSON.stringify(bad)}\n`,{mode:0o600});
    assert.notEqual(spawnSync('/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node',
      [new URL('../../scripts/import-native-privacy-phase1-media.mjs',import.meta.url).pathname,badPath,artifact,accumulator,path.join(root,'bad-import')]).status,0);
  }finally{await rm(root,{recursive:true,force:true});}
});

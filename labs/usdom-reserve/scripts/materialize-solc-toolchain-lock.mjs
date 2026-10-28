#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {constants,closeSync,fstatSync,openSync,readFileSync,realpathSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable}
  from '../sdk/durable-locked-parent-replacement.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const lockPath=path.join(root,'config/mainnet-toolchain-lock.json');
const manifestPath=path.join(root,'config/solc-0.8.37-official-manifest.json');
const expectedPath='/home/leonardov/.svm/0.8.37/solc-0.8.37';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
let directoryDescriptor;
try {
  const manifestBytes=readFileSync(manifestPath);
  const manifest=parseStrictJson(manifestBytes.toString('utf8'),{label:'pinned solc manifest',maxDepth:4});
  if(manifest.schema!=='usdom-official-solc-release/v1'
      ||manifest.origin!=='https://github.com/argotorg/solidity/releases/download/v0.8.37/solc-static-linux'
      ||manifest.version!=='0.8.37+commit.f401782d.Linux.g++'
      ||manifest.sha256!=='5de843c2c93563cc66425c99a4fb13fdbf32b4c4ae07469480faaf126e14404a') {
    throw new Error('pinned solc manifest differs from the reviewed official release');
  }
  const descriptor=openSync(expectedPath,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
  let observed;
  try {
    const stat=fstatSync(descriptor);
    if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o700) {
      throw new Error('solc ownership/mode/link policy mismatch');
    }
    const binary=readFileSync(descriptor);
    if(sha(binary)!==manifest.sha256) throw new Error('solc hash differs from pinned official manifest');
    observed=execFileSync(`/proc/self/fd/${descriptor}`,['--version'],{encoding:'utf8',timeout:10_000,
      env:{PATH:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}});
  } finally { closeSync(descriptor); }
  if(!observed.includes(`Version: ${manifest.version}`)) throw new Error('solc version output mismatch');
  const lockDirectory=path.dirname(lockPath);
  directoryDescriptor=openSync(lockDirectory,
    constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
  const directoryIdentity=fstatSync(directoryDescriptor);
  if(!directoryIdentity.isDirectory()||directoryIdentity.uid!==process.getuid()
      ||(directoryIdentity.mode&0o022)!==0) throw new Error('toolchain lock directory is unsafe');
  const descriptorDirectory=`/proc/self/fd/${directoryDescriptor}`;
  const descriptorLockPath=path.join(descriptorDirectory,path.basename(lockPath));
  const lockDescriptor=openSync(descriptorLockPath,
    constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
  let before,lockIdentity;
  try {
    const lockStat=fstatSync(lockDescriptor);
    if(!lockStat.isFile()||lockStat.nlink!==1||lockStat.uid!==process.getuid()||(lockStat.mode&0o777)!==0o600) {
      throw new Error('toolchain lock path policy mismatch');
    }
    lockIdentity={dev:lockStat.dev,ino:lockStat.ino,uid:lockStat.uid,mode:lockStat.mode,
      nlink:lockStat.nlink};
    before=readFileSync(lockDescriptor);
  } finally { closeSync(lockDescriptor); }
  const assertLockUnchanged=()=>{
    const current=openSync(descriptorLockPath,
      constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
    try {
      const stat=fstatSync(current);
      for(const field of ['dev','ino','uid','mode','nlink']) {
        if(stat[field]!==lockIdentity[field]) throw new Error('toolchain lock identity changed');
      }
      if(readFileSync(current).compare(before)!==0) throw new Error('toolchain lock content changed');
    } finally { closeSync(current); }
  };
  const lock=parseStrictJson(before.toString('utf8'),{label:'toolchain lock',maxDepth:8});
  if(lock.solc?.path!==expectedPath||lock.solc?.version!=='0.8.37'
      ||(lock.solc.sha256!==null&&lock.solc.sha256!==manifest.sha256)) {
    throw new Error('toolchain lock solc slot is not materializable');
  }
  lock.solc.sha256=manifest.sha256;
  const after=Buffer.from(`${JSON.stringify(lock,null,2)}\n`);
  assertLockUnchanged();
  if(before.compare(after)!==0) {
    assertLockUnchanged();
    const inspector=realpathSync('/usr/bin/python3');
    const inspectorBytes=readFileSync(inspector);
    await replaceLockedParentFileDurable({target:lockPath,contents:after,
      expectedSha256:sha(after),expectedPreviousSha256:sha(before),
      expectedParentDevice:String(directoryIdentity.dev),
      expectedParentInode:String(directoryIdentity.ino),
      metadataInspectorExecutable:inspector,metadataInspectorSha256:sha(inspectorBytes),
      expectedMode:0o600});
  }
  const installed=openSync(descriptorLockPath,
    constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
  try {
    const installedStat=fstatSync(installed);
    if(!installedStat.isFile()||installedStat.nlink!==1||installedStat.uid!==process.getuid()
        ||(installedStat.mode&0o777)!==0o600||readFileSync(installed).compare(after)!==0) {
      throw new Error('materialized toolchain lock verification failed');
    }
  } finally { closeSync(installed); }
  process.stdout.write(`${JSON.stringify({schema:'usdom-solc-lock-materialization/v1',sha256:manifest.sha256})}\n`);
} catch(error) {
  writeReleaseFailure('materialize-solc-toolchain-lock',error);
  process.exitCode=durableReplacementFailureExitCode(error);
} finally {
  if(directoryDescriptor!==undefined) closeSync(directoryDescriptor);
}

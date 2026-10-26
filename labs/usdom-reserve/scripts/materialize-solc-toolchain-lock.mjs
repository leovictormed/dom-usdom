#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {constants,closeSync,fsyncSync,fstatSync,lstatSync,openSync,readFileSync,
  renameSync,rmSync,statSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const lockPath=path.join(root,'config/mainnet-toolchain-lock.json');
const manifestPath=path.join(root,'config/solc-0.8.37-official-manifest.json');
const expectedPath='/home/leonardov/.svm/0.8.37/solc-0.8.37';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
let temporary;
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
  let binary;
  try {
    const stat=fstatSync(descriptor);
    if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o777)!==0o700) {
      throw new Error('solc ownership/mode/link policy mismatch');
    }
    binary=readFileSync(descriptor);
  } finally { closeSync(descriptor); }
  if(sha(binary)!==manifest.sha256) throw new Error('solc hash differs from pinned official manifest');
  const observed=execFileSync(expectedPath,['--version'],{encoding:'utf8',timeout:10_000,
    env:{PATH:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}});
  if(!observed.includes(`Version: ${manifest.version}`)) throw new Error('solc version output mismatch');
  const before=readFileSync(lockPath);
  const lockStat=lstatSync(lockPath);
  if(!lockStat.isFile()||lockStat.isSymbolicLink()||lockStat.nlink!==1||lockStat.uid!==process.getuid()) {
    throw new Error('toolchain lock path policy mismatch');
  }
  const lock=parseStrictJson(before.toString('utf8'),{label:'toolchain lock',maxDepth:8});
  if(lock.solc?.path!==expectedPath||lock.solc?.version!=='0.8.37'
      ||(lock.solc.sha256!==null&&lock.solc.sha256!==manifest.sha256)) {
    throw new Error('toolchain lock solc slot is not materializable');
  }
  lock.solc.sha256=manifest.sha256;
  const after=Buffer.from(`${JSON.stringify(lock,null,2)}\n`);
  if(readFileSync(lockPath).compare(before)!==0) throw new Error('toolchain lock changed during materialization');
  temporary=`${lockPath}.new-${process.pid}`;
  const fd=openSync(temporary,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try { writeFileSync(fd,after); fsyncSync(fd); } finally { closeSync(fd); }
  if(readFileSync(lockPath).compare(before)!==0) throw new Error('toolchain lock changed before install');
  renameSync(temporary,lockPath); temporary=undefined;
  process.stdout.write(`${JSON.stringify({schema:'usdom-solc-lock-materialization/v1',sha256:manifest.sha256})}\n`);
} catch(error) {
  if(temporary) try { rmSync(temporary); } catch {}
  writeReleaseFailure('materialize-solc-toolchain-lock',error);
  process.exitCode=1;
}

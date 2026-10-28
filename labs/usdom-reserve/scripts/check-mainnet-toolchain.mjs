#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {
  assertExecutableUnchanged,snapshotExecutablePath,
} from '../sdk/stable-executable.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repositoryRoot=path.resolve(root,'../..');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const toolPolicies=new Map([
  ['bash',{args:['--version'],version:'5.2.21'}],
  ['node',{args:['--version'],version:'v24.19.0'}],
  ['npm',{args:['--version'],version:'11.17.0'}],
  ['forge',{args:['--version'],version:'1.8.5'}],
  ['cast',{args:['--version'],version:'1.8.5'}],
  ['rustc',{args:['--version'],version:'1.98.0'}],
  ['cargo',{args:['--version'],version:'1.98.0'}],
  ['python3',{args:['--version'],version:'3.12.3'}],
  ['jq',{args:['--version'],version:'jq-1.7'}],
]);
const lockedFiles=new Map([
  ['package-lock.json','labs/usdom-reserve/package-lock.json'],
  ['containers/risc0-snarkjs/package-lock.json','labs/usdom-reserve/containers/risc0-snarkjs/package-lock.json'],
  ['../../Cargo.lock','Cargo.lock'],
  ['foundry.toml','labs/usdom-reserve/foundry.toml'],
  ['scripts/mainnet-tool-dispatcher','labs/usdom-reserve/scripts/mainnet-tool-dispatcher'],
]);

function decodeVersion(bytes,label) {
  let value;
  try { value=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} version output is not valid UTF-8`); }
  if(value.length===0||value.length>16*1024||value.includes('\0')||value.includes('\r')) {
    throw new Error(`${label} version output framing is invalid`);
  }
  return value;
}

try {
  const lockBytes=await readDirectProjectFile(root,'config/mainnet-toolchain-lock.json',{
    minimum:2,maximum:256*1024,label:'toolchain lock',
  });
  const lock=parseStrictJsonBytes(lockBytes,{label:'toolchain lock',maxBytes:256*1024,maxDepth:8});
  if(!exact(lock,['executables','files','rustToolchain','schema','solc','solcVersion'])
      ||lock.schema!=='usdom-mainnet-toolchain-lock/v1'||!Array.isArray(lock.executables)
      ||!Array.isArray(lock.files)||lock.solcVersion!=='0.8.37'||lock.rustToolchain!=='1.98.0'
      ||lock.executables.length!==toolPolicies.size||lock.files.length!==lockedFiles.size) {
    throw new Error('toolchain lock schema or versions are invalid');
  }
  const snapshots=[];
  const seenTools=new Set();
  for(const tool of lock.executables) {
    if(!exact(tool,['name','path','realpath','sha256','versionContains'])
        ||!toolPolicies.has(tool.name)||seenTools.has(tool.name)
        ||typeof tool.path!=='string'||!path.isAbsolute(tool.path)
        ||typeof tool.realpath!=='string'||!path.isAbsolute(tool.realpath)
        ||!/^[0-9a-f]{64}$/.test(tool.sha256)
        ||tool.versionContains!==toolPolicies.get(tool.name).version) {
      throw new Error('tool entry is invalid');
    }
    seenTools.add(tool.name);
    const snapshot=await snapshotExecutablePath(tool.path);
    if(snapshot.path!==tool.realpath||snapshot.sha256!==tool.sha256) {
      throw new Error(`${tool.name} executable identity mismatch`);
    }
    const policy=toolPolicies.get(tool.name);
    const output=await runPinnedExecutable(snapshot,policy.args,{
      cwd:root,maxBuffer:16*1024,timeout:30_000,
    });
    const version=decodeVersion(Buffer.concat([output.stdout,output.stderr]),tool.name);
    if(!version.includes(policy.version)) throw new Error(`${tool.name} version mismatch`);
    snapshots.push(snapshot);
  }
  const seenFiles=new Set();
  for(const file of lock.files) {
    if(!exact(file,['path','sha256'])||!lockedFiles.has(file.path)
        ||seenFiles.has(file.path)||!/^[0-9a-f]{64}$/.test(file.sha256)) {
      throw new Error('locked file entry is invalid');
    }
    seenFiles.add(file.path);
    const bytes=await readDirectProjectFile(repositoryRoot,lockedFiles.get(file.path),{
      minimum:1,maximum:64*1024*1024,label:`locked file ${file.path}`,
    });
    if(hash(bytes)!==file.sha256) throw new Error(`${file.path} hash mismatch`);
  }
  if(!exact(lock.solc,['path','sha256','version'])
      ||lock.solc.path!=='/home/leonardov/.svm/0.8.37/solc-0.8.37'
      ||lock.solc.version!=='0.8.37'||!/^[0-9a-f]{64}$/.test(lock.solc.sha256??'')) {
    throw new Error('solc 0.8.37 is not pre-staged and hash-locked');
  }
  const solc=await snapshotExecutablePath(lock.solc.path);
  if(solc.path!==lock.solc.path||solc.sha256!==lock.solc.sha256) {
    throw new Error('solc executable identity mismatch');
  }
  const solcOutput=await runPinnedExecutable(solc,['--version'],{
    cwd:root,maxBuffer:16*1024,timeout:30_000,
  });
  if(!decodeVersion(Buffer.concat([solcOutput.stdout,solcOutput.stderr]),'solc')
    .includes('0.8.37')) throw new Error('solc executable version mismatch');
  snapshots.push(solc);
  const rustToolchain=await readDirectProjectFile(repositoryRoot,'rust-toolchain.toml',{
    minimum:1,maximum:64*1024,label:'Rust toolchain selector',
  });
  const expectedRustToolchain=Buffer.from(
    '[toolchain]\nchannel = "1.98.0"\ncomponents = ["rustfmt", "clippy"]\n',
  );
  if(!rustToolchain.equals(expectedRustToolchain)) {
    throw new Error('Rust toolchain selector changed');
  }
  const guestLauncher=await snapshotExecutablePath(
    path.join(root,'scripts/risc0-guest-build-launcher'));
  const launcherOutput=await runPinnedExecutable(guestLauncher,['--preflight'],{
    cwd:root,maxBuffer:16*1024,timeout:30_000,
  });
  if(decodeVersion(Buffer.concat([launcherOutput.stdout,launcherOutput.stderr]),'guest launcher')
    !=='PASS: RISC Zero guest launcher preflight\n') {
    throw new Error('RISC Zero guest launcher preflight failed');
  }
  snapshots.push(guestLauncher);
  await Promise.all(snapshots.map(assertExecutableUnchanged));
  process.stdout.write(`${JSON.stringify({schema:lock.schema,status:'verified',
    tools:lock.executables.length,files:lock.files.length})}\n`);
} catch(error) {
  writeReleaseFailure('check-mainnet-toolchain',error);
  process.exitCode=1;
}

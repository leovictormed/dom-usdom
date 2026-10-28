import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {validateUnconfiguredOneKeyElectronBlePackageAuthority,
 loadUnconfiguredOneKeyElectronBlePackageAuthority} from '../../sdk/onekey-electron-ble-package-authority.mjs';

const source=new URL('../../config/onekey-electron-ble-package-authority.unconfigured.json',import.meta.url);
const clone=value=>structuredClone(value);

test('real package authority is strict, direct and wholly fail-closed',async()=>{
 const authority=await loadUnconfiguredOneKeyElectronBlePackageAuthority(source.pathname);
 assert.equal(Object.values(authority.gates).every(value=>value===false),true);
 assert.equal(Object.values(authority.packagePins).every(value=>value===null),true);
});

test('fake package pins, approvals, fallbacks and unknown fields are rejected',async()=>{
 const base=JSON.parse(await readFile(source,'utf8'));
 for(const mutate of [
  value=>{value.packagePins.electronVersion='99.0.0';},
  value=>{value.gates.packagedArtifactVerified=true;},
  value=>{value.hardwareSigningApproved=true;},
  value=>{value.runtimeTransport='usb';},
  value=>{value.forbiddenFallbacks=['usb'];},
  value=>{value.packagePins.archivePath='../../outside';},
  value=>{value.gates.usbFallbackApproved=false;},
  value=>{value.unreviewed=true;}
 ]) {
  const candidate=clone(base); mutate(candidate);
  assert.throws(()=>validateUnconfiguredOneKeyElectronBlePackageAuthority(candidate));
 }
});

test('loader rejects duplicate JSON, unsafe mode and oversized authority',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'usdom-onekey-package-'));
 try {
  await chmod(directory,0o700);
  const file=join(directory,'authority.json');
  await writeFile(file,'{"schema":"a","schema":"b"}',{mode:0o644});
  await chmod(file,0o644);
  await assert.rejects(loadUnconfiguredOneKeyElectronBlePackageAuthority(file),/duplicate/u);
  await writeFile(file,await readFile(source)); await chmod(file,0o600);
  await assert.rejects(loadUnconfiguredOneKeyElectronBlePackageAuthority(file),/safe direct regular file/u);
  await writeFile(file,Buffer.alloc(32769,0x20)); await chmod(file,0o644);
  await assert.rejects(loadUnconfiguredOneKeyElectronBlePackageAuthority(file),/safe direct regular file/u);
 } finally { await rm(directory,{recursive:true,force:true}); }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {auditOneKeySdkDependencyAuthority} from '../../sdk/onekey-sdk-dependency-authority.mjs';

const read=path=>JSON.parse(readFileSync(new URL(path,import.meta.url),'utf8'));
const base=()=>({authority:structuredClone(read('../../config/onekey-sdk-dependency-authority.json')),
 packageJson:structuredClone(read('../../package.json')),
 packageLock:structuredClone(read('../../package-lock.json'))});

test('OneKey 1.2.7 authority pins safe overrides and keeps hardware closed',()=>{
 const result=auditOneKeySdkDependencyAuthority(base());
 assert.equal(result.ok,true,JSON.stringify(result.violations));
 assert.equal(result.packages,11);
});

test('dependency authority rejects package, integrity, override and audit drift',()=>{
 for(const mutate of [
  value=>{value.packageJson.dependencies['@onekeyfe/hd-core']='1.2.6';},
  value=>{value.packageJson.dependencies['@onekeyfe/hd-transport-usb']='1.2.7';},
  value=>{value.packageLock.packages['node_modules/@onekeyfe/hd-transport-web-device'].integrity='sha512-evil';},
  value=>{value.packageJson.overrides.protobufjs='6.11.6';},
  value=>{value.packageLock.packages['node_modules/axios'].version='1.15.2';},
  value=>{value.authority.audit.vulnerabilities.high=1;value.authority.audit.vulnerabilities.total=1;},
  value=>{value.authority.hardwareSigningApproved=true;},
  value=>{value.authority.deviceIdentity.firmwareAllowlist=['unverified'];},
  value=>{value.authority.electronBleHost.hostPackageAccepted=true;},
  value=>{value.authority.electronBleHost.securityProfile.nodeIntegration=true;},
 ]) {
  const input=base(); mutate(input);
  assert.equal(auditOneKeySdkDependencyAuthority(input).ok,false);
 }
});

test('fresh npm audit report must contain zero findings',()=>{
 const input=base();
 input.auditReport={metadata:{vulnerabilities:{info:0,low:0,moderate:0,high:1,critical:0,total:1}}};
 const result=auditOneKeySdkDependencyAuthority(input);
 assert.equal(result.ok,false);
 assert.ok(result.violations.some(value=>value.reason==='dependency-audit'));
});

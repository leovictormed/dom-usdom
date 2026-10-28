#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {SignClient} from '@walletconnect/sign-client';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

const authority=parseStrictJsonBytes(await readFile(new URL('../config/walletconnect-sign-client-dependency-authority.json',import.meta.url)),{label:'WalletConnect dependency authority'});
const lock=JSON.parse(await readFile(new URL('../package-lock.json',import.meta.url),'utf8'));
const pkg=lock.packages?.['node_modules/@walletconnect/sign-client'];
if(authority.schema!=='usdom-walletconnect-sign-client-dependency-authority/v1'||authority.package!=='@walletconnect/sign-client'
  ||pkg?.version!==authority.version||pkg?.integrity!==authority.integrity
  ||authority.version!=='2.26.0'||authority.auditVulnerabilities!==0
  ||authority.communityLicenseAccepted!==false||authority.runtimeConfigured!==false
  ||authority.networkExecutionApproved!==false)throw new Error('WalletConnect SignClient dependency authority rejected');
if(!Array.isArray(authority.runtimePins)||authority.runtimePins.length!==6)throw new Error('WalletConnect runtime pin set rejected');
for(const pin of authority.runtimePins) {
  const installed=lock.packages?.[`node_modules/${pin.package}`];
  if(!installed||installed.version!==pin.version||installed.integrity!==pin.integrity||installed.license!==pin.license) {
    throw new Error(`WalletConnect runtime dependency drift: ${pin.package}`);
  }
}
const license=await readFile(new URL('../node_modules/@walletconnect/sign-client/LICENSE.md',import.meta.url));
if(createHash('sha256').update(license).digest('hex')!==authority.licenseSha256)throw new Error('WalletConnect license bytes drift');
if(typeof SignClient?.init!=='function')throw new Error('WalletConnect SignClient runtime export unavailable');
console.log('WalletConnect SignClient dependency pin: valid; runtime and license approval: blocked');

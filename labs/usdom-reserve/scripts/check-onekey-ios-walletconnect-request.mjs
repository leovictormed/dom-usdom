#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {getAddress,TypedDataEncoder} from 'ethers';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readOneKeyIosWalletConnectClientConfig} from '../sdk/onekey-ios-walletconnect-client.mjs';
import {readOneKeyIosTypedDataRequest} from '../sdk/onekey-ios-walletconnect-typed-data.mjs';
const canonical=value=>value===null||typeof value==='boolean'||typeof value==='string'||typeof value==='number'
 ?JSON.stringify(value):Array.isArray(value)?`[${value.map(canonical).join(',')}]`
 :`{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;

if(process.argv.length!==7){console.error('usage: check-onekey-ios-walletconnect-request.mjs CONFIG ENVELOPE PHYSICAL_EVIDENCE EXPECTED_ADDRESS REQUEST');process.exit(64);}
try {
 const config=await readOneKeyIosWalletConnectClientConfig(process.argv[2]);
 const envelope=parseStrictJsonBytes(await readDirectFile(process.argv[3],{minimum:2,maximum:2*1024*1024,
  privateMode:true,exactMode:0o600,label:'private EIP-712 envelope'}),{label:'private EIP-712 envelope'});
 const physicalBytes=await readDirectFile(process.argv[4],{minimum:2,maximum:65536,privateMode:true,exactMode:0o600,
  label:'physical OneKey account evidence'});
 const physical=parseStrictJsonBytes(physicalBytes,{label:'physical OneKey account evidence'});
 const request=await readOneKeyIosTypedDataRequest(process.argv[6]),expected=getAddress(process.argv[5]);
 const physicalKeys=['schema','status','projectIdSha256','address','roles','walletConnectExposesDeviceIdentity',
  'physicalConfirmationSource','model','addressShownOnDevice','operatorConfirmed','singleOperatorResidualRisk',
  'hardwareSigningApproved','realFundsApproved'].sort();
 const types={...envelope.typedData?.types};delete types.EIP712Domain;
 const digest=TypedDataEncoder.hash(envelope.typedData.domain,types,envelope.typedData.message);
 if(envelope.schema!=='usdom-onekey-eip712-signing/v1'||digest!==envelope.digest||request.digest!==digest
  ||request.expectedAddress!==expected||request.walletConnectProjectId!==config.projectId
  ||request.physicalEvidenceSha256!==createHash('sha256').update(physicalBytes).digest('hex')
  ||Object.keys(physical??{}).sort().join(',')!==physicalKeys.join(',')
  ||physical.schema!=='usdom-onekey-ios-onboarding-evidence-v1'
  ||physical.status!=='observed-awaiting-role-ratification'
  ||physical.projectIdSha256!==createHash('sha256').update(config.projectId).digest('hex')
  ||physical.walletConnectExposesDeviceIdentity!==false
  ||physical.physicalConfirmationSource!=='human-observed-device-screen'||physical.model!=='classic1s'
  ||physical.addressShownOnDevice!==true||physical.operatorConfirmed!==true
  ||physical.hardwareSigningApproved!==false||physical.realFundsApproved!==false
  ||getAddress(physical.address)!==expected||request.onboardingProjectIdSha256!==physical.projectIdSha256
  ||request.confirmationSource!==physical.physicalConfirmationSource||request.model!==physical.model
  ||canonical(request.typedData)!==canonical(envelope.typedData))throw new Error('WalletConnect request does not match current ceremony');
}catch(error){console.error(error?.message??'WalletConnect request rejected');process.exit(1);}

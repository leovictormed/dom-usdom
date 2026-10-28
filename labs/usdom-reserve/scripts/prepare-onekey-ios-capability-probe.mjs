#!/usr/bin/env node
import {keccak256,toUtf8Bytes} from 'ethers';
import {readOneKeyIosWalletConnectClientConfig} from '../sdk/onekey-ios-walletconnect-client.mjs';
import {prepareOneKeyIosTypedDataRequest} from '../sdk/onekey-ios-walletconnect-typed-data.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

if(process.argv.length!==5) {
 process.stderr.write('usage: prepare-onekey-ios-capability-probe.mjs CONFIG PHYSICAL_EVIDENCE REQUEST\n');
 process.exit(64);
}
const [configPath,physicalEvidencePath,requestPath]=process.argv.slice(2);
const config=await readOneKeyIosWalletConnectClientConfig(configPath);
const evidence=parseStrictJsonBytes(await readDirectFile(physicalEvidencePath,{minimum:2,maximum:16384,
 privateMode:true,exactMode:0o600,label:'OneKey iOS physical account evidence'}),
 {label:'OneKey iOS physical account evidence'});
const typedData={types:{EIP712Domain:[{name:'name',type:'string'},{name:'version',type:'string'},
 {name:'chainId',type:'uint256'},{name:'verifyingContract',type:'address'}],
 Capability:[{name:'action',type:'bytes32'},{name:'nonce',type:'uint256'}]},primaryType:'Capability',
 domain:{name:'USDOM OneKey Capability Probe',version:'1',chainId:1,
  verifyingContract:'0x000000000000000000000000000000000000dEaD'},
 message:{action:keccak256(toUtf8Bytes('USD0M_ONEKEY_IOS_EIP712_CAPABILITY_PROBE')),nonce:'0'}};
await prepareOneKeyIosTypedDataRequest({path:requestPath,expectedAddress:evidence.address,typedData,
 physicalEvidencePath,walletConnectProjectId:config.projectId});

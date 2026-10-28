import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {Wallet,TypedDataEncoder} from 'ethers';

const script=new URL('../../scripts/sign-release-authorizations.sh',import.meta.url);
test('release authorization uses deterministic private iPhone WalletConnect handoffs and never BLE identity',async()=>{
 const source=await readFile(script,'utf8');
 assert.equal(spawnSync('bash',['-n',fileURLToPath(script)],{encoding:'utf8'}).status,0);
 for(const marker of ['onekey-walletconnect-client.json','onekey-walletconnect-release-authorizations',
  'onekey-governance-owner-$((index + 1))-physical-account.json','prepare-onekey-ios-walletconnect-request.mjs',
  'check-onekey-ios-walletconnect-request.mjs','sign-onekey-ios-walletconnect-typed-data.mjs','extract-onekey-ios-walletconnect-signature.mjs',
  'assemble-onekey-safe-signatures.mjs','signing_state=signed-unresolved','status=80'])assert.ok(source.includes(marker),marker);
 assert.match(source,/\$mode-\$name-owner-\$\(\(index \+ 1\)\)-request\.json/);
 assert.match(source,/\$mode-\$name-owner-\$\(\(index \+ 1\)\)-response\.json/);
 assert.match(source,/if test ! -e "\$wc_response"[\s\S]*run_bounded_walletconnect/);
 assert.ok(source.indexOf('check-onekey-ios-walletconnect-request.mjs')<source.indexOf('if test ! -e "$wc_response"'));
 assert.ok(source.indexOf('signing_state=signed-unresolved')<source.indexOf('extract-onekey-ios-walletconnect-signature.mjs'));
 assert.ok(source.lastIndexOf('signing_state=clean')>source.lastIndexOf('install-private-file-new-stdin.mjs'));
 assert.doesNotMatch(source,/sign-onekey-mainnet-typed-data|onekey-governance-owner-.*-identity|Bluetooth|--ledger|eth_sendTransaction/iu);
 assert.doesNotMatch(source,/curl|wget|cast send|eth_sendRawTransaction/iu);
});

test('all three release wrappers enter the same hardened mobile signer without inheriting descriptors',async()=>{
 for(const [name,mode] of [['sign-native-release-attestations.sh','native'],['sign-production-release-authorization.sh','release'],
  ['sign-pilot-funds-authorization.sh','pilot']]) {
  const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
  assert.match(source,/set \+x/);assert.match(source,/unset BASH_XTRACEFD/);assert.match(source,/inherited_fd/);
  assert.match(source,new RegExp(`sign-release-authorizations\\.sh ${mode}`));
 }
});

test('existing durable request is checked against current owner, evidence, project and typed data before signing',async()=>{
 const root=fileURLToPath(new URL('../..',import.meta.url)),dir=await mkdtemp('/dev/shm/usdom-release-wc2325-');
 try {
  const wallet=new Wallet('0x'+'81'.repeat(32)),config=join(dir,'config.json'),evidence=join(dir,'physical.json'),
    envelope=join(dir,'envelope.json'),request=join(dir,'request.json');
  const typedData={types:{EIP712Domain:[{name:'chainId',type:'uint256'}],Release:[{name:'nonce',type:'uint256'}]},
    primaryType:'Release',domain:{chainId:1},message:{nonce:25}};
  const types={...typedData.types};delete types.EIP712Domain;
  await writeFile(config,JSON.stringify({schema:'usdom-onekey-ios-walletconnect-client-config/v1',projectId:'82'.repeat(16),
    metadata:{name:'USDOM',description:'release',url:'https://example.invalid',icons:['https://example.invalid/i.png']},
    communityLicenseAccepted:true,networkExecutionApproved:true})+'\n',{mode:0o600,flag:'wx'});
  await writeFile(evidence,JSON.stringify({schema:'usdom-onekey-ios-hardware-account-evidence/v1',source:'onekey-ios-app',
    deviceId:'classic1s-release',firmware:'4.13.0',address:wallet.address,appReleaseSha256:'83'.repeat(32),
    hardwareAddressConfirmed:true,hardwareAccountSelected:true,ratified:true,hardwareSigningApproved:false})+'\n',{mode:0o600,flag:'wx'});
  const document={schema:'usdom-onekey-eip712-signing/v1',digest:TypedDataEncoder.hash(typedData.domain,types,typedData.message),typedData};
  await writeFile(envelope,JSON.stringify(document)+'\n',{mode:0o600,flag:'wx'});
  let result=spawnSync(process.execPath,['scripts/prepare-onekey-ios-walletconnect-request.mjs',config,envelope,evidence,wallet.address,request],{cwd:root,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  result=spawnSync(process.execPath,['scripts/check-onekey-ios-walletconnect-request.mjs',config,envelope,evidence,wallet.address,request],{cwd:root,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  document.typedData.message.nonce=26;document.digest=TypedDataEncoder.hash(typedData.domain,types,document.typedData.message);
  await writeFile(envelope,JSON.stringify(document)+'\n',{mode:0o600});
  result=spawnSync(process.execPath,['scripts/check-onekey-ios-walletconnect-request.mjs',config,envelope,evidence,wallet.address,request],{cwd:root,encoding:'utf8'});
  assert.notEqual(result.status,0);
 }finally{await rm(dir,{recursive:true,force:true});}
});

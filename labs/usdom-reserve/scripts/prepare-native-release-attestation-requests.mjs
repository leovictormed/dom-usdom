#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readRuntimeSecretJsonFile} from '../sdk/runtime-secret-json.mjs';
import {createHash} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {TypedDataEncoder} from 'ethers';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';
import {validateNativePrivacyInstallationReceipt} from '../sdk/native-privacy-ceremony.mjs';
import {
  buildNativeReleaseAttestation,nativeReleaseAttestationTypedData,
} from '../sdk/native-release-attestation.mjs';
import {collectReleaseAuthorizationAnchor,resolveReleaseAuthorizationRpcSources,
  withReleaseAuthorizationProviders} from '../sdk/release-authorization-rpc.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repository=path.resolve(root,'../..');
const parseJson=(bytes,relative)=>parseStrictJsonBytes(bytes,{
  label:relative,maxBytes:4*1024*1024,maxDepth:64,
});
const sha=value=>createHash('sha256').update(value).digest('hex');
const fixedInputs=[
  ['config/mainnet-release-evidence.unconfigured.json',{exactMode:0o644}],
  ['config/proof-reserve.unconfigured.json',{exactMode:0o644}],
  ['config/mainnet-preflight-rpc-catalog.json',{exactMode:0o644,maximum:1024*1024}],
];
const readFixedInputs=()=>Promise.all(fixedInputs.map(([relative,options])=>
  readDirectProjectFile(root,relative,{...options,minimum:1,maximum:4*1024*1024,label:relative})));
function parseValidation(output) {
  if(!Buffer.isBuffer(output)) throw new Error('native runtime checker output must be bytes');
  let text;
  try { text=new TextDecoder('utf-8',{fatal:true}).decode(output); }
  catch { throw new Error('native runtime checker output is not valid UTF-8'); }
  if(text.length===0||!text.endsWith('\n')||text.endsWith('\n\n')||text.includes('\r')) {
    throw new Error('native runtime checker output framing is invalid');
  }
  const result=Object.create(null);
  for(const line of text.slice(0,-1).split('\n')) {
    const match=/^([a-z0-9_]+): (.+)$/.exec(line);
    if(!match||Object.hasOwn(result,match[1])) throw new Error('native runtime checker output is invalid');
    result[match[1]]=match[2];
  }
  return result;
}

const privateWalletEvidenceBytes=[];
async function readPrivateWalletEvidence(target,options) {
  const bytes=await readDirectFile(target,options);
  privateWalletEvidenceBytes.push(bytes);
  return bytes;
}
try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const fixedBytes=await readFixedInputs();
  const [releaseEvidence,releaseConfig]=fixedBytes.slice(0,2).map((bytes,index)=>
    parseJson(bytes,fixedInputs[index][0]));
  const manifestDocument=releaseEvidence.nativeRuntimeManifest;
  if(typeof manifestDocument?.path!=='string'||!/^[0-9a-f]{64}$/.test(manifestDocument.sha256??'')) {
    throw new Error('native runtime manifest evidence is missing');
  }
  const manifestBytes=await readDirectProjectFile(root,manifestDocument.path,{
    minimum:1,maximum:4*1024*1024,exactMode:0o600,label:'native runtime manifest',
  });
  if(sha(manifestBytes)!==manifestDocument.sha256) throw new Error('native runtime manifest hash mismatch');
  const cargo=await snapshotExecutable('cargo');
  const checked=await runPinnedExecutable(cargo,[
    'run','--quiet','--locked','-p','dom-node','--features','native-usdom-v4-poc',
    '--bin','dom-usdom-manifest-check','--','--manifest-file',path.resolve(root,manifestDocument.path),
    '--manifest-sha256',manifestDocument.sha256,'--network','mainnet',
  ],{cwd:repository,maxBuffer:4*1024*1024,timeout:10*60*1000});
  if(checked.stderr.length!==0) throw new Error('native runtime checker wrote stderr');
  const validation=parseValidation(checked.stdout);
  if(validation.status!=='valid'||!/^[0-9a-f]{64}$/.test(validation.privacy_verifier_config_hash??'')) {
    throw new Error('native runtime checker did not validate the privacy verifier');
  }
  const accountHome=os.userInfo().homedir;
  if(!path.isAbsolute(accountHome)||accountHome==='/'||os.homedir()!==accountHome
      ||process.env.HOME!==accountHome) throw new Error('account home identity is unsafe');
  const walletRoot=path.join(accountHome,'.local/share/dom-usdom/mainnet-wallet');
  const publicIdentityPath=path.join(walletRoot,'public-identity.json');
  const tpmEvidencePath=path.join(walletRoot,'tpm2-keystore-v1.json');
  const recoveryEvidencePath=path.join(walletRoot,'recovery-drill-v1/wallet-recovery-drill.json');
  const privacyInstallationPath=path.join(accountHome,'.local/share/dom-usdom/mainnet-privacy/installation.json');
  const privacyRoot=path.dirname(privacyInstallationPath);
  const privacyTranscriptPath=path.join(privacyRoot,'ceremony-transcript.json');
  const privacyVerifyingKeyPath=path.join(privacyRoot,'spend-verifying-key.bin');
  const privacyManifestPath=path.join(privacyRoot,'native-usdom-v2.json');
  const [identityBytes,tpmBytes,recoveryBytes,privacyInstallationBytes,privacyTranscriptBytes,
    privacyVerifyingKeyBytes,privacyManifestBytes]=await Promise.all([
    readPrivateWalletEvidence(publicIdentityPath,{minimum:1,maximum:4*1024*1024,privateMode:true,
      label:'wallet public identity'}),
    readPrivateWalletEvidence(tpmEvidencePath,{minimum:1,maximum:4*1024*1024,privateMode:true,
      label:'TPM custody evidence'}),
    readPrivateWalletEvidence(recoveryEvidencePath,{minimum:1,maximum:4*1024*1024,privateMode:true,
      label:'wallet recovery evidence'}),
    readPrivateWalletEvidence(privacyInstallationPath,{minimum:1,maximum:4*1024*1024,privateMode:true,
      label:'native privacy VK installation receipt'}),
    readPrivateWalletEvidence(privacyTranscriptPath,{minimum:1,maximum:8*1024*1024,privateMode:true,
      label:'installed native privacy ceremony transcript'}),
    readPrivateWalletEvidence(privacyVerifyingKeyPath,{minimum:1,maximum:16*1024*1024,privateMode:true,
      label:'installed native privacy verifying key'}),
    readPrivateWalletEvidence(privacyManifestPath,{minimum:1,maximum:4*1024*1024,privateMode:true,
      label:'installed native privacy runtime manifest'}),
  ]);
  const [identity,tpm,recovery,privacyInstallation]=[
    parseJson(identityBytes,'wallet public identity'),
    parseJson(tpmBytes,'TPM custody evidence'),
    parseJson(recoveryBytes,'wallet recovery evidence'),
    parseJson(privacyInstallationBytes,'native privacy VK installation receipt'),
  ];
  const identitySha=sha(identityBytes);
  const custodyEvidenceSha=sha(tpmBytes);
  const recoveryEvidenceSha=sha(recoveryBytes);
  validateNativePrivacyInstallationReceipt(privacyInstallation,{
    nativeRuntimeManifestBytes:manifestBytes,
    ceremonyTranscriptBytes:privacyTranscriptBytes,
    verifyingKeyBytes:privacyVerifyingKeyBytes,
    privacyVerifierConfigHash:validation.privacy_verifier_config_hash,
    verifyingKeySha256:validation.spend_verifying_key_sha256,
  });
  if(identity.schema!=='usdom-native-receiving-wallet-public-v1'
      || tpm.schema!=='usdom-tpm2-wallet-keystore-v1'
      || recovery.schema!=='usdom-wallet-recovery-drill-v1'
      || tpm.public_identity_sha256!==identitySha || tpm.wallet_address!==identity.recipient_address
      || recovery.wallet_address!==identity.recipient_address
      || tpm.native_manifest_sha256!==manifestDocument.sha256
      || recovery.native_manifest_sha256!==manifestDocument.sha256
      ||privacyInstallation.schema!=='usdom-native-privacy-vk-installation-v2'
      ||!privacyManifestBytes.equals(manifestBytes)) {
    throw new Error('wallet custody, recovery, identity and native runtime do not reconcile');
  }
  const catalog=parseJson(fixedBytes.at(-1),'mainnet preflight RPC catalog');
  const runtimeSources=readRuntimeSecretJsonFile('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',{label:'USDOM_MAINNET_PREFLIGHT_RPC_SOURCES',maxBytes:32*1024,maxDepth:8});
  const sources=resolveReleaseAuthorizationRpcSources({catalog,runtimeSources});
  const anchor=await withReleaseAuthorizationProviders(sources,providers=>
    collectReleaseAuthorizationAnchor({providers,releaseConfig,sources}));
  const completedAt=anchor.blockTimestamp;
  const subjects={
    nativePrivacyTrustedSetup:`0x${validation.privacy_verifier_config_hash}`,
    nativeScheduledRuntimeActivation:`0x${manifestDocument.sha256}`,
    nativeWalletCustody:`0x${custodyEvidenceSha}`,
    nativeWalletRecovery:`0x${recoveryEvidenceSha}`,
  };
  const kinds={nativePrivacyTrustedSetup:'native-privacy-trusted-setup',
    nativeScheduledRuntimeActivation:'native-scheduled-runtime-activation',
    nativeWalletCustody:'native-wallet-custody',nativeWalletRecovery:'native-wallet-recovery'};
  const requests=Object.fromEntries(Object.entries(kinds).map(([name,kind])=>{
    const built=buildNativeReleaseAttestation({kind,releaseEvidence,releaseConfig,completedAt,
      subjectCommitment:subjects[name]});
    const typed=nativeReleaseAttestationTypedData(built.attestation,releaseConfig);
    return [name,{attestation:built.attestation,digest:built.digest,
      typedData:TypedDataEncoder.getPayload(typed.domain,typed.types,typed.message)}];
  }));
  const [currentFixedBytes,currentManifestBytes,currentIdentityBytes,currentTpmBytes,
    currentRecoveryBytes,currentPrivacyInstallationBytes,currentPrivacyTranscriptBytes,
    currentPrivacyVerifyingKeyBytes,currentPrivacyManifestBytes]=await Promise.all([
    readFixedInputs(),
    readDirectProjectFile(root,manifestDocument.path,{
      minimum:manifestBytes.length,maximum:manifestBytes.length,exactMode:0o600,
      label:'native runtime manifest',
    }),
    readPrivateWalletEvidence(publicIdentityPath,{minimum:identityBytes.length,maximum:identityBytes.length,
      privateMode:true,label:'wallet public identity'}),
    readPrivateWalletEvidence(tpmEvidencePath,{minimum:tpmBytes.length,maximum:tpmBytes.length,
      privateMode:true,label:'TPM custody evidence'}),
    readPrivateWalletEvidence(recoveryEvidencePath,{minimum:recoveryBytes.length,maximum:recoveryBytes.length,
      privateMode:true,label:'wallet recovery evidence'}),
    readPrivateWalletEvidence(privacyInstallationPath,{minimum:privacyInstallationBytes.length,maximum:privacyInstallationBytes.length,
      privateMode:true,label:'native privacy VK installation receipt'}),
    readPrivateWalletEvidence(privacyTranscriptPath,{minimum:privacyTranscriptBytes.length,maximum:privacyTranscriptBytes.length,
      privateMode:true,label:'installed native privacy ceremony transcript'}),
    readPrivateWalletEvidence(privacyVerifyingKeyPath,{minimum:privacyVerifyingKeyBytes.length,maximum:privacyVerifyingKeyBytes.length,
      privateMode:true,label:'installed native privacy verifying key'}),
    readPrivateWalletEvidence(privacyManifestPath,{minimum:privacyManifestBytes.length,maximum:privacyManifestBytes.length,
      privateMode:true,label:'installed native privacy runtime manifest'}),
  ]);
  if(currentFixedBytes.some((bytes,index)=>!bytes.equals(fixedBytes[index]))
      ||!currentManifestBytes.equals(manifestBytes)||!currentIdentityBytes.equals(identityBytes)
      ||!currentTpmBytes.equals(tpmBytes)||!currentRecoveryBytes.equals(recoveryBytes)
      ||!currentPrivacyInstallationBytes.equals(privacyInstallationBytes)
      ||!currentPrivacyTranscriptBytes.equals(privacyTranscriptBytes)
      ||!currentPrivacyVerifyingKeyBytes.equals(privacyVerifyingKeyBytes)
      ||!currentPrivacyManifestBytes.equals(privacyManifestBytes)) {
    throw new Error('native release inputs changed during attestation request preparation');
  }
  process.stdout.write(`${JSON.stringify({schema:'usdom-native-release-attestation-requests/v3',
    releaseId:releaseEvidence.releaseId,sourceCommit:releaseEvidence.sourceCommit,
    finalizedAnchor:anchor,
    subjects:{...subjects,walletPublicIdentitySha256:identitySha,
      walletCustodyEvidenceSha256:custodyEvidenceSha,
      walletRecoveryEvidenceSha256:recoveryEvidenceSha},requests},null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-native-release-attestation-requests',error);
  process.exitCode=1;
} finally {
  for(const bytes of privateWalletEvidenceBytes) bytes.fill(0);
}

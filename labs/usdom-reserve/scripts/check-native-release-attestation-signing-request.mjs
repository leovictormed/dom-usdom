#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {validateNativeReleaseAttestationSigningRequest} from '../sdk/native-release-attestation.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const repository=path.resolve(root,'../..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const parse=(bytes,label)=>parseStrictJsonBytes(bytes,{
  label,maxBytes:4*1024*1024,maxDepth:64,
});
const readSnapshot=(name,label)=>readDirectFile(name,{
  minimum:1,maximum:4*1024*1024,exactMode:0o600,label,
});
function validationMap(output) {
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

try {
  if(process.argv.length!==6) throw new Error(
    'usage: check-native-release-attestation-signing-request REQUEST BUNDLE RELEASE EVIDENCE');
  const labels=['native attestation request','Safe evidence bundle',
    'release configuration snapshot','release evidence snapshot'];
  const snapshots=await Promise.all(process.argv.slice(2).map((name,index)=>
    readSnapshot(name,labels[index])));
  const [request,bundle,releaseConfig,releaseEvidence]=snapshots.map((bytes,index)=>
    parse(bytes,labels[index]));
  const manifestDocument=releaseEvidence.nativeRuntimeManifest;
  if(typeof manifestDocument?.path!=='string'||!(/^[0-9a-f]{64}$/).test(manifestDocument.sha256??'')) {
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
  const validation=validationMap(checked.stdout);
  if(validation.status!=='valid'||!(/^[0-9a-f]{64}$/).test(validation.privacy_verifier_config_hash??'')) {
    throw new Error('native runtime checker did not validate the privacy verifier');
  }
  const accountHome=os.userInfo().homedir;
  if(!path.isAbsolute(accountHome)||accountHome==='/'||os.homedir()!==accountHome
      ||process.env.HOME!==accountHome) throw new Error('account home identity is unsafe');
  const walletRoot=path.join(accountHome,'.local/share/dom-usdom/mainnet-wallet');
  const walletPaths=[path.join(walletRoot,'public-identity.json'),
    path.join(walletRoot,'tpm2-keystore-v1.json'),
    path.join(walletRoot,'recovery-drill-v1/wallet-recovery-drill.json')];
  const walletBytes=await Promise.all(walletPaths.map((name,index)=>readDirectFile(name,{
    minimum:1,maximum:4*1024*1024,privateMode:true,
    label:['wallet public identity','TPM custody evidence','wallet recovery evidence'][index],
  })));
  const [identity,tpm,recovery]=walletBytes.map((bytes,index)=>parse(bytes,
    ['wallet public identity','TPM custody evidence','wallet recovery evidence'][index]));
  const identitySha=sha(walletBytes[0]);
  if(identity.schema!=='usdom-native-receiving-wallet-public-v1'
      || tpm.schema!=='usdom-tpm2-wallet-keystore-v1'
      || recovery.schema!=='usdom-wallet-recovery-drill-v1'
      || tpm.public_identity_sha256!==identitySha||tpm.wallet_address!==identity.recipient_address
      || recovery.wallet_address!==identity.recipient_address
      || tpm.native_manifest_sha256!==manifestDocument.sha256
      || recovery.native_manifest_sha256!==manifestDocument.sha256) {
    throw new Error('wallet custody, recovery, identity and native runtime do not reconcile');
  }
  const result=validateNativeReleaseAttestationSigningRequest({request,bundle,
    bundleBytes:snapshots[1],
    bundleSha256:sha(snapshots[1]),releaseConfig,releaseEvidence,
    privacyVerifierConfigHash:validation.privacy_verifier_config_hash,
    nativeRuntimeManifestSha256:manifestDocument.sha256,walletPublicIdentitySha256:identitySha,
    walletCustodyEvidenceSha256:sha(walletBytes[1]),
    walletRecoveryEvidenceSha256:sha(walletBytes[2])});
  const [manifestAfter,...walletAfter]=await Promise.all([
    readDirectProjectFile(root,manifestDocument.path,{minimum:manifestBytes.length,
      maximum:manifestBytes.length,exactMode:0o600,label:'native runtime manifest'}),
    ...walletPaths.map((name,index)=>readDirectFile(name,{minimum:walletBytes[index].length,
      maximum:walletBytes[index].length,privateMode:true,
      label:['wallet public identity','TPM custody evidence','wallet recovery evidence'][index]})),
  ]);
  if(!manifestAfter.equals(manifestBytes)
      || walletAfter.some((bytes,index)=>!bytes.equals(walletBytes[index]))) {
    throw new Error('native attestation artifacts changed during validation');
  }
  process.stdout.write(`PASS: ${Object.keys(result.digests).length} native attestation digests independently derived\n`);
} catch(error) {
  writeReleaseFailure('check-native-release-attestation-signing-request',error);
  process.exitCode=1;
}

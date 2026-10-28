import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Wallet} from 'ethers';
import {mkdtemp,writeFile,readFile,mkdir,rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import os from 'node:os'; import path from 'node:path';
import {ceremonyContributionMessage,ceremonyDestructionMessage,ceremonyFinalizationMessage,
  ceremonyObjectHash,phase1ContributionMessage,phase1DestructionMessage,
  buildNativePrivacyInstallationReceipt,validateNativePrivacyInstallationReceipt,
  validateNativePrivacyCeremony,validateNativePrivacyCeremonyArtifacts} from '../../sdk/native-privacy-ceremony.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
async function fixture(){
  const circuitBytes=Buffer.from('frozen spend circuit'),finalProvingKeyBytes=Buffer.from('final pk'),verifyingKeyBytes=Buffer.from('canonical vk');
  const base={schema:'usdom-native-privacy-groth16-ceremony-v1',circuitSha256:sha(circuitBytes),
    r1csFingerprintSha256:'10'.repeat(32),releaseCommitment:'11'.repeat(32),
    privacyVerifierConfigHash:'22'.repeat(32),participantsRequired:3,
    initialProvingKeySha256:'12'.repeat(32),initialKeyProvenance:null,
    ceremonyVerifierBinarySha256:'14'.repeat(32)};
  const wallets=[Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom()]; let previous='0'.repeat(64);
  let phase1Previous='0'.repeat(64),phase1Accumulator='13'.repeat(32);const phase1=[];
  for(let i=0;i<3;i++){const participant=wallets[i].address;const record={ordinal:i+1,participant,
    participantCommitment:sha(Buffer.from(participant)),previousRecordHash:phase1Previous,
    previousAccumulatorSha256:phase1Accumulator,artifactSha256:String(i+7).repeat(64),accumulatorSha256:String(i+1).repeat(64),signature:'',destruction:null};
    record.destruction={participant,artifactSha256:record.artifactSha256,method:'isolated volatile entropy erased and independently witnessed',destroyedAt:`2026-10-27T11:0${i}:00.000Z`,signature:''};
    record.destruction.signature=await wallets[i].signMessage(phase1DestructionMessage(record.destruction));
    record.signature=await wallets[i].signMessage(phase1ContributionMessage(record));
    phase1.push(record);phase1Accumulator=record.accumulatorSha256;phase1Previous=ceremonyObjectHash(record);}
  base.initialKeyProvenance={kind:'powers-of-tau-bn254-multiparty-specialization-v1',initialAccumulatorSha256:'13'.repeat(32),
    finalAccumulatorSha256:phase1Accumulator,specializationSha256:base.initialProvingKeySha256,contributions:phase1};
  const contributions=[];
  for(let i=0;i<wallets.length;i++){
    const c={ordinal:i+1,participant:wallets[i].address,participantCommitment:sha(Buffer.from(wallets[i].address)),previousTranscriptHash:previous,
      previousProvingKeySha256:i===0?base.initialProvingKeySha256:contributions[i-1].contributionSha256,
      contributionSha256:String(i+3).repeat(64),phase2ArtifactSha256:String(i+6).repeat(64),circuitSha256:base.circuitSha256,r1csFingerprintSha256:base.r1csFingerprintSha256,
      releaseCommitment:base.releaseCommitment,signature:'',destruction:null};
    c.signature=await wallets[i].signMessage(ceremonyContributionMessage(c));
    c.destruction={participant:c.participant,contributionSha256:c.contributionSha256,
      method:'ephemeral isolated host securely erased and independently witnessed',destroyedAt:`2026-10-27T12:0${i}:00.000Z`,signature:''};
    c.destruction.signature=await wallets[i].signMessage(ceremonyDestructionMessage(c.destruction));
    contributions.push(c); previous=ceremonyObjectHash(c);
  }
  const transcript={...base,contributions,beacon:'ab'.repeat(64),finalProvingKeySha256:sha(finalProvingKeyBytes),
    verifyingKeySha256:sha(verifyingKeyBytes),finalTranscriptHash:'',finalizationSignatures:[]};
  transcript.finalTranscriptHash=ceremonyObjectHash({previousTranscriptHash:previous,beacon:transcript.beacon,
    finalProvingKeySha256:transcript.finalProvingKeySha256,verifyingKeySha256:transcript.verifyingKeySha256,
    circuitSha256:transcript.circuitSha256,releaseCommitment:transcript.releaseCommitment,
    privacyVerifierConfigHash:transcript.privacyVerifierConfigHash,
    r1csFingerprintSha256:transcript.r1csFingerprintSha256,
    initialProvingKeySha256:transcript.initialProvingKeySha256,
    initialKeyProvenance:transcript.initialKeyProvenance,
    ceremonyVerifierBinarySha256:transcript.ceremonyVerifierBinarySha256});
  transcript.finalizationSignatures=await Promise.all(wallets.map(async wallet=>({participant:wallet.address,
    signature:await wallet.signMessage(ceremonyFinalizationMessage(transcript))})));
  return {transcript,circuitBytes,finalProvingKeyBytes,verifyingKeyBytes};
}
test('validates chained distinct contributions, destruction attestations, beacon and unanimous finalization',async()=>{
  const f=await fixture(); assert.equal(validateNativePrivacyCeremony(f.transcript,f).participants.length,3);
});
test('installation receipt binds the exact native runtime manifest and rejects extensions',async()=>{
  const f=await fixture(),validated=validateNativePrivacyCeremony(f.transcript,f);
  const manifest=Buffer.from('{"schema":"native-runtime","generation":1}\n');
  const transcriptBytes=Buffer.from(`${JSON.stringify(f.transcript)}\n`);
  const receipt=buildNativePrivacyInstallationReceipt(validated,manifest,transcriptBytes);
  assert.equal(receipt.nativeRuntimeManifestSha256,sha(manifest));
  assert.equal(validateNativePrivacyInstallationReceipt(receipt,{nativeRuntimeManifestBytes:manifest,
    ceremonyTranscriptBytes:transcriptBytes,verifyingKeyBytes:f.verifyingKeyBytes,
    privacyVerifierConfigHash:validated.privacyVerifierConfigHash,
    verifyingKeySha256:validated.verifyingKeySha256}),receipt);
  assert.throws(()=>validateNativePrivacyInstallationReceipt(receipt,{nativeRuntimeManifestBytes:
    Buffer.from('{"schema":"native-runtime","generation":2}\n'),
    ceremonyTranscriptBytes:transcriptBytes,verifyingKeyBytes:f.verifyingKeyBytes,
    privacyVerifierConfigHash:validated.privacyVerifierConfigHash,
    verifyingKeySha256:validated.verifyingKeySha256}),/exact runtime manifest/);
  assert.throws(()=>validateNativePrivacyInstallationReceipt({...receipt,unexpected:true},{
    nativeRuntimeManifestBytes:manifest,privacyVerifierConfigHash:validated.privacyVerifierConfigHash,
    ceremonyTranscriptBytes:transcriptBytes,verifyingKeyBytes:f.verifyingKeyBytes,
    verifyingKeySha256:validated.verifyingKeySha256}),/exact runtime manifest/);
  assert.throws(()=>buildNativePrivacyInstallationReceipt({...validated,
    releaseCommitment:'f'.repeat(64)},manifest,transcriptBytes),
  /invalid privacy installation receipt inputs/);
  for(const replacement of [
    {ceremonyTranscriptBytes:Buffer.from('{}\n'),verifyingKeyBytes:f.verifyingKeyBytes},
    {ceremonyTranscriptBytes:transcriptBytes,verifyingKeyBytes:Buffer.from('foreign vk')},
  ]) assert.throws(()=>validateNativePrivacyInstallationReceipt(receipt,{
    nativeRuntimeManifestBytes:manifest,privacyVerifierConfigHash:validated.privacyVerifierConfigHash,
    verifyingKeySha256:validated.verifyingKeySha256,...replacement}),/exact runtime manifest/);
});
test('rejects chain, identity, destruction, beacon and artifact substitutions',async()=>{
  const f=await fixture();
  for(const mutate of [
    t=>t.contributions[1].previousTranscriptHash='ff'.repeat(32),
    t=>t.contributions[1].participant=t.contributions[0].participant,
    t=>t.contributions[1].destruction.method='deleted',
    t=>t.contributions[1].destruction.uncommittedClaim=true,
    t=>t.beacon='00',
    t=>t.finalizationSignatures.pop(),
    t=>t.initialKeyProvenance.contributions[1].ordinal=7,
    t=>t.initialKeyProvenance.contributions[2].participantCommitment=t.initialKeyProvenance.contributions[0].participantCommitment,
    t=>t.releaseCommitment='0'.repeat(64),
    t=>t.r1csFingerprintSha256='0'.repeat(64),
    t=>t.privacyVerifierConfigHash='0'.repeat(64),
  ]) { const copy=structuredClone(f.transcript); mutate(copy); assert.throws(()=>validateNativePrivacyCeremony(copy,f)); }
  assert.throws(()=>validateNativePrivacyCeremony(f.transcript,{...f,verifyingKeyBytes:Buffer.from('foreign')}));
});
test('production artifact acceptance requires the exact Phase1 artifacts',async()=>{
  const f=await fixture(), directory=await mkdtemp(path.join(os.tmpdir(),'usdom-mpc-gap-'));
  try {
    const binary=path.join(directory,'verifier'),bytes=Buffer.from('not executed');
    await writeFile(binary,bytes,{mode:0o700});
    f.transcript.ceremonyVerifierBinarySha256=sha(bytes);
    await assert.rejects(validateNativePrivacyCeremonyArtifacts(f.transcript,{artifactDirectory:directory,
      verifierBinary:binary,finalProvingKeyBytes:f.finalProvingKeyBytes,verifyingKeyBytes:f.verifyingKeyBytes}),
    /phase1-accumulator-000\.bin/);
  } finally { await rm(directory,{recursive:true,force:true}); }
});
test('ceremony verifier executes with a fixed environment and fd-bound artifact paths',async()=>{
  const source=await readFile(new URL('../../sdk/native-privacy-ceremony.mjs',import.meta.url),'utf8');
  assert.match(source,/const verifierEnvironment=Object\.freeze\(\{HOME:'\/nonexistent',PATH:'\/usr\/bin:\/bin',LC_ALL:'C',LANG:'C',TZ:'UTC'\}\)/);
  assert.match(source,/env:verifierEnvironment/);
  assert.match(source,/`\/proc\/self\/fd\/\$\{4\+value\.artifact\}`/);
  assert.match(source,/constants\.O_RDONLY\|constants\.O_NOFOLLOW\|constants\.O_CLOEXEC/);
  assert.doesNotMatch(source,/run\(\['(?:phase1|phase2|validate-final|extract-vk)[^\n]+(?:accumulatorPath|artifactPath|phase2Artifact|previous)/);
});
test('assembles and finalizes a create-once transcript from signed offline records',async()=>{
  const f=await fixture(),root=await mkdtemp(path.join(os.tmpdir(),'usdom-mpc-assembly-'));
  try{
    const records=path.join(root,'records'),signatures=path.join(root,'signatures');await mkdir(records,{mode:0o700});await mkdir(signatures,{mode:0o700});
    const {contributions,finalTranscriptHash,finalizationSignatures,...header}=f.transcript;
    const headerPath=path.join(root,'header.json');await writeFile(headerPath,`${JSON.stringify(header)}\n`,{mode:0o600});
    for(const record of contributions)await writeFile(path.join(records,`phase2-record-${String(record.ordinal).padStart(3,'0')}.json`),`${JSON.stringify(record)}\n`,{mode:0o600});
    for(const [index,signature] of finalizationSignatures.entries())await writeFile(path.join(signatures,`finalization-${String(index+1).padStart(3,'0')}.json`),`${JSON.stringify(signature)}\n`,{mode:0o600});
    const circuit=path.join(root,'circuit'),pk=path.join(root,'pk'),vk=path.join(root,'vk'),draft=path.join(root,'draft.json'),final=path.join(root,'final.json');
    await writeFile(circuit,f.circuitBytes,{mode:0o600});await writeFile(pk,f.finalProvingKeyBytes,{mode:0o600});await writeFile(vk,f.verifyingKeyBytes,{mode:0o600});
    const script=new URL('../../scripts/assemble-native-privacy-ceremony.mjs',import.meta.url).pathname,node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
    assert.equal(spawnSync(node,[script,'draft',headerPath,records,'3',draft]).status,0);
    assert.equal(spawnSync(node,[script,'finalize',draft,signatures,circuit,pk,vk,final]).status,0);
    assert.equal(parseInt((await readFile(final)).length)>0,true);
    assert.equal(spawnSync(node,[script,'finalize',draft,signatures,circuit,pk,vk,final]).status,0,'equal rerun must be idempotent');
  }finally{await rm(root,{recursive:true,force:true});}
});

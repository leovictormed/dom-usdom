import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {getAddress,verifyMessage} from 'ethers';
import {parseStrictJsonBytes} from './strict-json.mjs';

const H=/^[0-9a-f]{64}$/;
const nonzeroHash=value=>H.test(value)&&value!=='0'.repeat(64);
const sha=value=>createHash('sha256').update(value).digest('hex');
const canonical=value=>Array.isArray(value)?`[${value.map(canonical).join(',')}]`
  :value&&typeof value==='object'?`{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`
  :JSON.stringify(value);
export const ceremonyObjectHash=value=>sha(Buffer.from(canonical(value)));
const verifierEnvironment=Object.freeze({HOME:'/nonexistent',PATH:'/usr/bin:/bin',LC_ALL:'C',LANG:'C',TZ:'UTC'});

function sameArtifact(before,after) {
  return before.dev===after.dev&&before.ino===after.ino&&before.size===after.size
    &&before.mtimeNs===after.mtimeNs&&before.ctimeNs===after.ctimeNs;
}

async function openCeremonyArtifact(target,{minimum=1,maximum,label,expectedSha256}) {
  const absolute=path.resolve(target),directory=path.dirname(absolute),basename=path.basename(absolute);
  let directoryHandle,handle;
  try {
    directoryHandle=await open(directory,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
    const directoryStat=await directoryHandle.stat({bigint:true});
    const uid=typeof process.getuid==='function'?BigInt(process.getuid()):directoryStat.uid;
    if(!directoryStat.isDirectory()||directoryStat.uid!==uid||(directoryStat.mode&0o777n)!==0o700n
        ||await realpath(`/proc/self/fd/${directoryHandle.fd}`)!==directory) throw new Error(`${label} parent is unsafe`);
    handle=await open(`/proc/self/fd/${directoryHandle.fd}/${basename}`,
      constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_CLOEXEC);
    const before=await handle.stat({bigint:true});
    if(!before.isFile()||before.nlink!==1n||before.uid!==uid||(before.mode&0o777n)!==0o600n
        ||before.size<BigInt(minimum)||before.size>BigInt(maximum)
        ||await realpath(`/proc/self/fd/${handle.fd}`)!==absolute) throw new Error(`${label} is unsafe`);
    const bytes=await handle.readFile();
    const after=await handle.stat({bigint:true});
    if(!sameArtifact(before,after)||bytes.length!==Number(before.size)||sha(bytes)!==expectedSha256)
      throw new Error(`${label} hash or identity mismatch`);
    return handle;
  } catch(error) {
    await handle?.close();
    throw error;
  } finally { await directoryHandle?.close(); }
}
export const phase1ContributionMessage=value=>`USD0M native privacy Phase1 contribution v1\n${canonical(Object.fromEntries(Object.entries(value).filter(([key])=>key!=='signature')))}`;
export const phase1DestructionMessage=value=>`USD0M native privacy Phase1 erasure v1\n${canonical(Object.fromEntries(Object.entries(value).filter(([key])=>key!=='signature')))}`;
export const ceremonyContributionMessage=value=>`USD0M native privacy contribution v1\n${value.previousTranscriptHash}\n${value.previousProvingKeySha256}\n${value.contributionSha256}\n${value.circuitSha256}\n${value.r1csFingerprintSha256}\n${value.releaseCommitment}`;
export const ceremonyDestructionMessage=value=>`USD0M toxic-waste destruction v1\n${value.contributionSha256}\n${value.method}\n${value.destroyedAt}`;
export const ceremonyFinalizationMessage=value=>`USD0M native privacy ceremony finalization v1\n${value.finalTranscriptHash}\n${value.beacon}\n${value.finalProvingKeySha256}\n${value.verifyingKeySha256}\n${value.r1csFingerprintSha256}`;

const installationReceiptKeys=['schema','finalTranscriptHash','participants','circuitSha256',
  'releaseCommitment','privacyVerifierConfigHash','verifyingKeySha256','nativeRuntimeManifestSha256',
  'ceremonyTranscriptSha256'];
export function buildNativePrivacyInstallationReceipt(validated,nativeRuntimeManifestBytes,
  ceremonyTranscriptBytes) {
  const transcript=parseStrictJsonBytes(ceremonyTranscriptBytes,{label:'native privacy ceremony transcript',
    maxBytes:8*1024*1024,maxDepth:64});
  const transcriptParticipants=transcript?.contributions?.map(value=>getAddress(value.participant));
  if(!validated||!Buffer.isBuffer(nativeRuntimeManifestBytes)||nativeRuntimeManifestBytes.length<1
      ||!Buffer.isBuffer(ceremonyTranscriptBytes)||ceremonyTranscriptBytes.length<1
      ||!nonzeroHash(validated.finalTranscriptHash)||!Array.isArray(validated.participants)
      ||validated.participants.length<3||!nonzeroHash(validated.circuitSha256)
      ||!nonzeroHash(validated.releaseCommitment)||!nonzeroHash(validated.privacyVerifierConfigHash)
      ||!nonzeroHash(validated.verifyingKeySha256)
      ||transcript?.finalTranscriptHash!==validated.finalTranscriptHash
      ||transcript?.circuitSha256!==validated.circuitSha256
      ||transcript?.releaseCommitment!==validated.releaseCommitment
      ||transcript?.privacyVerifierConfigHash!==validated.privacyVerifierConfigHash
      ||transcript?.verifyingKeySha256!==validated.verifyingKeySha256
      ||JSON.stringify(transcriptParticipants)!==JSON.stringify(validated.participants)) {
    throw new Error('invalid privacy installation receipt inputs');
  }
  return Object.freeze({schema:'usdom-native-privacy-vk-installation-v2',...validated,
    nativeRuntimeManifestSha256:sha(nativeRuntimeManifestBytes),
    ceremonyTranscriptSha256:sha(ceremonyTranscriptBytes)});
}
export function validateNativePrivacyInstallationReceipt(receipt,{nativeRuntimeManifestBytes,
  ceremonyTranscriptBytes,verifyingKeyBytes,privacyVerifierConfigHash,verifyingKeySha256}) {
  if(!receipt||JSON.stringify(Object.keys(receipt).sort())!==JSON.stringify([...installationReceiptKeys].sort())
      ||receipt.schema!=='usdom-native-privacy-vk-installation-v2'
      ||!Buffer.isBuffer(nativeRuntimeManifestBytes)||receipt.nativeRuntimeManifestSha256!==sha(nativeRuntimeManifestBytes)
      ||!Buffer.isBuffer(ceremonyTranscriptBytes)||receipt.ceremonyTranscriptSha256!==sha(ceremonyTranscriptBytes)
      ||!Buffer.isBuffer(verifyingKeyBytes)||receipt.verifyingKeySha256!==sha(verifyingKeyBytes)
      ||receipt.privacyVerifierConfigHash!==privacyVerifierConfigHash
      ||receipt.verifyingKeySha256!==verifyingKeySha256
      ||!nonzeroHash(receipt.finalTranscriptHash)||!nonzeroHash(receipt.circuitSha256)
      ||!nonzeroHash(receipt.releaseCommitment)||!Array.isArray(receipt.participants)
      ||receipt.participants.length<3||new Set(receipt.participants.map(getAddress)).size!==receipt.participants.length)
    throw new Error('native privacy installation receipt does not bind the exact runtime manifest');
  return receipt;
}

export function validateNativePrivacyCeremony(transcript,{circuitBytes,finalProvingKeyBytes,verifyingKeyBytes}) {
  const keys=['schema','circuitSha256','r1csFingerprintSha256','releaseCommitment','privacyVerifierConfigHash','participantsRequired',
    'initialProvingKeySha256','initialKeyProvenance','ceremonyVerifierBinarySha256',
    'contributions','beacon','finalProvingKeySha256','verifyingKeySha256','finalTranscriptHash','finalizationSignatures'];
  if(!transcript||JSON.stringify(Object.keys(transcript).sort())!==JSON.stringify(keys.sort())
      ||transcript.schema!=='usdom-native-privacy-groth16-ceremony-v1'
      ||!H.test(transcript.circuitSha256)||sha(circuitBytes)!==transcript.circuitSha256
      ||!nonzeroHash(transcript.r1csFingerprintSha256)||!nonzeroHash(transcript.initialProvingKeySha256)
      ||!H.test(transcript.ceremonyVerifierBinarySha256)
      ||!transcript.initialKeyProvenance||transcript.initialKeyProvenance.kind!=='powers-of-tau-bn254-multiparty-specialization-v1'
      ||!nonzeroHash(transcript.releaseCommitment)||!nonzeroHash(transcript.privacyVerifierConfigHash)
      ||!Number.isSafeInteger(transcript.participantsRequired)||transcript.participantsRequired<3
      ||!Array.isArray(transcript.contributions)||transcript.contributions.length<transcript.participantsRequired
      ||!Array.isArray(transcript.finalizationSignatures)||!H.test(transcript.finalProvingKeySha256)
      ||!H.test(transcript.verifyingKeySha256)||sha(finalProvingKeyBytes)!==transcript.finalProvingKeySha256
      ||sha(verifyingKeyBytes)!==transcript.verifyingKeySha256
      ||typeof transcript.beacon!=='string'||!/^[0-9a-f]{128,}$/.test(transcript.beacon)) throw new Error('invalid ceremony header or artifacts');
  const provenance=transcript.initialKeyProvenance;
  if(JSON.stringify(Object.keys(provenance).sort())!==JSON.stringify(['contributions','finalAccumulatorSha256','initialAccumulatorSha256','kind','specializationSha256'])
      ||![provenance.initialAccumulatorSha256,provenance.finalAccumulatorSha256,provenance.specializationSha256].every(v=>H.test(v))
      ||provenance.specializationSha256!==transcript.initialProvingKeySha256
      ||!Array.isArray(provenance.contributions)||provenance.contributions.length<transcript.participantsRequired)
    throw new Error('invalid Phase-1 provenance');
  let phase1Previous='0'.repeat(64),phase1Accumulator=provenance.initialAccumulatorSha256;
  const phase1Identities=[];
  for(const [index,record] of provenance.contributions.entries()) {
    const expected=['ordinal','participant','participantCommitment','previousRecordHash','previousAccumulatorSha256','artifactSha256','accumulatorSha256','signature','destruction'];
    if(JSON.stringify(Object.keys(record).sort())!==JSON.stringify(expected.sort())||record.ordinal!==index+1
        ||record.previousRecordHash!==phase1Previous||record.previousAccumulatorSha256!==phase1Accumulator
        ||![record.participantCommitment,record.artifactSha256,record.accumulatorSha256].every(v=>H.test(v))
        ||phase1Identities.includes(record.participantCommitment)) throw new Error('broken Phase-1 contribution chain');
    const phase1Participant=getAddress(record.participant);
    if(sha(Buffer.from(phase1Participant))!==record.participantCommitment
        ||getAddress(verifyMessage(phase1ContributionMessage(record),record.signature))!==phase1Participant)
      throw new Error('invalid Phase-1 participant identity signature');
    const destruction=record.destruction;
    if(!destruction||JSON.stringify(Object.keys(destruction).sort())!==JSON.stringify(['artifactSha256','destroyedAt','method','participant','signature'])
        ||getAddress(destruction.participant)!==phase1Participant||destruction.artifactSha256!==record.artifactSha256
        ||typeof destruction.method!=='string'||destruction.method.length<16||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$/.test(destruction.destroyedAt)
        ||getAddress(verifyMessage(phase1DestructionMessage(destruction),destruction.signature))!==phase1Participant)
      throw new Error('invalid Phase-1 toxic-waste erasure attestation');
    phase1Identities.push(record.participantCommitment); phase1Accumulator=record.accumulatorSha256;
    phase1Previous=ceremonyObjectHash(record);
  }
  if(phase1Accumulator!==provenance.finalAccumulatorSha256) throw new Error('Phase-1 final accumulator mismatch');
  let previous='0'.repeat(64); const participants=[];
  for(const [ordinal,c] of transcript.contributions.entries()) {
    const ck=['ordinal','participant','participantCommitment','previousTranscriptHash','previousProvingKeySha256','contributionSha256','phase2ArtifactSha256','circuitSha256','r1csFingerprintSha256',
      'releaseCommitment','signature','destruction'];
    if(JSON.stringify(Object.keys(c).sort())!==JSON.stringify(ck.sort())||c.ordinal!==ordinal+1
        ||c.previousTranscriptHash!==previous||![c.contributionSha256,c.phase2ArtifactSha256,c.participantCommitment,c.previousProvingKeySha256].every(v=>H.test(v))
        ||c.circuitSha256!==transcript.circuitSha256||c.releaseCommitment!==transcript.releaseCommitment) throw new Error('broken contribution chain');
    if(c.r1csFingerprintSha256!==transcript.r1csFingerprintSha256
        ||c.previousProvingKeySha256!==(ordinal===0?transcript.initialProvingKeySha256:transcript.contributions[ordinal-1].contributionSha256)) throw new Error('contribution proving-key chain mismatch');
    const participant=getAddress(c.participant);
    if(sha(Buffer.from(participant))!==c.participantCommitment) throw new Error('Phase-2 participant commitment mismatch');
    if(getAddress(verifyMessage(ceremonyContributionMessage(c),c.signature))!==participant) throw new Error('invalid contribution signature');
    const d=c.destruction;
    if(!d||JSON.stringify(Object.keys(d).sort())!==JSON.stringify(
      ['participant','contributionSha256','method','destroyedAt','signature'].sort())
        ||d.participant!==c.participant||d.contributionSha256!==c.contributionSha256
        ||typeof d.method!=='string'||d.method.length<16||!/^\d{4}-\d{2}-\d{2}T.*Z$/.test(d.destroyedAt)
        ||getAddress(verifyMessage(ceremonyDestructionMessage(d),d.signature))!==participant) throw new Error('invalid toxic-waste destruction attestation');
    if(participants.includes(participant)) throw new Error('participant identity reused');
    participants.push(participant); previous=ceremonyObjectHash(c);
  }
  const finalMaterial={previousTranscriptHash:previous,beacon:transcript.beacon,
    finalProvingKeySha256:transcript.finalProvingKeySha256,verifyingKeySha256:transcript.verifyingKeySha256,
    circuitSha256:transcript.circuitSha256,releaseCommitment:transcript.releaseCommitment,
    privacyVerifierConfigHash:transcript.privacyVerifierConfigHash,
    r1csFingerprintSha256:transcript.r1csFingerprintSha256,
    initialProvingKeySha256:transcript.initialProvingKeySha256,
    initialKeyProvenance:transcript.initialKeyProvenance,
    ceremonyVerifierBinarySha256:transcript.ceremonyVerifierBinarySha256};
  const expectedFinal=ceremonyObjectHash(finalMaterial);
  if(transcript.finalTranscriptHash!==expectedFinal) throw new Error('final transcript hash mismatch');
  const signers=transcript.finalizationSignatures.map(s=>{
    if(!s||JSON.stringify(Object.keys(s).sort())!==JSON.stringify(['participant','signature'])) throw new Error('invalid finalization signature record');
    const participant=getAddress(s.participant);
    if(getAddress(verifyMessage(ceremonyFinalizationMessage(transcript),s.signature))!==participant) throw new Error('invalid finalization signature');
    return participant;
  });
  if(signers.length!==participants.length||new Set(signers).size!==participants.length
      ||participants.some(p=>!signers.includes(p))) throw new Error('all distinct participants must sign finalization');
  return Object.freeze({finalTranscriptHash:expectedFinal,participants:Object.freeze(participants),
    circuitSha256:transcript.circuitSha256,releaseCommitment:transcript.releaseCommitment,
    privacyVerifierConfigHash:transcript.privacyVerifierConfigHash,verifyingKeySha256:transcript.verifyingKeySha256});
}

export async function validateNativePrivacyCeremonyArtifacts(transcript,{artifactDirectory,verifierBinary,
  finalProvingKeyBytes,verifyingKeyBytes}) {
  const verifierHandle=await open(verifierBinary,constants.O_RDONLY|constants.O_NOFOLLOW);
  try {
  const verifierStat=await verifierHandle.stat();
  if(!verifierStat.isFile()||verifierStat.nlink!==1||verifierStat.size<1||verifierStat.size>64*1024*1024
      ||(verifierStat.mode&0o022)!==0) throw new Error('ceremony verifier binary metadata is unsafe');
  const binary=await verifierHandle.readFile();
  if(sha(binary)!==transcript.ceremonyVerifierBinarySha256) throw new Error('ceremony verifier binary pin mismatch');
  const run=(args,options={})=>spawnSync('/proc/self/fd/3',args,{...options,env:verifierEnvironment,
    stdio:['ignore',options.encoding!==undefined?'pipe':'ignore','pipe',verifierHandle.fd]});
  const runArtifacts=async(args,artifacts,options={})=>{
    const handles=[];
    try {
      for(const artifact of artifacts) handles.push(await openCeremonyArtifact(artifact.path,artifact));
      const descriptorArgs=args.map(value=>typeof value==='object'&&value!==null&&Number.isSafeInteger(value.artifact)
        ?`/proc/self/fd/${4+value.artifact}`:value);
      return spawnSync('/proc/self/fd/3',descriptorArgs,{...options,env:verifierEnvironment,
        stdio:['ignore',options.encoding!==undefined?'pipe':'ignore','pipe',verifierHandle.fd,...handles.map(h=>h.fd)]});
    } finally { for(const handle of handles) await handle.close(); }
  };
  const provenance=transcript.initialKeyProvenance;
  let phase1Previous='0'.repeat(64);
  let accumulatorPath=path.join(artifactDirectory,'phase1-accumulator-000.bin');
  if((await runArtifacts(['phase1-verify-initial',{artifact:0}],[{path:accumulatorPath,minimum:1,maximum:512*1024*1024,
    label:'Phase-1 initial accumulator',expectedSha256:provenance.initialAccumulatorSha256}],{timeout:60*60*1000})).status!==0)
    throw new Error('Phase-1 initial accumulator is not the public generator state');
  for(const record of provenance.contributions) {
    const ordinal=String(record.ordinal).padStart(3,'0');
    const artifactPath=path.join(artifactDirectory,`phase1-contribution-${ordinal}.bin`);
    const nextAccumulator=path.join(artifactDirectory,`phase1-accumulator-${ordinal}.bin`);
    await openCeremonyArtifact(nextAccumulator,{minimum:1,maximum:512*1024*1024,label:`Phase-1 accumulator ${ordinal}`,
      expectedSha256:record.accumulatorSha256}).then(handle=>handle.close());
    const verified=await runArtifacts(['phase1-verify',{artifact:0},{artifact:1},transcript.releaseCommitment,transcript.r1csFingerprintSha256,
      record.participantCommitment,String(record.ordinal),phase1Previous],[
      {path:accumulatorPath,minimum:1,maximum:512*1024*1024,label:`Phase-1 prior accumulator ${ordinal}`,expectedSha256:record.previousAccumulatorSha256},
      {path:artifactPath,minimum:1,maximum:512*1024*1024,label:`Phase-1 contribution ${ordinal}`,expectedSha256:record.artifactSha256}],{timeout:60*60*1000});
    if(verified.status!==0) throw new Error(`Phase-1 algebraic/PoK verification failed at ${record.ordinal}`);
    const extracted=await runArtifacts(['phase1-extract',{artifact:0}],[{path:artifactPath,minimum:1,maximum:512*1024*1024,
      label:`Phase-1 contribution ${ordinal}`,expectedSha256:record.artifactSha256}],{encoding:null,maxBuffer:512*1024*1024,timeout:60*60*1000});
    if(extracted.status!==0||sha(Buffer.from(extracted.stdout))!==record.accumulatorSha256) throw new Error(`Phase-1 accumulator extraction failed at ${record.ordinal}`);
    accumulatorPath=nextAccumulator;phase1Previous=ceremonyObjectHash(record);
  }
  const specialized=await runArtifacts(['phase1-specialize',{artifact:0}],[{path:accumulatorPath,minimum:1,maximum:512*1024*1024,
    label:'Phase-1 final accumulator',expectedSha256:provenance.finalAccumulatorSha256}],{encoding:null,maxBuffer:64*1024*1024,timeout:60*60*1000});
  if(specialized.status!==0||sha(Buffer.from(specialized.stdout))!==transcript.initialProvingKeySha256) throw new Error('Phase-1 exact specialization mismatch');
  let previous=path.join(artifactDirectory,'pk-000.bin');
  await openCeremonyArtifact(previous,{minimum:1,maximum:64*1024*1024,label:'ceremony PK0',
    expectedSha256:transcript.initialProvingKeySha256}).then(handle=>handle.close());
  for(const contribution of transcript.contributions) {
    const next=path.join(artifactDirectory,`pk-${String(contribution.ordinal).padStart(3,'0')}.bin`);
    const phase2Artifact=path.join(artifactDirectory,`phase2-contribution-${String(contribution.ordinal).padStart(3,'0')}.bin`);
    await openCeremonyArtifact(next,{minimum:1,maximum:64*1024*1024,label:`ceremony PK ${contribution.ordinal}`,
      expectedSha256:contribution.contributionSha256}).then(handle=>handle.close());
    const result=await runArtifacts(['phase2-verify',{artifact:0},{artifact:1},transcript.releaseCommitment,transcript.r1csFingerprintSha256,
      contribution.participantCommitment,String(contribution.ordinal),contribution.previousTranscriptHash],[
      {path:previous,minimum:1,maximum:64*1024*1024,label:`ceremony prior PK ${contribution.ordinal}`,expectedSha256:contribution.previousProvingKeySha256},
      {path:phase2Artifact,minimum:1,maximum:64*1024*1024+4096,label:`Phase-2 artifact ${contribution.ordinal}`,expectedSha256:contribution.phase2ArtifactSha256}],{timeout:15*60*1000});
    if(result.status!==0) throw new Error(`algebraic contribution verification failed at ${contribution.ordinal}`);
    const extractedPhase2=await runArtifacts(['phase2-extract',{artifact:0}],[{path:phase2Artifact,minimum:1,maximum:64*1024*1024+4096,
      label:`Phase-2 artifact ${contribution.ordinal}`,expectedSha256:contribution.phase2ArtifactSha256}],{encoding:null,maxBuffer:64*1024*1024,timeout:15*60*1000});
    if(extractedPhase2.status!==0||sha(Buffer.from(extractedPhase2.stdout))!==contribution.contributionSha256) throw new Error(`Phase-2 extraction failed at ${contribution.ordinal}`);
    previous=next;
  }
  if(sha(finalProvingKeyBytes)!==transcript.finalProvingKeySha256) throw new Error('final proving key differs from contribution chain');
  const finalCheck=await runArtifacts(['validate-final',{artifact:0}],[{path:previous,minimum:1,maximum:64*1024*1024,
    label:'final ceremony PK',expectedSha256:transcript.finalProvingKeySha256}],{encoding:'utf8',maxBuffer:4096,timeout:60*60*1000});
  if(finalCheck.status!==0
      ||!finalCheck.stdout.includes(`r1cs_sha256=${transcript.r1csFingerprintSha256} `)
      ||!finalCheck.stdout.includes(`verifier_config_hash=${transcript.privacyVerifierConfigHash}`))
    throw new Error('final proving key failed frozen-circuit/config validation');
  const extracted=await runArtifacts(['extract-vk',{artifact:0}],[{path:previous,minimum:1,maximum:64*1024*1024,
    label:'final ceremony PK',expectedSha256:transcript.finalProvingKeySha256}],{encoding:null,maxBuffer:16*1024*1024});
  if(extracted.status!==0||!Buffer.from(extracted.stdout).equals(verifyingKeyBytes)) throw new Error('VK is not derived from final PK');
  const fingerprint=run(['fingerprint'],{encoding:'utf8',maxBuffer:4096});
  if(fingerprint.status!==0||!fingerprint.stdout.includes(`sha256=${transcript.r1csFingerprintSha256} `)) throw new Error('R1CS fingerprint mismatch');
  return true;
  } finally { await verifierHandle.close(); }
}

import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {PINNED_SNARKJS_PACKAGE_INTEGRITY,PINNED_SNARKJS_VERSION,
  PINNED_SNARKJS_KNOWN_ADVISORIES,
  RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS,
  RISC0_TRUSTED_SETUP_PODMAN_PATHS,
  buildRisc0TrustedSetupPodmanPlan,
  validateRisc0TrustedSetupPodmanImageInspection,
  validateRisc0TrustedSetupToolchainAttestation,
  buildRisc0TrustedSetupVerificationReport,parseSnarkjsVerificationLogs,
  serializeRisc0TrustedSetupVerificationReport,validateRisc0TrustedSetupVerificationReport,
} from '../../sdk/risc0-trusted-setup-verification-report.mjs';

const authorityBytes=await readFile(new URL('../../config/risc0-trusted-setup-authority-v1.json',import.meta.url));
const authority=JSON.parse(authorityBytes),authoritySha256=createHash('sha256').update(authorityBytes).digest('hex');
const groups=Array.from({length:16},(_,index)=>(index+1).toString(16).padStart(8,'0')).join(' ');
const powersOfTauUtf8='[INFO]  snarkJS: Powers Of tau file OK!\n';
const zkeyUtf8=`[INFO]  snarkJS: Contribution Hash:\n ${groups}\n[INFO]  snarkJS: ZKey Ok!\n`;
const toolchainUtf8=`${JSON.stringify({nodeVersion:'v24.19.0',snarkjsVersion:PINNED_SNARKJS_VERSION,
  snarkjsPackageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY})}\n`;
const environment=()=>({schema:'usdom-risc0-trusted-setup-verification-environment/v7',
  containerImageDigest:`sha256:${'77'.repeat(32)}`,networkDisabled:true,nodeVersion:'v24.19.0',
  containerImageReference:`sha256:${'77'.repeat(32)}`,
  containerRuntime:{path:'/usr/bin/podman',sha256:'88'.repeat(32)},
  inputArtifacts:{r1csSha256:authority.r1cs_sha256,
    powersOfTauBlake2b512:authority.powers_of_tau_blake2b512,zkeySha256:'11'.repeat(32),
    expectedVerificationKeySha256:'66'.repeat(32)},
  snarkjsVersion:PINNED_SNARKJS_VERSION,snarkjsPackageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,
  knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],capabilitiesDropped:['ALL'],
  commands:structuredClone(RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS),inputMountReadOnly:true,
  noNewPrivileges:true,outputTmpfs:true,rootFilesystemReadOnly:true,runAsUser:'65532:65532'});
const stable=value=>Array.isArray(value)?value.map(stable):value&&typeof value==='object'
  ?Object.fromEntries(Object.keys(value).sort().map(key=>[key,stable(value[key])])):value;
const report=()=>{const descriptor=environment(),plan=buildRisc0TrustedSetupPodmanPlan(descriptor);
  const imageInspectionUtf8=`${JSON.stringify(plan.image)}\n`;
  return {schema:'usdom-risc0-groth16-trusted-setup-verification/v6',status:'verified',
  authoritySha256,artifacts:{r1cs:{sha256:authority.r1cs_sha256,size:authority.r1cs_size},
    powersOfTau:{blake2b512:authority.powers_of_tau_blake2b512,power:23,size:authority.powers_of_tau_size},
    zkey:{sha256:'11'.repeat(32),size:authority.zkey_size,verificationKeySha256:'66'.repeat(32)}},
  snarkjs:{version:PINNED_SNARKJS_VERSION,packageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY,
    isolated:true,networkDisabled:true,knownAdvisories:[...PINNED_SNARKJS_KNOWN_ADVISORIES],
    powersOfTauVerified:true,zkeyVerified:true},contributionDigests:[groups.replaceAll(' ','')],
  verificationLogs:{powersOfTauSha256:createHash('sha256').update(powersOfTauUtf8).digest('hex'),
    powersOfTauUtf8,zkeySha256:createHash('sha256').update(zkeyUtf8).digest('hex'),zkeyUtf8},
  containerExecution:{imageInspectionSha256:createHash('sha256').update(imageInspectionUtf8).digest('hex'),
    imageInspectionUtf8,planSha256:createHash('sha256').update(`${JSON.stringify(stable(plan),null,2)}\n`).digest('hex'),
    imageIdentifier:plan.image,toolchainAttestationSha256:createHash('sha256').update(toolchainUtf8).digest('hex'),
    toolchainAttestationUtf8:toolchainUtf8},verificationEnvironment:{document:descriptor,sha256:createHash('sha256')
    .update(`${JSON.stringify(stable(descriptor),null,2)}\n`).digest('hex')}};};

test('accepts exact source-pinned transcript verification evidence',()=>{
  const value=report();
  assert.deepEqual(validateRisc0TrustedSetupVerificationReport(value,{authority,authoritySha256}),value);
  assert.deepEqual(JSON.parse(serializeRisc0TrustedSetupVerificationReport(value)),value);
});

test('rejects replacement authority even when report and caller agree on its digest',()=>{
  const replacement='ab'.repeat(32),value=report();
  value.authoritySha256=replacement;
  assert.throws(()=>validateRisc0TrustedSetupVerificationReport(value,
    {authority,authoritySha256:replacement}),/authority digest mismatch/);
});

test('rejects false verification, artifact drift, duplicate contributors and extensions',()=>{
  for(const mutate of [
    value=>{value.snarkjs.zkeyVerified=false;},value=>{value.artifacts.r1cs.size++;},
    value=>{value.artifacts.zkey.sha256='0'.repeat(64);},
    value=>{value.contributionDigests.push(value.contributionDigests[0]);},value=>{value.extra=true;},
  ]) {const value=report();mutate(value);assert.throws(()=>validateRisc0TrustedSetupVerificationReport(value,{authority,authoritySha256}));}
});

test('builds the report from exact snarkjs success logs and contribution blocks',()=>{
  const powersOfTauLog=Buffer.from('[INFO]  snarkJS: Powers Of tau file OK!\n');
  const zkeyLog=Buffer.from(`[INFO]  snarkJS: Contribution Hash:\n ${groups}\n[INFO]  snarkJS: ZKey Ok!\n`);
  const parsed=parseSnarkjsVerificationLogs({powersOfTauLog,zkeyLog});
  assert.equal(parsed.contributionDigests[0],groups.replaceAll(' ',''));
  const built=buildRisc0TrustedSetupVerificationReport({authority,authoritySha256,
    r1cs:{sha256:authority.r1cs_sha256,size:authority.r1cs_size},
    powersOfTau:{blake2b512:authority.powers_of_tau_blake2b512,size:authority.powers_of_tau_size},
    zkey:{sha256:'11'.repeat(32),size:authority.zkey_size},verificationKeySha256:'66'.repeat(32),
    powersOfTauLog,zkeyLog,verificationEnvironment:environment(),
    podmanImageInspection:Buffer.from(`${JSON.stringify(environment().containerImageReference)}\n`),
    toolchainAttestation:Buffer.from(toolchainUtf8)});
  assert.equal(built.snarkjs.isolated,true);
  assert.deepEqual(built.snarkjs.knownAdvisories,PINNED_SNARKJS_KNOWN_ADVISORIES);
});

test('refuses to combine measured artifacts with different environment commitments',()=>{
  const powersOfTauLog=Buffer.from(powersOfTauUtf8),zkeyLog=Buffer.from(zkeyUtf8);
  for(const mutate of [value=>{value.inputArtifacts.zkeySha256='99'.repeat(32);},
    value=>{value.inputArtifacts.expectedVerificationKeySha256='aa'.repeat(32);},
    value=>{value.inputArtifacts.r1csSha256='bb'.repeat(32);},
  ]) {
    const descriptor=environment();mutate(descriptor);
    assert.throws(()=>buildRisc0TrustedSetupVerificationReport({authority,authoritySha256,
      r1cs:{sha256:authority.r1cs_sha256,size:authority.r1cs_size},
      powersOfTau:{blake2b512:authority.powers_of_tau_blake2b512,size:authority.powers_of_tau_size},
      zkey:{sha256:'11'.repeat(32),size:authority.zkey_size},verificationKeySha256:'66'.repeat(32),
      powersOfTauLog,zkeyLog,verificationEnvironment:descriptor,
      podmanImageInspection:Buffer.from(`${JSON.stringify(descriptor.containerImageReference)}\n`),
      toolchainAttestation:Buffer.from(toolchainUtf8)}));
  }
});

test('rejects self-contained logs that differ from hashes or contribution evidence',()=>{
  for(const mutate of [
    value=>{value.verificationLogs.zkeyUtf8=value.verificationLogs.zkeyUtf8.replace('ZKey Ok!','ZKey FAILED');},
    value=>{value.verificationLogs.zkeySha256='44'.repeat(32);},
    value=>{value.contributionDigests[0]='22'.repeat(64);},
  ]) {const value=report();mutate(value);assert.throws(()=>validateRisc0TrustedSetupVerificationReport(value,{authority,authoritySha256}));}
});

test('rejects verification environment substitution and unbound declarations',()=>{
  for(const mutate of [
    value=>{value.verificationEnvironment.document.networkDisabled=false;},
    value=>{value.verificationEnvironment.document.containerImageDigest=`sha256:${'88'.repeat(32)}`;},
    value=>{value.verificationEnvironment.document.containerImageReference='localhost/usdom-snarkjs:latest';},
    value=>{value.verificationEnvironment.document.containerImageReference=`localhost/other@sha256:${'88'.repeat(32)}`;},
    value=>{value.verificationEnvironment.document.commands.verifyZkey[2]='zkey-new';},
    value=>{value.verificationEnvironment.document.capabilitiesDropped=[];},
    value=>{value.verificationEnvironment.document.containerImageDigest=`sha256:${'0'.repeat(64)}`;},
    value=>{value.verificationEnvironment.document.nodeVersion='v24.18.9';},
    value=>{value.verificationEnvironment.document.nodeVersion='v25.0.0';},
    value=>{value.verificationEnvironment.document.nodeVersion='v24.019.0';},
    value=>{value.verificationEnvironment.document.nodeVersion='v24.1000.0';},
    value=>{value.verificationEnvironment.document.inputArtifacts.zkeySha256='99'.repeat(32);},
    value=>{value.verificationEnvironment.document.inputArtifacts.powersOfTauBlake2b512='0'.repeat(128);},
    value=>{value.verificationEnvironment.document.containerRuntime.path='/usr/local/bin/podman';},
    value=>{value.verificationEnvironment.document.containerRuntime.sha256='0'.repeat(64);},
    value=>{value.verificationEnvironment.sha256='55'.repeat(32);},
  ]) {const value=report();mutate(value);assert.throws(()=>validateRisc0TrustedSetupVerificationReport(value,{authority,authoritySha256}));}
});

test('rejects a self-consistent execution plan for artifacts different from the report',()=>{
  for(const field of ['zkeySha256','expectedVerificationKeySha256','r1csSha256']) {
    const value=report();
    value.verificationEnvironment.document.inputArtifacts[field]='99'.repeat(32);
    value.verificationEnvironment.sha256=createHash('sha256')
      .update(`${JSON.stringify(stable(value.verificationEnvironment.document),null,2)}\n`).digest('hex');
    const plan=buildRisc0TrustedSetupPodmanPlan(value.verificationEnvironment.document);
    value.containerExecution.planSha256=createHash('sha256')
      .update(`${JSON.stringify(stable(plan),null,2)}\n`).digest('hex');
    assert.throws(()=>validateRisc0TrustedSetupVerificationReport(value,{authority,authoritySha256}),
      /not bound to the reported artifacts/);
  }
});

test('rejects container plan and immutable image-ID divergence in the transcript',()=>{
  for(const mutate of [
    value=>{value.containerExecution.planSha256='55'.repeat(32);},
    value=>{value.containerExecution.imageInspectionSha256='66'.repeat(32);},
    value=>{value.containerExecution.imageInspectionUtf8='[]\n';},
    value=>{value.containerExecution.imageIdentifier=`sha256:${'99'.repeat(32)}`;},
    value=>{value.containerExecution.toolchainAttestationUtf8=value.containerExecution.toolchainAttestationUtf8.replace('0.7.6','0.7.5');},
  ]) {const value=report();mutate(value);assert.throws(()=>validateRisc0TrustedSetupVerificationReport(value,{authority,authoritySha256}));}
});

test('generates an exact shell-free Podman plan for the isolated verification',()=>{
  const plan=buildRisc0TrustedSetupPodmanPlan(environment());
  assert.equal(plan.schema,'usdom-risc0-trusted-setup-podman-plan/v1');
  assert.deepEqual(plan.runtime,environment().containerRuntime);
  assert.equal(plan.image,environment().containerImageReference);
  assert.equal(plan.expectedImageDigest,environment().containerImageDigest);
  assert.deepEqual(plan.expectedArtifacts,environment().inputArtifacts);
  assert.deepEqual(plan.imageInspection.argv,['/usr/bin/podman','image','inspect',
    '--format={{json .Id}}',environment().containerImageReference]);
  assert.equal(plan.outputFilesystem,'tmpfs');
  assert.equal(plan.invocations.find(value=>value.id==='verify-powers-of-tau').stdoutPath,
    RISC0_TRUSTED_SETUP_PODMAN_PATHS.powersOfTauLog);
  assert.equal(plan.invocations.find(value=>value.id==='verify-zkey').stdoutPath,
    RISC0_TRUSTED_SETUP_PODMAN_PATHS.zkeyLog);
  assert.equal(plan.invocations.length,4);
  for(const invocation of plan.invocations) {
    assert.equal(invocation.argv[0],'/usr/bin/podman');
    for(const required of ['--pull=never','--network=none','--read-only','--user=65532:65532',
      '--userns=keep-id:uid=65532,gid=65532','--cap-drop=ALL',
      '--security-opt=no-new-privileges','--entrypoint=node']) {
      assert.ok(invocation.argv.includes(required));
    }
    assert.equal(invocation.argv.includes('sh'),false);
    assert.equal(invocation.argv.includes('bash'),false);
    if(invocation.id!=='attest-toolchain') assert.equal(invocation.argv.at(-1).includes(';'),false);
    assert.equal(invocation.stderr,'merge-into-stdout');
  }
  for(const [id,command] of [['attest-toolchain','attestToolchain'],['verify-powers-of-tau','verifyPowersOfTau'],
    ['verify-zkey','verifyZkey'],['export-verification-key','exportVerificationKey']]) {
    const invocation=plan.invocations.find(value=>value.id===id);
    assert.deepEqual(invocation.argv.slice(-RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS[command].length+1),
      RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS[command].slice(1));
  }
});

test('requires the image to attest exact Node and snarkjs package bytes',()=>{
  assert.deepEqual(validateRisc0TrustedSetupToolchainAttestation(Buffer.from(toolchainUtf8),environment()),
    {nodeVersion:'v24.19.0',snarkjsVersion:PINNED_SNARKJS_VERSION,
      snarkjsPackageIntegrity:PINNED_SNARKJS_PACKAGE_INTEGRITY});
  for(const text of [toolchainUtf8.replace('0.7.6','0.7.5'),toolchainUtf8.replace('v24.19.0','v25.0.0'),
    ` ${toolchainUtf8}`,toolchainUtf8.replace('\n','\r\n')]) {
    assert.throws(()=>validateRisc0TrustedSetupToolchainAttestation(Buffer.from(text),environment()));
  }
});

test('requires Podman inspection to contain the exact immutable image ID',()=>{
  const plan=buildRisc0TrustedSetupPodmanPlan(environment());
  const valid=Buffer.from(`${JSON.stringify(plan.image)}\n`);
  assert.equal(validateRisc0TrustedSetupPodmanImageInspection(valid,plan),plan.image);
  for(const bytes of [Buffer.from('[]\n'),Buffer.from(`${JSON.stringify(`sha256:${'88'.repeat(32)}`)}\n`),
    Buffer.from(` "${plan.image}"\n`),Buffer.from(`\n${JSON.stringify(plan.image)}\n`),
    Buffer.from(`${JSON.stringify(plan.image)}\r\n`),Buffer.from('not-json\n')]) {
    assert.throws(()=>validateRisc0TrustedSetupPodmanImageInspection(bytes,plan));
  }
});

test('rejects ambiguous framing, failure markers and malformed contribution hashes',()=>{
  const good=Buffer.from('[INFO]  snarkJS: Powers Of tau file OK!\n');
  const groups=Array.from({length:16},(_,index)=>(index+1).toString(16).padStart(8,'0')).join(' ');
  const valid=`[INFO]  snarkJS: Contribution Hash:\n ${groups}\n[INFO]  snarkJS: ZKey Ok!\n`;
  for(const [powersOfTauLog,zkeyLog] of [
    [good,Buffer.from('snarkJS: ZKey Ok!\n')],
    [Buffer.from('\u001b[32msnarkJS: Powers Of tau file OK!\n'),Buffer.from('x')],
    [Buffer.from('not verified\n'),Buffer.from('not verified\n')],
    [good,Buffer.from(`${valid}ignored after success\n`)],
    [good,Buffer.from(`${valid.slice(0,-1)}\n[INFO]  snarkJS: ZKey Ok!\n`)],
    [good,Buffer.from(`[ERROR] verification failed\n${valid}`)],
    [Buffer.from('[INFO]  snarkJS: Powers Of tau file OK!\r\n'),Buffer.from(valid)],
    [good,Buffer.from(`[INFO]  snarkJS: Contribution Hash: ${groups}\n[INFO]  snarkJS: ZKey Ok!\n`)],
    [good,Buffer.from(`[INFO]  snarkJS: Contribution Hash:\n ${groups} deadbeef\n[INFO]  snarkJS: ZKey Ok!\n`)],
    [good,Buffer.from(`[INFO]  snarkJS: Contribution Hash:\n ${groups.split(' ').slice(0,15).join(' ')}\n[INFO]  snarkJS: ZKey Ok!\n`)],
  ]) {
    assert.throws(()=>parseSnarkjsVerificationLogs({powersOfTauLog,zkeyLog}));
  }
});

test('materializer streams large artifacts and rechecks immutable authorities',async()=>{
  const source=await readFile(new URL('../../scripts/prepare-risc0-trusted-setup-verification-report.mjs',import.meta.url),'utf8');
  assert.match(source,/createReadStream\(\{autoClose:false\}\)/);
  assert.match(source,/constants\.O_NOFOLLOW/);
  assert.match(source,/before\.nlink!==1n/);
  assert.match(source,/identity\(before\)!==identity\(after\)/);
  assert.match(source,/referenceAfter\.equals\(referenceBytes\)/);
  assert.match(source,/authorityAfter\.equals\(authorityBytes\)/);
  assert.match(source,/runtime\.digest!==environment\.containerRuntime\.sha256/);
  assert.match(source,/before\.mode&0o6000n/);
  assert.match(source,/--print-podman-plan/);
  assert.match(source,/buildRisc0TrustedSetupPodmanPlan\(environment\)/);
  assert.match(source,/process\.argv\.length!==2/);
  assert.match(source,/RISC0_TRUSTED_SETUP_PODMAN_PATHS/);
  assert.doesNotMatch(source,/process\.argv\.slice\(2\)/);
  assert.doesNotMatch(source,/readFile\(r1csPath|readFile\(ptauPath|readFile\(zkeyPath/);
});

test('executor uses fixed shell-free create-once evidence and tmpfs output',async()=>{
  const source=await readFile(new URL('../../scripts/execute-risc0-trusted-setup-verification.mjs',import.meta.url),'utf8');
  assert.match(source,/process\.argv\.length!==2/);
  assert.match(source,/shell:false/);
  assert.match(source,/O_NOFOLLOW/);
  assert.match(source,/writePrivateFileDurableNew/);
  assert.match(source,/stdio:\['ignore','pipe','pipe'\]/);
  assert.doesNotMatch(source,/link\(temporary,outputPath\)/);
  assert.match(source,/statfs\(directory/);
  assert.match(source,/await lstat\(directory/);
  assert.match(source,/await realpath\(directory\)!==directory/);
  assert.match(source,/TMPFS_MAGIC/);
  assert.match(source,/output exceeded its limit/);
  assert.match(source,/exceeded its time limit/);
  assert.match(source,/child\.kill\('SIGKILL'\)/);
  assert.match(source,/cross-process lock/);
  assert.match(source,/changed during container verification/);
  assert.match(source,/environmentAfter\.equals\(environmentBytes\)/);
  assert.match(source,/validateRisc0TrustedSetupPodmanImageInspection/);
  assert.match(source,/expectedVerificationKeySha256/);
  assert.doesNotMatch(source,/exec(?:File|Sync)?\(/);
  assert.doesNotMatch(source,/process\.argv\.slice/);
});

test('writer installs one transcript monotonically into both verifier configurations',async()=>{
  const writer=await readFile(new URL('../../scripts/write-risc0-trusted-setup-verification-report.sh',import.meta.url),'utf8');
  const generator=await readFile(new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url),'utf8');
  assert.match(writer,/install-private-file-immutable-stdin\.mjs --json "\$report_target"/);
  assert.match(writer,/\.proofSystem==null or \.proofSystem=="risc0-groth16-v3"/);
  assert.match(writer,/\.trustedSetupTranscriptSha256==null or \.trustedSetupTranscriptSha256==\$transcript/);
  assert.match(writer,/\.checkpointTrustedSetup\.transcript==null or \.checkpointTrustedSetup\.transcript==\$document/);
  assert.match(writer,/Another release materializer holds the config lock/);
  assert.match(writer,/Another trusted-setup writer holds the evidence lock/);
  assert.match(writer,/read-release-config-file-stdout\.mjs "\$target" \| cmp -s/);
  assert.match(writer,/replace-locked-source-stdin\.mjs "\$target"/);
  assert.match(writer,/"\$candidate_sha256" "\$\{target_sha256\[\$name\]\}" "\$parent_device" "\$parent_inode"/);
  assert.match(writer,/pin_runtime_tool node; pin_runtime_tool jq; pin_runtime_tool python3/);
  assert.match(generator,/verify-risc0-trusted-setup\)/);
  assert.match(generator,/execute:risc0-trusted-setup-verification/);
  assert.match(generator,/write:risc0-trusted-setup-verification/);
});

test('environment preparer derives every commitment without operator-filled values',async()=>{
  const source=await readFile(new URL('../../scripts/prepare-risc0-trusted-setup-verification-environment.mjs',import.meta.url),'utf8');
  assert.match(source,/process\.argv\.length!==2/);
  assert.match(source,/DISCOVERY_IMAGE='localhost\/usdom-snarkjs:0\.7\.6'/);
  assert.match(source,/--pull=never/);assert.match(source,/--network=none/);
  assert.match(source,/--userns=keep-id:uid=65532,gid=65532/);
  assert.match(source,/RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS\.attestToolchain/);
  assert.match(source,/RISC0_TRUSTED_SETUP_VERIFICATION_COMMANDS\.exportVerificationKey/);
  assert.match(source,/source-pinned trusted-setup artifact digest mismatch/);
  assert.match(source,/expectedVerificationKeySha256:verificationKey\.digest/);
  assert.match(source,/statfs\(temporary/);assert.match(source,/TMPFS_MAGIC/);
  assert.match(source,/refusing to clean a replaced bootstrap directory/);
  assert.doesNotMatch(source,/process\.argv\.slice/);
  assert.doesNotMatch(source,/shell:true/);
});

test('all trusted-setup preparers compile in the exact mainnet reference authority',async()=>{
  for(const relative of [
    '../../scripts/prepare-risc0-trusted-setup-verification-report.mjs',
    '../../scripts/prepare-risc0-trusted-setup-verification-environment.mjs',
    '../../scripts/prepare-trusted-setup-decision-report.mjs',
  ]) {
    const source=await readFile(new URL(relative,import.meta.url),'utf8');
    assert.match(source,/validateRiscZeroMainnetReference\(parse/);
  }
});

test('toolchain image build pins base, dependencies and offline final build',async()=>{
  const source=await readFile(new URL('../../scripts/build-risc0-snarkjs-image.sh',import.meta.url),'utf8');
  const policy=JSON.parse(await readFile(new URL('../../config/risc0-snarkjs-image-build-v1.json',import.meta.url)));
  const lock=JSON.parse(await readFile(new URL('../../containers/risc0-snarkjs/package-lock.json',import.meta.url)));
  assert.equal(policy.baseImage,'docker.io/library/node@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df');
  assert.equal(policy.baseImageAmd64ManifestSha256,'e5a8dee7bc1e6a215d224a7ef8206f7e77271bc3cabd5febf2beafac0674f174');
  assert.equal(lock.packages['node_modules/snarkjs'].version,PINNED_SNARKJS_VERSION);
  assert.equal(lock.packages['node_modules/snarkjs'].integrity,PINNED_SNARKJS_PACKAGE_INTEGRITY);
  assert.match(source,/npm ci .*--ignore-scripts/);assert.match(source,/npm pack snarkjs@0\.7\.6 --ignore-scripts/);
  assert.match(source,/podman" build --network=none --pull=never --no-cache/);
  assert.match(source,/test "\$base_digest" = 'sha256:e5a8dee7/);
  assert.match(source,/--network=none --read-only/);
});

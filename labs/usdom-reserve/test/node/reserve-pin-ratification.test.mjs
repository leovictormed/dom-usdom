import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {chmod,link,mkdir,mkdtemp,rm,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {getCreateAddress} from 'ethers';
import {safeOwnersCommitment} from '../../sdk/configuration.mjs';
import {deriveDomDomain} from '../../sdk/preactivation-policy.mjs';
import {checkpointRegistryPreActivationConfigHash} from '../../sdk/checkpoint-registry.mjs';
import {buildReservePinRatificationProposal,restoreReservePinRatificationBaseline,
  verifyReservePinRatificationProposal}
  from '../../sdk/reserve-pin-ratification.mjs';
import {materializeProductionSolidityPins} from '../../sdk/production-solidity-pins.mjs';
import {installReservePinRatificationProposal,prepareReservePinRatificationFromProject}
  from '../../sdk/reserve-pin-ratification-project.mjs';

const h=b=>'0x'+b.repeat(64),a=b=>'0x'+b.repeat(40),blob=b=>Buffer.from(b);
function fixture() {
  const r={ethereumChainId:'1',productionReady:false,realFundsAuthorized:false,deploymentMethod:'CREATE',
    deployer:a('a'),deployerNonce:'1',verifierDeployer:a('b'),verifierDeployerNonce:'2',
    checkpointRegistryDeployer:a('c'),checkpointRegistryDeployerNonce:'3',checkpointVerifierDeployer:a('d'),checkpointVerifierDeployerNonce:'4',
    token:a('2'),tokenCodeHash:h('7'),verifierCodeHash:h('1'),verifierConfigHash:h('2'),
    checkpointRegistryRuntimeCodeHash:h('3'),checkpointVerifierCodeHash:h('4'),checkpointVerifierConfigHash:h('5'),
    governance:a('4'),governanceCodeHash:h('a'),governanceImplementation:a('4'),governanceImplementationCodeHash:h('a'),
    guardian:a('5'),guardianCodeHash:h('b'),guardianImplementation:a('5'),guardianImplementationCodeHash:h('b'),
    withdrawalDelaySeconds:'86400',governanceDelaySeconds:'172800',maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'1000000',
    checkpointDomNetworkMagic:'2712847316',checkpointDomChainId:h('c'),checkpointFirstV4Height:'101',checkpointIntervalBlocks:'100',checkpointConfirmationDepthBlocks:'10',checkpointChallengePeriodSeconds:'172800',
    checkpointVerifierCodeHash:h('4'),checkpointVerifierConfigHash:h('5'),checkpointGuardian:a('8'),checkpointGuardianCodeHash:h('e'),checkpointGuardianImplementation:a('8'),checkpointGuardianImplementationCodeHash:h('e'),
    checkpointInitialHeight:'100',checkpointInitialBlock:h('f'),checkpointInitialContextHash:h('1'),checkpointInitialTotalDifficulty:'1000000',
    governanceOwners:[a('9'),a('a'),a('b')],guardianOwners:[a('c'),a('d'),a('e')],checkpointGuardianOwners:[a('6'),a('7'),a('8')]};
  r.reserve=getCreateAddress({from:r.deployer,nonce:1n}); r.verifier=getCreateAddress({from:r.verifierDeployer,nonce:2n});
  r.checkpointRegistry=getCreateAddress({from:r.checkpointRegistryDeployer,nonce:3n}); r.checkpointVerifier=getCreateAddress({from:r.checkpointVerifierDeployer,nonce:4n});
  r.governanceOwnersCommitment=safeOwnersCommitment(r.governanceOwners); r.guardianOwnersCommitment=safeOwnersCommitment(r.guardianOwners);
  r.domDomain=deriveDomDomain({domNetworkMagic:r.checkpointDomNetworkMagic,domChainId:r.checkpointDomChainId,ethereumChainId:'1',reserve:r.reserve,checkpointRegistry:r.checkpointRegistry});
  r.checkpointRegistryConfigHash=checkpointRegistryPreActivationConfigHash({ethereumChainId:'1',registry:r.checkpointRegistry,bridgeDomain:r.domDomain,domNetworkMagic:r.checkpointDomNetworkMagic,domChainId:r.checkpointDomChainId,firstV4Height:r.checkpointFirstV4Height,checkpointInterval:r.checkpointIntervalBlocks,confirmationDepth:r.checkpointConfirmationDepthBlocks,challengePeriod:r.checkpointChallengePeriodSeconds,verifier:r.checkpointVerifier,verifierCodeHash:r.checkpointVerifierCodeHash,verifierConfigHash:r.checkpointVerifierConfigHash,guardian:r.checkpointGuardian,guardianCodeHash:r.checkpointGuardianCodeHash,guardianImplementation:r.checkpointGuardianImplementation,guardianImplementationCodeHash:r.checkpointGuardianImplementationCodeHash,guardianOwnersCommitment:safeOwnersCommitment(r.checkpointGuardianOwners),initialHeight:r.checkpointInitialHeight,initialBlock:r.checkpointInitialBlock,initialContextHash:r.checkpointInitialContextHash,initialTotalDifficulty:r.checkpointInitialTotalDifficulty}).checkpointConfigHash;
  const source=readFileSync(new URL('../../contracts/USDOMProofReserve.sol',import.meta.url));
  const inventory=blob('inventory'),toolchain=blob('lock');
  const digest=value=>createHash('sha256').update(value).digest('hex');
  const manifest=Buffer.from([
    `${digest(toolchain)}  config/mainnet-toolchain-lock.json`,
    `${digest(inventory)}  config/rebuild-v3-critical-source-inventory.json`,
    `${digest(source)}  contracts/USDOMProofReserve.sol`,
  ].sort().join('\n')+'\n');
  const inputs={releaseConfig:r,releaseConfigBytes:blob(JSON.stringify(r)),reserveSourceBytes:source,finalizedBurnVerifierArtifactBytes:blob('artifact'),finalizedBurnVerifierConfigBytes:blob('config'),sourceManifestBytes:manifest,criticalSourceInventoryBytes:inventory,toolchainLockBytes:toolchain};
  return inputs;
}

test('derives the three reserve pins into a review-only release/source/toolchain-bound proposal',()=>{
  const inputs=fixture(),proposal=buildReservePinRatificationProposal(inputs);
  assert.equal(verifyReservePinRatificationProposal({proposal,...inputs}),true);
  assert.equal(Object.keys(proposal.pins).length,3); assert.equal(proposal.productionPinsActivated,false);
  assert.match(proposal.reviewPatch,/PRODUCTION_RESERVE_PREACTIVATION_CONFIG_HASH/);
  assert.match(proposal.reviewPatch,/^-.*bytes32\(0\)/m); assert.match(proposal.reviewPatch,/^\+.*0x[0-9a-f]{64}/m);
});

test('fails closed on every bound byte input, authority state and pre-activated source',()=>{
  const inputs=fixture(),proposal=buildReservePinRatificationProposal(inputs);
  for(const field of ['releaseConfigBytes','reserveSourceBytes','finalizedBurnVerifierArtifactBytes','finalizedBurnVerifierConfigBytes','sourceManifestBytes','criticalSourceInventoryBytes','toolchainLockBytes']) {
    const changed={...inputs,[field]:Buffer.concat([inputs[field],blob('x')])};
    assert.throws(()=>verifyReservePinRatificationProposal({proposal,...changed}),
      /differs|deliberately zero|release config|JSON|source manifest/);
  }
  assert.throws(()=>verifyReservePinRatificationProposal({proposal:{...proposal,productionPinsActivated:true},...inputs}),/authority state/);
  const activated=Buffer.from(inputs.reserveSourceBytes.toString().replace('bytes32(0)',h('f')));
  assert.throws(()=>buildReservePinRatificationProposal({...inputs,reserveSourceBytes:activated}),/deliberately zero/);
});

test('rejects detached release objects before deriving or verifying any pin',()=>{
  const inputs=fixture(),proposal=buildReservePinRatificationProposal(inputs);
  const objectB={...inputs.releaseConfig,unexpected:true};
  assert.throws(()=>buildReservePinRatificationProposal({...inputs,releaseConfig:objectB}),
    /object differs from its authority bytes/);
  assert.throws(()=>verifyReservePinRatificationProposal({proposal,...inputs,releaseConfig:objectB}),
    /object differs from its authority bytes/);
  const bytesB=Buffer.from(JSON.stringify(objectB));
  assert.throws(()=>verifyReservePinRatificationProposal({proposal,...inputs,releaseConfig:objectB,
    releaseConfigBytes:bytesB}),/differs from current release\/source\/toolchain inputs/);
});

test('rejects non-UTF-8 reserve source bytes before patch construction',()=>{
  const inputs=fixture();
  assert.throws(()=>buildReservePinRatificationProposal({...inputs,
    reserveSourceBytes:Buffer.concat([inputs.reserveSourceBytes,Buffer.from([0xff])])}),
  /canonical UTF-8/);
});

test('rejects a self-consistent proposal over a source graph detached from its manifest',()=>{
  const inputs=fixture();
  const detached=Buffer.from(inputs.sourceManifestBytes.toString().replace(/[0-9a-f]{64}(?=  contracts\/USDOMProofReserve\.sol)/,'0'.repeat(64)));
  assert.throws(()=>buildReservePinRatificationProposal({...inputs,sourceManifestBytes:detached}),
    /USDOMProofReserve\.sol differs from the authenticated source manifest/);
});

async function skeletalProject() {
  const root=await mkdtemp(path.join(tmpdir(),'reserve-pin-ratification-'));
  await chmod(root,0o700);
  for(const directory of ['config','contracts','out/DOMFinalizedBurnRiscZeroVerifier.sol']) {
    await mkdir(path.join(root,directory),{recursive:true,mode:0o700});
  }
  const files={
    'config/release.json':'{}','config/verifier.json':'{}',
    'contracts/USDOMProofReserve.sol':'x',
    'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json':'{}',
    'MANIFEST.sha256':'x','config/rebuild-v3-critical-source-inventory.json':'{}',
    'config/mainnet-toolchain-lock.json':'{}'};
  for(const [name,contents] of Object.entries(files)) {
    await writeFile(path.join(root,name),contents,{mode:0o600});
  }
  return root;
}

test('project ratification rejects symlink, hardlink and mutable-mode inputs before parsing',async()=>{
  const variants=[
    ['symlink',async root=>symlink('release.json',path.join(root,'config/release-input.json'))],
    ['hardlink',async root=>link(path.join(root,'config/release.json'),path.join(root,'config/release-input.json'))],
    ['mutable mode',async root=>{await writeFile(path.join(root,'config/release-input.json'),'{}',{mode:0o600});
      await chmod(path.join(root,'config/release-input.json'),0o666);}]
  ];
  for(const [name,install] of variants) {
    const root=await skeletalProject();
    try {
      await install(root);
      await assert.rejects(prepareReservePinRatificationFromProject({root,
        releasePath:'config/release-input.json',verifierConfigPath:'config/verifier.json'}),
      /release config is not a safe direct regular file/,name);
    } finally {await rm(root,{recursive:true,force:true});}
  }
});

test('project ratification rejects non-UTF-8 JSON authorities without replacement decoding',async()=>{
  for(const [relative,label] of [
    ['config/verifier.json','config/verifier.json'],
    ['out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',
      'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json'],
  ]) {
    const root=await skeletalProject();
    try {
      await writeFile(path.join(root,relative),Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
        {mode:0o600});
      await assert.rejects(prepareReservePinRatificationFromProject({root,
        releasePath:'config/release.json',verifierConfigPath:'config/verifier.json'}),
      new RegExp(`${label.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}: input contains invalid UTF-8`));
    } finally {await rm(root,{recursive:true,force:true});}
  }
});

test('proposal publication is durable create-once-or-equal and rejects aliases or stale reuse',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'reserve-pin-publication-'));
  await chmod(root,0o700);
  const target=path.join(root,'proposal.json'),bytes=Buffer.from('{"proposal":1}\n');
  try {
    assert.deepEqual(await installReservePinRatificationProposal(target,bytes),bytes);
    assert.deepEqual(await installReservePinRatificationProposal(target,bytes),bytes);
    await assert.rejects(installReservePinRatificationProposal(target,Buffer.from('{"proposal":2}\n')),
      /differs from requested bytes/);
    const alias=path.join(root,'alias.json'); await symlink('proposal.json',alias);
    await assert.rejects(installReservePinRatificationProposal(alias,bytes),/durable target is unsafe/);
    const hardlink=path.join(root,'hardlink.json'); await link(target,hardlink);
    await assert.rejects(installReservePinRatificationProposal(hardlink,bytes),/durable target is unsafe/);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('an installed candidate permits only an exact idempotent retry of its original proposal',()=>{
  const inputs=fixture(),proposal=buildReservePinRatificationProposal(inputs);
  const candidate=Buffer.from(materializeProductionSolidityPins({releaseConfig:inputs.releaseConfig,
    reserveSource:inputs.reserveSourceBytes.toString('utf8'),component:'reserve'}).reserveSource);
  const baseline=restoreReservePinRatificationBaseline({proposal,candidateSourceBytes:candidate});
  assert.deepEqual(baseline,inputs.reserveSourceBytes);
  assert.equal(verifyReservePinRatificationProposal({proposal,...inputs,reserveSourceBytes:baseline}),true);
  const changed=Buffer.from(candidate); changed[changed.length-2]^=1;
  assert.throws(()=>restoreReservePinRatificationBaseline({proposal,candidateSourceBytes:changed}),
    /differs from the ratified candidate/);
  assert.throws(()=>restoreReservePinRatificationBaseline({proposal:{...proposal,pins:{...proposal.pins,
    PRODUCTION_VERIFIER_CODE_HASH:h('f')}},candidateSourceBytes:candidate}),/differs from the ratified pin/);
});

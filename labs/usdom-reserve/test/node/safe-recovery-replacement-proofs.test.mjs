import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,writeFile,chmod,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Wallet} from 'ethers';

const checker=fileURLToPath(new URL('../../scripts/check-safe-recovery-replacement-proofs.mjs',import.meta.url));
const signer=await readFile(new URL('../../scripts/sign-recoverable-safe-recovery.sh',import.meta.url),'utf8');
const roles=['governance','reserveGuardian','checkpointGuardian'];
const keys=['1','2','3'].map(value=>`0x${value.padStart(64,'0')}`);
const safes=['0x1000000000000000000000000000000000000001','0x2000000000000000000000000000000000000002','0x3000000000000000000000000000000000000003'];
const planHash=`0x${'ab'.repeat(32)}`;
const types={SafeRecoveryReplacementProof:[
  {name:'role',type:'string'},
  {name:'replacementOwner',type:'address'},
  {name:'planHash',type:'bytes32'},
]};

async function fixture(){
  const wallets=keys.map(key=>new Wallet(key));
  const plan={planHash,roles:roles.map((role,index)=>({role,safe:safes[index],newOwner:wallets[index].address}))};
  const proofs=[];
  for(let index=0;index<roles.length;index++){
    const role=roles[index],replacementOwner=wallets[index].address,safe=safes[index];
    const domain={name:'USDOM Safe Recovery Replacement Proof',version:'1',chainId:1,verifyingContract:safe};
    const message={role,replacementOwner,planHash};
    proofs.push({role,replacementOwner,safe,typedData:{types:{EIP712Domain:[
      {name:'name',type:'string'},{name:'version',type:'string'},{name:'chainId',type:'uint256'},
      {name:'verifyingContract',type:'address'},
    ],...types},primaryType:'SafeRecoveryReplacementProof',domain,message},
    signature:await wallets[index].signTypedData(domain,types,message)});
  }
  return {plan,bundle:{schema:'usdom-safe-recovery-replacement-proofs/v2',ethereumChainId:'1',planHash,proofs}};
}

async function runWith(plan,bundle){
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-replacement-proof-'));
  await chmod(directory,0o700);
  const planPath=path.join(directory,'plan.json'),proofPath=path.join(directory,'proofs.json');
  await writeFile(planPath,JSON.stringify(plan),{mode:0o600});
  await writeFile(proofPath,JSON.stringify(bundle),{mode:0o600});
  try {
    return spawnSync(process.execPath,[checker],{encoding:'utf8',env:{...process.env,
      USDOM_SAFE_RECOVERY_PLAN:planPath,USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS:proofPath}});
  } finally { await rm(directory,{recursive:true,force:true}); }
}

test('replacement possession proofs bind every new owner to the exact recovery plan',async()=>{
  const {plan,bundle}=await fixture();
  const result=await runWith(plan,bundle);
  assert.equal(result.status,0,result.stderr);
  assert.deepEqual(JSON.parse(result.stdout),{schema:'usdom-safe-recovery-replacement-proof-check/v1',valid:true,planHash,proofCount:3});
});

test('replacement possession checker rejects plan, typed-data and signature mutations',async()=>{
  const cases=[
    value=>{value.bundle.planHash=`0x${'cd'.repeat(32)}`;},
    value=>{value.bundle.proofs[0].typedData.message.role='reserveGuardian';},
    value=>{value.bundle.proofs[1].signature=value.bundle.proofs[0].signature;},
    value=>{value.bundle.proofs[0].signature=`0x${value.bundle.proofs[0].signature.slice(2).toUpperCase()}`;},
    value=>{value.bundle.proofs[2].extra=true;},
    value=>{value.plan.roles[0].newOwner=value.plan.roles[1].newOwner;},
  ];
  for(const mutate of cases){
    const value=await fixture(); mutate(value);
    const result=await runWith(value.plan,value.bundle);
    assert.notEqual(result.status,0);
    assert.deepEqual(JSON.parse(result.stderr),{schema:'usdom-release-safe-diagnostic/v1',ok:false,
      operation:'check-safe-recovery-replacement-proofs',code:'RELEASE_OPERATION_REJECTED'});
  }
});

test('replacement possession checker rejects group-readable recovery evidence',async()=>{
  const value=await fixture();
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-replacement-proof-mode-'));
  await chmod(directory,0o700);
  const planPath=path.join(directory,'plan.json'),proofPath=path.join(directory,'proofs.json');
  await writeFile(planPath,JSON.stringify(value.plan),{mode:0o600});
  await writeFile(proofPath,JSON.stringify(value.bundle),{mode:0o640});
  await chmod(proofPath,0o640);
  try {
    const result=spawnSync(process.execPath,[checker],{encoding:'utf8',env:{...process.env,
      USDOM_SAFE_RECOVERY_PLAN:planPath,USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS:proofPath}});
    assert.notEqual(result.status,0);
  } finally { await rm(directory,{recursive:true,force:true}); }
});

test('Safe recovery signer snapshots and continuously rechecks replacement proofs',()=>{
  assert.match(signer,/: "\$\{USDOM_SAFE_RECOVERY_REPLACEMENT_PROOFS:\?/);
  assert.match(signer,/replacement_proofs_snapshot="\$temporary\/replacement-proofs\.json"/);
  assert.match(signer,/snapshot_private "\$replacement_proofs_source" "\$replacement_proofs_snapshot"/);
  assert.match(signer,/"\$cmp_bin" -s "\$replacement_proofs_snapshot" "\$temporary\/replacement-proofs\.current\.json"/);
  assert.match(signer,/check-safe-recovery-replacement-proofs\.mjs >\/dev\/null/);
  assert.match(signer,/assert_signing_inputs_unchanged[\s\S]+wallet sign/);
});

test('Safe recovery operator authorization binds the complete offline signing context',()=>{
  assert.match(signer,/usdom-safe-recovery-offline-sign-v1\|action=signRecoverableSafeRecovery\|phase=offline-sign-only\|chainId=1\|planHash=\$plan_hash\|transactionPackageHash=\$transaction_package_hash\|safeTxHashes=\$safe_transaction_hashes\|planSha256=\$plan_sha256\|replacementProofsSha256=\$replacement_proofs_sha256\|safePackageSha256=\$safe_package_sha256\|safeBaselineSha256=\$safe_baseline_sha256/);
  assert.match(signer,/\.roles \| map\(\.role \+ ":" \+ \.safeTxHash\) \| join\(","\)/);
  assert.match(signer,/ASSINO RECUPERACAO SAFE SEM TRANSMITIR AUTH \$authorization_hash/);
  assert.ok(signer.indexOf('assert_signing_inputs_unchanged',signer.indexOf('authorization_hash=$(sha256_file'))>signer.indexOf('AUTH $authorization_hash'));
});

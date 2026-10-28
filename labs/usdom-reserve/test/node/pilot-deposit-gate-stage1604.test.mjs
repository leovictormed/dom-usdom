import assert from 'node:assert/strict'; import test from 'node:test'; import {chmodSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import {fileURLToPath} from 'node:url'; import {spawnSync} from 'node:child_process';
import {AbiCoder,Wallet,keccak256} from 'ethers';
import {buildPilotFundsSnapshot,pilotFundsAuthorizationDigest,pilotFundsReleaseId,
 pilotFundsSnapshotCommitment} from '../../sdk/pilot-funds-authorization.mjs';
import {rpcConsensusEvidence} from '../../sdk/rpc-consensus-evidence.mjs';
import {buildPilotDepositGatePlan,validatePilotDepositGatePlan,assemblePilotDepositGateTransaction,pilotDepositAuthorizationHash,_pilotDepositGateInternals} from '../../sdk/pilot-deposit-gate.mjs';
const address=n=>'0x'+n.toString(16).padStart(40,'0'),hash=n=>'0x'+n.toString(16).padStart(64,'0'),sha=n=>n.toString(16).padStart(64,'0');
const wallets=[new Wallet(hash(101)),new Wallet(hash(102)),new Wallet(hash(103))];
const release={ethereumChainId:'1',productionReady:true,realFundsAuthorized:false,governance:address(1),governanceCodeHash:hash(30),reserve:address(2),token:address(3),reserveConfigHash:hash(4),checkpointRegistryConfigHash:hash(5),maxOutstandingBaseUnits:'1000000',outflowCapacityBaseUnitsPerDay:'1000000',governanceOwners:wallets.map(v=>v.address),guardianOwners:[address(11),address(12),address(13)],checkpointGuardianOwners:[address(14),address(15),address(16)]};
const snapshot=buildPilotFundsSnapshot({releaseConfig:release,releaseConfigSha256:sha(1),deploymentPackageSha256:sha(2),safeControlBundleSha256:sha(3),nativePrivacyInstallationSha256:sha(4),checkpointCapacityEvidenceSha256:sha(5),finalizedBurnCapacityEvidenceSha256:sha(6),operationalGasEvidenceSha256:sha(7),residualRiskDraftSha256:sha(8),pilotDepositBaseUnits:'1000000',funder:address(20),salt:hash(21),receivingCommitment:hash(22),planSha256:sha(9),phaseCatalogSha256:sha(10),releaseValidationReportSha256:sha(11)});
const safePackage={threshold:'2',ownersByRole:{governance:wallets.map(v=>v.address)},controls:[{role:'governance',safe:release.governance}]};
const snapshotCommitment=pilotFundsSnapshotCommitment(snapshot);
const authorization={schema:'usdom-pilot-funds-authorization/v1',snapshotCommitment,
 releaseId:pilotFundsReleaseId(snapshotCommitment),validAfter:'1000',validUntil:'2000',
 governance:release.governance,pilotDepositBaseUnits:snapshot.pilotDepositBaseUnits,
 funder:snapshot.funder,salt:snapshot.salt,receivingCommitment:snapshot.receivingCommitment,
 nonce:hash(31),signature:'0x1234'};
const digest=pilotFundsAuthorizationDigest(authorization,release);
const rpcConsensus=rpcConsensusEvidence([{sourceId:'a',originKeccak256:hash(32)},
 {sourceId:'b',originKeccak256:hash(33)}]);
const authorizationState={schema:'usdom-pilot-funds-authorization-state/v1',authorization,digest,
 consumed:false,finalizedObservation:{chainId:'1',governance:release.governance,
 governanceCodeHash:release.governanceCodeHash,finalizedBlockHash:hash(34),finalizedBlockNumber:'99',
 snapshotBlockHashAfter:hash(34),finalizedBlockTimestamp:'1500',rpcConsensus,
 approvals:{pilotFundsAuthorization:{digest,valid:true}}}};
const expected=keccak256(AbiCoder.defaultAbiCoder().encode(['uint256','address','address','uint64','bytes32','bytes32','uint64','uint64'],[1n,release.reserve,snapshot.funder,snapshot.pilotDepositBaseUnits,snapshot.salt,snapshot.receivingCommitment,authorizationState.authorization.validUntil,'0']));
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const plan=buildPilotDepositGatePlan({snapshot,authorizationState,releaseConfig:release,safePackage,safeNonce:'7',pilotAuthorizationGeneration:'0',finalizedBlockNumber:'100',finalizedBlockHash:hash(23),observedAuthorization:expected});

test('pilot authorization hash has one canonical cross-language vector and binds every field',()=>{
 const input={chainId:'31337',reserve:address(0x1234),funder:address(0x5678),amount:'1000000',
  salt:'0x'+'ab'.repeat(32),receivingCommitment:'0x'+'cd'.repeat(32),validUntil:'1800600000',generation:'7'};
 const base=pilotDepositAuthorizationHash(input);
 assert.equal(base,'0xb62d4b7517cfe103cc9eccb8ef46e2ea015e89d540ba7e396a49d862a776685d');
 for(const [field,value] of Object.entries({chainId:'31338',reserve:address(0x1235),funder:address(0x5679),
  amount:'1000001',salt:'0x'+'ac'.repeat(32),receivingCommitment:'0x'+'ce'.repeat(32),
  validUntil:'1800600001',generation:'8'})) assert.notEqual(base,pilotDepositAuthorizationHash({...input,[field]:value}),field);
 assert.throws(()=>pilotDepositAuthorizationHash({...input,generation:(1n<<64n).toString()}));
});

test('all gate action calldata bind snapshot, generation and queue epoch',()=>{
 const iface=_pilotDepositGateInternals.reserveInterface;
 const cancel=iface.encodeFunctionData('cancelPilotDepositAuthorization',[plan.snapshotCommitment,plan.generation]);
 const clear=iface.encodeFunctionData('clearExpiredPilotDepositAuthorization',[plan.snapshotCommitment,plan.generation]);
 const pause=iface.encodeFunctionData('pauseQueueEpoch',['9',plan.generation]);
 assert.notEqual(cancel,iface.encodeFunctionData('cancelPilotDepositAuthorization',[hash(99),plan.generation]));
 assert.notEqual(cancel,iface.encodeFunctionData('cancelPilotDepositAuthorization',[plan.snapshotCommitment,'1']));
 assert.notEqual(clear,iface.encodeFunctionData('clearExpiredPilotDepositAuthorization',[hash(99),plan.generation]));
 assert.notEqual(clear,iface.encodeFunctionData('clearExpiredPilotDepositAuthorization',[plan.snapshotCommitment,'1']));
 assert.notEqual(pause,iface.encodeFunctionData('pauseQueueEpoch',['10',plan.generation]));
 assert.notEqual(pause,iface.encodeFunctionData('pauseQueueEpoch',['9','1']));
 const changedSnapshot=structuredClone(snapshot);changedSnapshot.salt=hash(99);
 assert.notEqual(plan.snapshotCommitment,pilotFundsSnapshotCommitment(changedSnapshot));
});

test('gate plan fixes exact snapshot tuple, Safe nonce and independent Safe hash',()=>{
 assert.equal(validatePilotDepositGatePlan(plan,{snapshot,authorizationState,releaseConfig:release,safePackage}),plan);
 const decoded=_pilotDepositGateInternals.reserveInterface.decodeFunctionData('authorizePilotDeposit',plan.safeTransaction.data);
 assert.deepEqual([decoded.snapshotCommitment,decoded.funder,decoded.amount.toString(),decoded.salt,decoded.receivingCommitment,decoded.validUntil.toString(),decoded.expectedGeneration.toString()],[plan.snapshotCommitment,snapshot.funder,snapshot.pilotDepositBaseUnits,snapshot.salt,snapshot.receivingCommitment,authorizationState.authorization.validUntil,'0']);
 for(const mutate of [p=>p.safeTransaction.nonce='8',p=>p.safeTransaction.data='0x00'+p.safeTransaction.data.slice(4),p=>p.snapshotCommitment=hash(99),p=>p.validUntil='2000000001',p=>p.generation='1']) { const copy=structuredClone(plan); mutate(copy); assert.throws(()=>validatePilotDepositGatePlan(copy,{snapshot,authorizationState,releaseConfig:release,safePackage})); }
 const forged=structuredClone(authorizationState); forged.digest=hash(99);
 assert.throws(()=>buildPilotDepositGatePlan({snapshot,authorizationState:forged,releaseConfig:release,
  safePackage,safeNonce:'7',pilotAuthorizationGeneration:'0',finalizedBlockNumber:'100',
  finalizedBlockHash:hash(23),observedAuthorization:expected}),/digest differs/);
});

test('assembly accepts exactly two distinct authorized owners in canonical order',async()=>{
 const entries=[]; for(const wallet of [wallets[2],wallets[0]]) entries.push({signer:wallet.address,signature:wallet.signingKey.sign(plan.safeTxHash).serialized});
 const transaction=assemblePilotDepositGateTransaction({plan,snapshot,authorizationState,releaseConfig:release,safePackage,signatures:entries});
 assert.equal(transaction.to,release.governance); assert.equal(transaction.signers.length,2); assert.equal(transaction.data.slice(0,10),_pilotDepositGateInternals.safeInterface.getFunction('execTransaction').selector);
 assert.throws(()=>assemblePilotDepositGateTransaction({plan,snapshot,authorizationState,releaseConfig:release,safePackage,signatures:[entries[0],entries[0]]}),/2-of-3/);
 const noncanonical=structuredClone(entries); noncanonical[0].signature=`${noncanonical[0].signature.slice(0,-2)}00`;
 assert.throws(()=>assemblePilotDepositGateTransaction({plan,snapshot,authorizationState,releaseConfig:release,safePackage,signatures:noncanonical}),/noncanonical/);
});

test('operator route binds dual finalized state, Safe review, recovery and completion-last',()=>{
 const source=readFileSync(path.join(root,'scripts/execute-pilot-deposit-gate.sh'),'utf8');
 for(const marker of ['flock -n 9','cmp -s "$tmp/a.json" "$tmp/b.json"','prepare-private-safe-hash-eth-call.mjs','AUTORIZO GATE PILOTO OWNER $index','sign_owner 1 "$sig1" "$sighex1"; sign_owner 2 "$sig2" "$sighex2"','check-pilot-gate-relayer-raw.mjs','pilot-deposit-gate-relayer-envelope.json','AUTORIZO TRANSMITIR GATE PILOTO','cast receipt "$txhash"','cast block finalized','ExecutionSuccess(bytes32,uint256)','PilotDepositAuthorized(bytes32,bytes32,uint64,uint64)','pilot-deposit-gate-finalized.json']) assert.ok(source.includes(marker),marker);
 assert.match(source,/realpath -e \/proc\/\$\$\/fd\/9/);
 assert.match(source,/evidence_parent_identity=\$\(stat -Lc '%d:%i:%u:%a' -- \/proc\/\$\$\/fd\/9\)/);
 assert.match(source,/assert_evidence_parent\(\)[\s\S]*stat -c '%d:%i:%u:%a'[\s\S]*stat -Lc '%d:%i:%u:%a'/);
 assert.ok((source.match(/assert_evidence_parent/g)??[]).length>=7);
 assert.match(source,/pilot_broadcast_state=clean[\s\S]*cleanup\(\)[\s\S]*pilot_broadcast_state != clean[\s\S]*status=80/);
 assert.match(source,/tmp_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$tmp"\)/);
 assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$tmp" 2>\/dev\/null\) == "\$tmp_identity"/);
 assert.match(source,/trap 'cleanup \$\?' EXIT/);
 for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
  assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));
 assert.match(source,/txhash=.*raw-validation[\s\S]*pilot_broadcast_state=signed-unresolved/);
 assert.match(source,/pilot_broadcast_state=publishing[\s\S]*publish-private-raw-transaction\.mjs/);
 assert.ok(source.lastIndexOf('pilot_broadcast_state=clean')>source.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"'));
 assert.match(source,/prepare-pilot-gate-relayer-envelope\.mjs "\$tmp\/private-transaction-input\.json" "\$package" "\$relayer_policy" "\$nonce1" "\$gas" "\$max_fee" 2000000000/);
 assert.doesNotMatch(source,/AUTORIZO ASSINAR GATE PILOTO AUTH|sign-onekey-mainnet-transaction/);
 assert.match(source,/AUTORIZO GATE PILOTO OWNER \$index HASH \$safe_hash[\s\S]*check-pilot-funds-authorization-live\.mjs[\s\S]*owner-\$index-pre-sign-a\.json[\s\S]*sign-onekey-ios-walletconnect-typed-data\.mjs/);
 assert.match(source,/prepare-pilot-gate-relayer-envelope\.mjs[\s\S]*raw privada do relayer ausente/);
 assert.doesNotMatch(source,/--ledger|prepare-ledger|assemble-ledger/);
 const postFinality=source.indexOf('post-finality-receipt-$label.json');
 assert.ok(postFinality>source.indexOf('finality_deadline=$((SECONDS+14400))'));
 assert.ok(postFinality<source.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"'));
 const finalSlice=source.slice(postFinality-300,source.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"'));
 for(const marker of ['for pair in "a:$rpc1" "b:$rpc2"','cast receipt "$txhash"','cast tx "$txhash"','transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs','hash,from,to,nonce,input,value,blockNumber,blockHash','cast block "$block" --field hash']) assert.ok(finalSlice.includes(marker),marker);
 assert.ok(source.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"')>source.lastIndexOf("authorizedPilotSnapshot()(bytes32)"));
 const generator=readFileSync(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
 const authorize=generator.indexOf('npm run --silent materialize:pilot-funds-authorization');
 const gate=generator.indexOf('run-operational-status78-cycle.mjs pilot-gate',authorize);
 const deposit=generator.indexOf('npm run --silent prepare:closed-mainnet-deposit',gate);
 assert.ok(authorize>=0&&gate>authorize&&deposit>gate);
});

test('persisted outer raw transaction cannot be swapped after signing',async()=>{
 const signatures=[wallets[0],wallets[1]].map(wallet=>({signer:wallet.address,signature:wallet.signingKey.sign(plan.safeTxHash).serialized}));
 const packageValue=assemblePilotDepositGateTransaction({plan,snapshot,authorizationState,releaseConfig:release,safePackage,signatures});
 const raw=await wallets[2].signTransaction({chainId:1,to:packageValue.to,value:0,data:packageValue.data,nonce:4,gasLimit:300000,maxFeePerGas:10n, maxPriorityFeePerGas:1n,type:2});
 const directory=mkdtempSync(path.join(os.tmpdir(),'pilot-gate-')); try {
  const rawPath=path.join(directory,'raw'),packagePath=path.join(directory,'package.json'); writeFileSync(rawPath,raw+'\n',{mode:0o600}); writeFileSync(packagePath,JSON.stringify(packageValue),{mode:0o600}); chmodSync(rawPath,0o600); chmodSync(packagePath,0o600);
  const valid=spawnSync(process.execPath,['scripts/check-pilot-deposit-gate-raw.mjs',rawPath,packagePath],{cwd:root,encoding:'utf8'}); assert.equal(valid.status,0,valid.stderr);
  const changed=await wallets[2].signTransaction({chainId:1,to:packageValue.to,value:0,data:'0x',nonce:4,gasLimit:300000,maxFeePerGas:10n,maxPriorityFeePerGas:1n,type:2}); writeFileSync(rawPath,changed+'\n',{mode:0o600}); assert.notEqual(spawnSync(process.execPath,['scripts/check-pilot-deposit-gate-raw.mjs',rawPath,packagePath],{cwd:root}).status,0);
 } finally {rmSync(directory,{recursive:true,force:true});}
});

test('restart path rejects partial completion, replaced tx and reorg before deposit',()=>{
 const source=readFileSync(path.join(root,'scripts/execute-pilot-deposit-gate.sh'),'utf8');
 const completionBranch=source.slice(source.indexOf('if test -e "$completion"; then'),source.indexOf('node scripts/check-pilot-funds-authorization-live.mjs'));
 for(const marker of ['assemble-pilot-deposit-gate-transaction.mjs','check-pilot-gate-relayer-raw.mjs','cast receipt "$txhash"','cast tx "$txhash"','transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs','hash,from,to,nonce,input,value,blockNumber,blockHash','ExecutionSuccess(bytes32,uint256)','PilotDepositAuthorized(bytes32,bytes32,uint64,uint64)','completed_finalized_hash','completed_index','observe "$rpc1" "$tmp/completion-state-a.json"','deposits(bytes32)(address,uint64,bytes32)']) assert.ok(completionBranch.includes(marker),marker);
 assert.ok(source.includes("authorizedPilotDeposit()(bytes32)")); assert.ok(source.includes("pilotDepositConsumed()(bool)"));
 assert.ok(source.includes('if ! cast receipt "$txhash"'));
 assert.ok(source.includes('assert_plan_prestate "$tmp/pre-send-a.json"')); assert.ok(source.includes('.pilotAuthorizationGeneration'));
 const generator=readFileSync(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
 const depositPhase=generator.slice(generator.indexOf('execute-pilot-deposit-secret)'),generator.indexOf('submit-pilot-burn-secret)'));
 assert.ok(depositPhase.indexOf('execute:pilot-deposit-gate')<depositPhase.indexOf('prepare:closed-mainnet-deposit'));
 assert.ok(depositPhase.includes('pilot-deposit-gate-finalized.json'));
});

test('expired generation is cleared, finalized and archived before retry',async()=>{
 const clear=readFileSync(path.join(root,'scripts/execute-expired-pilot-gate-clear.sh'),'utf8');
 assert.match(clear,/usdom-pilot-gate-clear-relayer-package\/v1/);
 assert.match(clear,/prepare-pilot-gate-relayer-envelope\.mjs/);
 assert.match(clear,/check-pilot-gate-relayer-raw\.mjs/);
 assert.doesNotMatch(clear,/--ledger|prepare-ledger|assemble-ledger|ledger_signature|sign-onekey-mainnet-transaction|AUTORIZO LIMPAR GATE EXPIRADO AUTH/);
 assert.match(clear,/realpath -e \/proc\/\$\$\/fd\/9/);
 assert.match(clear,/evidence_parent_identity=\$\(stat -Lc '%d:%i:%u:%a' -- \/proc\/\$\$\/fd\/9\)/);
 assert.match(clear,/assert_evidence_parent\(\)[\s\S]*stat -c '%d:%i:%u:%a'[\s\S]*stat -Lc '%d:%i:%u:%a'/);
 assert.ok((clear.match(/assert_evidence_parent/g)??[]).length>=5);
 assert.match(clear,/pilot_clear_broadcast_state=clean[\s\S]*cleanup\(\)[\s\S]*pilot_clear_broadcast_state != clean[\s\S]*status=80/);
 assert.match(clear,/txhash=.*raw\.json[\s\S]*pilot_clear_broadcast_state=signed-unresolved/);
 assert.match(clear,/pilot_clear_broadcast_state=publishing[\s\S]*publish-private-raw-transaction\.mjs/);
 assert.ok(clear.lastIndexOf('pilot_clear_broadcast_state=clean')>clear.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"'));
 const clearBarrier=clear.indexOf('post-finality-receipt-$label.json');
 assert.ok(clearBarrier>clear.indexOf('finality_deadline=$((SECONDS+14400))')&&clearBarrier<clear.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"'));
 const clearBarrierSlice=clear.slice(clearBarrier-250,clear.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"'));
 for(const marker of ['for pair in "a:$rpc1" "b:$rpc2"','cast receipt "$txhash"','cast tx "$txhash"','transactionHash,blockNumber,blockHash,transactionIndex,status,from,to,logs','hash,from,to,nonce,input,value,blockNumber,blockHash','cast block "$block" --field hash']) assert.ok(clearBarrierSlice.includes(marker),marker);
 for(const marker of ['flock -n 9','clearExpiredPilotDepositAuthorization(bytes32,uint64)','authorizedPilotValidUntil()(uint64)','pilotAuthorizationGeneration()(uint64)','PilotDepositAuthorizationCancelled(bytes32,bytes32,uint64,uint64,address)','cast receipt "$txhash"','cast tx "$txhash"','cast block finalized','pilot-deposit-gate-clear-finalized.json','transactionIndex','usdom-pilot-deposit-gate-clear-finalized/v2']) assert.ok(clear.includes(marker),marker);
 assert.ok(clear.lastIndexOf('install-private-file-new-stdin.mjs --json "$completion"')>clear.lastIndexOf('pilotAuthorizationGeneration()(uint64)'));
 const clearData=_pilotDepositGateInternals.reserveInterface.encodeFunctionData('clearExpiredPilotDepositAuthorization',[plan.snapshotCommitment,plan.generation]);
 const signed=await wallets[2].signTransaction({chainId:1,to:release.reserve,value:0,data:clearData,nonce:9,gasLimit:100000,maxFeePerGas:10n,maxPriorityFeePerGas:1n,type:2});
 const directory=mkdtempSync(path.join(os.tmpdir(),'pilot-clear-')); try {
  const rawPath=path.join(directory,'raw'); writeFileSync(rawPath,signed+'\n',{mode:0o600}); chmodSync(rawPath,0o600);
  const valid=spawnSync(process.execPath,['scripts/check-pilot-deposit-gate-clear-raw.mjs',rawPath,release.reserve,plan.snapshotCommitment,plan.generation],{cwd:root,encoding:'utf8'}); assert.equal(valid.status,0,valid.stderr);
  const wrong=spawnSync(process.execPath,['scripts/check-pilot-deposit-gate-clear-raw.mjs',rawPath,release.reserve,hash(999),plan.generation],{cwd:root,encoding:'utf8'}); assert.notEqual(wrong.status,0);
 } finally {rmSync(directory,{recursive:true,force:true});}
 const generator=readFileSync(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
 assert.ok(generator.indexOf('run-operational-status78-cycle.mjs pilot-gate-clear')<generator.indexOf('rotate-expired-pilot-funds-authorization.mjs'));
 const rotation=readFileSync(path.join(root,'scripts/rotate-expired-pilot-funds-authorization.mjs'),'utf8');
 assert.ok(rotation.includes('expired-cleared-finalized')); assert.ok(rotation.includes('requires finalized on-chain generation invalidation'));
});

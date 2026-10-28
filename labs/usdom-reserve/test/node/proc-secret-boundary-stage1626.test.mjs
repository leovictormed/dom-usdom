import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import path from 'node:path';import test from 'node:test';import {fileURLToPath} from 'node:url';import {Wallet,Transaction} from 'ethers';
import {prepareLedgerEip1559Transaction,assembleLedgerEip1559Transaction} from '../../sdk/ledger-eip1559-transaction.mjs';
import {prepareLedgerEip1559CreateTransaction,assembleLedgerEip1559CreateTransaction} from '../../sdk/ledger-eip1559-create-transaction.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
test('ledger EIP-1559 signing binds hidden calldata without passing it to the signer',()=>{const wallet=Wallet.createRandom(),prepared=prepareLedgerEip1559Transaction({from:wallet.address,to:'0x'+'12'.repeat(20),data:'0x'+ 'ab'.repeat(512),nonce:'3',gasLimit:'100000',maxFeePerGas:'3000000000',maxPriorityFeePerGas:'2000000000'}),signature=wallet.signingKey.sign(prepared.unsignedHash).serialized,raw=assembleLedgerEip1559Transaction(prepared,signature),tx=Transaction.from(raw);assert.equal(tx.from,wallet.address);assert.equal(tx.data,'0x'+'ab'.repeat(512));assert.throws(()=>assembleLedgerEip1559Transaction(prepared,Wallet.createRandom().signingKey.sign(prepared.unsignedHash).serialized),/signer mismatch/);});
test('private CREATE signing binds exact initcode and rejects substitution',()=>{const wallet=Wallet.createRandom(),data='0x'+ 'ab'.repeat(512),prepared=prepareLedgerEip1559CreateTransaction({from:wallet.address,data,nonce:'3',gasLimit:'100000',maxFeePerGas:'3000000000'}),signature=wallet.signingKey.sign(prepared.unsignedHash).serialized,raw=assembleLedgerEip1559CreateTransaction(prepared,signature),tx=Transaction.from(raw);assert.equal(tx.to,null);assert.equal(tx.from,wallet.address);assert.equal(tx.data,data);assert.throws(()=>assembleLedgerEip1559CreateTransaction({...prepared,unsignedSerialized:prepared.unsignedSerialized.slice(0,-2)+'00'},signature),/hash mismatch|policy mismatch|invalid/);assert.throws(()=>assembleLedgerEip1559CreateTransaction(prepared,Wallet.createRandom().signingKey.sign(prepared.unsignedHash).serialized),/signature invalid/);assert.throws(()=>assembleLedgerEip1559CreateTransaction(prepared,`0x${signature.slice(2).toUpperCase()}`),/signature invalid/);assert.throws(()=>assembleLedgerEip1559CreateTransaction(prepared,`${signature.slice(0,-2)}00`),/signature invalid/);});
test('pilot executors expose only RPC aliases, digests and private file paths to children',()=>{for(const name of ['execute-pilot-deposit-gate.sh','execute-pilot-deposit-gate-cancel.sh','execute-expired-pilot-gate-clear.sh']){const source=readFileSync(path.join(root,'scripts',name),'utf8');assert.match(source,/usdom_rpc_a usdom_rpc_b/);assert.doesNotMatch(source,/\.\[\]\.url/);assert.doesNotMatch(source,/cast (?:estimate|mktx)[^\n]*--data "\$data"/);assert.doesNotMatch(source,/publish-private-raw-transaction\.mjs "\$raw" "\$rpc/);assert.doesNotMatch(source,/getTransactionHash\([^\n]*"\$safe_data"/);assert.match(source,/check-pilot-gate-relayer-raw\.mjs/);assert.doesNotMatch(source,/sign-onekey-mainnet-transaction/);assert.doesNotMatch(source,/--ledger|prepare-ledger|assemble-ledger/);}});

test('expired gate clear hashes and compares calldata through its private file',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-expired-pilot-gate-clear.sh'),'utf8');
  assert.match(source,/keccak256\(v\.data\)[\s\S]*"\$tmp\/private-transaction-input\.json"/);
  assert.match(source,/--slurpfile private "\$tmp\/private-transaction-input\.json"/);
  assert.doesNotMatch(source,/cast keccak "\$data"|--arg data "\$data"/);
});
test('emergency gate cancel hashes and compares calldata through its private package',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-pilot-deposit-gate-cancel.sh'),'utf8');
  assert.match(source,/prepare-pilot-gate-relayer-envelope\.mjs "\$tmp\/private-transaction-input\.json" "\$package"/);
  assert.match(source,/check-pilot-gate-relayer-raw\.mjs/);
  assert.doesNotMatch(source,/cast keccak "\$data"|--arg data "\$data"/);
});
test('primary pilot gate hashes and compares calldata through its private package',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-pilot-deposit-gate.sh'),'utf8');
  assert.match(source,/prepare-pilot-gate-relayer-envelope\.mjs "\$tmp\/private-transaction-input\.json" "\$package"/);
  assert.match(source,/--slurpfile package "\$package"/);
  assert.doesNotMatch(source,/cast keccak "\$data"|--arg data "\$\(jq -er \.data "\$package"\)"/);
});

test('deployment executors publish signed transactions only from private files',()=>{
  for(const [name,rawPath] of [
    ['execute-mainnet-deployment.sh','"$raw_snapshot"'],
    ['execute-safe-control-deployment.sh','"$temporary/$role-raw.txt"'],
    ['execute-recoverable-safe-recovery.sh','"$raw_snapshot"'],
  ]) {
    const source=readFileSync(path.join(root,'scripts',name),'utf8');
    assert.ok(source.includes(`publish-private-raw-transaction.mjs ${rawPath}`),name);
    assert.doesNotMatch(source,/rpc publish "\$(?:raw|raw_line|raw_transaction)"/,name);
    assert.doesNotMatch(source,/publish-private-raw-transaction\.mjs "\$(?:raw|raw_line|raw_transaction)"/,name);
  }
});
test('mainnet deployment restart compares prior CREATE initcode through the package file',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-mainnet-deployment.sh'),'utf8');
  assert.match(source,/--slurpfile package "\$package_snapshot"/);
  assert.match(source,/\$package\[0\]\.transactions\[\$prior\]\.data/);
  assert.doesNotMatch(source,/--arg data "\$prior_data"|prior_data=/);
});
test('mainnet deployment keeps current CREATE initcode in its private handoff',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-mainnet-deployment.sh'),'utf8');
  for(const mode of ['estimate','plan','hash','prepare']) assert.ok(source.includes(`prepare-private-mainnet-create.mjs ${mode} "$transaction_initial"`),mode);
  assert.match(source,/contract-deployment-\$index-relayer-envelope\.json/);
  assert.match(source,/contract-deployment-\$index-relayer-external-raw\.txt/);
  assert.doesNotMatch(source,/sign-onekey-mainnet-transaction|onekey-classic-1s-identity/);
  assert.doesNotMatch(source,/wallet (?:address|sign)[^\n]*--ledger|assemble-private-mainnet-create/);
  assert.doesNotMatch(source,/rpc estimate --create "\$data"|plan-mainnet-deployment-gas\.mjs[^\n]*"\$data"|keccak "\$data"|mktx[^\n]*--create "\$data"|\bdata=\$\("\$jq_bin"/);
});

test('Safe deployment keeps operational calldata in an owner-only file or stdin',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-safe-control-deployment.sh'),'utf8');
  assert.match(source,/prepare-safe-deployment-private-input\.mjs/);
  assert.match(source,/prepare-private-eth-estimate-gas\.mjs "\$private_transaction_input"/);
  assert.match(source,/prepare-safe-control-deployment-relayer-envelope\.mjs "\$role" "\$private_transaction_input"/);
  assert.match(source,/check-safe-control-deployment-relayer-raw\.mjs "\$role" "\$temporary\/\$role-raw\.txt"/);
  assert.doesNotMatch(source,/--ledger|prepare-ledger|assemble-ledger|OneKey/);
  assert.doesNotMatch(source,/rpc estimate "\$to" "\$data"|mktx "\$to" "\$data"/);
  const helper=readFileSync(path.join(root,'scripts','prepare-safe-deployment-private-input.mjs'),'utf8');
  assert.match(helper,/readDirectFile\(process\.argv\[3\]/);
  assert.doesNotMatch(helper,/process\.argv\[[^\]]+\].*data/);
});

test('Safe recovery keeps swapOwner calldata in an owner-only file or stdin',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-recoverable-safe-recovery.sh'),'utf8');
  assert.match(source,/prepare-safe-recovery-private-input\.mjs/);
  assert.match(source,/prepare-ledger-eip1559-transaction\.mjs \\\n+        "\$private_transaction_input"/);
  assert.doesNotMatch(source,/rpc mktx "\$to" "\$data"/);
  const helper=readFileSync(path.join(root,'scripts','prepare-safe-recovery-private-input.mjs'),'utf8');
  assert.match(helper,/readDirectFile\(process\.argv\[3\]/);
  assert.doesNotMatch(helper,/process\.argv\[[^\]]+\].*data/);
});

test('closed deposit and redemption keep calldata in private files or stdin',()=>{
  for(const name of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(path.join(root,'scripts',name),'utf8');
    assert.match(source,/prepare-closed-mainnet-private-transaction-input\.mjs/);
    assert.match(source,/prepare-private-eth-estimate-gas\.mjs "\$private_input"/);
    if(name.includes('deposit')) {
      assert.match(source,/prepare-onekey-eip1559-transaction\.mjs "\$private_input"/);
      assert.match(source,/sign-onekey-mainnet-transaction\.mjs "\$onekey_identity" "\$prepared" "\$raw_candidate"/);
    } else {
      assert.match(source,/prepare-onekey-eip1559-transaction\.mjs "\$private_input"/);
      assert.match(source,/sign-onekey-mainnet-transaction\.mjs "\$onekey_identity" "\$prepared" "\$raw_candidate"/);
    }
    assert.doesNotMatch(source,/cast estimate "\$to" "\$data"|cast mktx[^\n]*--data "\$data"|--arg data "\$\{expected_data/);
  }
});
test('reserve resume keeps the signed outer calldata in owner-only files or stdin',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-reserve-resume.sh'),'utf8');
  assert.match(source,/prepare-private-eth-estimate-gas\.mjs "\$private_input"/);
  assert.match(source,/prepare-ledger-eip1559-transaction\.mjs "\$private_input"/);
  assert.match(source,/assemble-ledger-eip1559-transaction\.mjs "\$prepared"/);
  assert.match(source,/--rawfile calldata "\$calldata_file"/);
  assert.doesNotMatch(source,/cast estimate[^\n]*"\$exec_data"|cast keccak "\$exec_data"|cast mktx[^\n]*"\$exec_data"|--arg calldata "\$\{calldata/);
});
test('reserve resume hashes and queries the internal Safe calldata through its private file',()=>{
  const source=readFileSync(path.join(root,'scripts','execute-reserve-resume.sh'),'utf8');
  assert.match(source,/prepare-reserve-resume-private-safe-input\.mjs hash "\$calldata_file"/);
  assert.match(source,/prepare-reserve-resume-private-safe-input\.mjs call "\$calldata_file"/);
  assert.match(source,/printf '%s\\n' "\$safe_hash_call" \| cast rpc eth_call --raw/);
  assert.doesNotMatch(source,/cast keccak "\$calldata"|getTransactionHash\([^\n]*"\$calldata"/);
});
test('pilot gate executors reject inherited transport, tool and descriptor mutation',()=>{for(const name of ['execute-pilot-deposit-gate.sh','execute-pilot-deposit-gate-cancel.sh','execute-expired-pilot-gate-clear.sh']){const source=readFileSync(path.join(root,'scripts',name),'utf8');for(const variable of ['NODE_EXTRA_CA_CERTS','NODE_TLS_REJECT_UNAUTHORIZED','SSL_CERT_FILE','SSL_CERT_DIR','OPENSSL_CONF','RES_OPTIONS','HOSTALIASES','DYLD_INSERT_LIBRARIES'])assert.match(source,new RegExp(`unset[\\s\\S]{0,500}\\b${variable}\\b`),`${name}: ${variable}`);assert.match(source,/for inherited_name in \$\{!FOUNDRY_@\} \$\{!CAST_@\}/);assert.match(source,/ulimit -c 0/);assert.match(source,/for fd_path in \/proc\/"\$\$"\/fd\/\*/);assert.match(source,/stat -c '%u:%a' -- "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"/);}});
test('pilot gate receipt and finality observation loops are bounded and restart-safe',()=>{for(const name of ['execute-pilot-deposit-gate.sh','execute-pilot-deposit-gate-cancel.sh','execute-expired-pilot-gate-clear.sh']){const source=readFileSync(path.join(root,'scripts',name),'utf8');assert.match(source,/receipt_deadline=\$\(\(SECONDS\+1800\)\)/,name);assert.match(source,/finality_deadline=\$\(\(SECONDS\+14400\)\)/,name);assert.match(source,/receipt observation timed out; restart to recover without rebroadcast/,name);assert.match(source,/finality observation timed out; restart to recover without rebroadcast/,name);}});
test('expired gate cleanup authenticates its private temporary directory',()=>{const source=readFileSync(path.join(root,'scripts/execute-expired-pilot-gate-clear.sh'),'utf8');assert.match(source,/tmp_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$tmp"\)/);assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' "\$tmp" 2>\/dev\/null\) == "\$tmp_identity"/);assert.match(source,/trap 'cleanup \$\?' EXIT/);for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));});
test('canary material is transported by 0600 files or stdin, never argv/environment templates',()=>{const canary='RPC_API_KEY_CANARY_1626';for(const name of ['materialize-private-foundry-rpc-aliases.mjs','prepare-private-eth-estimate-gas.mjs','prepare-ledger-eip1559-transaction.mjs','assemble-ledger-eip1559-transaction.mjs']){const source=readFileSync(path.join(root,'scripts',name),'utf8');assert.doesNotMatch(source,new RegExp(canary));assert.match(source,/readDirectFile|readFileSync\(0/);}const checker=readFileSync(path.join(root,'scripts/check-pilot-safe-diagnostics.mjs'),'utf8');assert.match(checker,/sentinels/);});

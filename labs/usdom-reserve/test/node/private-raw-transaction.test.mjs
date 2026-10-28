import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,linkSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {parseRawTransactionPublicationResponse,
  readBoundedPublicationResponse,readPrivateRawTransaction} from '../../sdk/private-raw-transaction.mjs';
import {buildMainnetPreflightRpcCatalog} from '../../sdk/mainnet-preflight-rpc.mjs';

test('raw transaction reader accepts only owner 0600 single-link regular files',()=>{
  const root=mkdtempSync(join(tmpdir(),'usdom-private-raw-'));
  try {
    const file=join(root,'raw'); writeFileSync(file,'0x0102\n',{mode:0o600});
    assert.equal(readPrivateRawTransaction(file),'0x0102');
    chmodSync(file,0o644); assert.throws(()=>readPrivateRawTransaction(file),/0600/); chmodSync(file,0o600);
    const hard=join(root,'hard'); linkSync(file,hard); assert.throws(()=>readPrivateRawTransaction(file),/single-link/);
    rmSync(hard); const symbolic=join(root,'symbolic'); symlinkSync(file,symbolic);
    assert.throws(()=>readPrivateRawTransaction(symbolic)); rmSync(symbolic);
    writeFileSync(file,'0x0G',{mode:0o600}); assert.throws(()=>readPrivateRawTransaction(file),/malformed/);
  } finally { rmSync(root,{recursive:true,force:true}); }
});

test('publisher rejects credential-bearing RPC before network and never echoes raw',()=>{
  const root=mkdtempSync(join(tmpdir(),'usdom-private-publish-'));
  try {
    const file=join(root,'raw'); writeFileSync(file,'0x0102\n',{mode:0o600});
    for(const url of ['https://user:password@example.invalid','https://example.invalid/?api_key=secret',
      'https://example.invalid/#secret']) {
      const result=spawnSync(process.execPath,[new URL('../../scripts/publish-private-raw-transaction.mjs',import.meta.url).pathname,
        file,url],{encoding:'utf8'});
      assert.notEqual(result.status,0);
      assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
      assert.doesNotMatch(`${result.stdout}${result.stderr}`,/0x0102|user:password|api_key|secret/);
    }
  } finally { rmSync(root,{recursive:true,force:true}); }
});

test('publisher binds a selected private RPC endpoint to the reviewed public catalog',()=>{
  const root=mkdtempSync(join(tmpdir(),'usdom-private-publish-catalog-'));
  const policy={tlsPolicy:'node-default-ca-hostname-expiry-origin-pinned-v1',
    clockPolicy:'utc-wall-clock-sane-v1',clientPolicy:'ethereum-execution-client-stable-v1'};
  const reviewed=[
    {operatorId:'alpha',providerId:'alpha',infrastructureId:'alpha-prod',url:'https://alpha.example/',...policy},
    {operatorId:'beta',providerId:'beta',infrastructureId:'beta-prod',url:'https://beta.example/',...policy},
  ];
  try {
    const raw=join(root,'raw'),sources=join(root,'sources.json'),catalog=join(root,'catalog.json');
    writeFileSync(raw,'0x0102\n',{mode:0o600});
    writeFileSync(sources,JSON.stringify([{...reviewed[0],url:'https://attacker.example/'},reviewed[1]]),{mode:0o600});
    writeFileSync(catalog,JSON.stringify(buildMainnetPreflightRpcCatalog(reviewed)),{mode:0o644});
    chmodSync(raw,0o600); chmodSync(sources,0o600); chmodSync(catalog,0o644);
    const result=spawnSync(process.execPath,[new URL('../../scripts/publish-private-raw-transaction.mjs',import.meta.url).pathname,
      raw,sources,catalog,'0'],{encoding:'utf8'});
    assert.notEqual(result.status,0);
    assert.equal(JSON.parse(result.stderr).code,'RELEASE_OPERATION_REJECTED');
    assert.doesNotMatch(`${result.stdout}${result.stderr}`,/0x0102|attacker\.example/);
  } finally { rmSync(root,{recursive:true,force:true}); }
});

test('publisher refuses HTTP redirects for signed transaction transport',()=>{
  const source=readFileSync(new URL(
    '../../scripts/publish-private-raw-transaction.mjs',import.meta.url),'utf8');
  assert.match(source,/fetch\(url,\{method:'POST',[\s\S]*redirect:'error'/);
});

test('publisher response accepts one exact hash and rejects ambiguous JSON',()=>{
  const hash='ab'.repeat(32);
  const accepted=Buffer.from(`{"jsonrpc":"2.0","id":1,"result":"0x${hash}"}`);
  assert.equal(parseRawTransactionPublicationResponse(accepted),`0x${hash}`);
  assert.ok(accepted.every(byte=>byte===0));
  for(const text of [
    `{"jsonrpc":"2.0","id":1,"result":"0x${'cd'.repeat(32)}","result":"0x${hash}"}`,
    `{"jsonrpc":"2.0","id":1,"result":"0x${hash}","extra":true}`,
    `{"jsonrpc":"2.0","id":1,"error":{},"result":"0x${hash}"}`,
  ]) {
    const bytes=Buffer.from(text);
    assert.throws(()=>parseRawTransactionPublicationResponse(bytes));
    assert.ok(bytes.every(byte=>byte===0));
  }
  const oversized=Buffer.alloc(64*1024+1,1);
  assert.throws(()=>parseRawTransactionPublicationResponse(oversized),/size/);
  assert.ok(oversized.every(byte=>byte===0));
});

test('publisher bounds the RPC body while streaming, before allocating the full response',async()=>{
  const payload=Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x'+'ab'.repeat(32)+'"}');
  const accepted=new Response(new ReadableStream({start(controller){
    controller.enqueue(payload.subarray(0,7));controller.enqueue(payload.subarray(7));controller.close();
  }}),{headers:{'content-length':String(payload.length)}});
  assert.deepEqual(await readBoundedPublicationResponse(accepted),payload);
  const declared=new Response('x',{headers:{'content-length':'65537'}});
  await assert.rejects(readBoundedPublicationResponse(declared),/size/);
  let cancelled=false;
  const oversized=new Response(new ReadableStream({pull(controller){controller.enqueue(new Uint8Array(32768));},
    cancel(){cancelled=true;}}));
  await assert.rejects(readBoundedPublicationResponse(oversized),/size/);
  assert.equal(cancelled,true);
  const source=readFileSync(new URL('../../scripts/publish-private-raw-transaction.mjs',import.meta.url),'utf8');
  assert.match(source,/readBoundedPublicationResponse\(response\)/);
  assert.doesNotMatch(source,/response\.arrayBuffer\(\)/);
});

test('pilot executors keep raw transactions out of argv, values in env, disk tmp and logs',()=>{
  for(const name of ['deposit','redemption']) {
    const source=readFileSync(new URL(`../../scripts/execute-closed-mainnet-${name}.sh`,import.meta.url),'utf8');
    assert.match(source,/mktemp -d -p \/dev\/shm "\$prefix\.XXXXXXXX" \| head -c 128/);
    assert.match(source,/temporary=\$\(private_tmpdir usdom-closed-(?:deposit|redemption)\)/);
    assert.match(source,/for abandoned in \/dev\/shm\/usdom-closed-/);
    assert.match(source,/trap 'cleanup \$\?' EXIT/);
    for(const signal of ['HUP','INT','TERM']) assert.match(source,new RegExp(`trap 'cleanup [0-9]+' ${signal}`));
    assert.doesNotMatch(source,/chmod 0600 "\$raw_candidate"/);
    assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 45s \\\n\s+node scripts\/publish-private-raw-transaction\.mjs "\$raw_file" "\$rpc1" \| head -c 68 >"\$publication_output"/);
    assert.match(source,/test "\$\(stat_run -c '%s' "\$publication_output"\)" -le 67/);
    assert.match(source,/timeout --foreground --signal=TERM --kill-after=5s 120s \\\n\s+node scripts\/check-transaction-hash-output\.mjs "\$publication_output" "\$expected_hash"/);
    assert.doesNotMatch(source,/tx_hash=\$\(node scripts\/publish-private-raw-transaction\.mjs/);
    assert.match(source,/onekey_identity="\$evidence\/onekey-classic-1s-identity\.json"/);
    assert.match(source,/prepare-onekey-eip1559-transaction\.mjs "\$private_input"/);
    assert.match(source,/sign-onekey-mainnet-transaction\.mjs "\$onekey_identity" "\$prepared" "\$raw_candidate"/);
    assert.doesNotMatch(source,/--ledger|wallet sign|wallet address|prepare-ledger|assemble-ledger/i);
    assert.doesNotMatch(source,/cast mktx /);
    assert.match(source,/test "\$\(stat_run -c '%s' "\$raw_candidate"\)" -le 1048576/);
    assert.match(source,/\[\[ -f \$raw_candidate && ! -L \$raw_candidate \]\]/);
    assert.match(source,/test "\$\(stat_run -c '%u:%a:%h' -- "\$raw_candidate"\)" = "\$UID:600:1"/);
    const attestationIndex=source.indexOf("stat_run -c '%u:%a:%h' -- \"$raw_candidate\"");
    assert.ok(source.indexOf("head -c 1048577")<attestationIndex);
    assert.ok(source.indexOf(name==='deposit'?'write_deposit_validation "$candidate"':'write_redemption_candidate "$candidate"',attestationIndex)>attestationIndex);
    assert.doesNotMatch(source,/rm -f -- "\$raw_file"/);
    assert.match(source,/remove_private_raw "\$raw_file"/);
    assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s rm -rf -- "\$path"/g)??[]).length,1);
    assert.equal((source.match(/timeout --foreground --signal=TERM --kill-after=5s 120s rm -f -- "\$path"/g)??[]).length,1);
    assert.equal((source.match(/remove_private_tree "/g)??[]).length,2);
    assert.equal((source.match(/remove_private_raw "\$raw_file"/g)??[]).length,name==='deposit'?2:1);
    assert.match(source,/\[\[ ! -e \$path && ! -L \$path \]\]/);
    assert.match(source,/\[\[ -e \$raw_file && ! -e \$validation \]\]/);
    assert.match(source,/check-pilot-nonce-recovery\.mjs/);
    assert.doesNotMatch(source,/cast publish|RAW=|raw=\$\(cat|raw=\$\(cast mktx/);
  }
});

test('closed deposit cleanup removes only its authenticated private directory',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-deposit.sh',import.meta.url),'utf8');
  assert.match(source,/temporary_identity=\$\(stat_run -c '%u:%d:%i:%a' -- "\$temporary"\)/);
  assert.match(source,/abandoned_identity=\$\(stat_run -c '%u:%d:%i:%a' -- "\$abandoned"\)/);
  assert.match(source,/test "\$\(stat_run -c '%u:%d:%i:%a' -- "\$path"\)" = "\$expected_identity"/);
  assert.match(source,/remove_private_tree "\$temporary" "\$temporary_identity"/);
});

test('closed redemption cleanup removes only authenticated private directories',()=>{
  const source=readFileSync(new URL('../../scripts/execute-closed-mainnet-redemption.sh',import.meta.url),'utf8');
  assert.match(source,/temporary_identity=\$\(stat_run -c '%u:%d:%i:%a' -- "\$temporary"\)/);
  assert.match(source,/abandoned_identity=\$\(stat_run -c '%u:%d:%i:%a' -- "\$abandoned"\)/);
  assert.match(source,/test "\$\(stat_run -c '%u:%d:%i:%a' -- "\$path"\)" = "\$expected_identity"/);
  assert.match(source,/remove_private_tree "\$temporary" "\$temporary_identity"/);
});

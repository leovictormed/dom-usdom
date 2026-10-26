import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,chmod,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {validatePrivateRpcProxyReady} from '../../sdk/private-rpc-proxy-ready.mjs';

const pid=1234;
const token='ab'.repeat(32);
const ready={schema:'usdom-private-rpc-catalog-proxy-v1',pid,
  urls:[0,1].map(index=>`http://127.0.0.1:49152/${token}/${index}`)};

test('proxy readiness validator accepts one canonical ordered capability set',()=>{
  assert.deepEqual(validatePrivateRpcProxyReady(ready,{expectedPid:pid}),ready);
});

test('proxy readiness validator rejects schema, pid and exact-key drift',()=>{
  for(const changed of [
    {...ready,extra:true},
    {pid,urls:ready.urls},
    {...ready,schema:'usdom-private-rpc-catalog-proxy-v2'},
    {...ready,pid:'1234'},
    {...ready,pid:0},
    {...ready,pid:2_147_483_648},
  ]) assert.throws(()=>validatePrivateRpcProxyReady(changed,{expectedPid:pid}),/readiness/);
  assert.throws(()=>validatePrivateRpcProxyReady(ready,{expectedPid:pid+1}),/pid/);
});

test('proxy readiness validator rejects URL duplication, token/index/port and type drift',()=>{
  const cases=[
    {...ready,urls:[ready.urls[0],ready.urls[0]]},
    {...ready,urls:[ready.urls[0],`http://127.0.0.1:49152/${'cd'.repeat(32)}/1`]},
    {...ready,urls:[ready.urls[0],`http://127.0.0.1:49152/${token}/2`]},
    {...ready,urls:[ready.urls[0],`http://127.0.0.1:49153/${token}/1`]},
    {...ready,urls:[ready.urls[0],7]},
    {...ready,urls:[ready.urls[0]]},
  ];
  for(const changed of cases) assert.throws(()=>validatePrivateRpcProxyReady(changed),/readiness/);
});

test('shared readiness reader rejects duplicate keys and changed bytes',async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-ready-'));
  await chmod(directory,0o700);
  const file=path.join(directory,'ready.json');
  const checker=new URL('../../scripts/check-private-rpc-proxy-ready.mjs',import.meta.url);
  try {
    await writeFile(file,`${JSON.stringify(ready)}\n`,{mode:0o600});
    const accepted=spawnSync(process.execPath,[checker.pathname,file,String(pid)],{encoding:'utf8'});
    assert.equal(accepted.status,0,accepted.stderr);
    const [digest,...urls]=accepted.stdout.trimEnd().split('\n');
    assert.match(digest,/^[0-9a-f]{64}$/);
    assert.deepEqual(urls,ready.urls);
    await writeFile(file,`{"schema":"${ready.schema}","pid":${pid},"pid":${pid},"urls":${JSON.stringify(ready.urls)}}\n`,{mode:0o600});
    const duplicate=spawnSync(process.execPath,[checker.pathname,file,String(pid)],{encoding:'utf8'});
    assert.notEqual(duplicate.status,0);
    await writeFile(file,Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),{mode:0o600});
    const invalidUtf8=spawnSync(process.execPath,[checker.pathname,file,String(pid)],{encoding:'utf8'});
    assert.notEqual(invalidUtf8.status,0);
    await writeFile(file,`${JSON.stringify(ready)} \n`,{mode:0o600});
    const changed=spawnSync(process.execPath,[checker.pathname,file,String(pid),digest],{encoding:'utf8'});
    assert.notEqual(changed.status,0);
  } finally { await rm(directory,{recursive:true,force:true}); }
});

test('producer and both authority consumers share and continuously recheck the readiness validator',async()=>{
  const [producer,deployment,recovery]=await Promise.all([
    readFile(new URL('../../scripts/serve-private-rpc-catalog-proxy.mjs',import.meta.url),'utf8'),
    readFile(new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url),'utf8'),
    readFile(new URL('../../scripts/execute-recoverable-safe-recovery.sh',import.meta.url),'utf8'),
  ]);
  assert.match(producer,/validatePrivateRpcProxyReady\(value,\{expectedPid:process\.pid\}\)/);
  for(const consumer of [deployment,recovery]) {
    assert.match(consumer,/check-private-rpc-proxy-ready\.mjs/);
    assert.match(consumer,/rpc_proxy_ready_sha=\$\{rpc_ready\[0\]\}/);
    assert.match(consumer,/assert_rpc_proxy_alive[\s\S]*rpc_proxy_ready_sha/);
    assert.match(consumer,/rpc\(\) \{[\s\S]*assert_rpc_proxy_alive/);
  }
});

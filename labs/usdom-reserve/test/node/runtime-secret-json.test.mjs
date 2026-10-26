import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,linkSync,mkdirSync,mkdtempSync,readFileSync,rmSync,symlinkSync,writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readRuntimeSecretJsonFile} from '../../sdk/runtime-secret-json.mjs';

const VALUE='USDOM_TEST_RPC_SOURCES';
const FILE=`${VALUE}_FILE`;
let fallbackFile;

function fixture(t,payload='[{"url":"https://provider.invalid/key"}]') {
  const root=mkdtempSync(path.join(os.tmpdir(),'usdom-runtime-secret-'));
  chmodSync(root,0o700);
  const file=path.join(root,'sources.json');
  writeFileSync(file,payload,{mode:0o600});
  chmodSync(file,0o600);
  const previousValue=process.env[VALUE];
  const previousFile=process.env[FILE];
  delete process.env[VALUE]; process.env[FILE]=file; fallbackFile=file;
  t.after(()=>{
    if(previousValue===undefined) delete process.env[VALUE]; else process.env[VALUE]=previousValue;
    if(previousFile===undefined) delete process.env[FILE]; else process.env[FILE]=previousFile;
    rmSync(root,{recursive:true,force:true});
  });
  return {root,file};
}

const read=()=>{ if(!process.env[FILE]&&fallbackFile) process.env[FILE]=fallbackFile; return readRuntimeSecretJsonFile(VALUE,{label:'test RPC sources',maxBytes:1024,maxDepth:8}); };

test('runtime RPC JSON accepts only the owner-only path handoff',t=>{
  fixture(t);
  assert.equal(JSON.stringify(read()),'[{"url":"https://provider.invalid/key"}]');
  process.env[VALUE]='[{"url":"https://leaked.invalid"}]';
  assert.throws(read,new RegExp(`${VALUE} is forbidden`));
});

test('runtime RPC JSON rejects indirect, shared, linked and oversized files',t=>{
  const {root,file}=fixture(t);
  chmodSync(file,0o644);
  assert.throws(read,/current-user 0600/);
  chmodSync(file,0o600);

  const hard=path.join(root,'hard.json');
  linkSync(file,hard);
  assert.throws(read,/single-link/);
  rmSync(hard);

  const link=path.join(root,'link.json');
  symlinkSync(file,link);
  process.env[FILE]=link;
  assert.throws(read,/must not traverse symbolic links/);
  process.env[FILE]=file;

  writeFileSync(file,'x'.repeat(1025),{mode:0o600});
  assert.throws(read,/bounded file/);
  writeFileSync(file,Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),{mode:0o600});
  assert.throws(read,/not valid UTF-8/);
  writeFileSync(file,'{}',{mode:0o600});
  const shared=path.join(root,'shared');
  mkdirSync(shared,{mode:0o755});
  chmodSync(shared,0o755);
  const sharedFile=path.join(shared,'sources.json');
  writeFileSync(sharedFile,'{}',{mode:0o600});
  process.env[FILE]=sharedFile;
  assert.throws(read,/parent directory must be direct and owner-only/);
});

test('cast-facing executors expose only ephemeral loopback proxy URLs',()=>{
  const component=fileURLToPath(new URL('../..',import.meta.url));
  const proxy=readFileSync(path.join(component,'scripts','serve-private-rpc-catalog-proxy.mjs'),'utf8');
  assert.match(proxy,/readRuntimeSecretJsonFile\('USDOM_MAINNET_PREFLIGHT_RPC_SOURCES'/);
  assert.match(proxy,/server\.listen\(0,'127\.0\.0\.1'/);
  assert.match(proxy,/redirect:'error'/);
  assert.match(proxy,/MAX_REQUEST=4\*1024\*1024/);
  assert.match(proxy,/MAX_RESPONSE=32\*1024\*1024/);
  assert.match(proxy,/MAX_CONCURRENT_REQUESTS=8/);
  assert.match(proxy,/MAX_REQUESTS_PER_SOURCE=512/);
  assert.match(proxy,/reply\.id!==parsed\.id/);
  assert.match(proxy,/TextDecoder\('utf-8',\{fatal:true\}\)/);
  const readyValidator=readFileSync(path.join(component,'sdk','private-rpc-proxy-ready.mjs'),'utf8');
  assert.ok(readyValidator.includes('^http:\\/\\/127\\.0\\.0\\.1:'));
  for(const name of ['execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh']) {
    const source=readFileSync(path.join(component,'scripts',name),'utf8');
    assert.match(source,/serve-private-rpc-catalog-proxy\.mjs/);
    assert.match(source,/check-private-rpc-proxy-ready\.mjs/);
    assert.doesNotMatch(source,/resolve-mainnet-deployment-rpc-sources/);
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {chmodSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {buildMainnetPreflightRpcCatalog} from '../../sdk/mainnet-preflight-rpc.mjs';

const script=new URL('../../scripts/materialize-private-foundry-rpc-aliases.mjs',import.meta.url).pathname;
const policy={tlsPolicy:'node-default-ca-hostname-expiry-origin-pinned-v1',
  clockPolicy:'utc-wall-clock-sane-v1',clientPolicy:'ethereum-execution-client-stable-v1'};
const sources=[
  {operatorId:'alpha',providerId:'alpha',infrastructureId:'alpha-prod',url:'https://alpha.example/',...policy},
  {operatorId:'beta',providerId:'beta',infrastructureId:'beta-prod',url:'https://beta.example/',...policy},
];

function fixture(){
  const root=mkdtempSync(join(tmpdir(),'usdom-rpc-aliases-'));
  const privateFile=join(root,'sources.json'),catalogFile=join(root,'catalog.json');
  writeFileSync(privateFile,JSON.stringify(sources),{mode:0o600});
  writeFileSync(catalogFile,JSON.stringify(buildMainnetPreflightRpcCatalog(sources)),{mode:0o644});
  chmodSync(privateFile,0o600); chmodSync(catalogFile,0o644);
  return {root,privateFile,catalogFile};
}

test('private Foundry aliases are bound to the reviewed public RPC catalog',()=>{
  const value=fixture();
  try {
    const accepted=spawnSync(process.execPath,[script,value.privateFile,value.catalogFile],{encoding:'utf8'});
    assert.equal(accepted.status,0,accepted.stderr);
    assert.match(accepted.stdout,/usdom_rpc_a = "https:\/\/alpha\.example\/"/);
    assert.match(accepted.stdout,/usdom_rpc_b = "https:\/\/beta\.example\/"/);

    const substituted=sources.map((source,index)=>index===0
      ?{...source,url:'https://attacker.example/'}:source);
    writeFileSync(value.privateFile,JSON.stringify(substituted),{mode:0o600});
    chmodSync(value.privateFile,0o600);
    const rejected=spawnSync(process.execPath,[script,value.privateFile,value.catalogFile],{encoding:'utf8'});
    assert.notEqual(rejected.status,0);
    assert.equal(JSON.parse(rejected.stderr).code,'RELEASE_OPERATION_REJECTED');
    assert.doesNotMatch(rejected.stderr,/attacker\.example/);
  } finally { rmSync(value.root,{recursive:true,force:true}); }
});

test('private Foundry aliases require the exact public catalog and private modes',()=>{
  const value=fixture();
  try {
    const missing=spawnSync(process.execPath,[script,value.privateFile],{encoding:'utf8'});
    assert.notEqual(missing.status,0);
    chmodSync(value.catalogFile,0o600);
    const wrongMode=spawnSync(process.execPath,[script,value.privateFile,value.catalogFile],{encoding:'utf8'});
    assert.notEqual(wrongMode.status,0);
  } finally { rmSync(value.root,{recursive:true,force:true}); }
});

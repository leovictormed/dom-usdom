import test from 'node:test';import assert from 'node:assert/strict';import {mkdtemp,writeFile,chmod,readFile,rm} from 'node:fs/promises';import path from 'node:path';import {tmpdir} from 'node:os';import {spawnSync} from 'node:child_process';import {Wallet} from 'ethers';
const root=path.resolve(import.meta.dirname,'../..'),run=(script,args)=>spawnSync(process.execPath,[path.join(root,'scripts',script),...args],{cwd:root,encoding:'utf8'});
async function json(dir,name,value){const p=path.join(dir,name);await writeFile(p,`${JSON.stringify(value)}\n`,{mode:0o600});await chmod(p,0o600);return p;}
test('role identities are exact and separation rejects owners and sibling relayers',async()=>{const dir=await mkdtemp(path.join(tmpdir(),'relayer-roles-')),relayer=Wallet.createRandom(),owner=Wallet.createRandom();
 const identity={schema:'usdom-mainnet-gas-relayer-public-identity/v2',chainId:'1',address:relayer.address,role:'recovery-gas-only',encryptedKeystoreSha256:'aa'.repeat(32),custodyAuthority:false,tokenCustody:false},identityPath=await json(dir,'identity.json',identity);
 assert.equal(run('read-mainnet-gas-relayer-identity.mjs',[identityPath,'recovery']).stdout.trim(),relayer.address);assert.notEqual(run('read-mainnet-gas-relayer-identity.mjs',[identityPath,'pilot-gate']).status,0);
 const owners=await json(dir,'owners.json',{owners:[owner.address]});assert.equal(run('check-gas-relayer-role-separation.mjs',[relayer.address,owners]).status,0);assert.notEqual(run('check-gas-relayer-role-separation.mjs',[owner.address,owners]).status,0);assert.notEqual(run('check-gas-relayer-role-separation.mjs',[relayer.address,identityPath]).status,0);
});
test('creator and resumable pilot enumerate five isolated fixed roles',async()=>{const creator=await readFile(path.join(root,'scripts/create-mainnet-gas-relayer.sh'),'utf8'),pilot=await readFile(path.join(root,'scripts/prepare-onekey-ios-safe-mainnet-pilot.sh'),'utf8');
 for(const role of ['deployment','safe-deployment','recovery','reserve-resume','pilot-gate']){assert.match(creator,new RegExp(role));assert.match(pilot,new RegExp(role));}
 assert.match(creator,/root="\$relayer_base\/\$role"/);assert.match(creator,/test ! -e "\$root"/);assert.match(creator,/check-gas-relayer-role-separation\.mjs/);assert.match(pilot,/relayer-\$role-pending/);assert.match(pilot,/create-mainnet-gas-relayer\.sh "\$role"/);
 assert.ok(pilot.includes('PATH="${node_bin%/*}:/home/leonardov/.foundry/bin:/usr/bin:/bin" bash scripts/create-mainnet-gas-relayer.sh "$role"'));
 for(const file of ['create-mainnet-gas-relayer.sh','prepare-onekey-ios-safe-mainnet-pilot.sh'])assert.equal(spawnSync('bash',['-n',path.join(root,'scripts',file)]).status,0);
});
test('relayer handoff pins the installed tools even when the SSH PATH lacks node and cast',async t=>{
 const dir=await mkdtemp(path.join(tmpdir(),'relayer-path-'));
 t.after(()=>rm(dir,{recursive:true,force:true}));
 const pilot=await readFile(path.join(root,'scripts/prepare-onekey-ios-safe-mainnet-pilot.sh'),'utf8');
 const creator=await readFile(path.join(root,'scripts/create-mainnet-gas-relayer.sh'),'utf8');
 const invocation=pilot.split('\n').find(line=>line.includes(' bash scripts/create-mainnet-gas-relayer.sh "$role"'));
 assert.ok(invocation);
 const boundary=creator.split('\n').filter(line=>line.startsWith('source ')||line.startsWith('pin_runtime_tool ')).join('\n');
 assert.ok(boundary.includes('pin_runtime_tool node; pin_runtime_tool cast'));
 const lock=JSON.parse(await readFile(path.join(root,'config/mainnet-toolchain-lock.json'),'utf8'));
 const nodePath=lock.executables.find(tool=>tool.name==='node').realpath;
 const castPath=lock.executables.find(tool=>tool.name==='cast').realpath;
 const quote=value=>"'"+value.replaceAll("'","'\\''")+"'";
 const probe=path.join(dir,'probe.sh');
 await writeFile(probe,`set -euo pipefail\nproject=${quote(root)}\n${boundary}\nassert_runtime_tool node\nassert_runtime_tool cast\n`+
   `test "$1" = deployment\ntest "$USDOM_PILOT_STATE_DIR" = ${quote(path.join(dir,'state'))}\n`+
   `test "$USDOM_RELAYER_STATE_DIR" = ${quote(path.join(dir,'relayers'))}\nprintf '%s\\n' "$node_bin" "$cast_bin"\n`,{mode:0o700});
 const env={PATH:'/usr/bin:/bin',USDOM_PILOT_STATE_DIR:path.join(dir,'state'),USDOM_RELAYER_STATE_DIR:path.join(dir,'relayers')};
 const missing=spawnSync('/bin/bash',[probe,'deployment'],{cwd:root,env,encoding:'utf8',timeout:10000});
 assert.notEqual(missing.status,0,'the original SSH failure must be reproduced');
 assert.match(missing.stderr,/realpath/u);
 const command=`set -euo pipefail\nnode_bin=${quote(nodePath)}\nrole=deployment\n`+
   invocation.replace('scripts/create-mainnet-gas-relayer.sh',quote(probe));
 const result=spawnSync('/bin/bash',['--noprofile','--norc','-c',command],{cwd:root,env,encoding:'utf8',timeout:20000});
 assert.equal(result.status,0,result.stderr);assert.equal(result.stderr,'');
 assert.equal(result.stdout,`${nodePath}\n${castPath}\n`);
});

import assert from 'node:assert/strict'; import test from 'node:test';
import {mkdtemp,readFile,writeFile,chmod,mkdir} from 'node:fs/promises'; import {spawnSync} from 'node:child_process'; import os from 'node:os'; import path from 'node:path'; import net from 'node:net';
const root=new URL('../..',import.meta.url).pathname,manager=path.join(root,'scripts/manage-closed-mainnet-node.mjs'),node=process.execPath;
async function port(){const s=net.createServer();await new Promise((ok,no)=>s.listen(0,'127.0.0.1',e=>e?no(e):ok()));const p=s.address().port;await new Promise(ok=>s.close(ok));return p}
test('supervisor authenticates readiness and preserves PID identity across graceful restart',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'dom-node-supervisor-')),state=path.join(dir,'state'),data=path.join(dir,'data'),token=path.join(dir,'rpc.token'),p=await port();await mkdir(data,{mode:0o700});await writeFile(token,'a'.repeat(64)+'\n',{mode:0o600});
 const daemon=path.join(dir,'daemon.mjs'),launcher=path.join(dir,'launch.sh');
 await writeFile(daemon,`#!/usr/bin/env node\nimport http from'node:http';const token='a'.repeat(64);let server;server=http.createServer((q,r)=>{if(q.headers.authorization!=='Bearer '+token){r.writeHead(401).end();return}if(q.url==='/ready')r.end(JSON.stringify({ready:true,status:'ready'}));else if(q.url==='/status')r.end(JSON.stringify({version:3,chain_height:7,network:'mainnet'}));else if(q.url==='/chain/identity')r.end(JSON.stringify({rpc_api_version:1,protocol_version:3,network:'mainnet',network_magic:'444f4d31',chain_id:'f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b',genesis_hash:'182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce',tip_height:7,tip_hash:'00'.repeat(32),max_scan_range:100}));else if(q.url==='/shutdown'&&q.method==='POST'){r.end();setImmediate(()=>server.close(()=>process.exit(0)))}else r.writeHead(404).end()});server.listen(${p},'127.0.0.1');\n`);await chmod(daemon,0o755);
 await writeFile(launcher,`#!/usr/bin/env bash\nexec ${JSON.stringify(node)} ${JSON.stringify(daemon)}\n`);await chmod(launcher,0o755);
 const env={...process.env,USDOM_CLOSED_MAINNET_NODE_MOCK:'YES',USDOM_CLOSED_MAINNET_NODE_STATE_ROOT:state,USDOM_CLOSED_MAINNET_NODE_MOCK_LAUNCHER:launcher,USDOM_CLOSED_MAINNET_NODE_MOCK_BINARY:daemon,USDOM_CLOSED_MAINNET_NODE_MOCK_RPC_URL:`http://127.0.0.1:${p}`,USDOM_CLOSED_MAINNET_NODE_MOCK_TOKEN:token,USDOM_CLOSED_MAINNET_NODE_MOCK_DATA:data};
 const run=c=>spawnSync(node,[manager,c],{cwd:root,env,encoding:'utf8',timeout:45000});
 assert.equal(run('prepare').status,0);assert.equal(run('start').status,0);const first=JSON.parse(await readFile(path.join(state,'process.json')));assert.equal(run('readiness').status,0);assert.equal(run('restart').status,0);const second=JSON.parse(await readFile(path.join(state,'process.json')));assert.notEqual(second.pid,first.pid);assert.equal(run('verify-restart').status,0);assert.equal(run('stop').status,0);await assert.rejects(readFile(path.join(state,'process.json')));
});
test('productive phase builds, pins, supervises and gracefully stops without enabling mining',async()=>{
 const source=await readFile(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8'),start=source.indexOf('  produce-checkpoint-evidence-secret)'),end=source.indexOf('\n  measure-release-capacity)',start),phase=source.slice(start,end);
 for(const marker of ['USDOM_CLOSED_MAINNET_BUILD_ONLY=YES','manage-closed-mainnet-node.mjs prepare','manage-closed-mainnet-node.mjs start','manage-closed-mainnet-node.mjs readiness','manage-closed-mainnet-node.mjs restart','manage-closed-mainnet-node.mjs verify-restart','manage-closed-mainnet-node.mjs stop'])assert.ok(phase.includes(marker),marker);
 assert.match(phase,/trap 'node scripts\/manage-closed-mainnet-node\.mjs stop; exit 130' INT/u);
 assert.match(await readFile(path.join(root,'scripts/run-closed-mainnet-node.sh'),'utf8'),/export DOM_MINE=false/);
});
test('supervisor cannot inherit mining, wallet or reward authority and has no block producer',async()=>{
 const supervisor=await readFile(manager,'utf8'),launcher=await readFile(path.join(root,'scripts/run-closed-mainnet-node.sh'),'utf8');
 assert.doesNotMatch(supervisor,/\.\.\.process\.env/u);
 for(const forbidden of ['DOM_MINE','DOM_WALLET_PATH','DOM_WALLET_PASSWORD_FILE','DOM_MINING_REWARD_ADDRESS','DOM_COINBASE_ADDRESS'])assert.doesNotMatch(supervisor,new RegExp(`env:\\{[^}]*${forbidden}`,'su'));
 assert.match(launcher,/export DOM_MINE=false/u);
 assert.doesNotMatch(launcher,/DOM_MINE=true|DOM_WALLET_PATH=|DOM_WALLET_PASSWORD_FILE=|DOM_MINING_REWARD_ADDRESS=|DOM_COINBASE_ADDRESS=/u);
 assert.doesNotMatch(supervisor,/regtest\/mine|mine_block|generateBlock|block producer/iu);
});

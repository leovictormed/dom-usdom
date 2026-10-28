import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {chmod,mkdir,mkdtemp,readFile,rm,stat,symlink,writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import {validateOneKeyPilotRpcSources,installOneKeyPilotRpcSources} from '../../sdk/onekey-pilot-rpc-sources.mjs';
import {buildMainnetPreflightRpcCatalog} from '../../sdk/mainnet-preflight-rpc.mjs';
const root=path.resolve(import.meta.dirname,'../..');
const listen=handler=>new Promise(resolve=>{const server=createServer(handler);server.listen(0,'127.0.0.1',()=>resolve(server));});
const url=server=>`http://127.0.0.1:${server.address().port}/`;
const reply=(result='0x1')=>(_req,res)=>{res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({jsonrpc:'2.0',id:1,result}));};

test('two local mock origins validate chain 1 and install a private create-once source file',async()=>{const a=await listen(reply()),b=await listen(reply()),dir=await mkdtemp('/dev/shm/usdom-rpc2358-');try{const output=path.join(dir,'sources.json');const rows=await installOneKeyPilotRpcSources({urls:[url(a),url(b)],outputPath:output,allowLoopbackHttpForTest:true,timeoutMs:1000});assert.equal(rows.length,2);assert.equal((await stat(output)).mode&0o777,0o600);await assert.rejects(()=>installOneKeyPilotRpcSources({urls:[url(a),url(b)],outputPath:output,allowLoopbackHttpForTest:true,timeoutMs:1000}));const stored=await readFile(output,'utf8');assert.match(stored,/operator-1/);}finally{a.close();b.close();await rm(dir,{recursive:true,force:true});}});

test('duplicate origin, wrong chain and timeout fail closed',async()=>{const good=await listen(reply()),wrong=await listen(reply('0x2')),slow=await listen(()=>{});try{await assert.rejects(()=>validateOneKeyPilotRpcSources([url(good),url(good)],{allowLoopbackHttpForTest:true,timeoutMs:100}),/distinct/);await assert.rejects(()=>validateOneKeyPilotRpcSources([url(good),url(wrong)],{allowLoopbackHttpForTest:true,timeoutMs:100}),/chainId 1/);await assert.rejects(()=>validateOneKeyPilotRpcSources([url(good),url(slow)],{allowLoopbackHttpForTest:true,timeoutMs:20}),/timed out/);}finally{good.close();wrong.close();slow.close();}});

test('CLI rejects malformed piped stdin with RPC validation errors',async()=>{
  const dir=await mkdtemp('/dev/shm/usdom-rpc-cli-invalid2358-');
  try{
    const output=path.join(dir,'sources.json');
    for(const [input,message] of [
      ['', 'RPC input size rejected'],
      ['abc', 'RPC input size rejected'],
      ['ab\0c', 'RPC input size rejected'],
      ['a'.repeat(16385), 'RPC input size rejected'],
      ['https://rpc-a.example.invalid/\n', 'exactly two RPC input lines required'],
      ['https://rpc-a.example.invalid/\r\nhttps://rpc-b.example.invalid/\r\n', 'exactly two RPC input lines required'],
      ['first\nsecond\nthird\n', 'exactly two RPC input lines required'],
    ]){
      const run=spawnSync(process.execPath,[path.join(root,'scripts/install-onekey-pilot-rpc-sources.mjs'),output],{cwd:dir,env:{},input,encoding:'utf8',timeout:5000});
      assert.equal(run.error,undefined);
      assert.equal(run.status,1,run.stderr);
      assert.equal(run.stdout,'');
      assert.equal(run.stderr,`${message}\n`);
      await assert.rejects(()=>stat(output),{code:'ENOENT'});
    }
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('CLI installs two HTTPS sources from piped stdin with mocked chainId requests',async()=>{
  const dir=await mkdtemp('/dev/shm/usdom-rpc-cli-valid2358-');
  try{
    const urls=['https://rpc-a.example.invalid/','https://rpc-b.example.invalid/'];
    const mock=path.join(dir,'mock-fetch.mjs');
    await writeFile(mock,`import assert from 'node:assert/strict';
globalThis.fetch=async(url,options)=>{
  assert.ok(${JSON.stringify(urls)}.includes(url));
  assert.equal(options.method,'POST');
  assert.deepEqual(JSON.parse(options.body),{jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]});
  return new Response(JSON.stringify({jsonrpc:'2.0',id:1,result:'0x1'}),{status:200});
};\n`);
    for(const [index,ending] of ['','\n'].entries()){
      const output=path.join(dir,`sources-${index}.json`);
      const run=spawnSync(process.execPath,['--import',mock,path.join(root,'scripts/install-onekey-pilot-rpc-sources.mjs'),output],{cwd:dir,env:{},input:urls.join('\n')+ending,encoding:'utf8',timeout:5000});
      assert.equal(run.error,undefined);
      assert.equal(run.status,0,run.stderr);
      assert.equal(run.stdout,'');
      assert.equal(run.stderr,'');
      assert.equal((await stat(output)).mode&0o777,0o600);
      assert.deepEqual(JSON.parse(await readFile(output,'utf8')).map(source=>source.url),urls);
    }
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('orchestrator reports pending without exposing RPC values through argv, env or output',async()=>{const script=await readFile(path.join(root,'scripts/prepare-onekey-ios-safe-mainnet-pilot.sh'),'utf8');for(const marker of ['read -r -s -p','</dev/tty',"printf '%s\\n%s\\n' \"$rpc_a\" \"$rpc_b\" |","rpc-sources-pending","prepare-mainnet-preflight-rpc-catalog.mjs"])assert.match(script,new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));assert.doesNotMatch(script,/export rpc_[ab]|install-onekey-pilot-rpc-sources\.mjs[^\n]*\$rpc_[ab]/);const dir=await mkdtemp('/dev/shm/usdom-rpc-status2358-');try{const mocked=path.join(dir,'prepare.sh');await writeFile(mocked,script.replace(/system_dependencies_ready\(\)\{[^\n]+\}/,'system_dependencies_ready(){ true; }').replace(/toolchain_ready\(\)\{[^\n]+\}/,'toolchain_ready(){ true; }'),{mode:0o700});await chmod(mocked,0o700);const run=spawnSync('bash',[mocked,'--status'],{cwd:'/tmp',encoding:'utf8',env:{PATH:'/usr/bin:/bin',HOME:'/tmp',USER:process.env.USER,LOGNAME:process.env.LOGNAME,USDOM_PILOT_STATE_DIR:dir}});assert.equal(run.status,0,run.stderr);assert.equal(run.stdout.trim(),'rpc-sources-pending');}finally{await rm(dir,{recursive:true,force:true});}});

test('advance installs and reuses the RPC catalog through the private file environment contract',async()=>{
  const base=await mkdtemp('/dev/shm/usdom-rpc-advance2358-');
  try{
    const project=path.join(base,'project'),state=path.join(base,'state');
    const scripts=path.join(project,'scripts'),config=path.join(project,'config');
    for(const directory of [project,state,scripts,config])await mkdir(directory,{mode:0o700});
    const original=await readFile(path.join(root,'scripts/prepare-onekey-ios-safe-mainnet-pilot.sh'),'utf8');
    // Isolate prerequisite checks; exercise the actual catalog preparation and installation commands.
    const isolated=original
      .replace(/^project=.*$/m,`project=${project}`)
      .replace(/^node_bin=.*$/m,`node_bin=${process.execPath}`)
      .replace(/^solc=.*$/m,`solc=${process.execPath}`)
      .replace(/system_dependencies_ready\(\)\{[^\n]+\}/,'system_dependencies_ready(){ true; }')
      .replace(/toolchain_ready\(\)\{[^\n]+\}/,'toolchain_ready(){ true; }')
      .replace(/^"\$node_bin" scripts\/check-(?:onekey-production-boundary|onekey-production-readiness-dag|walletconnect-sign-client-dependency)\.mjs >\/dev\/null$/gm,':');
    const entrypoint=path.join(scripts,'prepare-onekey-ios-safe-mainnet-pilot.sh');
    await writeFile(entrypoint,isolated,{mode:0o700});
    await writeFile(path.join(scripts,'write-mainnet-preflight-rpc-catalog.sh'),
      await readFile(path.join(root,'scripts/write-mainnet-preflight-rpc-catalog.sh')),{mode:0o700});
    for(const script of ['prepare-mainnet-preflight-rpc-catalog.mjs',
      'install-public-file-create-once-stdin.mjs','request-reown-project-id.mjs']){
      await symlink(path.join(root,'scripts',script),path.join(scripts,script));
    }
    const sources=await validateOneKeyPilotRpcSources(
      ['https://rpc-a.example.invalid/','https://rpc-b.example.invalid/'],
      {fetchImpl:async()=>new Response(JSON.stringify({jsonrpc:'2.0',id:1,result:'0x1'}),{status:200})});
    const sourcePath=path.join(state,'mainnet-preflight-rpc-sources.json');
    const sourceBytes=JSON.stringify(sources,null,2)+'\n';
    await writeFile(sourcePath,sourceBytes,{mode:0o600});
    const catalogPath=path.join(config,'mainnet-preflight-rpc-catalog.json');
    let installedBytes,installedMetadata,requestBytes;
    for(let attempt=0;attempt<2;attempt++){
      const run=spawnSync('/usr/bin/bash',[entrypoint,'--advance'],{
        cwd:'/',encoding:'utf8',timeout:15000,
        env:{PATH:'/usr/bin:/bin',HOME:base,USDOM_PILOT_STATE_DIR:state,
          USDOM_RELAYER_STATE_DIR:path.join(base,'relayers')},
      });
      assert.equal(run.error,undefined);
      assert.equal(run.status,78,run.stderr);
      assert.equal(run.stdout,'');
      assert.equal(run.stderr,`AWAITING_PUBLIC_PROJECT_ID: save only the validated public response at ${state}/reown-project-response.json\n`);
      const catalogBytes=await readFile(catalogPath,'utf8'),metadata=await stat(catalogPath);
      assert.deepEqual(JSON.parse(catalogBytes),buildMainnetPreflightRpcCatalog(sources));
      assert.equal(metadata.mode&0o777,0o644);
      assert.equal(metadata.nlink,1);
      assert.equal(await readFile(sourcePath,'utf8'),sourceBytes);
      const currentRequest=await readFile(path.join(state,'reown-project-request.json'),'utf8');
      if(attempt===0){installedBytes=catalogBytes;installedMetadata=metadata;requestBytes=currentRequest;}
      else{
        assert.equal(catalogBytes,installedBytes);
        assert.equal(metadata.ino,installedMetadata.ino);
        assert.equal(metadata.mtimeMs,installedMetadata.mtimeMs);
        assert.equal(currentRequest,requestBytes);
      }
      await assert.rejects(()=>stat(path.join(state,'mainnet-preflight-rpc-catalog.candidate.json')),{code:'ENOENT'});
    }
  }finally{await rm(base,{recursive:true,force:true});}
});

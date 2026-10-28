import assert from 'node:assert/strict';
import {chmodSync,existsSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const node='/home/leonardov/.local/toolchains/node-v24.19.0-linux-x64/bin/node';
const run=(command,args,options={})=>spawnSync(command,args,{cwd:root,encoding:'utf8',...options});
const planResult=run(node,['scripts/write-open-claims-execution-plan.mjs']);
assert.equal(planResult.status,0,planResult.stderr);
const plan=JSON.parse(planResult.stdout),pkg=JSON.parse(readFileSync(path.join(root,'package.json')));

test('all generated plan commands and direct executables resolve offline',()=>{
  const generator=readFileSync(path.join(root,'scripts/generate-closed-mainnet-phase-command.sh'),'utf8');
  for(const phase of plan.phaseOrder) {
    assert.match(generator,new RegExp(`\\n  ${phase.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}(?:\\)|\\n)`),`usage/case omits ${phase}`);
    const generated=run('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',phase]);
    assert.equal(generated.status,0,generated.stderr);
    assert.equal(run('/usr/bin/bash',['-n'],{input:generated.stdout}).status,0,phase);
    for(const match of generated.stdout.matchAll(/(?:^|[;|]\s*|\s)(node|bash|python3)\s+(scripts\/[A-Za-z0-9._/-]+)/gm)) {
      assert.ok(existsSync(path.join(root,match[2])),`${phase}: missing ${match[2]}`);
    }
    for(const match of generated.stdout.matchAll(/npm run --silent ([a-z0-9:_-]+)/g)) {
      const command=pkg.scripts[match[1]];
      assert.equal(typeof command,'string',`${phase}: missing npm command ${match[1]}`);
      for(const target of command.matchAll(/(?:^|&&\s*|;\s*)(?:bash|node|python3)\s+(scripts\/[A-Za-z0-9._/-]+)/g)) {
        assert.ok(existsSync(path.join(root,target[1])),`${match[1]}: missing ${target[1]}`);
      }
    }
    assert.doesNotMatch(generated.stdout,/YOUR_|CHANGE_ME|PLACEHOLDER|REPLACE_ME|\bTODO\b|\bTBD\b/);
  }
});

test('runtime secret-file names line up with every generated collector',()=>{
  const checkpoint=run('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh','produce-checkpoint-evidence-secret']).stdout;
  for(const variable of ['USDOM_CHECKPOINT_RATIFICATION_RPC_SOURCES_FILE','USDOM_CHECKPOINT_FINALIZED_RPC_SOURCES_FILE']) {
    assert.match(checkpoint,new RegExp(`export ${variable}=`));
  }
  const witness=readFileSync(path.join(root,'scripts/collect-authenticated-checkpoint-witness-source.sh'),'utf8');
  const consumer=readFileSync(path.join(root,'scripts/collect-authenticated-checkpoint-witness-source.mjs'),'utf8');
  assert.match(witness,/export USDOM_CHECKPOINT_WITNESS_RPC_SOURCES_FILE=/);
  assert.match(consumer,/readRuntimeSecretJsonFile\('USDOM_CHECKPOINT_WITNESS_RPC_SOURCES'/);
});

test('execution RPC projection is reproducible and rejects source drift',()=>{
  const directory=mkdtempSync(path.join(os.tmpdir(),'usdom-runtime-inputs-'));
  try {
    chmodSync(directory,0o700);
    const input=path.join(directory,'input.json'),output=path.join(directory,'output.json');
    const sources=[
      {operatorId:'alpha',providerId:'a',infrastructureId:'ia',url:'https://a.example/',tlsPolicy:'x'},
      {operatorId:'beta',providerId:'b',infrastructureId:'ib',url:'https://b.example/',tlsPolicy:'x'},
    ];
    writeFileSync(input,`${JSON.stringify(sources)}\n`,{mode:0o600});
    const args=['scripts/materialize-checkpoint-runtime-rpc-sources.mjs',input,output];
    assert.equal(run(node,args).status,0);
    const first=readFileSync(output,'utf8');
    assert.deepEqual(JSON.parse(first),sources.map(({operatorId,url})=>({operatorId,url})));
    assert.equal(run(node,args).status,0,'equal rerun must be idempotent');
    sources[0].url='https://changed.example/'; writeFileSync(input,`${JSON.stringify(sources)}\n`);
    assert.notEqual(run(node,args).status,0,'published runtime inputs must reject drift');
    assert.equal(readFileSync(output,'utf8'),first);
  } finally { rmSync(directory,{recursive:true,force:true}); }
});

test('all 33 routes have an executable producer and later validator',()=>{
  assert.equal(plan.entries.length,33);
  const implemented=plan.entries.filter(row=>row.implementationStatus==='external-operation');
  assert.equal(implemented.length,33);
  for(const row of implemented) {
    assert.ok(row.evidenceProducerCommands.length,`${row.claim}: producer missing`);
    assert.ok(row.independentValidatorCommands.length,`${row.claim}: validator missing`);
    assert.equal(row.readinessConsumer,'readinessRequirementKeys(real-funds)');
    const phase=run('/usr/bin/bash',['scripts/generate-closed-mainnet-phase-command.sh',row.phase])
      .stdout.replace(/[ \t]*\\\n\s*/g,' ');
    const producer=Math.max(...row.evidenceProducerCommands.map(value=>phase.indexOf(value)));
    const validator=Math.min(...row.independentValidatorCommands.map(value=>phase.indexOf(value)));
    assert.ok(producer>=0&&validator>producer,`${row.claim}: route is not executable in order`);
  }
  assert.deepEqual(plan.entries.filter(row=>row.implementationStatus!=='external-operation'),[]);
  assert.equal(run(node,['scripts/check-open-claims-execution-plan.mjs']).status,0);
});

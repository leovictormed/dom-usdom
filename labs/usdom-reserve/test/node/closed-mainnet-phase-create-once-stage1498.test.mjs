import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';

const root=new URL('../..',import.meta.url);
const generator=new URL('../../scripts/generate-closed-mainnet-phase-command.sh',import.meta.url);
const planResult=spawnSync(process.execPath,['scripts/write-open-claims-execution-plan.mjs'],{
  cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},maxBuffer:16*1024*1024,
});
assert.equal(planResult.status,0,planResult.stderr);
const phases=JSON.parse(planResult.stdout).phaseOrder;

test('all non-enrollment pilot phases publish persistent files through create-once helpers',async()=>{
  assert.equal(phases.length,23);
  for(const phase of phases) {
    const generated=spawnSync('/usr/bin/bash',[generator.pathname,phase],{
      cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
    });
    assert.equal(generated.status,0,`${phase}: ${generated.stderr}`);
    assert.equal(spawnSync('/usr/bin/bash',['-n'],{input:generated.stdout,encoding:'utf8'}).status,0,phase);
    if(phase==='enroll-safe-owners-secret') continue;
    assert.doesNotMatch(generated.stdout,/\bcp\s+[^\n]*(?:--no-clobber|\s-n(?:\s|$))/,
      `${phase} uses a check-then-copy publication`);
    assert.doesNotMatch(generated.stdout,/(?:>|>>)\s*"?\$USDOM_[A-Z0-9_]+"?/,
      `${phase} redirects directly into a persistent USDOM destination`);
    assert.doesNotMatch(generated.stdout,/\bchmod\s+[0-7]+\s+"?\$USDOM_[A-Z0-9_]+"?/,
      `${phase} repairs persistent permissions after publication`);
  }
  const installer=await readFile(new URL('../../scripts/install-private-file-new-stdin.mjs',import.meta.url),'utf8');
  const durable=await readFile(new URL('../../sdk/durable-private-file.mjs',import.meta.url),'utf8');
  assert.match(installer,/writePrivateFileDurableNew\(target,bytes/);
  assert.match(durable,/writePrivateFileDurableNew[\s\S]*replace:false,privateParent:true/);
});

test('common phase prefix creates the evidence path without following or chmod-repairing it',()=>{
  for(const phase of phases) {
    const generated=spawnSync('/usr/bin/bash',[generator.pathname,phase],{
      cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},
    });
    assert.equal(generated.status,0,phase);
    assert.match(generated.stdout,
      /python3 scripts\/ensure-private-directory-path\.py "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"/);
    assert.doesNotMatch(generated.stdout,
      /install -d -m 0700 "\$USDOM_CONTROL_EVIDENCE_DIRECTORY"/);
  }
});

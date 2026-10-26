import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const launchers=['run-secret-node-entrypoint.sh','observe-authenticated-checkpoint.sh'];

test('credential-bearing Node launchers are count-pinned and exec absolute identity',async()=>{
  for(const name of launchers) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    assert.match(source,/NODE_BIN=\$\(realpath "\$\(command -v node\)"\)/);
    assert.match(source,/node_identity=\$\(stat[\s\S]*node_sha256=\$\(sha256sum/);
    assert.match(source,/ENV_BIN=\$\(realpath "\$\(command -v env\)"\)/);
    assert.match(source,/exec "\$ENV_BIN" -i[\s\S]*"\$NODE_BIN" /);
    assert.doesNotMatch(source,/exec node\s/);
  }
});

test('no shell script retains a PATH-resolved Node exec',async()=>{
  const directory=path.join(component,'scripts');
  const names=(await readdir(directory)).filter(name=>name.endsWith('.sh'));
  const offenders=[];
  for(const name of names) {
    const source=await readFile(path.join(directory,name),'utf8');
    if(/(?:^|\n)exec node\s/.test(source)) offenders.push(name);
  }
  assert.deepEqual(offenders,[]);
});

test('launcher inventory rejects a PATH exec regression',async()=>{
  const source=await readFile(path.join(component,'scripts/observe-authenticated-checkpoint.sh'),'utf8');
  assert.match(source,/exec "\$ENV_BIN" -i[\s\S]*"\$NODE_BIN"/);
  assert.match(`${source}\nexec node malicious.mjs\n`,/(?:^|\n)exec node\s/);
});

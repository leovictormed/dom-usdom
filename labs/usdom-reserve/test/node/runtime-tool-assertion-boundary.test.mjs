import assert from 'node:assert/strict';
import {readdirSync,readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(import.meta.dirname,'../..');

test('every local runtime-tool assertion fails immediately on an intermediate mismatch',()=>{
  const scripts=path.join(root,'scripts');
  const covered=[];
  for(const name of readdirSync(scripts).filter(name=>name.endsWith('.sh'))) {
    const source=readFileSync(path.join(scripts,name),'utf8');
    const body=source.match(/assert_tool_unchanged\(\) \{([\s\S]*?)\n\}/)?.[1];
    if(!body) continue;
    covered.push(name);
    const checks=body.split('\n').filter(line=>/^\s*\[\[/.test(line));
    assert.ok(body.includes('sha256')&&checks.some(line=>/sha256|observed_sha|\$sha/.test(line)),`${name}: hash check`);
    for(const line of checks) assert.match(line,/\|\| return 1\s*$/,`${name}: ${line.trim()}`);
    for(const line of body.split('\n').filter(line=>/^\s*read -r observed_sha /.test(line)))
      assert.match(line,/\|\| return 1\s*$/,`${name}: hash reader`);
  }
  assert.equal(covered.length,24);
});

test('shared runtime helper normalizes hyphenated tool names and fails hash mismatch immediately',()=>{
  const source=readFileSync(path.join(root,'scripts/pinned-shell-tool-functions.sh'),'utf8');
  assert.match(source,/variable_name=\$\{name\/\/-\/_\}/);
  assert.match(source,/sha256sum[\s\S]*\|\| return 1/);
});

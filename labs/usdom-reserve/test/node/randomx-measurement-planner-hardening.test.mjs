import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL(
  '../../scripts/plan-randomx-measurement.mjs',import.meta.url),'utf8');

test('RandomX measurement planner strictly parses and rechecks every accepted input',()=>{
  assert.match(source,/parseStrictJson\(reportText/);
  assert.doesNotMatch(source,/JSON\.parse\(reportText\)/);
  assert.match(source,/const inputSnapshots=new Map\(\)/);
  assert.match(source,/for\(const \[file,expected\] of inputSnapshots\)/);
  assert.match(source,/exact:expected\.length,record:false/);
  assert.match(source,/current\.equals\(expected\)/);
  assert.match(source,/authenticated_input_changed/);
  assert.ok(source.indexOf('authenticated_input_changed')<source.indexOf('const report='));
});

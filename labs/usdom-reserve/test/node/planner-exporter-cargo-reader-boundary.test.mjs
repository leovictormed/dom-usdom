import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const scripts=['plan-authenticated-randomx-aggregate-set.sh','export-dom-preactivation-anchor.sh'];
test('planner/exporter pin bounded Cargo and canonical parent immediately before handoff',()=>{
 for(const name of scripts){
  const target=path.join(root,'scripts',name),syntax=spawnSync('bash',['-n',target],{encoding:'utf8'});
  assert.equal(syntax.status,0,syntax.stderr); const source=readFileSync(target,'utf8');
  assert.match(source,/cargo_size=\$\(stat -Lc '%s' "\$cargo_bin"\); \(\( cargo_size > 0 && cargo_size <= 512 \* 1024 \* 1024 \)\)/,name);
  assert.match(source,/cargo_directory_identity=\$\(stat -Lc '%d:%i:%u:%a'/,name);
  assert.match(source,/\[\[ \$\(realpath "\$cargo_directory"\) == "\$cargo_directory" \]\]/,name);
  assert.match(source,/assert_cargo_unchanged\n(?:exec )?"\$cargo_bin" run/,name);
  const boundary=source.slice(source.indexOf('assert_cargo_unchanged()'),source.indexOf('pin_cargo\n'));
  assert.match(boundary,/sha256sum "\$cargo_bin"/,name);
 }
});

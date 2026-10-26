import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const scripts=[
  'prove-authenticated-randomx-receipt-set.sh',
  'prove-authenticated-randomx-aggregate-set.sh',
  'prove-authenticated-economic-receipt-set.sh',
  'prove-authenticated-checkpoint-segment-set.sh',
  'prove-authenticated-checkpoint-outer.sh',
  'prove-authenticated-finalized-burn.sh',
];

test('all authenticated prover shell tool readers bind canonical parent and bounded executable',()=>{
  for(const name of scripts) {
    const target=path.join(root,'scripts',name);
    const syntax=spawnSync('bash',['-n',target],{encoding:'utf8'});
    assert.equal(syntax.status,0,`${name}: ${syntax.stderr}`);
    const source=readFileSync(target,'utf8');
    assert.match(source,/size=\$\(stat -Lc '%s' "\$path"\); \(\( size > 0 && size <= 512 \* 1024 \* 1024 \)\)/,name);
    assert.match(source,/\[\[ \$\(realpath "\$directory"\) == "\$directory" \]\]/,name);
    assert.match(source,/\$\{name\}_directory_identity/,name);
    assert.match(source,/stat -Lc '%d:%i:%u:%a' "\$directory"/,name);
    assert.match(source,/\$\{!directory_identity_name\}/,name);
    const hashAt=source.indexOf('printf -v "${name}_sha256"');
    assert.ok(hashAt>=0,name);
    assert.ok(source.indexOf("stat -Lc '%d:%i:%s:%Y:%Z' \"$path\"",hashAt)>hashAt,
      `${name}: file identity must be rechecked after hashing`);
    const assertAt=source.indexOf('assert_tool_unchanged()');
    const hashRecheck=source.indexOf('sha256sum "$path"',assertAt);
    assert.ok(source.indexOf("stat -Lc '%d:%i:%s:%Y:%Z' \"$path\"",hashRecheck)>hashRecheck,
      `${name}: file identity must be rechecked after the final hash`);
  }
});

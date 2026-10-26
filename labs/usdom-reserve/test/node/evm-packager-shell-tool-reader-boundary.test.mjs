import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const scripts=[
  'package-authenticated-checkpoint-outer-evm-proof.sh',
  'package-authenticated-finalized-burn-evm-proof.sh',
];

test('EVM proof packagers bind canonical parent and bounded tool executables',()=>{
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
    const initialHash=source.indexOf('printf -v "${name}_sha256"');
    assert.ok(source.indexOf("stat -Lc '%d:%i:%s:%Y:%Z' \"$path\"",initialHash)>initialHash,name);
    const finalBoundary=source.indexOf('assert_tool_unchanged()');
    const finalHash=source.indexOf('sha256sum "$path"',finalBoundary);
    assert.ok(source.indexOf("stat -Lc '%d:%i:%s:%Y:%Z' \"$path\"",finalHash)>finalHash,name);
  }
});

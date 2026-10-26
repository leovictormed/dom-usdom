import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
test('TPM bootstrap pins bounded Node and canonical parent for reads and cleanup',()=>{
 const target=path.join(root,'scripts/bootstrap-closed-mainnet-tpm-authority.sh');
 const syntax=spawnSync('bash',['-n',target],{encoding:'utf8'}); assert.equal(syntax.status,0,syntax.stderr);
 const source=readFileSync(target,'utf8');
 assert.match(source,/node_size=\$\(stat -Lc '%s' "\$NODE_BIN"\); \(\( node_size > 0 && node_size <= 512 \* 1024 \* 1024 \)\)/);
 assert.match(source,/node_directory_identity=\$\(stat -Lc '%d:%i:%u:%a'/);
 assert.match(source,/test "\$\(realpath "\$node_directory"\)" = "\$node_directory"/);
 const fn=source.slice(source.indexOf('assert_node_unchanged()'),source.indexOf('TPM_TOOLS='));
 assert.match(fn,/sha256sum "\$NODE_BIN"/); assert.match(fn,/node_directory_identity/);
 assert.match(source,/assert_node_unchanged &&\n\s+"\$NODE_BIN" -e/);
});

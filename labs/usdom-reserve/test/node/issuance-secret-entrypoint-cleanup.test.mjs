import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

test('token-bearing issuance launcher execs only pinned Node',async()=>{
  const source=await readFile(path.join(component,'scripts/run-secret-node-entrypoint.sh'),'utf8');
  assert.match(source,/NODE_BIN=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/node_identity=\$\(stat[\s\S]*node_sha256=\$\(sha256sum/);
  assert.match(source,/test "\$\(stat[\s\S]*"\$NODE_BIN"\)" = "\$node_identity"[\s\S]*test "\$\(sha256sum "\$NODE_BIN"/);
  assert.match(source,/exec "\$ENV_BIN" -i HOME="\$HOME" USDOM_SECRET_NODE_LAUNCHER=1[\s\S]*"\$NODE_BIN" "scripts\/\$entrypoint"/);
  assert.doesNotMatch(source,/exec node\s|(?:^|\n)node\s+"scripts\//);
  assert.doesNotMatch(source,/mktemp|trap\s|(?:^|\s)&\s*$/m);
});

test('issuance process zeroes every retained secret Buffer on all exits',async()=>{
  const source=await readFile(path.join(component,'scripts/submit-finalized-deposit-issuance.mjs'),'utf8');
  assert.match(source,/const secretBuffers=\[\];[\s\S]*try \{/);
  assert.equal((source.match(/secretBuffers\.push\(/g)??[]).length,3);
  assert.match(source,/finally \{\s*for\(const bytes of secretBuffers\) bytes\.fill\(0\);\s*\}/);
  assert.doesNotMatch(source,/mkdtemp|mkstemp|writeFile\([^)]*(?:token|witness)/);
});

test('launcher inventory rejects PATH Node execution',async()=>{
  const source=await readFile(path.join(component,'scripts/run-secret-node-entrypoint.sh'),'utf8');
  const audit=value=>assert.doesNotMatch(value,/exec node\s|(?:^|\n)node\s+"scripts\//);
  assert.doesNotThrow(()=>audit(source));
  assert.throws(()=>audit(`${source}\nexec node "scripts/$entrypoint"\n`));
});

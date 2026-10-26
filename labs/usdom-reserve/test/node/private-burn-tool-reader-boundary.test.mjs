import assert from 'node:assert/strict'; import {readFileSync} from 'node:fs'; import {spawnSync} from 'node:child_process'; import path from 'node:path'; import test from 'node:test'; import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
test('private burn tools bind bounded executables and canonical parents',()=>{
 for(const [name,tools] of [['prepare-closed-mainnet-private-burn.sh',['cargo']],['submit-closed-mainnet-private-burn.sh',['node','cargo']]]){
  const target=path.join(root,'scripts',name),syntax=spawnSync('bash',['-n',target],{encoding:'utf8'}); assert.equal(syntax.status,0,syntax.stderr); const source=readFileSync(target,'utf8');
  for(const tool of tools){ const upper=tool.toUpperCase()+'_BIN'; assert.match(source,new RegExp(`${tool}_size=\\$\\(stat -Lc '%s' "\\$${upper}"\\); \\(\\( ${tool}_size > 0 && ${tool}_size <= 512 \\* 1024 \\* 1024 \\)\\)`)); assert.match(source,new RegExp(`${tool}_directory_identity=\\$\\(stat -Lc '%d:%i:%u:%a'`)); const fn=source.slice(source.indexOf(`assert_${tool}_unchanged()`)); assert.match(fn,new RegExp(`sha256sum "\\$${upper}"`)); assert.match(fn,new RegExp(`${tool}_directory_identity`)); }
 }
 const submit=readFileSync(path.join(root,'scripts/submit-closed-mainnet-private-burn.sh'),'utf8'); assert.match(submit,/assert_node_unchanged &&\n\s+"\$NODE_BIN" -e/);
});

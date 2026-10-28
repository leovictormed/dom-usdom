import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

for(const [writer,collector,target] of [
 ['write-checkpoint-bootstrap-ratification-observation.sh','collect-checkpoint-bootstrap-ratification-observation.mjs','ratification-observation.json'],
 ['write-checkpoint-finalized-event-observation.sh','collect-checkpoint-finalized-event-observation.mjs','checkpoint-finalized-event-observation.json'],
]) test(`${writer} invalidates derived observation before collector RPC`,async()=>{
 const source=await readFile(new URL(`../../scripts/${writer}`,import.meta.url),'utf8');
 const targetAt=source.indexOf(`TARGET="$BASE/raw/${target}"`);
 const removal=source.indexOf('remove-private-file-durable.mjs" "$TARGET"',targetAt);
 const collect=source.indexOf(collector,removal);
 const install=source.indexOf('install-private-file-immutable-stdin.mjs" "$TARGET"',collect);
 assert.ok(targetAt>=0&&removal>targetAt&&collect>removal&&install>collect);
 assert.doesNotMatch(source,/observation already exists/);
 assert.match(source,/TEMPORARY_IDENTITY=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$TEMPORARY"\)/);
 assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$TEMPORARY" 2>\/dev\/null\) == "\$TEMPORARY_IDENTITY"/);
});

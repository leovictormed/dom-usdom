import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

for(const [name,pointer,prepare] of [
 ['write-checkpoint-bootstrap-ratification-report.sh','.checkpointBootstrapRatificationReport=null','prepare-checkpoint-bootstrap-ratification-report.mjs'],
 ['write-checkpoint-finalized-event-report.sh','.checkpointFinalizedEventReport=null','prepare-checkpoint-finalized-event-report.mjs'],
]) test(`${name} publishes completion pointer last across retry`,async()=>{
 const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
 const installToken='replace-locked-source-stdin.mjs';
 const clear=source.indexOf(pointer),clearInstall=source.indexOf(installToken,clear);
 const remove=source.indexOf('remove-private-file-durable.mjs',clearInstall);
 const build=source.indexOf(prepare,remove);
 const report=source.indexOf('install-private-file-immutable-stdin.mjs',build);
 const complete=source.indexOf(installToken,report);
 assert.ok(clear>=0&&clearInstall>clear&&remove>clearInstall&&build>remove&&report>build&&complete>report);
 assert.match(source,/pin_runtime_tool python3/);
 assert.equal((source.match(/replace-locked-source-stdin\.mjs/g)??[]).length,2);
 assert.match(source,/metadata_sha256=\$candidate_sha256/);
 assert.match(source,/INVALIDATION_IDENTITY=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$INVALIDATION"\)/);
 assert.match(source,/TEMPORARY_IDENTITY=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$TEMPORARY"\)/);
 assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$TEMPORARY" 2>\/dev\/null\) == "\$TEMPORARY_IDENTITY"/);
 assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$INVALIDATION" 2>\/dev\/null\) == "\$INVALIDATION_IDENTITY"/);
});

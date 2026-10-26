import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

for(const [name,pointer,prepare] of [
 ['write-checkpoint-bootstrap-ratification-report.sh','.checkpointBootstrapRatificationReport=null','prepare-checkpoint-bootstrap-ratification-report.mjs'],
 ['write-checkpoint-finalized-event-report.sh','.checkpointFinalizedEventReport=null','prepare-checkpoint-finalized-event-report.mjs'],
]) test(`${name} publishes completion pointer last across retry`,async()=>{
 const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
 const clear=source.indexOf(pointer),clearInstall=source.indexOf('install-release-config-stdin.mjs',clear);
 const remove=source.indexOf('remove-private-file-durable.mjs',clearInstall);
 const build=source.indexOf(prepare,remove);
 const report=source.indexOf('install-private-file-immutable-stdin.mjs',build);
 const complete=source.indexOf('install-release-config-stdin.mjs',report);
 assert.ok(clear>=0&&clearInstall>clear&&remove>clearInstall&&build>remove&&report>build&&complete>report);
});

import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL('../../scripts/write-security-validation-report.sh',import.meta.url),'utf8');

test('security report clears metadata pointer before removing stale report and rebuilding',()=>{
 const lock=source.indexOf('Another security-validation writer holds the output lock');
 const clear=source.indexOf("jq '.securityValidationReport=null'",lock);
 const installClear=source.indexOf('replace-locked-source-stdin.mjs',clear);
 const remove=source.indexOf('remove-private-file-durable.mjs',installClear);
 const prepare=source.indexOf('prepare-security-validation-report.mjs',remove);
 const installReport=source.indexOf('install-private-file-immutable-stdin.mjs',prepare);
 const installMetadata=source.indexOf('replace-locked-source-stdin.mjs',installReport);
 assert.ok(lock>=0&&clear>lock&&installClear>clear&&remove>installClear&&prepare>remove
   &&installReport>prepare&&installMetadata>installReport);
 assert.equal((source.match(/replace-locked-source-stdin\.mjs/g)??[]).length,2);
 assert.match(source,/metadata_sha256=\$candidate_sha256/);
 assert.match(source,/pin_runtime_tool python3/);
 assert.match(source,/invalidation_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$invalidation"\)/);
 assert.match(source,/temporary_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary"\)/);
 assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
 assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$invalidation" 2>\/dev\/null\) == "\$invalidation_identity"/);
});

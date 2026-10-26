import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL('../../scripts/write-security-validation-report.sh',import.meta.url),'utf8');

test('security report clears metadata pointer before removing stale report and rebuilding',()=>{
 const lock=source.indexOf('Another security-validation writer holds the output lock');
 const clear=source.indexOf("jq '.securityValidationReport=null'",lock);
 const installClear=source.indexOf('install-release-config-stdin.mjs',clear);
 const remove=source.indexOf('remove-private-file-durable.mjs',installClear);
 const prepare=source.indexOf('prepare-security-validation-report.mjs',remove);
 const installReport=source.indexOf('install-private-file-immutable-stdin.mjs',prepare);
 const installMetadata=source.indexOf('install-release-config-stdin.mjs',installReport);
 assert.ok(lock>=0&&clear>lock&&installClear>clear&&remove>installClear&&prepare>remove
   &&installReport>prepare&&installMetadata>installReport);
});

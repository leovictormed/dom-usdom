import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const source=await readFile(new URL('../../scripts/write-recoverable-safe-release-evidence.sh',import.meta.url),'utf8');
test('Safe release evidence invalidates completion marker before derived set and republishes it last',()=>{
 const lock=source.indexOf('Another Safe release-evidence writer holds the output lock');
 const invalidation=source.indexOf('for derived in release-evidence-fragment.json',lock);
 const build=source.indexOf('prepare-recoverable-safe-release-evidence.mjs',invalidation);
 const firstSupport=source.indexOf('publish_and_verify_immutable "$temporary/$file"',build);
 const completion=source.indexOf('publish_and_verify_immutable "$fragment"',firstSupport);
 assert.ok(lock>=0&&invalidation>lock&&build>invalidation&&firstSupport>build&&completion>firstSupport);
 const block=source.slice(invalidation,source.indexOf('\ndone',invalidation)+5);
 for(const name of ['release-evidence-fragment.json','governance-configuration.json',
  'guardian-configuration.json','checkpoint-guardian-configuration.json',
  'control-plane-separation.json','control-plane-recovery-drill.json',
  'safe-control-release-evidence-bundle.json']) assert.ok(block.includes(name));
 assert.doesNotMatch(block,/\$package_source|\$baseline_source|\$recovery_source/);
 assert.match(source,/temporary_identity=\$\(\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary"\)/);
 assert.match(source,/\/usr\/bin\/stat -c '%u:%d:%i:%a' -- "\$temporary" 2>\/dev\/null\) == "\$temporary_identity"/);
});

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const names=[
  'write-operations-review-report.sh',
  'write-verifier-reproducible-build-report.sh',
  'write-checkpoint-verifier-reproducible-build-report.sh',
  'write-checkpoint-registry-reproducible-build-report.sh',
  'write-reserve-reproducible-build-report.sh',
  'write-security-validation-report.sh',
];

test('all report writer Node children share the finite lifecycle policy',()=>{
  let bounded=0;
  for(const name of names){
    const script=fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));
    assert.equal(spawnSync('bash',['-n',script]).status,0,name);
    const source=readFileSync(script,'utf8');
    assert.doesNotMatch(source,/^\s*node\s/m,name);
    const sites=source.match(/^\s*(?:assert_runtime_tool node; assert_runtime_tool timeout; )?"?\$?timeout(?:_bin)?"? --signal=TERM --kill-after=2s 120s "?\$?node(?:_bin)?"?\s/gm)??[];
    assert.equal(sites.length,10,name);
    bounded+=sites.length;
  }
  assert.equal(bounded,60);
});

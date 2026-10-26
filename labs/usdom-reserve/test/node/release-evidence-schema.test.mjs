import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {parseStrictJson} from '../../sdk/strict-json.mjs';
import {isExactReleaseEvidenceShape,RELEASE_EVIDENCE_KEYS} from '../../sdk/release-evidence-schema.mjs';

test('release evidence schema is shared exactly by gate and materializers',async()=>{
  const path=new URL('../../config/mainnet-release-evidence.unconfigured.json',import.meta.url);
  const evidence=parseStrictJson(await readFile(path,'utf8'),{label:'release evidence template'});
  assert.equal(isExactReleaseEvidenceShape(evidence),true);
  assert.deepEqual(Object.keys(evidence).sort(),[...RELEASE_EVIDENCE_KEYS].sort());
  assert.equal(isExactReleaseEvidenceShape({...evidence,unexpected:null}),false);
  const missing={...evidence}; delete missing.releaseId;
  assert.equal(isExactReleaseEvidenceShape(missing),false);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {collectReleaseEvidenceDocumentPaths} from '../../sdk/release-evidence-document-paths.mjs';

const hash=value=>value.repeat(64);

test('release evidence paths are canonical, exact, unique and selectively skipped',()=>{
  const evidence={
    current:{path:'evidence/current.json',sha256:hash('a')},
    nested:{items:[null,{path:'evidence/nested.json',sha256:hash('b')}]},
  };
  assert.deepEqual([...collectReleaseEvidenceDocumentPaths(evidence)],
    ['evidence/current.json','evidence/nested.json']);
  assert.deepEqual([...collectReleaseEvidenceDocumentPaths(evidence,{skipTopLevelKey:'current'})],
    ['evidence/nested.json']);
});

test('release evidence traversal rejects malformed, duplicate, deep and oversized structures',()=>{
  assert.throws(()=>collectReleaseEvidenceDocumentPaths({bad:{path:'evidence/x.json'}}),
    /malformed document/);
  assert.throws(()=>collectReleaseEvidenceDocumentPaths({bad:{
    path:'../outside.json',sha256:hash('a'),
  }}),/malformed document/);
  for(const path of ['config/production-requirements.json','out/arbitrary.json',
    'evidence/report\nforged.json','evidence/réport.json']) {
    assert.throws(()=>collectReleaseEvidenceDocumentPaths({bad:{path,sha256:hash('a')}}),
      /malformed document/);
  }
  assert.throws(()=>collectReleaseEvidenceDocumentPaths({
    first:{path:'evidence/x.json',sha256:hash('a')},
    second:{path:'evidence/x.json',sha256:hash('b')},
  }),/duplicate document paths/);
  const deep={}; let cursor=deep;
  for(let index=0;index<10;index++) cursor=cursor.next={};
  assert.throws(()=>collectReleaseEvidenceDocumentPaths(deep),/depth bound/);
  assert.throws(()=>collectReleaseEvidenceDocumentPaths({a:null,b:null},{maxNodes:2}),/node bound/);
});

test('the two RISC Zero adapters may share exactly one ceremony transcript',()=>{
  const transcript={path:'evidence/risc0-groth16-ceremony.txt',sha256:hash('c')};
  const evidence={
    trustedSetup:{required:true,transcript},
    checkpointTrustedSetup:{required:true,transcript:{...transcript}},
  };
  assert.deepEqual([...collectReleaseEvidenceDocumentPaths(evidence)],[transcript.path]);
  assert.throws(()=>collectReleaseEvidenceDocumentPaths({
    ...evidence,unexpected:{...transcript},
  }),/duplicate document paths/);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {SECURITY_VALIDATION_CHECKS,buildSecurityValidationReport,
  serializeSecurityValidationReport,validateSecurityValidationReport,
} from '../../sdk/security-validation-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const evidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.2.3'};
const toolGroup=id=>id==='production-solidity-lint'||id==='production-solidity-build'
 ||id==='solidity-regression'||id==='deep-solidity-regression'?'forge':id;
const results=SECURITY_VALIDATION_CHECKS.map(({id,command},index)=>({id,command,exitCode:0,
 stdoutSha256:sha(`stdout-${index}`),stderrSha256:sha(`stderr-${index}`),
 toolSha256:sha(`tool-${toolGroup(id)}`)}));
const context={releaseEvidence:evidence,requirementsSha256:sha('requirements'),
 sourceManifestSha256:sha('manifest')};

test('security validation report canonically binds all fixed release checks',()=>{
 const report=buildSecurityValidationReport({...context,results});
 assert.equal(report.status,'passed');
 assert.deepEqual(report.checks,results);
 assert.deepEqual(validateSecurityValidationReport(report,context),report);
 assert(serializeSecurityValidationReport(report).equals(
  serializeSecurityValidationReport(buildSecurityValidationReport({...context,results}))));
});

test('security validation report rejects failed, reordered, substituted and stale checks',()=>{
 const report=buildSecurityValidationReport({...context,results});
 const mutations=[
  value=>{value.checks[0].exitCode=1;},
  value=>{[value.checks[0],value.checks[1]]=[value.checks[1],value.checks[0]];},
  value=>{value.checks[0].command='true';},
  value=>{value.checks.pop();},
  value=>{value.requirementsSha256=sha('other');},
  value=>{value.sourceCommit='b'.repeat(40);},
  value=>{value.extra=true;},
 ];
 for(const mutate of mutations) {
  const changed=structuredClone(report); mutate(changed);
  assert.throws(()=>validateSecurityValidationReport(changed,context));
 }
});

test('security validation builder refuses incomplete provenance and fabricated results',()=>{
 for(const input of [
  {releaseEvidence:{...evidence,sourceCommit:null}},
  {requirementsSha256:'bad'},
  {sourceManifestSha256:'bad'},
  {results:results.slice(1)},
  {results:results.map((value,index)=>index?value:{...value,stdoutSha256:'bad'})},
  {results:results.map((value,index)=>index?value:{...value,toolSha256:'bad'})},
  {results:results.map((value,index)=>index?value:{...value,stdoutSha256:'0'.repeat(64)})},
  {results:results.map((value,index)=>index?value:{...value,stderrSha256:'0'.repeat(64)})},
  {results:results.map((value,index)=>index?value:{...value,toolSha256:'0'.repeat(64)})},
  {requirementsSha256:'0'.repeat(64)},
  {sourceManifestSha256:'0'.repeat(64)},
  {results:results.map(value=>value.id==='deep-solidity-regression'
   ?{...value,toolSha256:sha('other-forge')}:value)},
 ]) assert.throws(()=>buildSecurityValidationReport({...context,results,...input}));
});

test('security-validation JSON authority rejects duplicate escaped keys and invalid UTF-8',()=>{
 for(const bytes of [
  Buffer.from('{"schema":"a","\\u0073chema":"b"}\n'),
  Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
 ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'security validation',maxBytes:4*1024*1024,
  maxDepth:64}),/duplicate (?:object )?key|invalid UTF-8/);
});

test('materializer requires stable safely owned executables before and after execution',async()=>{
 const source=await (await import('node:fs/promises')).readFile(
  new URL('../../scripts/prepare-security-validation-report.mjs',import.meta.url),'utf8');
 assert.match(source,/snapshotValidationExecutable\(file\)/);
 assert.match(source,/snapshotExecutable\(file\)/);
 assert.match(source,/runPinnedExecutable\(tool,args/);
 assert.match(source,/maxBuffer:64\*1024\*1024,timeout:60\*60\*1000/);
 assert.doesNotMatch(source,/execFileAsync|execFile\(/);
 assert.match(source,/toolSha256:tool\.sha256/);
 assert.match(source,/execute\('final-source-manifest','python3 scripts\/source-manifest\.py'/);
 assert.match(source,/assertCleanEnvironment\(process\.env\)/);
 assert.match(source,/parseStrictJsonBytes\(releaseEvidenceBytes/);
 assert.doesNotMatch(source,/releaseEvidenceBytes\.toString\(['"]utf8['"]\)/);
 assert.match(source,/releaseEvidenceAfter\.equals\(releaseEvidenceBytes\)/);
 assert.match(source,/requirementsAfter\.equals\(requirementsBytes\)/);
 assert.match(source,/sourceManifestAfter\.equals\(sourceManifestBytes\)/);
 for(const name of ['LD_PRELOAD','NODE_OPTIONS','FOUNDRY_PROFILE','RUSTC_WRAPPER','PYTHONPATH',
  'GIT_CONFIG_GLOBAL','NPM_CONFIG_SCRIPT_SHELL']) assert.match(source,new RegExp(`'${name}'`));
});

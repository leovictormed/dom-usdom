import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {buildReserveReproducibleBuildReport,serializeReserveReproducibleBuildReport,
  sourceSetSha256,validateReserveReproducibleBuildReport,
} from '../../sdk/reserve-reproducible-build-report.mjs';
import {parseStrictJsonBytes} from '../../sdk/strict-json.mjs';
import {PRODUCTION_SOLC_LONG_VERSION,PRODUCTION_SOLC_SHA256}
  from '../../sdk/reproducible-build-environment.mjs';

const sha=value=>createHash('sha256').update(value).digest('hex');
const artifactSha=sha('artifact'),sourceSha=sha('sources');
const evidence={schema:1,releaseId:'release-1',sourceCommit:'a'.repeat(40),sourceTag:'usdom-v1.2.3',
 reserveArtifact:{path:'out/USDOMProofReserve.sol/USDOMProofReserve.json',sha256:artifactSha}};
const releaseConfig={ethereumChainId:'1',reserve:'0x'+'11'.repeat(20),
 reserveConfigHash:'0x'+'22'.repeat(32),reserveRuntimeCodeHash:'0x'+'33'.repeat(32),
 reserveInitcodeHash:'0x'+'44'.repeat(32)};
const observed=id=>({buildId:id,compilerExecutableSha256:PRODUCTION_SOLC_SHA256,
 compilerVersion:PRODUCTION_SOLC_LONG_VERSION,
 artifactSha256:artifactSha,sourceSetSha256:sourceSha,
 runtimeCodeHash:releaseConfig.reserveRuntimeCodeHash,initcodeHash:releaseConfig.reserveInitcodeHash});
const context={releaseEvidence:evidence,releaseConfig,observations:[
 observed('isolated-build-a'),observed('isolated-build-b')]};

test('reserve report requires two identical isolated release builds',()=>{
 const report=buildReserveReproducibleBuildReport(context);
 assert.equal(report.status,'reproduced');
 assert.deepEqual(validateReserveReproducibleBuildReport(report,context),report);
 assert(serializeReserveReproducibleBuildReport(report).equals(
  serializeReserveReproducibleBuildReport(buildReserveReproducibleBuildReport(context))));
});

test('reserve report rejects artifact, runtime, compiler, source and schema substitution',()=>{
 const report=buildReserveReproducibleBuildReport(context);
 const mutations=[
  value=>{value.observations[1].artifactSha256=sha('other');},
  value=>{value.observations[1].runtimeCodeHash='0x'+'55'.repeat(32);},
  value=>{value.observations[1].compilerVersion='0.8.36+commit.00000000';},
  value=>{for(const observation of value.observations) observation.compilerExecutableSha256=sha('other-solc');},
  value=>{value.observations[1].sourceSetSha256=sha('other');},
  value=>{value.command='forge build';},
  value=>{value.extra=true;},
 ];
 for(const mutate of mutations) {
  const changed=structuredClone(report); mutate(changed);
  assert.throws(()=>validateReserveReproducibleBuildReport(changed,context));
 }
});

test('reserve report rejects incomplete release and duplicate build identity',()=>{
 for(const input of [
  {releaseEvidence:{...evidence,sourceCommit:null}},
  {releaseEvidence:{...evidence,reserveArtifact:{...evidence.reserveArtifact,path:'out/wrong.json'}}},
  {releaseConfig:{...releaseConfig,ethereumChainId:'31337'}},
  {releaseConfig:{...releaseConfig,reserveRuntimeCodeHash:'0x'+'00'.repeat(32)}},
  {observations:[observed('isolated-build-a'),observed('isolated-build-a')]},
 ]) assert.throws(()=>buildReserveReproducibleBuildReport({...context,...input}));
});

test('reserve report rejects zero artifact and source-set SHA-256 placeholders',()=>{
 const zero='0'.repeat(64);
 const zeroArtifact=structuredClone(context);
 zeroArtifact.releaseEvidence.reserveArtifact.sha256=zero;
 for(const observation of zeroArtifact.observations) observation.artifactSha256=zero;
 assert.throws(()=>buildReserveReproducibleBuildReport(zeroArtifact),/nonzero/);
 const zeroSources=structuredClone(context);
 for(const observation of zeroSources.observations) observation.sourceSetSha256=zero;
 assert.throws(()=>buildReserveReproducibleBuildReport(zeroSources),/nonzero/);
});

test('source-set commitment is ordered and rejects missing compiler hashes',()=>{
 const first=sourceSetSha256({sources:{'b.sol':{keccak256:'0x'+'22'.repeat(32)},
  'a.sol':{keccak256:'0x'+'11'.repeat(32)}}});
 const second=sourceSetSha256({sources:{'a.sol':{keccak256:'0x'+'11'.repeat(32)},
  'b.sol':{keccak256:'0x'+'22'.repeat(32)}}});
 assert.equal(first,second);
 assert.throws(()=>sourceSetSha256({sources:{'a.sol':{}}}));
});

test('fixed writer performs two isolated create-once builds without live capability',async()=>{
 const [prepare,writer]=await Promise.all([
  readFile(new URL('../../scripts/prepare-reserve-reproducible-build-report.mjs',import.meta.url),'utf8'),
  readFile(new URL('../../scripts/write-reserve-reproducible-build-report.sh',import.meta.url),'utf8'),
 ]);
 assert.match(prepare,/isolatedBuild\('isolated-build-a'/);
 assert.match(prepare,/isolatedBuild\('isolated-build-b'/);
 assert.match(prepare,/productionFoundryBuildArguments\(/);
 assert.match(prepare,/output,cache,root,solc\.path/);
 assert.match(prepare,/release inputs changed during builds/);
 assert.equal((prepare.match(/parseStrictJsonBytes\(/g)??[]).length,3);
 assert.doesNotMatch(prepare,/\.toString\(['"]utf8['"]\)/);
 assert.match(prepare,/artifactAfter\.equals\(canonicalArtifact\)/);
 assert.match(prepare,/assertArtifactSourcesUnchanged\(root,sourceSnapshot\)/);
 assert.match(prepare,/assertExecutableUnchanged\(forge\)/);
 assert.match(writer,/flock -n 8/);
 assert.match(writer,/flock -n 9/);
 assert.match(writer,/chmod 0600 "\$report"/);
 assert.match(writer,/install-private-file-immutable-stdin\.mjs/);
 assert.doesNotMatch(`${prepare}\n${writer}`,/\bcurl\b|cast (?:send|publish)|ledger|git (?:push|commit|tag)/i);
});

test('reserve build JSON authority rejects duplicate escaped keys and invalid UTF-8',()=>{
 for(const bytes of [
  Buffer.from('{"metadata":{},"\\u006detadata":{}}\n'),
  Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d]),
 ]) assert.throws(()=>parseStrictJsonBytes(bytes,{label:'reserve artifact',
  maxBytes:64*1024*1024,maxDepth:128}),/duplicate (?:object )?key|invalid UTF-8/);
});

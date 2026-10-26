#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseGitSignatureFingerprint} from '../sdk/git-signature.mjs';
import {materializeReleaseProvenance} from '../sdk/release-provenance-materialization.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {runPinnedExecutable} from '../sdk/pinned-executable-child.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';

const EXPECTED_IDENTITY='Soren Planck <sorenplanck@tutamail.com>';

function text(bytes,label) {
  try { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error(`${label} is not valid UTF-8`); }
}
async function git(tool,repository,args,{allowEmpty=false}={}) {
  const result=await runPinnedExecutable(tool,['-C',repository,...args],{
    maxBuffer:4*1024*1024,timeout:30*1000,
  });
  if(result.stderr.length!==0) throw new Error(`git ${args[0]} wrote stderr`);
  const output=text(result.stdout,`git ${args[0]} stdout`);
  if(allowEmpty&&output==='') return '';
  if(!output.endsWith('\n')||output.endsWith('\n\n')||output.includes('\r')) {
    throw new Error(`git ${args[0]} stdout framing is invalid`);
  }
  return output.slice(0,-1);
}

try {
  if(process.argv.length!==2) throw new Error('this command accepts no arguments');
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const gitExecutable=await snapshotExecutable('git');
  const repository=await git(gitExecutable,root,['rev-parse','--show-toplevel']);
  const projectRelative=path.relative(repository,root).split(path.sep).join('/');
  if(!projectRelative||projectRelative.startsWith('../')||path.isAbsolute(projectRelative)) {
    throw new Error('USDOM component is outside the Git worktree');
  }
  const sourceCommit=await git(gitExecutable,repository,['rev-parse','--verify','HEAD^{commit}']);
  const identities=(await git(gitExecutable,repository,[
    'show','-s','--format=%an <%ae>%n%cn <%ce>','HEAD',
  ])).split('\n');
  if(identities.length!==2||identities.some(value=>value!==EXPECTED_IDENTITY)) {
    throw new Error('source commit author or committer identity is invalid');
  }
  let signature;
  try {
    const result=await runPinnedExecutable(gitExecutable,
      ['-C',repository,'verify-commit','--raw','HEAD'],{
        maxBuffer:4*1024*1024,timeout:30*1000,
    });
    signature=`${text(result.stdout,'git verify-commit stdout')}\n${text(result.stderr,'git verify-commit stderr')}`;
  } catch(error) {
    signature=`${Buffer.isBuffer(error.stdout)?text(error.stdout,'git verify-commit stdout'):''}\n${Buffer.isBuffer(error.stderr)?text(error.stderr,'git verify-commit stderr'):''}`;
    throw new Error(`source commit signature is invalid: ${signature.trim()}`);
  }
  const signingFingerprint=process.env.USDOM_RELEASE_SIGNING_KEY_FINGERPRINT;
  if(parseGitSignatureFingerprint(signature)!==signingFingerprint) {
    throw new Error('source commit signer differs from the external release trust anchor');
  }
  for(const relative of [
    'config/mainnet-release-evidence.unconfigured.json','config/operator-intent.json',
  ]) {
    await git(gitExecutable,repository,['cat-file','-e',`HEAD:${projectRelative}/${relative}`],
      {allowEmpty:true});
  }
  const inputPaths=['package.json','config/mainnet-release-evidence.unconfigured.json',
    'config/operator-intent.json'];
  const inputBytes=await Promise.all(inputPaths.map(relative=>readDirectProjectFile(root,relative)));
  const packageJson=parseStrictJsonBytes(inputBytes[0],{
    label:'package.json',maxBytes:1024*1024,maxDepth:16,
  });
  const releaseEvidence=parseStrictJsonBytes(inputBytes[1],
    {label:'mainnet release evidence',maxBytes:2*1024*1024,maxDepth:32});
  const operatorIntent=parseStrictJsonBytes(inputBytes[2],
    {label:'operator intent',maxBytes:2*1024*1024,maxDepth:32});
  const result=materializeReleaseProvenance({releaseEvidence,operatorIntent,
    packageVersion:packageJson.version,sourceCommit,signingFingerprint});
  try {
    await git(gitExecutable,repository,['rev-parse','--verify',`refs/tags/${result.identity.sourceTag}`]);
    throw new Error('derived release tag already exists before the evidence commit');
  } catch(error) {
    if(error.message==='derived release tag already exists before the evidence commit') throw error;
  }
  const [sourceCommitAfter,currentInputBytes]=await Promise.all([
    git(gitExecutable,repository,['rev-parse','--verify','HEAD^{commit}']),
    Promise.all(inputPaths.map(relative=>readDirectProjectFile(root,relative))),
  ]);
  if(sourceCommitAfter!==sourceCommit
      ||currentInputBytes.some((bytes,index)=>!bytes.equals(inputBytes[index]))) {
    throw new Error('release provenance inputs changed during materialization');
  }
  process.stdout.write(`${JSON.stringify({
    schema:'usdom-release-provenance-materialization/v1',...result,
  },null,2)}\n`);
} catch(error) {
  writeReleaseFailure('prepare-release-provenance-materialization',error);
  process.exitCode=1;
}

const h64=/^[0-9a-f]{64}$/;
const zero64='0'.repeat(64);
const commit=/^[0-9a-f]{40}$/;
const tag=/^usdom-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const top=['schema','status','releaseId','sourceCommit','sourceTag','toolchainLockSha256','cargoLockSha256','runs'];
const runFields=['kind','runId','commandManifestSha256','runSha256','terminalSha256','processLogSha256','eventsSha256','supervisorSha256','startedAt','finishedAt'];
const kinds=['checkpoint390','randomxCache','nativePrivacy'];
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
  &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
const utc=value=>typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value)
  &&Number.isFinite(Date.parse(value));
const fail=message=>{throw new Error(message);};

export function validateReleaseValidationReport(report,{releaseEvidence,toolchainLockSha256,cargoLockSha256}={}) {
  if(!exact(report,top)||report.schema!=='usdom-release-validation-report/v1'||report.status!=='passed') {
    fail('release validation report schema or status is invalid');
  }
  if(typeof report.releaseId!=='string'||report.releaseId.length===0
      ||!commit.test(report.sourceCommit??'')||!tag.test(report.sourceTag??'')
      ||report.releaseId!==releaseEvidence?.releaseId||report.sourceCommit!==releaseEvidence?.sourceCommit
      ||report.sourceTag!==releaseEvidence?.sourceTag) fail('release validation report provenance mismatch');
  if(!h64.test(report.toolchainLockSha256??'')||report.toolchainLockSha256===zero64
      ||report.toolchainLockSha256!==toolchainLockSha256
      ||!h64.test(report.cargoLockSha256??'')||report.cargoLockSha256===zero64
      ||report.cargoLockSha256!==cargoLockSha256) {
    fail('release validation report toolchain/input mismatch');
  }
  if(!Array.isArray(report.runs)||report.runs.length!==3) fail('release validation report must contain three runs');
  const ids=new Set(); const supervisors=new Set();
  let previousFinishedAt=null;
  report.runs.forEach((run,index)=>{
    if(!exact(run,runFields)||run.kind!==kinds[index]) fail('release validation run schema/order is invalid');
    for(const name of ['runId','commandManifestSha256','runSha256','terminalSha256','processLogSha256','eventsSha256','supervisorSha256']) {
      if(!h64.test(run[name]??'')||run[name]===zero64) {
        fail(`release validation ${name} is invalid`);
      }
    }
    if(run.runId!==run.commandManifestSha256||ids.has(run.runId)) fail('release validation run identity is replayed or unbound');
    ids.add(run.runId); supervisors.add(run.supervisorSha256);
    if(!utc(run.startedAt)||!utc(run.finishedAt)||Date.parse(run.finishedAt)<Date.parse(run.startedAt)) {
      fail('release validation run interval is invalid');
    }
    if(previousFinishedAt!==null&&Date.parse(run.startedAt)<previousFinishedAt) {
      fail('release validation runs overlap or are out of execution order');
    }
    previousFinishedAt=Date.parse(run.finishedAt);
  });
  if(supervisors.size!==1) fail('release validation runs used different supervisor generations');
  return true;
}

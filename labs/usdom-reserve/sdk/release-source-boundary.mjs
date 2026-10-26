const commitPattern=/^[0-9a-f]{40}$/;
const allowedStatusCodes=Object.freeze(new Set(['??',' M','M ','MM','A ','AM']));

function fail(message) { throw new Error(message); }

function canonicalProjectRoot(value) {
  if(typeof value!=='string' || value==='' || value.startsWith('/') || value.includes('\\')
      || value.split('/').some(part=>part==='' || part==='.' || part==='..')) {
    fail('release project-relative path is invalid');
  }
  return value;
}

/**
 * Enforce the immutable-source/evidence-only boundary used by expensive
 * release-specific proof executors. The exact source commit must be checked
 * out. Only the two release metadata files and files below evidence/ may
 * differ while the evidence child commit is being assembled.
 */
export function validateReleaseSourceBoundary({head,sourceCommit,status,projectRelative}) {
  if(!commitPattern.test(head??'') || head!==sourceCommit) {
    fail('release proof HEAD differs from sourceCommit');
  }
  const root=canonicalProjectRoot(projectRelative);
  if(typeof status!=='string') fail('release Git status must be NUL-delimited text');
  const exactAllowed=new Set([
    `${root}/config/mainnet-release-evidence.unconfigured.json`,
    `${root}/config/operator-intent.json`,
  ]);
  for(const record of status.split('\0').filter(Boolean)) {
    const code=record.slice(0,2);
    if(record.length<4 || record[2]!==' ' || !allowedStatusCodes.has(code)) {
      fail('release proof encountered an ambiguous Git status record');
    }
    const relative=record.slice(3);
    if(relative==='' || relative.includes('\0') || relative.startsWith('/')
        || relative.includes('\\') || relative.split('/').some(part=>part==='' || part==='.' || part==='..')) {
      fail('release proof encountered a noncanonical Git status path');
    }
    if(!exactAllowed.has(relative) && !relative.startsWith(`${root}/evidence/`)) {
      fail(`release proof source tree changed outside the evidence layer: ${relative}`);
    }
  }
}

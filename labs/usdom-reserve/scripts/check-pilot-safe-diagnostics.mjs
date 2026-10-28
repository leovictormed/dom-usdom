import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {pilotFailureLine,releaseFailureLine} from '../sdk/pilot-safe-diagnostics.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const entrypoints=[
  'check-closed-mainnet-deposit-package.mjs','check-closed-mainnet-deposit-raw.mjs',
  'check-closed-mainnet-phase-artifacts.mjs','check-mainnet-preflight.mjs',
  'check-mainnet-readiness.mjs','initialize-closed-mainnet-genesis.mjs',
  'materialize-finalized-burn-release-evidence.mjs','mine-closed-mainnet-issuance-block.mjs',
  'prepare-authenticated-finalized-burn-submission.mjs','prepare-closed-mainnet-deposit.mjs',
  'submit-finalized-deposit-issuance.mjs',
];
const forbidden=/(console\.(?:error|warn|log)|stderr\.write)[^\n]*(?:error\??\.message|String\(error|error\.stack|error\.cause)/;

for(const name of entrypoints) {
  const source=fs.readFileSync(path.join(root,'scripts',name),'utf8');
  if(!source.includes("../sdk/pilot-safe-diagnostics.mjs")||!source.includes('writePilotFailure(')) {
    throw new Error(`pilot entrypoint lacks safe diagnostics: ${name}`);
  }
  if(forbidden.test(source)) throw new Error(`pilot entrypoint emits an exception: ${name}`);
}
let releaseEntrypoints=0;
for(const name of fs.readdirSync(path.join(root,'scripts')).filter(name=>name.endsWith('.mjs'))) {
  const source=fs.readFileSync(path.join(root,'scripts',name),'utf8');
  if(forbidden.test(source)||/error\s*:\s*String\(error/.test(source)
      ||/throw new Error\([^;\n]*(?:\.stderr|\.stdout)/.test(source)) {
    throw new Error(`release entrypoint exposes untrusted diagnostic material: ${name}`);
  }
  if(source.includes('writeReleaseFailure(')) releaseEntrypoints++;
}
const sentinels=[
  'RAW_SIGNED_TX_SENTINEL_91e3','WITNESS_SENTINEL_ba72','RHO_SENTINEL_44cf',
  'DEPOSIT_ID_SENTINEL_028a','FUNDER_SENTINEL_5d23','BURN_ID_SENTINEL_9f01',
  'REQUEST_ID_SENTINEL_113a','RECIPIENT_SENTINEL_f1ac','RPC_SECRET_SENTINEL_8841',
];
const hostile=new Error(sentinels.join(':'));
hostile.stack=sentinels.toReversed().join('|');
hostile.cause={secret:sentinels.join('')};
const line=pilotFailureLine('closed-mainnet-phase-check',hostile);
const releaseLine=releaseFailureLine('adversarial-release-entrypoint',hostile);
if(sentinels.some(value=>line.includes(value)||releaseLine.includes(value))) {
  throw new Error('safe diagnostic leaked sentinel');
}
process.stdout.write(`${JSON.stringify({ok:true,pilotEntrypoints:entrypoints.length,
  releaseEntrypoints,sentinels:sentinels.length})}\n`);

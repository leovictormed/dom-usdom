#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {dirname,join} from 'node:path';
import {readAndValidateClosedMainnetParameterPolicy} from '../sdk/closed-mainnet-parameter-policy.mjs';

const root=join(dirname(fileURLToPath(import.meta.url)),'..');
const policy=readAndValidateClosedMainnetParameterPolicy(join(root,'config/closed-mainnet-pilot-parameter-policy.json'));
const reserve=readFileSync(join(root,'contracts/USDOMProofReserve.sol'),'utf8');
const registry=readFileSync(join(root,'contracts/DOMCheckpointRegistry.sol'),'utf8');
const checkpoint=JSON.parse(readFileSync(join(root,'config/checkpoint-verifier.unconfigured.json'),'utf8'));
const required=[
  [reserve,/REFILL_PERIOD = 1 days;/,'reserve refill'],[reserve,/MAX_CERTIFICATE_LIFETIME = 7 days;/,'certificate lifetime'],
  [reserve,/MIN_EXECUTION_WINDOW = 1 hours;/,'execution window'],[reserve,/ETHEREUM_SECONDS_PER_SLOT = 12;/,'slot seconds'],
  [reserve,/MAX_PRUNE_BATCH = 256;/,'prune batch'],[reserve,/VERIFIER_GAS_LIMIT = 5_000_000;/,'reserve verifier gas'],
  [reserve,/TOKEN_GAS_LIMIT = 500_000;/,'token gas'],[reserve,/REGISTRY_GAS_LIMIT = 100_000;/,'registry gas'],
  [reserve,/CONTROL_PLANE_GAS_LIMIT = 50_000;/,'reserve control gas'],[reserve,/CONTROL_PLANE_THRESHOLD = 2;/,'reserve threshold'],
  [reserve,/CONTROL_PLANE_OWNER_COUNT = 3;/,'reserve owners'],[registry,/MAX_CHECKPOINT_INTERVAL = 360;/,'checkpoint interval bound'],
  [registry,/VERIFIER_GAS_LIMIT = 5_000_000;/,'registry verifier gas'],[registry,/CONTROL_PLANE_THRESHOLD = 2;/,'registry threshold'],
  [registry,/CONTROL_PLANE_OWNER_COUNT = 3;/,'registry owners'],
];
for(const [source,pattern,label] of required) if(!pattern.test(source)) throw new Error(`${label} no longer matches reviewed policy`);
for(const [key,value] of Object.entries({checkpointInterval:'360',confirmationDepth:'30',challengePeriod:'172800',maxCheckpointSpan:'390',maxProofBytes:'260',ethereumChainId:'1'})) {
  if(checkpoint[key]!==value) throw new Error(`checkpoint ${key} no longer matches reviewed policy`);
}
if(policy.ethereum.pilotAmountBaseUnits!==policy.reserve.maxOutstandingBaseUnits) throw new Error('pilot amount must equal the closed exposure ceiling');
let releaseConfigReviewed=false;
if(process.argv.length===4&&process.argv[2]==='--release-config') {
  const release=JSON.parse(readFileSync(process.argv[3],'utf8'));
  const exact={ethereumChainId:policy.ethereum.chainId,token:policy.ethereum.token,
    withdrawalDelaySeconds:policy.reserve.withdrawalDelaySeconds,
    governanceDelaySeconds:policy.reserve.governanceDelaySeconds,
    maxOutstandingBaseUnits:policy.reserve.maxOutstandingBaseUnits,
    outflowCapacityBaseUnitsPerDay:policy.reserve.outflowCapacityBaseUnitsPerRefillPeriod,
    nativeRelaySafetyMarginSeconds:policy.nativeFinality.relaySafetyMarginSeconds,
    nativeMaxEthereumAnchorAgeSeconds:policy.nativeFinality.maximumEthereumAnchorAgeSeconds,
    nativeMaxDomClockLeadSeconds:policy.nativeFinality.maximumDomClockLeadSeconds};
  for(const [key,value] of Object.entries(exact)) {
    const actual=key==='token' ? String(release[key]).toLowerCase() : release[key];
    const wanted=key==='token' ? value.toLowerCase() : value;
    if(actual!==wanted) throw new Error(`release config ${key} differs from reviewed pilot policy`);
  }
  if(release.productionReady!==false||release.realFundsAuthorized!==false) throw new Error('parameter review cannot authorize production or funds');
  releaseConfigReviewed=true;
} else if(process.argv.length!==2) throw new Error('usage: check-closed-mainnet-parameter-policy.mjs [--release-config PATH]');
process.stdout.write(JSON.stringify({schema:policy.schema,status:'PASS',authorizationImplied:false,categoriesReviewed:8,releaseConfigReviewed})+'\n');

import {createHash} from 'node:crypto';
import {assessMainnetPreflight} from './mainnet-preflight.mjs';
import {rpcConsensusEvidence,validateRpcConsensusEvidence} from './rpc-consensus-evidence.mjs';
import {mainnetPreflightRpcSourceSet,requireOperationalTlsClock} from './mainnet-preflight-rpc.mjs';
import {collectReleaseEvidenceDocumentPaths} from './release-evidence-document-paths.mjs';
import {isExactReleaseEvidenceShape} from './release-evidence-schema.mjs';

export const MAINNET_PREFLIGHT_MATERIALIZATION=Object.freeze({
  predeployment:Object.freeze({
    evidenceField:'mainnetPredeploymentAttestationReport',
    requirementField:'production_mainnet_predeployment_preflight_passed',
    evidencePath:'evidence/mainnet-predeployment-attestation.json',
  }),
  postdeployment:Object.freeze({
    evidenceField:'mainnetColdStartAttestationReport',
    requirementField:'production_mainnet_cold_start_attestation_completed',
    evidencePath:'evidence/mainnet-cold-start-attestation.json',
  }),
});

const reportKeys=['blockerCount','blockers','collectionCompletedAtMs','collectionStartedAtMs',
  'finalizedBlockHash','finalizedBlockNumber','observation','phase','ready','rpcConsensus'];
const MAX_COLLECTION_DURATION_MS=10*60*1000;
const MAX_MATERIALIZATION_DELAY_MS=30*60*1000;
const MAX_FUTURE_SKEW_MS=15*1000;

function fail(message) { throw new Error(message); }
function exact(value,keys,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...keys].sort())) {
    fail(`${label} must contain exact fields`);
  }
}
function canonical(value) {
  if(Array.isArray(value)) return value.map(canonical);
  if(value && typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,canonical(value[key])]),
  );
  return value;
}
function same(left,right) { return JSON.stringify(canonical(left))===JSON.stringify(canonical(right)); }
function content(value) { return `${JSON.stringify(value,null,2)}\n`; }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }

export function prepareMainnetPreflightMaterialization({
  phase,report,releaseConfig,riscZeroReference,evidence,requirements,rpcCatalog,nowMs=Date.now(),
}) {
  const policy=MAINNET_PREFLIGHT_MATERIALIZATION[phase];
  if(!policy) fail('phase must be predeployment or postdeployment');
  exact(report,reportKeys,'mainnet preflight report');
  requireOperationalTlsClock(nowMs);
  if(!Number.isSafeInteger(report.collectionStartedAtMs)
      || !Number.isSafeInteger(report.collectionCompletedAtMs)
      || report.collectionStartedAtMs>report.collectionCompletedAtMs
      || report.collectionCompletedAtMs-report.collectionStartedAtMs>MAX_COLLECTION_DURATION_MS
      || report.collectionCompletedAtMs>nowMs+MAX_FUTURE_SKEW_MS
      || nowMs-report.collectionCompletedAtMs>MAX_MATERIALIZATION_DELAY_MS) {
    fail('mainnet preflight report collection window is stale, future or invalid');
  }
  validateRpcConsensusEvidence(report.rpcConsensus);
  const approvedSources=mainnetPreflightRpcSourceSet(rpcCatalog).sources.map(source=>({
    sourceId:source.operatorId,originKeccak256:source.originKeccak256,
  }));
  if(!same(report.rpcConsensus,rpcConsensusEvidence(approvedSources))) {
    fail('mainnet preflight report RPC consensus differs from the approved catalog');
  }
  if(report.phase!==phase || report.ready!==true || report.blockerCount!==0
      || !Array.isArray(report.blockers) || report.blockers.length!==0) {
    fail('mainnet preflight report is not a zero-blocker success for the requested phase');
  }
  const recomputed=assessMainnetPreflight({
    phase,releaseConfig,observation:report.observation,riscZeroReference,
  });
  const expected={...recomputed,collectionStartedAtMs:report.collectionStartedAtMs,
    collectionCompletedAtMs:report.collectionCompletedAtMs,
    observation:report.observation,rpcConsensus:report.rpcConsensus};
  if(!recomputed.ready || recomputed.blockerCount!==0 || !same(report,expected)) {
    fail('mainnet preflight report does not match independent recomputation');
  }
  if(!isExactReleaseEvidenceShape(evidence) || evidence.schema!==1
      || !Object.hasOwn(evidence,policy.evidenceField)) {
    fail('release evidence does not contain the required preflight slot');
  }
  if(!requirements || typeof requirements!=='object' || Array.isArray(requirements)
      || !Object.hasOwn(requirements,policy.requirementField)
      || requirements[policy.requirementField]!==false) {
    fail('production requirements do not contain the immutable false preflight policy slot');
  }
  const reportContent=content(report);
  const document={path:policy.evidencePath,sha256:sha256(reportContent)};
  const paths=collectReleaseEvidenceDocumentPaths(evidence,{skipTopLevelKey:policy.evidenceField});
  if(paths.includes(policy.evidencePath)) {
    fail('mainnet preflight evidence path is already used by another slot');
  }
  const current=evidence[policy.evidenceField];
  if(current!==null && !same(current,document)) {
    fail('release evidence already binds a different preflight report');
  }
  const nextEvidence={...evidence,[policy.evidenceField]:document};
  return Object.freeze({
    ...policy,reportContent,document,
    evidenceContent:content(nextEvidence),requirementsContent:content(requirements),
  });
}

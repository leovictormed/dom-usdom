import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {createRiscZeroHealthSourceCatalog} from '../../sdk/risc0-health-source-catalog.mjs';
import {
  prepareRiscZeroHealthSourceCatalogMaterialization,
  RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,
} from '../../sdk/risc0-health-source-catalog-materialization.mjs';

const hash=value=>'0x'+value.toString(16).padStart(64,'0');
const releaseEvidenceTemplate=JSON.parse(readFileSync(new URL(
  '../../config/mainnet-release-evidence.unconfigured.json',import.meta.url),'utf8'));
const catalog=createRiscZeroHealthSourceCatalog({sources:[
  {sourceId:'rpc-a',operatorId:'operator-a',providerId:'provider-a',
    infrastructureId:'infra-a',endpointHash:hash(1)},
  {sourceId:'rpc-b',operatorId:'operator-b',providerId:'provider-b',
    infrastructureId:'infra-b',endpointHash:hash(2)},
]});

test('catalog materializer writes canonical content and exact release-evidence SHA-256',()=>{
  const evidence={...structuredClone(releaseEvidenceTemplate),riscZeroHealthSourceCatalog:null};
  const result=prepareRiscZeroHealthSourceCatalogMaterialization({catalog,evidence});
  assert.equal(result.catalogContent,JSON.stringify(catalog,null,2)+'\n');
  assert.equal(result.sha256,createHash('sha256').update(result.catalogContent).digest('hex'));
  assert.deepEqual(result.nextEvidence,{...evidence,riscZeroHealthSourceCatalog:{
    path:RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,sha256:result.sha256,
  }});
  assert.deepEqual(JSON.parse(result.evidenceContent),result.nextEvidence);
});

test('catalog materializer rejects invalid catalogs and incompatible evidence without output',()=>{
  assert.throws(()=>prepareRiscZeroHealthSourceCatalogMaterialization({
    catalog:{...catalog,catalogHash:hash(99)},evidence:{riscZeroHealthSourceCatalog:null},
  }),/hash mismatch/);
  assert.throws(()=>prepareRiscZeroHealthSourceCatalogMaterialization({catalog,evidence:{schema:1}}),
    /does not expose/);
  assert.throws(()=>prepareRiscZeroHealthSourceCatalogMaterialization({catalog,evidence:{
    ...structuredClone(releaseEvidenceTemplate),
    riscZeroHealthSourceCatalog:{path:'evidence/old-health.json',sha256:'a'.repeat(64)},
  }}),/already binds a different/);
  assert.throws(()=>prepareRiscZeroHealthSourceCatalogMaterialization({catalog,evidence:{
    ...structuredClone(releaseEvidenceTemplate),
    operationsReviewReport:{path:RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,sha256:'a'.repeat(64)},
  }}),/already used by another slot/);
});

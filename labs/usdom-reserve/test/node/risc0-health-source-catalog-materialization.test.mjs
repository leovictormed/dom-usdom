import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createRiscZeroHealthSourceCatalog} from '../../sdk/risc0-health-source-catalog.mjs';
import {
  prepareRiscZeroHealthSourceCatalogMaterialization,
  RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,
} from '../../sdk/risc0-health-source-catalog-materialization.mjs';

const hash=value=>'0x'+value.toString(16).padStart(64,'0');
const catalog=createRiscZeroHealthSourceCatalog({sources:[
  {sourceId:'rpc-a',operatorId:'operator-a',providerId:'provider-a',
    infrastructureId:'infra-a',endpointHash:hash(1)},
  {sourceId:'rpc-b',operatorId:'operator-b',providerId:'provider-b',
    infrastructureId:'infra-b',endpointHash:hash(2)},
]});

test('catalog materializer writes canonical content and exact release-evidence SHA-256',()=>{
  const evidence={schema:1,riscZeroHealthSourceCatalog:null,other:'preserved'};
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
});

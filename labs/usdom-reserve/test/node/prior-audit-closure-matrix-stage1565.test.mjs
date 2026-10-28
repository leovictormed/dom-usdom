import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const report=readFileSync(path.join(root,'docs/reports/PRIOR-AUDIT-FINDING-CLOSURE-MATRIX-ETAPA1565-2026-10-27.md'),'utf8');
const expected=['M-01','R-01','R-02','R-03','R-04','REC-1','REC-2','REC-3','REC-4',
  'INT-1','INT-2','INT-3','INT-4','INT-5','INT-6','INT-7','INT-8','TOK-01','GOV-01',
  'SIG-01','ACC-01','STATIC-REENT','STATIC-EQ','STATIC-TIME','STATIC-PRAGMA','STATIC-OZ','DEP-01','PRIV-01'];

test('prior audit matrix closes every finding and recommendation exactly once',()=>{
  const rows=[...report.matchAll(/^\| ([A-Z0-9-]+) \|/gm)].map(match=>match[1]).filter(id=>id!=='ID');
  assert.deepEqual(rows,expected);
  assert.equal(new Set(rows).size,expected.length);
});

test('closure matrix preserves external evidence and risk boundaries',()=>{
  assert.match(report,/Claims operacionais permanecem falsas até evidência real/);
  assert.match(report,/cerimônia multiparte real, instalação da VK resultante/);
  assert.match(report,/não é\s+garantia de risco zero nem bloqueio automático/);
  assert.match(report,/não declara o projeto pronto antes das evidências externas/);
  assert.doesNotMatch(report,/auditoria externa (?:é|como) requisito obrigatório/i);
});

test('named authoritative implementation evidence exists',()=>{
  for(const relative of ['contracts/USDOMProofReserve.sol','contracts/DOMFinalizedBurnRiscZeroVerifier.sol',
    'contracts/DOMCheckpointRegistry.sol','test/solidity/AuditV2.t.sol','test/solidity/USDTPolicy.t.sol',
    'scripts/write-open-claims-execution-plan.mjs','config/production-requirements.json']) {
    assert.ok(existsSync(path.join(root,relative)),relative);
  }
  for(const relative of ['../../crates/dom-chain/src/native_usdom_v4.rs','../../crates/dom-store/src/db.rs',
    '../../crates/dom-usdom-privacy/src/circuit.rs','../../crates/dom-usdom-privacy/src/phase1.rs',
    '../../crates/dom-usdom-privacy/src/ceremony.rs']) assert.ok(existsSync(path.join(root,relative)),relative);
});

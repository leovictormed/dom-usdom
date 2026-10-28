import test from 'node:test';
import assert from 'node:assert/strict';
import {auditOneKeyProductionBoundary} from '../../sdk/onekey-production-boundary.mjs';

const inventory={schema:1,scripts:['scripts/signer.sh']};

test('OneKey production inventory accepts a Ledger-free executor',()=>{
 const report=auditOneKeyProductionBoundary({inventory,
  readSource:()=>`#!/bin/sh\nonekey-sign --transport usb\n`});
 assert.deepEqual(report,{ok:true,checked:1,discovered:1,violations:[]});
});

test('OneKey production inventory rejects every Ledger signing form',()=>{
 for(const line of ['cast wallet address --ledger','cast mktx --ledger /tmp/tx',
  'flag=(--ledger)','flag=--ledger,','flag=--ledger;','flag="--ledger"']) {
  const report=auditOneKeyProductionBoundary({inventory,readSource:()=>line});
  assert.equal(report.ok,false);
  assert.deepEqual(report.violations,[{path:'scripts/signer.sh',line:1,
   reason:'ledger-option'}]);
 }
});

test('discovery rejects a Ledger option omitted from the canonical inventory',()=>{
 const sources={
  'scripts/signer.sh':'onekey-sign --transport usb',
  'scripts/generated-command.sh':'args=(--ledger)',
 };
 const report=auditOneKeyProductionBoundary({inventory,
  allScriptPaths:Object.keys(sources),readSource:path=>sources[path]});
 assert.equal(report.ok,false);
 assert.deepEqual(report.violations,[{path:'scripts/generated-command.sh',line:1,
  reason:'uninventoried-ledger-option'}]);
});

test('accounting ledger words and option-name extensions are not hardware flags',()=>{
 const report=auditOneKeyProductionBoundary({inventory,readSource:()=>[
  'ledger_balance=10',
  'printf "accounting ledger entry"',
  'tool --ledgerx --ledger_device',
 ].join('\n')});
 assert.equal(report.ok,true);
 assert.deepEqual(report.violations,[]);
});

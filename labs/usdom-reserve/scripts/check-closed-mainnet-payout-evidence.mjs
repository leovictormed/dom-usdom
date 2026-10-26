#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {readFileSync,lstatSync} from 'node:fs';
import {validateClosedMainnetPayoutEvidence} from '../sdk/closed-mainnet-payout-evidence.mjs';

if(process.argv.length!==5) throw new Error('usage: check-closed-mainnet-payout-evidence BASELINE EXECUTION PACKAGE');
const [, ,baselinePath,executionPath,packagePath]=process.argv;
for(const path of [baselinePath,executionPath,packagePath]) {
  if(lstatSync(path).isSymbolicLink()) throw new Error('payout evidence input must not be a symlink');
}
const baselineBytes=readFileSync(baselinePath);
const baseline=JSON.parse(baselineBytes),execution=JSON.parse(readFileSync(executionPath));
const packageValue=JSON.parse(readFileSync(packagePath));
const baselineSha256=createHash('sha256').update(baselineBytes).digest('hex');
validateClosedMainnetPayoutEvidence({baseline,baselineSha256,execution,packageValue});
process.stdout.write('ok\n');

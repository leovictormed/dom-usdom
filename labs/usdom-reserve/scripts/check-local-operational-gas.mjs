#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {validateLocalOperationalGasEvidence} from '../sdk/local-operational-gas-evidence.mjs';
if(process.argv.length!==3) throw new Error('usage: check-local-operational-gas REPORT');
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
validateLocalOperationalGasEvidence(JSON.parse(readFileSync(process.argv[2],'utf8')),{root});
const requirements=JSON.parse(readFileSync(path.join(root,'config/production-requirements.json'),'utf8'));
for(const key of ['production_queue_withdrawal_worst_case_gas_measured',
 'production_prune_expired_256_worst_case_gas_measured',
 'production_prune_discardable_256_worst_case_gas_measured',
 'production_safe_admin_overhead_gas_measured']) {
  if(requirements[key]!==false) throw new Error(`${key} must remain false for local evidence`);
}
process.stdout.write('ok\n');

#!/usr/bin/env node
import {readFileSync} from 'node:fs';import {validateRecoveryV3FinalizedStep} from '../sdk/safe-recovery-roster-execution-v3.mjs';
try{const [plan,assembled,journal,a,b]=process.argv.slice(2).map(p=>JSON.parse(readFileSync(p)));process.stdout.write(`${JSON.stringify(validateRecoveryV3FinalizedStep({plan,ordinal:journal.ordinal,assembled,journal,rpcObservations:[a,b]}))}\n`);}catch(e){console.error(e.message);process.exit(1)}

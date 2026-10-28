#!/usr/bin/env node
import {archiveClosedMainnetPhaseGeneration} from '../sdk/closed-mainnet-phase-generation-archive.mjs';
if(process.argv.length!==2) throw new Error('phase generation archival accepts no arguments');
const result=archiveClosedMainnetPhaseGeneration({
  privateRoot:'/home/leonardov/usdom-mainnet-private',
  publicDirectory:'/home/leonardov/usdom-mainnet-public',
});
process.stdout.write(`${JSON.stringify({status:'archived',...result})}\n`);

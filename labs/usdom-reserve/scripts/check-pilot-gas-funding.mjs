#!/usr/bin/env node
import {validatePilotGasFunding} from '../sdk/pilot-gas-funding.mjs';
if(process.argv.length!==5) process.exit(64);
process.stdout.write(JSON.stringify(validatePilotGasFunding({balanceA:process.argv[2],balanceB:process.argv[3],maximumCost:process.argv[4]}))+'\n');

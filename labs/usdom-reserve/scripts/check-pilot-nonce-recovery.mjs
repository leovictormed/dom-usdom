#!/usr/bin/env node
import {classifyPilotNonce} from '../sdk/pilot-nonce-recovery.mjs';
if(process.argv.length!==10) process.exit(64);
process.stdout.write(classifyPilotNonce(...process.argv.slice(2))+'\n');

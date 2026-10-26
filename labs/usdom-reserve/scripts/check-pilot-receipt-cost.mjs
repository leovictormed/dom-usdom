#!/usr/bin/env node
import {validatePilotReceiptCost} from '../sdk/pilot-receipt-cost.mjs';
if(process.argv.length!==5) process.exit(64);
process.stdout.write(JSON.stringify(validatePilotReceiptCost({gasUsed:process.argv[2],effectiveGasPrice:process.argv[3],maximumCost:process.argv[4]}))+'\n');

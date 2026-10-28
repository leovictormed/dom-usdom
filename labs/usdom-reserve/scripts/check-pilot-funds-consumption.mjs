#!/usr/bin/env node
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {buildPilotFundsConsumption,validatePilotFundsConsumption} from '../sdk/pilot-funds-consumption.mjs';

if(![8,9].includes(process.argv.length)) {
  throw new Error('usage: check-pilot-funds-consumption.mjs [MARKER] PACKAGE GATE EXECUTION FINALITY0 FINALITY1 FINALITY2');
}
const hasMarker=process.argv.length===9;
const offset=hasMarker?3:2;
const paths=process.argv.slice(offset);
const bytes=await Promise.all(paths.map(value=>readDirectFile(value,{minimum:2,maximum:4*1024*1024,
  exactMode:0o600,label:'pilot consumption input'})));
const packageValue=parseStrictJsonBytes(bytes[0],{label:'deposit package'});
const inputs={packageValue,packageBytes:bytes[0],gateBytes:bytes[1],executionBytes:bytes[2],finalityBytes:bytes.slice(3)};
if(hasMarker) {
  const markerBytes=await readDirectFile(process.argv[2],{minimum:2,maximum:64*1024,exactMode:0o600,
    label:'pilot consumption marker'});
  validatePilotFundsConsumption(parseStrictJsonBytes(markerBytes,{label:'pilot consumption marker'}),inputs);
  process.stdout.write(`${JSON.stringify({ok:true,depositId:packageValue.depositId})}\n`);
} else process.stdout.write(`${JSON.stringify(buildPilotFundsConsumption(inputs))}\n`);

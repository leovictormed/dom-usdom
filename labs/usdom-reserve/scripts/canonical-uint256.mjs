#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
const DEC=/^(?:0|[1-9][0-9]{0,77})$/,HEX=/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$/,MAX=(1n<<256n)-1n;
const parse=value=>{if(typeof value!=='string'||(!DEC.test(value)&&!HEX.test(value)))throw new Error('noncanonical uint256');const number=BigInt(value);if(number>MAX)throw new Error('uint256 overflow');return number;};
try {
  const [operation,...values]=process.argv.slice(2);
  if(operation==='normalize'&&values.length===1) process.stdout.write(`${parse(values[0])}\n`);
  else if(operation==='ge'&&values.length===2) process.stdout.write(`${parse(values[0])>=parse(values[1])?'true':'false'}\n`);
  else if(operation==='add1'&&values.length===1) {const result=parse(values[0])+1n;if(result>MAX)throw new Error('uint256 overflow');process.stdout.write(`${result}\n`);}
  else throw new Error('canonical uint256 operation invalid');
} catch(error) { writeReleaseFailure('canonical-uint256',error);process.exitCode=1; }

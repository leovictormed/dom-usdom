#!/usr/bin/env node
import {randomBytes} from 'node:crypto';
let value; do value=randomBytes(32); while(value.every(byte=>byte===0));
process.stdout.write(`0x${value.toString('hex')}\n`);

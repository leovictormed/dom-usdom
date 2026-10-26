#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {validateClosedMainnetRedemptionRelease} from '../sdk/closed-mainnet-redemption-release.mjs';
if(process.argv.length!==7) process.exit(64);
const read=path=>JSON.parse(readFileSync(path,'utf8'));
process.stdout.write(JSON.stringify(validateClosedMainnetRedemptionRelease({
  submission:read(process.argv[2]),packageValue:read(process.argv[3]),release:read(process.argv[4]),
  releaseConfigSha256:process.argv[5],verifierManifestSha256:process.argv[6],
}))+'\n');

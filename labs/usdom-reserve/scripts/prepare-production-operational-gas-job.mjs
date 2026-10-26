#!/usr/bin/env node
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {buildProductionOperationalGasMeasurementJob} from '../sdk/local-operational-gas-evidence.mjs';
if(process.argv.length!==4) throw new Error('usage: prepare-production-operational-gas-job RELEASE LOCAL_EVIDENCE');
const bytes=path=>readFileSync(path),sha=value=>createHash('sha256').update(value).digest('hex');
const releaseBytes=bytes(process.argv[2]),localBytes=bytes(process.argv[3]);
const job=buildProductionOperationalGasMeasurementJob({release:JSON.parse(releaseBytes),
 localEvidence:JSON.parse(localBytes),releaseSha256:sha(releaseBytes),localEvidenceSha256:sha(localBytes)});
process.stdout.write(JSON.stringify(job,null,2)+'\n');

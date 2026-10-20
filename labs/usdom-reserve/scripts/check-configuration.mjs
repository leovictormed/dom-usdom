import {readFile} from 'node:fs/promises';
import {validateConfiguration, validateProofConfiguration} from '../sdk/configuration.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
try {
  if(process.argv.length!==3) throw new Error('Usage: node scripts/check-configuration.mjs CONFIG.json');
  const configuration=parseStrictJson(await readFile(process.argv[2],'utf8'),{label:process.argv[2]});
  const kind='ethereumChainId' in configuration ? 'proof-reserve' : 'quorum-prototype';
  (kind==='proof-reserve' ? validateProofConfiguration : validateConfiguration)(configuration);
  console.log(JSON.stringify({configurationSyntaxValid:true, mainnetReadinessVerified:false,
    kind,note:'This check does not verify deployed bytecode, custody, DOM consensus, finality, issuance or operational readiness.'},null,2));
} catch(error) { console.error(`Configuration rejected: ${error.message}`); process.exitCode=1; }

import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {validateConfiguration, validateProofConfiguration} from '../sdk/configuration.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
try {
  if(process.argv.length!==3) throw new Error('Usage: node scripts/check-configuration.mjs CONFIG.json');
  const configuration=parseStrictJson((await readDirectFile(process.argv[2],{
    minimum:1,maximum:4*1024*1024,label:'configuration',
  })).toString('utf8'),{label:process.argv[2]});
  const kind='ethereumChainId' in configuration ? 'proof-reserve' : 'quorum-prototype';
  (kind==='proof-reserve' ? validateProofConfiguration : validateConfiguration)(configuration);
  console.log(JSON.stringify({configurationSyntaxValid:true, mainnetReadinessVerified:false,
    kind,note:'This check does not verify deployed bytecode, custody, DOM consensus, finality, issuance or operational readiness.'},null,2));
} catch(error) { writeReleaseFailure('check-configuration',error); process.exitCode=1; }

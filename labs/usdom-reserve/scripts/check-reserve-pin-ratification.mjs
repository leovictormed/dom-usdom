import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {prepareReservePinRatificationFromProject} from '../sdk/reserve-pin-ratification-project.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
try {
  if(process.argv.length!==5) throw new Error('usage: check-reserve-pin-ratification.mjs PROPOSAL RELEASE_CONFIG FINALIZED_BURN_VERIFIER_CONFIG');
  const bytes=await readDirectFile(path.resolve(process.argv[2]),{minimum:2,maximum:4*1024*1024,
    label:'ratification proposal'});
  const proposal=parseStrictJsonBytes(bytes,{label:'ratification proposal',maxDepth:32});
  await prepareReservePinRatificationFromProject({root,releasePath:process.argv[3],verifierConfigPath:process.argv[4],proposal});
  process.stdout.write('reserve production-pin ratification proposal verified offline\n');
} catch(error) {writeReleaseFailure('check-reserve-pin-ratification',error);process.exitCode=1;}

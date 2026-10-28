import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {installReservePinRatificationProposal,prepareReservePinRatificationFromProject}
  from '../sdk/reserve-pin-ratification-project.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
try {
  if(process.argv.length!==5) throw new Error('usage: prepare-reserve-pin-ratification.mjs RELEASE_CONFIG FINALIZED_BURN_VERIFIER_CONFIG OUTPUT');
  const proposal=await prepareReservePinRatificationFromProject({root,releasePath:process.argv[2],verifierConfigPath:process.argv[3]});
  const installed=await installReservePinRatificationProposal(process.argv[4],
    Buffer.from(JSON.stringify(proposal,null,2)+'\n'));
  const installedProposal=parseStrictJsonBytes(installed,{label:'installed ratification proposal',maxDepth:32});
  await prepareReservePinRatificationFromProject({root,releasePath:process.argv[2],
    verifierConfigPath:process.argv[3],proposal:installedProposal});
  process.stdout.write(`reserve production-pin ratification proposal installed: ${path.resolve(process.argv[4])}\n`);
} catch(error) {writeReleaseFailure('prepare-reserve-pin-ratification',error);process.exitCode=1;}

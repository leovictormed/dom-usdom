import {writePilotFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash,randomBytes} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  buildClosedMainnetDepositPackage,validateClosedMainnetDepositPackage,
} from '../sdk/closed-mainnet-deposit.mjs';
import {readDirectFile,readDirectProjectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const releasePath='config/proof-reserve.unconfigured.json';
const walletPath=path.join(os.homedir(),'.local','share','dom-usdom','mainnet-wallet','public-identity.json');

const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');

async function readPublicWallet() {
  return readDirectFile(walletPath,{
    minimum:1,maximum:64*1024,privateMode:true,label:'public wallet identity',
  });
}

if(process.argv.length!==2) {
  console.error('Usage: npm run --silent prepare:closed-mainnet-deposit');
  process.exitCode=2;
} else {
  try {
    const funder=process.env.USDOM_DEPOSIT_FUNDER;
    if(typeof funder!=='string') throw new Error('Ledger funder address was not derived');
    const [releaseBytes,walletBytes]=await Promise.all([
      readDirectProjectFile(root,releasePath),readPublicWallet(),
    ]);
    const release=parseStrictJson(releaseBytes.toString('utf8'),{
      label:releasePath,maxBytes:256*1024,
    });
    const wallet=parseStrictJson(walletBytes.toString('utf8'),{
      label:walletPath,maxBytes:64*1024,
    });
    let salt;
    do salt='0x'+randomBytes(32).toString('hex'); while(BigInt(salt)===0n);
    const deposit=buildClosedMainnetDepositPackage({
      release,wallet,funder,salt,releaseConfigSha256:sha256(releaseBytes),
      walletIdentitySha256:sha256(walletBytes),
    });
    validateClosedMainnetDepositPackage(deposit);
    const [currentReleaseBytes,currentWalletBytes]=await Promise.all([
      readDirectProjectFile(root,releasePath,{minimum:releaseBytes.length,
        maximum:releaseBytes.length,label:releasePath}),readPublicWallet(),
    ]);
    if(!currentReleaseBytes.equals(releaseBytes)||!currentWalletBytes.equals(walletBytes)) {
      throw new Error('closed mainnet deposit inputs changed during preparation');
    }
    process.stdout.write(JSON.stringify(deposit,null,2)+'\n');
  } catch(error) {
    writePilotFailure('closed-mainnet-deposit-prepare',error);
    process.exitCode=1;
  }
}

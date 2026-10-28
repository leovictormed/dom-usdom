#!/usr/bin/env node
import {open} from 'node:fs/promises';
import {runOneKeyIosWalletConnectSigning} from '../sdk/onekey-ios-walletconnect-client.mjs';
import {OneKeyIosSigningFailure,describeOneKeyIosSigningFailure,oneKeyIosSigningExitCode,
  combineOneKeyIosSigningFailures} from '../sdk/onekey-ios-walletconnect-typed-data.mjs';

if(process.argv.length!==6) {
  console.error('usage: sign-onekey-ios-walletconnect-typed-data.mjs PRIVATE_CONFIG REQUEST PHYSICAL_EVIDENCE OUTPUT');
  process.exit(64);
}
let tty,entered=false,failure,exitCode=0;
try {
  tty=await open('/dev/tty','w');
  await runOneKeyIosWalletConnectSigning({configPath:process.argv[2],requestPath:process.argv[3],
    physicalEvidencePath:process.argv[4],outputPath:process.argv[5],displayDeepLink:async deeplink=>{
      if(entered)throw new Error('WalletConnect deeplink may be displayed only once');
      entered=true;
      await tty.write(`\u001b[?1049h\u001b[2J\u001b[HAbra este link uma unica vez no iPhone OneKey:\n\n${deeplink}\n`);
    }});
} catch(error) {
  failure=error instanceof OneKeyIosSigningFailure?error:
    new OneKeyIosSigningFailure('INITIALIZATION_FAILED','initializing-client',{cause:error});
  exitCode=oneKeyIosSigningExitCode(failure);
} finally {
  if(tty) {
    try {if(entered)await tty.write('\u001b[2J\u001b[H\u001b[?1049l');}
    catch(error) {failure=combineOneKeyIosSigningFailures(failure,
      new OneKeyIosSigningFailure('TERMINAL_RESTORE_FAILED','client-shutdown',{cause:error,exitCode:80}));exitCode=80;}
    finally {
      try {await tty.close();}
      catch(error) {failure=combineOneKeyIosSigningFailures(failure,
        new OneKeyIosSigningFailure('TERMINAL_RESTORE_FAILED','client-shutdown',{cause:error,exitCode:80}));exitCode=80;}
    }
  }
}

// Report only after leaving the private screen. Remote errors can contain
// pairing credentials, so keep diagnostics local and do not echo their text.
if(failure) {
  const diagnostic=describeOneKeyIosSigningFailure(failure);
  const cleanup=(diagnostic.cleanupFailures??[]).map(item=>
    `ONEKEY_SIGNING_CLEANUP_FAILED: phase=${item.phase} code=${item.code}\n`).join('');
  await new Promise(resolve=>process.stderr.write(
    `ONEKEY_SIGNING_FAILED: phase=${diagnostic.phase} code=${diagnostic.code}\n${diagnostic.message}\n${cleanup}`
    +(exitCode===80?'Não repita automaticamente: a conclusão segura ainda precisa ser conferida.\n':''),resolve));
} else {
  await new Promise(resolve=>process.stdout.write('Assinatura salva.\n',resolve));
}
// Durable output, session/pairing cleanup and terminal restoration have finished.
// Residual SDK timers must not retain this one-shot command or its shell lock.
process.exit(exitCode);

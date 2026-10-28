#!/usr/bin/env node
import {randomUUID} from 'node:crypto';
import {open,readFile} from 'node:fs/promises';
import {SignClient} from '@walletconnect/sign-client';
import {EphemeralWalletConnectStorage} from '../sdk/onekey-ios-walletconnect-client.mjs';
import {describeIosOnboardingFailure,executeIosOnboarding,validateReownProjectResponse}
  from '../sdk/onekey-ios-onboarding.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';

if(process.argv.length!==5)throw new Error('usage: onboard-onekey-ios-owner PROJECT_RESPONSE OWNER_ROLE OUTPUT');

const project=validateReownProjectResponse(parseStrictJsonBytes(await readFile(process.argv[2]),
  {label:'Reown project response'}));
const tty=await open('/dev/tty','r+');
const storage=new EphemeralWalletConnectStorage();
let client,privateScreen=false,currentStage='initializing',failure;

const ask=async text=>{
  await tty.write(text);
  const buffer=Buffer.alloc(256);
  const {bytesRead}=await tty.read(buffer,0,buffer.length,null);
  return buffer.subarray(0,bytesRead).toString().trim();
};
const leavePrivateScreen=async()=>{
  if(!privateScreen)return;
  await tty.write('\u001b[2J\u001b[H\u001b[?1049l');
  privateScreen=false;
};

try {
  client=await SignClient.init({projectId:project,logger:'silent',storage,telemetryEnabled:false,
    customStoragePrefix:`usdom-onboarding-${randomUUID()}`,
    metadata:{name:'USDOM Safe onboarding',description:'OneKey owner discovery',
      url:'https://github.com/leovictormed/dom-usdom',icons:[]}});
  await executeIosOnboarding({client,projectId:project,ownerRole:process.argv[3],outputPath:process.argv[4],
    timeoutMilliseconds:300_000,
    onStage:async stage=>{
      currentStage=stage;
      if(stage==='approval-received')await leavePrivateScreen();
    },
    onDeepLink:async link=>{
      privateScreen=true;
      await tty.write(`\u001b[?1049h\u001b[2J\u001b[HAbra uma vez no iPhone o NOVO link desta execução:\n${link}\n\nCopie este link novamente: links de tentativas anteriores não correspondem a esta conexão.\nAguardando aprovação no OneKey App.\nNão pressione ENTER no Termius.\n`);
    },
    confirmOnDevice:async({address})=>{
      await leavePrivateScreen();
      await tty.write('\nA conexão com o aplicativo não exibe o endereço automaticamente no dispositivo.\n'
        +'No OneKey App, selecione a mesma conta vinculada à sua Classic 1S.\n'
        +'Toque em Receber (Receive), escolha Ethereum (ETH) e toque em Verificar no dispositivo (Verify on device).\n'
        +'Mantenha a OneKey ligada, desbloqueada e conectada por Bluetooth ao iPhone.\n'
        +'Compare o endereço completo no visor físico com o endereço abaixo.\n'
        +'Se o endereço não aparecer ou for diferente, não confirme; use Ctrl+C para cancelar.\n');
      const expected=`CONFIRMO ${address}`;
      let answer;
      for(let attempt=0;attempt<3;++attempt){
        answer=await ask(`Após conferir ${address} no visor físico, digite a linha COMPLETA:\n${expected}\nSua resposta: `);
        if(answer===expected||answer!=='CONFIRMO')break;
        if(attempt<2)await tty.write('Faltou o endereço após CONFIRMO. Nada foi confirmado; tente novamente abaixo.\n');
      }
      return {schema:'usdom-onekey-classic1s-human-confirmation-v1',source:'human-observed-device-screen',
        model:'classic1s',addressShownOnDevice:true,address,
        operatorConfirmed:answer===expected,mock:false};
    },
  });
} catch(error) {
  failure=error;
  process.exitCode=Number.isSafeInteger(error?.exitCode)?error.exitCode:1;
} finally {
  await leavePrivateScreen().catch(()=>{});
  try {
    client?.core?.heartbeat?.stop?.();
    if(typeof client?.core?.relayer?.transportClose==='function')await client.core.relayer.transportClose();
  } catch(error) {
    if(!failure){failure=error;process.exitCode=80;currentStage='client-shutdown';}
  } finally {
    storage.clear();
    await tty.close();
  }
}

if(failure){
  const diagnostic=describeIosOnboardingFailure(failure,currentStage);
  await new Promise(resolve=>process.stderr.write(
    `ONEKEY_ONBOARDING_FAILED: phase=${diagnostic.phase} code=${diagnostic.code}\n${diagnostic.message}\n`,resolve));
}
// This one-shot CLI has completed durable output and cleanup. WalletConnect can
// retain internal timers even after transportClose; do not leave the shell lock held.
process.exit(process.exitCode??0);

// Public local fixtures only. No production keys, RPC URLs or compiler imports.
import {spawn} from 'node:child_process';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import {JsonRpcProvider} from 'ethers';
export async function localEvm(t) {
  const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise(resolve => server.close(resolve));
  const child = spawn(process.env.USDOM_ANVIL ?? 'anvil', ['--host','127.0.0.1','--port',String(port),'--chain-id','31337','--silent'], {stdio:'ignore'});
  let spawnError; child.on('error',error=>{spawnError=error;});
  const exited = new Promise(resolve => {child.once('exit',resolve);child.once('error',resolve);});
  const provider = new JsonRpcProvider(`http://127.0.0.1:${port}`,31337,{staticNetwork:true,cacheTimeout:-1});
  provider.pollingInterval=20;
  t.after(async()=>{provider.destroy(); if(child.exitCode===null)child.kill('SIGTERM'); await exited;});
  for(let i=0;;i++) {
    try {await provider.send('eth_chainId',[]);break;}
    catch(error) {if(spawnError)throw spawnError;if(child.exitCode!==null)throw Error('Anvil exited before readiness');if(i===300)throw error;await delay(100);}
  }
  return {provider,request:({method,params=[]})=>provider.send(method,params)};
}

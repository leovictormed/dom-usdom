import {EventEmitter} from 'node:events';
import {ONEKEY_NOTIFY_CHARACTERISTIC_UUID,ONEKEY_SERVICE_UUID,
 ONEKEY_WRITE_CHARACTERISTIC_UUID} from '@onekeyfe/hd-shared';

const normalize=value=>String(value??'').toLowerCase().replaceAll('-','');
const service=normalize(ONEKEY_SERVICE_UUID);
const writeUuid=normalize(ONEKEY_WRITE_CHARACTERISTIC_UUID);
const notifyUuid=normalize(ONEKEY_NOTIFY_CHARACTERISTIC_UUID);
const idPattern=/^[A-Za-z0-9._:-]{1,128}$/u;

export function createOneKeyLinuxNobleAdapter({noble,scanMilliseconds=3000,
 operationMilliseconds=10000}={}) {
 if(!noble||typeof noble.on!=='function'||typeof noble.startScanning!=='function') throw new Error('invalid Noble host');
 const events=new EventEmitter(),discovered=new Map(),connected=new Map(),connecting=new Map();
 const characteristics=new Map(),pending=new Set();
 let closed=false,scanTimer,generation=0;
 const assertOpen=()=>{if(closed)throw new Error('BLE adapter is closed');};
 const current=epoch=>{if(closed||epoch!==generation)throw new Error('BLE operation cancelled');};
 const disconnectPeripheral=peripheral=>new Promise(resolve=>{
  if(!peripheral||peripheral.state==='disconnected') return resolve();
  peripheral.disconnect(()=>resolve());
 });
 const callbackOperation=(start,label,{epoch=generation,onLate}={})=>new Promise((resolve,reject)=>{
  let settled=false;
  const finish=(error,value)=>{if(settled){if(onLate)void onLate(error,value);return;}
   settled=true;clearTimeout(timer);pending.delete(cancel);
   if(epoch!==generation||closed)reject(new Error('BLE operation cancelled'));
   else if(error)reject(error);else resolve(value);};
  const cancel=()=>{if(settled)return;settled=true;clearTimeout(timer);pending.delete(cancel);reject(new Error('BLE operation cancelled'));};
  const timer=setTimeout(()=>{if(settled)return;settled=true;pending.delete(cancel);reject(new Error(`${label} timed out`));},operationMilliseconds);
  pending.add(cancel);try{start(finish);}catch(error){finish(error);}
 });
 const discover=peripheral=>{const uuids=peripheral?.advertisement?.serviceUuids??[];
  if(idPattern.test(peripheral?.id??'')&&uuids.some(value=>normalize(value)===service)
    &&typeof peripheral.advertisement?.localName==='string'&&peripheral.advertisement.localName.trim()) discovered.set(peripheral.id,peripheral);};
 noble.on('discover',discover);
 const stopScan=async()=>{clearTimeout(scanTimer);scanTimer=undefined;
  await callbackOperation(done=>noble.stopScanning(error=>done(error)),'BLE stop scan').catch(error=>{
   if(noble.state!=='poweredOn')return;throw error;
  });};
 const enumerate=async()=>{assertOpen();if(noble.state!=='poweredOn')throw new Error(`Bluetooth unavailable: ${noble.state}`);
  discovered.clear();const epoch=generation;
  await new Promise((resolve,reject)=>{let settled=false;
   const cancel=()=>{if(settled)return;settled=true;clearTimeout(scanTimer);pending.delete(cancel);reject(new Error('BLE operation cancelled'));};
   pending.add(cancel);noble.startScanning([ONEKEY_SERVICE_UUID],true,error=>{
    if(settled)return;if(error){settled=true;pending.delete(cancel);reject(error);return;}
    scanTimer=setTimeout(()=>{if(settled)return;settled=true;pending.delete(cancel);resolve();},scanMilliseconds);
   });});
  current(epoch);await stopScan();current(epoch);
  return [...discovered.values()].map(p=>({id:p.id,name:p.advertisement.localName,state:p.state??'disconnected',mtu:p.mtu}));};
 const getPeripheral=id=>{if(!idPattern.test(id))throw new Error('invalid BLE device id');
  const peripheral=discovered.get(id)||connected.get(id)||connecting.get(id);if(!peripheral)throw new Error('BLE device not discovered');return peripheral;};
 const disconnect=async id=>{const peripheral=connected.get(id)||connecting.get(id);if(!peripheral)return;
  await callbackOperation(done=>peripheral.disconnect(error=>done(error)),'BLE disconnect',{onLate:()=>{}});
  connected.delete(id);connecting.delete(id);characteristics.delete(id);};
 const connect=async id=>{assertOpen();const epoch=generation,peripheral=getPeripheral(id);connecting.set(id,peripheral);
  const disconnectListener=()=>{connected.delete(id);connecting.delete(id);characteristics.delete(id);
   events.emit('disconnect',{id,name:peripheral.advertisement.localName,reason:'device-disconnected'});};
  peripheral.once('disconnect',disconnectListener);
  try {
   await callbackOperation(done=>peripheral.connect(error=>done(error)),'BLE connect',{epoch,
    onLate:()=>disconnectPeripheral(peripheral)});current(epoch);connecting.delete(id);connected.set(id,peripheral);
   const services=await callbackOperation(done=>peripheral.discoverServices([ONEKEY_SERVICE_UUID],(error,value)=>done(error,value)),
    'BLE service discovery',{epoch,onLate:()=>disconnectPeripheral(peripheral)});current(epoch);
   const selected=services.find(value=>normalize(value.uuid)===service);if(!selected)throw new Error('OneKey BLE service missing');
   const chars=await callbackOperation(done=>selected.discoverCharacteristics([],(error,value)=>done(error,value)),
    'BLE characteristic discovery',{epoch,onLate:()=>disconnectPeripheral(peripheral)});current(epoch);
   const write=chars.find(value=>normalize(value.uuid)===writeUuid),notify=chars.find(value=>normalize(value.uuid)===notifyUuid);
   if(!write||!notify||!write.properties?.some(value=>['write','writeWithoutResponse'].includes(value))
     ||!notify.properties?.includes('notify')) throw new Error('OneKey BLE characteristics rejected');
   characteristics.set(id,{write,notify});
  } catch(error) {characteristics.delete(id);connected.delete(id);connecting.delete(id);
   peripheral.removeListener('disconnect',disconnectListener);await disconnectPeripheral(peripheral);throw error;}
 };
 const subscribe=async id=>{const epoch=generation,pair=characteristics.get(id);if(!pair)throw new Error('BLE device not connected');
  const onData=data=>events.emit('notification',id,Buffer.from(data).toString('hex'));
  pair.notify.on('data',onData);
  try {await callbackOperation(done=>pair.notify.subscribe(error=>done(error)),'BLE subscribe',{epoch,
   onLate:()=>disconnectPeripheral(connected.get(id))});current(epoch);}
  catch(error){pair.notify.removeListener('data',onData);await disconnectPeripheral(connected.get(id));
   connected.delete(id);characteristics.delete(id);throw error;}};
 const unsubscribe=async id=>{const pair=characteristics.get(id);if(!pair)return;
  await callbackOperation(done=>pair.notify.unsubscribe(error=>done(error)),'BLE unsubscribe');pair.notify.removeAllListeners('data');};
 const write=async(id,data)=>{const epoch=generation,pair=characteristics.get(id);
  if(!pair||!/^(?:[0-9a-fA-F]{2}){1,244}$/u.test(data))throw new Error('invalid BLE write');
  await callbackOperation(done=>pair.write.write(Buffer.from(data,'hex'),true,error=>done(error)),'BLE write',{epoch,
   onLate:()=>disconnectPeripheral(connected.get(id))});current(epoch);};
 const cancelPairing=async()=>{generation+=1;clearTimeout(scanTimer);for(const cancel of [...pending])cancel();
  await new Promise(resolve=>noble.stopScanning(()=>resolve())).catch(()=>{});
  await Promise.all([...new Set([...connected.values(),...connecting.values()])].map(disconnectPeripheral));
  connected.clear();connecting.clear();characteristics.clear();};
 const listener=event=>callback=>{events.on(event,callback);return()=>events.off(event,callback);};
 return Object.freeze({enumerate,stopScan,getDevice:async id=>{const p=getPeripheral(id);return{id:p.id,
  name:p.advertisement.localName,state:p.state??'disconnected',mtu:p.mtu};},connect,
  release:async(id,keepSession)=>{if(!keepSession)await disconnect(id);},disconnect,subscribe,unsubscribe,write,cancelPairing,
  checkAvailability:async()=>noble.state==='poweredOn',onNotification:listener('notification'),onMtuChanged:listener('mtu'),
  onDeviceDisconnected:listener('disconnect'),async close(){if(closed)return;await cancelPairing();closed=true;
   noble.off('discover',discover);events.removeAllListeners();}});
}

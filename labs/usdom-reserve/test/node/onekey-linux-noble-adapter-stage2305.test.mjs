import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {ONEKEY_NOTIFY_CHARACTERISTIC_UUID,ONEKEY_SERVICE_UUID,ONEKEY_WRITE_CHARACTERISTIC_UUID} from '@onekeyfe/hd-shared';
import {createOneKeyLinuxNobleAdapter} from '../../sdk/onekey-linux-noble-adapter.mjs';

class FakeNoble extends EventEmitter {state='poweredOn';startScanning(_services,_duplicates,done){done();}
 stopScanning(done){done();}}
const characteristic=(uuid,properties)=>Object.assign(new EventEmitter(),{uuid,properties,
 subscribe(done){done();},unsubscribe(done){done();},write(_bytes,_withoutResponse,done){done();}});
function peripheral(id='classic-a',{lateConnect=false,badProperties=false}={}) {
 const p=Object.assign(new EventEmitter(),{id,state:'disconnected',mtu:185,
  advertisement:{localName:'OneKey Classic 1S',serviceUuids:[ONEKEY_SERVICE_UUID]},disconnects:0,
  connect(done){if(lateConnect)setTimeout(()=>{this.state='connected';done();},30);else{this.state='connected';done();}},
  disconnect(done){this.disconnects+=1;this.state='disconnected';done();},
  discoverServices(_ids,done){done(null,[{uuid:ONEKEY_SERVICE_UUID,discoverCharacteristics(_filter,next){next(null,[
   characteristic(ONEKEY_WRITE_CHARACTERISTIC_UUID,badProperties?[]:['writeWithoutResponse']),
   characteristic(ONEKEY_NOTIFY_CHARACTERISTIC_UUID,['notify'])]);}}]);}});return p;
}

test('Noble adapter clears discovery, exposes exact transport shapes and notifications',async()=>{
 const noble=new FakeNoble(),adapter=createOneKeyLinuxNobleAdapter({noble,scanMilliseconds:1,operationMilliseconds:50});
 const first=peripheral();setTimeout(()=>noble.emit('discover',first),0);assert.equal((await adapter.enumerate()).length,1);
 assert.equal((await adapter.enumerate()).length,0);
 noble.emit('discover',first);await adapter.connect(first.id);assert.deepEqual(await adapter.getDevice(first.id),
  {id:first.id,name:'OneKey Classic 1S',state:'connected',mtu:185});
 let notification;adapter.onNotification((id,data)=>{notification={id,data};});await adapter.subscribe(first.id);
 const pair=[...first.listeners('disconnect')];assert.ok(pair.length>0);
 await adapter.write(first.id,'aabb');await adapter.disconnect(first.id);assert.ok(first.disconnects>=1);
 await adapter.close();
});

test('cancellation quarantines a late connection and partial setup failure disconnects',async()=>{
 const noble=new FakeNoble(),late=peripheral('late',{lateConnect:true});
 const adapter=createOneKeyLinuxNobleAdapter({noble,scanMilliseconds:1,operationMilliseconds:100});
 noble.emit('discover',late);const connecting=adapter.connect(late.id);await new Promise(resolve=>setTimeout(resolve,2));
 await adapter.cancelPairing();await assert.rejects(connecting,/cancelled/u);await new Promise(resolve=>setTimeout(resolve,40));
 assert.equal(late.state,'disconnected');assert.ok(late.disconnects>=1);await adapter.close();
 const noble2=new FakeNoble(),bad=peripheral('bad',{badProperties:true});
 const adapter2=createOneKeyLinuxNobleAdapter({noble:noble2,scanMilliseconds:1,operationMilliseconds:50});
 noble2.emit('discover',bad);await assert.rejects(adapter2.connect(bad.id),/characteristics rejected/u);
 assert.equal(bad.state,'disconnected');await adapter2.close();
});

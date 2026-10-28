import test from 'node:test';
import assert from 'node:assert/strict';
import {dirname} from 'node:path';
import {readBleHandoffRequest,writeBleHandoffResponse} from '../../sdk/onekey-electron-ble-handoff.mjs';
import {openApprovedOneKeyBluetooth} from '../../sdk/onekey-bluetooth-factory.mjs';

const deviceId='classic-1s-test';
test('factory performs private authenticated handoff and preserves SDK result shape',async()=>{
 let request;
 const runtime={timeoutMilliseconds:1000,async launch({requestPath,onChild}){onChild({kill(){}});
  request=readBleHandoffRequest(requestPath);assert.equal(request.payload.ceremonyPolicy.expectedDeviceId,deviceId);
  writeBleHandoffResponse({directory:dirname(requestPath),request,result:{v:'0x0',r:`0x${'11'.repeat(32)}`,s:`0x${'22'.repeat(32)}`}});
  onChild(undefined);}};
 const opened=await openApprovedOneKeyBluetooth({expectedDeviceId:deviceId,approvedFirmwareVersions:['4.10.0'],runtime});
 const result=await opened.device.evmSignTransaction(opened.connectId,deviceId,{path:"m/44'/60'/0'/0/0"});
 assert.equal(result.success,true);assert.equal(result.payload.v,'0x0');assert.equal(result.payload.r,`0x${'11'.repeat(32)}`);
 assert.equal(result.payload.s,`0x${'22'.repeat(32)}`);
 assert.equal(request.action,'evmSignTransaction');await opened.close();
});

test('factory rejects wrong identity, concurrent use and unapproved production gate',async()=>{
 await assert.rejects(openApprovedOneKeyBluetooth({expectedDeviceId:deviceId}),/not approved/u);
 let release;const runtime={timeoutMilliseconds:1000,launch:()=>new Promise(resolve=>{release=resolve;})};
 const opened=await openApprovedOneKeyBluetooth({expectedDeviceId:deviceId,approvedFirmwareVersions:['4.10.0'],runtime});
 assert.throws(()=>opened.device.evmGetAddress(opened.connectId,'other',{}),/identity mismatch/u);
 const first=opened.device.evmGetAddress(opened.connectId,deviceId,{});
 await assert.rejects(opened.device.evmGetAddress(opened.connectId,deviceId,{}),/busy/u);release();
 await assert.rejects(first,/response|missing/u);await opened.close();
});

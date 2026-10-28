import HardwareSDK from '@onekeyfe/hd-common-connect-sdk';

const api=HardwareSDK.default?.default??HardwareSDK.default??HardwareSDK;
const request=window.usdomOneKeyCeremony.request;
const policy=request?.payload?.ceremonyPolicy;
const sdkRequest=request?.payload?.sdkRequest;
if(!policy||Object.keys(policy).sort().join(',')!=='approvedFirmwareVersions,expectedDeviceId'
  ||typeof policy.expectedDeviceId!=='string'||policy.expectedDeviceId.length<1
  ||!Array.isArray(policy.approvedFirmwareVersions)||policy.approvedFirmwareVersions.length===0
  ||!policy.approvedFirmwareVersions.every(value=>/^\d+\.\d+\.\d+$/u.test(value))) {
 throw new Error('OneKey ceremony policy rejected');
}
let connectId,operationPromise,disposed=false;
const dispose=async()=>{if(disposed)return;disposed=true;await api.dispose();};
window.addEventListener('beforeunload',()=>{void dispose();},{once:true});
try {
 await api.init({env:'desktop-web-ble',debug:false,fetchConfig:false});
 document.body.dataset.ready='true';
 const devices=await api.searchDevices();
 const list=devices?.payload??devices;
 if(!Array.isArray(list)||list.length!==1) throw new Error('exactly one OneKey BLE device is required');
 const live=list[0]; connectId=live.connectId??live.path??live.id;
 const state=await api.getDeviceState(connectId,{scope:'firmware'});
 const deviceId=state?.payload?.identity?.deviceId;
 const firmware=state?.payload?.versions?.firmware;
 if(state?.success!==true||state.payload?.protocol!=='V1'||state.payload.identity?.deviceType!=='classic1s'
   ||deviceId!==policy.expectedDeviceId||typeof firmware!=='string'
   ||!policy.approvedFirmwareVersions.includes(firmware)) throw new Error('OneKey identity or firmware rejected');
 const operation=api[request.action];
 if(typeof operation!=='function') throw new Error('OneKey operation unavailable');
 operationPromise=Promise.resolve(operation(connectId,deviceId,sdkRequest));
 let timer;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('OneKey operation timed out')),300_000);});
 let response;
 try {response=await Promise.race([operationPromise,timeout]);}
 catch(error) {
  if(connectId) await api.cancel(connectId);
  await Promise.race([operationPromise.catch(()=>{}),new Promise(resolve=>setTimeout(resolve,10_000))]);
  throw error;
 } finally {clearTimeout(timer);}
 if(response?.success!==true) throw new Error('OneKey operation failed');
 await window.usdomOneKeyCeremony.complete({action:request.action,status:'success',result:response.payload});
} catch(error) {
 if(connectId) await Promise.resolve(api.cancel(connectId)).catch(()=>{});
 await window.usdomOneKeyCeremony.fail({action:request.action,status:'failed'}).catch(()=>{});
 throw error;
} finally {await dispose();}

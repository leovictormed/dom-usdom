const KEYS=['schema','pid','urls'];
const MAX_PID=2_147_483_647;

function reject(message) { throw new Error(`private RPC proxy readiness: ${message}`); }

export function validatePrivateRpcProxyReady(value,{expectedPid}={}) {
  if(!value||typeof value!=='object'||Array.isArray(value)) reject('must be an object');
  const keys=Object.keys(value).sort();
  if(keys.length!==KEYS.length||keys.some((key,index)=>key!==[...KEYS].sort()[index])) {
    reject('has an unexpected or missing field');
  }
  if(value.schema!=='usdom-private-rpc-catalog-proxy-v1') reject('schema is unsupported');
  if(!Number.isSafeInteger(value.pid)||value.pid<1||value.pid>MAX_PID) reject('pid is invalid');
  if(expectedPid!==undefined&&value.pid!==expectedPid) reject('pid does not match the child process');
  if(!Array.isArray(value.urls)||value.urls.length<2||value.urls.length>5) {
    reject('urls must contain between two and five entries');
  }
  const seen=new Set();
  let commonPort;
  let commonToken;
  for(let index=0;index<value.urls.length;index++) {
    const text=value.urls[index];
    if(typeof text!=='string'||text.length>160||seen.has(text)) reject('URL is invalid or duplicated');
    const match=/^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/([0-9a-f]{64})\/([0-4])$/.exec(text);
    if(!match||Number(match[1])>65535||Number(match[3])!==index) reject('URL is not canonical');
    if(index===0) { commonPort=match[1]; commonToken=match[2]; }
    if(match[1]!==commonPort||match[2]!==commonToken) reject('URLs do not share one proxy capability');
    seen.add(text);
  }
  return {schema:value.schema,pid:value.pid,urls:[...value.urls]};
}

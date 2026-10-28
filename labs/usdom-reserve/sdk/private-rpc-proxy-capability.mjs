import {timingSafeEqual} from 'node:crypto';

export function matchPrivateRpcProxyCapabilityPath(value,capability,sourceCount) {
  if(typeof value!=='string'||!Buffer.isBuffer(capability)||capability.length!==32
      ||!Number.isSafeInteger(sourceCount)||sourceCount<1||sourceCount>5) return -1;
  const match=/^\/([0-9a-f]{64})\/([0-4])$/.exec(value);
  if(!match) return -1;
  const presented=Buffer.from(match[1],'hex');
  const matches=timingSafeEqual(presented,capability);
  presented.fill(0);
  const index=Number(match[2]);
  return matches&&index<sourceCount?index:-1;
}

import {closeSync,fstatSync,openSync,readFileSync,constants} from 'node:fs';

export function readPrivateRawTransaction(file) {
  if(typeof file!=='string'||file.length===0) throw new Error('private raw transaction file is required');
  let descriptor,bytes;
  try {
    descriptor=openSync(file,constants.O_RDONLY|constants.O_NOFOLLOW);
    const stat=fstatSync(descriptor);
    if(!stat.isFile()||stat.nlink!==1||(stat.mode&0o777)!==0o600||stat.uid!==process.getuid()
        ||stat.size<3||stat.size>1024*1024) {
      throw new Error('private raw transaction must be a current-user 0600 single-link bounded file');
    }
    bytes=readFileSync(descriptor);
  } finally { if(descriptor!==undefined) closeSync(descriptor); }
  let raw;
  try { raw=bytes.toString('ascii').trim(); } finally { bytes?.fill(0); }
  if(!/^0x[0-9a-f]+$/.test(raw)||raw.length%2!==0) throw new Error('private raw transaction is malformed');
  return raw;
}

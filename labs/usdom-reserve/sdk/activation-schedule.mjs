import {blake2b} from '@noble/hashes/blake2b';
import {concat,getBytes,hexlify,toBeHex,toUtf8Bytes,zeroPadValue} from 'ethers';
import {uint} from './reserve.mjs';

const magic=toUtf8Bytes('UDACTV01');
const tag=toUtf8Bytes('DOM:usdom-v4-activation-schedule:v1');
const zeroHash='0x'+'00'.repeat(32);
const networks=new Set([0x444f4d31n,0x444f4d54n,0x444f4d52n]);

function hash(value,name) {
  if(typeof value!=='string' || !/^0x[0-9a-fA-F]{64}$/.test(value)
      || value.toLowerCase()===zeroHash) throw new Error(`${name} must be nonzero bytes32`);
  return value.toLowerCase();
}

/** Encode and commit the exact UDACTV01 activation schedule used by Rust consensus. */
export function activationSchedule(input) {
  if(!input || typeof input!=='object' || Array.isArray(input)
      || Object.keys(input).length!==4
      || !['networkMagic','chainId','firstV4Height','emptyStateRoot'].every(name=>name in input)) {
    throw new Error('exact activation schedule fields required');
  }
  const networkMagic=uint(input.networkMagic,32);
  const chainId=hash(input.chainId,'chainId');
  const firstV4Height=uint(input.firstV4Height,64);
  const emptyStateRoot=hash(input.emptyStateRoot,'emptyStateRoot');
  if(!networks.has(networkMagic) || firstV4Height===0n) throw new Error('invalid activation schedule');
  const bytes=concat([
    magic,zeroPadValue(toBeHex(1),2),zeroPadValue(toBeHex(networkMagic),4),chainId,
    zeroPadValue(toBeHex(firstV4Height),8),emptyStateRoot,
  ]);
  if(getBytes(bytes).length!==86) throw new Error('invalid activation schedule encoding');
  const tagLength=new Uint8Array([tag.length&255,tag.length>>>8]);
  const commitment=hexlify(blake2b(getBytes(concat([tagLength,tag,bytes])),{dkLen:32}));
  return {networkMagic,chainId,firstV4Height,emptyStateRoot,bytes,commitment};
}

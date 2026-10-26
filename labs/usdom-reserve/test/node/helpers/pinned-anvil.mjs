import {createHash} from 'node:crypto';
import {readFile,realpath,stat} from 'node:fs/promises';

export const ANVIL_PATH='/home/leonardov/.foundry/bin/anvil';
export const ANVIL_SHA256='00f97668e1ae0fcca118fd7d2d1b6d25c0496447a523ca6bc2dfd10958c99604';

export async function pinnedAnvil() {
  const [resolved,metadata,bytes]=await Promise.all([
    realpath(ANVIL_PATH),stat(ANVIL_PATH,{bigint:true}),readFile(ANVIL_PATH),
  ]);
  if(resolved!==ANVIL_PATH||!metadata.isFile()||metadata.nlink!==1n
      ||(metadata.mode&0o022n)!==0n||(metadata.mode&0o111n)===0n
      ||(metadata.uid!==0n&&metadata.uid!==BigInt(process.getuid()))) {
    throw new Error('pinned Anvil executable metadata is unsafe');
  }
  if(createHash('sha256').update(bytes).digest('hex')!==ANVIL_SHA256) {
    throw new Error('pinned Anvil executable hash mismatch');
  }
  const after=await stat(ANVIL_PATH,{bigint:true});
  if(after.dev!==metadata.dev||after.ino!==metadata.ino||after.size!==metadata.size
      ||after.mtimeNs!==metadata.mtimeNs||after.ctimeNs!==metadata.ctimeNs) {
    throw new Error('pinned Anvil executable changed during authentication');
  }
  return ANVIL_PATH;
}

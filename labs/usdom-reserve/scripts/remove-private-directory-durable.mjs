import {randomBytes} from 'node:crypto';
import {constants} from 'node:fs';
import {lstat,open,readdir,realpath,rename,rm} from 'node:fs/promises';
import path from 'node:path';

if(process.argv.length!==3||!path.isAbsolute(process.argv[2])) {
  throw new Error('one absolute private directory path is required');
}
const target=path.resolve(process.argv[2]),parent=path.dirname(target),name=path.basename(target);
let handle;
try {
  handle=await open(parent,constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  const parentMetadata=await handle.stat({bigint:true});
  const uid=BigInt(process.getuid());
  const descriptorParent=`/proc/self/fd/${handle.fd}`;
  if(await realpath(descriptorParent)!==parent||parentMetadata.uid!==uid
      ||(parentMetadata.mode&0o777n)!==0o700n) throw new Error('private parent is unsafe');
  const source=path.join(descriptorParent,name);
  const escaped=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const tombstonePattern=new RegExp(`^\\.${escaped}\\.(?:invalid|purge)\\.[0-9a-f]{24}$`);
  async function purgeOrphans() {
    const candidates=(await readdir(descriptorParent)).filter(entry=>tombstonePattern.test(entry));
    if(candidates.length>64) throw new Error('private directory tombstone bound exceeded');
    for(const entry of candidates) {
      const orphan=path.join(descriptorParent,entry);
      let metadata;
      try { metadata=await lstat(orphan,{bigint:true}); }
      catch(error) { if(error?.code==='ENOENT') continue; throw error; }
      if(!metadata.isDirectory()||metadata.isSymbolicLink()||metadata.uid!==uid
          ||(metadata.mode&0o777n)!==0o700n) {
        throw new Error('private directory tombstone is unsafe');
      }
      const claimed=path.join(descriptorParent,`.${name}.purge.${randomBytes(12).toString('hex')}`);
      try { await rename(orphan,claimed); }
      catch(error) { if(error?.code==='ENOENT') continue; throw error; }
      await handle.sync();
      try { await rm(claimed,{recursive:true,force:false}); }
      catch(error) {
        // A concurrent remover may atomically reclaim this purge tombstone
        // after our rename. ENOENT proves that the direct claimed name is no
        // longer ours; every other failure remains fatal.
        if(error?.code!=='ENOENT') throw error;
      }
      await handle.sync();
    }
  }
  // A SIGKILL may land after rename but before recursive deletion. Recover
  // bounded, direct, owner-only tombstones before inspecting the live name.
  await purgeOrphans();
  let metadata;
  try { metadata=await lstat(source,{bigint:true}); }
  catch(error) { if(error?.code!=='ENOENT') throw error; }
  if(metadata) {
    if(!metadata.isDirectory()||metadata.isSymbolicLink()||metadata.uid!==uid
        ||(metadata.mode&0o777n)!==0o700n) throw new Error('private directory is unsafe');
    const tombstone=path.join(descriptorParent,`.${name}.invalid.${randomBytes(12).toString('hex')}`);
    try { await rename(source,tombstone); }
    catch(error) { if(error?.code!=='ENOENT') throw error; }
    await handle.sync();
    await purgeOrphans();
  }
  const named=await lstat(parent,{bigint:true});
  if(await realpath(parent)!==parent||named.dev!==parentMetadata.dev||named.ino!==parentMetadata.ino
      ||named.uid!==uid||named.mode!==parentMetadata.mode) throw new Error('private parent changed');
} finally { await handle?.close(); }

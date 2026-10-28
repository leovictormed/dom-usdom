import {createHash} from 'node:crypto';
import {lstat,readdir} from 'node:fs/promises';
import path from 'node:path';
import {readDirectFile} from './direct-project-file.mjs';

const run=/^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$/;
const excluded=new Set(['artifact-manifest.json','capacity-report.json','run-status.json']);
export async function buildFinalizedBurnCapacityArtifactManifest(runRoot,runId) {
  if(!path.isAbsolute(runRoot)||!run.test(runId)) throw new Error('finalized-burn capacity run identity is invalid');
  const files=[];
  async function walk(directory,relative='') {
    const entries=await readdir(directory,{withFileTypes:true});
    for(const entry of entries.sort((a,b)=>a.name.localeCompare(b.name))) {
      const childRelative=relative?`${relative}/${entry.name}`:entry.name;
      if(relative===''&&excluded.has(entry.name)) continue;
      const absolute=path.join(directory,entry.name),metadata=await lstat(absolute,{bigint:true});
      if(entry.isDirectory()&&!entry.isSymbolicLink()) {
        if(metadata.uid!==BigInt(process.getuid())||(metadata.mode&0o077n)!==0n) throw new Error('unsafe finalized-burn capacity directory');
        await walk(absolute,childRelative);
      } else {
        if(!entry.isFile()||entry.isSymbolicLink()||metadata.nlink!==1n||metadata.uid!==BigInt(process.getuid())
            ||(metadata.mode&0o077n)!==0n) throw new Error('unsafe finalized-burn capacity artifact');
        const bytes=await readDirectFile(absolute,{minimum:1,maximum:512*1024*1024,privateMode:true,label:'finalized-burn capacity artifact'});
        files.push({path:childRelative,sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length});
        if(files.length>10000) throw new Error('finalized-burn capacity artifact count exceeds bound');
      }
    }
  }
  await walk(runRoot);
  if(files.length<1) throw new Error('finalized-burn capacity artifact manifest is empty');
  const manifest={schema:'usdom-finalized-burn-capacity-artifact-manifest/v1',runId,files};
  return Object.freeze({manifest:Object.freeze(manifest),bytes:Buffer.from(JSON.stringify(manifest,null,2)+'\n')});
}

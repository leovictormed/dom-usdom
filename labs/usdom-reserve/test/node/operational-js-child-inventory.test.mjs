import assert from 'node:assert/strict';
import {readdir,readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const excluded=new Set(['node_modules','scripts','sdk','test']);

async function javascriptFiles(directory=root) {
  const files=[];
  for(const entry of await readdir(directory,{withFileTypes:true})) {
    if(entry.isSymbolicLink()) continue;
    const absolute=path.join(directory,entry.name);
    if(entry.isDirectory()) {
      if(directory===root&&excluded.has(entry.name)) continue;
      files.push(...await javascriptFiles(absolute));
    } else if(entry.isFile()&&/\.(?:mjs|js)$/.test(entry.name)) files.push(absolute);
  }
  return files;
}

test('operational JavaScript outside scripts and SDK has no hidden child boundary',async()=>{
  const files=await javascriptFiles();
  assert.deepEqual(files,[],`unexpected operational JavaScript requires child-process audit: ${
    files.map(file=>path.relative(root,file)).join(', ')}`);
  const monitoring=await readdir(path.join(root,'monitoring'),{withFileTypes:true});
  assert(monitoring.length>0,'monitoring policy inventory is unexpectedly empty');
  for(const entry of monitoring) {
    assert(entry.isFile()&&!/\.(?:mjs|js)$/.test(entry.name),
      `monitoring executable requires child-process audit: ${entry.name}`);
    const source=await readFile(path.join(root,'monitoring',entry.name),'utf8');
    assert.doesNotMatch(source,/node:child_process|\bexecFile\s*\(|\bspawn\s*\(/);
  }
});

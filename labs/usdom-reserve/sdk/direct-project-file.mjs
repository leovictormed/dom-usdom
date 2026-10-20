import {lstat,readFile,realpath} from 'node:fs/promises';
import path from 'node:path';

export async function readDirectProjectFile(root,relative) {
  if(typeof relative!=='string') throw new Error('release path is not a string');
  const absolute=path.resolve(root,relative);
  if(absolute===root || !absolute.startsWith(root+path.sep)) {
    throw new Error('release path escapes project root');
  }
  const [resolved,metadata]=await Promise.all([realpath(absolute),lstat(absolute)]);
  if(resolved!==absolute || !metadata.isFile()) {
    throw new Error('release path is not a direct regular file');
  }
  return readFile(absolute);
}

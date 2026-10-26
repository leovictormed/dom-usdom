import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

for(const name of ['commit-release-source.sh','commit-release-evidence.sh']) {
  test(`${name} locks the Git directory inode without a persistent lock artifact`,async()=>{
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/git_directory=\$\(realpath --/);
    assert.match(source,/test -d "\$git_directory"; test ! -L "\$git_directory"/);
    assert.match(source,/stat -Lc '%u' "\$git_directory"/);
    assert.match(source,/\(\( \(8#\$git_directory_mode & 8#022\) == 0 \)\)/);
    assert.match(source,/exec 9<"\$git_directory"\nif ! flock -n 9/);
    assert.doesNotMatch(source,/usdom-release-ceremony\.lock/);
    assert.doesNotMatch(source,/exec 9>/);
  });
}

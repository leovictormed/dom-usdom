import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

for(const name of ['commit-release-source.sh','commit-release-evidence.sh']) {
  test(`${name} pins Git across authorization and mutation`,async()=>{
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/git_bin=\$\(realpath "\$\(command -v git\)"\)/);
    assert.match(source,/git_sha256=\$\(sha256sum "\$git_bin"/);
    assert.match(source,/git_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
    assert.match(source,/git_directory_owner=/);
    assert.match(source,/assert_git_unchanged\(\)/);
    assert.ok((source.match(/assert_git_unchanged/g)??[]).length>=3);
    assert.match(source,/"\$git_bin" -C "\$repository" commit -S/);
    assert.doesNotMatch(source,/(^|[;(]\s*)git -C/m);
  });
}

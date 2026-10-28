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
    assert.match(source,/pin_release_tree_tool "\$staged_tree"[\s\S]*check-staged-sensitive-content\.mjs" 7/);
    assert.match(source,/IFS= read -r -d '' release_sensitive_scanner <&7/);
    assert.doesNotMatch(source,/release_sensitive_scanner=\$\(cat/);
    assert.match(source,/node --input-type=module --eval "\$release_sensitive_scanner"/);
    assert.doesNotMatch(source,/node \/proc\/(?:self|\$\$)\/fd\/7/);
    assert.match(source,/pin_runtime_tool npm/);
    assert.match(source,/npm\(\) \{ assert_runtime_tool npm; node "\$npm_bin" "\$@"; \}/);
    assert.match(source,/case "\$\{changed_path##\*\/\}" in/);
    assert.doesNotMatch(source,/basename "\$changed_path"/);
    assert.match(source,/export GIT_CONFIG_NOSYSTEM=1/);
    assert.match(source,/export GIT_CONFIG_GLOBAL=\/dev\/null/);
    assert.ok((source.match(/assert_git_unchanged/g)??[]).length>=3);
    assert.match(source,/"\$git_bin" -c "gpg\.ssh\.program=\$ssh_keygen_bin" -C "\$repository"\s+\\?\s*commit-tree -S -p/);
    assert.match(source,/update-ref HEAD/);
    assert.match(source,/read-tree --reset/);
    assert.doesNotMatch(source,/"\$git_bin"[^\n]* commit -S/);
    assert.doesNotMatch(source,/(^|[;(]\s*)git -C/m);
    if(name==='commit-release-source.sh') {
      assert.match(source,/ls-tree -r --name-only -z "\$staged_tree"/);
      assert.doesNotMatch(source,/diff-tree -r --name-only[^\n]*"\$before" "\$staged_tree"/);
    }
  });
}

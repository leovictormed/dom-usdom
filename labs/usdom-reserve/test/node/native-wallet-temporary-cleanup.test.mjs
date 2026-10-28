import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const script=path.join(component,'scripts','prepare-native-receiving-wallet.sh');

test('native wallet passphrase cleanup is pinned, recursive and status preserving',async()=>{
  const source=await readFile(script,'utf8');
  assert.match(source,/NODE_BIN=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/require\("fs"\)\.rmSync\(process\.argv\[1\],\{recursive:true,force:true\}\)/);
  assert.doesNotMatch(source,/trap cleanup EXIT HUP INT TERM/);
  assert.match(source,/trap 'cleanup \$\?' EXIT/);
  assert.match(source,/trap 'cleanup 129' HUP/);
  assert.match(source,/trap 'cleanup 130' INT/);
  assert.match(source,/trap 'cleanup 143' TERM/);
  assert.match(source,/unset PASSPHRASE_FIRST PASSPHRASE_SECOND/);
  assert.match(source,/SECRET_DIRECTORY_IDENTITY=\$\(stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY"\)/);
  assert.match(source,/stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY" 2>\/dev\/null\) == "\$SECRET_DIRECTORY_IDENTITY"/);
  assert.match(source,/# Do not erase a pathname that was replaced after collecting passphrases\.[\s\S]*status=1/);
  assert.match(source,/assert_node_unchanged\n"\$NODE_BIN" "\$SCRIPT_DIRECTORY\/install-private-file-immutable-stdin\.mjs"/);
});

test('local signal cleanup erases nested tmpfs-like secret tree and returns 143',async()=>{
  const root=await mkdtemp(path.join(tmpdir(),'usdom-wallet-cleanup-'));
  await writeFile(path.join(root,'password'),'do-not-persist',{mode:0o600});
  const body=`set -euo pipefail
temporary=$1
cleanup() {
  local status=\${1:-$?}
  trap - EXIT HUP INT TERM
  node -e 'require("fs").rmSync(process.argv[1],{recursive:true,force:true})' "$temporary" || status=1
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 143' TERM
kill -TERM $$
`;
  const result=spawnSync('bash',['-c',body,'bash',root],{encoding:'utf8',
    env:{PATH:`/usr/lib/chatgpt/resources/cua_node/bin:${process.env.PATH}`}});
  assert.equal(result.status,143,result.stderr);
  await assert.rejects(access(root));
});

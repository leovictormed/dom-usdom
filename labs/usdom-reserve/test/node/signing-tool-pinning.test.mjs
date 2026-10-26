import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const signer=new URL('../../scripts/sign-release-authorizations.sh',import.meta.url);
test('checkpoint SHA framing rejects whitespace, extra lines and malformed digests',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'usdom-sha-frame-'));
  const file=join(directory,'request.sha256');
  const check='set -e; exec 8<"$1"; IFS= read -r value <&8; if IFS= read -r _ <&8; then exit 1; fi; exec 8<&-; [[ "$value" =~ ^[0-9a-f]{64}$ ]]';
  try {
    for(const [value,accepted] of [
      ['a'.repeat(64)+'\n',true],
      ['a'.repeat(64),false],
      ['A'.repeat(64)+'\n',false],
      ['a'.repeat(64)+' \n',false],
      ['a'.repeat(64)+'\n\n',false],
      ['a'.repeat(64)+'\n'+'b'.repeat(64)+'\n',false],
      ['a'.repeat(63)+'\n',false],
    ]) {
      await writeFile(file,value);
      assert.equal(spawnSync('bash',['-c',check,'bash',file]).status===0,accepted,value);
    }
  } finally { await rm(directory,{recursive:true,force:true}); }
});
test('release and native Ledger ceremony pins cast after TTY authorization',async()=>{
  const source=await readFile(signer,'utf8');
  assert.match(source,/sha256_bin=\$\(realpath "\$\(command -v sha256sum\)"\)/);
  assert.match(source,/assert_sha256_unchanged/);
  assert.match(source,/cmp_bin=\$\(realpath "\$\(command -v cmp\)"\)/);
  assert.match(source,/cmp_sha256=\$\(sha256_file "\$cmp_bin"\)/);
  assert.match(source,/assert_cmp_unchanged/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cmp\s+-s/m);
  assert.doesNotMatch(source,/\|\s*tr\b/);
  assert.match(source,/\$'\\r'/);
  assert.match(source,/signature=\$\("\$timeout_bin"[\s\S]*"\$cast_bin" wallet sign[\s\S]*\[\[ "\$signature" != \*\$'\\r'\*/);
  assert.match(source,/install-private-file-new-stdin\.mjs[\s\S]*snapshot_private "\$\{outputs\[\$name\]\}"[\s\S]*"\$cmp_bin" -s/);
  assert.match(source,/cast_bin=\$\(realpath "\$\(command -v cast\)"\)/);
  assert.match(source,/cast_sha256=\$\(sha256_file "\$cast_bin"/);
  assert.match(source,/cast_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/node_bin=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/node_sha256=\$\(sha256_file "\$node_bin"/);
  assert.match(source,/jq_bin=\$\(realpath "\$\(command -v jq\)"\)/);
  assert.match(source,/jq_sha256=\$\(sha256_file "\$jq_bin"/);
  assert.match(source,/assert_jq_unchanged/);
  assert.doesNotMatch(source,/(^|[|;(]\s*)jq\s/m);
  assert.match(source,/map\(ascii_downcase\) \| sort \| \.\[\]/);
  assert.doesNotMatch(source,/\|\s*LC_ALL=C sort/);
  assert.match(source,/assert_node_unchanged/);
  assert.doesNotMatch(source,/(^|[;(]\s*)node (?:scripts|"\$project)/m);
  assert.match(source,/cast_directory_owner=/);
  assert.match(source,/test "\$authorization" = "\$phrase"\nassert_cast_unchanged/);
  assert.ok((source.match(/assert_cast_unchanged/g)??[]).length>=5);
  assert.match(source,/"\$cast_bin" wallet sign/);
  assert.match(source,/"\$cast_bin" wallet verify/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cast wallet/m);
  assert.match(source,/\$'\\r'/);
  assert.match(source,/install-private-file-(?:new|immutable)-stdin\.mjs[\s\S]*(?:snapshot_private|snapshot) [\s\S]*"\$cmp_bin" -s/);
});

for(const [name,phrase] of [
  ['sign-checkpoint-bootstrap-ratification.sh','ASSINO CHECKPOINT BOOTSTRAP USDOM SEM TRANSMITIR'],
  ['sign-recoverable-safe-recovery.sh','ASSINO RECUPERACAO SAFE SEM TRANSMITIR'],
]) test(`${name} pins cast after TTY authorization`,async()=>{
  const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
  assert.match(source,/sha256_bin=\$\(realpath "\$\(command -v sha256sum\)"\)/);
  assert.match(source,/assert_sha256_unchanged/);
  assert.match(source,/cmp_bin=\$\(realpath "\$\(command -v cmp\)"\)/);
  assert.match(source,/cmp_sha256=\$\(sha256_file "\$cmp_bin"\)/);
  assert.match(source,/assert_cmp_unchanged/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cmp\s+-s/m);
  assert.doesNotMatch(source,/\|\s*tr\b/);
  assert.match(source,/node_bin=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/node_sha256=\$\(sha256_file "\$node_bin"/);
  assert.match(source,/jq_bin=\$\(realpath "\$\(command -v jq\)"\)/);
  assert.match(source,/jq_sha256=\$\(sha256_file "\$jq_bin"/);
  assert.match(source,/assert_jq_unchanged/);
  assert.doesNotMatch(source,/(^|[|;(]\s*)jq\s/m);
  assert.match(source,/assert_node_unchanged/);
  assert.doesNotMatch(source,/(^|[;(]\s*)node (?:scripts|"\$ROOT)/m);
  assert.doesNotMatch(source,/(?:^|[;{(]\s*)node\b/m);
  assert.doesNotMatch(source,/\bcut\s+-c/);
  assert.match(source,/cast_bin=\$\(realpath "\$\(command -v cast\)"\)/);
  assert.match(source,/cast_sha256=\$\(sha256_file "\$cast_bin"/);
  assert.match(source,/cast_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/cast_directory_owner=/);
  assert.ok(source.indexOf('assert_cast_unchanged',source.indexOf(phrase))>source.indexOf(phrase));
  assert.match(source,/"\$cast_bin" wallet address/);
  assert.match(source,/"\$cast_bin" wallet sign/);
  assert.doesNotMatch(source,/(^|[;(]\s*)cast wallet/m);
  if(name==='sign-recoverable-safe-recovery.sh') {
    assert.match(source,/signatures-\$role-\$signer_index\.json/);
    assert.match(source,/signature_draft=\$updated/);
    assert.doesNotMatch(source,/(^|[;(]\s*)mv\s/m);
  }
});

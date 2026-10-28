import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import test from 'node:test';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const scripts=[
  'package-authenticated-checkpoint-outer-evm-proof.sh',
  'package-authenticated-finalized-burn-evm-proof.sh',
];

test('EVM proof packagers bind canonical parent and bounded tool executables',()=>{
  for(const name of scripts) {
    const target=path.join(root,'scripts',name);
    const syntax=spawnSync('bash',['-n',target],{encoding:'utf8'});
    assert.equal(syntax.status,0,`${name}: ${syntax.stderr}`);
    const source=readFileSync(target,'utf8');
    assert.match(source,/size=\$\(stat -Lc '%s' "\$path"\); \(\( size > 0 && size <= 512 \* 1024 \* 1024 \)\)/,name);
    assert.match(source,/\[\[ \$\(realpath "\$directory"\) == "\$directory" \]\]/,name);
    assert.match(source,/\$\{name\}_directory_identity/,name);
    assert.match(source,/stat -Lc '%d:%i:%u:%a' "\$directory"/,name);
    assert.match(source,/\$\{!directory_identity_name\}/,name);
    const initialHash=source.indexOf('printf -v "${name}_sha256"');
    assert.ok(source.indexOf("stat -Lc '%d:%i:%s:%Y:%Z' \"$path\"",initialHash)>initialHash,name);
    const finalBoundary=source.indexOf('assert_tool_unchanged()');
    const finalHash=source.indexOf('sha256sum "$path"',finalBoundary);
    assert.ok(source.indexOf("stat -Lc '%d:%i:%s:%Y:%Z' \"$path\"",finalHash)>finalHash,name);
    assert.match(source,/for command in [^\n]* rm timeout sync; do pin_tool "\$command"; done/,name);
    const cleanup=source.slice(source.indexOf('cleanup_snapshot() {'),source.indexOf("if (($# != 0))"));
    assert.match(cleanup,/trap - EXIT HUP INT TERM/,name);
    assert.match(cleanup,/assert_tool_unchanged rm; assert_tool_unchanged timeout/,name);
    assert.match(cleanup,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$rm_bin" -rf -- "\$SNAPSHOT_ROOT"/,name);
    assert.match(cleanup,/\[\[ ! -e \$SNAPSHOT_ROOT && ! -L \$SNAPSHOT_ROOT \]\] \|\| status=1/,name);
    for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
      assert.match(source,new RegExp(`trap 'cleanup_snapshot ${status}' ${signal}`),name);
    assert.doesNotMatch(source,/(^|[^"$])rm -rf -- "\$SNAPSHOT_ROOT"/,name);
    const removal=source.slice(source.indexOf('remove_output_file() {'),source.indexOf('for directory in'));
    assert.match(removal,/case \$file in/,name);
    assert.match(removal,/\[\[ -f \$file && ! -L \$file \]\]/,name);
    assert.match(removal,/assert_tool_unchanged rm; assert_tool_unchanged timeout/,name);
    assert.match(removal,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$rm_bin" -- "\$file"/,name);
    assert.match(removal,/\[\[ ! -e \$file && ! -L \$file \]\]/,name);
    assert.equal((source.match(/remove_output_file "\$(?:final_index|destination)"/g)??[]).length,2,name);
    assert.doesNotMatch(source,/(?:^|;)\s*rm -- "\$(?:final_index|destination)"/m,name);
    assert.match(source,/for command in [^\n]* timeout sync; do pin_tool "\$command"; done/,name);
    const durability=source.slice(source.indexOf('sync_output_directory() {'),source.indexOf('for directory in'));
    assert.match(durability,/\[\[ -d \$OUTPUT_DIR && ! -L \$OUTPUT_DIR \]\]/,name);
    assert.match(durability,/assert_tool_unchanged sync; assert_tool_unchanged timeout/,name);
    assert.match(durability,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$sync_bin" -d "\$OUTPUT_DIR"/,name);
    assert.match(durability,/test "\$before" = "\$after"/,name);
    assert.equal((source.match(/sync_output_directory/g)??[]).length,3,name);
    assert.doesNotMatch(source,/(?:^|;)\s*sync -d "\$OUTPUT_DIR"/m,name);
    if(name==='package-authenticated-finalized-burn-evm-proof.sh') {
      assert.match(source,/for command in [^\n]* sha256sum mkdir rm timeout sync; do pin_tool "\$command"; done/);
      const creation=source.slice(source.indexOf('assert_tool_unchanged mkdir; assert_tool_unchanged timeout'),source.indexOf('"$node_bin" "$LAB_ROOT/scripts/read-private-file-stdout.mjs" "$JOB_DIR'));
      assert.match(creation,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$mkdir_bin" -p --/);
      assert.equal((creation.match(/assert_tool_unchanged mkdir/g)??[]).length,2);
      assert.match(creation,/"directory:\$\("\$id_bin" -u\):700"/);
      assert.match(creation,/for private_directory in/);
      assert.doesNotMatch(source,/(^|[;&|]\s*)mkdir -p/m);
      const sizing=source.slice(source.indexOf('snapshot_file_size() {'),source.indexOf('for directory in'));
      assert.match(sizing,/\[\[ \$file == "\$SNAPSHOT_ROOT\/"\* \]\]/);
      assert.match(sizing,/assert_private_file "\$file"/);
      assert.match(sizing,/assert_tool_unchanged stat; assert_tool_unchanged timeout/);
      assert.equal((sizing.match(/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$stat_bin"/g)??[]).length,3);
      assert.match(sizing,/test "\$before" = "\$after"/);
      assert.match(sizing,/\[\[ \$size =~ \^\(0\|\[1-9\]\[0-9\]\{0,19\}\)\$ \]\]/);
      assert.equal((source.match(/snapshot_file_size "\$snapshot_/g)??[]).length,8);
      assert.doesNotMatch(source,/wc -c/);
      const hashing=source.slice(source.indexOf('snapshot_sha256() {'),source.indexOf('for directory in'));
      assert.match(hashing,/\[\[ \$file == "\$SNAPSHOT_ROOT\/"\* && \$maximum =~ \^\[1-9\]\[0-9\]\{0,9\}\$ \]\]/);
      assert.match(hashing,/assert_tool_unchanged node; assert_tool_unchanged timeout/);
      assert.match(hashing,/size=\$\(snapshot_file_size "\$file"\); \(\( size <= maximum \)\)/);
      assert.match(hashing,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$node_bin" -e/);
      assert.match(hashing,/b\.length>m/);
      assert.match(hashing,/test "\$before" = "\$after"/);
      assert.match(hashing,/\[\[ \$digest =~ \^\[0-9a-f\]\{64\}\$ \]\]/);
      assert.equal((source.match(/_sha=\$\(snapshot_sha256 /g)??[]).length,5);
      assert.equal((source.match(/snapshot_sha256 "\$snapshot_/g)??[]).length,7);
      assert.match(source,/snapshot_file_size "\$snapshot_output\/\$groth_name"[\s\S]*snapshot_sha256 "\$snapshot_output\/\$groth_name"/);
      assert.match(source,/snapshot_file_size "\$snapshot_output\/\$seal_name"[\s\S]*snapshot_sha256 "\$snapshot_output\/\$seal_name"/);
      assert.match(source,/install-private-file-stdin\.mjs"[\s\S]*"\$final_index"[\s\S]*for record in "\$groth_name"[\s\S]*sha256_file "\$destination"/);
      assert.doesNotMatch(source,/sha256sum "\$snapshot_.*\| cut/);
      assert.match(source,/for command in [^\n]* sha256sum [^\n]*rm timeout sync; do pin_tool "\$command"; done/);
      const critical=source.slice(source.indexOf('critical="$SNAPSHOT_ROOT/finalized-burn-evm-critical-inputs.sha256"'),source.indexOf('"$env_bin" -u BONSAI_API_URL'));
      assert.equal((critical.match(/assert_tool_unchanged sha256sum/g)??[]).length,3);
      assert.equal((critical.match(/assert_tool_unchanged timeout/g)??[]).length,2);
      assert.equal((critical.match(/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$sha256sum_bin"/g)??[]).length,3);
      assert.match(critical,/"\$sha256sum_bin" -c "\$critical"/);
      assert.doesNotMatch(critical,/(^|[;&|]\s*)sha256sum\s/m);
    } else {
      assert.match(source,/for command in [^\n]* mkdir rm timeout sync; do pin_tool "\$command"; done/);
      const creation=source.slice(source.indexOf('assert_tool_unchanged mkdir; assert_tool_unchanged timeout'),source.indexOf('capture() {'));
      assert.match(creation,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$mkdir_bin" -p --/);
      assert.equal((creation.match(/assert_tool_unchanged mkdir/g)??[]).length,2);
      assert.match(creation,/"directory:\$\("\$id_bin" -u\):700"/);
      assert.match(creation,/for private_directory in/);
      assert.doesNotMatch(source,/(^|[;&|]\s*)mkdir -p/m);
      const capture=source.slice(source.indexOf('capture() {'),source.indexOf('for name in checkpoint-outer-proof-job-index'));
      assert.match(capture,/assert_tool_unchanged node; assert_tool_unchanged timeout/);
      assert.match(capture,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$node_bin"/);
      assert.equal((capture.match(/assert_tool_unchanged node/g)??[]).length,2);
      assert.match(capture,/assert_private_file "\$2"/);
      assert.match(source,/for command in [^\n]* sha256sum [^\n]*rm timeout sync; do pin_tool "\$command"; done/);
      const critical=source.slice(source.indexOf('critical="$SNAPSHOT_ROOT/checkpoint-outer-evm-critical-inputs.sha256"'),source.indexOf('"$env_bin" -u BONSAI_API_URL'));
      assert.equal((critical.match(/assert_tool_unchanged sha256sum/g)??[]).length,3);
      assert.equal((critical.match(/assert_tool_unchanged timeout/g)??[]).length,2);
      assert.equal((critical.match(/"\$timeout_bin" --foreground --signal=TERM/g)??[]).length,3);
      assert.equal((critical.match(/--kill-after=5s 120s "\$sha256sum_bin"/g)??[]).length,3);
      assert.match(critical,/"\$sha256sum_bin" -c "\$critical"/);
      assert.doesNotMatch(critical,/(^|[;&|]\s*)sha256sum\s/m);
    }
  }
});

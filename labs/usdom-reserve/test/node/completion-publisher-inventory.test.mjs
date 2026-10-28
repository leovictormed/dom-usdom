import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

const scripts=new URL('../../scripts/',import.meta.url);
const read=name=>readFileSync(new URL(name,scripts),'utf8');

test('all nine completion publishers are durable and completion-last',()=>{
  const atomic=read('install-release-config-stdin.mjs');
  assert.match(atomic,/writeFileDurable\(target,bytes,/);

  const publishers=[
    ['package-authenticated-checkpoint-outer-evm-proof.sh','checkpoint-outer-evm-proof-index.json'],
    ['package-authenticated-finalized-burn-evm-proof.sh','finalized-burn-evm-proof-index.json'],
    ['prove-authenticated-checkpoint-outer.sh','checkpoint-outer-receipt-set-index.json'],
    ['prove-authenticated-checkpoint-segment-set.sh','checkpoint-segment-receipt-set-index.json'],
    ['prove-authenticated-economic-receipt-set.sh','economic-receipt-set-index.json'],
    ['prove-authenticated-finalized-burn.sh','finalized-burn-receipt-index.json'],
    ['prove-authenticated-randomx-aggregate-set.sh','randomx-aggregate-receipt-set-index.json'],
    ['prove-authenticated-randomx-receipt-set.sh','randomx-receipt-set-index.json'],
  ];
  const boundedRemoval=new Set([
    'package-authenticated-checkpoint-outer-evm-proof.sh',
    'package-authenticated-finalized-burn-evm-proof.sh',
  ]);
  for(const [file,index] of publishers){
    const source=read(file);
    const final=source.indexOf(`final_index="$OUTPUT_DIR/${index}"`);
    let remove;
    let durable;
    if(boundedRemoval.has(file)) {
      assert.match(source,new RegExp(`remove_output_file\\(\\) \\{[\\s\\S]*\\$OUTPUT_DIR/${index.replaceAll('.','\\.')}[\\s\\S]*\\*\\) return 1`),file);
      assert.match(source,/remove_output_file\(\) \{[\s\S]*assert_tool_unchanged rm; assert_tool_unchanged timeout[\s\S]*"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$rm_bin" -- "\$file"[\s\S]*\[\[ ! -e \$file && ! -L \$file \]\]/,file);
      assert.match(source,/sync_output_directory\(\) \{[\s\S]*assert_tool_unchanged sync; assert_tool_unchanged timeout[\s\S]*"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s "\$sync_bin" -d "\$OUTPUT_DIR"[\s\S]*test "\$before" = "\$after"/,file);
      remove=source.indexOf('remove_output_file "$final_index"',final);
      durable=source.indexOf('sync_output_directory',remove);
    } else {
      remove=source.indexOf('rm -- "$final_index"',final);
      durable=source.indexOf('sync -d "$OUTPUT_DIR"',remove);
    }
    const install=source.lastIndexOf('install-private-file-stdin.mjs');
    assert.notEqual(final,-1,`${file}: named completion index missing`);
    assert.ok(final<remove && remove<durable && durable<install,
      `${file}: completion must be durably invalidated before publication`);
    assert.ok(source.lastIndexOf(index)<=install || source.includes('"$final_index"'),
      `${file}: completion index must be installed last`);
  }
});

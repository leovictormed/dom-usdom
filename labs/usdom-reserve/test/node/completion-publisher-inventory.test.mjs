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
  for(const [file,index] of publishers){
    const source=read(file);
    const final=source.indexOf(`final_index="$OUTPUT_DIR/${index}"`);
    const remove=source.indexOf('rm -- "$final_index"',final);
    const durable=source.indexOf('sync -d "$OUTPUT_DIR"',remove);
    const install=source.lastIndexOf('install-private-file-stdin.mjs');
    assert.notEqual(final,-1,`${file}: named completion index missing`);
    assert.ok(final<remove && remove<durable && durable<install,
      `${file}: completion must be durably invalidated before publication`);
    assert.ok(source.lastIndexOf(index)<=install || source.includes('"$final_index"'),
      `${file}: completion index must be installed last`);
  }
});

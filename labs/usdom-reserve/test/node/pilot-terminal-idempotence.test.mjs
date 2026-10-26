import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
test('terminal pilot evidence is deterministic and rerun-safe',()=>{
  for(const file of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    const tail=source.slice(source.lastIndexOf('execution='));
    assert.match(tail,/execution_candidate=/); assert.match(tail,/jq -n [\s\S]+>"\$execution_candidate"/);
    assert.match(tail,/if \[\[ -e \$execution \]\]; then cmp -s "\$execution_candidate" "\$execution"; else node scripts\/install-private-file-new-stdin\.mjs --json "\$execution"/);
    assert.doesNotMatch(tail,/\| node scripts\/install-private-file-new-stdin\.mjs --json "\$execution"/);
  }
});

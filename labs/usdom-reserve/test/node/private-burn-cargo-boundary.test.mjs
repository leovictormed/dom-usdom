import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const scripts=['prepare-closed-mainnet-private-burn.sh','submit-closed-mainnet-private-burn.sh'];

test('private-burn operator builds use a pinned Cargo identity',async()=>{
  for(const name of scripts) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/CARGO_BIN=\$\(realpath "\$\(command -v cargo\)"\)/,name);
    assert.match(source,/cargo_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/,name);
    assert.match(source,/cargo_sha256=\$\(sha256sum "\$CARGO_BIN"/,name);
    const build=source.indexOf('"$CARGO_BIN" build --quiet --release --locked');
    assert.ok(build>0,name);
    assert.match(source.slice(build-160,build+500),
      /assert_cargo_unchanged[\s\S]*(?:timeout --signal=TERM --kill-after=30s 3600s )?"\$CARGO_BIN" build[\s\S]*assert_cargo_unchanged/,name);
    assert.doesNotMatch(source,/(^|[;&(]\s*)cargo\s+build/m,name);
  }
});

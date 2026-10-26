import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const scripts=['observe-finalized-deposit-wallet.sh','register-finalized-deposit-wallet.sh'];

test('wallet identity RPC reads use one pinned and bounded curl identity',async()=>{
  for(const name of scripts) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/CURL_BIN=\$\(realpath "\$\(command -v curl\)"\)/,name);
    assert.match(source,/curl_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/,name);
    assert.match(source,/curl_sha256=\$\(sha256sum "\$CURL_BIN"/,name);
    assert.equal((source.match(/"\$CURL_BIN" --fail --silent --show-error --max-time 10 --max-filesize 65536 --proto '=http'/g)??[]).length,2,name);
    assert.equal((source.match(/assert_curl_unchanged/g)??[]).length,4,name);
    assert.doesNotMatch(source,/(^|[;&(]\s*)curl\s+--fail/m,name);
  }
});

test('wallet operator builds use one pinned Cargo identity',async()=>{
  for(const name of scripts) {
    const source=await readFile(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
    assert.match(source,/CARGO_BIN=\$\(realpath "\$\(command -v cargo\)"\)/,name);
    assert.match(source,/cargo_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/,name);
    assert.match(source,/cargo_sha256=\$\(sha256sum "\$CARGO_BIN"/,name);
    const build=source.indexOf('"$CARGO_BIN" build --quiet --release --locked');
    assert.ok(build>0,name);
    assert.match(source.slice(build-160,build+500),
      /assert_cargo_unchanged[\s\S]*timeout --signal=TERM --kill-after=30s 3600s "\$CARGO_BIN" build[\s\S]*assert_cargo_unchanged/,name);
    assert.doesNotMatch(source,/(^|[;&(]\s*)cargo\s+build/m,name);
  }
});

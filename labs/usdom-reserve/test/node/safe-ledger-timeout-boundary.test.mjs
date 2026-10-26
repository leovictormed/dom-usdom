import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const script=new URL('../../scripts/sign-recoverable-safe-recovery.sh',import.meta.url);
const releaseScript=new URL('../../scripts/sign-release-authorizations.sh',import.meta.url);
const deploymentExecutor=new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url);

test('Safe Ledger calls use a pinned bounded timeout child',async()=>{
  const source=await readFile(script,'utf8');
  assert.match(source,/command in cast jq node[\s\S]* timeout;/);
  assert.match(source,/timeout_bin=\$\(realpath "\$\(command -v timeout\)"\)/);
  assert.match(source,/timeout_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/timeout_sha256=\$\(sha256_file "\$timeout_bin"\)/);
  assert.match(source,/assert_timeout_unchanged\(\) \{/);
  assert.equal((source.match(/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s/g)??[]).length,2);
  assert.doesNotMatch(source,/\$\("\$cast_bin" wallet (?:address|sign)/);
  for(const operation of ['wallet address --ledger','wallet sign --data --from-file']) {
    const offset=source.indexOf(operation);
    assert.ok(offset>0);
    assert.match(source.slice(offset,offset+350),/assert_cast_unchanged[\s\S]*assert_timeout_unchanged/);
  }
});

test('mainnet deployment Ledger identity check has a bounded authenticated timeout',async()=>{
  const source=await readFile(deploymentExecutor,'utf8');
  const operation=source.indexOf('observed_ledger_deployer=$("$timeout_bin"');
  assert.ok(operation>0);
  assert.match(source.slice(operation-100,operation+500),
    /assert_timeout_unchanged[\s\S]*--foreground --signal=TERM --kill-after=5s 300s[\s\S]*wallet address --ledger[\s\S]*assert_cast_unchanged[\s\S]*assert_timeout_unchanged/);
  assert.equal((source.match(/wallet address --ledger/g)??[]).length,1);
  assert.doesNotMatch(source,/test "\$\("\$cast_bin" wallet address --ledger\)"/);
});

test('release and native authorization Ledger calls use the same pinned timeout',async()=>{
  const source=await readFile(releaseScript,'utf8');
  assert.match(source,/timeout_bin=\$\(realpath "\$\(command -v timeout\)"\)/);
  assert.match(source,/timeout_sha256=\$\(sha256_file "\$timeout_bin"\)/);
  assert.equal((source.match(/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 300s/g)??[]).length,2);
  assert.doesNotMatch(source,/\$\("\$cast_bin" wallet (?:address|sign)/);
  for(const operation of ['wallet address --ledger','wallet sign --no-hash']) {
    const offset=source.indexOf(operation);
    assert.ok(offset>0);
    assert.match(source.slice(offset,offset+420),/assert_cast_unchanged[\s\S]*assert_timeout_unchanged/);
  }
});

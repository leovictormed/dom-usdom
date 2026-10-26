import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const names=['execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh'];

function audit(source) {
  for(const tool of ['cast','node','jq','sha256','cmp','timeout','flock']) {
    assert.match(source,new RegExp(`${tool}_bin=\\$\\(realpath`));
    assert.match(source,new RegExp(`assert_${tool}_unchanged\\(\\)`));
  }
  assert.match(source,/sha256_file\(\)[\s\S]*assert_sha256_unchanged/);
  const afterBootstrap=source.slice(source.indexOf('sha256_bin='));
  assert.doesNotMatch(afterBootstrap,/sha256sum\s+"/);
  assert.doesNotMatch(source,/(?:^|[;&]\s*)cmp\s+-s\s/m);
  for(const line of source.split('\n').filter(line=>/"\$cmp_bin" -s/.test(line)))
    assert.match(line,/assert_cmp_unchanged; "\$cmp_bin" -s/);
  for(const tool of ['cast','node','jq'])
    assert.match(source,new RegExp(`assert_${tool}_unchanged\\(\\)[\\s\\S]*?sha256_file "\\$${tool}_bin"`));
  assert.doesNotMatch(source,/\btimeout --signal=/);
  assert.doesNotMatch(source,/(?:^|[;&]\s*)flock\s+-n\s+9/m);
  for(const line of source.split('\n').filter(line=>/"\$timeout_bin" --signal=/.test(line))) {
    const offset=source.split('\n').indexOf(line);
    assert.ok(source.split('\n').slice(Math.max(0,offset-1),offset).some(previous=>/assert_timeout_unchanged/.test(previous)));
  }
  assert.equal((source.match(/^exec 9<"\$evidence_directory"$/gm)??[]).length,1);
  assert.equal((source.match(/^exec 9/gm)??[]).length,1,'lock descriptor must never be reused');
  assert.doesNotMatch(source,/9>&-|<&9/);
  assert.match(source,/exec 9<"\$evidence_directory"\nassert_flock_unchanged\n(?:if ! )?"\$flock_bin" -n 9/);
  assert.ok(source.indexOf("trap 'cleanup $?' EXIT")>source.indexOf('"$flock_bin" -n 9'));
  assert.doesNotMatch(source,/(?:^|[;&]\s*)(?:sync|mv|cp)\s/m);
  assert.doesNotMatch(source,/chmod\s+[^\n]*"\$(?:receipt_file|evidence_file|raw_file|hash_file)"/);
  assert.doesNotMatch(source,/>\s*"\$(?:receipt_file|evidence_file|raw_file|hash_file)"/);
  assert.match(source,/(?:persist_new|persist_private_new) "\$(?:receipt_1|evidence_draft|raw_draft|hash_draft)" "\$(?:receipt_file|evidence_file|raw_file|hash_file)"/);
}

test('deploy and Safe executors pin the same authority-transforming tools',async()=>{
  for(const name of names) audit(await readFile(path.join(component,'scripts',name),'utf8'));
});

test('parity checker rejects late PATH sha256 and cmp authority',async()=>{
  const source=await readFile(path.join(component,'scripts',names[0]),'utf8');
  assert.throws(()=>audit(`${source}\nsha256sum "$authority"\n`));
  assert.throws(()=>audit(`${source}\ncmp -s "$before" "$after"\n`));
  assert.throws(()=>audit(`${source}\ntimeout --signal=TERM 120s child\n`));
  assert.throws(()=>audit(`${source}\nflock -n 9\n`));
  assert.throws(()=>audit(source.replace('exec 9<"$evidence_directory"','exec 9<"$evidence_directory"\nexec 9>/tmp/reused')));
  assert.throws(()=>audit(`${source}\nsync -f "$evidence_file"\n`));
  assert.throws(()=>audit(`${source}\ncp "$draft" "$evidence_file"\n`));
  assert.throws(()=>audit(`${source}\nprintf x > "$receipt_file"\n`));
  assert.throws(()=>audit(source.replace('assert_cmp_unchanged; "$cmp_bin" -s','"$cmp_bin" -s')));
});

import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

function commonAudit(source) {
  assert.doesNotMatch(source,/(?:^|[;&]\s*)(?:mv|cp)\s/m);
  assert.doesNotMatch(source,/>\s*"\$(?:SIGNATURE|SIGNATURE_SHA|signatures_output|transactions_output)"/);
  assert.doesNotMatch(source,/chmod\s+[^\n]*"\$(?:SIGNATURE|SIGNATURE_SHA|signatures_output|transactions_output)"/);
}

test('release authorization artifacts use create-once install and exact readback',async()=>{
  const source=await readFile(path.join(component,'scripts/sign-release-authorizations.sh'),'utf8');
  commonAudit(source);
  assert.match(source,/install-private-file-new-stdin\.mjs" "\$\{outputs\[\$name\]\}"[\s\S]*snapshot_private "\$\{outputs\[\$name\]\}"[\s\S]*"\$cmp_bin" -s "\$temporary\/\$name\.hex"/);
});

test('checkpoint signature and sidecar use immutable install and exact readback',async()=>{
  const source=await readFile(path.join(component,'scripts/sign-checkpoint-bootstrap-ratification.sh'),'utf8');
  commonAudit(source);
  for(const [target,draft,installed] of [
    ['SIGNATURE_SHA','signature.sha256','signature-sha.installed.txt'],
    ['SIGNATURE','signature.hex','signature.installed.hex'],
  ]) assert.match(source,new RegExp(`install-private-file-immutable-stdin\\.mjs" "\\$${target}" < "\\$TEMPORARY\\/${draft.replace('.','\\.')}"[\\s\\S]*snapshot "\\$${target}" "\\$TEMPORARY\\/${installed.replace('.','\\.')}"[\\s\\S]*"\\$cmp_bin" -s "\\$TEMPORARY\\/${draft.replace('.','\\.')}`));
});

test('Safe signature and transaction packages use create-once install and readback',async()=>{
  const source=await readFile(path.join(component,'scripts/sign-recoverable-safe-recovery.sh'),'utf8');
  commonAudit(source);
  for(const [target,draft,installed] of [
    ['signatures_output','signature_draft','signatures.installed.json'],
    ['transactions_output','transaction_draft','transactions.installed.json'],
  ]) assert.match(source,new RegExp(`install-private-file-new-stdin\\.mjs" "\\$${target}" < "\\$${draft}"[\\s\\S]*snapshot_private "\\$${target}" "\\$temporary\\/${installed.replaceAll('.','\\.')}"[\\s\\S]*"\\$cmp_bin" -s "\\$${draft}"`));
});

test('inventory rejects direct final writes, moves and final chmod',async()=>{
  const source=await readFile(path.join(component,'scripts/sign-recoverable-safe-recovery.sh'),'utf8');
  for(const attack of [
    `${source}\nprintf x > "$signatures_output"\n`,
    `${source}\ncp "$signature_draft" "$signatures_output"\n`,
    `${source}\nmv "$transaction_draft" "$transactions_output"\n`,
    `${source}\nchmod 0600 "$transactions_output"\n`,
  ]) assert.throws(()=>commonAudit(attack));
});

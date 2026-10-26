import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const interactive=[
  'submit-closed-mainnet-private-burn.sh','register-finalized-deposit-wallet.sh',
  'observe-finalized-deposit-wallet.sh','drill-closed-mainnet-wallet-recovery.sh',
  'bootstrap-closed-mainnet-tpm-authority.sh',
];
const witness='build-finalized-deposit-witness.sh';

test('credential flows close caller descriptors and revoke stdin after password entry',async()=>{
  for(const name of interactive) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    assert.match(source,/for fd_path in \/proc\/\$\$\/fd\/\*/);
    assert.match(source,/exec \{inherited_fd\}>&-/);
    assert.ok(source.indexOf('exec {inherited_fd}>&-')<source.indexOf('command -v'),`${name}: fd closure precedes children`);
    assert.match(source,/unset (?:recovery_password|tpm_owner_authorization)\nexec <\/dev\/null/);
    assert.match(source,/(?:cargo|"\$CARGO_BIN") build[\s\S]*<\/dev\/null/);
  }
  const source=await readFile(path.join(component,'scripts',witness),'utf8');
  assert.match(source,/set -euo pipefail\n[\s\S]*exec <\/dev\/null/);
  assert.ok(source.indexOf('exec </dev/null')<source.indexOf('command -v'),'witness stdin closes before children');
  assert.match(source,/exec \{inherited_fd\}>&-/);
});

test('local proc-fd harness prevents inherited evidence fd and stdin reaching child',()=>{
  const body=`set -euo pipefail
for fd_path in /proc/$$/fd/*; do
  inherited_fd=\${fd_path##*/}
  [[ "$inherited_fd" =~ ^[0-9]+$ ]] || exit 1
  ((inherited_fd > 2)) || continue
  [[ "$inherited_fd" == 255 ]] && continue
  exec {inherited_fd}>&-
done
exec </dev/null
bash -c 'test ! -e /proc/$$/fd/9; if IFS= read -r value; then exit 91; fi; printf isolated'
`;
  const wrapper='secret=$(mktemp); trap \'rm -f "$secret"\' EXIT; printf sensitive >"$secret"; exec 9<"$secret"; exec bash -c "$1"';
  const result=spawnSync('bash',['-c',wrapper,'bash',body],{input:'password-still-on-stdin\n',encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
  assert.equal(result.stdout,'isolated');
  assert.equal(result.stderr,'');
});

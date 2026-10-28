import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');

test('private burn submission pins Node and erases secrets with explicit signal status',async()=>{
  const source=await readFile(path.join(component,'scripts/submit-closed-mainnet-private-burn.sh'),'utf8');
  assert.match(source,/NODE_BIN=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/assert_node_unchanged\(\)[\s\S]*node_identity[\s\S]*node_sha256/);
  assert.match(source,/cleanup\(\) \{[\s\S]*local status=\$\{1:-\$\?\}[\s\S]*unset recovery_password/);
  assert.match(source,/SECRET_DIRECTORY_IDENTITY=\$\(stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY"\)/);
  assert.match(source,/stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY" 2>\/dev\/null\) == "\$SECRET_DIRECTORY_IDENTITY"/);
  assert.match(source,/# Never erase a pathname that no longer names our private submission directory\.[\s\S]*status=1/);
  assert.match(source,/assert_node_unchanged &&[\s\S]*run_pinned_timeout --foreground --signal=TERM --kill-after=5s 30s[\s\S]*"\$NODE_BIN" -e 'require\("fs"\)\.rmSync/);
  assert.match(source,/assert_node_unchanged && assert_runtime_tool timeout && test ! -e "\$SECRET_DIRECTORY"[\s\S]*else\n      status=1/);
  for(const [signal,status] of [['HUP',129],['INT',130],['TERM',143]])
    assert.match(source,new RegExp(`trap 'cleanup ${status}' ${signal}`));
  assert.match(source,/trap 'cleanup \$\?' EXIT/);
  assert.doesNotMatch(source,/find "\$SECRET_DIRECTORY" -depth -delete|trap cleanup EXIT HUP INT TERM|trap 'rm -rf/);
  assert.doesNotMatch(source,/(?:^|\n)node\s+"\$LAB_ROOT\//);
  assert.equal(source.split('\n').filter(line=>/(?:^|\s)&\s*(?:#.*)?$/.test(line)).length,0);
});

test('cleanup inventory rejects PATH deletion and ambiguous signal traps',async()=>{
  const source=await readFile(path.join(component,'scripts/submit-closed-mainnet-private-burn.sh'),'utf8');
  const audit=value=>{
    assert.doesNotMatch(value,/find "\$SECRET_DIRECTORY" -depth -delete|rm -rf -- "\$SECRET_DIRECTORY"/);
    assert.doesNotMatch(value,/trap cleanup EXIT HUP INT TERM/);
    assert.match(value,/trap 'cleanup 143' TERM/);
  };
  assert.doesNotThrow(()=>audit(source));
  assert.throws(()=>audit(`${source}\nfind "$SECRET_DIRECTORY" -depth -delete\n`));
  assert.throws(()=>audit(`${source}\ntrap cleanup EXIT HUP INT TERM\n`));
});

test('private burn invalidates only its derived receipt before secrets and RPC',async()=>{
  const source=await readFile(path.join(component,'scripts/submit-closed-mainnet-private-burn.sh'),'utf8');
  const removal=source.indexOf('remove-private-file-durable.mjs" "$SUBMISSION_RECEIPT"');
  const secret=source.indexOf('SECRET_DIRECTORY=$(mktemp',removal);
  const intent=source.indexOf('install-private-file-immutable-stdin.mjs" --json "$SUBMISSION_INTENT"',removal);
  const submit=source.indexOf('"$submit_binary"',intent);
  assert.ok(removal>=0&&secret>removal&&intent>secret&&submit>intent);
  assert.doesNotMatch(source,/remove-private-file-durable\.mjs" "\$SUBMISSION_INTENT"/);
});

test('private burn preparation isolates credentials and validates every output entry',async()=>{
  const source=await readFile(path.join(component,'scripts/prepare-closed-mainnet-private-burn.sh'),'utf8');
  assert.match(source,/for fd_path in \/proc\/\$\$\/fd\/\*/);
  assert.match(source,/unset LD_PRELOAD[\s\S]*SSLKEYLOGFILE[\s\S]*CARGO_TARGET_DIR/);
  assert.match(source,/trap 'cleanup 129' HUP/);
  assert.match(source,/trap 'cleanup 130' INT/);
  assert.match(source,/trap 'cleanup 143' TERM/);
  assert.match(source,/SECRET_DIRECTORY_IDENTITY=\$\(stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY"\)/);
  assert.match(source,/stat -c '%u:%d:%i:%a' "\$SECRET_DIRECTORY" 2>\/dev\/null\) == "\$SECRET_DIRECTORY_IDENTITY"/);
  assert.match(source,/# A replaced pathname is not the secret directory this process created\.[\s\S]*status=1/);
  assert.ok(source.indexOf('exec </dev/null')>source.indexOf('unset recovery_password'));
  assert.match(source,/find "\$OUTPUT_STATE" -mindepth 1 -print0/);
  assert.match(source,/stat -c '%u:%h' "\$output_entry"/);
  assert.match(source,/Prepared burn output contains an unsafe entry/);
  assert.match(source,/"\$SECRET_DIRECTORY\/keystore\.stdout" 2>"\$SECRET_DIRECTORY\/keystore\.stderr"/);
  assert.match(source,/"\$SECRET_DIRECTORY\/builder\.stdout" 2>"\$SECRET_DIRECTORY\/builder\.stderr"/);
  assert.match(source,/private diagnostics were suppressed/);
  assert.match(source,/rmSync\(process\.argv\[1\],\{recursive:true,force:true\}\)/);
  assert.match(source,/test ! -e "\$SECRET_DIRECTORY"/);
});

test('private burn submission refuses special or group-readable prepared-state entries',async()=>{
  const source=await readFile(path.join(component,'scripts/submit-closed-mainnet-private-burn.sh'),'utf8');
  assert.match(source,/find "\$PREPARED_STATE" -mindepth 1 -print0/);
  assert.match(source,/\(8#\$entry_mode & 077\) == 0/);
  assert.match(source,/Prepared burn state contains an unsafe entry/);
  assert.match(source,/usdom-closed-mainnet-private-burn-submission-v1/);
  assert.match(source,/\.accepted==true and \.state=="queued"/);
  assert.match(source,/private-burn-index\.json/);
  assert.match(source,/sha256sum "\$PREPARED_STATE\/private-burn-payload\.bin"/);
  assert.match(source,/"\$SECRET_DIRECTORY\/keystore\.stdout" 2>"\$SECRET_DIRECTORY\/keystore\.stderr"/);
  assert.match(source,/"\$SECRET_DIRECTORY\/submit\.stdout" 2>"\$SECRET_DIRECTORY\/submit\.stderr"/);
  assert.match(source,/private diagnostics were suppressed/);
});

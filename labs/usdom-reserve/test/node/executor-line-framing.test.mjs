import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

const component=path.resolve(import.meta.dirname,'../..');
const check=`
set -e
file=$1
exec {fd}<"$file"
if ! IFS= read -r value <&$fd; then exit 1; fi
if IFS= read -r extra <&$fd; then exit 1; fi
exec {fd}<&-
[[ "$value" != *$'\\r'* && "$value" != *$'\\n'* ]]
[[ "$value" =~ ^0x[0-9a-f]{64}$ ]]
`;

test('executor authority output accepts exactly one canonical LF line',async t=>{
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-executor-line-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const file=path.join(directory,'authority.txt');
  const hash=`0x${'a'.repeat(64)}`;
  for(const [bytes,accepted] of [
    [`${hash}\n`,true],
    [hash,false],
    [`${hash}\r\n`,false],
    [`${hash}\n\n`,false],
    [`${hash}\n${hash}\n`,false],
    [`${hash}${hash}\n`,false],
    [` ${hash}\n`,false],
  ]) {
    await writeFile(file,bytes);
    assert.equal(spawnSync('bash',['-c',check,'bash',file]).status===0,accepted,
      JSON.stringify(bytes));
  }
});

test('deployment and Safe executors never normalize authority output with tr',async()=>{
  for(const name of ['execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh']) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    assert.match(source,/read_canonical_line\(\)/);
    assert.doesNotMatch(source,/\|\s*tr\b|\btr\s+-d/);
    assert.match(source,/rpc publish[\s\S]*> "\$publish_output"[\s\S]*read_canonical_line "\$publish_output"/);
  }
});

test('deployment derivation uses a bounded strict stdout and empty-stderr protocol',async()=>{
  const source=await readFile(path.join(component,'scripts','execute-mainnet-deployment.sh'),'utf8');
  assert.match(source,/run_node_json_authority\(\)/);
  assert.match(source,/"\$timeout_bin" --signal=TERM 120s "\$node_bin" "\$script"[\s\S]*> "\$output" 2> "\$error"/);
  assert.match(source,/test ! -s "\$error"[\s\S]*check-private-strict-json-file\.mjs "\$output"/);
  assert.doesNotMatch(source,/transaction=\$\("\$node_bin" scripts\/prepare-mainnet-deployment-transaction/);
  assert.equal((source.match(/run_node_json_authority "\$temporary\/transaction\./g)??[]).length,4);
});

test('Safe envelope, target, raw and final derivations share the strict child protocol',async()=>{
  const source=await readFile(path.join(component,'scripts','execute-recoverable-safe-recovery.sh'),'utf8');
  assert.match(source,/run_node_json_authority\(\)/);
  assert.match(source,/"\$timeout_bin" --signal=TERM 120s "\$node_bin" "\$script"[\s\S]*> "\$output" 2> "\$error"/);
  assert.match(source,/test ! -s "\$error"[\s\S]*check-private-strict-json-file\.mjs "\$output"/);
  for(const helper of [
    'prepare-recoverable-safe-recovery-envelope.mjs',
    'check-recoverable-safe-recovery-target.mjs',
    'check-recoverable-safe-recovery-raw-transaction.mjs',
    'collect-recoverable-safe-recovery.mjs',
  ]) assert.match(source,new RegExp(`run_node_json_authority[^\\n]*(?:\\\\\\n[^\\n]*)?${helper.replaceAll('.','\\.')}`));
  assert.doesNotMatch(source,/"\$node_bin" scripts\/check-recoverable-safe-recovery-raw-transaction\.mjs\s*>/);
});

test('Safe observer status protocol distinguishes finalized, pending and failures',async t=>{
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-observer-protocol-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const output=path.join(directory,'stdout');
  const error=path.join(directory,'stderr');
  const classify=`
set -e
status=$1; output=$2; error=$3
if ((status==0)); then test ! -s "$error"; test "$(cat "$output")" = '{}'; exit; fi
test ! -s "$output"
if ((status==3)); then test "$(cat "$error")" = USDOM_SAFE_RECOVERY_NOT_FINALIZED; exit; fi
exit "$status"
`;
  for(const value of [
    {status:0,out:'{}\n',err:'',accepted:true},
    {status:0,out:'{}\n',err:'warning\n',accepted:false},
    {status:3,out:'',err:'USDOM_SAFE_RECOVERY_NOT_FINALIZED\n',accepted:true},
    {status:3,out:'{}\n',err:'USDOM_SAFE_RECOVERY_NOT_FINALIZED\n',accepted:false},
    {status:3,out:'',err:'not finalized\n',accepted:false},
    {status:3,out:'',err:'USDOM_SAFE_RECOVERY_NOT_FINALIZED\nextra\n',accepted:false},
    {status:1,out:'',err:'failure\n',accepted:false},
    {status:124,out:'',err:'timeout\n',accepted:false},
    {status:143,out:'',err:'terminated\n',accepted:false},
  ]) {
    await writeFile(output,value.out); await writeFile(error,value.err);
    const result=spawnSync('bash',['-c',classify,'bash',String(value.status),output,error]);
    assert.equal(result.status===0,value.accepted,JSON.stringify(value));
  }
});

test('Safe observer implementation enforces its special status-three wire protocol',async()=>{
  const executor=await readFile(path.join(component,'scripts','execute-recoverable-safe-recovery.sh'),'utf8');
  const observer=await readFile(path.join(component,'scripts','observe-recoverable-safe-recovery-execution.mjs'),'utf8');
  assert.match(executor,/run_safe_observer\(\)/);
  assert.match(executor,/\(\(status == 0\)\)[\s\S]*test ! -s "\$error"[\s\S]*check-private-strict-json-file/);
  assert.match(executor,/test ! -s "\$output"[\s\S]*\(\(status == 3\)\)[\s\S]*USDOM_SAFE_RECOVERY_NOT_FINALIZED/);
  assert.match(observer,/error instanceof SafeRecoveryNotFinalizedError[\s\S]*USDOM_SAFE_RECOVERY_NOT_FINALIZED[\s\S]*process\.exitCode=3/);
});

test('RPC proxy background channels are separate, bounded and never replayed',async()=>{
  for(const name of ['execute-mainnet-deployment.sh','execute-recoverable-safe-recovery.sh']) {
    const source=await readFile(path.join(component,'scripts',name),'utf8');
    assert.match(source,/rpc_proxy_stdout=.*rpc-proxy\.stdout/);
    assert.match(source,/rpc_proxy_stderr=.*rpc-proxy\.stderr/);
    assert.match(source,/check_rpc_proxy_channels\(\)[\s\S]*TextDecoder\("utf-8",\{fatal:true\}\)/);
    assert.match(source,/check_rpc_proxy_channels\(\)[\s\S]*65536/);
    assert.match(source,/for _ in \{1\.\.200\}; do\n  check_rpc_proxy_channels bounded/);
    assert.match(source,/check_rpc_proxy_channels empty[\s\S]*check-private-rpc-proxy-ready\.mjs[\s\S]*"\$rpc_proxy_ready"/);
    assert.match(source,/Private RPC proxy failed before readiness with status %s/);
    assert.doesNotMatch(source,/cat "\$rpc_proxy_(?:log|stderr|stdout)"/);
    assert.doesNotMatch(source,/rpc-proxy\.log|>"\$rpc_proxy_log" 2>&1/);
  }
});

test('RPC proxy channel validator rejects oversize, invalid UTF-8 and success diagnostics',async t=>{
  const directory=await mkdtemp(path.join(tmpdir(),'usdom-proxy-channels-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  const stdout=path.join(directory,'stdout'),stderr=path.join(directory,'stderr');
  const validator='const fs=require("fs"),fatal=new TextDecoder("utf-8",{fatal:true});for(const [file,max] of [[process.argv[1],65536],[process.argv[2],65536]]){const bytes=fs.readFileSync(file);if(bytes.length>max)process.exit(1);fatal.decode(bytes);if(process.argv[3]==="empty"&&bytes.length!==0)process.exit(1)}';
  const run=mode=>spawnSync(process.execPath,['-e',validator,stdout,stderr,mode]).status===0;
  await writeFile(stdout,''); await writeFile(stderr,''); assert.equal(run('empty'),true);
  await writeFile(stderr,'https://user:secret@example.invalid\n');
  assert.equal(run('empty'),false); assert.equal(run('bounded'),true);
  await writeFile(stderr,Buffer.from([0xff])); assert.equal(run('bounded'),false);
  await writeFile(stderr,'x'.repeat(65537)); assert.equal(run('bounded'),false);
  await writeFile(stderr,''); await writeFile(stdout,'unexpected\n'); assert.equal(run('empty'),false);
});

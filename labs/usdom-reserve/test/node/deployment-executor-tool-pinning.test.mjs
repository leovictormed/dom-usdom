import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const executor=new URL('../../scripts/execute-mainnet-deployment.sh',import.meta.url);
test('mainnet deployment pins cast through signing and broadcast consent',async()=>{
  const source=await readFile(executor,'utf8');

  assert.match(source,/deployment_broadcast_state=clean[\s\S]*cleanup\(\)[\s\S]*deployment_broadcast_state != clean[\s\S]*status=80/);
  assert.match(source,/transaction_hash=.*validation_current[\s\S]*deployment_broadcast_state=signed-unresolved/);
  assert.match(source,/if \[\[ \$seen_any == true \]\]; then deployment_broadcast_state=observed; fi/);
  assert.ok(source.indexOf('deployment_broadcast_state=publishing\n  "$node_bin" scripts/publish-private-raw-transaction.mjs')<
    source.lastIndexOf('deployment_broadcast_state=clean'));
  assert.match(source,/\(\( status != 0 \)\) \|\| status=1/);

  assert.match(source,/temporary=\$\("\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s \\\n\s+mktemp -d -p \/dev\/shm usdom-mainnet-deployment\.XXXXXXXX \| \/usr\/bin\/head -c 128\)/);
  assert.match(source,/\[\[ \$temporary =~ \^\/dev\/shm\/usdom-mainnet-deployment\\\.\[A-Za-z0-9\]\{8\}\$ \]\]/);
  assert.match(source,/test "\$\(stat -c '%u:%a' -- "\$temporary"\)" = "\$\(id -u\):700"/);
  assert.doesNotMatch(source,/chmod 0700 "\$temporary"/);
  assert.match(source,/printf '%s\\n' "\$raw" > "\$raw_draft"\n  assert_private_file "\$raw_draft"/);
  assert.match(source,/run_node_json_authority "\$validation_draft" scripts\/check-mainnet-deployment-raw-transaction\.mjs "\$index"/);
  assert.doesNotMatch(source,/chmod 0600 "\$(?:raw_draft|validation_draft)"/);
  assert.match(source,/run_jq_json_authority "\$temporary\/finalized-anchor\.json" -n --arg index/);
  assert.match(source,/run_node_empty_authority finalized-anchor scripts\/check-deployment-evidence\.mjs "\$temporary\/finalized-anchor\.json" anchor/);
  assert.doesNotMatch(source,/chmod 0600 "\$temporary\/finalized-anchor\.json"/);

  const jqJsonAuthority=source.slice(source.indexOf('run_jq_json_authority() {'),
    source.indexOf('run_node_empty_authority() {'));
  assert.match(jqJsonAuthority,/assert_jq_unchanged\n  assert_timeout_unchanged/);
  assert.match(jqJsonAuthority,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(jqJsonAuthority,/\[\[process\.argv\[1\],2097152\],\[process\.argv\[2\],65536\]\]/);
  assert.match(jqJsonAuthority,/assert_private_file "\$output"\n  assert_private_file "\$error"/);
  assert.match(jqJsonAuthority,/check-private-strict-json-file\.mjs "\$output"/);

  const receiptProjection=source.slice(source.indexOf('project_receipt() {'),
    source.indexOf('package_source='));
  assert.match(receiptProjection,/assert_private_file "\$1"/);
  assert.match(receiptProjection,/run_node_json_authority "\$2" scripts\/project-deployment-receipt\.mjs "\$1"/);
  assert.doesNotMatch(receiptProjection,/chmod|"\$node_bin"/);
  assert.equal((source.match(/project_receipt "/g)??[]).length,5);
  assert.match(source,/run_node_json_authority "\$validation_current" scripts\/check-mainnet-deployment-raw-transaction\.mjs "\$index"/);
  assert.doesNotMatch(source,/chmod 0600 "\$validation_current"/);
  assert.match(source,/printf '%s\\n' "\$transaction_hash" > "\$temporary\/hash\.txt"\n  assert_private_file "\$temporary\/hash\.txt"/);
  assert.match(source,/run_node_empty_authority submission-hash scripts\/check-deployment-submission-hash\.mjs "\$temporary\/hash\.txt"/);
  assert.doesNotMatch(source,/chmod 0600 "\$temporary\/hash\.txt"/);

  const lineAuthority=source.slice(source.indexOf('run_jq_line_authority() {'),
    source.indexOf('run_node_json_authority() {'));
  assert.match(lineAuthority,/assert_jq_unchanged\n  assert_timeout_unchanged/);
  assert.match(lineAuthority,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(lineAuthority,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(lineAuthority,/test -s "\$output"\n  test ! -s "\$error"\n  read_canonical_line "\$output"/);
  assert.equal((source.match(/run_jq_line_authority "(?:prepublish|transmit)-seen-/g)??[]).length,3);
  assert.doesNotMatch(source,/"\$jq_bin" -e '\. == null' "\$(?:seen|transmit_seen)_file"/);
  assert.match(source,/cast_bin=\$\(realpath "\$\(command -v cast\)"\)/);
  assert.match(source,/cast_sha256=\$\(sha256sum "\$cast_bin"/);
  assert.match(source,/cast_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/node_bin=\$\(realpath "\$\(command -v node\)"\)/);
  assert.match(source,/node_sha256=\$\(sha256sum "\$node_bin"/);
  assert.match(source,/node_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/jq_bin=\$\(realpath "\$\(command -v jq\)"\)/);
  assert.match(source,/jq_sha256=\$\(sha256sum "\$jq_bin"/);
  assert.match(source,/jq_identity=\$\(stat -Lc '%d:%i:%s:%Y:%Z'/);
  assert.match(source,/assert_jq_unchanged/);
  assert.match(source,/assert_node_unchanged/);
  assert.equal((source.match(/run_node_json_authority "\$(?:validation_draft|validation_current)" scripts\/check-mainnet-deployment-raw-transaction\.mjs "\$index"/g)??[]).length,2);
  assert.doesNotMatch(source,/(^|[;(]\s*)node (?:scripts|-e)/m);
  assert.match(source,/assert_timeout_unchanged[\s\S]*"\$timeout_bin" --signal=TERM 120s "\$cast_bin"/);
  assert.match(source,/AUTORIZO ASSINAR[\s\S]*assert_cast_unchanged[\s\S]*wallet sign --no-hash "\$create_signing_hash"/);
  assert.match(source,/AUTORIZO TRANSMITIR[\s\S]*assert_cast_unchanged[\s\S]*publish-private-raw-transaction\.mjs/);
  assert.match(source,/AUTORIZO ASSINAR[\s\S]*assert_jq_unchanged[\s\S]*prepare-private-mainnet-create\.mjs prepare/);
  assert.match(source,/AUTORIZO TRANSMITIR[\s\S]*assert_jq_unchanged[\s\S]*publish-private-raw-transaction\.mjs/);
  assert.match(source,/assert_cast_unchanged\n  assert_node_unchanged\n  assert_jq_unchanged[\s\S]*publish-private-raw-transaction\.mjs[\s\S]*published=\$\(read_canonical_line/);
  assert.doesNotMatch(source,/(^|[|;(]\s*)jq\s/m);
  assert.doesNotMatch(source,/(^|[;(]\s*)cast (?:wallet|keccak)/m);
  const persistence=source.slice(source.indexOf('persist_new() {'),source.indexOf('snapshot() {'));
  assert.match(persistence,/assert_node_unchanged\n  assert_timeout_unchanged/);
  assert.match(persistence,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 30s/);
  assert.match(persistence,/install-private-file-new-stdin\.mjs "\$destination"[\s\S]*> "\$output" 2> "\$error"/);
  assert.match(persistence,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(persistence,/test ! -s "\$output"\n  test ! -s "\$error"/);
  assert.match(persistence,/snapshot "\$destination" "\$installed"\n  assert_cmp_unchanged; "\$cmp_bin" -s "\$source" "\$installed"/);
  assert.doesNotMatch(persistence,/\.equals\(fs\.readFileSync/);
  const jsonAuthority=source.slice(source.indexOf('run_node_json_authority() {'),
    source.indexOf('canonical_quantity() {'));
  assert.match(jsonAuthority,/assert_node_unchanged\n  assert_timeout_unchanged/);
  assert.match(jsonAuthority,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s/);
  assert.match(jsonAuthority,/\[process\.argv\[1\],2097152\],[\s\S]*\[process\.argv\[2\],65536\]/);
  assert.match(jsonAuthority,/fatal\.decode\(bytes\)/);
  assert.match(jsonAuthority,/test -s "\$output"\n  test ! -s "\$error"/);
  assert.match(jsonAuthority,/run_node_empty_authority generated-json scripts\/check-private-strict-json-file\.mjs "\$output"/);
  const emptyAuthority=source.slice(source.indexOf('run_node_empty_authority() {'),
    source.indexOf('run_node_json_authority() {'));
  assert.match(emptyAuthority,/assert_node_unchanged\n  assert_timeout_unchanged/);
  assert.match(emptyAuthority,/"\$timeout_bin" --foreground --signal=TERM --kill-after=5s 120s/);
  assert.match(emptyAuthority,/bytes\.length>65536[\s\S]*fatal\.decode\(bytes\)/);
  assert.match(emptyAuthority,/test ! -s "\$output"\n  test ! -s "\$error"/);
  assert.equal((source.match(/run_node_empty_authority (?:generated-json|strict-json) scripts\/check-private-strict-json-file\.mjs/g)??[]).length,34);
  assert.doesNotMatch(source,/"\$node_bin" scripts\/check-private-strict-json-file\.mjs/);
});

test('mainnet deployment binds its evidence lock to the pathname parent',async()=>{
  const source=await readFile(executor,'utf8');
  assert.match(source,/realpath -e \/proc\/\$\$\/fd\/9/);
  assert.match(source,/evidence_parent_identity=\$\(stat -Lc '%d:%i:%u:%a' -- \/proc\/\$\$\/fd\/9\)/);
  assert.match(source,/assert_evidence_parent\(\)[\s\S]*realpath -e "\$evidence_directory"[\s\S]*stat -Lc '%d:%i:%u:%a' -- \/proc\/\$\$\/fd\/9/);
  assert.ok((source.match(/assert_evidence_parent/g)??[]).length>=6);
  assert.ok(source.indexOf('assert_evidence_parent\n  deployment_broadcast_state=publishing')<
    source.indexOf('publish-private-raw-transaction.mjs "$raw_snapshot"'));
});

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const scripts=[
  {name:'bootstrap-closed-mainnet-tpm-authority.sh',assertion:'assert_node_unchanged',node:'NODE_BIN'},
  {name:'drill-closed-mainnet-wallet-recovery.sh',assertion:'assert_node_unchanged',node:'NODE_BIN'},
  {name:'provision-closed-mainnet-tpm-keystore.sh',assertion:'assert_runtime_tool node',node:'node_bin'},
  {name:'prepare-native-receiving-wallet.sh',assertion:'assert_node_unchanged',node:'NODE_BIN'},
  {name:'register-finalized-deposit-wallet.sh',assertion:'assert_node_unchanged',node:'NODE_BIN'},
  {name:'observe-finalized-deposit-wallet.sh',assertion:'assert_node_unchanged',node:'NODE_BIN'},
  {name:'submit-closed-mainnet-private-burn.sh',assertion:'assert_node_unchanged',node:'NODE_BIN'},
];
test('TPM and wallet credential flows bound secret-directory cleanup',()=>{
  for(const {name,assertion,node} of scripts) {
    const script=fileURLToPath(new URL(`../../scripts/${name}`,import.meta.url));
    assert.equal(spawnSync('bash',['-n',script]).status,0,name);
    const source=readFileSync(script,'utf8');
    const cleanup=source.slice(source.indexOf('cleanup() {'),source.indexOf("trap 'cleanup $?' EXIT"));
    assert.match(cleanup,new RegExp(`${assertion.replace(' ','\\s+')}[\\s\\S]*run_pinned_timeout --foreground --signal=TERM --kill-after=5s 30s`),name);
    assert.match(cleanup,new RegExp(`"\\$${node}" -e 'require\\("fs"\\)\\.rmSync`),name);
    assert.equal(cleanup.split(assertion).length-1,2,name);
    assert.match(cleanup,/test ! -e "\$SECRET_DIRECTORY"/,name);
    assert.match(cleanup,/else\n      status=1/,name);
  }
});

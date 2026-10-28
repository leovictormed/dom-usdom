import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const load=name=>readFileSync(new URL(`../../scripts/${name}`,import.meta.url),'utf8');
const deposit=load('execute-closed-mainnet-deposit.sh');
const redemption=load('execute-closed-mainnet-redemption.sh');
const deploy=load('execute-mainnet-deployment.sh');
const safeDeploy=load('execute-safe-control-deployment.sh');
const recovery=load('execute-recoverable-safe-recovery.sh');
const resume=load('execute-reserve-resume.sh');

test('deposit and redemption reviews bind every transaction field and evidence',()=>{
  for(const source of [deposit,redemption]) {
    for(const field of ['chainId=1','signer=%s','target=%s','nonce=%s','selector=%s',
      'tokenAmountBaseUnits=','valueWei=0','dataHash=%s','evidencePackageSha256=%s',
      'gasLimit=%s','maxFeePerGas=%s','priorityFeePerGas=2000000000','maximumGasCostWei=%s']) {
      assert.ok(source.includes(field),field);
    }
    assert.match(source,/AUTORIZO ASSINAR .+ AUTH \$authorization_hash/);
    assert.match(source,/AUTORIZO TRANSMITIR .+ TX \$expected_hash/);
  }
  assert.match(deposit,/releaseConfigSha256=%s reserveConfigHash=%s/);
  assert.match(deposit,/usdom-closed-deposit-sign-v2\|action=\$name\|stage=\$index\|chainId=1\|signer=\$funder\|target=\$to\|nonce=\$nonce\|tokenAmountBaseUnits=\$amount\|valueWei=0\|dataHash=\$data_hash\|evidencePackageSha256=\$package_sha\|releaseConfigSha256=\$release_config_sha\|reserveConfigHash=\$reserve_config_hash\|gasLimit=\$gas\|maxFeePerGas=\$fee\|maxPriorityFeePerGas=2000000000\|maximumGasCostWei=\$proposed_cost/);
  assert.match(redemption,/releaseConfigSha256=%s verifierManifestSha256=%s/);
  assert.match(redemption,/usdom-closed-redemption-sign-v2\|action=\$name\|stage=\$index\|chainId=1\|signer=\$signer\|target=\$to\|nonce=\$nonce\|tokenAmountBaseUnits=1000000\|valueWei=0\|dataHash=\$data_hash\|evidencePackageSha256=\$package_sha\|releaseConfigSha256=\$release_sha\|verifierManifestSha256=\$verifier_sha\|validUntil=\$valid_until\|gasLimit=\$gas\|maxFeePerGas=\$fee\|maxPriorityFeePerGas=2000000000\|maximumGasCostWei=\$proposed_cost/);
});

test('contract and Safe deployment reviews are per action and hash-bound',()=>{
  for(const field of ['action=CREATE','chainId=1','nonce=%s','valueWei=0','initcodeHash=%s',
    'expectedRuntimeCodeHash=%s','gasLimit=%s','maxFeePerGas=%s','priorityFeePerGas=%s']) {
    assert.ok(deploy.includes(field),field);
  }
  assert.match(deploy,/usdom-mainnet-deployment-sign-v1\|action=CREATE\|chainId=1\|index=\$\{index\}\|deployer=\$\{deployer\.toLowerCase\(\)\}\|nonce=\$\{nonce\}\|contract=\$\{contract\.toLowerCase\(\)\}/);
  assert.match(deploy,/releaseConfigSha256=%s packageSha256=%s observationDocumentSha256=%s authorizationHash=%s/);
  assert.match(deploy,/AUTORIZO ASSINAR DEPLOY INDICE \$index AUTH \$authorization_hash/);
  assert.match(deploy,/AUTORIZO TRANSMITIR DEPLOY INDICE \$index TX \$transaction_hash/);
  assert.match(safeDeploy,/prepare-safe-control-deployment-relayer-envelope\.mjs/);
  assert.match(safeDeploy,/check-safe-control-deployment-relayer-raw\.mjs/);
  assert.match(safeDeploy,/AUTORIZO TRANSMITIR SAFE \$role NONCE \$nonce TX \$tx_hash/);
  assert.doesNotMatch(safeDeploy,/AUTORIZO ASSINAR SAFE|wallet sign|--ledger|OneKey/);
});

test('recovery has separate sign and publish authorization for each role',()=>{
  assert.doesNotMatch(recovery,/AUTORIZO TRES SWAPOWNER/);
  assert.match(recovery,/action=swapOwner role=%s chainId=1 signer=%s target=%s nonce=%s selector=%s valueWei=%s dataHash=%s envelopeHash=%s/);
  assert.match(recovery,/AUTORIZO ASSINAR SWAPOWNER \$role ENVELOPE \$envelope_hash/);
  assert.match(recovery,/AUTORIZO TRANSMITIR SWAPOWNER \$role TX \$transaction_hash/);
});

test('authorization parsing is exact, nonlocalized and fail-closed',()=>{
  for(const source of [deposit,redemption,deploy,safeDeploy,recovery,resume]) {
    assert.match(source,/LC_ALL=C|export LANG=C LC_ALL=C|export LC_ALL=C/);
    assert.match(source,/read -r -p/);
    assert.doesNotMatch(source,/\bread\b[^\n]*-i|nocasematch|\|\| true[^\n]*(?:AUTORIZO|authorization)/);
  }
});
test('resume review binds config/calldata and publication to exact transaction hash',()=>{
  assert.match(resume,/reserveConfigHash=\$reserve_config_hash/);
  assert.match(resume,/selector=\$exec_selector calldataHash=\$exec_data_hash/);
  assert.match(resume,/AUTORIZO ASSINAR RETOMADA \$step AUTH \$authorization_hash/);
  assert.match(resume,/AUTORIZO TRANSMITIR RETOMADA \$step TX \$\{expected_txhash,,\}/);
  assert.match(resume,/test "\$\{txhash,,\}" = "\$\{expected_txhash,,\}"/);
});

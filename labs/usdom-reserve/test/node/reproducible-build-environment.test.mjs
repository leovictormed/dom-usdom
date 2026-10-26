import assert from 'node:assert/strict';
import test from 'node:test';
import {assertProductionSolidityMetadata,assertReproducibleBuildEnvironment,
  productionFoundryBuildArguments,reproducibleFoundryChildEnvironment,
} from '../../sdk/reproducible-build-environment.mjs';

test('accepts inert process settings and rejects compiler/build injection',()=>{
 assert.equal(assertReproducibleBuildEnvironment({PATH:'/usr/bin',HOME:'/tmp/home'}),true);
 for(const environment of [{FOUNDRY_PROFILE:'deep'},{foundry_optimizer_runs:'1'},
  {DAPP_BUILD_OPTIMIZE:'1'},{SOLC_PATH:'/tmp/solc'},{LD_PRELOAD:'/tmp/inject.so'},
  {RUSTC_WRAPPER:'/tmp/wrapper'},{ETH_RPC_URL:'https://secret.invalid'},
  {HTTPS_PROXY:'http://proxy.invalid'},{XDG_CONFIG_HOME:'/tmp/host-config'}]) {
  assert.throws(()=>assertReproducibleBuildEnvironment(environment),/forbids ambient variables/);
 }
});

test('Foundry child gets an isolated offline deterministic boundary',()=>{
 const env=reproducibleFoundryChildEnvironment({HOME:'/safe/home',PATH:'/host/bin'},'/tmp/config');
 assert.deepEqual(env,{HOME:'/safe/home',PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',
  XDG_CONFIG_HOME:'/tmp/config',FOUNDRY_PROFILE:'default'});
 const args=productionFoundryBuildArguments('contracts/A.sol','/tmp/out','/tmp/cache','/src',
  '/compiler/solc-0.8.37');
 assert.deepEqual(args,['build','contracts/A.sol','--root','/src','--offline','--no-auto-detect',
  '--use','/compiler/solc-0.8.37','--evm-version','cancun','--optimize','--optimizer-runs','1','--via-ir','--force','--out',
  '/tmp/out','--cache-path','/tmp/cache','--ignored-error-codes','6335','-D','warnings']);
});

test('production artifact metadata binds exact solc and code-generation settings',()=>{
 const artifact={metadata:{compiler:{version:'0.8.37+commit.f401782d'},settings:{
  evmVersion:'cancun',viaIR:true,optimizer:{enabled:true,runs:1},metadata:{bytecodeHash:'none'},
 }}};
 assert.equal(assertProductionSolidityMetadata(artifact),true);
 for(const mutate of [
  value=>{value.metadata.compiler.version='0.8.37+commit.00000000';},
  value=>{value.metadata.settings.evmVersion='prague';},
  value=>{value.metadata.settings.optimizer.runs=201;},
  value=>{value.metadata.settings.viaIR=false;},
  value=>{value.metadata.settings.metadata.bytecodeHash='ipfs';},
 ]) { const changed=structuredClone(artifact); mutate(changed);
  assert.throws(()=>assertProductionSolidityMetadata(changed),/production Solidity policy/); }
});

test('ignores empty overrides but rejects invalid containers',()=>{
 assert.equal(assertReproducibleBuildEnvironment({FOUNDRY_PROFILE:''}),true);
 assert.throws(()=>assertReproducibleBuildEnvironment(null),/invalid/);
});

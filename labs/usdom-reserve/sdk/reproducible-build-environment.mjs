const exact=new Set([
  'LD_LIBRARY_PATH','LD_PRELOAD','NODE_OPTIONS','RUSTC_WORKSPACE_WRAPPER','RUSTC_WRAPPER',
  'RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RISC0_DEV_MODE','ETH_RPC_URL','ETHERSCAN_API_KEY',
  'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','XDG_CONFIG_HOME',
]);
const prefixes=['DAPP_','FOUNDRY_','SOLC_','ETH_RPC_'];

export function assertReproducibleBuildEnvironment(environment=process.env) {
  if(!environment||typeof environment!=='object'||Array.isArray(environment)) {
    throw new Error('build environment is invalid');
  }
  const present=Object.keys(environment).filter(name=>{
    const upper=name.toUpperCase();
    return environment[name]!==undefined&&environment[name]!==''
      &&(exact.has(upper)||prefixes.some(prefix=>upper.startsWith(prefix)));
  }).sort();
  if(present.length) throw new Error(`reproducible build forbids ambient variables: ${present.join(', ')}`);
  return true;
}

export function reproducibleFoundryChildEnvironment(environment=process.env,configHome) {
  assertReproducibleBuildEnvironment(environment);
  if(typeof environment.HOME!=='string'||!environment.HOME.startsWith('/')
      ||typeof configHome!=='string'||!configHome.startsWith('/')) {
    throw new Error('reproducible Foundry HOME paths are invalid');
  }
  return Object.freeze({
    HOME:environment.HOME,
    PATH:'/usr/bin:/bin',
    LANG:'C',
    LC_ALL:'C',
    XDG_CONFIG_HOME:configHome,
    FOUNDRY_PROFILE:'default',
  });
}

export async function snapshotProductionSolc(environment=process.env) {
  if(typeof environment.HOME!=='string'||!path.isAbsolute(environment.HOME)) {
    throw new Error('production Solc HOME is invalid');
  }
  return snapshotExecutablePath(path.join(environment.HOME,'.svm',PRODUCTION_SOLC_VERSION,
    `solc-${PRODUCTION_SOLC_VERSION}`));
}

export function productionFoundryBuildArguments(contract,output,cache,root,solcPath) {
  for(const [label,value] of Object.entries({contract,output,cache,root,solcPath})) {
    if(typeof value!=='string'||value.length===0) throw new Error(`Foundry ${label} is invalid`);
  }
  if(!path.isAbsolute(solcPath)) throw new Error('Foundry solcPath must be absolute');
  return ['build',contract,'--root',root,'--offline','--no-auto-detect','--use',solcPath,
    '--evm-version','cancun','--optimize','--optimizer-runs','1','--via-ir','--force','--out',output,
    '--cache-path',cache,'--ignored-error-codes','6335','-D','warnings'];
}
import path from 'node:path';
import {snapshotExecutablePath} from './stable-executable.mjs';

export const PRODUCTION_SOLC_VERSION='0.8.37';

export function assertProductionSolidityMetadata(artifact) {
  const metadata=artifact?.metadata,settings=metadata?.settings;
  if(metadata?.compiler?.version!==`${PRODUCTION_SOLC_VERSION}+commit.f401782d`
      ||settings?.evmVersion!=='cancun'||settings?.viaIR!==true
      ||settings?.optimizer?.enabled!==true||settings?.optimizer?.runs!==1
      ||settings?.metadata?.bytecodeHash!=='none') {
    throw new Error('artifact compiler/settings differ from production Solidity policy');
  }
  return true;
}
